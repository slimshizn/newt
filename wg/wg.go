package wg

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/websocket"
	"github.com/vishvananda/netlink"
	"golang.org/x/exp/rand"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type WgConfig struct {
	ListenPort int    `json:"listenPort"`
	IpAddress  string `json:"ipAddress"`
	Peers      []Peer `json:"peers"`
}

type Peer struct {
	PublicKey  string   `json:"publicKey"`
	AllowedIPs []string `json:"allowedIps"`
	Endpoint   string   `json:"endpoint"`
}

type PeerBandwidth struct {
	PublicKey string  `json:"publicKey"`
	BytesIn   float64 `json:"bytesIn"`
	BytesOut  float64 `json:"bytesOut"`
}

type PeerReading struct {
	BytesReceived    int64
	BytesTransmitted int64
	LastChecked      time.Time
}

type WireGuardService struct {
	interfaceName string
	mtu           int
	client        *websocket.Client
	wgClient      *wgctrl.Client
	config        WgConfig
	key           wgtypes.Key
	reachableAt   string
	newtId        string
	lastReadings  map[string]PeerReading
	mu            sync.Mutex
	port          uint16
	stopHolepunch chan struct{}
}

// Add this type definition
type fixedPortBind struct {
	port uint16
	conn.Bind
}

func (b *fixedPortBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	// Ignore the requested port and use our fixed port
	return b.Bind.Open(b.port)
}

func NewFixedPortBind(port uint16) conn.Bind {
	return &fixedPortBind{
		port: port,
		Bind: conn.NewDefaultBind(),
	}
}

func FindAvailableUDPPort(minPort, maxPort uint16) (uint16, error) {
	if maxPort < minPort {
		return 0, fmt.Errorf("invalid port range: min=%d, max=%d", minPort, maxPort)
	}

	// Create a slice of all ports in the range
	portRange := make([]uint16, maxPort-minPort+1)
	for i := range portRange {
		portRange[i] = minPort + uint16(i)
	}

	// Fisher-Yates shuffle to randomize the port order
	rand.Seed(uint64(time.Now().UnixNano()))
	for i := len(portRange) - 1; i > 0; i-- {
		j := rand.Intn(i + 1)
		portRange[i], portRange[j] = portRange[j], portRange[i]
	}

	// Try each port in the randomized order
	for _, port := range portRange {
		addr := &net.UDPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: int(port),
		}
		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			continue // Port is in use or there was an error, try next port
		}
		_ = conn.SetDeadline(time.Now())
		conn.Close()
		return port, nil
	}

	return 0, fmt.Errorf("no available UDP ports found in range %d-%d", minPort, maxPort)
}

func NewWireGuardService(interfaceName string, mtu int, reachableAt string, generateAndSaveKeyTo string, host string, newtId string, wsClient *websocket.Client) (*WireGuardService, error) {
	wgClient, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create WireGuard client: %v", err)
	}

	var key wgtypes.Key
	// if generateAndSaveKeyTo is provided, generate a private key and save it to the file. if the file already exists, load the key from the file
	if _, err := os.Stat(generateAndSaveKeyTo); os.IsNotExist(err) {
		// generate a new private key
		key, err = wgtypes.GeneratePrivateKey()
		if err != nil {
			logger.Fatal("Failed to generate private key: %v", err)
		}
		// save the key to the file
		err = os.WriteFile(generateAndSaveKeyTo, []byte(key.String()), 0644)
		if err != nil {
			logger.Fatal("Failed to save private key: %v", err)
		}
	} else {
		keyData, err := os.ReadFile(generateAndSaveKeyTo)
		if err != nil {
			logger.Fatal("Failed to read private key: %v", err)
		}
		key, err = wgtypes.ParseKey(string(keyData))
		if err != nil {
			logger.Fatal("Failed to parse private key: %v", err)
		}
	}

	port, err := FindAvailableUDPPort(49152, 65535)
	if err != nil {
		fmt.Printf("Error finding available port: %v\n", err)
		return nil, err
	}

	service := &WireGuardService{
		interfaceName: interfaceName,
		mtu:           mtu,
		client:        wsClient,
		wgClient:      wgClient,
		key:           key,
		reachableAt:   reachableAt,
		newtId:        newtId,
		lastReadings:  make(map[string]PeerReading),
		port:          port,
		stopHolepunch: make(chan struct{}),
	}

	if err := service.sendUDPHolePunch(host + ":21820"); err != nil {
		logger.Error("Failed to send UDP hole punch: %v", err)
	}

	// start the UDP holepunch
	go service.keepSendingUDPHolePunch(host)

	// Register websocket handlers
	wsClient.RegisterHandler("newt/wg/receive-config", service.handleConfig)
	wsClient.RegisterHandler("newt/wg/peer/add", service.handleAddPeer)
	wsClient.RegisterHandler("newt/wg/peer/remove", service.handleRemovePeer)

	return service, nil
}

func (s *WireGuardService) Close() {
	s.wgClient.Close()
}

func (s *WireGuardService) LoadRemoteConfig() error {

	err := s.client.SendMessage("newt/wg/get-config", map[string]interface{}{
		"publicKey": fmt.Sprintf("%s", s.key.PublicKey().String()),
		"endpoint":  s.reachableAt,
	})
	if err != nil {
		logger.Error("Failed to send registration message: %v", err)
		return err
	}

	logger.Info("Requesting WireGuard configuration from remote server")

	go s.periodicBandwidthCheck()

	return nil
}

func (s *WireGuardService) handleConfig(msg websocket.WSMessage) {
	var config WgConfig

	logger.Info("Received message: %v", msg)

	jsonData, err := json.Marshal(msg.Data)
	if err != nil {
		logger.Info("Error marshaling data: %v", err)
		return
	}

	if err := json.Unmarshal(jsonData, &config); err != nil {
		logger.Info("Error unmarshaling target data: %v", err)
		return
	}
	s.config = config

	// stop the holepunch
	close(s.stopHolepunch)

	// Ensure the WireGuard interface and peers are configured
	if err := s.ensureWireguardInterface(config); err != nil {
		logger.Error("Failed to ensure WireGuard interface: %v", err)
	}

	if err := s.ensureWireguardPeers(config.Peers); err != nil {
		logger.Error("Failed to ensure WireGuard peers: %v", err)
	}
}

func (s *WireGuardService) ensureWireguardInterface(wgconfig WgConfig) error {
	// Check if the WireGuard interface exists
	_, err := netlink.LinkByName(s.interfaceName)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			// Interface doesn't exist, so create it
			err = s.createWireGuardInterface()
			if err != nil {
				logger.Fatal("Failed to create WireGuard interface: %v", err)
			}
			logger.Info("Created WireGuard interface %s\n", s.interfaceName)
		} else {
			logger.Fatal("Error checking for WireGuard interface: %v", err)
		}
	} else {
		logger.Info("WireGuard interface %s already exists\n", s.interfaceName)
		return nil
	}

	logger.Info("Assigning IP address %s to interface %s\n", wgconfig.IpAddress, s.interfaceName)
	// Assign IP address to the interface
	err = s.assignIPAddress(wgconfig.IpAddress)
	if err != nil {
		logger.Fatal("Failed to assign IP address: %v", err)
	}

	// Check if the interface already exists
	_, err = s.wgClient.Device(s.interfaceName)
	if err != nil {
		return fmt.Errorf("interface %s does not exist", s.interfaceName)
	}

	// Parse the private key
	key, err := wgtypes.ParseKey(s.key.String())
	if err != nil {
		return fmt.Errorf("failed to parse private key: %v", err)
	}

	config := wgtypes.Config{
		PrivateKey: &key,
		ListenPort: new(int),
	}

	// Use the service's fixed port instead of the config port
	*config.ListenPort = int(s.port)

	// Create and configure the WireGuard interface
	err = s.wgClient.ConfigureDevice(s.interfaceName, config)
	if err != nil {
		return fmt.Errorf("failed to configure WireGuard device: %v", err)
	}

	// bring up the interface
	link, err := netlink.LinkByName(s.interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get interface: %v", err)
	}

	if err := netlink.LinkSetMTU(link, s.mtu); err != nil {
		return fmt.Errorf("failed to set MTU: %v", err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to bring up interface: %v", err)
	}

	// if err := s.ensureMSSClamping(); err != nil {
	// 	logger.Warn("Failed to ensure MSS clamping: %v", err)
	// }

	logger.Info("WireGuard interface %s created and configured", s.interfaceName)

	return nil
}

func (s *WireGuardService) createWireGuardInterface() error {
	wgLink := &netlink.GenericLink{
		LinkAttrs: netlink.LinkAttrs{Name: s.interfaceName},
		LinkType:  "wireguard",
	}
	return netlink.LinkAdd(wgLink)
}

func (s *WireGuardService) assignIPAddress(ipAddress string) error {
	link, err := netlink.LinkByName(s.interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get interface: %v", err)
	}

	addr, err := netlink.ParseAddr(ipAddress)
	if err != nil {
		return fmt.Errorf("failed to parse IP address: %v", err)
	}

	return netlink.AddrAdd(link, addr)
}

func (s *WireGuardService) ensureWireguardPeers(peers []Peer) error {
	// get the current peers
	device, err := s.wgClient.Device(s.interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get device: %v", err)
	}

	// get the peer public keys
	var currentPeers []string
	for _, peer := range device.Peers {
		currentPeers = append(currentPeers, peer.PublicKey.String())
	}

	// remove any peers that are not in the config
	for _, peer := range currentPeers {
		found := false
		for _, configPeer := range peers {
			if peer == configPeer.PublicKey {
				found = true
				break
			}
		}
		if !found {
			err := s.removePeer(peer)
			if err != nil {
				return fmt.Errorf("failed to remove peer: %v", err)
			}
		}
	}

	// add any peers that are in the config but not in the current peers
	for _, configPeer := range peers {
		found := false
		for _, peer := range currentPeers {
			if configPeer.PublicKey == peer {
				found = true
				break
			}
		}
		if !found {
			err := s.addPeer(configPeer)
			if err != nil {
				return fmt.Errorf("failed to add peer: %v", err)
			}
		}
	}

	return nil
}

// func (s *WireGuardService) ensureMSSClamping() error {
// 	// Calculate MSS value (MTU - 40 for IPv4 header (20) and TCP header (20))
// 	mssValue := mtuInt - 40

// 	// Rules to be managed - just the chains, we'll construct the full command separately
// 	chains := []string{"INPUT", "OUTPUT", "FORWARD"}

// 	// First, try to delete any existing rules
// 	for _, chain := range chains {
// 		deleteCmd := exec.Command("/usr/sbin/iptables",
// 			"-t", "mangle",
// 			"-D", chain,
// 			"-p", "tcp",
// 			"--tcp-flags", "SYN,RST", "SYN",
// 			"-j", "TCPMSS",
// 			"--set-mss", fmt.Sprintf("%d", mssValue))

// 		logger.Info("Attempting to delete existing MSS clamping rule for chain %s", chain)

// 		// Try deletion multiple times to handle multiple existing rules
// 		for i := 0; i < 3; i++ {
// 			out, err := deleteCmd.CombinedOutput()
// 			if err != nil {
// 				// Convert exit status 1 to string for better logging
// 				if exitErr, ok := err.(*exec.ExitError); ok {
// 					logger.Debug("Deletion stopped for chain %s: %v (output: %s)",
// 						chain, exitErr.String(), string(out))
// 				}
// 				break // No more rules to delete
// 			}
// 			logger.Info("Deleted MSS clamping rule for chain %s (attempt %d)", chain, i+1)
// 		}
// 	}

// 	// Then add the new rules
// 	var errors []error
// 	for _, chain := range chains {
// 		addCmd := exec.Command("/usr/sbin/iptables",
// 			"-t", "mangle",
// 			"-A", chain,
// 			"-p", "tcp",
// 			"--tcp-flags", "SYN,RST", "SYN",
// 			"-j", "TCPMSS",
// 			"--set-mss", fmt.Sprintf("%d", mssValue))

// 		logger.Info("Adding MSS clamping rule for chain %s", chain)

// 		if out, err := addCmd.CombinedOutput(); err != nil {
// 			errMsg := fmt.Sprintf("Failed to add MSS clamping rule for chain %s: %v (output: %s)",
// 				chain, err, string(out))
// 			logger.Error(errMsg)
// 			errors = append(errors, fmt.Errorf(errMsg))
// 			continue
// 		}

// 		// Verify the rule was added
// 		checkCmd := exec.Command("/usr/sbin/iptables",
// 			"-t", "mangle",
// 			"-C", chain,
// 			"-p", "tcp",
// 			"--tcp-flags", "SYN,RST", "SYN",
// 			"-j", "TCPMSS",
// 			"--set-mss", fmt.Sprintf("%d", mssValue))

// 		if out, err := checkCmd.CombinedOutput(); err != nil {
// 			errMsg := fmt.Sprintf("Rule verification failed for chain %s: %v (output: %s)",
// 				chain, err, string(out))
// 			logger.Error(errMsg)
// 			errors = append(errors, fmt.Errorf(errMsg))
// 			continue
// 		}

// 		logger.Info("Successfully added and verified MSS clamping rule for chain %s", chain)
// 	}

// 	// If we encountered any errors, return them combined
// 	if len(errors) > 0 {
// 		var errMsgs []string
// 		for _, err := range errors {
// 			errMsgs = append(errMsgs, err.Error())
// 		}
// 		return fmt.Errorf("MSS clamping setup encountered errors:\n%s",
// 			strings.Join(errMsgs, "\n"))
// 	}

// 	return nil
// }

func (s *WireGuardService) handleAddPeer(msg websocket.WSMessage) {
	var peer Peer

	jsonData, err := json.Marshal(msg.Data)
	if err != nil {
		logger.Info("Error marshaling data: %v", err)
	}

	if err := json.Unmarshal(jsonData, &peer); err != nil {
		logger.Info("Error unmarshaling target data: %v", err)
	}

	err = s.addPeer(peer)
	if err != nil {
		return
	}
}

func (s *WireGuardService) addPeer(peer Peer) error {
	pubKey, err := wgtypes.ParseKey(peer.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %v", err)
	}

	// parse allowed IPs into array of net.IPNet
	var allowedIPs []net.IPNet
	for _, ipStr := range peer.AllowedIPs {
		_, ipNet, err := net.ParseCIDR(ipStr)
		if err != nil {
			return fmt.Errorf("failed to parse allowed IP: %v", err)
		}
		allowedIPs = append(allowedIPs, *ipNet)
	}
	// add keep alive using *time.Duration	 of 1 second
	keepalive := time.Second
	endpoint, err := net.ResolveUDPAddr("udp", peer.Endpoint)
	if err != nil {
		return fmt.Errorf("failed to resolve endpoint address: %w", err)
	}

	peerConfig := wgtypes.PeerConfig{
		PublicKey:                   pubKey,
		AllowedIPs:                  allowedIPs,
		PersistentKeepaliveInterval: &keepalive,
		Endpoint:                    endpoint,
	}

	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerConfig},
	}

	if err := s.wgClient.ConfigureDevice(s.interfaceName, config); err != nil {
		return fmt.Errorf("failed to add peer: %v", err)
	}

	logger.Info("Peer %s added successfully", peer.PublicKey)

	return nil
}

func (s *WireGuardService) handleRemovePeer(msg websocket.WSMessage) {
	// parse the publicKey from the message which is json { "publicKey": "asdfasdfl;akjsdf" }
	type RemoveRequest struct {
		PublicKey string `json:"publicKey"`
	}

	jsonData, err := json.Marshal(msg.Data)
	if err != nil {
		logger.Info("Error marshaling data: %v", err)
	}

	var request RemoveRequest
	if err := json.Unmarshal(jsonData, &request); err != nil {
		logger.Info("Error unmarshaling data: %v", err)
		return
	}

	if err := s.removePeer(request.PublicKey); err != nil {
		logger.Info("Error removing peer: %v", err)
		return
	}
}

func (s *WireGuardService) removePeer(publicKey string) error {
	pubKey, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %v", err)
	}

	peerConfig := wgtypes.PeerConfig{
		PublicKey: pubKey,
		Remove:    true,
	}

	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerConfig},
	}

	if err := s.wgClient.ConfigureDevice(s.interfaceName, config); err != nil {
		return fmt.Errorf("failed to remove peer: %v", err)
	}

	logger.Info("Peer %s removed successfully", publicKey)

	return nil
}

func (s *WireGuardService) periodicBandwidthCheck() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if err := s.reportPeerBandwidth(); err != nil {
			logger.Info("Failed to report peer bandwidth: %v", err)
		}
	}
}

func (s *WireGuardService) calculatePeerBandwidth() ([]PeerBandwidth, error) {
	device, err := s.wgClient.Device(s.interfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get device: %v", err)
	}

	peerBandwidths := []PeerBandwidth{}
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, peer := range device.Peers {
		publicKey := peer.PublicKey.String()
		currentReading := PeerReading{
			BytesReceived:    peer.ReceiveBytes,
			BytesTransmitted: peer.TransmitBytes,
			LastChecked:      now,
		}

		var bytesInDiff, bytesOutDiff float64
		lastReading, exists := s.lastReadings[publicKey]

		if exists {
			timeDiff := currentReading.LastChecked.Sub(lastReading.LastChecked).Seconds()
			if timeDiff > 0 {
				// Calculate bytes transferred since last reading
				bytesInDiff = float64(currentReading.BytesReceived - lastReading.BytesReceived)
				bytesOutDiff = float64(currentReading.BytesTransmitted - lastReading.BytesTransmitted)

				// Handle counter wraparound (if the counter resets or overflows)
				if bytesInDiff < 0 {
					bytesInDiff = float64(currentReading.BytesReceived)
				}
				if bytesOutDiff < 0 {
					bytesOutDiff = float64(currentReading.BytesTransmitted)
				}

				// Convert to MB
				bytesInMB := bytesInDiff / (1024 * 1024)
				bytesOutMB := bytesOutDiff / (1024 * 1024)

				peerBandwidths = append(peerBandwidths, PeerBandwidth{
					PublicKey: publicKey,
					BytesIn:   bytesInMB,
					BytesOut:  bytesOutMB,
				})
			} else {
				// If readings are too close together or time hasn't passed, report 0
				peerBandwidths = append(peerBandwidths, PeerBandwidth{
					PublicKey: publicKey,
					BytesIn:   0,
					BytesOut:  0,
				})
			}
		} else {
			// For first reading of a peer, report 0 to establish baseline
			peerBandwidths = append(peerBandwidths, PeerBandwidth{
				PublicKey: publicKey,
				BytesIn:   0,
				BytesOut:  0,
			})
		}

		// Update the last reading
		s.lastReadings[publicKey] = currentReading
	}

	// Clean up old peers
	for publicKey := range s.lastReadings {
		found := false
		for _, peer := range device.Peers {
			if peer.PublicKey.String() == publicKey {
				found = true
				break
			}
		}
		if !found {
			delete(s.lastReadings, publicKey)
		}
	}

	return peerBandwidths, nil
}

func (s *WireGuardService) reportPeerBandwidth() error {
	bandwidths, err := s.calculatePeerBandwidth()
	if err != nil {
		return fmt.Errorf("failed to calculate peer bandwidth: %v", err)
	}

	err = s.client.SendMessage("newt/receive-bandwidth", map[string]interface{}{
		"bandwidthData": bandwidths,
	})
	if err != nil {
		return fmt.Errorf("failed to send bandwidth data: %v", err)
	}

	return nil
}

func (s *WireGuardService) sendUDPHolePunch(serverAddr string) error {
	// Bind to specific local port
	localAddr := &net.UDPAddr{
		Port: int(s.port),
		IP:   net.IPv4zero,
	}

	remoteAddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %v", err)
	}

	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		return fmt.Errorf("failed to bind UDP socket: %v", err)
	}
	defer conn.Close()

	payload := struct {
		NewtID string `json:"newtId"`
	}{
		NewtID: s.newtId,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %v", err)
	}

	_, err = conn.WriteToUDP(data, remoteAddr)
	if err != nil {
		return fmt.Errorf("failed to send UDP packet: %v", err)
	}

	logger.Info("Sent UDP hole punch to %s", serverAddr)

	return nil
}

func (s *WireGuardService) keepSendingUDPHolePunch(host string) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopHolepunch:
			logger.Info("Stopping UDP holepunch")
			return
		case <-ticker.C:
			if err := s.sendUDPHolePunch(host + ":21820"); err != nil {
				logger.Error("Failed to send UDP hole punch: %v", err)
			}
		}
	}
}
