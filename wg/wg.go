package wg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/websocket"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	interfaceName string
	listenAddr    string
	mtuInt        int
	lastReadings  = make(map[string]PeerReading)
	mu            sync.Mutex
)

type WgConfig struct {
	PrivateKey string `json:"privateKey"`
	ListenPort int    `json:"listenPort"`
	IpAddress  string `json:"ipAddress"`
	Peers      []Peer `json:"peers"`
}

type Peer struct {
	PublicKey  string   `json:"publicKey"`
	AllowedIPs []string `json:"allowedIps"`
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

var (
	wgClient *wgctrl.Client
)

type WireGuardService struct {
	interfaceName        string
	mtu                  int
	client               *websocket.Client
	wgClient             *wgctrl.Client
	config               WgConfig
	key                  wgtypes.Key
	reachableAt          string
	generateAndSaveKeyTo string
	lastReadings         map[string]PeerReading
	mu                   sync.Mutex
}

func NewWireGuardService(interfaceName string, mtu int, reachableAt string, generateAndSaveKeyTo string, wsClient *websocket.Client) (*WireGuardService, error) {
	wgClient, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create WireGuard client: %v", err)
	}

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	service := &WireGuardService{
		interfaceName:        interfaceName,
		mtu:                  mtu,
		client:               wsClient,
		wgClient:             wgClient,
		key:                  key,
		reachableAt:          reachableAt,
		generateAndSaveKeyTo: generateAndSaveKeyTo,
		lastReadings:         make(map[string]PeerReading),
	}

	// Register websocket handlers
	wsClient.RegisterHandler("wg/peer/config", service.handleConfig)
	wsClient.RegisterHandler("wg/peer/add", service.handleAddPeer)
	wsClient.RegisterHandler("wg/peer/remove", service.handleRemovePeer)

	// Register connect handler to initiate configuration
	wsClient.OnConnect(service.handleConnect)

	return service, nil
}

func (s *WireGuardService) handleConnect() error {
	logger.Debug("Public key: %s", s.key.PublicKey())

	err := s.client.SendMessage("wg/register", map[string]interface{}{
		"publicKey": fmt.Sprintf("%s", s.key.PublicKey()),
	})
	if err != nil {
		logger.Error("Failed to send registration message: %v", err)
		return err
	}

	logger.Info("Sent registration message")
	return nil
}

func (s *WireGuardService) Start() error {

	// if generateAndSaveKeyTo is provided, generate a private key and save it to the file. if the file already exists, load the key from the file
	if _, err := os.Stat(s.generateAndSaveKeyTo); os.IsNotExist(err) {
		// generate a new private key
		s.key, err = wgtypes.GeneratePrivateKey()
		if err != nil {
			logger.Fatal("Failed to generate private key: %v", err)
		}
		// save the key to the file
		err = os.WriteFile(s.generateAndSaveKeyTo, []byte(s.key.String()), 0644)
		if err != nil {
			logger.Fatal("Failed to save private key: %v", err)
		}
	} else {
		keyData, err := os.ReadFile(s.generateAndSaveKeyTo)
		if err != nil {
			logger.Fatal("Failed to read private key: %v", err)
		}
		s.key, err = wgtypes.ParseKey(string(keyData))
		if err != nil {
			logger.Fatal("Failed to parse private key: %v", err)
		}
	}

	// Get initial configuration
	err := s.loadRemoteConfig()
	if err != nil {
		return fmt.Errorf("failed to load initial configuration: %v", err)
	}

	return nil
}

func (s *WireGuardService) StartBandwidthReporting() {
	go s.periodicBandwidthCheck()
}

func (s *WireGuardService) loadRemoteConfig() error {
	body := bytes.NewBuffer([]byte(fmt.Sprintf(`{"publicKey": "%s", "reachableAt": "%s"}`, s.key.PublicKey().String(), s.reachableAt)))

	// send a ws message to the server to get the config

	err := s.client.SendMessage("wg/config/get", body)
	if err != nil {
		return fmt.Errorf("failed to send config request: %v", err)
	}

	return nil
}

func (s *WireGuardService) handleConfig(msg websocket.WSMessage) {
	var config WgConfig

	jsonData, err := json.Marshal(msg.Data)
	if err != nil {
		logger.Info("Error marshaling data: %v", err)
	}

	if err := json.Unmarshal(jsonData, &config); err != nil {
		logger.Info("Error unmarshaling target data: %v", err)
	}

	s.config = config

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
	_, err := netlink.LinkByName(interfaceName)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			// Interface doesn't exist, so create it
			err = s.createWireGuardInterface()
			if err != nil {
				logger.Fatal("Failed to create WireGuard interface: %v", err)
			}
			logger.Info("Created WireGuard interface %s\n", interfaceName)
		} else {
			logger.Fatal("Error checking for WireGuard interface: %v", err)
		}
	} else {
		logger.Info("WireGuard interface %s already exists\n", interfaceName)
		return nil
	}

	// Assign IP address to the interface
	err = s.assignIPAddress(wgconfig.IpAddress)
	if err != nil {
		logger.Fatal("Failed to assign IP address: %v", err)
	}
	logger.Info("Assigned IP address %s to interface %s\n", wgconfig.IpAddress, interfaceName)

	// Check if the interface already exists
	_, err = wgClient.Device(interfaceName)
	if err != nil {
		return fmt.Errorf("interface %s does not exist", interfaceName)
	}

	// Parse the private key
	key, err := wgtypes.ParseKey(wgconfig.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %v", err)
	}

	// Create a new WireGuard configuration
	config := wgtypes.Config{
		PrivateKey: &key,
		ListenPort: new(int),
	}
	*config.ListenPort = wgconfig.ListenPort

	// Create and configure the WireGuard interface
	err = wgClient.ConfigureDevice(interfaceName, config)
	if err != nil {
		return fmt.Errorf("failed to configure WireGuard device: %v", err)
	}

	// bring up the interface
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get interface: %v", err)
	}

	if err := netlink.LinkSetMTU(link, mtuInt); err != nil {
		return fmt.Errorf("failed to set MTU: %v", err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to bring up interface: %v", err)
	}

	if err := s.ensureMSSClamping(); err != nil {
		logger.Warn("Failed to ensure MSS clamping: %v", err)
	}

	logger.Info("WireGuard interface %s created and configured", interfaceName)

	return nil
}

func (s *WireGuardService) createWireGuardInterface() error {
	wgLink := &netlink.GenericLink{
		LinkAttrs: netlink.LinkAttrs{Name: interfaceName},
		LinkType:  "wireguard",
	}
	return netlink.LinkAdd(wgLink)
}

func (s *WireGuardService) assignIPAddress(ipAddress string) error {
	link, err := netlink.LinkByName(interfaceName)
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
	device, err := wgClient.Device(interfaceName)
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

func (s *WireGuardService) ensureMSSClamping() error {
	// Calculate MSS value (MTU - 40 for IPv4 header (20) and TCP header (20))
	mssValue := mtuInt - 40

	// Rules to be managed - just the chains, we'll construct the full command separately
	chains := []string{"INPUT", "OUTPUT", "FORWARD"}

	// First, try to delete any existing rules
	for _, chain := range chains {
		deleteCmd := exec.Command("/usr/sbin/iptables",
			"-t", "mangle",
			"-D", chain,
			"-p", "tcp",
			"--tcp-flags", "SYN,RST", "SYN",
			"-j", "TCPMSS",
			"--set-mss", fmt.Sprintf("%d", mssValue))

		logger.Info("Attempting to delete existing MSS clamping rule for chain %s", chain)

		// Try deletion multiple times to handle multiple existing rules
		for i := 0; i < 3; i++ {
			out, err := deleteCmd.CombinedOutput()
			if err != nil {
				// Convert exit status 1 to string for better logging
				if exitErr, ok := err.(*exec.ExitError); ok {
					logger.Debug("Deletion stopped for chain %s: %v (output: %s)",
						chain, exitErr.String(), string(out))
				}
				break // No more rules to delete
			}
			logger.Info("Deleted MSS clamping rule for chain %s (attempt %d)", chain, i+1)
		}
	}

	// Then add the new rules
	var errors []error
	for _, chain := range chains {
		addCmd := exec.Command("/usr/sbin/iptables",
			"-t", "mangle",
			"-A", chain,
			"-p", "tcp",
			"--tcp-flags", "SYN,RST", "SYN",
			"-j", "TCPMSS",
			"--set-mss", fmt.Sprintf("%d", mssValue))

		logger.Info("Adding MSS clamping rule for chain %s", chain)

		if out, err := addCmd.CombinedOutput(); err != nil {
			errMsg := fmt.Sprintf("Failed to add MSS clamping rule for chain %s: %v (output: %s)",
				chain, err, string(out))
			logger.Error(errMsg)
			errors = append(errors, fmt.Errorf(errMsg))
			continue
		}

		// Verify the rule was added
		checkCmd := exec.Command("/usr/sbin/iptables",
			"-t", "mangle",
			"-C", chain,
			"-p", "tcp",
			"--tcp-flags", "SYN,RST", "SYN",
			"-j", "TCPMSS",
			"--set-mss", fmt.Sprintf("%d", mssValue))

		if out, err := checkCmd.CombinedOutput(); err != nil {
			errMsg := fmt.Sprintf("Rule verification failed for chain %s: %v (output: %s)",
				chain, err, string(out))
			logger.Error(errMsg)
			errors = append(errors, fmt.Errorf(errMsg))
			continue
		}

		logger.Info("Successfully added and verified MSS clamping rule for chain %s", chain)
	}

	// If we encountered any errors, return them combined
	if len(errors) > 0 {
		var errMsgs []string
		for _, err := range errors {
			errMsgs = append(errMsgs, err.Error())
		}
		return fmt.Errorf("MSS clamping setup encountered errors:\n%s",
			strings.Join(errMsgs, "\n"))
	}

	return nil
}

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

	peerConfig := wgtypes.PeerConfig{
		PublicKey:  pubKey,
		AllowedIPs: allowedIPs,
	}

	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerConfig},
	}

	if err := wgClient.ConfigureDevice(interfaceName, config); err != nil {
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

	if err := wgClient.ConfigureDevice(interfaceName, config); err != nil {
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
	device, err := wgClient.Device(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get device: %v", err)
	}

	peerBandwidths := []PeerBandwidth{}
	now := time.Now()

	mu.Lock()
	defer mu.Unlock()

	for _, peer := range device.Peers {
		publicKey := peer.PublicKey.String()
		currentReading := PeerReading{
			BytesReceived:    peer.ReceiveBytes,
			BytesTransmitted: peer.TransmitBytes,
			LastChecked:      now,
		}

		var bytesInDiff, bytesOutDiff float64
		lastReading, exists := lastReadings[publicKey]

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
		lastReadings[publicKey] = currentReading
	}

	// Clean up old peers
	for publicKey := range lastReadings {
		found := false
		for _, peer := range device.Peers {
			if peer.PublicKey.String() == publicKey {
				found = true
				break
			}
		}
		if !found {
			delete(lastReadings, publicKey)
		}
	}

	return peerBandwidths, nil
}

func (s *WireGuardService) reportPeerBandwidth() error {
	bandwidths, err := s.calculatePeerBandwidth()
	if err != nil {
		return fmt.Errorf("failed to calculate peer bandwidth: %v", err)
	}

	jsonData, err := json.Marshal(bandwidths)
	if err != nil {
		return fmt.Errorf("failed to marshal bandwidth data: %v", err)
	}

	err = s.client.SendMessage("wg/bandwidth", jsonData)
	if err != nil {
		return fmt.Errorf("failed to send bandwidth data: %v", err)
	}

	return nil
}
