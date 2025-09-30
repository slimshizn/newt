package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fosrl/newt/docker"
	"github.com/fosrl/newt/healthcheck"
	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/proxy"
	"github.com/fosrl/newt/updates"
	"github.com/fosrl/newt/websocket"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type WgData struct {
	Endpoint           string               `json:"endpoint"`
	PublicKey          string               `json:"publicKey"`
	ServerIP           string               `json:"serverIP"`
	TunnelIP           string               `json:"tunnelIP"`
	Targets            TargetsByType        `json:"targets"`
	HealthCheckTargets []healthcheck.Config `json:"healthCheckTargets"`
}

type TargetsByType struct {
	UDP []string `json:"udp"`
	TCP []string `json:"tcp"`
}

type TargetData struct {
	Targets []string `json:"targets"`
}

type ExitNodeData struct {
	ExitNodes []ExitNode `json:"exitNodes"`
}

type SSHPublicKeyData struct {
	PublicKey string `json:"publicKey"`
}

// ExitNode represents an exit node with an ID, endpoint, and weight.
type ExitNode struct {
	ID                     int     `json:"exitNodeId"`
	Name                   string  `json:"exitNodeName"`
	Endpoint               string  `json:"endpoint"`
	Weight                 float64 `json:"weight"`
	WasPreviouslyConnected bool    `json:"wasPreviouslyConnected"`
}

type ExitNodePingResult struct {
	ExitNodeID             int     `json:"exitNodeId"`
	LatencyMs              int64   `json:"latencyMs"`
	Weight                 float64 `json:"weight"`
	Error                  string  `json:"error,omitempty"`
	Name                   string  `json:"exitNodeName"`
	Endpoint               string  `json:"endpoint"`
	WasPreviouslyConnected bool    `json:"wasPreviouslyConnected"`
}

type BlueprintResult struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// Custom flag type for multiple CA files
type stringSlice []string

func (s *stringSlice) String() string {
	return strings.Join(*s, ",")
}

func (s *stringSlice) Set(value string) error {
	*s = append(*s, value)
	return nil
}

var (
	endpoint                           string
	id                                 string
	secret                             string
	mtu                                string
	mtuInt                             int
	dns                                string
	privateKey                         wgtypes.Key
	err                                error
	logLevel                           string
	interfaceName                      string
	generateAndSaveKeyTo               string
	keepInterface                      bool
	acceptClients                      bool
	updownScript                       string
	dockerSocket                       string
	dockerEnforceNetworkValidation     string
	dockerEnforceNetworkValidationBool bool
	pingInterval                       time.Duration
	pingTimeout                        time.Duration
	publicKey                          wgtypes.Key
	pingStopChan                       chan struct{}
	stopFunc                           func()
	healthFile                         string
	useNativeInterface                 bool
	authorizedKeysFile                 string
	preferEndpoint                     string
	healthMonitor                      *healthcheck.Monitor
	enforceHealthcheckCert             bool
	blueprintFile                      string

	// New mTLS configuration variables
	tlsClientCert string
	tlsClientKey  string
	tlsClientCAs  []string

	// Legacy PKCS12 support (deprecated)
	tlsPrivateKey string
)

func main() {
	// if PANGOLIN_ENDPOINT, NEWT_ID, and NEWT_SECRET are set as environment variables, they will be used as default values
	endpoint = os.Getenv("PANGOLIN_ENDPOINT")
	id = os.Getenv("NEWT_ID")
	secret = os.Getenv("NEWT_SECRET")
	mtu = os.Getenv("MTU")
	dns = os.Getenv("DNS")
	logLevel = os.Getenv("LOG_LEVEL")
	updownScript = os.Getenv("UPDOWN_SCRIPT")
	interfaceName = os.Getenv("INTERFACE")
	generateAndSaveKeyTo = os.Getenv("GENERATE_AND_SAVE_KEY_TO")
	keepInterfaceEnv := os.Getenv("KEEP_INTERFACE")
	acceptClientsEnv := os.Getenv("ACCEPT_CLIENTS")
	useNativeInterfaceEnv := os.Getenv("USE_NATIVE_INTERFACE")
	enforceHealthcheckCertEnv := os.Getenv("ENFORCE_HC_CERT")

	keepInterface = keepInterfaceEnv == "true"
	acceptClients = acceptClientsEnv == "true"
	useNativeInterface = useNativeInterfaceEnv == "true"
	enforceHealthcheckCert = enforceHealthcheckCertEnv == "true"

	dockerSocket = os.Getenv("DOCKER_SOCKET")
	pingIntervalStr := os.Getenv("PING_INTERVAL")
	pingTimeoutStr := os.Getenv("PING_TIMEOUT")
	dockerEnforceNetworkValidation = os.Getenv("DOCKER_ENFORCE_NETWORK_VALIDATION")
	healthFile = os.Getenv("HEALTH_FILE")
	// authorizedKeysFile = os.Getenv("AUTHORIZED_KEYS_FILE")
	authorizedKeysFile = ""

	// Read new mTLS environment variables
	tlsClientCert = os.Getenv("TLS_CLIENT_CERT")
	tlsClientKey = os.Getenv("TLS_CLIENT_KEY")
	tlsClientCAsEnv := os.Getenv("TLS_CLIENT_CAS")
	if tlsClientCAsEnv != "" {
		tlsClientCAs = strings.Split(tlsClientCAsEnv, ",")
		// Trim spaces from each CA file path
		for i, ca := range tlsClientCAs {
			tlsClientCAs[i] = strings.TrimSpace(ca)
		}
	}

	// Legacy PKCS12 support (deprecated)
	tlsPrivateKey = os.Getenv("TLS_CLIENT_CERT_PKCS12")
	// Keep backward compatibility with old environment variable name
	if tlsPrivateKey == "" && tlsClientKey == "" && len(tlsClientCAs) == 0 {
		tlsPrivateKey = os.Getenv("TLS_CLIENT_CERT")
	}
	blueprintFile = os.Getenv("BLUEPRINT_FILE")

	if endpoint == "" {
		flag.StringVar(&endpoint, "endpoint", "", "Endpoint of your pangolin server")
	}
	if id == "" {
		flag.StringVar(&id, "id", "", "Newt ID")
	}
	if secret == "" {
		flag.StringVar(&secret, "secret", "", "Newt secret")
	}
	if mtu == "" {
		flag.StringVar(&mtu, "mtu", "1280", "MTU to use")
	}
	if dns == "" {
		flag.StringVar(&dns, "dns", "9.9.9.9", "DNS server to use")
	}
	if logLevel == "" {
		flag.StringVar(&logLevel, "log-level", "INFO", "Log level (DEBUG, INFO, WARN, ERROR, FATAL)")
	}
	if updownScript == "" {
		flag.StringVar(&updownScript, "updown", "", "Path to updown script to be called when targets are added or removed")
	}
	if interfaceName == "" {
		flag.StringVar(&interfaceName, "interface", "newt", "Name of the WireGuard interface")
	}
	if generateAndSaveKeyTo == "" {
		flag.StringVar(&generateAndSaveKeyTo, "generateAndSaveKeyTo", "", "Path to save generated private key")
	}
	if keepInterfaceEnv == "" {
		flag.BoolVar(&keepInterface, "keep-interface", false, "Keep the WireGuard interface")
	}
	if useNativeInterfaceEnv == "" {
		flag.BoolVar(&useNativeInterface, "native", false, "Use native WireGuard interface (requires WireGuard kernel module) and linux")
	}
	if acceptClientsEnv == "" {
		flag.BoolVar(&acceptClients, "accept-clients", false, "Accept clients on the WireGuard interface")
	}
	if enforceHealthcheckCertEnv == "" {
		flag.BoolVar(&enforceHealthcheckCert, "enforce-hc-cert", false, "Enforce certificate validation for health checks (default: false, accepts any cert)")
	}
	if dockerSocket == "" {
		flag.StringVar(&dockerSocket, "docker-socket", "", "Path or address to Docker socket (typically unix:///var/run/docker.sock)")
	}
	if pingIntervalStr == "" {
		flag.StringVar(&pingIntervalStr, "ping-interval", "3s", "Interval for pinging the server (default 3s)")
	}
	if pingTimeoutStr == "" {
		flag.StringVar(&pingTimeoutStr, "ping-timeout", "5s", "	Timeout for each ping (default 5s)")
	}
	// load the prefer endpoint just as a flag
	flag.StringVar(&preferEndpoint, "prefer-endpoint", "", "Prefer this endpoint for the connection (if set, will override the endpoint from the server)")

	// if authorizedKeysFile == "" {
	// 	flag.StringVar(&authorizedKeysFile, "authorized-keys-file", "~/.ssh/authorized_keys", "Path to authorized keys file (if unset, no keys will be authorized)")
	// }

	// Add new mTLS flags
	if tlsClientCert == "" {
		flag.StringVar(&tlsClientCert, "tls-client-cert-file", "", "Path to client certificate file (PEM/DER format)")
	}
	if tlsClientKey == "" {
		flag.StringVar(&tlsClientKey, "tls-client-key", "", "Path to client private key file (PEM/DER format)")
	}

	// Handle multiple CA files
	var tlsClientCAsFlag stringSlice
	flag.Var(&tlsClientCAsFlag, "tls-client-ca", "Path to CA certificate file for validating remote certificates (can be specified multiple times)")

	// Legacy PKCS12 flag (deprecated)
	if tlsPrivateKey == "" {
		flag.StringVar(&tlsPrivateKey, "tls-client-cert", "", "Path to client certificate (PKCS12 format) - DEPRECATED: use --tls-client-cert-file and --tls-client-key instead")
	}

	if pingIntervalStr != "" {
		pingInterval, err = time.ParseDuration(pingIntervalStr)
		if err != nil {
			fmt.Printf("Invalid PING_INTERVAL value: %s, using default 3 seconds\n", pingIntervalStr)
			pingInterval = 3 * time.Second
		}
	} else {
		pingInterval = 3 * time.Second
	}

	if pingTimeoutStr != "" {
		pingTimeout, err = time.ParseDuration(pingTimeoutStr)
		if err != nil {
			fmt.Printf("Invalid PING_TIMEOUT value: %s, using default 5 seconds\n", pingTimeoutStr)
			pingTimeout = 5 * time.Second
		}
	} else {
		pingTimeout = 5 * time.Second
	}

	if dockerEnforceNetworkValidation == "" {
		flag.StringVar(&dockerEnforceNetworkValidation, "docker-enforce-network-validation", "false", "Enforce validation of container on newt network (true or false)")
	}
	if healthFile == "" {
		flag.StringVar(&healthFile, "health-file", "", "Path to health file (if unset, health file won't be written)")
	}
	if blueprintFile == "" {
		flag.StringVar(&blueprintFile, "blueprint-file", "", "Path to blueprint file (if unset, no blueprint will be applied)")
	}

	// do a --version check
	version := flag.Bool("version", false, "Print the version")

	flag.Parse()

	// Merge command line CA flags with environment variable CAs
	if len(tlsClientCAsFlag) > 0 {
		tlsClientCAs = append(tlsClientCAs, tlsClientCAsFlag...)
	}

	logger.Init()
	loggerLevel := parseLogLevel(logLevel)
	logger.GetLogger().SetLevel(parseLogLevel(logLevel))

	newtVersion := "version_replaceme"
	if *version {
		fmt.Println("Newt version " + newtVersion)
		os.Exit(0)
	} else {
		logger.Info("Newt version " + newtVersion)
	}

	if err := updates.CheckForUpdate("fosrl", "newt", newtVersion); err != nil {
		logger.Error("Error checking for updates: %v\n", err)
	}

	// parse the mtu string into an int
	mtuInt, err = strconv.Atoi(mtu)
	if err != nil {
		logger.Fatal("Failed to parse MTU: %v", err)
	}

	// parse if we want to enforce container network validation
	dockerEnforceNetworkValidationBool, err = strconv.ParseBool(dockerEnforceNetworkValidation)
	if err != nil {
		logger.Info("Docker enforce network validation cannot be parsed. Defaulting to 'false'")
		dockerEnforceNetworkValidationBool = false
	}

	// Add TLS configuration validation
	if err := validateTLSConfig(); err != nil {
		logger.Fatal("TLS configuration error: %v", err)
	}

	// Show deprecation warning if using PKCS12
	if tlsPrivateKey != "" {
		logger.Warn("Using deprecated PKCS12 format for mTLS. Consider migrating to separate certificate files using --tls-client-cert-file, --tls-client-key, and --tls-client-ca")
	}

	privateKey, err = wgtypes.GeneratePrivateKey()
	if err != nil {
		logger.Fatal("Failed to generate private key: %v", err)
	}

	// Create client option based on TLS configuration
	var opt websocket.ClientOption
	if tlsClientCert != "" && tlsClientKey != "" {
		// Use new separate certificate configuration
		opt = websocket.WithTLSConfig(websocket.TLSConfig{
			ClientCertFile: tlsClientCert,
			ClientKeyFile:  tlsClientKey,
			CAFiles:        tlsClientCAs,
		})
		logger.Debug("Using separate certificate files for mTLS")
		logger.Debug("Client cert: %s", tlsClientCert)
		logger.Debug("Client key: %s", tlsClientKey)
		logger.Debug("CA files: %v", tlsClientCAs)
	} else if tlsPrivateKey != "" {
		// Use existing PKCS12 configuration for backward compatibility
		opt = websocket.WithTLSConfig(websocket.TLSConfig{
			PKCS12File: tlsPrivateKey,
		})
		logger.Debug("Using PKCS12 file for mTLS: %s", tlsPrivateKey)
	}

	// Create a new client
	client, err := websocket.NewClient(
		"newt",
		id,     // CLI arg takes precedence
		secret, // CLI arg takes precedence
		endpoint,
		pingInterval,
		pingTimeout,
		opt,
	)
	if err != nil {
		logger.Fatal("Failed to create client: %v", err)
	}
	endpoint = client.GetConfig().Endpoint // Update endpoint from config
	id = client.GetConfig().ID             // Update ID from config

	// output env var values if set
	logger.Debug("Endpoint: %v", endpoint)
	logger.Debug("Log Level: %v", logLevel)
	logger.Debug("Docker Network Validation Enabled: %v", dockerEnforceNetworkValidationBool)
	logger.Debug("Health Check Certificate Enforcement: %v", enforceHealthcheckCert)

	// Add new TLS debug logging
	if tlsClientCert != "" {
		logger.Debug("TLS Client Cert File: %v", tlsClientCert)
	}
	if tlsClientKey != "" {
		logger.Debug("TLS Client Key File: %v", tlsClientKey)
	}
	if len(tlsClientCAs) > 0 {
		logger.Debug("TLS CA Files: %v", tlsClientCAs)
	}
	if tlsPrivateKey != "" {
		logger.Debug("TLS PKCS12 File: %v", tlsPrivateKey)
	}

	if dns != "" {
		logger.Debug("Dns: %v", dns)
	}
	if dockerSocket != "" {
		logger.Debug("Docker Socket: %v", dockerSocket)
	}
	if mtu != "" {
		logger.Debug("MTU: %v", mtu)
	}
	if updownScript != "" {
		logger.Debug("Up Down Script: %v", updownScript)
	}

	// Create TUN device and network stack
	var tun tun.Device
	var tnet *netstack.Net
	var dev *device.Device
	var pm *proxy.ProxyManager
	var connected bool
	var wgData WgData
	var dockerEventMonitor *docker.EventMonitor

	if acceptClients {
		setupClients(client)
	}

	// Initialize health check monitor with status change callback
	healthMonitor = healthcheck.NewMonitor(func(targets map[int]*healthcheck.Target) {
		logger.Debug("Health check status update for %d targets", len(targets))

		// Send health status update to the server
		healthStatuses := make(map[int]interface{})
		for id, target := range targets {
			healthStatuses[id] = map[string]interface{}{
				"status":     target.Status.String(),
				"lastCheck":  target.LastCheck.Format(time.RFC3339),
				"checkCount": target.CheckCount,
				"lastError":  target.LastError,
				"config":     target.Config,
			}
		}

		// print the status of the targets
		logger.Debug("Health check status: %+v", healthStatuses)

		err := client.SendMessage("newt/healthcheck/status", map[string]interface{}{
			"targets": healthStatuses,
		})
		if err != nil {
			logger.Error("Failed to send health check status update: %v", err)
		}
	}, enforceHealthcheckCert)

	var pingWithRetryStopChan chan struct{}

	closeWgTunnel := func() {
		if pingStopChan != nil {
			// Stop the ping check
			close(pingStopChan)
			pingStopChan = nil
		}

		// Stop proxy manager if running
		if pm != nil {
			pm.Stop()
			pm = nil
		}

		// Close WireGuard device first - this will automatically close the TUN device
		if dev != nil {
			dev.Close()
			dev = nil
		}

		// Clear references but don't manually close since dev.Close() already did it
		if tnet != nil {
			tnet = nil
		}
		if tun != nil {
			tun = nil // Don't call tun.Close() here since dev.Close() already closed it
		}

	}

	// Register handlers for different message types
	client.RegisterHandler("newt/wg/connect", func(msg websocket.WSMessage) {
		logger.Debug("Received registration message")
		if stopFunc != nil {
			stopFunc()     // stop the ws from sending more requests
			stopFunc = nil // reset stopFunc to nil to avoid double stopping
		}

		if connected {
			// Mark as disconnected

			closeWgTunnel()

			connected = false
		}

		// print out the data
		logger.Debug("Received registration message data: %+v", msg.Data)

		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Info("Error marshaling data: %v", err)
			return
		}

		if err := json.Unmarshal(jsonData, &wgData); err != nil {
			logger.Info("Error unmarshaling target data: %v", err)
			return
		}

		logger.Debug("Received: %+v", msg)
		tun, tnet, err = netstack.CreateNetTUN(
			[]netip.Addr{netip.MustParseAddr(wgData.TunnelIP)},
			[]netip.Addr{netip.MustParseAddr(dns)},
			mtuInt)
		if err != nil {
			logger.Error("Failed to create TUN device: %v", err)
		}

		setDownstreamTNetstack(tnet)

		// Create WireGuard device
		dev = device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(
			mapToWireGuardLogLevel(loggerLevel),
			"wireguard: ",
		))

		host, _, err := net.SplitHostPort(wgData.Endpoint)
		if err != nil {
			logger.Error("Failed to split endpoint: %v", err)
			return
		}

		logger.Info("Connecting to endpoint: %s", host)

		endpoint, err := resolveDomain(wgData.Endpoint)
		if err != nil {
			logger.Error("Failed to resolve endpoint: %v", err)
			return
		}

		clientsHandleNewtConnection(wgData.PublicKey, endpoint)

		// Configure WireGuard
		config := fmt.Sprintf(`private_key=%s
public_key=%s
allowed_ip=%s/32
endpoint=%s
persistent_keepalive_interval=5`, fixKey(privateKey.String()), fixKey(wgData.PublicKey), wgData.ServerIP, endpoint)

		err = dev.IpcSet(config)
		if err != nil {
			logger.Error("Failed to configure WireGuard device: %v", err)
		}

		// Bring up the device
		err = dev.Up()
		if err != nil {
			logger.Error("Failed to bring up WireGuard device: %v", err)
		}

		logger.Debug("WireGuard device created. Lets ping the server now...")

		// Even if pingWithRetry returns an error, it will continue trying in the background
		if pingWithRetryStopChan != nil {
			// Stop the previous pingWithRetry if it exists
			close(pingWithRetryStopChan)
			pingWithRetryStopChan = nil
		}
		// Use reliable ping for initial connection test
		logger.Debug("Testing initial connection with reliable ping...")
		_, err = reliablePing(tnet, wgData.ServerIP, pingTimeout, 5)
		if err != nil {
			logger.Warn("Initial reliable ping failed, but continuing: %v", err)
		} else {
			logger.Debug("Initial connection test successful")
		}

		pingWithRetryStopChan, _ = pingWithRetry(tnet, wgData.ServerIP, pingTimeout)

		// Always mark as connected and start the proxy manager regardless of initial ping result
		// as the pings will continue in the background
		if !connected {
			logger.Debug("Starting ping check")
			pingStopChan = startPingCheck(tnet, wgData.ServerIP, client)
		}

		// Create proxy manager
		pm = proxy.NewProxyManager(tnet)

		connected = true

		// add the targets if there are any
		if len(wgData.Targets.TCP) > 0 {
			updateTargets(pm, "add", wgData.TunnelIP, "tcp", TargetData{Targets: wgData.Targets.TCP})
			// Also update wgnetstack proxy manager
			// if wgService != nil {
			// 	updateTargets(wgService.GetProxyManager(), "add", wgData.TunnelIP, "tcp", TargetData{Targets: wgData.Targets.TCP})
			// }
		}

		if len(wgData.Targets.UDP) > 0 {
			updateTargets(pm, "add", wgData.TunnelIP, "udp", TargetData{Targets: wgData.Targets.UDP})
			// Also update wgnetstack proxy manager
			// if wgService != nil {
			// 	updateTargets(wgService.GetProxyManager(), "add", wgData.TunnelIP, "udp", TargetData{Targets: wgData.Targets.UDP})
			// }
		}

		clientsAddProxyTarget(pm, wgData.TunnelIP)

		if err := healthMonitor.AddTargets(wgData.HealthCheckTargets); err != nil {
			logger.Error("Failed to bulk add health check targets: %v", err)
		} else {
			logger.Debug("Successfully added %d health check targets", len(wgData.HealthCheckTargets))
		}

		err = pm.Start()
		if err != nil {
			logger.Error("Failed to start proxy manager: %v", err)
		}
	})

	client.RegisterHandler("newt/wg/reconnect", func(msg websocket.WSMessage) {
		logger.Info("Received reconnect message")

		// Close the WireGuard device and TUN
		closeWgTunnel()

		// Mark as disconnected
		connected = false

		if stopFunc != nil {
			stopFunc()     // stop the ws from sending more requests
			stopFunc = nil // reset stopFunc to nil to avoid double stopping
		}

		// Request exit nodes from the server
		stopFunc = client.SendMessageInterval("newt/ping/request", map[string]interface{}{}, 3*time.Second)

		logger.Info("Tunnel destroyed, ready for reconnection")
	})

	client.RegisterHandler("newt/wg/terminate", func(msg websocket.WSMessage) {
		logger.Info("Received termination message")

		// Close the WireGuard device and TUN
		closeWgTunnel()

		if stopFunc != nil {
			stopFunc()     // stop the ws from sending more requests
			stopFunc = nil // reset stopFunc to nil to avoid double stopping
		}

		// Mark as disconnected
		connected = false

		logger.Info("Tunnel destroyed")
	})

	client.RegisterHandler("newt/ping/exitNodes", func(msg websocket.WSMessage) {
		logger.Debug("Received ping message")
		if stopFunc != nil {
			stopFunc()     // stop the ws from sending more requests
			stopFunc = nil // reset stopFunc to nil to avoid double stopping
		}

		// Parse the incoming list of exit nodes
		var exitNodeData ExitNodeData

		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Info("Error marshaling data: %v", err)
			return
		}
		if err := json.Unmarshal(jsonData, &exitNodeData); err != nil {
			logger.Info("Error unmarshaling exit node data: %v", err)
			return
		}
		exitNodes := exitNodeData.ExitNodes

		if len(exitNodes) == 0 {
			logger.Info("No exit nodes provided")
			return
		}

		// If there is just one exit node, we can skip pinging it and use it directly
		if len(exitNodes) == 1 || preferEndpoint != "" {
			logger.Debug("Only one exit node available, using it directly: %s", exitNodes[0].Endpoint)

			// if the preferEndpoint is set, we will use it instead of the exit node endpoint. first you need to find the exit node with that endpoint in the list and send that one
			if preferEndpoint != "" {
				for _, node := range exitNodes {
					if node.Endpoint == preferEndpoint {
						exitNodes[0] = node
						break
					}
				}
			}

			// Prepare data to send to the cloud for selection
			pingResults := []ExitNodePingResult{
				{
					ExitNodeID:             exitNodes[0].ID,
					LatencyMs:              0, // No ping latency since we are using it directly
					Weight:                 exitNodes[0].Weight,
					Error:                  "",
					Name:                   exitNodes[0].Name,
					Endpoint:               exitNodes[0].Endpoint,
					WasPreviouslyConnected: exitNodes[0].WasPreviouslyConnected,
				},
			}

			stopFunc = client.SendMessageInterval("newt/wg/register", map[string]interface{}{
				"publicKey":   publicKey.String(),
				"pingResults": pingResults,
				"newtVersion": newtVersion,
			}, 1*time.Second)

			return
		}

		type nodeResult struct {
			Node    ExitNode
			Latency time.Duration
			Err     error
		}

		results := make([]nodeResult, len(exitNodes))
		const pingAttempts = 3
		for i, node := range exitNodes {
			var totalLatency time.Duration
			var lastErr error
			successes := 0
			client := &http.Client{
				Timeout: 5 * time.Second,
			}
			url := node.Endpoint
			if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
				url = "http://" + url
			}
			if !strings.HasSuffix(url, "/ping") {
				url = strings.TrimRight(url, "/") + "/ping"
			}
			for j := 0; j < pingAttempts; j++ {
				start := time.Now()
				resp, err := client.Get(url)
				latency := time.Since(start)
				if err != nil {
					lastErr = err
					logger.Warn("Failed to ping exit node %d (%s) attempt %d: %v", node.ID, url, j+1, err)
					continue
				}
				resp.Body.Close()
				totalLatency += latency
				successes++
			}
			var avgLatency time.Duration
			if successes > 0 {
				avgLatency = totalLatency / time.Duration(successes)
			}
			if successes == 0 {
				results[i] = nodeResult{Node: node, Latency: 0, Err: lastErr}
			} else {
				results[i] = nodeResult{Node: node, Latency: avgLatency, Err: nil}
			}
		}

		// Prepare data to send to the cloud for selection
		var pingResults []ExitNodePingResult
		for _, res := range results {
			errMsg := ""
			if res.Err != nil {
				errMsg = res.Err.Error()
			}
			pingResults = append(pingResults, ExitNodePingResult{
				ExitNodeID:             res.Node.ID,
				LatencyMs:              res.Latency.Milliseconds(),
				Weight:                 res.Node.Weight,
				Error:                  errMsg,
				Name:                   res.Node.Name,
				Endpoint:               res.Node.Endpoint,
				WasPreviouslyConnected: res.Node.WasPreviouslyConnected,
			})
		}

		// If we were previously connected and there is at least one other good node,
		// exclude the previously connected node from pingResults sent to the cloud so we don't try to reconnect to it
		// This is to avoid issues where the previously connected node might be down or unreachable
		if connected {
			var filteredPingResults []ExitNodePingResult
			previouslyConnectedNodeIdx := -1
			for i, res := range pingResults {
				if res.WasPreviouslyConnected {
					previouslyConnectedNodeIdx = i
				}
			}
			// Count good nodes (latency > 0, no error, not previously connected)
			goodNodeCount := 0
			for i, res := range pingResults {
				if i != previouslyConnectedNodeIdx && res.LatencyMs > 0 && res.Error == "" {
					goodNodeCount++
				}
			}
			if previouslyConnectedNodeIdx != -1 && goodNodeCount > 0 {
				for i, res := range pingResults {
					if i != previouslyConnectedNodeIdx {
						filteredPingResults = append(filteredPingResults, res)
					}
				}
				pingResults = filteredPingResults
				logger.Info("Excluding previously connected exit node from ping results due to other available nodes")
			}
		}

		// Send the ping results to the cloud for selection
		stopFunc = client.SendMessageInterval("newt/wg/register", map[string]interface{}{
			"publicKey":   publicKey.String(),
			"pingResults": pingResults,
			"newtVersion": newtVersion,
		}, 1*time.Second)

		logger.Debug("Sent exit node ping results to cloud for selection: pingResults=%+v", pingResults)
	})

	client.RegisterHandler("newt/tcp/add", func(msg websocket.WSMessage) {
		logger.Debug("Received: %+v", msg)

		// if there is no wgData or pm, we can't add targets
		if wgData.TunnelIP == "" || pm == nil {
			logger.Info("No tunnel IP or proxy manager available")
			return
		}

		targetData, err := parseTargetData(msg.Data)
		if err != nil {
			logger.Info("Error parsing target data: %v", err)
			return
		}

		if len(targetData.Targets) > 0 {
			updateTargets(pm, "add", wgData.TunnelIP, "tcp", targetData)

			// Also update wgnetstack proxy manager
			// if wgService != nil && wgService.GetNetstackNet() != nil && wgService.GetProxyManager() != nil {
			// 	updateTargets(wgService.GetProxyManager(), "add", wgData.TunnelIP, "tcp", targetData)
			// }
		}
	})

	client.RegisterHandler("newt/udp/add", func(msg websocket.WSMessage) {
		logger.Info("Received: %+v", msg)

		// if there is no wgData or pm, we can't add targets
		if wgData.TunnelIP == "" || pm == nil {
			logger.Info("No tunnel IP or proxy manager available")
			return
		}

		targetData, err := parseTargetData(msg.Data)
		if err != nil {
			logger.Info("Error parsing target data: %v", err)
			return
		}

		if len(targetData.Targets) > 0 {
			updateTargets(pm, "add", wgData.TunnelIP, "udp", targetData)

			// Also update wgnetstack proxy manager
			// if wgService != nil && wgService.GetNetstackNet() != nil && wgService.GetProxyManager() != nil {
			// 	updateTargets(wgService.GetProxyManager(), "add", wgData.TunnelIP, "udp", targetData)
			// }
		}
	})

	client.RegisterHandler("newt/udp/remove", func(msg websocket.WSMessage) {
		logger.Info("Received: %+v", msg)

		// if there is no wgData or pm, we can't add targets
		if wgData.TunnelIP == "" || pm == nil {
			logger.Info("No tunnel IP or proxy manager available")
			return
		}

		targetData, err := parseTargetData(msg.Data)
		if err != nil {
			logger.Info("Error parsing target data: %v", err)
			return
		}

		if len(targetData.Targets) > 0 {
			updateTargets(pm, "remove", wgData.TunnelIP, "udp", targetData)

			// Also update wgnetstack proxy manager
			// if wgService != nil && wgService.GetNetstackNet() != nil && wgService.GetProxyManager() != nil {
			// 	updateTargets(wgService.GetProxyManager(), "remove", wgData.TunnelIP, "udp", targetData)
			// }
		}
	})

	client.RegisterHandler("newt/tcp/remove", func(msg websocket.WSMessage) {
		logger.Info("Received: %+v", msg)

		// if there is no wgData or pm, we can't add targets
		if wgData.TunnelIP == "" || pm == nil {
			logger.Info("No tunnel IP or proxy manager available")
			return
		}

		targetData, err := parseTargetData(msg.Data)
		if err != nil {
			logger.Info("Error parsing target data: %v", err)
			return
		}

		if len(targetData.Targets) > 0 {
			updateTargets(pm, "remove", wgData.TunnelIP, "tcp", targetData)

			// Also update wgnetstack proxy manager
			// if wgService != nil && wgService.GetNetstackNet() != nil && wgService.GetProxyManager() != nil {
			// 	updateTargets(wgService.GetProxyManager(), "remove", wgData.TunnelIP, "tcp", targetData)
			// }
		}
	})

	// Register handler for Docker socket check
	client.RegisterHandler("newt/socket/check", func(msg websocket.WSMessage) {
		logger.Debug("Received Docker socket check request")

		if dockerSocket == "" {
			logger.Debug("Docker socket path is not set")
			err := client.SendMessage("newt/socket/status", map[string]interface{}{
				"available":  false,
				"socketPath": dockerSocket,
			})
			if err != nil {
				logger.Error("Failed to send Docker socket check response: %v", err)
			}
			return
		}

		// Check if Docker socket is available
		isAvailable := docker.CheckSocket(dockerSocket)

		// Send response back to server
		err := client.SendMessage("newt/socket/status", map[string]interface{}{
			"available":  isAvailable,
			"socketPath": dockerSocket,
		})
		if err != nil {
			logger.Error("Failed to send Docker socket check response: %v", err)
		} else {
			logger.Debug("Docker socket check response sent: available=%t", isAvailable)
		}
	})

	// Register handler for Docker container listing
	client.RegisterHandler("newt/socket/fetch", func(msg websocket.WSMessage) {
		logger.Debug("Received Docker container fetch request")

		if dockerSocket == "" {
			logger.Debug("Docker socket path is not set")
			return
		}

		// List Docker containers
		containers, err := docker.ListContainers(dockerSocket, dockerEnforceNetworkValidationBool)
		if err != nil {
			logger.Error("Failed to list Docker containers: %v", err)
			return
		}

		// Send container list back to server
		err = client.SendMessage("newt/socket/containers", map[string]interface{}{
			"containers": containers,
		})
		if err != nil {
			logger.Error("Failed to send registration message: %v", err)
		}

		if err != nil {
			logger.Error("Failed to send Docker container list: %v", err)
		} else {
			logger.Debug("Docker container list sent, count: %d", len(containers))
		}
	})

	// EXPERIMENTAL: WHAT SHOULD WE DO ABOUT SECURITY?
	client.RegisterHandler("newt/send/ssh/publicKey", func(msg websocket.WSMessage) {
		logger.Debug("Received SSH public key request")

		var sshPublicKeyData SSHPublicKeyData

		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Info("Error marshaling data: %v", err)
			return
		}
		if err := json.Unmarshal(jsonData, &sshPublicKeyData); err != nil {
			logger.Info("Error unmarshaling SSH public key data: %v", err)
			return
		}

		sshPublicKey := sshPublicKeyData.PublicKey

		if authorizedKeysFile == "" {
			logger.Debug("No authorized keys file set, skipping public key response")
			return
		}

		// Expand tilde to home directory if present
		expandedPath := authorizedKeysFile
		if strings.HasPrefix(authorizedKeysFile, "~/") {
			homeDir, err := os.UserHomeDir()
			if err != nil {
				logger.Error("Failed to get user home directory: %v", err)
				return
			}
			expandedPath = filepath.Join(homeDir, authorizedKeysFile[2:])
		}

		// if it is set but the file does not exist, create it
		if _, err := os.Stat(expandedPath); os.IsNotExist(err) {
			logger.Debug("Authorized keys file does not exist, creating it: %s", expandedPath)
			if err := os.MkdirAll(filepath.Dir(expandedPath), 0755); err != nil {
				logger.Error("Failed to create directory for authorized keys file: %v", err)
				return
			}
			if _, err := os.Create(expandedPath); err != nil {
				logger.Error("Failed to create authorized keys file: %v", err)
				return
			}
		}

		// Check if the public key already exists in the file
		fileContent, err := os.ReadFile(expandedPath)
		if err != nil {
			logger.Error("Failed to read authorized keys file: %v", err)
			return
		}

		// Check if the key already exists (trim whitespace for comparison)
		existingKeys := strings.Split(string(fileContent), "\n")
		keyAlreadyExists := false
		trimmedNewKey := strings.TrimSpace(sshPublicKey)

		for _, existingKey := range existingKeys {
			if strings.TrimSpace(existingKey) == trimmedNewKey && trimmedNewKey != "" {
				keyAlreadyExists = true
				break
			}
		}

		if keyAlreadyExists {
			logger.Info("SSH public key already exists in authorized keys file, skipping")
			return
		}

		// append the public key to the authorized keys file
		logger.Debug("Appending public key to authorized keys file: %s", sshPublicKey)
		file, err := os.OpenFile(expandedPath, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			logger.Error("Failed to open authorized keys file: %v", err)
			return
		}
		defer file.Close()

		if _, err := file.WriteString(sshPublicKey + "\n"); err != nil {
			logger.Error("Failed to write public key to authorized keys file: %v", err)
			return
		}

		logger.Info("SSH public key appended to authorized keys file")
	})

	// Register handler for adding health check targets
	client.RegisterHandler("newt/healthcheck/add", func(msg websocket.WSMessage) {
		logger.Debug("Received health check add request: %+v", msg)

		type HealthCheckConfig struct {
			Targets []healthcheck.Config `json:"targets"`
		}

		var config HealthCheckConfig
		// add a bunch of targets at once
		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Error("Error marshaling health check data: %v", err)
			return
		}

		if err := json.Unmarshal(jsonData, &config); err != nil {
			logger.Error("Error unmarshaling health check config: %v", err)
			return
		}

		if err := healthMonitor.AddTargets(config.Targets); err != nil {
			logger.Error("Failed to add health check targets: %v", err)
		} else {
			logger.Debug("Added %d health check targets", len(config.Targets))
		}

		logger.Debug("Health check targets added: %+v", config.Targets)
	})

	// Register handler for removing health check targets
	client.RegisterHandler("newt/healthcheck/remove", func(msg websocket.WSMessage) {
		logger.Debug("Received health check remove request: %+v", msg)

		type HealthCheckConfig struct {
			IDs []int `json:"ids"`
		}

		var requestData HealthCheckConfig
		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Error("Error marshaling health check remove data: %v", err)
			return
		}

		if err := json.Unmarshal(jsonData, &requestData); err != nil {
			logger.Error("Error unmarshaling health check remove request: %v", err)
			return
		}

		// Multiple target removal
		if err := healthMonitor.RemoveTargets(requestData.IDs); err != nil {
			logger.Error("Failed to remove health check targets %v: %v", requestData.IDs, err)
		} else {
			logger.Info("Removed %d health check targets: %v", len(requestData.IDs), requestData.IDs)
		}
	})

	// Register handler for enabling health check targets
	client.RegisterHandler("newt/healthcheck/enable", func(msg websocket.WSMessage) {
		logger.Debug("Received health check enable request: %+v", msg)

		var requestData struct {
			ID int `json:"id"`
		}
		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Error("Error marshaling health check enable data: %v", err)
			return
		}

		if err := json.Unmarshal(jsonData, &requestData); err != nil {
			logger.Error("Error unmarshaling health check enable request: %v", err)
			return
		}

		if err := healthMonitor.EnableTarget(requestData.ID); err != nil {
			logger.Error("Failed to enable health check target %s: %v", requestData.ID, err)
		} else {
			logger.Info("Enabled health check target: %s", requestData.ID)
		}
	})

	// Register handler for disabling health check targets
	client.RegisterHandler("newt/healthcheck/disable", func(msg websocket.WSMessage) {
		logger.Debug("Received health check disable request: %+v", msg)

		var requestData struct {
			ID int `json:"id"`
		}
		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Error("Error marshaling health check disable data: %v", err)
			return
		}

		if err := json.Unmarshal(jsonData, &requestData); err != nil {
			logger.Error("Error unmarshaling health check disable request: %v", err)
			return
		}

		if err := healthMonitor.DisableTarget(requestData.ID); err != nil {
			logger.Error("Failed to disable health check target %s: %v", requestData.ID, err)
		} else {
			logger.Info("Disabled health check target: %s", requestData.ID)
		}
	})

	// Register handler for getting health check status
	client.RegisterHandler("newt/healthcheck/status/request", func(msg websocket.WSMessage) {
		logger.Debug("Received health check status request")

		targets := healthMonitor.GetTargets()
		healthStatuses := make(map[int]interface{})
		for id, target := range targets {
			healthStatuses[id] = map[string]interface{}{
				"status":     target.Status.String(),
				"lastCheck":  target.LastCheck.Format(time.RFC3339),
				"checkCount": target.CheckCount,
				"lastError":  target.LastError,
				"config":     target.Config,
			}
		}

		err := client.SendMessage("newt/healthcheck/status", map[string]interface{}{
			"targets": healthStatuses,
		})
		if err != nil {
			logger.Error("Failed to send health check status response: %v", err)
		}
	})

	// Register handler for getting health check status
	client.RegisterHandler("newt/blueprint/results", func(msg websocket.WSMessage) {
		logger.Debug("Received blueprint results message")

		var blueprintResult BlueprintResult

		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Info("Error marshaling data: %v", err)
			return
		}
		if err := json.Unmarshal(jsonData, &blueprintResult); err != nil {
			logger.Info("Error unmarshaling config results data: %v", err)
			return
		}

		if blueprintResult.Success {
			logger.Debug("Blueprint applied successfully!")
		} else {
			logger.Warn("Blueprint application failed: %s", blueprintResult.Message)
		}
	})

	client.OnConnect(func() error {
		publicKey = privateKey.PublicKey()
		logger.Debug("Public key: %s", publicKey)
		logger.Info("Websocket connected")

		if !connected {
			// make sure the stop function is called
			if stopFunc != nil {
				stopFunc()
			}
			// request from the server the list of nodes to ping at newt/ping/request
			stopFunc = client.SendMessageInterval("newt/ping/request", map[string]interface{}{}, 3*time.Second)
			logger.Debug("Requesting exit nodes from server")
			clientsOnConnect()
		}

		// Send registration message to the server for backward compatibility
		err := client.SendMessage("newt/wg/register", map[string]interface{}{
			"publicKey":           publicKey.String(),
			"newtVersion":         newtVersion,
			"backwardsCompatible": true,
		})

		sendBlueprint(client)

		if err != nil {
			logger.Error("Failed to send registration message: %v", err)
			return err
		}

		return nil
	})

	// Connect to the WebSocket server
	if err := client.Connect(); err != nil {
		logger.Fatal("Failed to connect to server: %v", err)
	}
	defer client.Close()

	// Initialize Docker event monitoring if Docker socket is available and monitoring is enabled
	if dockerSocket != "" {
		logger.Debug("Initializing Docker event monitoring")
		dockerEventMonitor, err = docker.NewEventMonitor(dockerSocket, dockerEnforceNetworkValidationBool, func(containers []docker.Container) {
			// Send updated container list via websocket when Docker events occur
			logger.Debug("Docker event detected, sending updated container list (%d containers)", len(containers))
			err := client.SendMessage("newt/socket/containers", map[string]interface{}{
				"containers": containers,
			})
			if err != nil {
				logger.Error("Failed to send updated container list after Docker event: %v", err)
			} else {
				logger.Debug("Updated container list sent successfully")
			}
		})

		if err != nil {
			logger.Error("Failed to create Docker event monitor: %v", err)
		} else {
			err = dockerEventMonitor.Start()
			if err != nil {
				logger.Error("Failed to start Docker event monitoring: %v", err)
			} else {
				logger.Debug("Docker event monitoring started successfully")
			}
		}
	}

	// Wait for interrupt signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	// Close clients first (including WGTester)
	closeClients()

	if dockerEventMonitor != nil {
		dockerEventMonitor.Stop()
	}

	if healthMonitor != nil {
		healthMonitor.Stop()
	}

	if dev != nil {
		dev.Close()
	}

	if pm != nil {
		pm.Stop()
	}

	if client != nil {
		client.Close()
	}
	logger.Info("Exiting...")
	os.Exit(0)
}

// validateTLSConfig validates the TLS configuration
func validateTLSConfig() error {
	// Check for conflicting configurations
	pkcs12Specified := tlsPrivateKey != ""
	separateFilesSpecified := tlsClientCert != "" || tlsClientKey != "" || len(tlsClientCAs) > 0

	if pkcs12Specified && separateFilesSpecified {
		return fmt.Errorf("cannot use both PKCS12 format (--tls-client-cert) and separate certificate files (--tls-client-cert-file, --tls-client-key, --tls-client-ca)")
	}

	// If using separate files, both cert and key are required
	if (tlsClientCert != "" && tlsClientKey == "") || (tlsClientCert == "" && tlsClientKey != "") {
		return fmt.Errorf("both --tls-client-cert-file and --tls-client-key must be specified together")
	}

	// Validate certificate files exist
	if tlsClientCert != "" {
		if _, err := os.Stat(tlsClientCert); os.IsNotExist(err) {
			return fmt.Errorf("client certificate file does not exist: %s", tlsClientCert)
		}
	}

	if tlsClientKey != "" {
		if _, err := os.Stat(tlsClientKey); os.IsNotExist(err) {
			return fmt.Errorf("client key file does not exist: %s", tlsClientKey)
		}
	}

	// Validate CA files exist
	for _, caFile := range tlsClientCAs {
		if _, err := os.Stat(caFile); os.IsNotExist(err) {
			return fmt.Errorf("CA certificate file does not exist: %s", caFile)
		}
	}

	// Validate PKCS12 file exists if specified
	if tlsPrivateKey != "" {
		if _, err := os.Stat(tlsPrivateKey); os.IsNotExist(err) {
			return fmt.Errorf("PKCS12 certificate file does not exist: %s", tlsPrivateKey)
		}
	}

	return nil
}
