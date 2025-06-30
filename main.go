package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fosrl/newt/docker"
	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/proxy"
	"github.com/fosrl/newt/websocket"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type WgData struct {
	Endpoint  string        `json:"endpoint"`
	PublicKey string        `json:"publicKey"`
	ServerIP  string        `json:"serverIP"`
	TunnelIP  string        `json:"tunnelIP"`
	Targets   TargetsByType `json:"targets"`
}

type TargetsByType struct {
	UDP []string `json:"udp"`
	TCP []string `json:"tcp"`
}

type TargetData struct {
	Targets []string `json:"targets"`
}

func fixKey(key string) string {
	key = strings.TrimSpace(key)
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		logger.Fatal("Error decoding base64: %v", err)
	}
	return hex.EncodeToString(decoded)
}

func ping(tnet *netstack.Net, dst string) error {
	logger.Info("Pinging %s", dst)
	socket, err := tnet.Dial("ping4", dst)
	if err != nil {
		return fmt.Errorf("failed to create ICMP socket: %w", err)
	}
	defer socket.Close()

	requestPing := icmp.Echo{
		Seq:  rand.Intn(1 << 16),
		Data: []byte("gopher burrow"),
	}

	icmpBytes, err := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &requestPing}).Marshal(nil)
	if err != nil {
		return fmt.Errorf("failed to marshal ICMP message: %w", err)
	}

	if err := socket.SetReadDeadline(time.Now().Add(time.Second * 10)); err != nil {
		return fmt.Errorf("failed to set read deadline: %w", err)
	}

	start := time.Now()
	_, err = socket.Write(icmpBytes)
	if err != nil {
		return fmt.Errorf("failed to write ICMP packet: %w", err)
	}

	n, err := socket.Read(icmpBytes[:])
	if err != nil {
		return fmt.Errorf("failed to read ICMP packet: %w", err)
	}

	replyPacket, err := icmp.ParseMessage(1, icmpBytes[:n])
	if err != nil {
		return fmt.Errorf("failed to parse ICMP packet: %w", err)
	}

	replyPing, ok := replyPacket.Body.(*icmp.Echo)
	if !ok {
		return fmt.Errorf("invalid reply type: got %T, want *icmp.Echo", replyPacket.Body)
	}

	if !bytes.Equal(replyPing.Data, requestPing.Data) || replyPing.Seq != requestPing.Seq {
		return fmt.Errorf("invalid ping reply: got seq=%d data=%q, want seq=%d data=%q",
			replyPing.Seq, replyPing.Data, requestPing.Seq, requestPing.Data)
	}

	logger.Info("Ping latency: %v", time.Since(start))
	return nil
}

// --- CHANGED: added healthFile as parameter ---
func startPingCheck(tnet *netstack.Net, serverIP string, stopChan chan struct{}, healthFile string) {
	initialInterval := 10 * time.Second
	maxInterval := 60 * time.Second
	currentInterval := initialInterval
	consecutiveFailures := 0

	ticker := time.NewTicker(currentInterval)
	defer ticker.Stop()

	go func() {
		for {
			select {
			case <-ticker.C:
				err := ping(tnet, serverIP)
				if err != nil {
					consecutiveFailures++
					logger.Warn("Periodic ping failed (%d consecutive failures): %v", consecutiveFailures, err)
					logger.Warn("HINT: Do you have UDP port 51820 (or the port in config.yml) open on your Pangolin server?")
					// --- CHANGED: Only remove file if healthFile is set ---
					if consecutiveFailures >= 3 && healthFile != "" {
						_ = os.Remove(healthFile)
					}
					// Increase interval if we have consistent failures, with a maximum cap
					if consecutiveFailures >= 3 && currentInterval < maxInterval {
						currentInterval = time.Duration(float64(currentInterval) * 1.5)
						if currentInterval > maxInterval {
							currentInterval = maxInterval
						}
						ticker.Reset(currentInterval)
						logger.Info("Increased ping check interval to %v due to consecutive failures", currentInterval)
					}
				} else {
					// --- CHANGED: Only write file if healthFile is set ---
					if healthFile != "" {
						err := os.WriteFile(healthFile, []byte("ok"), 0644)
						if err != nil {
							logger.Warn("Failed to write health file: %v", err)
						}
					}
					// On success, if we've backed off, gradually return to normal interval
					if currentInterval > initialInterval {
						currentInterval = time.Duration(float64(currentInterval) * 0.8)
						if currentInterval < initialInterval {
							currentInterval = initialInterval
						}
						ticker.Reset(currentInterval)
						logger.Info("Decreased ping check interval to %v after successful ping", currentInterval)
					}
					consecutiveFailures = 0
				}
			case <-stopChan:
				logger.Info("Stopping ping check")
				return
			}
		}
	}()
}

func monitorConnectionStatus(tnet *netstack.Net, serverIP string, client *websocket.Client) {
	const checkInterval = 30 * time.Second
	connectionLost := false
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			err := ping(tnet, serverIP)
			if err != nil && !connectionLost {
				connectionLost = true
				logger.Warn("Connection to server lost. Continuous reconnection attempts will be made.")
				logger.Warn("Please check your internet connection and ensure the Pangolin server is online.")
				logger.Warn("Newt will continue reconnection attempts automatically when connectivity is restored.")
			} else if err == nil && connectionLost {
				connectionLost = false
				logger.Info("Connection to server restored!")
				err := client.SendMessage("newt/wg/register", map[string]interface{}{
					"publicKey": privateKey.PublicKey().String(),
				})
				if err != nil {
					logger.Error("Failed to send registration message after reconnection: %v", err)
				} else {
					logger.Info("Successfully re-registered with server after reconnection")
				}
			}
		}
	}
}

func pingWithRetry(tnet *netstack.Net, dst string) error {
	const (
		initialMaxAttempts = 15
		initialRetryDelay  = 2 * time.Second
		maxRetryDelay      = 60 * time.Second
	)

	attempt := 1
	retryDelay := initialRetryDelay

	logger.Info("Ping attempt %d", attempt)
	if err := ping(tnet, dst); err == nil {
		return nil
	} else {
		logger.Warn("Ping attempt %d failed: %v", attempt, err)
	}

	go func() {
		attempt = 2
		for {
			logger.Info("Ping attempt %d", attempt)
			if err := ping(tnet, dst); err != nil {
				logger.Warn("Ping attempt %d failed: %v", attempt, err)
				if attempt%5 == 0 && retryDelay < maxRetryDelay {
					retryDelay = time.Duration(float64(retryDelay) * 1.5)
					if retryDelay > maxRetryDelay {
						retryDelay = maxRetryDelay
					}
					logger.Info("Increasing ping retry delay to %v", retryDelay)
				}
				time.Sleep(retryDelay)
				attempt++
			} else {
				logger.Info("Ping succeeded after %d attempts", attempt)
				return
			}
		}
	}()
	return fmt.Errorf("initial ping attempts failed, continuing in background")
}

func parseLogLevel(level string) logger.LogLevel {
	switch strings.ToUpper(level) {
	case "DEBUG":
		return logger.DEBUG
	case "INFO":
		return logger.INFO
	case "WARN":
		return logger.WARN
	case "ERROR":
		return logger.ERROR
	case "FATAL":
		return logger.FATAL
	default:
		return logger.INFO
	}
}

func mapToWireGuardLogLevel(level logger.LogLevel) int {
	switch level {
	case logger.DEBUG:
		return device.LogLevelVerbose
	case logger.WARN:
		return device.LogLevelError
	case logger.ERROR, logger.FATAL:
		return device.LogLevelSilent
	default:
		return device.LogLevelSilent
	}
}

func resolveDomain(domain string) (string, error) {
	host, port, err := net.SplitHostPort(domain)
	if err != nil {
		host = domain
		port = ""
	}
	if strings.HasPrefix(host, "http://") {
		host = strings.TrimPrefix(host, "http://")
	} else if strings.HasPrefix(host, "https://") {
		host = strings.TrimPrefix(host, "https://")
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", fmt.Errorf("DNS lookup failed: %v", err)
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("no IP addresses found for domain %s", host)
	}
	var ipAddr string
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			ipAddr = ipv4.String()
			break
		}
	}
	if ipAddr == "" {
		ipAddr = ips[0].String()
	}
	if port != "" {
		ipAddr = net.JoinHostPort(ipAddr, port)
	}
	return ipAddr, nil
}

// --- ADDED: healthFile variable ---
var (
	endpoint      string
	id            string
	secret        string
	mtu           string
	mtuInt        int
	dns           string
	privateKey    wgtypes.Key
	err           error
	logLevel      string
	updownScript  string
	tlsPrivateKey string
	dockerSocket  string
	healthFile    string // NEW
)

func main() {
	endpoint = os.Getenv("PANGOLIN_ENDPOINT")
	id = os.Getenv("NEWT_ID")
	secret = os.Getenv("NEWT_SECRET")
	mtu = os.Getenv("MTU")
	dns = os.Getenv("DNS")
	logLevel = os.Getenv("LOG_LEVEL")
	updownScript = os.Getenv("UPDOWN_SCRIPT")
	tlsPrivateKey = os.Getenv("TLS_CLIENT_CERT")
	dockerSocket = os.Getenv("DOCKER_SOCKET")
	healthFile = os.Getenv("HEALTH_FILE") // NEW

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
		flag.StringVar(&dns, "dns", "8.8.8.8", "DNS server to use")
	}
	if logLevel == "" {
		flag.StringVar(&logLevel, "log-level", "INFO", "Log level (DEBUG, INFO, WARN, ERROR, FATAL)")
	}
	if updownScript == "" {
		flag.StringVar(&updownScript, "updown", "", "Path to updown script to be called when targets are added or removed")
	}
	if tlsPrivateKey == "" {
		flag.StringVar(&tlsPrivateKey, "tls-client-cert", "", "Path to client certificate used for mTLS")
	}
	if dockerSocket == "" {
		flag.StringVar(&dockerSocket, "docker-socket", "", "Path to Docker socket (typically /var/run/docker.sock)")
	}
	// --- ADDED: CLI flag for healthFile if not set by env ---
	if healthFile == "" {
		flag.StringVar(&healthFile, "health-file", "", "Path to health file (if unset, health file won’t be written)")
	}

	version := flag.Bool("version", false, "Print the version")
	flag.Parse()

	newtVersion := "Newt version replaceme"
	if *version {
		fmt.Println(newtVersion)
		os.Exit(0)
	} else {
		logger.Info(newtVersion)
	}

	logger.Init()
	loggerLevel := parseLogLevel(logLevel)
	logger.GetLogger().SetLevel(parseLogLevel(logLevel))

	mtuInt, err = strconv.Atoi(mtu)
	if err != nil {
		logger.Fatal("Failed to parse MTU: %v", err)
	}

	privateKey, err = wgtypes.GeneratePrivateKey()
	if err != nil {
		logger.Fatal("Failed to generate private key: %v", err)
	}
	var opt websocket.ClientOption
	if tlsPrivateKey != "" {
		opt = websocket.WithTLSConfig(tlsPrivateKey)
	}
	client, err := websocket.NewClient(
		id, secret, endpoint, opt,
	)
	if err != nil {
		logger.Fatal("Failed to create client: %v", err)
	}

	var tun tun.Device
	var tnet *netstack.Net
	var dev *device.Device
	var pm *proxy.ProxyManager
	var connected bool
	var wgData WgData

	client.RegisterHandler("newt/terminate", func(msg websocket.WSMessage) {
		logger.Info("Received terminate message")
		if pm != nil {
			pm.Stop()
		}
		if dev != nil {
			dev.Close()
		}
		client.Close()
	})

	pingStopChan := make(chan struct{})
	defer close(pingStopChan)

	client.RegisterHandler("newt/wg/connect", func(msg websocket.WSMessage) {
		logger.Info("Received registration message")

		if connected {
			logger.Info("Already connected! But I will send a ping anyway...")
			_ = pingWithRetry(tnet, wgData.ServerIP)
			return
		}

		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Info("Error marshaling data: %v", err)
			return
		}

		if err := json.Unmarshal(jsonData, &wgData); err != nil {
			logger.Info("Error unmarshaling target data: %v", err)
			return
		}

		logger.Info("Received: %+v", msg)
		tun, tnet, err = netstack.CreateNetTUN(
			[]netip.Addr{netip.MustParseAddr(wgData.TunnelIP)},
			[]netip.Addr{netip.MustParseAddr(dns)},
			mtuInt)
		if err != nil {
			logger.Error("Failed to create TUN device: %v", err)
		}

		dev = device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(
			mapToWireGuardLogLevel(loggerLevel),
			"wireguard: ",
		))

		endpoint, err := resolveDomain(wgData.Endpoint)
		if err != nil {
			logger.Error("Failed to resolve endpoint: %v", err)
			return
		}

		config := fmt.Sprintf(`private_key=%s
public_key=%s
allowed_ip=%s/32
endpoint=%s
persistent_keepalive_interval=5`, fixKey(privateKey.String()), fixKey(wgData.PublicKey), wgData.ServerIP, endpoint)

		err = dev.IpcSet(config)
		if err != nil {
			logger.Error("Failed to configure WireGuard device: %v", err)
		}

		err = dev.Up()
		if err != nil {
			logger.Error("Failed to bring up WireGuard device: %v", err)
		}

		logger.Info("WireGuard device created. Lets ping the server now...")

		_ = pingWithRetry(tnet, wgData.ServerIP)

		if !connected {
			logger.Info("Starting ping check")
			// --- CHANGED: Pass healthFile to startPingCheck ---
			startPingCheck(tnet, wgData.ServerIP, pingStopChan, healthFile)
			go monitorConnectionStatus(tnet, wgData.ServerIP, client)
		}

		pm = proxy.NewProxyManager(tnet)
		connected = true

		if len(wgData.Targets.TCP) > 0 {
			updateTargets(pm, "add", wgData.TunnelIP, "tcp", TargetData{Targets: wgData.Targets.TCP})
		}
		if len(wgData.Targets.UDP) > 0 {
			updateTargets(pm, "add", wgData.TunnelIP, "udp", TargetData{Targets: wgData.Targets.UDP})
		}

		err = pm.Start()
		if err != nil {
			logger.Error("Failed to start proxy manager: %v", err)
		}
	})

}
