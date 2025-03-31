package wgtester

import (
	"context"
	"encoding/binary"
	"log"
	"net"
	"sync"
	"time"
)

const (
	// Magic bytes to identify our packets
	magicHeader uint32 = 0xDEADBEEF
	// Request packet type
	packetTypeRequest uint8 = 1
	// Response packet type
	packetTypeResponse uint8 = 2
	// Packet format:
	// - 4 bytes: magic header (0xDEADBEEF)
	// - 1 byte: packet type (1 = request, 2 = response)
	// - 8 bytes: timestamp (for round-trip timing)
	packetSize = 13
)

// Server handles listening for connection check requests
type Server struct {
	conn        *net.UDPConn
	listenAddr  string
	shutdownCh  chan struct{}
	isRunning   bool
	runningLock sync.Mutex
}

// NewServer creates a new connection test server
func NewServer(listenAddr string) *Server {
	return &Server{
		listenAddr: listenAddr,
		shutdownCh: make(chan struct{}),
	}
}

// Start begins listening for connection test packets
func (s *Server) Start() error {
	s.runningLock.Lock()
	defer s.runningLock.Unlock()

	if s.isRunning {
		return nil
	}

	addr, err := net.ResolveUDPAddr("udp", s.listenAddr)
	if err != nil {
		return err
	}

	s.conn, err = net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}

	s.isRunning = true
	go s.handleConnections()

	log.Printf("Server listening on %s", s.listenAddr)
	return nil
}

// Stop shuts down the server
func (s *Server) Stop() {
	s.runningLock.Lock()
	defer s.runningLock.Unlock()

	if !s.isRunning {
		return
	}

	close(s.shutdownCh)
	if s.conn != nil {
		s.conn.Close()
	}
	s.isRunning = false
	log.Println("Server stopped")
}

// handleConnections processes incoming packets
func (s *Server) handleConnections() {
	buffer := make([]byte, packetSize)

	for {
		select {
		case <-s.shutdownCh:
			return
		default:
			// Set read deadline to avoid blocking forever
			s.conn.SetReadDeadline(time.Now().Add(1 * time.Second))

			n, addr, err := s.conn.ReadFromUDP(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// Just a timeout, keep going
					continue
				}
				log.Printf("Error reading from UDP: %v", err)
				continue
			}

			if n != packetSize {
				continue // Ignore malformed packets
			}

			// Check magic header
			magic := binary.BigEndian.Uint32(buffer[0:4])
			if magic != magicHeader {
				continue // Not our packet
			}

			// Check packet type
			packetType := buffer[4]
			if packetType != packetTypeRequest {
				continue // Not a request packet
			}

			// Keep the timestamp the same (for RTT calculation)
			// Just change the packet type to response
			buffer[4] = packetTypeResponse

			// Send response
			_, err = s.conn.WriteToUDP(buffer, addr)
			if err != nil {
				log.Printf("Error sending response: %v", err)
			}
		}
	}
}

// Client handles checking connectivity to a server
type Client struct {
	conn           *net.UDPConn
	serverAddr     string
	monitorRunning bool
	monitorLock    sync.Mutex
	shutdownCh     chan struct{}
	packetInterval time.Duration
	timeout        time.Duration
	maxAttempts    int
}

// ConnectionStatus represents the current connection state
type ConnectionStatus struct {
	Connected bool
	RTT       time.Duration
}

// NewClient creates a new connection test client
func NewClient(serverAddr string) (*Client, error) {
	return &Client{
		serverAddr:     serverAddr,
		shutdownCh:     make(chan struct{}),
		packetInterval: 2 * time.Second,
		timeout:        500 * time.Millisecond, // Timeout for individual packets
		maxAttempts:    3,                      // Default max attempts
	}, nil
}

// SetPacketInterval changes how frequently packets are sent in monitor mode
func (c *Client) SetPacketInterval(interval time.Duration) {
	c.packetInterval = interval
}

// SetTimeout changes the timeout for waiting for responses
func (c *Client) SetTimeout(timeout time.Duration) {
	c.timeout = timeout
}

// SetMaxAttempts changes the maximum number of attempts for TestConnection
func (c *Client) SetMaxAttempts(attempts int) {
	c.maxAttempts = attempts
}

// Close cleans up client resources
func (c *Client) Close() {
	c.StopMonitor()
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
}

// ensureConnection makes sure we have an active UDP connection
func (c *Client) ensureConnection() error {
	if c.conn != nil {
		return nil
	}

	serverAddr, err := net.ResolveUDPAddr("udp", c.serverAddr)
	if err != nil {
		return err
	}

	c.conn, err = net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		return err
	}

	return nil
}

// TestConnection checks if the connection to the server is working
// Returns true if connected, false otherwise
func (c *Client) TestConnection(ctx context.Context) (bool, time.Duration) {
	if err := c.ensureConnection(); err != nil {
		return false, 0
	}

	// Prepare packet buffer
	packet := make([]byte, packetSize)
	binary.BigEndian.PutUint32(packet[0:4], magicHeader)
	packet[4] = packetTypeRequest

	// Send multiple attempts as specified
	for attempt := 0; attempt < c.maxAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return false, 0
		default:
			// Add current timestamp to packet
			timestamp := time.Now().UnixNano()
			binary.BigEndian.PutUint64(packet[5:13], uint64(timestamp))

			// Send the packet
			_, err := c.conn.Write(packet)
			if err != nil {
				log.Printf("Error sending packet: %v", err)
				continue
			}

			// Set read deadline
			c.conn.SetReadDeadline(time.Now().Add(c.timeout))

			// Wait for response
			responseBuffer := make([]byte, packetSize)
			n, err := c.conn.Read(responseBuffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// Timeout, try next attempt
					time.Sleep(100 * time.Millisecond) // Brief pause between attempts
					continue
				}
				log.Printf("Error reading response: %v", err)
				continue
			}

			if n != packetSize {
				continue // Malformed packet
			}

			// Verify response
			magic := binary.BigEndian.Uint32(responseBuffer[0:4])
			packetType := responseBuffer[4]
			if magic != magicHeader || packetType != packetTypeResponse {
				continue // Not our response
			}

			// Extract the original timestamp and calculate RTT
			sentTimestamp := int64(binary.BigEndian.Uint64(responseBuffer[5:13]))
			rtt := time.Duration(time.Now().UnixNano() - sentTimestamp)

			return true, rtt
		}
	}

	return false, 0
}

// TestConnectionWithTimeout tries to test connection with a timeout
// Returns true if connected, false otherwise
func (c *Client) TestConnectionWithTimeout(timeout time.Duration) (bool, time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return c.TestConnection(ctx)
}

// MonitorCallback is the function type for connection status change callbacks
type MonitorCallback func(status ConnectionStatus)

// StartMonitor begins monitoring the connection and calls the callback
// when the connection status changes
func (c *Client) StartMonitor(callback MonitorCallback) error {
	c.monitorLock.Lock()
	defer c.monitorLock.Unlock()

	if c.monitorRunning {
		return nil // Already running
	}

	if err := c.ensureConnection(); err != nil {
		return err
	}

	c.monitorRunning = true
	c.shutdownCh = make(chan struct{})

	go func() {
		var lastConnected bool
		firstRun := true

		ticker := time.NewTicker(c.packetInterval)
		defer ticker.Stop()

		for {
			select {
			case <-c.shutdownCh:
				return
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
				connected, rtt := c.TestConnection(ctx)
				cancel()

				// Callback if status changed or it's the first check
				if connected != lastConnected || firstRun {
					callback(ConnectionStatus{
						Connected: connected,
						RTT:       rtt,
					})
					lastConnected = connected
					firstRun = false
				}
			}
		}
	}()

	return nil
}

// StopMonitor stops the connection monitoring
func (c *Client) StopMonitor() {
	c.monitorLock.Lock()
	defer c.monitorLock.Unlock()

	if !c.monitorRunning {
		return
	}

	close(c.shutdownCh)
	c.monitorRunning = false
}
