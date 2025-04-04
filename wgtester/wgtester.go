package wgtester

import (
	"encoding/binary"
	"net"
	"sync"
	"time"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/network"
	"golang.org/x/net/ipv4"
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

// Server handles listening for connection check requests using raw sockets
type Server struct {
	rawConn      *ipv4.RawConn
	serverAddr   string
	serverPort   uint16
	shutdownCh   chan struct{}
	isRunning    bool
	runningLock  sync.Mutex
	newtID       string
	outputPrefix string
}

// NewServer creates a new connection test server using raw sockets
func NewServer(serverAddr string, serverPort uint16, newtID string) *Server {
	return &Server{
		serverAddr:   serverAddr,
		serverPort:   serverPort,
		shutdownCh:   make(chan struct{}),
		newtID:       newtID,
		outputPrefix: "[WGTester] ",
	}
}

// Start begins listening for connection test packets using raw sockets
func (s *Server) Start() error {
	s.runningLock.Lock()
	defer s.runningLock.Unlock()

	if s.isRunning {
		return nil
	}

	// Configure server and client for BPF filtering
	server := &network.Server{
		Hostname: s.serverAddr,
		Addr:     network.HostToAddr(s.serverAddr),
		Port:     s.serverPort,
	}

	clientIP := network.GetClientIP(server.Addr.IP)

	// Use the server port as our client port to match the WireGuard configuration
	client := &network.PeerNet{
		IP:     clientIP,
		Port:   s.serverPort, // Use same port as server to share with WireGuard
		NewtID: s.newtID,
	}

	// Setup raw connection with custom BPF to filter for our magic header
	rawConn := network.SetupRawConnWithCustomBPF(server, client, magicHeader)
	s.rawConn = rawConn

	s.isRunning = true
	go s.handleConnections()

	logger.Info(""+s.outputPrefix+"Server started on %s:%d", s.serverAddr, s.serverPort)
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
	if s.rawConn != nil {
		s.rawConn.Close()
	}
	s.isRunning = false
	logger.Info(s.outputPrefix + "Server stopped")
}

// handleConnections processes incoming packets
func (s *Server) handleConnections() {
	for {
		select {
		case <-s.shutdownCh:
			return
		default:
			// Read packet with timeout using RawConn
			err := s.rawConn.SetReadDeadline(time.Now().Add(1 * time.Second))
			if err != nil {
				logger.Error(s.outputPrefix+"Error setting read deadline: %v", err)
				continue
			}

			// Create buffer for the entire IP packet
			payload := make([]byte, 2000) // Large enough for any UDP packet

			// Read the packet
			_, _, _, err = s.rawConn.ReadFrom(payload)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// Just a timeout, keep going
					continue
				}
				logger.Error(s.outputPrefix+"Error reading from UDP: %v", err)
				continue
			}

			// Extract IP and port information
			srcIP, srcPort, _, _ := network.ExtractIPAndPorts(payload)
			if srcIP == nil {
				continue // Invalid packet
			}

			// Extract UDP payload
			udpPayload := network.ExtractUDPPayload(payload)
			if udpPayload == nil || len(udpPayload) < packetSize {
				continue // Too small to be our packet
			}

			// Check magic header
			magic := binary.BigEndian.Uint32(udpPayload[0:4])
			if magic != magicHeader {
				continue // Not our packet
			}

			// Check packet type
			packetType := udpPayload[4]
			if packetType != packetTypeRequest {
				continue // Not a request packet
			}

			// Create response packet
			responsePacket := make([]byte, packetSize)
			// Copy the same magic header
			binary.BigEndian.PutUint32(responsePacket[0:4], magicHeader)
			// Change the packet type to response
			responsePacket[4] = packetTypeResponse
			// Copy the timestamp (for RTT calculation)
			if len(udpPayload) >= 13 {
				copy(responsePacket[5:13], udpPayload[5:13])
			}

			// Use the client's source information to send the response
			peerClient := &network.PeerNet{
				IP:     s.rawConn.LocalAddr().(*net.IPAddr).IP,
				Port:   s.serverPort,
				NewtID: s.newtID,
			}

			// Setup target server from the source of the incoming packet
			server := &network.Server{
				Hostname: srcIP.String(),
				Addr:     &net.IPAddr{IP: srcIP},
				Port:     srcPort,
			}

			// Log response being sent for debugging
			logger.Debug(s.outputPrefix+"Sending response to %s:%d", srcIP.String(), srcPort)

			// Send the response packet
			err = network.SendPacket(responsePacket, s.rawConn, server, peerClient)
			if err != nil {
				logger.Error(s.outputPrefix+"Error sending response: %v", err)
			} else {
				logger.Debug(s.outputPrefix + "Response sent successfully")
			}
			if err != nil {
				logger.Error(s.outputPrefix+"Error sending response: %v", err)
			}
		}
	}
}
