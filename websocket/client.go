package websocket

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/fosrl/newt/logger"

	"github.com/gorilla/websocket"
)

type Client struct {
	conn        *websocket.Conn
	config      *Config
	baseURL     string
	handlers    map[string]MessageHandler
	done        chan struct{}
	handlersMux sync.RWMutex

	reconnectInterval time.Duration
	isConnected       bool
	reconnectMux      sync.RWMutex

	onConnect     func() error
	onTokenUpdate func(token string)
}

type ClientOption func(*Client)

type MessageHandler func(message WSMessage)

// WithBaseURL sets the base URL for the client
func WithBaseURL(url string) ClientOption {
	return func(c *Client) {
		c.baseURL = url
	}
}

func (c *Client) OnConnect(callback func() error) {
	c.onConnect = callback
}

func (c *Client) OnTokenUpdate(callback func(token string)) {
	c.onTokenUpdate = callback
}

// NewClient creates a new Newt client
func NewClient(newtID, secret string, endpoint string, opts ...ClientOption) (*Client, error) {
	config := &Config{
		NewtID:   newtID,
		Secret:   secret,
		Endpoint: endpoint,
	}

	client := &Client{
		config:            config,
		baseURL:           endpoint, // default value
		handlers:          make(map[string]MessageHandler),
		done:              make(chan struct{}),
		reconnectInterval: 10 * time.Second,
		isConnected:       false,
	}

	// Apply options before loading config
	for _, opt := range opts {
		opt(client)
	}

	// Load existing config if available
	if err := client.loadConfig(); err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	return client, nil
}

// Connect establishes the WebSocket connection
func (c *Client) Connect() error {
	go c.connectWithRetry()
	return nil
}

// Close closes the WebSocket connection
func (c *Client) Close() error {
	close(c.done)
	if c.conn != nil {
		return c.conn.Close()
	}

	// stop the ping monitor
	c.setConnected(false)

	return nil
}

// SendMessage sends a message through the WebSocket connection
func (c *Client) SendMessage(messageType string, data interface{}) error {
	if c.conn == nil {
		return fmt.Errorf("not connected")
	}

	msg := WSMessage{
		Type: messageType,
		Data: data,
	}

	return c.conn.WriteJSON(msg)
}

// RegisterHandler registers a handler for a specific message type
func (c *Client) RegisterHandler(messageType string, handler MessageHandler) {
	c.handlersMux.Lock()
	defer c.handlersMux.Unlock()
	c.handlers[messageType] = handler
}

// readPump pumps messages from the WebSocket connection
func (c *Client) readPump() {
	defer c.conn.Close()

	for {
		select {
		case <-c.done:
			return
		default:
			var msg WSMessage
			err := c.conn.ReadJSON(&msg)
			if err != nil {
				return
			}

			c.handlersMux.RLock()
			if handler, ok := c.handlers[msg.Type]; ok {
				handler(msg)
			}
			c.handlersMux.RUnlock()
		}
	}
}

func (c *Client) getToken() (string, error) {
	// Parse the base URL to ensure we have the correct hostname
	baseURL, err := url.Parse(c.baseURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse base URL: %w", err)
	}

	// Ensure we have the base URL without trailing slashes
	baseEndpoint := strings.TrimRight(baseURL.String(), "/")

	// If we already have a token, try to use it
	if c.config.Token != "" {
		tokenCheckData := map[string]interface{}{
			"newtId": c.config.NewtID,
			"secret": c.config.Secret,
			"token":  c.config.Token,
		}
		jsonData, err := json.Marshal(tokenCheckData)
		if err != nil {
			return "", fmt.Errorf("failed to marshal token check data: %w", err)
		}

		// Create a new request
		req, err := http.NewRequest(
			"POST",
			baseEndpoint+"/api/v1/auth/newt/get-token",
			bytes.NewBuffer(jsonData),
		)
		if err != nil {
			return "", fmt.Errorf("failed to create request: %w", err)
		}

		// Set headers
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", "x-csrf-protection")

		// Make the request
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			return "", fmt.Errorf("failed to check token validity: %w", err)
		}
		defer resp.Body.Close()

		var tokenResp TokenResponse
		if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
			return "", fmt.Errorf("failed to decode token check response: %w", err)
		}

		// If token is still valid, return it
		if tokenResp.Success && tokenResp.Message == "Token session already valid" {
			return c.config.Token, nil
		}
	}

	// Get a new token
	tokenData := map[string]interface{}{
		"newtId": c.config.NewtID,
		"secret": c.config.Secret,
	}
	jsonData, err := json.Marshal(tokenData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal token request data: %w", err)
	}

	// Create a new request
	req, err := http.NewRequest(
		"POST",
		baseEndpoint+"/api/v1/auth/newt/get-token",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", "x-csrf-protection")

	// Make the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to request new token: %w", err)
	}
	defer resp.Body.Close()

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		// print out the token response for debugging
		buf := new(bytes.Buffer)
		buf.ReadFrom(resp.Body)
		logger.Info("Token response: %s", buf.String())
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}

	if !tokenResp.Success {
		return "", fmt.Errorf("failed to get token: %s", tokenResp.Message)
	}

	if tokenResp.Data.Token == "" {
		return "", fmt.Errorf("received empty token from server")
	}

	return tokenResp.Data.Token, nil
}

func (c *Client) connectWithRetry() {
	for {
		select {
		case <-c.done:
			return
		default:
			err := c.establishConnection()
			if err != nil {
				logger.Error("Failed to connect: %v. Retrying in %v...", err, c.reconnectInterval)
				time.Sleep(c.reconnectInterval)
				continue
			}
			return
		}
	}
}

func (c *Client) establishConnection() error {
	// Get token for authentication
	token, err := c.getToken()
	if err != nil {
		return fmt.Errorf("failed to get token: %w", err)
	}

	c.onTokenUpdate(token)

	// Parse the base URL to determine protocol and hostname
	baseURL, err := url.Parse(c.baseURL)
	if err != nil {
		return fmt.Errorf("failed to parse base URL: %w", err)
	}

	// Determine WebSocket protocol based on HTTP protocol
	wsProtocol := "wss"
	if baseURL.Scheme == "http" {
		wsProtocol = "ws"
	}

	// Create WebSocket URL
	wsURL := fmt.Sprintf("%s://%s/api/v1/ws", wsProtocol, baseURL.Host)
	u, err := url.Parse(wsURL)
	if err != nil {
		return fmt.Errorf("failed to parse WebSocket URL: %w", err)
	}

	// Add token to query parameters
	q := u.Query()
	q.Set("token", token)
	q.Set("clientType", "newt")
	u.RawQuery = q.Encode()

	// Connect to WebSocket
	conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to connect to WebSocket: %w", err)
	}

	c.conn = conn
	c.setConnected(true)

	// Start the ping monitor
	go c.pingMonitor()
	// Start the read pump
	go c.readPump()

	if c.onConnect != nil {
		err := c.saveConfig()
		if err != nil {
			logger.Error("Failed to save config: %v", err)
		}
		if err := c.onConnect(); err != nil {
			logger.Error("OnConnect callback failed: %v", err)
		}
	}

	return nil
}

func (c *Client) pingMonitor() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			if err := c.conn.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(10*time.Second)); err != nil {
				logger.Error("Ping failed: %v", err)
				c.reconnect()
				return
			}
		}
	}
}

func (c *Client) reconnect() {
	c.setConnected(false)
	if c.conn != nil {
		c.conn.Close()
	}

	go c.connectWithRetry()
}

func (c *Client) setConnected(status bool) {
	c.reconnectMux.Lock()
	defer c.reconnectMux.Unlock()
	c.isConnected = status
}
