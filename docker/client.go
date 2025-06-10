package docker

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/fosrl/newt/logger"
)

// Container represents a Docker container
type Container struct {
	ID       string             `json:"id"`
	Name     string             `json:"name"`
	Image    string             `json:"image"`
	State    string             `json:"state"`
	Status   string             `json:"status"`
	Ports    []Port             `json:"ports"`
	Labels   map[string]string  `json:"labels"`
	Created  int64              `json:"created"`
	Networks map[string]Network `json:"networks"`
}

// Port represents a port mapping for a Docker container
type Port struct {
	PrivatePort int    `json:"privatePort"`
	PublicPort  int    `json:"publicPort,omitempty"`
	Type        string `json:"type"`
	IP          string `json:"ip,omitempty"`
}

// Network represents network information for a Docker container
type Network struct {
	NetworkID           string   `json:"networkId"`
	EndpointID          string   `json:"endpointId"`
	Gateway             string   `json:"gateway,omitempty"`
	IPAddress           string   `json:"ipAddress,omitempty"`
	IPPrefixLen         int      `json:"ipPrefixLen,omitempty"`
	IPv6Gateway         string   `json:"ipv6Gateway,omitempty"`
	GlobalIPv6Address   string   `json:"globalIPv6Address,omitempty"`
	GlobalIPv6PrefixLen int      `json:"globalIPv6PrefixLen,omitempty"`
	MacAddress          string   `json:"macAddress,omitempty"`
	Aliases             []string `json:"aliases,omitempty"`
	DNSNames            []string `json:"dnsNames,omitempty"`
}

// CheckSocket checks if Docker socket is available
func CheckSocket(socketPath string) bool {
	// Use the provided socket path or default to standard location
	if socketPath == "" {
		socketPath = "/var/run/docker.sock"
	}

	// Try to create a connection to the Docker socket
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		logger.Debug("Docker socket not available at %s: %v", socketPath, err)
		return false
	}
	defer conn.Close()

	logger.Debug("Docker socket is available at %s", socketPath)
	return true
}

// IsWithinHostNetwork checks if a provided target is within the host container network
func IsWithinHostNetwork(socketPath string, containerNameAsHostname bool, targetAddress string, targetPort int) (bool, error) {
	// Always enforce network validation
	containers, err := ListContainers(socketPath, true, containerNameAsHostname)
	if err != nil {
		return false, fmt.Errorf("failed to list Docker containers: %s", err)
	}

	// If we can find the passed hostname/ip in the networks or as the container name, it is valid and can add it
	for _, c := range containers {
		for _, network := range c.Networks {
			//If the container name matches, check the ports being mapped too
			if containerNameAsHostname {
				if c.Name == targetAddress {
					for _, port := range c.Ports {
						if port.PublicPort == targetPort || port.PrivatePort == targetPort {
							return true, nil
						}
					}
				}
			} else {
				//If the ip address matches, check the ports being mapped too
				if network.IPAddress == targetAddress {
					for _, port := range c.Ports {
						if port.PublicPort == targetPort || port.PrivatePort == targetPort {
							return true, nil
						}
					}
				}
			}
		}
	}

	combinedTargetAddress := targetAddress + ":" + strconv.Itoa(targetPort)
	return false, fmt.Errorf("target address not within host container network: %s", combinedTargetAddress)
}

// ListContainers lists all Docker containers with their network information
func ListContainers(socketPath string, enforceNetworkValidation bool, containerNameAsHostname bool) ([]Container, error) {
	// Use the provided socket path or default to standard location
	if socketPath == "" {
		socketPath = "/var/run/docker.sock"
	}

	// Create a new Docker client
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Create client with custom socket path
	cli, err := client.NewClientWithOpts(
		client.WithHost("unix://"+socketPath),
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %v", err)
	}
	defer cli.Close()

	// Get the host container
	hostContainer, err := getHostContainer(ctx, cli)
	if err != nil {
		return nil, fmt.Errorf("failed to get host container: %v", err)
	}

	// List containers
	containers, err := cli.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %v", err)
	}

	var dockerContainers []Container
	for _, c := range containers {
		// Short ID like docker ps
		shortId := c.ID[:12]

		// Get container name (remove leading slash)
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}

		// Convert ports
		var ports []Port
		for _, port := range c.Ports {
			dockerPort := Port{
				PrivatePort: int(port.PrivatePort),
				Type:        port.Type,
			}
			if port.PublicPort != 0 {
				dockerPort.PublicPort = int(port.PublicPort)
			}
			if port.IP != "" {
				dockerPort.IP = port.IP
			}
			ports = append(ports, dockerPort)
		}

		// Get network information by inspecting the container
		networks := make(map[string]Network)

		// Inspect the container to get detailed network information
		containerInfo, err := cli.ContainerInspect(ctx, c.ID)
		if err != nil {
			logger.Debug("Failed to inspect container %s (%s) for network info: %v", shortId, name, err)
			// Continue without network info if inspection fails
		} else {
			// Only containers within the host container network will be returned
			isInHostContainerNetwork := false

			// Extract network information from inspection
			if containerInfo.NetworkSettings != nil && containerInfo.NetworkSettings.Networks != nil {
				for networkName, endpoint := range containerInfo.NetworkSettings.Networks {
					// Determine if the current container is in the host container network
					for _, hostContainerNetwork := range hostContainer.NetworkSettings.Networks {
						if !isInHostContainerNetwork {
							isInHostContainerNetwork = endpoint.NetworkID == hostContainerNetwork.NetworkID
						}
					}

					dockerNetwork := Network{
						NetworkID:           endpoint.NetworkID,
						EndpointID:          endpoint.EndpointID,
						Gateway:             endpoint.Gateway,
						IPPrefixLen:         endpoint.IPPrefixLen,
						IPv6Gateway:         endpoint.IPv6Gateway,
						GlobalIPv6Address:   endpoint.GlobalIPv6Address,
						GlobalIPv6PrefixLen: endpoint.GlobalIPv6PrefixLen,
						MacAddress:          endpoint.MacAddress,
						Aliases:             endpoint.Aliases,
						DNSNames:            endpoint.DNSNames,
					}

					// Don't set the IP address if container name is used as hostname
					if !containerNameAsHostname {
						dockerNetwork.IPAddress = endpoint.IPAddress
					}

					networks[networkName] = dockerNetwork
				}
			}

			// Don't continue returning this container if not in the host container network(s)
			if enforceNetworkValidation && !isInHostContainerNetwork {
				logger.Debug("Container not found within the host container network, skipping: %s (%s)", shortId, name)
				continue
			}
		}

		dockerContainer := Container{
			ID:       shortId,
			Name:     name,
			Image:    c.Image,
			State:    c.State,
			Status:   c.Status,
			Ports:    ports,
			Labels:   c.Labels,
			Created:  c.Created,
			Networks: networks,
		}
		dockerContainers = append(dockerContainers, dockerContainer)
	}

	return dockerContainers, nil
}

func getHostContainer(dockerContext context.Context, dockerClient *client.Client) (*container.InspectResponse, error) {
	// Get hostname from the os
	containerHostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("failed to find hostname: %v", err)
	}

	// Get host container from the docker socket
	hostContainer, err := dockerClient.ContainerInspect(dockerContext, containerHostname)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect host container: %v", err)
	}

	return &hostContainer, nil
}