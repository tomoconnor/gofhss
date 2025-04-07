package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"time"
)

// Pre-shared list of endpoints.
var endpoints = []string{
	"127.0.0.1:8001",
	"127.0.0.1:8002",
	"127.0.0.1:8003",
	"127.0.0.1:8004",
	"127.0.0.1:8005",
	"127.0.0.1:8006",
	"127.0.0.1:8007",
	"127.0.0.1:8008", // lol boob
	"127.0.0.1:8009",
	"127.0.0.1:8010",
}

// Duration of each time slot.
const slotDuration = 10 * time.Second

// Global variable for client's clock offset (client's adjusted time relative to server).
var clientTimeOffset time.Duration

// currentEndpoint calculates the active endpoint using the server's local clock.
func currentEndpoint() string {
	slot := int(time.Now().Unix() / int64(slotDuration.Seconds()))
	index := slot % len(endpoints)
	return endpoints[index]
}

// currentClientEndpoint calculates the active endpoint for the client using its synchronized clock.
func currentClientEndpoint() string {
	effectiveTime := time.Now().Add(clientTimeOffset)
	slot := int(effectiveTime.Unix() / int64(slotDuration.Seconds()))
	index := slot % len(endpoints)
	return endpoints[index]
}

// loadServerTLSConfig loads the TLS configuration for the server using certificate files.
func loadServerTLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		return nil, err
	}
	// Optionally, you can set more TLS config options here.
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}, nil
}

// runServerSwitching listens on only the active endpoint using TLS, then switches when the time slot expires.
func runServerSwitching() {
	tlsConfig, err := loadServerTLSConfig()
	if err != nil {
		log.Fatalf("Failed to load TLS configuration: %v", err)
	}

	for {
		activeEndpoint := currentEndpoint()
		log.Printf("Switching to active endpoint: %s", activeEndpoint)
		ln, err := tls.Listen("tcp", activeEndpoint, tlsConfig)
		if err != nil {
			log.Printf("Failed to listen on %s: %v", activeEndpoint, err)
			time.Sleep(2 * time.Second)
			continue
		}

		now := time.Now()
		slotSeconds := int64(slotDuration.Seconds())
		currentSlot := now.Unix() / slotSeconds
		nextSlotStart := (currentSlot + 1) * slotSeconds
		timeUntilSwitch := time.Until(time.Unix(nextSlotStart, 0))
		log.Printf("Listening on %s for %v", activeEndpoint, timeUntilSwitch)

		// done signals when the current time slot is over.
		done := make(chan struct{})

		// Accept connections concurrently until the time slot is over.
		go func() {
			for {
				// Set a short deadline to allow periodic checks of the done channel.
				if tcpListener, ok := ln.(*net.TCPListener); ok {
					tcpListener.SetDeadline(time.Now().Add(1 * time.Second))
				}
				conn, err := ln.Accept()
				if err != nil {
					if errors.Is(err, net.ErrClosed) {
						return
					}
					if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
						select {
						case <-done:
							return
						default:
							continue
						}
					}
					log.Printf("Error accepting connection: %v", err)
					continue
				}
				go handleConnection(conn, activeEndpoint)
			}
		}()

		time.Sleep(timeUntilSwitch)
		close(done)
		ln.Close()
		log.Printf("Switching from endpoint %s", activeEndpoint)
	}
}

// handleConnection processes an incoming TLS connection.
// It responds to a "SYNC" command with the current Unix timestamp or echoes received messages.
func handleConnection(conn net.Conn, listeningAddress string) {
	defer conn.Close()

	// Optionally verify that the connection is on the expected active endpoint.
	if listeningAddress != currentEndpoint() {
		log.Printf("Connection on inactive endpoint %s, expected %s. Closing.", listeningAddress, currentEndpoint())
		return
	}

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Printf("Error reading from connection: %v", err)
		return
	}
	msg := string(buffer[:n])
	if msg == "SYNC" {
		now := time.Now().Unix()
		_, err := conn.Write([]byte(fmt.Sprintf("%d", now)))
		if err != nil {
			log.Printf("Failed to send SYNC response: %v", err)
		} else {
			log.Printf("Processed SYNC request on %s", listeningAddress)
		}
		return
	}
	log.Printf("Received on %s: %s", listeningAddress, msg)
	_, err = conn.Write([]byte(fmt.Sprintf("Echo: %s", msg)))
	if err != nil {
		log.Printf("Error writing response: %v", err)
	}
}

// syncClock performs a clock synchronization handshake with the server over TLS.
// It sends a "SYNC" request and computes an offset based on the server's timestamp.
func syncClock() {
	for {
		activeEndpoint := currentEndpoint() // initial guess based on local time
		log.Printf("Attempting clock sync with endpoint %s", activeEndpoint)
		conn, err := tls.Dial("tcp", activeEndpoint, &tls.Config{
			// For demonstration purposes only; in production, verify the server's certificate.
			InsecureSkipVerify: true,
		})
		if err != nil {
			log.Printf("Clock sync: failed to connect to %s: %v. Retrying...", activeEndpoint, err)
			time.Sleep(2 * time.Second)
			continue
		}
		start := time.Now()
		_, err = conn.Write([]byte("SYNC"))
		if err != nil {
			log.Printf("Clock sync: failed to send SYNC: %v", err)
			conn.Close()
			continue
		}
		buffer := make([]byte, 64)
		n, err := conn.Read(buffer)
		if err != nil {
			log.Printf("Clock sync: failed to read response: %v", err)
			conn.Close()
			continue
		}
		serverTimeStr := string(buffer[:n])
		serverUnix, err := strconv.ParseInt(serverTimeStr, 10, 64)
		if err != nil {
			log.Printf("Clock sync: failed to parse server time: %v", err)
			conn.Close()
			continue
		}
		rtt := time.Since(start)
		estimatedServerTime := time.Unix(serverUnix, 0)
		estimatedOffset := estimatedServerTime.Sub(time.Now().Add(rtt / 2))
		clientTimeOffset = estimatedOffset
		log.Printf("Clock sync successful. Estimated offset: %v", clientTimeOffset)
		conn.Close()
		break
	}
}

// runClient performs clock sync over TLS, then connects using TLS to the synchronized active endpoint.
func runClient(message string) {
	syncClock()

	for {
		activeEndpoint := currentClientEndpoint()
		log.Printf("Client connecting to endpoint %s", activeEndpoint)
		conn, err := tls.Dial("tcp", activeEndpoint, &tls.Config{
			// In production, proper certificate verification should be implemented.
			InsecureSkipVerify: true,
		})
		if err != nil {
			log.Printf("Failed to connect to %s: %v. Retrying...", activeEndpoint, err)
			time.Sleep(2 * time.Second)
			continue
		}

		_, err = conn.Write([]byte(message))
		if err != nil {
			log.Printf("Failed to send message: %v", err)
			conn.Close()
			continue
		}

		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err != nil {
			log.Printf("Failed to read response: %v", err)
			conn.Close()
			continue
		}
		log.Printf("Received response: %s", string(buffer[:n]))
		conn.Close()
		break
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go server|client [message]")
		return
	}
	mode := os.Args[1]
	if mode == "server" {
		runServerSwitching()
	} else if mode == "client" {
		if len(os.Args) < 3 {
			fmt.Println("Usage: go run main.go client [message]")
			return
		}
		message := os.Args[2]
		runClient(message)
	} else {
		fmt.Println("Unknown mode. Use 'server' or 'client'.")
	}
}
