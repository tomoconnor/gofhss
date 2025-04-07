package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
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

// Shared secret used to derive the pseudorandom endpoint sequence.
// Both client and server must use the same secret.
var sharedSecret = "my_shared_secret"

// currentEndpointWithSecret computes the active endpoint using the given time (t) and a pseudorandom
// sequence derived from the shared secret. It takes the current time slot (t divided by the slot duration),
// feeds it through an HMAC-SHA256 function with the shared secret, and uses the result to pick an endpoint.
func currentEndpointWithSecret(t time.Time) string {
	slot := t.Unix() / int64(slotDuration.Seconds())
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(slot))
	mac := hmac.New(sha256.New, []byte(sharedSecret))
	mac.Write(buf)
	hash := mac.Sum(nil)
	idx := int(binary.BigEndian.Uint32(hash[:4])) % len(endpoints)
	return endpoints[idx]
}

// currentEndpoint returns the server's active endpoint based on its local clock.
func currentEndpoint() string {
	return currentEndpointWithSecret(time.Now())
}

// currentClientEndpoint returns the client's active endpoint using the synchronized clock.
func currentClientEndpoint() string {
	return currentEndpointWithSecret(time.Now().Add(clientTimeOffset))
}

// loadServerTLSConfig loads the TLS configuration for the server using certificate files.
func loadServerTLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		return nil, err
	}
	// Additional TLS config options can be set here.
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
					// Use errors.Is to check if the listener was closed.
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
		activeEndpoint := currentEndpoint() // initial guess based on local time and secret
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

func robustSyncClock(rounds int) {
	var offsets []time.Duration
	for i := 0; i < rounds; i++ {
		activeEndpoint := currentEndpoint() // initial guess based on local time
		conn, err := tls.Dial("tcp", activeEndpoint, &tls.Config{
			InsecureSkipVerify: true,
		})
		if err != nil {
			log.Printf("Clock sync round %d: failed to connect: %v", i, err)
			time.Sleep(1 * time.Second)
			continue
		}
		start := time.Now()
		_, err = conn.Write([]byte("SYNC"))
		if err != nil {
			conn.Close()
			continue
		}
		buffer := make([]byte, 64)
		n, err := conn.Read(buffer)
		if err != nil {
			conn.Close()
			continue
		}
		serverUnix, err := strconv.ParseInt(string(buffer[:n]), 10, 64)
		if err != nil {
			conn.Close()
			continue
		}
		rtt := time.Since(start)
		estimatedServerTime := time.Unix(serverUnix, 0)
		offset := estimatedServerTime.Sub(time.Now().Add(rtt / 2))
		offsets = append(offsets, offset)
		conn.Close()
		time.Sleep(500 * time.Millisecond)
	}
	if len(offsets) == 0 {
		log.Println("Failed to sync clock")
		return
	}
	var sum time.Duration
	for _, off := range offsets {
		sum += off
	}
	clientTimeOffset = sum / time.Duration(len(offsets))
	log.Printf("Robust clock sync successful. Estimated offset: %v", clientTimeOffset)
}

// runClient performs clock sync over TLS, then connects using TLS to the synchronized active endpoint.
func runClient(message string) {
	robustSyncClock(5) // Perform robust clock sync
	//syncClock()

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
