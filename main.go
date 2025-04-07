// main.go
//
// Copyright (C) 2025 T O'Connor.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/agpl-3.0.html>.
//

package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Pre-shared list of endpoints.
// In a real-world scenario, these would be securely managed and not hardcoded.
// This is just for demonstration purposes.
// The endpoints are expected to be reachable and listening on the specified ports.
// In a production environment, you would typically use a more secure method to manage endpoints.
// For example, you might use a service discovery mechanism or a secure configuration management system.

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
// In a real-world scenario, this should be securely managed and not hardcoded.
// This is just for demonstration purposes.
var sharedSecret = "my_shared_secret"

// Flags to enable optional features.
var enableRobustSync bool
var enableTimestamped bool
var enableChallenge bool

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

// currentEndpoint returns the server's active endpoint using its local clock.
func currentEndpoint() string {
	return currentEndpointWithSecret(time.Now())
}

// currentClientEndpoint returns the client's active endpoint using the synchronized clock.
func currentClientEndpoint() string {
	return currentEndpointWithSecret(time.Now().Add(clientTimeOffset))
}

// loadServerTLSConfig loads the TLS configuration for the server.
// In a production environment, you would typically use a more secure method to manage certificates.
// For example, you might use a certificate management service or a secure configuration management system.
func loadServerTLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}, nil
}

// runServerSwitching listens on only the active endpoint using TLS and switches endpoints when the time slot expires.
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
// It performs challenge–response and timestamp verification if enabled.
func handleConnection(conn net.Conn, listeningAddress string) {
	defer conn.Close()

	// Verify that the connection is arriving on the active endpoint.
	if listeningAddress != currentEndpoint() {
		log.Printf("Connection on inactive endpoint %s, expected %s. Closing.", listeningAddress, currentEndpoint())
		return
	}

	// Challenge–response handshake.
	if enableChallenge {
		nonce := make([]byte, 16)
		_, err := rand.Read(nonce)
		if err != nil {
			log.Printf("Failed to generate challenge nonce: %v", err)
			return
		}
		nonceStr := hex.EncodeToString(nonce)
		challengeMsg := "CHALLENGE:" + nonceStr
		_, err = conn.Write([]byte(challengeMsg))
		if err != nil {
			log.Printf("Failed to send challenge: %v", err)
			return
		}
		buffer := make([]byte, 128)
		n, err := conn.Read(buffer)
		if err != nil {
			log.Printf("Failed to read challenge response: %v", err)
			return
		}
		response := string(buffer[:n])
		mac := hmac.New(sha256.New, []byte(sharedSecret))
		mac.Write(nonce)
		expected := hex.EncodeToString(mac.Sum(nil))
		if response != "RESPONSE:"+expected {
			log.Printf("Invalid challenge response. Expected RESPONSE:%s, got %s", expected, response)
			return
		}
		log.Printf("Challenge response verified.")
	}

	// Read the incoming message.
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Printf("Error reading from connection: %v", err)
		return
	}
	msg := string(buffer[:n])

	// If timestamped messages are enabled, verify the timestamp.
	if enableTimestamped {
		parts := strings.SplitN(msg, "|", 2)
		if len(parts) != 2 {
			log.Printf("Invalid timestamped message format.")
			return
		}
		tsPart := parts[0]
		msgPart := parts[1]
		if !strings.HasPrefix(tsPart, "TIMESTAMP:") {
			log.Printf("Invalid timestamp prefix.")
			return
		}
		tsStr := strings.TrimPrefix(tsPart, "TIMESTAMP:")
		tsInt, err := strconv.ParseInt(tsStr, 10, 64)
		if err != nil {
			log.Printf("Invalid timestamp: %v", err)
			return
		}
		msgTime := time.Unix(tsInt, 0)
		if absDuration(time.Since(msgTime)) > 15*time.Second {
			log.Printf("Timestamp out of acceptable range. Message time: %v, server time: %v", msgTime, time.Now())
			return
		}
		msg = msgPart
	}

	// Handle a clock sync request.
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

// absDuration returns the absolute value of a duration.
func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// syncClock performs a single round of clock synchronization.
func syncClock() {
	for {
		activeEndpoint := currentEndpoint()
		log.Printf("Attempting clock sync with endpoint %s", activeEndpoint)
		conn, err := tls.Dial("tcp", activeEndpoint, &tls.Config{InsecureSkipVerify: true})
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
		clientTimeOffset = estimatedServerTime.Sub(time.Now().Add(rtt / 2))
		log.Printf("Clock sync successful. Estimated offset: %v", clientTimeOffset)
		conn.Close()
		break
	}
}

// robustSyncClock performs multiple rounds of synchronization and averages the offsets.
func robustSyncClock(rounds int) {
	var offsets []time.Duration
	for i := 0; i < rounds; i++ {
		activeEndpoint := currentEndpoint()
		conn, err := tls.Dial("tcp", activeEndpoint, &tls.Config{InsecureSkipVerify: true})
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
		log.Println("Failed to sync clock robustly")
		return
	}
	var sum time.Duration
	for _, off := range offsets {
		sum += off
	}
	clientTimeOffset = sum / time.Duration(len(offsets))
	log.Printf("Robust clock sync successful. Estimated offset: %v", clientTimeOffset)
}

// runClient performs clock synchronization and sends a message over TLS.
func runClient(message string) {
	if enableRobustSync {
		robustSyncClock(5)
	} else {
		syncClock()
	}

	for {
		activeEndpoint := currentClientEndpoint()
		dialer := &net.Dialer{
			Timeout: 5 * time.Second,
		}

		log.Printf("Client connecting to endpoint %s", activeEndpoint)
		conn, err := tls.DialWithDialer(dialer, "tcp", activeEndpoint, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			log.Printf("Failed to connect to %s: %v. Retrying...", activeEndpoint, err)
			time.Sleep(2 * time.Second)
			continue
		}
		log.Printf("Connected to %s", activeEndpoint)

		// Challenge–response handshake.
		if enableChallenge {
			log.Printf("Performing challenge-response handshake.")
			buffer := make([]byte, 128)
			n, err := conn.Read(buffer)
			if err != nil {
				log.Printf("Failed to read challenge: %v", err)
				conn.Close()
				continue
			}
			challengeMsg := string(buffer[:n])
			if !strings.HasPrefix(challengeMsg, "CHALLENGE:") {
				log.Printf("Expected challenge message, got: %s", challengeMsg)
				conn.Close()
				continue
			}
			nonceStr := strings.TrimPrefix(challengeMsg, "CHALLENGE:")
			nonce, err := hex.DecodeString(nonceStr)
			if err != nil {
				log.Printf("Invalid challenge nonce: %v", err)
				conn.Close()
				continue
			}
			mac := hmac.New(sha256.New, []byte(sharedSecret))
			mac.Write(nonce)
			response := "RESPONSE:" + hex.EncodeToString(mac.Sum(nil))
			_, err = conn.Write([]byte(response))
			if err != nil {
				log.Printf("Failed to send challenge response: %v", err)
				conn.Close()
				continue
			}
			log.Printf("Challenge response sent.")

			// Check if the endpoint is still the same.
			// If the active endpoint has changed during the handshake,
			// abort and retry.
			if currentClientEndpoint() != activeEndpoint {
				log.Printf("Endpoint changed during challenge handshake. Aborting connection.")
				conn.Close()
				continue
			}
		}

		// If timestamped messages are enabled, prepend a timestamp.
		if enableTimestamped {
			timestamp := time.Now().Unix()
			message = fmt.Sprintf("TIMESTAMP:%d|MSG:%s", timestamp, message)
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
	mode := flag.String("mode", "", "server or client")
	msg := flag.String("msg", "", "Message for client mode")
	robustFlag := flag.Bool("robust", false, "Enable robust clock sync")
	timestampFlag := flag.Bool("timestamp", false, "Enable timestamped messages")
	challengeFlag := flag.Bool("challenge", false, "Enable challenge-response authentication")
	flag.Parse()

	enableRobustSync = *robustFlag
	enableTimestamped = *timestampFlag
	enableChallenge = *challengeFlag

	if *mode == "server" {
		runServerSwitching()
	} else if *mode == "client" {
		if *msg == "" {
			fmt.Println("Usage: -mode=client -msg='your message'")
			os.Exit(1)
		}
		runClient(*msg)
	} else {
		fmt.Println("Usage: -mode=server or -mode=client")
	}
}
