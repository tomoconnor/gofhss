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

// Global variable for client's clock offset.
var clientTimeOffset time.Duration

// Shared secret used for the pseudorandom endpoint selection and challenge–response.
var sharedSecret = "my_shared_secret"

// Feature flags.
var enableRobustSync bool
var enableTimestamped bool
var enableChallenge bool

// currentEndpointWithSecret computes the active endpoint using an HMAC over the current time slot.
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

// currentEndpoint returns the server's active endpoint.
func currentEndpoint() string {
	return currentEndpointWithSecret(time.Now())
}

// currentClientEndpoint returns the client's active endpoint (adjusted by sync offset).
func currentClientEndpoint() string {
	return currentEndpointWithSecret(time.Now().Add(clientTimeOffset))
}

// loadServerTLSConfig loads TLS certificates.
func loadServerTLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}

// runServerSwitching listens on the active endpoint via TLS and switches endpoints when the slot expires.
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

		done := make(chan struct{})
		go func() {
			for {
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

// handleConnection processes one incoming TLS connection.
// It reads one composite message and decides what to do based on its fields.
// If challenge mode is enabled, the server first sends a challenge and then waits for a composite message
// that must include a "RESPONSE" field along with other fields.
func handleConnection(conn net.Conn, listeningAddress string) {
	defer conn.Close()

	if listeningAddress != currentEndpoint() {
		log.Printf("Connection on inactive endpoint %s, expected %s. Closing.", listeningAddress, currentEndpoint())
		return
	}

	var compositeMsg string
	if enableChallenge {
		// Send challenge.
		nonce := make([]byte, 16)
		if _, err := rand.Read(nonce); err != nil {
			log.Printf("Failed to generate challenge nonce: %v", err)
			return
		}
		nonceStr := hex.EncodeToString(nonce)
		challengeMsg := "CHALLENGE:" + nonceStr
		if _, err := conn.Write([]byte(challengeMsg)); err != nil {
			log.Printf("Failed to send challenge: %v", err)
			return
		}

		// Now read a composite message that must include a RESPONSE field.
		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err != nil {
			log.Printf("Failed to read composite message after challenge: %v", err)
			return
		}
		compositeMsg = string(buffer[:n])
		log.Printf("Raw composite message: %s", compositeMsg)

		// Parse composite message.
		parts := strings.Split(compositeMsg, "|")
		var responseField, timestampField, msgField, syncField string
		for _, part := range parts {
			part = strings.TrimSpace(part)
			switch {
			case strings.HasPrefix(part, "RESPONSE:"):
				responseField = strings.TrimPrefix(part, "RESPONSE:")
			case strings.HasPrefix(part, "TIMESTAMP:"):
				timestampField = strings.TrimPrefix(part, "TIMESTAMP:")
			case strings.HasPrefix(part, "MSG:"):
				msgField = strings.TrimPrefix(part, "MSG:")
			case strings.HasPrefix(part, "CLOCKSYNC"):
				syncField = "CLOCKSYNC"
			}
		}

		// Verify challenge response.
		mac := hmac.New(sha256.New, []byte(sharedSecret))
		mac.Write(nonce)
		expected := hex.EncodeToString(mac.Sum(nil))
		if responseField != expected {
			log.Printf("Invalid challenge response. Expected RESPONSE:%s, got RESPONSE:%s", expected, responseField)
			return
		}
		log.Printf("Challenge response verified.")

		// If this composite message is merely a clock sync request, process it.
		if syncField == "CLOCKSYNC" {
			now := time.Now().Unix()
			if _, err := conn.Write([]byte(fmt.Sprintf("%d", now))); err != nil {
				log.Printf("Failed to send CLOCKSYNC response: %v", err)
			} else {
				log.Printf("Processed CLOCKSYNC request on %s", listeningAddress)
			}
			return
		}

		// In challenge mode, we expect at least a MSG field.
		if enableTimestamped {
			if timestampField == "" {
				log.Printf("Timestamp field missing in composite message.")
				return
			}
			tsInt, err := strconv.ParseInt(timestampField, 10, 64)
			if err != nil {
				log.Printf("Invalid timestamp: %v", err)
				return
			}
			msgTime := time.Unix(tsInt, 0)
			if absDuration(time.Since(msgTime)) > 15*time.Second {
				log.Printf("Timestamp out of acceptable range. Message time: %v, server time: %v", msgTime, time.Now())
				return
			}
		}

		if msgField == "" {
			log.Printf("MSG field missing in composite message.")
			return
		}

		log.Printf("Received on %s: %s", listeningAddress, msgField)
		if _, err := conn.Write([]byte(fmt.Sprintf("Echo: %s", msgField))); err != nil {
			log.Printf("Error writing echo response: %v", err)
		}
	} else {
		// Non-challenge mode: read composite message.
		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err != nil {
			log.Printf("Error reading composite message: %v", err)
			return
		}
		compositeMsg = string(buffer[:n])
		log.Printf("Raw composite message: %s", compositeMsg)
		parts := strings.Split(compositeMsg, "|")
		var timestampField, msgField, syncField string
		for _, part := range parts {
			part = strings.TrimSpace(part)
			switch {
			case strings.HasPrefix(part, "TIMESTAMP:"):
				timestampField = strings.TrimPrefix(part, "TIMESTAMP:")
			case strings.HasPrefix(part, "MSG:"):
				msgField = strings.TrimPrefix(part, "MSG:")
			case strings.HasPrefix(part, "CLOCKSYNC"):
				syncField = "CLOCKSYNC"
			}
		}
		if syncField == "CLOCKSYNC" {
			now := time.Now().Unix()
			if _, err := conn.Write([]byte(fmt.Sprintf("%d", now))); err != nil {
				log.Printf("Failed to send CLOCKSYNC response: %v", err)
			} else {
				log.Printf("Processed CLOCKSYNC request on %s", listeningAddress)
			}
			return
		}
		if enableTimestamped {
			if timestampField == "" {
				log.Printf("Timestamp field missing in composite message.")
				return
			}
			tsInt, err := strconv.ParseInt(timestampField, 10, 64)
			if err != nil {
				log.Printf("Invalid timestamp: %v", err)
				return
			}
			msgTime := time.Unix(tsInt, 0)
			if absDuration(time.Since(msgTime)) > 15*time.Second {
				log.Printf("Timestamp out of acceptable range. Message time: %v, server time: %v", msgTime, time.Now())
				return
			}
		}
		if msgField == "" {
			msgField = compositeMsg
		}
		log.Printf("Received on %s: %s", listeningAddress, msgField)
		if _, err := conn.Write([]byte(fmt.Sprintf("Echo: %s", msgField))); err != nil {
			log.Printf("Error writing echo response: %v", err)
		}
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
// If timestamped messages are enabled, the client sends a composite message: TIMESTAMP and CLOCKSYNC.
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

		var syncMsg string
		if enableChallenge {
			// Read challenge from server
			buffer := make([]byte, 128)
			n, err := conn.Read(buffer)
			if err != nil {
				log.Printf("Clock sync: failed to read challenge: %v", err)
				conn.Close()
				continue
			}
			challengeMsg := string(buffer[:n])
			if !strings.HasPrefix(challengeMsg, "CHALLENGE:") {
				log.Printf("Clock sync: expected challenge message, got: %s", challengeMsg)
				conn.Close()
				continue
			}
			nonceStr := strings.TrimPrefix(challengeMsg, "CHALLENGE:")
			nonce, err := hex.DecodeString(nonceStr)
			if err != nil {
				log.Printf("Clock sync: invalid challenge nonce: %v", err)
				conn.Close()
				continue
			}
			mac := hmac.New(sha256.New, []byte(sharedSecret))
			mac.Write(nonce)
			responseVal := hex.EncodeToString(mac.Sum(nil))

			if enableTimestamped {
				syncMsg = fmt.Sprintf("RESPONSE:%s|TIMESTAMP:%d|CLOCKSYNC", responseVal, time.Now().Unix())
			} else {
				syncMsg = fmt.Sprintf("RESPONSE:%s|CLOCKSYNC", responseVal)
			}
		} else {
			if enableTimestamped {
				syncMsg = fmt.Sprintf("TIMESTAMP:%d|CLOCKSYNC", time.Now().Unix())
			} else {
				syncMsg = "CLOCKSYNC"
			}
		}

		_, err = conn.Write([]byte(syncMsg))
		if err != nil {
			log.Printf("Clock sync: failed to send sync message: %v", err)
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
		serverTimeStr := strings.TrimSpace(string(buffer[:n]))
		serverUnix, err := strconv.ParseInt(serverTimeStr, 10, 64)
		if err != nil {
			log.Printf("Clock sync: failed to parse server time: %v", err)
			conn.Close()
			continue
		}
		rtt := time.Since(time.Now()) // RTT measurement here is approximate.
		estimatedServerTime := time.Unix(serverUnix, 0)
		clientTimeOffset = estimatedServerTime.Sub(time.Now().Add(rtt / 2))
		log.Printf("Clock sync successful. Estimated offset: %v", clientTimeOffset)
		conn.Close()
		break
	}
}

// robustSyncClock performs multiple rounds of clock synchronization.
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

		var syncMsg string
		if enableChallenge {
			// Read challenge from server
			buffer := make([]byte, 128)
			n, err := conn.Read(buffer)
			if err != nil {
				log.Printf("Clock sync round %d: failed to read challenge: %v", i, err)
				conn.Close()
				continue
			}
			challengeMsg := string(buffer[:n])
			if !strings.HasPrefix(challengeMsg, "CHALLENGE:") {
				log.Printf("Clock sync round %d: expected challenge message, got: %s", i, challengeMsg)
				conn.Close()
				continue
			}
			nonceStr := strings.TrimPrefix(challengeMsg, "CHALLENGE:")
			nonce, err := hex.DecodeString(nonceStr)
			if err != nil {
				log.Printf("Clock sync round %d: invalid challenge nonce: %v", i, err)
				conn.Close()
				continue
			}
			mac := hmac.New(sha256.New, []byte(sharedSecret))
			mac.Write(nonce)
			responseVal := hex.EncodeToString(mac.Sum(nil))

			if enableTimestamped {
				syncMsg = fmt.Sprintf("RESPONSE:%s|TIMESTAMP:%d|CLOCKSYNC", responseVal, time.Now().Unix())
			} else {
				syncMsg = fmt.Sprintf("RESPONSE:%s|CLOCKSYNC", responseVal)
			}
		} else {
			if enableTimestamped {
				syncMsg = fmt.Sprintf("TIMESTAMP:%d|CLOCKSYNC", time.Now().Unix())
			} else {
				syncMsg = "CLOCKSYNC"
			}
		}

		start := time.Now()
		_, err = conn.Write([]byte(syncMsg))
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
		serverUnix, err := strconv.ParseInt(strings.TrimSpace(string(buffer[:n])), 10, 64)
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
// In challenge mode, the composite message sent includes a RESPONSE field (from the challenge)
// in addition to TIMESTAMP (if enabled) and MSG.
func runClient(message string) {
	if enableRobustSync {
		robustSyncClock(5)
	} else {
		syncClock()
	}

	for {
		activeEndpoint := currentClientEndpoint()
		dialer := &net.Dialer{Timeout: 5 * time.Second}

		log.Printf("Client connecting to endpoint %s", activeEndpoint)
		conn, err := tls.DialWithDialer(dialer, "tcp", activeEndpoint, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			log.Printf("Failed to connect to %s: %v. Retrying...", activeEndpoint, err)
			time.Sleep(2 * time.Second)
			continue
		}
		log.Printf("Connected to %s", activeEndpoint)

		var compositeMsg string
		if enableChallenge {
			// Read challenge from server.
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
			responseVal := hex.EncodeToString(mac.Sum(nil))
			if enableTimestamped {
				compositeMsg = fmt.Sprintf("RESPONSE:%s|TIMESTAMP:%d|MSG:%s", responseVal, time.Now().Unix(), message)
			} else {
				compositeMsg = fmt.Sprintf("RESPONSE:%s|MSG:%s", responseVal, message)
			}
		} else {
			if enableTimestamped {
				compositeMsg = fmt.Sprintf("TIMESTAMP:%d|MSG:%s", time.Now().Unix(), message)
			} else {
				compositeMsg = fmt.Sprintf("MSG:%s", message)
			}
		}

		if _, err := conn.Write([]byte(compositeMsg)); err != nil {
			log.Printf("Failed to send composite message: %v", err)
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
