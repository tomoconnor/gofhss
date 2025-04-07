package main

import (
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

// currentEndpoint computes the active endpoint using the server's local clock.
func currentEndpoint() string {
	slot := int(time.Now().Unix() / int64(slotDuration.Seconds()))
	index := slot % len(endpoints)
	return endpoints[index]
}

// currentClientEndpoint computes the active endpoint for the client using its synchronized clock.
func currentClientEndpoint() string {
	effectiveTime := time.Now().Add(clientTimeOffset)
	slot := int(effectiveTime.Unix() / int64(slotDuration.Seconds()))
	index := slot % len(endpoints)
	return endpoints[index]
}

// runServerSwitching listens on the active endpoint only for the duration of the current time slot.
// When the time slot expires, the listener is closed and the server switches to the next endpoint.
func runServerSwitching() {
	for {
		activeEndpoint := currentEndpoint()
		log.Printf("Switching to active endpoint: %s", activeEndpoint)
		ln, err := net.Listen("tcp", activeEndpoint)
		if err != nil {
			log.Printf("Failed to listen on %s: %v", activeEndpoint, err)
			time.Sleep(2 * time.Second)
			continue
		}

		// Compute how long to listen: until the next time slot boundary.
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
					// Check if the error is due to the listener being closed.
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

		// Wait for the time slot to end.
		time.Sleep(timeUntilSwitch)
		close(done)
		ln.Close()
		log.Printf("Switching from endpoint %s", activeEndpoint)
	}
}

// handleConnection processes an incoming connection.
// It supports a clock sync request ("SYNC") or echoes back any received message.
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

// syncClock performs a clock synchronization handshake with the server.
// The client sends a "SYNC" request and computes an offset based on the server's time and measured RTT.
func syncClock() {
	for {
		activeEndpoint := currentEndpoint() // initial guess based on local time
		log.Printf("Attempting clock sync with endpoint %s", activeEndpoint)
		conn, err := net.Dial("tcp", activeEndpoint)
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
		// Calculate round-trip time (RTT) and estimate network delay (half of RTT).
		rtt := time.Since(start)
		estimatedServerTime := time.Unix(serverUnix, 0)
		estimatedOffset := estimatedServerTime.Sub(time.Now().Add(rtt / 2))
		clientTimeOffset = estimatedOffset
		log.Printf("Clock sync successful. Estimated offset: %v", clientTimeOffset)
		conn.Close()
		break
	}
}

// runClient first synchronizes the clock, then computes the active endpoint using the offset,
// and finally connects to that endpoint to send its message.
func runClient(message string) {
	syncClock()

	for {
		activeEndpoint := currentClientEndpoint()
		log.Printf("Client connecting to endpoint %s", activeEndpoint)
		conn, err := net.Dial("tcp", activeEndpoint)
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
