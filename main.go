package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

// Pre-shared list of endpoints.
// In a real system, these would be distributed IP addresses.
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

// Duration of each time slot
const slotDuration = 10 * time.Second

// currentEndpoint calculates which endpoint should be active based on the current time slot.
func currentEndpoint() string {
	// Compute slot based on Unix time divided by slotDuration seconds.
	slot := int(time.Now().Unix() / int64(slotDuration.Seconds()))
	index := slot % len(endpoints)
	return endpoints[index]
}

// runServer starts a listener on every pre-shared endpoint.
// Each listener only processes connections if it matches the active slot.
func runServer() {
	for _, addr := range endpoints {
		go func(address string) {
			ln, err := net.Listen("tcp", address)
			if err != nil {
				log.Printf("Failed to listen on %s: %v", address, err)
				return
			}
			defer ln.Close()
			log.Printf("Server listening on %s", address)
			for {
				conn, err := ln.Accept()
				if err != nil {
					log.Printf("Error accepting on %s: %v", address, err)
					continue
				}
				go handleConnection(conn, address)
			}
		}(addr)
	}
	// Keep the server running indefinitely.
	select {}
}

// handleConnection processes a connection.
// It first checks if the connection arrived on the expected active endpoint.
func handleConnection(conn net.Conn, listeningAddress string) {
	defer conn.Close()

	// Determine what the active endpoint should be.
	active := currentEndpoint()
	if active != listeningAddress {
		log.Printf("Connection on inactive endpoint %s (active: %s). Closing connection.", listeningAddress, active)
		return
	}

	// Read incoming data.
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Printf("Error reading from connection: %v", err)
		return
	}
	data := buffer[:n]
	log.Printf("Received on %s: %s", listeningAddress, string(data))

	// For demonstration, echo the received data back to the client.
	_, err = conn.Write([]byte(fmt.Sprintf("Echo: %s", data)))
	if err != nil {
		log.Printf("Error writing response: %v", err)
	}
}

// runClient computes the active endpoint and connects to it to send a message.
func runClient(message string) {
	for {
		activeEndpoint := currentEndpoint()
		log.Printf("Client using endpoint %s", activeEndpoint)
		conn, err := net.Dial("tcp", activeEndpoint)
		if err != nil {
			log.Printf("Failed to connect to %s: %v. Retrying...", activeEndpoint, err)
			time.Sleep(2 * time.Second)
			continue
		}

		// Send the message.
		_, err = conn.Write([]byte(message))
		if err != nil {
			log.Printf("Failed to send message: %v", err)
			conn.Close()
			continue
		}

		// Receive and print the server's response.
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
	// Expect a command-line argument to run as "server" or "client".
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go server|client [message]")
		return
	}
	mode := os.Args[1]
	if mode == "server" {
		runServer()
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
