# Endpoint-Hopping Client-Server with TLS, Pseudorandom Endpoint Selection, and Optional Features

This project is a proof-of-concept client-server application designed to improve resistance to interception by dynamically switching network endpoints—similar to Frequency Hopping Spread Spectrum (FHSS). It features:

- **Endpoint Hopping:** Switching between a predefined list of endpoints at fixed time intervals.
- **Pseudorandom Endpoint Selection:** Both client and server derive the active endpoint using an HMAC-SHA256 algorithm with a shared secret.
- **Dynamic Listener Switching:** The server binds only to the active endpoint for each time slot and re-binds when the slot expires.
- **Clock Synchronization:** A basic SYNC handshake (with an option for robust, multi-round sync) to align the clocks of the client and server.
- **TLS Encryption with Connection Timeouts:** All communications are secured with TLS. The client uses `tls.DialWithDialer` to enforce connection timeouts.
- **Optional Challenge–Response Authentication:** Adds an extra layer of authentication using a unique challenge nonce for every new connection. If an endpoint switch occurs during the handshake, the connection aborts and a new challenge is generated on the next attempt.
- **Optional Timestamped Messages:** Ensures message freshness by including a timestamp with each message, which the server verifies to prevent replay attacks.

## Features

- **Endpoint Hopping:**  
  Uses a list of endpoints (e.g., `127.0.0.1:8001` to `127.0.0.1:8010`) and changes the active endpoint every fixed time slot (default: 10 seconds).

- **Pseudorandom Endpoint Selection:**  
  The active endpoint for each time slot is computed by hashing the time slot (derived from the current time) using HMAC-SHA256 with a shared secret. Only entities possessing the secret can predict the hopping sequence.

- **Dynamic Listener Switching:**  
  The server binds exclusively to the active endpoint for the duration of a time slot, then re-binds as the slot changes—making interception more challenging.

- **Clock Synchronization:**  
  The client aligns its clock with the server using a SYNC handshake over TLS. Optionally, multiple synchronization rounds can be performed to average out network latency.

- **TLS Connection Timeout:**  
  The client leverages `tls.DialWithDialer` with a configurable timeout (for example, 5 seconds) to ensure that slow connections (potentially caused by endpoint switching) are aborted and retried.

- **Optional Challenge–Response Authentication:**  
  When enabled, the server generates a new random nonce for each new TLS connection and sends it as part of a challenge. The client must respond with a correct HMAC value (using the shared secret) before the connection proceeds. If an endpoint switch occurs during the handshake, the connection is aborted, and a new challenge will be issued upon reconnecting.

- **Optional Timestamped Messages:**  
  If enabled, messages are prefixed with a timestamp. The server checks that the message timestamp is within an acceptable window to mitigate replay attacks.


Absolutely — here's a clean, thoughtful **Acceptable Use** section you can add to your README. It's designed to set ethical expectations, reduce your liability, and discourage abuse while staying friendly and transparent:

---

## 🛡️ Acceptable Use

This software is provided **for educational and research** only.

It is **not** intended to facilitate or hide:
- Malware command-and-control infrastructure
- Unauthorized access or intrusion attempts
- Fraud, impersonation, or harassment
- Evading lawful monitoring, surveillance, or regulation

### By using this software, you agree to:
- Use it only in compliance with applicable laws in your jurisdiction
- Take full responsibility for your actions
- Respect the privacy and security of others

> **Reminder:** Just because something can evade detection doesn’t mean it should. This project aims to empower *resilience*, not recklessness.

If you’re unsure whether your use case is acceptable, err on the side of caution or seek legal advice


## Prerequisites

- [Go](https://golang.org/dl/) (version 1.18 or later recommended)
- [OpenSSL](https://www.openssl.org/) (for generating TLS certificates)

## Setup

### 1. Generate TLS Certificates

Generate a self-signed certificate and private key using OpenSSL:

```bash
openssl req -x509 -newkey rsa:4096 -nodes -keyout server.key -out server.crt -days 365 -subj "/CN=localhost"
```

This command creates `server.crt` and `server.key`, which the server uses for its TLS configuration.

### 2. Clone the Repository

Clone the repository and change to the project directory:

```bash
git clone https://github.com/tomoconnor/gofhss.git
cd gofhss
```

## Building and Running

### Running the Server

To start the server (for example, with challenge–response and timestamp verification enabled):

```bash
go run main.go -mode=server -challenge=true -timestamp=true
```

The server will:
- Compute the active endpoint for the current time slot using the shared secret.
- Securely bind to that endpoint via TLS.
- Switch endpoints when the time slot expires. Each new connection (including those after an endpoint switch) triggers a new challenge handshake.

### Running the Client

To run the client with all features enabled (robust clock sync, timestamped messages, challenge–response authentication, and TLS connection timeout), use:

```bash
go run main.go -mode=client -msg="Hello, world!" -robust=true -timestamp=true -challenge=true
```

The client will:
- Synchronize its clock with the server (using either a single SYNC handshake or multiple rounds if robust sync is enabled).
- Use `tls.DialWithDialer` with a specified timeout (e.g., 5 seconds) to connect securely.
- Perform a challenge–response handshake. If the active endpoint changes during the handshake, the connection is aborted and retried, ensuring each connection gets a fresh challenge.
- Prepend a timestamp to the message (if enabled) and send it to the server.
- Receive and display the server’s echo response.

## How It Works

1. **Pseudorandom Endpoint Selection:**  
   Both client and server use an HMAC-SHA256 algorithm with the shared secret and the current time slot to determine the active endpoint.

2. **Dynamic Listener Switching:**  
   The server binds to the active endpoint for a given time slot and switches as the slot expires, complicating any interception attempts.

3. **Clock Synchronization:**  
   The client aligns its clock with the server using a SYNC handshake. Optionally, multiple rounds of synchronization average out network delays.

4. **TLS Connection Timeout:**  
   The client uses `tls.DialWithDialer` with a timeout to prevent prolonged connection attempts if the endpoint becomes outdated due to switching.

5. **Optional Challenge–Response:**  
   Every new connection results in the server generating a fresh nonce for a challenge. The client must respond with the correct HMAC response based on this nonce and the shared secret. If the endpoint changes during the handshake, the connection aborts and a new challenge is generated on the next attempt.

6. **Optional Timestamped Messages:**  
   The client prepends a timestamp to each message, and the server verifies that the message is recent to prevent replay attacks.

## Security Considerations

- **Proof-of-Concept:**  
  This project is a proof-of-concept. Additional hardening is required for production environments.

- **Shared Secret:**  
  The integrity of the pseudorandom endpoint selection and challenge–response mechanisms depends on safeguarding the shared secret.

- **Clock Synchronization:**  
  Consider more robust synchronization methods (e.g., NTP-like algorithms) in scenarios with high latency or significant clock drift.

- **TLS Certificate Validation:**  
  In production, proper certificate validation should be enforced rather than using `InsecureSkipVerify`.

- **Timeout Tuning:**  
  Adjust the TLS connection timeout based on your network conditions to achieve a balance between responsiveness and reliability.

## Future Improvements

- Enhance clock synchronization using statistically robust filtering.
- Improve error handling and logging mechanisms.
- Integrate proper certificate validation on the client.
- Allow dynamic configuration of time slot duration and connection timeout.
- Explore secret rotation strategies and more sophisticated pseudorandom algorithms.

## License

This project is licensed under the GNU Affero General Public License, version 3 (AGPLv3). You can find a copy of the license in the [LICENSE](LICENSE) file or view it online at [https://www.gnu.org/licenses/agpl-3.0.html](https://www.gnu.org/licenses/agpl-3.0.html).
