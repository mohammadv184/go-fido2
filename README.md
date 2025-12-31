# Go FIDO2

A comprehensive, CGO-free Go implementation of the **FIDO2 Client to Authenticator Protocol (CTAP2)**.

This library allows Go applications to communicate directly with FIDO2 authenticators (security keys) such as YubiKeys, SoloKeys, and others. It implements the core CTAP2 protocol in a transport-agnostic manner, supporting the full stack from transport layers up to high-level operations like credential creation, assertion retrieval, and credential management.

## Support Level

### Transport & OS Support

| Transport             | Linux | macOS | Windows |
|:----------------------|:-----:|:-----:|:-------:|
| **USB HID**           |   ✅   |   ✅   |    ✅    |
| **PCSC (Smart Card)** |  🚧   |  🚧   |   🚧    |
| **BLE**               |  🚧   |  🚧   |   🚧    |

*Legend: ✅ Supported, 🚧 Planned/In Progress


## Features

*   **Platform Agnostic Implementation**: Designed to support multiple transports (HID, NFC, BLE, PCSC).
*   **CTAP2 & CTAP2.1 Support**: Implements the core CTAP2 protocol logic.
*   **Cross-Platform HID Support**: Native USB HID communication on **Linux**, **macOS**, and **Windows** without CGO (using `purego` and syscalls).
*   **Device Discovery**: Easily enumerate and connect to supported FIDO2 devices.
*   **Client PIN Management**: Set, change, and verify PINs (Protocol 1 and 2).
*   **Credential Management**: Enumerate, update, and delete resident credentials (passkeys).
*   **Biometric Enrollment**: Manage fingerprints (enroll, enumerate, remove).
*   **Large Blobs**: Read and write large data blobs (if supported by the device).
*   **Enterprise Attestation**: Support for enabling enterprise attestation.

## Installation

```bash
go get github.com/mohammadv184/go-fido2
```

## Quick Start

### Enumerating Devices

```go
package main

import (
	"fmt"
	"log"

	"github.com/mohammadv184/go-fido2"
)

func main() {
	// Enumerate currently supported devices (e.g. USB HID)
	devices, err := fido2.Enumerate()
	if err != nil {
		log.Fatalf("Failed to enumerate devices: %v", err)
	}

	for _, d := range devices {
		fmt.Printf("Found device: %s (Product: %s, Manufacturer: %s)\n", 
			d.Path, d.Product, d.Manufacturer)
	}
}
```

### Getting Authenticator Info

```go
package main

import (
	"fmt"
	"log"

	"github.com/mohammadv184/go-fido2"
)

func main() {
	// Find devices

devices, _ := fido2.Enumerate()
	if len(devices) == 0 {
		log.Fatal("No FIDO2 devices found")
	}

	// Open the first device found
	dev, err := fido2.Open(devices[0])
	if err != nil {
		log.Fatalf("Failed to open device: %v", err)
	}
	defer dev.Close()

	// Get Info
	info := dev.Info()
	fmt.Printf("Versions: %v\n", info.Versions)
	fmt.Printf("AAGUID: %s\n", info.AAGUID)
	fmt.Printf("Extensions: %v\n", info.Extensions)
}
```

## Advanced Usage

### Making a Credential (Registration)

To register a new credential, you need to define the Relying Party (RP), User, and other parameters.

```go
import (
	"github.com/mohammadv184/go-fido2"
	"github.com/mohammadv184/go-fido2/protocol/ctap2"
	"github.com/mohammadv184/go-fido2/protocol/webauthn"
)

// ... inside main ...

// 1. Check if user verification (PIN/Bio) is required/configured
pinUvAuthToken := []byte{} // Obtain this via dev.GetPinUvAuthTokenUsingPIN if needed

// 2. Define parameters
rp := webauthn.PublicKeyCredentialRpEntity{
	ID:   "example.com",
	Name: "Example Service",
}
user := webauthn.PublicKeyCredentialUserEntity{
	ID:          []byte("user-id-123"),
	Name:        "alice@example.com",
	DisplayName: "Alice",
}
pubKeyCredParams := []webauthn.PublicKeyCredentialParameters{
	{Type: "public-key", Alg: -7}, // ES256
	{Type: "public-key", Alg: -257}, // RS256
}

// 3. Make Credential
resp, err := dev.MakeCredential(
	pinUvAuthToken,
	[]byte("challenge-data"),
	rp,
	user,
	pubKeyCredParams,
	nil, // excludeList
	nil, // extensions
	nil, // options
	0,   // enterpriseAttestation
	nil, // attestationFormats
)
if err != nil {
	log.Fatalf("MakeCredential failed: %v", err)
}

fmt.Printf("Attestation Object: %x\n", resp.AuthDataRaw)
```

### Credential Management (Listing Passkeys)

You can enumerate resident keys (passkeys) stored on the device.

```go
// 1. Get PIN Token (assuming PIN is set)
token, err := dev.GetPinUvAuthTokenUsingPIN("123456", ctap2.PermissionCredentialManagement, "")
if err != nil {
    log.Fatal(err)
}

// 2. Get Metadata
metadata, _ := dev.GetCredsMetadata(token)
fmt.Printf("Stored Credentials: %d\n", metadata.ExistingResidentCredentialsCount)

// 3. Enumerate Relying Parties
for rpResp, err := range dev.EnumerateRPs(token) {
    if err != nil {
        log.Println("Error enumerating RP:", err)
        break
    }
    fmt.Printf("RP: %s (%s)\n", rpResp.RP.Name, rpResp.RP.ID)

    // 4. Enumerate Credentials for this RP
    for credResp, err := range dev.EnumerateCredentials(token, rpResp.RPIDHash) {
        if err != nil {
            break
        }
        fmt.Printf(" - User: %s (%s)\n", credResp.User.DisplayName, credResp.User.Name)
    }
}
```

## Contributing
Contributions are welcome! Please open issues or pull requests for improvements or bug fixes.

## Security

If you discover any security-related issues, please email mohammad.v184@gmail.com instead of using the issue tracker.

## License

Please see the [LICENSE](LICENSE) file for details.