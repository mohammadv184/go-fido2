package ctap2

// AuthenticatorLargeBlobsRequest represents the request for AuthenticatorLargeBlobs command.
type AuthenticatorLargeBlobsRequest struct {
	Get               uint                  `cbor:"1,keyasint,omitempty"`
	Set               []byte                `cbor:"2,keyasint,omitempty"`
	Offset            uint                  `cbor:"3,keyasint"`
	Length            uint                  `cbor:"4,keyasint,omitempty"`
	PinUvAuthParam    []byte                `cbor:"5,keyasint,omitempty"`
	PinUvAuthProtocol PinUvAuthProtocolType `cbor:"6,keyasint,omitempty"`
}

// LargeBlob represents a large blob data structure.
type LargeBlob struct {
	Ciphertext []byte `cbor:"1,keyasint"`
	Nonce      []byte `cbor:"2,keyasint"`
	OrigSize   uint   `cbor:"3,keyasint"`
}

// AuthenticatorLargeBlobsResponse represents the response for AuthenticatorLargeBlobs command.
type AuthenticatorLargeBlobsResponse struct {
	Config []byte `cbor:"1,keyasint"`
}
