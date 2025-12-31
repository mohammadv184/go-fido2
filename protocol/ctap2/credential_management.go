package ctap2

import (
	"github.com/ldclabs/cose/key"
	"github.com/mohammadv184/go-fido2/protocol/webauthn"
)

// AuthenticatorCredentialManagementRequest represents the request for AuthenticatorCredentialManagement command.
type AuthenticatorCredentialManagementRequest struct {
	SubCommand        CredentialManagementSubCommand       `cbor:"1,keyasint"`
	SubCommandParams  CredentialManagementSubCommandParams `cbor:"2,keyasint,omitzero"`
	PinUvAuthProtocol PinUvAuthProtocolType                `cbor:"3,keyasint,omitempty"`
	PinUvAuthParam    []byte                               `cbor:"4,keyasint,omitempty"`
}

// CredentialManagementSubCommandParams represents parameters for CredentialManagement sub-commands.
type CredentialManagementSubCommandParams struct {
	RPIDHash     []byte                                 `cbor:"1,keyasint,omitempty"`
	CredentialID webauthn.PublicKeyCredentialDescriptor `cbor:"2,keyasint,omitzero"`
	User         webauthn.PublicKeyCredentialUserEntity `cbor:"3,keyasint,omitzero"`
}

// AuthenticatorCredentialManagementResponse represents the response for AuthenticatorCredentialManagement command.
type AuthenticatorCredentialManagementResponse struct {
	ExistingResidentCredentialsCount             uint                                   `cbor:"1,keyasint"`
	MaxPossibleRemainingResidentCredentialsCount uint                                   `cbor:"2,keyasint"`
	RP                                           webauthn.PublicKeyCredentialRpEntity   `cbor:"3,keyasint"`
	RPIDHash                                     []byte                                 `cbor:"4,keyasint"`
	TotalRPs                                     uint                                   `cbor:"5,keyasint"`
	User                                         webauthn.PublicKeyCredentialUserEntity `cbor:"6,keyasint"`
	CredentialID                                 webauthn.PublicKeyCredentialDescriptor `cbor:"7,keyasint"`
	PublicKey                                    *key.Key                               `cbor:"8,keyasint"`
	TotalCredentials                             uint                                   `cbor:"9,keyasint"`
	CredProtect                                  uint                                   `cbor:"10,keyasint"`
	LargeBlobKey                                 []byte                                 `cbor:"11,keyasint"`
	ThirdPartyPayment                            bool                                   `cbor:"12,keyasint"`
}

// CredentialManagementSubCommand represents sub-commands for CredentialManagement.
type CredentialManagementSubCommand byte

func (cmd CredentialManagementSubCommand) String() string {
	return credentialManagementSubCommandStringMap[cmd]
}

const (
	// CredentialManagementSubCommandGetCredsMetadata retrieves credential management metadata.
	CredentialManagementSubCommandGetCredsMetadata CredentialManagementSubCommand = iota + 1
	// CredentialManagementSubCommandEnumerateRPsBegin begins the Relying Party enumeration.
	CredentialManagementSubCommandEnumerateRPsBegin
	// CredentialManagementSubCommandEnumerateRPsGetNextRP retrieves the next Relying Party in enumeration.
	CredentialManagementSubCommandEnumerateRPsGetNextRP
	// CredentialManagementSubCommandEnumerateCredentialsBegin begins the credential enumeration for an RP.
	CredentialManagementSubCommandEnumerateCredentialsBegin
	// CredentialManagementSubCommandEnumerateCredentialsGetNextCredential retrieves the next credential in enumeration.
	CredentialManagementSubCommandEnumerateCredentialsGetNextCredential
	// CredentialManagementSubCommandDeleteCredential deletes a credential.
	CredentialManagementSubCommandDeleteCredential
	// CredentialManagementSubCommandUpdateUserInformation updates user information for a credential.
	CredentialManagementSubCommandUpdateUserInformation
)

var credentialManagementSubCommandStringMap = map[CredentialManagementSubCommand]string{
	CredentialManagementSubCommandGetCredsMetadata:                      "GetCredsMetadata",
	CredentialManagementSubCommandEnumerateRPsBegin:                     "EnumerateRPsBegin",
	CredentialManagementSubCommandEnumerateRPsGetNextRP:                 "EnumerateRPsGetNextRP",
	CredentialManagementSubCommandEnumerateCredentialsBegin:             "EnumerateCredentialsBegin",
	CredentialManagementSubCommandEnumerateCredentialsGetNextCredential: "EnumerateCredentialsGetNextCredential",
	CredentialManagementSubCommandDeleteCredential:                      "DeleteCredential",
	CredentialManagementSubCommandUpdateUserInformation:                 "UpdateUserInformation",
}
