package ctap2

import (
	"io"
	"iter"

	"github.com/ldclabs/cose/key"
	"github.com/mohammadv184/go-fido2/protocol/webauthn"
)

// Client is the interface for CTAP2 client operations.
// It defines the methods that an authenticator must support to be compliant with CTAP2.
type Client interface {
	io.Closer

	// MakeCredential creates a new credential on the authenticator.
	MakeCredential(pinUvAuthProtocolType PinUvAuthProtocolType, pinUvAuthToken []byte, clientData []byte,
		rp webauthn.PublicKeyCredentialRpEntity, user webauthn.PublicKeyCredentialUserEntity,
		pubKeyCredParams []webauthn.PublicKeyCredentialParameters,
		excludeList []webauthn.PublicKeyCredentialDescriptor,
		extensions *CreateExtensionInputs, options map[Option]bool,
		enterpriseAttestation uint,
		attestationFormatsPreference []webauthn.AttestationStatementFormatIdentifier,
	) (*AuthenticatorMakeCredentialResponse, error)

	// GetAssertion retrieves an assertion from the authenticator.
	GetAssertion(pinUvAuthProtocolType PinUvAuthProtocolType, pinUvAuthToken []byte,
		rpID string, clientData []byte, allowList []webauthn.PublicKeyCredentialDescriptor,
		extensions *GetExtensionInputs, options map[Option]bool,
	) iter.Seq2[*AuthenticatorGetAssertionResponse, error]

	// GetInfo retrieves the authenticator's information.
	GetInfo() (*AuthenticatorGetInfoResponse, error)

	// GetPINRetries retrieves the number of remaining PIN attempts.
	GetPINRetries(pinUvAuthProtocolType PinUvAuthProtocolType) (uint, bool, error)

	// GetKeyAgreement retrieves the key agreement key for the specified PIN/UV auth protocol.
	GetKeyAgreement(pinUvAuthProtocolType PinUvAuthProtocolType) (key.Key, error)

	// SetPIN sets the PIN for the authenticator.
	SetPIN(pinUvAuthProtocolType PinUvAuthProtocolType, keyAgreement key.Key, pin string) error

	// ChangePIN changes the PIN for the authenticator.
	ChangePIN(pinUvAuthProtocolType PinUvAuthProtocolType, keyAgreement key.Key, currentPin string, newPin string) error

	// GetPinToken retrieves the PIN token from the authenticator.
	// This method is used for backward compatibility.
	GetPinToken(pinUvAuthProtocolType PinUvAuthProtocolType, keyAgreement key.Key, pin string) ([]byte, error)

	// GetPinUvAuthTokenUsingUvWithPermissions retrieves the PIN/UV auth token using user verification with permissions.
	GetPinUvAuthTokenUsingUvWithPermissions(
		pinUvAuthProtocolType PinUvAuthProtocolType,
		keyAgreement key.Key,
		permissions Permission,
		rpID string,
	) ([]byte, error)

	// GetUVRetries retrieves the number of remaining UV attempts.
	GetUVRetries() (uint, error)

	// GetPinUvAuthTokenUsingPinWithPermissions retrieves the PIN/UV auth token using PIN with permissions.
	GetPinUvAuthTokenUsingPinWithPermissions(
		pinUvAuthProtocolType PinUvAuthProtocolType,
		keyAgreement key.Key,
		pin string,
		permissions Permission,
		rpID string,
	) ([]byte, error)

	// GetBioModality retrieves the biometric modality of the authenticator.
	GetBioModality(preview bool) (*AuthenticatorBioEnrollmentResponse, error)

	// GetFingerprintSensorInfo retrieves information about the fingerprint sensor.
	GetFingerprintSensorInfo(preview bool) (*AuthenticatorBioEnrollmentResponse, error)

	// BeginEnroll starts the biometric enrollment process.
	BeginEnroll(
		preview bool,
		pinUvAuthProtocolType PinUvAuthProtocolType,
		pinUvAuthToken []byte,
		timeoutMilliseconds uint,
	) (*AuthenticatorBioEnrollmentResponse, error)

	// EnrollCaptureNextSample captures the next sample for biometric enrollment.
	EnrollCaptureNextSample(
		preview bool,
		pinUvAuthProtocolType PinUvAuthProtocolType,
		pinUvAuthToken []byte,
		templateID []byte,
		timeoutMilliseconds uint,
	) (*AuthenticatorBioEnrollmentResponse, error)

	// CancelCurrentEnrollment cancels the current biometric enrollment.
	CancelCurrentEnrollment(preview bool) error

	// EnumerateEnrollments lists the biometric enrollments on the authenticator.
	EnumerateEnrollments(
		preview bool,
		pinUvAuthProtocolType PinUvAuthProtocolType,
		pinUvAuthToken []byte,
	) (*AuthenticatorBioEnrollmentResponse, error)

	// SetFriendlyName sets a friendly name for a biometric enrollment.
	SetFriendlyName(
		preview bool,
		pinUvAuthProtocolType PinUvAuthProtocolType,
		pinUvAuthToken []byte,
		templateID []byte,
		friendlyName string,
	) error

	// RemoveEnrollment removes a biometric enrollment.
	RemoveEnrollment(
		preview bool,
		pinUvAuthProtocolType PinUvAuthProtocolType,
		pinUvAuthToken []byte,
		templateID []byte,
	) error

	// GetCredsMetadata retrieves metadata about credential management.
	GetCredsMetadata(
		preview bool,
		pinUvAuthProtocolType PinUvAuthProtocolType,
		pinUvAuthToken []byte,
	) (*AuthenticatorCredentialManagementResponse, error)

	// EnumerateRPs lists the Relying Parties with credentials on the authenticator.
	EnumerateRPs(
		preview bool,
		pinUvAuthProtocolType PinUvAuthProtocolType,
		pinUvAuthToken []byte,
	) iter.Seq2[*AuthenticatorCredentialManagementResponse, error]

	// EnumerateCredentials lists the credentials for a specific Relying Party.
	EnumerateCredentials(
		preview bool,
		pinUvAuthProtocolType PinUvAuthProtocolType,
		pinUvAuthToken []byte,
		rpIDHash []byte,
	) iter.Seq2[*AuthenticatorCredentialManagementResponse, error]

	// DeleteCredential deletes a credential from the authenticator.
	DeleteCredential(
		preview bool,
		pinUvAuthProtocolType PinUvAuthProtocolType,
		pinUvAuthToken []byte,
		credentialID webauthn.PublicKeyCredentialDescriptor,
	) error

	// UpdateUserInformation updates the user information for a credential.
	UpdateUserInformation(
		preview bool,
		pinUvAuthProtocolType PinUvAuthProtocolType,
		pinUvAuthToken []byte,
		credentialID webauthn.PublicKeyCredentialDescriptor,
		user webauthn.PublicKeyCredentialUserEntity,
	) error

	// LargeBlobs manages large blobs on the authenticator.
	LargeBlobs(
		pinUvAuthProtocolType PinUvAuthProtocolType,
		pinUvAuthToken []byte,
		get uint,
		set []byte,
		offset uint,
		length uint,
	) (*AuthenticatorLargeBlobsResponse, error)

	// EnableEnterpriseAttestation enables enterprise attestation.
	EnableEnterpriseAttestation(pinUvAuthProtocolType PinUvAuthProtocolType, pinUvAuthToken []byte) error

	// ToggleAlwaysUV toggles the Always UV setting.
	ToggleAlwaysUV(pinUvAuthProtocolType PinUvAuthProtocolType, pinUvAuthToken []byte) error

	// SetMinPINLength sets the minimum PIN length.
	SetMinPINLength(
		pinUvAuthProtocolType PinUvAuthProtocolType,
		pinUvAuthToken []byte,
		newMinPINLength uint,
		minPinLengthRPIDs []string,
		forceChangePin bool,
		pinComplexityPolicy bool,
	) error

	// Selection prompts the user to select an account or confirm presence.
	Selection() error

	// Reset resets the authenticator to factory defaults.
	Reset() error
}
