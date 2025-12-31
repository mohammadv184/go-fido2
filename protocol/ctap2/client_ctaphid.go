package ctap2

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"iter"
	"slices"

	"github.com/fxamacker/cbor/v2"
	"github.com/mohammadv184/go-fido2/protocol/ctaphid"

	"github.com/ldclabs/cose/key"
	"github.com/mohammadv184/go-fido2/protocol/webauthn"
)

// CTAPHIDClient implements the Client interface using CTAPHID.
type CTAPHIDClient struct {
	ctaphidClient *ctaphid.Client
	cborEncMode   cbor.EncMode

	cid ctaphid.ChannelID
}

// NewClient creates a new CTAP2 client over CTAPHID.
// It initializes the communication by sending a CTAPHID_INIT command with a random nonce.
func NewClient(
	ctaphidClient *ctaphid.Client,
	cborEncMode cbor.EncMode,
) (*CTAPHIDClient, error) {
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ctaphidInitResp, err := ctaphidClient.Init(ctaphid.BroadcastCID, nonce)
	if err != nil {
		return nil, err
	}

	return &CTAPHIDClient{
		ctaphidClient: ctaphidClient,
		cborEncMode:   cborEncMode,
		cid:           ctaphidInitResp.CID,
	}, nil
}

// Close closes the underlying CTAPHID connection.
func (c *CTAPHIDClient) Close() error {
	return c.ctaphidClient.Close()
}

// MakeCredential performs the AuthenticatorMakeCredential operation.
func (c *CTAPHIDClient) MakeCredential(
	pinUvAuthProtocolType PinUvAuthProtocolType,
	pinUvAuthToken []byte,
	clientData []byte,
	rp webauthn.PublicKeyCredentialRpEntity,
	user webauthn.PublicKeyCredentialUserEntity,
	pubKeyCredParams []webauthn.PublicKeyCredentialParameters,
	excludeList []webauthn.PublicKeyCredentialDescriptor,
	extensions *CreateExtensionInputs,
	options map[Option]bool,
	enterpriseAttestation uint,
	attestationFormatsPreference []webauthn.AttestationStatementFormatIdentifier,
) (*AuthenticatorMakeCredentialResponse, error) {
	hasher := sha256.New()
	hasher.Write(clientData)
	clientDataHash := hasher.Sum(nil)

	req := &AuthenticatorMakeCredentialRequest{
		ClientDataHash:               clientDataHash,
		RP:                           rp,
		User:                         user,
		PubKeyCredParams:             pubKeyCredParams,
		ExcludeList:                  excludeList,
		Extensions:                   extensions,
		Options:                      options,
		EnterpriseAttestation:        enterpriseAttestation,
		AttestationFormatsPreference: attestationFormatsPreference,
	}

	if pinUvAuthToken != nil {
		pinUvAuthParam := Authenticate(
			pinUvAuthProtocolType,
			pinUvAuthToken,
			clientDataHash,
		)

		req.PinUvAuthParam = pinUvAuthParam
		req.PinUvAuthProtocol = pinUvAuthProtocolType
	}

	b, err := c.cborEncMode.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal MakeCredential CBOR request: %w", err)
	}

	respRaw, err := c.ctaphidClient.CBOR(c.cid, slices.Concat([]byte{byte(CMDAuthenticatorMakeCredential)}, b))
	if err != nil {
		return nil, err
	}

	var resp *AuthenticatorMakeCredentialResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return nil, err
	}
	resp.AuthData, err = ParseMakeCredentialAuthData(resp.AuthDataRaw)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (c *CTAPHIDClient) GetAssertion(
	pinUvAuthProtocolType PinUvAuthProtocolType,
	pinUvAuthToken []byte,
	rpID string,
	clientData []byte,
	allowList []webauthn.PublicKeyCredentialDescriptor,
	extensions *GetExtensionInputs,
	options map[Option]bool,
) iter.Seq2[*AuthenticatorGetAssertionResponse, error] {
	return func(yield func(*AuthenticatorGetAssertionResponse, error) bool) {
		hasher := sha256.New()
		hasher.Write(clientData)
		clientDataHash := hasher.Sum(nil)

		req := &AuthenticatorGetAssertionRequest{
			RPID:           rpID,
			ClientDataHash: clientDataHash,
			AllowList:      allowList,
			Extensions:     extensions,
			Options:        options,
		}

		if pinUvAuthToken != nil {
			pinUvAuthParamBegin := Authenticate(
				pinUvAuthProtocolType,
				pinUvAuthToken,
				clientDataHash,
			)

			req.PinUvAuthParam = pinUvAuthParamBegin
			req.PinUvAuthProtocol = pinUvAuthProtocolType
		}

		bBegin, err := c.cborEncMode.Marshal(req)
		if err != nil {
			yield(nil, err)
			return
		}

		respRawBegin, err := c.ctaphidClient.CBOR(
			c.cid,
			slices.Concat([]byte{byte(CMDAuthenticatorGetAssertion)}, bBegin),
		)
		if err != nil {
			yield(nil, err)
			return
		}

		var respBegin *AuthenticatorGetAssertionResponse
		if err := cbor.Unmarshal(respRawBegin.Data, &respBegin); err != nil {
			yield(nil, err)
			return
		}
		respBegin.AuthData, err = ParseGetAssertionAuthData(respBegin.AuthDataRaw)
		if err != nil {
			yield(nil, err)
			return
		}

		if !yield(respBegin, nil) {
			return
		}

		for i := uint(1); i < respBegin.NumberOfCredentials; i++ {
			respRaw, err := c.ctaphidClient.CBOR(c.cid, []byte{byte(CMDAuthenticatorGetNextAssertion)})
			if err != nil {
				yield(nil, err)
				return
			}

			var resp *AuthenticatorGetAssertionResponse
			if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
				yield(nil, err)
				return
			}
			resp.AuthData, err = ParseGetAssertionAuthData(resp.AuthDataRaw)
			if err != nil {
				yield(nil, err)
				return
			}

			if !yield(resp, nil) {
				return
			}
		}
	}
}

func (c *CTAPHIDClient) GetInfo() (*AuthenticatorGetInfoResponse, error) {
	respRaw, err := c.ctaphidClient.CBOR(c.cid, []byte{byte(CMDAuthenticatorGetInfo)})
	if err != nil {
		return nil, err
	}

	var resp *AuthenticatorGetInfoResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return nil, err
	}

	return resp, nil
}

func (c *CTAPHIDClient) GetPINRetries(
	pinUvAuthProtocolType PinUvAuthProtocolType,
) (uint, bool, error) {
	req := &AuthenticatorClientPINRequest{
		// While this parameter is unnecessary, SoloKeys Solo 2 requires it for some reason.
		PinUvAuthProtocol: pinUvAuthProtocolType,
		SubCommand:        ClientPINSubCommandGetPINRetries,
	}

	b, err := c.cborEncMode.Marshal(req)
	if err != nil {
		return 0, false, err
	}

	respRaw, err := c.ctaphidClient.CBOR(c.cid, slices.Concat([]byte{byte(CMDAuthenticatorClientPIN)}, b))
	if err != nil {
		return 0, false, err
	}

	var resp *AuthenticatorClientPINResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return 0, false, err
	}

	return resp.PinRetries, resp.PowerCycleState, nil
}

func (c *CTAPHIDClient) GetKeyAgreement(
	pinUvAuthProtocolType PinUvAuthProtocolType,
) (key.Key, error) {
	req := &AuthenticatorClientPINRequest{
		PinUvAuthProtocol: pinUvAuthProtocolType,
		SubCommand:        ClientPINSubCommandGetKeyAgreement,
	}

	b, err := c.cborEncMode.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal keyAgreement CBOR request: %w", err)
	}

	respRaw, err := c.ctaphidClient.CBOR(c.cid, slices.Concat([]byte{byte(CMDAuthenticatorClientPIN)}, b))
	if err != nil {
		return nil, fmt.Errorf("keyAgreement CBOR request failed: %w", err)
	}

	var resp *AuthenticatorClientPINResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return nil, fmt.Errorf("cannot unmarshal keyAgreement CBOR response: %w", err)
	}

	return resp.KeyAgreement, nil
}

func (c *CTAPHIDClient) SetPIN(
	pinUvAuthProtocolType PinUvAuthProtocolType,
	keyAgreement key.Key,
	pin string,
) error {
	protocol, err := NewPinUvAuthProtocol(pinUvAuthProtocolType)
	if err != nil {
		return err
	}

	platformCoseKey, sharedSecret, err := protocol.Encapsulate(keyAgreement)
	if err != nil {
		return err
	}

	// Pad pin with zero bytes until
	pinBytes := []byte(pin)
	for i := 0; i < 64-len(pin); i++ {
		pinBytes = append(pinBytes, 0)
	}

	ciphertext, err := protocol.Encrypt(sharedSecret, pinBytes)
	if err != nil {
		return err
	}

	req := &AuthenticatorClientPINRequest{
		PinUvAuthProtocol: protocol.Type,
		SubCommand:        ClientPINSubCommandSetPIN,
		KeyAgreement:      platformCoseKey,
		NewPinEnc:         ciphertext,
		PinUvAuthParam: Authenticate(
			pinUvAuthProtocolType,
			sharedSecret,
			ciphertext,
		),
	}

	b, err := c.cborEncMode.Marshal(req)
	if err != nil {
		return err
	}

	respRaw, err := c.ctaphidClient.CBOR(c.cid, slices.Concat([]byte{byte(CMDAuthenticatorClientPIN)}, b))
	if err != nil {
		return err
	}

	var resp *AuthenticatorClientPINResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return err
	}

	return nil
}

func (c *CTAPHIDClient) ChangePIN(
	pinUvAuthProtocolType PinUvAuthProtocolType,
	keyAgreement key.Key,
	currentPin string,
	newPin string,
) error {
	protocol, err := NewPinUvAuthProtocol(pinUvAuthProtocolType)
	if err != nil {
		return err
	}

	platformCoseKey, sharedSecret, err := protocol.Encapsulate(keyAgreement)
	if err != nil {
		return err
	}

	// Hash PIN and return the first 16 bytes of hash
	hasher := sha256.New()
	hasher.Write([]byte(currentPin))
	pinHash := hasher.Sum(nil)[:16]

	pinHashEnc, err := protocol.Encrypt(sharedSecret, pinHash)
	if err != nil {
		return err
	}

	newPinBytes := []byte(newPin)
	for i := 0; i < 64-len([]byte(newPin)); i++ {
		newPinBytes = append(newPinBytes, 0)
	}

	newPinEnc, err := protocol.Encrypt(sharedSecret, newPinBytes)
	if err != nil {
		return err
	}

	req := &AuthenticatorClientPINRequest{
		PinUvAuthProtocol: protocol.Type,
		SubCommand:        ClientPINSubCommandChangePIN,
		KeyAgreement:      platformCoseKey,
		PinHashEnc:        pinHashEnc,
		NewPinEnc:         newPinEnc,
		PinUvAuthParam: Authenticate(
			pinUvAuthProtocolType,
			sharedSecret,
			slices.Concat(newPinEnc, pinHashEnc),
		),
	}

	b, err := c.cborEncMode.Marshal(req)
	if err != nil {
		return err
	}

	respRaw, err := c.ctaphidClient.CBOR(c.cid, slices.Concat([]byte{byte(CMDAuthenticatorClientPIN)}, b))
	if err != nil {
		return err
	}

	var resp *AuthenticatorClientPINResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return err
	}

	return nil
}

// GetPinToken allows getting a PinUvAuthToken (superseded by GetPinUvAuthTokenUsingUvWithPermissions or
// GetPinUvAuthTokenUsingPinWithPermissions, thus for backwards compatibility only).
func (c *CTAPHIDClient) GetPinToken(
	pinUvAuthProtocolType PinUvAuthProtocolType,
	keyAgreement key.Key,
	pin string,
) ([]byte, error) {
	protocol, err := NewPinUvAuthProtocol(pinUvAuthProtocolType)
	if err != nil {
		return nil, err
	}

	platformCoseKey, sharedSecret, err := protocol.Encapsulate(keyAgreement)
	if err != nil {
		return nil, err
	}

	hasher := sha256.New()
	hasher.Write([]byte(pin))
	pinHash := hasher.Sum(nil)[:16]

	pinHashEnc, err := protocol.Encrypt(sharedSecret, pinHash)
	if err != nil {
		return nil, err
	}

	req := &AuthenticatorClientPINRequest{
		PinUvAuthProtocol: protocol.Type,
		SubCommand:        ClientPINSubCommandGetPinToken,
		KeyAgreement:      platformCoseKey,
		PinHashEnc:        pinHashEnc,
	}

	b, err := c.cborEncMode.Marshal(req)
	if err != nil {
		return nil, err
	}

	respRaw, err := c.ctaphidClient.CBOR(c.cid, slices.Concat([]byte{byte(CMDAuthenticatorClientPIN)}, b))
	if err != nil {
		return nil, err
	}

	var resp *AuthenticatorClientPINResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return nil, err
	}

	pinUvAuthToken, err := protocol.Decrypt(sharedSecret, resp.PinUvAuthToken)
	if err != nil {
		return nil, err
	}

	return pinUvAuthToken, nil
}

// GetPinUvAuthTokenUsingUvWithPermissions allows getting a PinUvAuthToken with specific permissions using User Verification.
func (c *CTAPHIDClient) GetPinUvAuthTokenUsingUvWithPermissions(
	pinUvAuthProtocolType PinUvAuthProtocolType,
	keyAgreement key.Key,
	permissions Permission,
	rpID string,
) ([]byte, error) {
	protocol, err := NewPinUvAuthProtocol(pinUvAuthProtocolType)
	if err != nil {
		return nil, err
	}

	platformCoseKey, sharedSecret, err := protocol.Encapsulate(keyAgreement)
	if err != nil {
		return nil, err
	}

	req := &AuthenticatorClientPINRequest{
		PinUvAuthProtocol: protocol.Type,
		SubCommand:        ClientPINSubCommandGetPinUvAuthTokenUsingUvWithPermissions,
		KeyAgreement:      platformCoseKey,
		Permissions:       permissions,
		RPID:              rpID,
	}

	b, err := c.cborEncMode.Marshal(req)
	if err != nil {
		return nil, err
	}

	respRaw, err := c.ctaphidClient.CBOR(c.cid, slices.Concat([]byte{byte(CMDAuthenticatorClientPIN)}, b))
	if err != nil {
		return nil, err
	}

	var resp *AuthenticatorClientPINResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return nil, err
	}

	pinUvAuthToken, err := protocol.Decrypt(sharedSecret, resp.PinUvAuthToken)
	if err != nil {
		return nil, err
	}

	return pinUvAuthToken, nil
}

func (c *CTAPHIDClient) GetUVRetries() (uint, error) {
	req := &AuthenticatorClientPINRequest{
		SubCommand: ClientPINSubCommandGetUVRetries,
	}

	b, err := c.cborEncMode.Marshal(req)
	if err != nil {
		return 0, err
	}

	respRaw, err := c.ctaphidClient.CBOR(c.cid, slices.Concat([]byte{byte(CMDAuthenticatorClientPIN)}, b))
	if err != nil {
		return 0, err
	}

	var resp *AuthenticatorClientPINResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return 0, err
	}

	return resp.UvRetries, nil
}

// GetPinUvAuthTokenUsingPinWithPermissions allows getting a PinUvAuthToken with specific permissions using PIN.
func (c *CTAPHIDClient) GetPinUvAuthTokenUsingPinWithPermissions(
	pinUvAuthProtocolType PinUvAuthProtocolType,
	keyAgreement key.Key,
	pin string,
	permissions Permission,
	rpID string,
) ([]byte, error) {
	protocol, err := NewPinUvAuthProtocol(pinUvAuthProtocolType)
	if err != nil {
		return nil, err
	}

	platformCoseKey, sharedSecret, err := protocol.Encapsulate(keyAgreement)
	if err != nil {
		return nil, err
	}

	hasher := sha256.New()
	hasher.Write([]byte(pin))
	pinHash := hasher.Sum(nil)[:16]

	pinHashEnc, err := protocol.Encrypt(sharedSecret, pinHash)
	if err != nil {
		return nil, err
	}

	req := &AuthenticatorClientPINRequest{
		PinUvAuthProtocol: protocol.Type,
		SubCommand:        ClientPINSubCommandGetPinUvAuthTokenUsingPinWithPermissions,
		KeyAgreement:      platformCoseKey,
		PinHashEnc:        pinHashEnc,
		Permissions:       permissions,
		RPID:              rpID,
	}

	b, err := c.cborEncMode.Marshal(req)
	if err != nil {
		return nil, err
	}

	respRaw, err := c.ctaphidClient.CBOR(c.cid, slices.Concat([]byte{byte(CMDAuthenticatorClientPIN)}, b))
	if err != nil {
		return nil, err
	}

	var resp *AuthenticatorClientPINResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return nil, err
	}

	pinUvAuthToken, err := protocol.Decrypt(sharedSecret, resp.PinUvAuthToken)
	if err != nil {
		return nil, err
	}

	return pinUvAuthToken, nil
}

func (c *CTAPHIDClient) Reset() error {
	_, err := c.ctaphidClient.CBOR(c.cid, []byte{byte(CMDAuthenticatorReset)})
	if err != nil {
		return err
	}

	return nil
}

func (c *CTAPHIDClient) GetBioModality(
	preview bool,
) (*AuthenticatorBioEnrollmentResponse, error) {
	req := &AuthenticatorBioEnrollmentRequest{GetModality: true}

	b, err := c.cborEncMode.Marshal(req)
	if err != nil {
		return nil, err
	}

	command := CMDAuthenticatorBioEnrollment
	if preview {
		command = CMDPrototypeAuthenticatorBioEnrollment
	}

	respRaw, err := c.ctaphidClient.CBOR(c.cid, slices.Concat([]byte{byte(command)}, b))
	if err != nil {
		return nil, err
	}

	var resp *AuthenticatorBioEnrollmentResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return nil, err
	}

	return resp, nil
}

func (c *CTAPHIDClient) GetFingerprintSensorInfo(
	preview bool,
) (*AuthenticatorBioEnrollmentResponse, error) {
	req := &AuthenticatorBioEnrollmentRequest{
		Modality:   BioModalityFingerprint,
		SubCommand: BioEnrollmentSubCommandGetFingerprintSensorInfo,
	}

	b, err := c.cborEncMode.Marshal(req)
	if err != nil {
		return nil, err
	}

	command := CMDAuthenticatorBioEnrollment
	if preview {
		command = CMDPrototypeAuthenticatorBioEnrollment
	}

	respRaw, err := c.ctaphidClient.CBOR(c.cid, slices.Concat([]byte{byte(command)}, b))
	if err != nil {
		return nil, err
	}

	var resp *AuthenticatorBioEnrollmentResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return nil, err
	}

	return resp, nil
}

func (c *CTAPHIDClient) BeginEnroll(
	preview bool,
	pinUvAuthProtocolType PinUvAuthProtocolType,
	pinUvAuthToken []byte,
	timeoutMilliseconds uint,
) (*AuthenticatorBioEnrollmentResponse, error) {
	bSubCommandParams, err := c.cborEncMode.Marshal(BioEnrollmentSubCommandParams{
		TimeoutMilliseconds: timeoutMilliseconds,
	})
	if err != nil {
		return nil, err
	}
	if timeoutMilliseconds == 0 {
		bSubCommandParams = nil
	}

	pinUvAuthParam := Authenticate(
		pinUvAuthProtocolType,
		pinUvAuthToken,
		slices.Concat(
			[]byte{byte(BioModalityFingerprint), byte(BioEnrollmentSubCommandEnrollBegin)},
			bSubCommandParams,
		),
	)

	req := &AuthenticatorBioEnrollmentRequest{
		Modality:   BioModalityFingerprint,
		SubCommand: BioEnrollmentSubCommandEnrollBegin,
		SubCommandParams: BioEnrollmentSubCommandParams{
			TimeoutMilliseconds: timeoutMilliseconds,
		},
		PinUvAuthProtocol: pinUvAuthProtocolType,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := c.cborEncMode.Marshal(req)
	if err != nil {
		return nil, err
	}

	command := CMDAuthenticatorBioEnrollment
	if preview {
		command = CMDPrototypeAuthenticatorBioEnrollment
	}

	respRaw, err := c.ctaphidClient.CBOR(c.cid, slices.Concat([]byte{byte(command)}, b))
	if err != nil {
		return nil, err
	}

	var resp *AuthenticatorBioEnrollmentResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return nil, err
	}

	return resp, nil
}

func (c *CTAPHIDClient) EnrollCaptureNextSample(
	preview bool,
	pinUvAuthProtocolType PinUvAuthProtocolType,
	pinUvAuthToken []byte,
	templateID []byte,
	timeoutMilliseconds uint,
) (*AuthenticatorBioEnrollmentResponse, error) {
	bSubCommandParams, err := c.cborEncMode.Marshal(BioEnrollmentSubCommandParams{
		TemplateID:          templateID,
		TimeoutMilliseconds: timeoutMilliseconds,
	})
	if err != nil {
		return nil, err
	}

	pinUvAuthParam := Authenticate(
		pinUvAuthProtocolType,
		pinUvAuthToken,
		slices.Concat(
			[]byte{byte(BioModalityFingerprint), byte(BioEnrollmentSubCommandEnrollCaptureNextSample)},
			bSubCommandParams,
		),
	)

	req := &AuthenticatorBioEnrollmentRequest{
		Modality:   BioModalityFingerprint,
		SubCommand: BioEnrollmentSubCommandEnrollCaptureNextSample,
		SubCommandParams: BioEnrollmentSubCommandParams{
			TemplateID:          templateID,
			TimeoutMilliseconds: timeoutMilliseconds,
		},
		PinUvAuthProtocol: pinUvAuthProtocolType,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := c.cborEncMode.Marshal(req)
	if err != nil {
		return nil, err
	}

	command := CMDAuthenticatorBioEnrollment
	if preview {
		command = CMDPrototypeAuthenticatorBioEnrollment
	}

	respRaw, err := c.ctaphidClient.CBOR(c.cid, slices.Concat([]byte{byte(command)}, b))
	if err != nil {
		return nil, err
	}

	var resp *AuthenticatorBioEnrollmentResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return nil, err
	}

	return resp, nil
}

func (c *CTAPHIDClient) CancelCurrentEnrollment(
	preview bool,
) error {
	req := &AuthenticatorBioEnrollmentRequest{
		Modality:   BioModalityFingerprint,
		SubCommand: BioEnrollmentSubCommandCancelCurrentEnrollment,
	}

	b, err := c.cborEncMode.Marshal(req)
	if err != nil {
		return err
	}

	command := CMDAuthenticatorBioEnrollment
	if preview {
		command = CMDPrototypeAuthenticatorBioEnrollment
	}

	if _, err := c.ctaphidClient.CBOR(c.cid, slices.Concat([]byte{byte(command)}, b)); err != nil {
		return err
	}

	return nil
}

func (c *CTAPHIDClient) EnumerateEnrollments(
	preview bool,
	pinUvAuthProtocolType PinUvAuthProtocolType,
	pinUvAuthToken []byte,
) (*AuthenticatorBioEnrollmentResponse, error) {
	pinUvAuthParam := Authenticate(
		pinUvAuthProtocolType,
		pinUvAuthToken,
		[]byte{byte(BioModalityFingerprint), byte(BioEnrollmentSubCommandEnumerateEnrollments)},
	)

	req := &AuthenticatorBioEnrollmentRequest{
		Modality:          BioModalityFingerprint,
		SubCommand:        BioEnrollmentSubCommandEnumerateEnrollments,
		PinUvAuthProtocol: pinUvAuthProtocolType,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := c.cborEncMode.Marshal(req)
	if err != nil {
		return nil, err
	}

	command := CMDAuthenticatorBioEnrollment
	if preview {
		command = CMDPrototypeAuthenticatorBioEnrollment
	}

	respRaw, err := c.ctaphidClient.CBOR(c.cid, slices.Concat([]byte{byte(command)}, b))
	if err != nil {
		return nil, err
	}

	var resp *AuthenticatorBioEnrollmentResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return nil, err
	}

	return resp, nil
}

func (c *CTAPHIDClient) SetFriendlyName(
	preview bool,
	pinUvAuthProtocolType PinUvAuthProtocolType,
	pinUvAuthToken []byte,
	templateID []byte,
	friendlyName string,
) error {
	bSubCommandParams, err := c.cborEncMode.Marshal(BioEnrollmentSubCommandParams{
		TemplateID:           templateID,
		TemplateFriendlyName: friendlyName,
	})
	if err != nil {
		return err
	}

	pinUvAuthParam := Authenticate(
		pinUvAuthProtocolType,
		pinUvAuthToken,
		slices.Concat(
			[]byte{byte(BioModalityFingerprint), byte(BioEnrollmentSubCommandSetFriendlyName)},
			bSubCommandParams,
		),
	)

	req := &AuthenticatorBioEnrollmentRequest{
		Modality:   BioModalityFingerprint,
		SubCommand: BioEnrollmentSubCommandSetFriendlyName,
		SubCommandParams: BioEnrollmentSubCommandParams{
			TemplateID:           templateID,
			TemplateFriendlyName: friendlyName,
		},
		PinUvAuthProtocol: pinUvAuthProtocolType,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := c.cborEncMode.Marshal(req)
	if err != nil {
		return err
	}

	command := CMDAuthenticatorBioEnrollment
	if preview {
		command = CMDPrototypeAuthenticatorBioEnrollment
	}

	if _, err := c.ctaphidClient.CBOR(c.cid, slices.Concat([]byte{byte(command)}, b)); err != nil {
		return err
	}

	return nil
}

func (c *CTAPHIDClient) RemoveEnrollment(
	preview bool,
	pinUvAuthProtocolType PinUvAuthProtocolType,
	pinUvAuthToken []byte,
	templateID []byte,
) error {
	bSubCommandParams, err := c.cborEncMode.Marshal(BioEnrollmentSubCommandParams{
		TemplateID: templateID,
	})
	if err != nil {
		return err
	}

	pinUvAuthParam := Authenticate(
		pinUvAuthProtocolType,
		pinUvAuthToken,
		slices.Concat(
			[]byte{byte(BioModalityFingerprint), byte(BioEnrollmentSubCommandRemoveEnrollment)},
			bSubCommandParams,
		),
	)

	req := &AuthenticatorBioEnrollmentRequest{
		Modality:   BioModalityFingerprint,
		SubCommand: BioEnrollmentSubCommandRemoveEnrollment,
		SubCommandParams: BioEnrollmentSubCommandParams{
			TemplateID: templateID,
		},
		PinUvAuthProtocol: pinUvAuthProtocolType,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := c.cborEncMode.Marshal(req)
	if err != nil {
		return err
	}

	command := CMDAuthenticatorBioEnrollment
	if preview {
		command = CMDPrototypeAuthenticatorBioEnrollment
	}

	if _, err := c.ctaphidClient.CBOR(c.cid, slices.Concat([]byte{byte(command)}, b)); err != nil {
		return err
	}

	return nil
}

func (c *CTAPHIDClient) GetCredsMetadata(
	preview bool,
	pinUvAuthProtocolType PinUvAuthProtocolType,
	pinUvAuthToken []byte,
) (*AuthenticatorCredentialManagementResponse, error) {
	pinUvAuthParam := Authenticate(
		pinUvAuthProtocolType,
		pinUvAuthToken,
		[]byte{byte(CredentialManagementSubCommandGetCredsMetadata)},
	)

	req := &AuthenticatorCredentialManagementRequest{
		SubCommand:        CredentialManagementSubCommandGetCredsMetadata,
		PinUvAuthProtocol: pinUvAuthProtocolType,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := c.cborEncMode.Marshal(req)
	if err != nil {
		return nil, err
	}

	command := CMDAuthenticatorCredentialManagement
	if preview {
		command = CMDPrototypeAuthenticatorCredentialManagement
	}

	respRaw, err := c.ctaphidClient.CBOR(c.cid, slices.Concat([]byte{byte(command)}, b))
	if err != nil {
		return nil, err
	}

	var resp *AuthenticatorCredentialManagementResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return nil, err
	}

	return resp, nil
}

func (c *CTAPHIDClient) EnumerateRPs(
	preview bool,
	pinUvAuthProtocolType PinUvAuthProtocolType,
	pinUvAuthToken []byte,
) iter.Seq2[*AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(*AuthenticatorCredentialManagementResponse, error) bool) {
		pinUvAuthParamBegin := Authenticate(
			pinUvAuthProtocolType,
			pinUvAuthToken,
			[]byte{byte(CredentialManagementSubCommandEnumerateRPsBegin)},
		)

		reqBegin := &AuthenticatorCredentialManagementRequest{
			SubCommand:        CredentialManagementSubCommandEnumerateRPsBegin,
			PinUvAuthProtocol: pinUvAuthProtocolType,
			PinUvAuthParam:    pinUvAuthParamBegin,
		}

		bBegin, err := c.cborEncMode.Marshal(reqBegin)
		if err != nil {
			yield(nil, err)
			return
		}

		command := CMDAuthenticatorCredentialManagement
		if preview {
			command = CMDPrototypeAuthenticatorCredentialManagement
		}

		respRawBegin, err := c.ctaphidClient.CBOR(c.cid,
			slices.Concat(
				[]byte{byte(command)},
				bBegin,
			),
		)
		if err != nil {
			yield(nil, err)
			return
		}

		var respBegin *AuthenticatorCredentialManagementResponse
		if err := cbor.Unmarshal(respRawBegin.Data, &respBegin); err != nil {
			yield(nil, err)
			return
		}

		if respBegin.TotalRPs == 0 {
			return
		}

		if !yield(respBegin, nil) {
			return
		}

		for i := uint(1); i < respBegin.TotalRPs; i++ {
			reqNext := &AuthenticatorCredentialManagementRequest{
				SubCommand: CredentialManagementSubCommandEnumerateRPsGetNextRP,
			}

			bNext, err := c.cborEncMode.Marshal(reqNext)
			if err != nil {
				yield(nil, err)
				return
			}

			respRawNext, err := c.ctaphidClient.CBOR(c.cid, slices.Concat([]byte{0x0A}, bNext))
			if err != nil {
				yield(nil, err)
				return
			}

			var respNext *AuthenticatorCredentialManagementResponse
			if err := cbor.Unmarshal(respRawNext.Data, &respNext); err != nil {
				yield(nil, err)
				return
			}

			if !yield(respNext, nil) {
				return
			}
		}
	}
}

func (c *CTAPHIDClient) EnumerateCredentials(
	preview bool,
	pinUvAuthProtocolType PinUvAuthProtocolType,
	pinUvAuthToken []byte,
	rpIDHash []byte,
) iter.Seq2[*AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(*AuthenticatorCredentialManagementResponse, error) bool) {
		bSubCommandParams, err := c.cborEncMode.Marshal(CredentialManagementSubCommandParams{RPIDHash: rpIDHash})
		if err != nil {
			yield(nil, err)
			return
		}

		pinUvAuthParamBegin := Authenticate(
			pinUvAuthProtocolType,
			pinUvAuthToken,
			slices.Concat(
				[]byte{byte(CredentialManagementSubCommandEnumerateCredentialsBegin)},
				bSubCommandParams,
			),
		)

		reqBegin := &AuthenticatorCredentialManagementRequest{
			SubCommand:        CredentialManagementSubCommandEnumerateCredentialsBegin,
			SubCommandParams:  CredentialManagementSubCommandParams{RPIDHash: rpIDHash},
			PinUvAuthProtocol: pinUvAuthProtocolType,
			PinUvAuthParam:    pinUvAuthParamBegin,
		}

		bBegin, err := c.cborEncMode.Marshal(reqBegin)
		if err != nil {
			yield(nil, err)
			return
		}

		command := CMDAuthenticatorCredentialManagement
		if preview {
			command = CMDPrototypeAuthenticatorCredentialManagement
		}

		respRawBegin, err := c.ctaphidClient.CBOR(c.cid,
			slices.Concat(
				[]byte{byte(command)},
				bBegin,
			),
		)
		if err != nil {
			yield(nil, err)
			return
		}

		var respBegin *AuthenticatorCredentialManagementResponse
		if err := cbor.Unmarshal(respRawBegin.Data, &respBegin); err != nil {
			yield(nil, err)
			return
		}

		if respBegin.TotalCredentials == 0 {
			return
		}

		if !yield(respBegin, nil) {
			return
		}

		for i := uint(1); i < respBegin.TotalCredentials; i++ {
			reqNext := &AuthenticatorCredentialManagementRequest{
				SubCommand: CredentialManagementSubCommandEnumerateRPsGetNextRP,
			}

			bNext, err := c.cborEncMode.Marshal(reqNext)
			if err != nil {
				yield(nil, err)
				return
			}

			respRawNext, err := c.ctaphidClient.CBOR(c.cid, slices.Concat([]byte{0x0A}, bNext))
			if err != nil {
				yield(nil, err)
				return
			}

			var respNext *AuthenticatorCredentialManagementResponse
			if err := cbor.Unmarshal(respRawNext.Data, &respNext); err != nil {
				yield(nil, err)
				return
			}

			if !yield(respNext, nil) {
				return
			}
		}
	}
}

func (c *CTAPHIDClient) DeleteCredential(
	preview bool,
	pinUvAuthProtocolType PinUvAuthProtocolType,
	pinUvAuthToken []byte,
	credentialID webauthn.PublicKeyCredentialDescriptor,
) error {
	bSubCommandParams, err := c.cborEncMode.Marshal(CredentialManagementSubCommandParams{
		CredentialID: credentialID,
	})
	if err != nil {
		return err
	}

	pinUvAuthParam := Authenticate(
		pinUvAuthProtocolType,
		pinUvAuthToken,
		slices.Concat(
			[]byte{byte(CredentialManagementSubCommandDeleteCredential)},
			bSubCommandParams,
		),
	)

	req := &AuthenticatorCredentialManagementRequest{
		SubCommand:        CredentialManagementSubCommandDeleteCredential,
		SubCommandParams:  CredentialManagementSubCommandParams{CredentialID: credentialID},
		PinUvAuthProtocol: pinUvAuthProtocolType,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := c.cborEncMode.Marshal(req)
	if err != nil {
		return err
	}

	command := CMDAuthenticatorCredentialManagement
	if preview {
		command = CMDPrototypeAuthenticatorCredentialManagement
	}

	if _, err := c.ctaphidClient.CBOR(c.cid, slices.Concat([]byte{byte(command)}, b)); err != nil {
		return err
	}

	return nil
}

func (c *CTAPHIDClient) UpdateUserInformation(
	preview bool,
	pinUvAuthProtocolType PinUvAuthProtocolType,
	pinUvAuthToken []byte,
	credentialID webauthn.PublicKeyCredentialDescriptor,
	user webauthn.PublicKeyCredentialUserEntity,
) error {
	bSubCommandParams, err := c.cborEncMode.Marshal(CredentialManagementSubCommandParams{
		CredentialID: credentialID,
		User:         user,
	})
	if err != nil {
		return err
	}

	pinUvAuthParam := Authenticate(
		pinUvAuthProtocolType,
		pinUvAuthToken,
		slices.Concat(
			[]byte{byte(CredentialManagementSubCommandUpdateUserInformation)},
			bSubCommandParams,
		),
	)

	req := &AuthenticatorCredentialManagementRequest{
		SubCommand: CredentialManagementSubCommandUpdateUserInformation,
		SubCommandParams: CredentialManagementSubCommandParams{
			CredentialID: credentialID,
			User:         user,
		},
		PinUvAuthProtocol: pinUvAuthProtocolType,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := c.cborEncMode.Marshal(req)
	if err != nil {
		return err
	}

	command := CMDAuthenticatorCredentialManagement
	if preview {
		command = CMDPrototypeAuthenticatorCredentialManagement
	}

	if _, err := c.ctaphidClient.CBOR(c.cid, slices.Concat([]byte{byte(command)}, b)); err != nil {
		return err
	}

	return nil
}

func (c *CTAPHIDClient) LargeBlobs(
	pinUvAuthProtocolType PinUvAuthProtocolType,
	pinUvAuthToken []byte,
	get uint,
	set []byte,
	offset uint,
	length uint,
) (*AuthenticatorLargeBlobsResponse, error) {
	req := &AuthenticatorLargeBlobsRequest{
		Get:    get,
		Set:    set,
		Offset: offset,
		Length: length,
	}

	if pinUvAuthToken != nil {
		padding := make([]byte, 32)
		for i := range padding {
			padding[i] = 0xff
		}

		offsetBin := make([]byte, 4)
		binary.LittleEndian.PutUint32(offsetBin, uint32(offset))

		hasher := sha256.New()
		hasher.Reset()
		hasher.Write(set)
		hash := hasher.Sum(nil)

		pinUvAuthParam := Authenticate(
			pinUvAuthProtocolType,
			pinUvAuthToken,
			slices.Concat(
				padding,
				[]byte{0x0c, 0x00},
				offsetBin,
				hash,
			),
		)

		req.PinUvAuthParam = pinUvAuthParam
		req.PinUvAuthProtocol = pinUvAuthProtocolType
	}

	b, err := c.cborEncMode.Marshal(req)
	if err != nil {
		return nil, err
	}

	respRaw, err := c.ctaphidClient.CBOR(c.cid, slices.Concat([]byte{byte(CMDAuthenticatorLargeBlobs)}, b))
	if err != nil {
		return nil, err
	}

	if get > 0 {
		var resp *AuthenticatorLargeBlobsResponse
		if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
			return nil, err
		}

		return resp, nil
	}

	return nil, nil
}

func (c *CTAPHIDClient) EnableEnterpriseAttestation(
	pinUvAuthProtocolType PinUvAuthProtocolType,
	pinUvAuthToken []byte,
) error {
	padding := make([]byte, 32)
	for i := range padding {
		padding[i] = 0xff
	}

	pinUvAuthParam := Authenticate(
		pinUvAuthProtocolType,
		pinUvAuthToken,
		slices.Concat(
			padding,
			[]byte{0x0d, byte(ConfigSubCommandEnableEnterpriseAttestation)},
		),
	)

	req := &AuthenticatorConfigRequest{
		SubCommand:        ConfigSubCommandEnableEnterpriseAttestation,
		PinUvAuthProtocol: pinUvAuthProtocolType,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := c.cborEncMode.Marshal(req)
	if err != nil {
		return err
	}

	if _, err := c.ctaphidClient.CBOR(c.cid, slices.Concat([]byte{byte(CMDAuthenticatorConfig)}, b)); err != nil {
		return err
	}

	return nil
}

func (c *CTAPHIDClient) ToggleAlwaysUV(
	pinUvAuthProtocolType PinUvAuthProtocolType,
	pinUvAuthToken []byte,
) error {
	padding := make([]byte, 32)
	for i := range padding {
		padding[i] = 0xff
	}

	pinUvAuthParam := Authenticate(
		pinUvAuthProtocolType,
		pinUvAuthToken,
		slices.Concat(
			padding,
			[]byte{0x0d, byte(ConfigSubCommandToggleAlwaysUv)},
		),
	)

	req := &AuthenticatorConfigRequest{
		SubCommand:        ConfigSubCommandToggleAlwaysUv,
		PinUvAuthProtocol: pinUvAuthProtocolType,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := c.cborEncMode.Marshal(req)
	if err != nil {
		return err
	}

	if _, err := c.ctaphidClient.CBOR(c.cid, slices.Concat([]byte{byte(CMDAuthenticatorConfig)}, b)); err != nil {
		return err
	}

	return nil
}

func (c *CTAPHIDClient) SetMinPINLength(
	pinUvAuthProtocolType PinUvAuthProtocolType,
	pinUvAuthToken []byte,
	newMinPINLength uint,
	minPinLengthRPIDs []string,
	forceChangePin bool,
	pinComplexityPolicy bool,
) error {
	padding := make([]byte, 32)
	for i := range padding {
		padding[i] = 0xff
	}

	subCommandParams := &SetMinPINLengthConfigSubCommandParams{
		NewMinPINLength:     newMinPINLength,
		MinPinLengthRPIDs:   minPinLengthRPIDs,
		ForceChangePin:      forceChangePin,
		PinComplexityPolicy: pinComplexityPolicy,
	}
	bSubCommandParams, err := c.cborEncMode.Marshal(subCommandParams)
	if err != nil {
		return err
	}

	pinUvAuthParam := Authenticate(
		pinUvAuthProtocolType,
		pinUvAuthToken,
		slices.Concat(
			padding,
			[]byte{0x0d, byte(ConfigSubCommandSetMinPINLength)},
			bSubCommandParams,
		),
	)

	req := &AuthenticatorConfigRequest{
		SubCommand:        ConfigSubCommandSetMinPINLength,
		SubCommandParams:  subCommandParams,
		PinUvAuthProtocol: pinUvAuthProtocolType,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := c.cborEncMode.Marshal(req)
	if err != nil {
		return err
	}

	if _, err := c.ctaphidClient.CBOR(c.cid, slices.Concat([]byte{byte(CMDAuthenticatorConfig)}, b)); err != nil {
		return err
	}

	return nil
}

// Selection blocks execution until the user will confirm his presence or operation will be canceled.
func (c *CTAPHIDClient) Selection() error {
	_, err := c.ctaphidClient.CBOR(c.cid, []byte{byte(CMDAuthenticatorSelection)})
	if err != nil {
		var ctapError *ctaphid.CTAPError
		if !errors.As(err, &ctapError) || ctapError.StatusCode != ctaphid.StatusCTAP2ErrKeepaliveCancel {
			return err
		}
	}

	return nil
}
