// Package fido2 provides a high-level interface for interacting with FIDO2 authenticators over HID.
// It supports core FIDO2 operations such as making credentials, getting assertions,
// and managing device settings like PINs and biometric enrollments.
package fido2

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"iter"
	"slices"
	"sync"

	"github.com/fxamacker/cbor/v2"
	"github.com/ldclabs/cose/key"
	"github.com/mohammadv184/go-fido2/protocol/ctap2"
	"github.com/mohammadv184/go-fido2/protocol/ctaphid"
	"github.com/mohammadv184/go-fido2/protocol/webauthn"
	"github.com/mohammadv184/go-fido2/transport/hid"
)

// Device represents a FIDO2 device.
type Device struct {
	ctapClient  ctap2.Client
	cborEncMode cbor.EncMode
	info        *ctap2.AuthenticatorGetInfoResponse
	mu          sync.Mutex
	closed      bool
}

// DeviceDescriptor provides information about a FIDO2 device.
// It is returned by the Enumerate function.
type DeviceDescriptor struct {
	// Path is the platform-specific device path.
	Path string
	// VendorID is the USB vendor identifier.
	VendorID uint16
	// ProductID is the USB product identifier.
	ProductID uint16
	// SerialNumber is the device serial number.
	SerialNumber string
	// Manufacturer is the device manufacturer name.
	Manufacturer string
	// Product is the device product name.
	Product string
}

// Enumerate returns a list of connected FIDO2 devices.
func Enumerate() ([]DeviceDescriptor, error) {
	hidDevs, err := hid.EnumerateFilter(func(d *hid.Device) bool {
		return d.UsagePage() == hid.FIDOUsagePage
	})

	if err != nil {
		return nil, fmt.Errorf("failed to enumerate devices: %w", err)
	}

	devDescs := make([]DeviceDescriptor, 0, len(hidDevs))
	for _, d := range hidDevs {
		devDescs = append(devDescs, DeviceDescriptor{
			Path:         d.Path(),
			VendorID:     d.VendorID(),
			ProductID:    d.ProductID(),
			SerialNumber: d.SerialNumber(),
			Manufacturer: d.Manufacturer(),
			Product:      d.Product(),
		})
	}

	return devDescs, nil
}

// Open opens a FIDO2 device using its descriptor.
func Open(descriptor DeviceDescriptor) (*Device, error) {
	return OpenPath(descriptor.Path)
}

// OpenPath opens a FIDO2 device by its platform-specific path.
func OpenPath(path string) (*Device, error) {
	hidDev, err := hid.Get(path)
	if err != nil {
		return nil, fmt.Errorf("failed to get device: %w", err)
	}

	if hidDev.UsagePage() != hid.FIDOUsagePage {
		return nil, fmt.Errorf("device at %s is not a FIDO device", path)
	}

	if err := hidDev.Open(false); err != nil {
		return nil, fmt.Errorf("failed to open device: %w", err)
	}

	ctaphidClient := ctaphid.NewClient(hidDev)

	encMode, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		_ = ctaphidClient.Close()
		return nil, fmt.Errorf("failed to create CBOR encoding mode: %w", err)
	}

	ctapClient, err := ctap2.NewCTAPHIDClient(ctaphidClient, encMode)
	if err != nil {
		_ = ctaphidClient.Close()
		return nil, fmt.Errorf("failed to create CTAP2 client: %w", err)
	}

	info, err := ctapClient.GetInfo()
	if err != nil {
		_ = ctapClient.Close()
		return nil, fmt.Errorf("failed to get authenticator info: %w", err)
	}

	return &Device{
		ctapClient:  ctapClient,
		cborEncMode: encMode,
		mu:          sync.Mutex{},
		info:        info,
	}, nil
}

// Info returns the authenticator information.
func (d *Device) Info() *ctap2.AuthenticatorGetInfoResponse {
	return d.info
}

// Close closes the connection to the FIDO2 device.
func (d *Device) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	return d.ctapClient.Close()
}

// MakeCredential initiates the process of creating a new credential.
func (d *Device) MakeCredential( // nolint:gocyclo
	pinUvAuthToken []byte,
	clientData []byte,
	rp webauthn.PublicKeyCredentialRpEntity,
	user webauthn.PublicKeyCredentialUserEntity,
	pubKeyCredParams []webauthn.PublicKeyCredentialParameters,
	excludeList []webauthn.PublicKeyCredentialDescriptor,
	extInputs *webauthn.CreateAuthenticationExtensionsClientInputs,
	options map[ctap2.Option]bool,
	enterpriseAttestation uint,
	attestationFormatsPreference []webauthn.AttestationStatementFormatIdentifier,
) (*ctap2.AuthenticatorMakeCredentialResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	notRequired, ok := d.info.Options[ctap2.OptionMakeCredentialUvNotRequired]
	if (!ok || !notRequired) && pinUvAuthToken == nil {
		return nil, ErrPinUvAuthTokenRequired
	}

	var (
		protocol     *ctap2.PinUvAuthProtocol
		sharedSecret []byte
	)

	extensions := new(ctap2.CreateExtensionInputs)

	if extInputs.LargeBlobInputs != nil {
		return nil, newErrorMessage(ErrSyntaxError, "largeBlob extension is not supported yet")
	}

	if extInputs.CreateHMACSecretMCInputs != nil && extInputs.PRFInputs != nil {
		return nil, newErrorMessage(ErrSyntaxError, "you cannot use hmac-secret and prf extensions at the same time")
	}

	// hmac-secret
	if extInputs.CreateHMACSecretInputs != nil {
		if !slices.Contains(d.info.Extensions, webauthn.ExtensionIdentifierHMACSecret) {
			return nil, newErrorMessage(ErrNotSupported, "device doesn't support hmac-secret extension")
		}

		extensions.CreateHMACSecretInput = &ctap2.CreateHMACSecretInput{
			HMACSecret: extInputs.HMACCreateSecret,
		}
	}

	// hmac-secret-mc
	if extInputs.CreateHMACSecretMCInputs != nil {
		if !slices.Contains(d.info.Extensions, webauthn.ExtensionIdentifierHMACSecretMC) {
			return nil, newErrorMessage(ErrNotSupported, "device doesn't support hmac-secret-mc extension")
		}

		salt := slices.Concat(
			extInputs.HMACGetSecret.Salt1,
			extInputs.HMACGetSecret.Salt2,
		)

		var err error
		protocol, err = ctap2.NewPinUvAuthProtocol(d.info.PinUvAuthProtocols[0])
		if err != nil {
			return nil, err
		}

		keyAgreement, err := d.ctapClient.GetKeyAgreement(d.info.PinUvAuthProtocols[0])
		if err != nil {
			return nil, err
		}

		var platformCoseKey key.Key
		platformCoseKey, sharedSecret, err = protocol.Encapsulate(keyAgreement)
		if err != nil {
			return nil, err
		}

		saltEnc, err := protocol.Encrypt(sharedSecret, salt)
		if err != nil {
			return nil, err
		}

		saltAuth := ctap2.Authenticate(
			d.info.PinUvAuthProtocols[0],
			sharedSecret,
			saltEnc,
		)

		extensions.CreateHMACSecretInput = &ctap2.CreateHMACSecretInput{
			HMACSecret: true,
		}
		extensions.CreateHMACSecretMCInput = &ctap2.CreateHMACSecretMCInput{
			HMACSecret: ctap2.HMACSecret{
				KeyAgreement:      platformCoseKey,
				SaltEnc:           saltEnc,
				SaltAuth:          saltAuth,
				PinUvAuthProtocol: d.info.PinUvAuthProtocols[0],
			},
		}
	}

	// prf
	if extInputs.PRFInputs != nil {
		if !slices.Contains(d.info.Extensions, webauthn.ExtensionIdentifierHMACSecretMC) {
			return nil, newErrorMessage(ErrNotSupported, "device doesn't support prf extension during registration")
		}

		if extInputs.PRF.EvalByCredential != nil {
			return nil, newErrorMessage(ErrNotSupported, "evalByCredential is not supported during registration")
		}

		if extInputs.PRF.Eval == nil {
			return nil, newErrorMessage(ErrSyntaxError, "eval is empty")
		}

		hasher := sha256.New()
		hasher.Write([]byte("WebAuthn PRF"))
		hasher.Write([]byte{0x00})
		hasher.Write(extInputs.PRF.Eval.First)
		salt := hasher.Sum(nil)

		if extInputs.PRF.Eval.Second != nil {
			hasher.Reset()
			hasher.Write([]byte("WebAuthn PRF"))
			hasher.Write([]byte{0x00})
			hasher.Write(extInputs.PRF.Eval.Second)
			salt = slices.Concat(salt, hasher.Sum(nil))
		}

		var err error
		protocol, err = ctap2.NewPinUvAuthProtocol(d.info.PinUvAuthProtocols[0])
		if err != nil {
			return nil, err
		}

		keyAgreement, err := d.ctapClient.GetKeyAgreement(d.info.PinUvAuthProtocols[0])
		if err != nil {
			return nil, err
		}

		var platformCoseKey key.Key
		platformCoseKey, sharedSecret, err = protocol.Encapsulate(keyAgreement)
		if err != nil {
			return nil, err
		}

		saltEnc, err := protocol.Encrypt(sharedSecret, salt)
		if err != nil {
			return nil, err
		}

		saltAuth := ctap2.Authenticate(
			d.info.PinUvAuthProtocols[0],
			sharedSecret,
			saltEnc,
		)

		extensions.CreateHMACSecretInput = &ctap2.CreateHMACSecretInput{
			HMACSecret: true,
		}
		extensions.CreateHMACSecretMCInput = &ctap2.CreateHMACSecretMCInput{
			HMACSecret: ctap2.HMACSecret{
				KeyAgreement:      platformCoseKey,
				SaltEnc:           saltEnc,
				SaltAuth:          saltAuth,
				PinUvAuthProtocol: d.info.PinUvAuthProtocols[0],
			},
		}
	}

	// credProtection
	if extInputs.CreateCredentialProtectionInputs != nil {
		var credProtect int

		switch extInputs.CredentialProtectionPolicy {
		case webauthn.CredentialProtectionPolicyUserVerificationOptional:
			credProtect = 0x01
		case webauthn.CredentialProtectionPolicyUserVerificationOptionalWithCredentialIDList:
			credProtect = 0x02
		case webauthn.CredentialProtectionPolicyUserVerificationRequired:
			credProtect = 0x03
		default:
			return nil, newErrorMessage(ErrNotSupported, "invalid credential protection policy")
		}

		if extInputs.EnforceCredentialProtectionPolicy &&
			extInputs.CredentialProtectionPolicy != webauthn.CredentialProtectionPolicyUserVerificationOptional &&
			!slices.Contains(d.info.Extensions, webauthn.ExtensionIdentifierCredentialProtection) {
			return nil, newErrorMessage(ErrNotSupported, "device doesn't support credProtect extension")
		}

		extensions.CreateCredProtectInput = &ctap2.CreateCredProtectInput{
			CredProtect: credProtect,
		}
	}

	// credBlob
	if extInputs.CreateCredentialBlobInputs != nil {
		if !slices.Contains(d.info.Extensions, webauthn.ExtensionIdentifierCredentialBlob) {
			return nil, newErrorMessage(ErrNotSupported, "device doesn't support credBlob extension")
		}

		if uint(len(extInputs.CredBlob)) > d.info.MaxCredBlobLength {
			return nil, newErrorMessage(
				ErrNotSupported,
				fmt.Sprintf("credBlob length must be less than %d bytes", d.info.MaxCredBlobLength),
			)
		}

		extensions.CreateCredBlobInput = &ctap2.CreateCredBlobInput{
			CredBlob: extInputs.CredBlob,
		}
	}

	// minPinLength
	if extInputs.CreateMinPinLengthInputs != nil {
		if !slices.Contains(d.info.Extensions, webauthn.ExtensionIdentifierMinPinLength) {
			return nil, newErrorMessage(ErrNotSupported, "device doesn't support minPinLength extension")
		}

		extensions.CreateMinPinLengthInput = &ctap2.CreateMinPinLengthInput{
			MinPinLength: extInputs.MinPinLength,
		}
	}
	if extInputs.CreatePinComplexityPolicyInputs != nil {
		if !slices.Contains(d.info.Extensions, webauthn.ExtensionIdentifierPinComplexityPolicy) {
			return nil, newErrorMessage(ErrNotSupported, "device doesn't support pinComplexityPolicy extension")
		}

		extensions.CreatePinComplexityPolicyInput = &ctap2.CreatePinComplexityPolicyInput{
			PinComplexityPolicy: extInputs.PinComplexityPolicy,
		}
	}

	resp, err := d.ctapClient.MakeCredential(
		d.info.PinUvAuthProtocols[0],
		pinUvAuthToken,
		clientData,
		rp,
		user,
		pubKeyCredParams,
		excludeList,
		extensions,
		options,
		enterpriseAttestation,
		attestationFormatsPreference,
	)
	if err != nil {
		return nil, err
	}

	extOutputs := new(webauthn.CreateAuthenticationExtensionsClientOutputs)
	resp.ExtensionOutputs = extOutputs

	if extInputs.CreateCredentialProtectionInputs != nil && extInputs.CredentialProperties {
		extOutputs.CreateCredentialPropertiesOutputs = &webauthn.CreateCredentialPropertiesOutputs{
			CredentialProperties: webauthn.CredentialPropertiesOutput{
				ResidentKey: options[ctap2.OptionResidentKeys],
			},
		}
	}

	if !resp.AuthData.Flags.ExtensionDataIncluded() {
		return resp, nil
	}

	// credBlob
	if resp.AuthData.Extensions.CreateCredBlobOutput != nil {
		extOutputs.CreateCredentialBlobOutputs = &webauthn.CreateCredentialBlobOutputs{
			CredBlob: resp.AuthData.Extensions.CredBlob,
		}
	}

	// hmac-secret
	if resp.AuthData.Extensions.CreateHMACSecretOutput != nil {
		extOutputs.CreateHMACSecretOutputs = &webauthn.CreateHMACSecretOutputs{
			HMACCreateSecret: resp.AuthData.Extensions.CreateHMACSecretOutput.HMACSecret,
		}
	}

	// hmac-secret-mc (it needs tests, thought I cannot find any devices that support it yet)
	if resp.AuthData.Extensions.CreateHMACSecretMCOutput != nil {
		salt, err := protocol.Decrypt(sharedSecret, resp.AuthData.Extensions.CreateHMACSecretMCOutput.HMACSecret)
		if err != nil {
			return nil, err
		}

		switch len(salt) {
		case 32:
			extOutputs.PRFOutputs = &webauthn.PRFOutputs{
				PRF: webauthn.AuthenticationExtensionsPRFOutputs{
					Enabled: true,
					Results: webauthn.AuthenticationExtensionsPRFValues{
						First: salt[:32],
					},
				},
			}
		case 64:
			extOutputs.PRFOutputs = &webauthn.PRFOutputs{
				PRF: webauthn.AuthenticationExtensionsPRFOutputs{
					Enabled: true,
					Results: webauthn.AuthenticationExtensionsPRFValues{
						First:  salt[:32],
						Second: salt[32:],
					},
				},
			}
		default:
			return nil, newErrorMessage(ErrInvalidSaltSize, "salt must be 32 or 64 bytes")
		}
	}

	return resp, nil
}

// GetAssertion provides a generator function to iterate over assertions.
func (d *Device) GetAssertion( // nolint:gocyclo
	pinUvAuthToken []byte,
	rpID string,
	clientData []byte,
	allowList []webauthn.PublicKeyCredentialDescriptor,
	extInputs *webauthn.GetAuthenticationExtensionsClientInputs,
	options map[ctap2.Option]bool,
) iter.Seq2[*ctap2.AuthenticatorGetAssertionResponse, error] {
	return func(yield func(*ctap2.AuthenticatorGetAssertionResponse, error) bool) {
		d.mu.Lock()
		defer d.mu.Unlock()

		var (
			protocol     *ctap2.PinUvAuthProtocol
			sharedSecret []byte
		)

		extensions := new(ctap2.GetExtensionInputs)

		if extInputs.LargeBlobInputs != nil {
			yield(nil, newErrorMessage(ErrSyntaxError, "largeBlob extension is not supported yet"))
			return
		}

		if extInputs.PRFInputs != nil && extInputs.GetHMACSecretInputs != nil {
			yield(
				nil,
				newErrorMessage(ErrSyntaxError, "you cannot use hmac-secret and prf extensions at the same time"),
			)
			return
		}

		// hmac-secret
		if extInputs.GetHMACSecretInputs != nil {
			salt := slices.Concat(
				extInputs.HMACGetSecret.Salt1,
				extInputs.HMACGetSecret.Salt2,
			)

			var err error
			protocol, err = ctap2.NewPinUvAuthProtocol(d.info.PinUvAuthProtocols[0])
			if err != nil {
				yield(nil, err)
				return
			}

			keyAgreement, err := d.ctapClient.GetKeyAgreement(d.info.PinUvAuthProtocols[0])
			if err != nil {
				yield(nil, err)
				return
			}

			var platformCoseKey key.Key
			platformCoseKey, sharedSecret, err = protocol.Encapsulate(keyAgreement)
			if err != nil {
				yield(nil, err)
				return
			}

			saltEnc, err := protocol.Encrypt(sharedSecret, salt)
			if err != nil {
				yield(nil, err)
				return
			}

			saltAuth := ctap2.Authenticate(
				d.info.PinUvAuthProtocols[0],
				sharedSecret,
				saltEnc,
			)

			extensions.GetHMACSecretInput = &ctap2.GetHMACSecretInput{
				HMACSecret: ctap2.HMACSecret{
					KeyAgreement:      platformCoseKey,
					SaltEnc:           saltEnc,
					SaltAuth:          saltAuth,
					PinUvAuthProtocol: d.info.PinUvAuthProtocols[0],
				},
			}
		}

		// prf
		if extInputs.PRFInputs != nil {
			if extInputs.PRF.EvalByCredential != nil && len(allowList) == 0 {
				yield(
					nil,
					newErrorMessage(ErrNotSupported, "evalByCredential works only in conjunction with allowList"),
				)
				return
			}

			var ev *webauthn.AuthenticationExtensionsPRFValues
			var ids [][]byte
			for idStr := range extInputs.PRF.EvalByCredential {
				id, err := base64.URLEncoding.DecodeString(idStr)
				if err != nil {
					yield(nil, newErrorMessage(ErrSyntaxError, "invalid credential id"))
					return
				}

				ids = append(ids, id)
			}

			for _, id := range ids {
				index := slices.IndexFunc(allowList, func(descriptor webauthn.PublicKeyCredentialDescriptor) bool {
					return slices.Equal(descriptor.ID, id)
				})
				if index != -1 {
					v, ok := extInputs.PRF.EvalByCredential[base64.URLEncoding.EncodeToString(allowList[index].ID)]
					if ok {
						ev = &v
					}
				}
			}

			if ev == nil && extInputs.PRF.Eval != nil {
				ev = extInputs.PRF.Eval
			}

			hasher := sha256.New()
			hasher.Write([]byte("WebAuthn PRF"))
			hasher.Write([]byte{0x00})
			hasher.Write(ev.First)
			salt := hasher.Sum(nil)

			if ev.Second != nil {
				hasher.Reset()
				hasher.Write([]byte("WebAuthn PRF"))
				hasher.Write([]byte{0x00})
				hasher.Write(ev.Second)
				salt = slices.Concat(salt, hasher.Sum(nil))
			}

			var err error
			protocol, err = ctap2.NewPinUvAuthProtocol(d.info.PinUvAuthProtocols[0])
			if err != nil {
				yield(nil, err)
				return
			}

			keyAgreement, err := d.ctapClient.GetKeyAgreement(d.info.PinUvAuthProtocols[0])
			if err != nil {
				yield(nil, err)
				return
			}

			var platformCoseKey key.Key
			platformCoseKey, sharedSecret, err = protocol.Encapsulate(keyAgreement)
			if err != nil {
				yield(nil, err)
				return
			}

			saltEnc, err := protocol.Encrypt(sharedSecret, salt)
			if err != nil {
				yield(nil, err)
				return
			}

			saltAuth := ctap2.Authenticate(
				d.info.PinUvAuthProtocols[0],
				sharedSecret,
				saltEnc,
			)

			extensions.GetHMACSecretInput = &ctap2.GetHMACSecretInput{
				HMACSecret: ctap2.HMACSecret{
					KeyAgreement:      platformCoseKey,
					SaltEnc:           saltEnc,
					SaltAuth:          saltAuth,
					PinUvAuthProtocol: d.info.PinUvAuthProtocols[0],
				},
			}
		}

		// credBlob
		if extInputs.GetCredentialBlobInputs != nil {
			extensions.GetCredBlobInput = &ctap2.GetCredBlobInput{
				CredBlob: extInputs.GetCredBlob,
			}
		}

		for assertion, err := range d.ctapClient.GetAssertion(
			d.info.PinUvAuthProtocols[0],
			pinUvAuthToken,
			rpID,
			clientData,
			allowList,
			extensions,
			options,
		) {
			if err != nil {
				yield(nil, err)
				return
			}

			assertion.ExtensionOutputs = new(webauthn.GetAuthenticationExtensionsClientOutputs)

			// Yield assertions without extension data
			if !assertion.AuthData.Flags.ExtensionDataIncluded() {
				yield(assertion, nil)
				return
			}

			// credBlob
			if assertion.AuthData.Extensions.GetCredBlobOutput != nil {
				assertion.ExtensionOutputs.GetCredentialBlobOutputs = &webauthn.GetCredentialBlobOutputs{
					GetCredBlob: assertion.AuthData.Extensions.CredBlob,
				}
			}

			// hmac-secret or prf
			if assertion.AuthData.Extensions.GetHMACSecretOutput != nil {
				salt, err := protocol.Decrypt(sharedSecret, assertion.AuthData.Extensions.HMACSecret)
				if err != nil {
					yield(nil, err)
					return
				}

				switch len(salt) {
				case 32:
					if extInputs.GetHMACSecretInputs != nil {
						assertion.ExtensionOutputs.GetHMACSecretOutputs = &webauthn.GetHMACSecretOutputs{
							HMACGetSecret: webauthn.HMACGetSecretOutput{
								Output1: salt[:32],
							},
						}
					}
					if extInputs.PRFInputs != nil {
						assertion.ExtensionOutputs.PRFOutputs = &webauthn.PRFOutputs{
							PRF: webauthn.AuthenticationExtensionsPRFOutputs{
								Enabled: true,
								Results: webauthn.AuthenticationExtensionsPRFValues{
									First: salt[:32],
								},
							},
						}
					}
				case 64:
					if extInputs.GetHMACSecretInputs != nil {
						assertion.ExtensionOutputs.GetHMACSecretOutputs = &webauthn.GetHMACSecretOutputs{
							HMACGetSecret: webauthn.HMACGetSecretOutput{
								Output1: salt[:32],
								Output2: salt[32:],
							},
						}
					}
					if extInputs.PRFInputs != nil {
						assertion.ExtensionOutputs.PRFOutputs = &webauthn.PRFOutputs{
							PRF: webauthn.AuthenticationExtensionsPRFOutputs{
								Enabled: true,
								Results: webauthn.AuthenticationExtensionsPRFValues{
									First:  salt[:32],
									Second: salt[32:],
								},
							},
						}
					}
				default:
					yield(nil, newErrorMessage(ErrInvalidSaltSize, "salt must be 32 or 64 bytes"))
					return
				}
			}

			if !yield(assertion, nil) {
				return
			}
		}
	}
}

// GetPINRetries retrieves the number of PIN retries remaining.
func (d *Device) GetPINRetries() (uint, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	clientPin, ok := d.info.Options[ctap2.OptionClientPIN]
	if !ok {
		return 0, false, newErrorMessage(ErrNotSupported, "device doesn't support clientPin option")
	}
	if !clientPin {
		return 0, false, newErrorMessage(ErrPinNotSet, "please set PIN first")
	}

	return d.ctapClient.GetPINRetries(d.info.PinUvAuthProtocols[0])
}

// SetPIN sets a new PIN on the device.
func (d *Device) SetPIN(pin string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	clientPin, ok := d.info.Options[ctap2.OptionClientPIN]
	if !ok {
		return newErrorMessage(ErrNotSupported, "device doesn't support clientPin option")
	}
	if clientPin {
		return newErrorMessage(ErrPinAlreadySet, "pin already set, use changePin instead")
	}

	keyAgreement, err := d.ctapClient.GetKeyAgreement(d.info.PinUvAuthProtocols[0])
	if err != nil {
		return err
	}

	return d.ctapClient.SetPIN(d.info.PinUvAuthProtocols[0], keyAgreement, pin)
}

// ChangePIN updates the device's PIN.
func (d *Device) ChangePIN(currentPin string, newPin string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	clientPin, ok := d.info.Options[ctap2.OptionClientPIN]
	if !ok {
		return newErrorMessage(ErrNotSupported, "device doesn't support clientPin option")
	}
	if !clientPin {
		return newErrorMessage(ErrPinNotSet, "please set PIN first")
	}

	keyAgreement, err := d.ctapClient.GetKeyAgreement(d.info.PinUvAuthProtocols[0])
	if err != nil {
		return err
	}

	return d.ctapClient.ChangePIN(
		d.info.PinUvAuthProtocols[0],
		keyAgreement,
		currentPin,
		newPin,
	)
}

// GetPinUvAuthTokenUsingPIN obtains a pinUvAuthToken using a given PIN.
func (d *Device) GetPinUvAuthTokenUsingPIN(
	pin string,
	permissions ctap2.Permission,
	rpID string,
) ([]byte, error) {
	noMcGaPermission, ok := d.info.Options[ctap2.OptionNoMcGaPermissionsWithClientPin]
	if ok && noMcGaPermission &&
		(permissions&ctap2.PermissionMakeCredential != 0 || permissions&ctap2.PermissionGetAssertion != 0) {
		return nil, newErrorMessage(
			ErrNotSupported,
			"you cannot get a pinUvAuthToken using PIN with MakeCredential or GetAssertion permissions if device has noMcGaPermissionsWithClientPin option",
		)
	}

	clientPIN, ok := d.info.Options[ctap2.OptionClientPIN]
	if !ok {
		return nil, newErrorMessage(
			ErrNotSupported,
			"you cannot get a pinUvAuthToken using PIN if device hasn't clientPin option",
		)
	}
	if !clientPIN {
		return nil, newErrorMessage(
			ErrPinNotSet,
			"please set PIN first",
		)
	}

	if _, ok := d.info.Options[ctap2.OptionBioEnroll]; !ok && permissions&ctap2.PermissionBioEnrollment != 0 {
		return nil, newErrorMessage(
			ErrNotSupported,
			"you cannot set be BioEnrollment permission if device doesn't support bioEnroll option",
		)
	}

	authnrCfg, ok := d.info.Options[ctap2.OptionAuthenticatorConfig]
	if (!ok || !authnrCfg) && permissions&ctap2.PermissionAuthenticatorConfiguration != 0 {
		return nil, newErrorMessage(
			ErrNotSupported,
			"you cannot set be AuthenticatorConfiguration permission if device doesn't support uv option")
	}

	keyAgreement, err := d.ctapClient.GetKeyAgreement(d.info.PinUvAuthProtocols[0])
	if err != nil {
		return nil, err
	}

	token, ok := d.info.Options[ctap2.OptionPinUvAuthToken]
	if !ok || !token {
		return d.ctapClient.GetPinToken(
			d.info.PinUvAuthProtocols[0],
			keyAgreement,
			pin,
		)
	}

	return d.ctapClient.GetPinUvAuthTokenUsingPinWithPermissions(
		d.info.PinUvAuthProtocols[0],
		keyAgreement,
		pin,
		permissions,
		rpID,
	)
}

// GetPinUvAuthTokenUsingUV obtains a pinUvAuthToken by performing user verification.
func (d *Device) GetPinUvAuthTokenUsingUV(
	permissions ctap2.Permission,
	rpID string,
) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	token, ok := d.info.Options[ctap2.OptionPinUvAuthToken]
	if !ok || !token {
		return nil, newErrorMessage(ErrNotSupported, "device doesn't support pinUvAuthToken")
	}

	uv, ok := d.info.Options[ctap2.OptionUserVerification]
	if !ok {
		return nil, newErrorMessage(ErrNotSupported, "device doesn't support user verification")
	}
	if !uv {
		return nil, newErrorMessage(ErrUvNotConfigured, "please configure UV first (e.g. enroll biometry)")
	}

	keyAgreement, err := d.ctapClient.GetKeyAgreement(d.info.PinUvAuthProtocols[0])
	if err != nil {
		return nil, err
	}

	return d.ctapClient.GetPinUvAuthTokenUsingUvWithPermissions(
		d.info.PinUvAuthProtocols[0],
		keyAgreement,
		permissions,
		rpID,
	)
}

// GetUVRetries retrieves the number of remaining user verification retries.
func (d *Device) GetUVRetries() (uint, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	uv, ok := d.info.Options[ctap2.OptionUserVerification]
	if !ok {
		return 0, newErrorMessage(ErrNotSupported, "device doesn't support user verification")
	}
	if !uv {
		return 0, newErrorMessage(ErrUvNotConfigured, "please configure UV first (e.g. enroll biometry)")
	}

	return d.ctapClient.GetUVRetries()
}

// Reset performs a factory reset on the device.
func (d *Device) Reset() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.ctapClient.Reset()
}

// GetBioModality returns bio modality of authenticator.
// Currently, only fingerprint modality is defined in the FIDO 2.2 specification.
func (d *Device) GetBioModality() (*ctap2.AuthenticatorBioEnrollmentResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	bioEnroll, ok := d.info.Options[ctap2.OptionBioEnroll]
	if d.info.IsPreviewOnly() {
		bioEnroll, ok = d.info.Options[ctap2.OptionUserVerificationMgmtPreview]
	}
	if !ok || !bioEnroll {
		return nil, newErrorMessage(ErrNotSupported, "device doesn't support biometric enrollment")
	}

	return d.ctapClient.GetBioModality(

		d.info.IsPreviewOnly(),
	)
}

// GetFingerprintSensorInfo returns three properties:
//
//		FingerprintKind: For touch type fingerprints, its value is 1. For swipe type fingerprints, its value is 2.
//		MaxCaptureSamplesRequiredForEnroll: Indicates the maximum good samples required for enrollment.
//	 	MaxTemplateFriendlyName: Indicates the maximum number of bytes the authenticator will accept as a templateFriendlyName.
func (d *Device) GetFingerprintSensorInfo() (*ctap2.AuthenticatorBioEnrollmentResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	bioEnroll, ok := d.info.Options[ctap2.OptionBioEnroll]
	if d.info.IsPreviewOnly() {
		bioEnroll, ok = d.info.Options[ctap2.OptionUserVerificationMgmtPreview]
	}
	if !ok || !bioEnroll {
		return nil, newErrorMessage(ErrNotSupported, "device doesn't support biometric enrollment")
	}

	return d.ctapClient.GetFingerprintSensorInfo(

		d.info.IsPreviewOnly(),
	)
}

// BeginEnroll begins a fingerprint enrollment process and returns TemplateID, LastEnrollSampleStatus,
// and RemainingSamples properties. Use those properties to continue to capture the next samples or cancel it.
func (d *Device) BeginEnroll(
	pinUvAuthToken []byte,
	timeoutMilliseconds uint,
) (*ctap2.AuthenticatorBioEnrollmentResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	bioEnroll, ok := d.info.Options[ctap2.OptionBioEnroll]
	if d.info.IsPreviewOnly() {
		bioEnroll, ok = d.info.Options[ctap2.OptionUserVerificationMgmtPreview]
	}
	if !ok || !bioEnroll {
		return nil, newErrorMessage(ErrNotSupported, "device doesn't support biometric enrollment")
	}

	return d.ctapClient.BeginEnroll(

		d.info.IsPreviewOnly(),
		d.info.PinUvAuthProtocols[0],
		pinUvAuthToken,
		timeoutMilliseconds,
	)
}

// EnrollCaptureNextSample continues capturing samples from an already started enrollment process.
func (d *Device) EnrollCaptureNextSample(
	pinUvAuthToken []byte,
	templateID []byte,
	timeoutMilliseconds uint,
) (*ctap2.AuthenticatorBioEnrollmentResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	bioEnroll, ok := d.info.Options[ctap2.OptionBioEnroll]
	if d.info.IsPreviewOnly() {
		bioEnroll, ok = d.info.Options[ctap2.OptionUserVerificationMgmtPreview]
	}
	if !ok || !bioEnroll {
		return nil, newErrorMessage(ErrNotSupported, "device doesn't support biometric enrollment")
	}

	return d.ctapClient.EnrollCaptureNextSample(

		d.info.IsPreviewOnly(),
		d.info.PinUvAuthProtocols[0],
		pinUvAuthToken,
		templateID,
		timeoutMilliseconds,
	)
}

// CancelCurrentEnrollment cancels a current enrollment process.
func (d *Device) CancelCurrentEnrollment() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	bioEnroll, ok := d.info.Options[ctap2.OptionBioEnroll]
	if d.info.IsPreviewOnly() {
		bioEnroll, ok = d.info.Options[ctap2.OptionUserVerificationMgmtPreview]
	}
	if !ok || !bioEnroll {
		return newErrorMessage(ErrNotSupported, "device doesn't support biometric enrollment")
	}

	return d.ctapClient.CancelCurrentEnrollment(

		d.info.IsPreviewOnly(),
	)
}

// EnumerateEnrollments enumerates enrollments by returning TemplateInfos property with an array of TemplateInfo
// for all the enrollments available on the authenticator.
func (d *Device) EnumerateEnrollments(pinUvAuthToken []byte) (*ctap2.AuthenticatorBioEnrollmentResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	bioEnroll, ok := d.info.Options[ctap2.OptionBioEnroll]
	if d.info.IsPreviewOnly() {
		bioEnroll, ok = d.info.Options[ctap2.OptionUserVerificationMgmtPreview]
	}
	if !ok || !bioEnroll {
		return nil, newErrorMessage(ErrNotSupported, "device doesn't support biometric enrollment")
	}

	return d.ctapClient.EnumerateEnrollments(

		d.info.IsPreviewOnly(),
		d.info.PinUvAuthProtocols[0],
		pinUvAuthToken,
	)
}

// SetFriendlyName allows renaming/setting of a friendly fingerprint name.
func (d *Device) SetFriendlyName(pinUvAuthToken []byte, templateID []byte, friendlyName string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	bioEnroll, ok := d.info.Options[ctap2.OptionBioEnroll]
	if d.info.IsPreviewOnly() {
		bioEnroll, ok = d.info.Options[ctap2.OptionUserVerificationMgmtPreview]
	}
	if !ok || !bioEnroll {
		return newErrorMessage(ErrNotSupported, "device doesn't support biometric enrollment")
	}

	return d.ctapClient.SetFriendlyName(

		d.info.IsPreviewOnly(),
		d.info.PinUvAuthProtocols[0],
		pinUvAuthToken,
		templateID,
		friendlyName,
	)
}

// RemoveEnrollment removes existing enrollment.
func (d *Device) RemoveEnrollment(pinUvAuthToken []byte, templateID []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	bioEnroll, ok := d.info.Options[ctap2.OptionBioEnroll]
	if d.info.IsPreviewOnly() {
		bioEnroll, ok = d.info.Options[ctap2.OptionUserVerificationMgmtPreview]
	}
	if !ok || !bioEnroll {
		return newErrorMessage(ErrNotSupported, "device doesn't support biometric enrollment")
	}

	return d.ctapClient.RemoveEnrollment(

		d.info.IsPreviewOnly(),
		d.info.PinUvAuthProtocols[0],
		pinUvAuthToken,
		templateID,
	)
}

// GetCredsMetadata retrieves credential management metadata if the device supports it.
// Mainly ExistingResidentCredentialsCount and MaxPossibleRemainingResidentCredentialsCount.
func (d *Device) GetCredsMetadata(pinUvAuthToken []byte) (*ctap2.AuthenticatorCredentialManagementResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	credMgmt, ok := d.info.Options[ctap2.OptionCredentialManagement]
	if d.info.IsPreviewOnly() {
		credMgmt, ok = d.info.Options[ctap2.OptionCredentialManagementPreview]
	}
	if !ok || !credMgmt {
		return nil, newErrorMessage(ErrNotSupported, "device doesn't support credential management")
	}

	return d.ctapClient.GetCredsMetadata(

		d.info.IsPreviewOnly(),
		d.info.PinUvAuthProtocols[0],
		pinUvAuthToken,
	)
}

// EnumerateRPs provides a generator function to iterate over Relying Parties stored on the device.
// It utilizes the Credential Management extension and yields results via a callback function.
// If the device does not support credential management, an error is yielded.
func (d *Device) EnumerateRPs(
	pinUvAuthToken []byte,
) iter.Seq2[*ctap2.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(*ctap2.AuthenticatorCredentialManagementResponse, error) bool) {
		d.mu.Lock()
		defer d.mu.Unlock()

		credMgmt, ok := d.info.Options[ctap2.OptionCredentialManagement]
		if d.info.IsPreviewOnly() {
			credMgmt, ok = d.info.Options[ctap2.OptionCredentialManagementPreview]
		}
		if !ok || !credMgmt {
			yield(nil, newErrorMessage(ErrNotSupported, "device doesn't support credential management"))
		}

		for rp, err := range d.ctapClient.EnumerateRPs(
			d.info.IsPreviewOnly(),
			d.info.PinUvAuthProtocols[0],
			pinUvAuthToken,
		) {
			if !yield(rp, err) {
				return
			}
		}
	}
}

// EnumerateCredentials provides a generator function to iterate over Credentials stored on the device
// for the specified Relying Party. It utilizes the Credential Management extension and yields results
// via a callback function. If the device does not support credential management, an error is yielded.
func (d *Device) EnumerateCredentials(
	pinUvAuthToken []byte,
	rpIDHash []byte,
) iter.Seq2[*ctap2.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(*ctap2.AuthenticatorCredentialManagementResponse, error) bool) {
		d.mu.Lock()
		defer d.mu.Unlock()

		credMgmt, ok := d.info.Options[ctap2.OptionCredentialManagement]
		if d.info.IsPreviewOnly() {
			credMgmt, ok = d.info.Options[ctap2.OptionCredentialManagementPreview]
		}
		if !ok || !credMgmt {
			yield(nil, newErrorMessage(ErrNotSupported, "device doesn't support credential management"))
		}

		for rp, err := range d.ctapClient.EnumerateCredentials(

			d.info.IsPreviewOnly(),
			d.info.PinUvAuthProtocols[0],
			pinUvAuthToken,
			rpIDHash,
		) {
			if !yield(rp, err) {
				return
			}
		}
	}
}

// DeleteCredential removes a specified credential from the device using the given authentication token.
// It returns an error if credential management is not supported or the operation fails.
func (d *Device) DeleteCredential(
	pinUvAuthToken []byte,
	credentialID webauthn.PublicKeyCredentialDescriptor,
) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	credMgmt, ok := d.info.Options[ctap2.OptionCredentialManagement]
	if d.info.IsPreviewOnly() {
		credMgmt, ok = d.info.Options[ctap2.OptionCredentialManagementPreview]
	}
	if !ok || !credMgmt {
		return newErrorMessage(ErrNotSupported, "device doesn't support credential management")
	}

	return d.ctapClient.DeleteCredential(

		d.info.IsPreviewOnly(),
		d.info.PinUvAuthProtocols[0],
		pinUvAuthToken,
		credentialID,
	)
}

// UpdateUserInformation updates information of an existing user credential on the device.
// Requires the device to support credential management features.
// Returns an error if the operation is not supported or fails.
func (d *Device) UpdateUserInformation(
	pinUvAuthToken []byte,
	credentialID webauthn.PublicKeyCredentialDescriptor,
	user webauthn.PublicKeyCredentialUserEntity,
) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	credMgmt, ok := d.info.Options[ctap2.OptionCredentialManagement]
	if d.info.IsPreviewOnly() {
		credMgmt, ok = d.info.Options[ctap2.OptionCredentialManagementPreview]
	}
	if !ok || !credMgmt {
		return newErrorMessage(ErrNotSupported, "device doesn't support credential management")
	}

	return d.ctapClient.UpdateUserInformation(

		false, //d.info.IsPreviewOnly(),
		d.info.PinUvAuthProtocols[0],
		pinUvAuthToken,
		credentialID,
		user,
	)
}

// GetLargeBlobs retrieves a list of large blobs from the device that supports the large blobs option.
// Returns an error if the device does not support large blobs or if there is an issue with the retrieval process.
// Ensures integrity by validating computed and actual hashes of the retrieved data.
func (d *Device) GetLargeBlobs() ([]*ctap2.LargeBlob, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	largeBlobs, ok := d.info.Options[ctap2.OptionLargeBlobs]
	if !ok || !largeBlobs {
		return nil, newErrorMessage(ErrNotSupported, "device doesn't support largeBlobs")
	}

	maxFragmentLength := d.info.MaxMsgSize - 64

	resp, err := d.ctapClient.LargeBlobs(

		0,
		nil,
		maxFragmentLength,
		nil,
		0,
		0,
	)
	if err != nil {
		return nil, err
	}

	config := resp.Config
	offset := maxFragmentLength

	// Continue to read
	for uint(len(config)) == maxFragmentLength {
		respNext, err := d.ctapClient.LargeBlobs(

			0,
			nil,
			maxFragmentLength,
			nil,
			offset,
			0,
		)
		if err != nil {
			return nil, err
		}

		config = slices.Concat(config, respNext.Config)
		offset += uint(len(respNext.Config))
	}

	bLargeBlobs := config[:len(config)-16]
	hash := config[len(config)-16:]

	hasher := sha256.New()
	hasher.Write(bLargeBlobs)
	if !slices.Equal(hash, hasher.Sum(nil)[:16]) {
		return nil, newErrorMessage(
			ErrLargeBlobsIntegrityCheck,
			"for some reason calculated and actual hashes mismatch",
		)
	}

	var blobs []*ctap2.LargeBlob
	if err := cbor.Unmarshal(bLargeBlobs, &blobs); err != nil {
		return nil, err
	}

	return blobs, nil
}

// SetLargeBlobs stores large blobs on the device, ensuring compatibility with its supported capabilities and limits.
// It validates device support, fragments the blob data if needed, and sends it in chunks to the device.
// Returns an error if the device does not support large blobs, the data exceeds size limits, or if any other failure occurs.
func (d *Device) SetLargeBlobs(pinUvAuthToken []byte, blobs []*ctap2.LargeBlob) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	largeBlobs, ok := d.info.Options[ctap2.OptionLargeBlobs]
	if !ok || !largeBlobs {
		return newErrorMessage(ErrNotSupported, "device doesn't support largeBlobs")
	}

	set, err := d.cborEncMode.Marshal(blobs)
	if err != nil {
		return err
	}

	hasher := sha256.New()
	hasher.Write(set)
	hash := hasher.Sum(nil)

	set = slices.Concat(set, hash[:16])

	if uint(len(set)) > d.info.MaxSerializedLargeBlobArray {
		return newErrorMessage(
			ErrLargeBlobsTooBig,
			fmt.Sprintf(
				"this device max serialized large blob size is %db while you are trying to save %db",
				d.info.MaxSerializedLargeBlobArray,
				len(set),
			),
		)
	}

	maxFragmentLength := d.info.MaxMsgSize - 64
	offset := uint(0)
	length := uint(len(set))

	i := 0
	for chunk := range slices.Chunk(set, int(maxFragmentLength)) { //nolint:gosec
		if i > 0 {
			length = 0
		}

		if _, err := d.ctapClient.LargeBlobs(

			d.info.PinUvAuthProtocols[0],
			pinUvAuthToken,
			0,
			chunk,
			offset,
			length,
		); err != nil {
			return err
		}

		offset += uint(len(chunk))
		i++
	}

	return nil
}

// EnableEnterpriseAttestation enables enterprise attestation on the device if supported, using the provided token.
func (d *Device) EnableEnterpriseAttestation(pinUvAuthToken []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if authnrCfg, ok := d.info.Options[ctap2.OptionAuthenticatorConfig]; !ok || !authnrCfg {
		return newErrorMessage(ErrNotSupported, "device doesn't support authnrCfg")
	}
	if _, ok := d.info.Options[ctap2.OptionEnterpriseAttestation]; !ok {
		return newErrorMessage(ErrNotSupported, "device doesn't support ep")
	}

	return d.ctapClient.EnableEnterpriseAttestation(

		d.info.PinUvAuthProtocols[0],
		pinUvAuthToken,
	)
}

// ToggleAlwaysUV toggles the always UV (User Verification) setting on the device if supported, using the provided token.
func (d *Device) ToggleAlwaysUV(pinUvAuthToken []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if authnrCfg, ok := d.info.Options[ctap2.OptionAuthenticatorConfig]; !ok || !authnrCfg {
		return newErrorMessage(ErrNotSupported, "device doesn't support authnrCfg")
	}
	if _, ok := d.info.Options[ctap2.OptionAlwaysUv]; !ok {
		return newErrorMessage(ErrNotSupported, "device doesn't support alwaysUv")
	}

	return d.ctapClient.ToggleAlwaysUV(

		d.info.PinUvAuthProtocols[0],
		pinUvAuthToken,
	)
}

// SetMinPINLength sets the minimum PIN length on the device if supported, using the provided token and parameters.
func (d *Device) SetMinPINLength(
	pinUvAuthToken []byte,
	newMinPINLength uint,
	minPinLengthRPIDs []string,
	forceChangePin bool,
	pinComplexityPolicy bool,
) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if authnrCfg, ok := d.info.Options[ctap2.OptionAuthenticatorConfig]; !ok || !authnrCfg {
		return newErrorMessage(ErrNotSupported, "device doesn't support authnrCfg")
	}

	return d.ctapClient.SetMinPINLength(

		d.info.PinUvAuthProtocols[0],
		pinUvAuthToken,
		newMinPINLength,
		minPinLengthRPIDs,
		forceChangePin,
		pinComplexityPolicy,
	)
}

// Selection is a higher-level version of ctap.Selection, which cancels the
// command if the context is canceled.
func (d *Device) Selection(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	errc := make(chan error, 1)

	go func() {
		if err := d.ctapClient.Selection(); err != nil {
			errc <- err
		}
		errc <- nil
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errc:
		return err
	}
}
