package ctap2

// AuthenticatorConfigRequest represents the request for AuthenticatorConfig command.
type AuthenticatorConfigRequest struct {
	SubCommand        ConfigSubCommand      `cbor:"1,keyasint"`
	SubCommandParams  any                   `cbor:"2,keyasint,omitzero"`
	PinUvAuthProtocol PinUvAuthProtocolType `cbor:"3,keyasint,omitempty"`
	PinUvAuthParam    []byte                `cbor:"4,keyasint,omitempty"`
}

// SetMinPINLengthConfigSubCommandParams represents the parameters for SetMinPINLength sub-command.
type SetMinPINLengthConfigSubCommandParams struct {
	NewMinPINLength     uint     `cbor:"1,keyasint,omitempty"`
	MinPinLengthRPIDs   []string `cbor:"2,keyasint,omitempty"`
	ForceChangePin      bool     `cbor:"3,keyasint,omitempty"`
	PinComplexityPolicy bool     `cbor:"4,keyasint,omitempty"`
}

// ConfigSubCommand represents the sub-command for AuthenticatorConfig.
type ConfigSubCommand byte

func (cmd ConfigSubCommand) String() string {
	return configSubCommandStringMap[cmd]
}

const (
	// ConfigSubCommandEnableEnterpriseAttestation enables enterprise attestation.
	ConfigSubCommandEnableEnterpriseAttestation ConfigSubCommand = iota + 1
	// ConfigSubCommandToggleAlwaysUv toggles the Always UV setting.
	ConfigSubCommandToggleAlwaysUv
	// ConfigSubCommandSetMinPINLength sets the minimum PIN length.
	ConfigSubCommandSetMinPINLength
	// ConfigSubCommandVendorPrototype represents a vendor prototype sub-command.
	ConfigSubCommandVendorPrototype ConfigSubCommand = 0xff
)

var configSubCommandStringMap = map[ConfigSubCommand]string{
	ConfigSubCommandEnableEnterpriseAttestation: "EnableEnterpriseAttestation",
	ConfigSubCommandToggleAlwaysUv:              "ToggleAlwaysUv",
	ConfigSubCommandSetMinPINLength:             "SetMinPINLength",
	ConfigSubCommandVendorPrototype:             "VendorPrototype",
}
