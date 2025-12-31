package webauthn

// PaymentEntityLogo represents a logo for a payment entity.
type PaymentEntityLogo struct {
	URL   string `cbor:"url"`
	Label string `cbor:"label"`
}

// PaymentCurrencyAmount represents a currency amount.
type PaymentCurrencyAmount struct {
	Currency string `cbor:"currency"`
	Value    string `cbor:"value"`
}

// PaymentCredentialInstrument represents a payment credential instrument.
type PaymentCredentialInstrument struct {
	DisplayName     string `cbor:"displayName"`
	Icon            string `cbor:"icon"`
	IconMustBeShown string `cbor:"iconMustBeShown,omitempty"` // should default to true
	Details         string `cbor:"details,omitempty"`
}

// AuthenticationExtensionsPaymentInputs represents the inputs for 'payment' extension.
type AuthenticationExtensionsPaymentInputs struct {
	IsPayment                    bool                            `cbor:"payment"`
	BrowserBoundPubKeyCredParams []PublicKeyCredentialParameters `cbor:"browserBoundPubKeyCredParams"`

	RPID                 string                       `cbor:"rpId"`
	TopOrigin            string                       `cbor:"topOrigin"`
	PayeeName            string                       `cbor:"payeeName"`
	PayeeOrigin          string                       `cbor:"payeeOrigin"`
	PaymentEntitiesLogos []PaymentEntityLogo          `cbor:"paymentEntitiesLogos"`
	Total                *PaymentCurrencyAmount       `cbor:"total"`
	Instrument           *PaymentCredentialInstrument `cbor:"instrument"`
}

// PaymentInputs wraps the payment extension inputs.
type PaymentInputs struct {
	Payment AuthenticationExtensionsPaymentInputs `cbor:"payment"`
}

// BrowserBoundSignature represents a browser-bound signature.
type BrowserBoundSignature struct {
	Signature []byte `cbor:"signature"`
}

// AuthenticationExtensionsPaymentOutputs represents the outputs for 'payment' extension.
type AuthenticationExtensionsPaymentOutputs struct {
	BrowserBoundSignature *BrowserBoundSignature `cbor:"browserBoundSignature,omitempty"`
}

// PaymentOutputs wraps the payment extension outputs.
type PaymentOutputs struct {
	Payment AuthenticationExtensionsPaymentOutputs `cbor:"payment"`
}
