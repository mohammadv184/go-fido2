package ctap2

// AuthenticatorBioEnrollmentRequest represents the request for AuthenticatorBioEnrollment command.
type AuthenticatorBioEnrollmentRequest struct {
	Modality          BioModality                   `cbor:"1,keyasint,omitempty"`
	SubCommand        BioEnrollmentSubCommand       `cbor:"2,keyasint,omitempty"`
	SubCommandParams  BioEnrollmentSubCommandParams `cbor:"3,keyasint,omitzero"`
	PinUvAuthProtocol PinUvAuthProtocolType         `cbor:"4,keyasint,omitempty"`
	PinUvAuthParam    []byte                        `cbor:"5,keyasint,omitempty"`
	GetModality       bool                          `cbor:"6,keyasint,omitempty"`
}

// BioEnrollmentSubCommandParams represents parameters for BioEnrollment sub-commands.
type BioEnrollmentSubCommandParams struct {
	TemplateID           []byte `cbor:"1,keyasint,omitempty"`
	TemplateFriendlyName string `cbor:"2,keyasint,omitempty"`
	TimeoutMilliseconds  uint   `cbor:"3,keyasint,omitempty"`
}

// AuthenticatorBioEnrollmentResponse represents the response for AuthenticatorBioEnrollment command.
type AuthenticatorBioEnrollmentResponse struct {
	Modality                           BioModality            `cbor:"1,keyasint,omitempty"`
	FingerprintKind                    uint                   `cbor:"2,keyasint,omitempty"`
	MaxCaptureSamplesRequiredForEnroll uint                   `cbor:"3,keyasint,omitempty"`
	TemplateID                         []byte                 `cbor:"4,keyasint,omitempty"`
	LastEnrollSampleStatus             LastEnrollSampleStatus `cbor:"5,keyasint,omitempty"`
	RemainingSamples                   uint                   `cbor:"6,keyasint,omitempty"`
	TemplateInfos                      []TemplateInfo         `cbor:"7,keyasint,omitzero"`
	MaxTemplateFriendlyName            uint                   `cbor:"8,keyasint,omitempty"`
}

// TemplateInfo represents information about a biometric template.
type TemplateInfo struct {
	TemplateID           []byte `cbor:"1,keyasint"`
	TemplateFriendlyName string `cbor:"2,keyasint,omitempty"`
}

// BioEnrollmentSubCommand represents sub-commands for BioEnrollment.
type BioEnrollmentSubCommand byte

func (cmd BioEnrollmentSubCommand) String() string {
	return bioEnrollmentSubCommandStringMap[cmd]
}

const (
	// BioEnrollmentSubCommandEnrollBegin begins the enrollment process.
	BioEnrollmentSubCommandEnrollBegin BioEnrollmentSubCommand = iota + 1
	// BioEnrollmentSubCommandEnrollCaptureNextSample captures the next sample for enrollment.
	BioEnrollmentSubCommandEnrollCaptureNextSample
	// BioEnrollmentSubCommandCancelCurrentEnrollment cancels the current enrollment process.
	BioEnrollmentSubCommandCancelCurrentEnrollment
	// BioEnrollmentSubCommandEnumerateEnrollments enumerates existing enrollments.
	BioEnrollmentSubCommandEnumerateEnrollments
	// BioEnrollmentSubCommandSetFriendlyName sets a friendly name for an enrollment.
	BioEnrollmentSubCommandSetFriendlyName
	// BioEnrollmentSubCommandRemoveEnrollment removes an enrollment.
	BioEnrollmentSubCommandRemoveEnrollment
	// BioEnrollmentSubCommandGetFingerprintSensorInfo retrieves fingerprint sensor information.
	BioEnrollmentSubCommandGetFingerprintSensorInfo
)

var bioEnrollmentSubCommandStringMap = map[BioEnrollmentSubCommand]string{
	BioEnrollmentSubCommandEnrollBegin:              "EnrollBegin",
	BioEnrollmentSubCommandEnrollCaptureNextSample:  "EnrollCaptureNextSample",
	BioEnrollmentSubCommandCancelCurrentEnrollment:  "CancelCurrentEnrollment",
	BioEnrollmentSubCommandEnumerateEnrollments:     "EnumerateEnrollments",
	BioEnrollmentSubCommandSetFriendlyName:          "SetFriendlyName",
	BioEnrollmentSubCommandRemoveEnrollment:         "RemoveEnrollment",
	BioEnrollmentSubCommandGetFingerprintSensorInfo: "GetFingerprintSensorInfo",
}

// BioModality represents the biometric modality.
type BioModality uint

func (bm BioModality) String() string {
	return bioModalityStringMap[bm]
}

const (
	// BioModalityFingerprint represents fingerprint modality.
	BioModalityFingerprint BioModality = iota + 1
)

var bioModalityStringMap = map[BioModality]string{
	BioModalityFingerprint: "Fingerprint",
}

// LastEnrollSampleStatus represents the status of the last enrollment sample.
type LastEnrollSampleStatus uint

func (les LastEnrollSampleStatus) String() string {
	return lastEnrollSampleStatusStringMap[les]
}

const (
	// LastEnrollSampleStatusFingerprintGood means the sample was good.
	LastEnrollSampleStatusFingerprintGood LastEnrollSampleStatus = iota
	// LastEnrollSampleStatusFingerprintTooHigh means the finger was too high on the sensor.
	LastEnrollSampleStatusFingerprintTooHigh
	// LastEnrollSampleStatusFingerprintTooLow means the finger was too low on the sensor.
	LastEnrollSampleStatusFingerprintTooLow
	// LastEnrollSampleStatusFingerprintTooLeft means the finger was too left on the sensor.
	LastEnrollSampleStatusFingerprintTooLeft
	// LastEnrollSampleStatusFingerprintTooRight means the finger was too right on the sensor.
	LastEnrollSampleStatusFingerprintTooRight
	// LastEnrollSampleStatusFingerprintTooFast means the finger was moved too fast.
	LastEnrollSampleStatusFingerprintTooFast
	// LastEnrollSampleStatusFingerprintTooSlow means the finger was moved too slow.
	LastEnrollSampleStatusFingerprintTooSlow
	// LastEnrollSampleStatusFingerprintPoorQuality means the sample quality was poor.
	LastEnrollSampleStatusFingerprintPoorQuality
	// LastEnrollSampleStatusFingerprintTooSkewed means the finger was too skewed.
	LastEnrollSampleStatusFingerprintTooSkewed
	// LastEnrollSampleStatusFingerprintTooShort means the sample was too short.
	LastEnrollSampleStatusFingerprintTooShort
	// LastEnrollSampleStatusFingerprintMergeFailure means merging the samples failed.
	LastEnrollSampleStatusFingerprintMergeFailure
	// LastEnrollSampleStatusFingerprintExists means the fingerprint already exists.
	LastEnrollSampleStatusFingerprintExists
	_
	// LastEnrollSampleStatusNoUserActivity means no user activity was detected.
	LastEnrollSampleStatusNoUserActivity
	// LastEnrollSampleStatusNoUserPresenceTransition means no user presence transition was detected.
	LastEnrollSampleStatusNoUserPresenceTransition
)

var lastEnrollSampleStatusStringMap = map[LastEnrollSampleStatus]string{
	LastEnrollSampleStatusFingerprintGood:          "Good",
	LastEnrollSampleStatusFingerprintTooHigh:       "Too High",
	LastEnrollSampleStatusFingerprintTooLow:        "Too Low",
	LastEnrollSampleStatusFingerprintTooLeft:       "Too Left",
	LastEnrollSampleStatusFingerprintTooRight:      "Too Right",
	LastEnrollSampleStatusFingerprintTooFast:       "Too Fast",
	LastEnrollSampleStatusFingerprintTooSlow:       "Too Slow",
	LastEnrollSampleStatusFingerprintPoorQuality:   "Poor Quality",
	LastEnrollSampleStatusFingerprintTooSkewed:     "Too Skewed",
	LastEnrollSampleStatusFingerprintTooShort:      "Too Short",
	LastEnrollSampleStatusFingerprintMergeFailure:  "Merge Failure",
	LastEnrollSampleStatusFingerprintExists:        "Exists",
	LastEnrollSampleStatusNoUserActivity:           "No User Activity",
	LastEnrollSampleStatusNoUserPresenceTransition: "No User Presence Transition",
}
