package audit

// ChainReport is the read-time verification outcome for an audit
// chain slice. Shaped for the admin endpoint that returns it as
// JSON: integers for index math, booleans for at-a-glance status,
// base64 strings for MACs so the operator can paste them into a
// SIEM console for out-of-band comparison.
//
// Intact is derived from FirstBreakIndex (< 0 means intact) — the
// computed-in-Go method Intact() is exposed so callers don't have
// to remember the convention; the JSON payload carries both so
// dashboards can render without re-implementing the rule.
type ChainReport struct {
	Length          int    `json:"length"`
	Capacity        int    `json:"capacity"`
	Wrapped         bool   `json:"wrapped"`
	Intact          bool   `json:"intact"`
	FirstBreakIndex int    `json:"first_break_index"`
	GenesisUsed     string `json:"genesis_used"`
	GenesisProvided bool   `json:"genesis_provided"`
	ChainTip        string `json:"chain_tip"`
	// KeyMissing is true when the chain key was nil/short at verify
	// time. A MAC comparison against a missing key fails every
	// event — without this signal, operators see "tampered at 0"
	// and chase a ghost. When true, FirstBreakIndex / Intact
	// should be interpreted as "unverifiable," not "broken."
	KeyMissing bool `json:"key_missing"`
}

// VerifyRingBuffer walks the ring buffer in chronological order and
// returns a ChainReport. expectedGenesis is what the caller expects
// events[0].PrevMAC to equal. Pass "" for:
//   - the first-ever chain (no prior tip), OR
//   - "verify internal consistency only; I don't know the genesis"
//     — in that case we use events[0].PrevMAC itself, which means
//     FirstBreakIndex > 0 implies real tampering within the
//     buffered window, while index 0 just means the caller's
//     genesis didn't match and we've already told them so.
//
// Pass a non-empty expectedGenesis to verify end-to-end against a
// SIEM-side checkpoint.
//
// VerifyRingBuffer is safe to call concurrently with Emit — Snapshot
// takes a copy under the ring's mutex.
func VerifyRingBuffer(ring *RingBufferEmitter, expectedGenesis string, key []byte) ChainReport {
	if ring == nil {
		return ChainReport{FirstBreakIndex: -1, Intact: true}
	}
	events := ring.Snapshot()
	length := len(events)
	capacity := ring.Capacity()
	wrapped := length > 0 && length == capacity
	keyMissing := len(key) < 32

	report := ChainReport{
		Length:          length,
		Capacity:        capacity,
		Wrapped:         wrapped,
		FirstBreakIndex: -1,
		GenesisProvided: expectedGenesis != "",
		KeyMissing:      keyMissing,
	}
	if length == 0 {
		report.Intact = true
		report.GenesisUsed = expectedGenesis
		return report
	}

	genesis := expectedGenesis
	if genesis == "" {
		// "I don't know the genesis" — accept whatever the first
		// event advertises and verify the rest against it. With
		// this mode, a tampered events[0] is undetectable (the
		// verifier has no anchor to disagree with). The endpoint
		// flags this via GenesisProvided=false so operators know
		// this is a weaker check than SIEM-checkpointed verify.
		genesis = events[0].PrevMAC
	}
	report.GenesisUsed = genesis
	report.ChainTip = events[length-1].MAC

	breakIdx := VerifyChain(events, key, genesis)
	report.FirstBreakIndex = breakIdx
	report.Intact = breakIdx < 0
	return report
}

// DeriveChainKey returns the key used to HMAC the audit chain, or
// nil if the input key is too short to be safe. Centralized so the
// boot-time gate in cmd/root.go and the read-time verify in
// http/cmmc_audit.go cannot drift apart. A ≥32-byte key is the
// HMAC-SHA256 best-practice threshold; shorter keys are refused
// rather than silently padded.
func DeriveChainKey(raw []byte) []byte {
	if len(raw) < 32 {
		return nil
	}
	return raw
}
