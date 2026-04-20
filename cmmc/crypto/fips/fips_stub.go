//go:build !go1.24

package fips

// Enabled always returns false on pre-1.24 toolchains — the
// crypto/fips140 package does not exist there so we cannot prove the
// posture. The SSP must note that the deployment build requires Go
// 1.24+ (or RHEL go-toolset) for the runtime FIPS assertion to be
// meaningful. At Mode() this surfaces as "disabled".
func Enabled() bool {
	return false
}
