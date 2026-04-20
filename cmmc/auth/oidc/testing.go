package oidc

import "time"

// EncodeStateCookieForTest is exported for handler-level tests in the
// fbhttp package. It lets tests build a valid signed state cookie without
// going through the /login redirect, so /callback can be exercised in
// isolation. Not used in production code.
func EncodeStateCookieForTest(sc StateCookie, signingKey []byte) (string, error) {
	return encodeStateCookie(sc, signingKey)
}

// ResetSingletonForTest wipes the package-global provider state so test
// binaries don't leak singleton init between tests. Not used in
// production code. Named "ForTest" to make greppers trip when a
// non-test file imports it.
func ResetSingletonForTest() {
	singletonMu.Lock()
	singletonProvider = nil
	singletonVerifier = nil
	singletonOAuth2 = nil
	singletonCfg = Config{}
	singletonInited = false
	singletonMu.Unlock()
	lazyCfgMu.Lock()
	lazyCfg = nil
	lazyAttempted = false
	lazyLastTry = time.Time{}
	lazyCfgMu.Unlock()
}
