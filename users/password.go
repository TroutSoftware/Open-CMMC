package users

import (
	"crypto/rand"
	"encoding/base64"

	"golang.org/x/crypto/bcrypt"

	fberrors "github.com/filebrowser/filebrowser/v2/errors"
)

// ValidateAndHashPwd validates and hashes a password.
//
// CMMC trim-1: the common-passwords blocklist (832 KB embedded
// file) was dropped. Under OIDC, user passwords live in Keycloak
// and Keycloak's realm password policy is authoritative. The only
// remaining caller here is OIDC provisioning's placeholder-
// password generator, which uses crypto/rand + base64 — not a
// human-chosen password that could collide with the blocklist.
func ValidateAndHashPwd(password string, minimumLength uint) (string, error) {
	if uint(len(password)) < minimumLength {
		return "", fberrors.ErrShortPassword{MinimumLength: minimumLength}
	}
	return HashPwd(password)
}

// HashPwd hashes a password.
func HashPwd(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// CheckPwd checks if a password is correct.
func CheckPwd(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func RandomPwd(passwordLength uint) (string, error) {
	randomPasswordBytes := make([]byte, passwordLength)
	var _, err = rand.Read(randomPasswordBytes)
	if err != nil {
		return "", err
	}

	// This is done purely to make the password human-readable
	var randomPasswordString = base64.URLEncoding.EncodeToString(randomPasswordBytes)
	return randomPasswordString, nil
}
