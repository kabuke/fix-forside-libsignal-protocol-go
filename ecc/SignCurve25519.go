package ecc

// Package curve25519sign implements a signature scheme based on Curve25519 keys.
// See https://moderncrypto.org/mail-archive/curves/2014/000205.html for details.

import (
	"crypto/sha512"

	"filippo.io/edwards25519"
)

// sign signs the message with privateKey and returns a signature as a byte slice.
func sign(privateKey *[32]byte, message []byte, random [64]byte) *[64]byte {
	// Calculate Ed25519 public key from Curve25519 private key
	privScalar, err := new(edwards25519.Scalar).SetBytesWithClamping(privateKey[:])
	if err != nil {
		panic("invalid private key")
	}
	publicKey := new(edwards25519.Point).ScalarBaseMult(privScalar).Bytes()

	// Calculate r
	diversifier := [32]byte{
		0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

	var r [64]byte
	hash := sha512.New()
	hash.Write(diversifier[:])
	hash.Write(privateKey[:])
	hash.Write(message)
	hash.Write(random[:])
	hash.Sum(r[:0])

	// Reduce r mod L (Ed25519 curve order)
	rScalar, _ := edwards25519.NewScalar().SetUniformBytes(r[:])

	// Calculate R = r * B (base point)
	R := new(edwards25519.Point).ScalarBaseMult(rScalar)
	encodedR := R.Bytes()

	// Calculate h = SHA512(R || A_ed || msg)
	hash.Reset()
	hash.Write(encodedR[:])
	hash.Write(publicKey[:])
	hash.Write(message)
	var hramDigest [64]byte
	hash.Sum(hramDigest[:0])
	hramScalar, _ := edwards25519.NewScalar().SetUniformBytes(hramDigest[:])

	// Calculate S = (r + h * privKey) mod L
	s := edwards25519.NewScalar().MultiplyAdd(hramScalar, privScalar, rScalar)

	// Combine R and S into the signature
	signature := new([64]byte)
	copy(signature[:], encodedR[:])
	copy(signature[32:], s.Bytes())

	// Restore the sign bit in the signature
	signature[63] |= publicKey[31] & 0x80

	return signature
}

// verify checks whether the message has a valid signature.
func verify(publicKey [32]byte, message []byte, signature *[64]byte) bool {
	publicKey[31] &= 0x7F

	// Load the public key into a Point object
	A, err := new(edwards25519.Point).SetBytes(publicKey[:])
	if err != nil {
		return false
	}

	// Split the signature into R and S
	R := new(edwards25519.Point)
	_, err = R.SetBytes(signature[:32])
	if err != nil {
		return false
	}

	// Create a scalar from the last 32 bytes of the signature
	s := new(edwards25519.Scalar)
	_, err = s.SetCanonicalBytes(signature[32:])
	if err != nil {
		return false
	}

	// s := new(edwards25519.Scalar).SetBytes(signature[32:])

	// Calculate h = SHA512(R || A_ed || msg)
	hash := sha512.New()
	hash.Write(signature[:32])
	hash.Write(publicKey[:])
	hash.Write(message)
	var hramDigest [64]byte
	hash.Sum(hramDigest[:0])
	hramScalar, _ := edwards25519.NewScalar().SetUniformBytes(hramDigest[:])

	// Check if S * B == R + h * A
	check := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(hramScalar, A, s)
	return check.Equal(R) == 1
}

// func main() {
// 	// Example usage
// 	privateKey := &[32]byte{0x1, 0x2, 0x3} // Use real key in production
// 	message := []byte("Hello, world!")
// 	random := [64]byte{}

// 	signature := sign(privateKey, message, random)
// 	fmt.Printf("Signature: %x\n", signature)

// 	publicKey := new(edwards25519.Point).ScalarBaseMult(new(edwards25519.Scalar).SetBytesWithClamping(privateKey[:])).Bytes()
// 	valid := verify(publicKey, message, signature)
// 	fmt.Printf("Signature valid: %v\n", valid)
// }
