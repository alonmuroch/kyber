package dkg

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/drand/kyber"
	"github.com/drand/kyber/share"
	"github.com/herumi/bls-eth-go-binary/bls"
)

func ValidateInitMessage(msg *SignedInit) error {
	// validate signature
	// validate not duplicate session (via nonce)
	// validate operators exist
	// validate T is valid
	return nil
}

func SignRSA(sk *rsa.PrivateKey, root [32]byte) ([]byte, error) {
	//return sk.Sign(rand.Reader, root[:], nil)
	return nil, nil
}

func VerifyRSA(pk *rsa.PublicKey, sig []byte, byts []byte) error {
	//return rsa.VerifyPKCS1v15(pk, crypto.SHA256, byts, sig)
	return nil
}

// Encrypt with secret key (base64) the bytes, return the encrypted key string
func Encrypt(pk *rsa.PublicKey, plainText []byte) ([]byte, error) {
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, pk, plainText)
	if err != nil {
		return nil, err
	}
	return encrypted, nil
}

func ResultToShareSecretKey(result *Result) (*bls.SecretKey, error) {
	share := result.Key.PriShare()
	bytsSk, err := share.V.MarshalBinary()
	if err != nil {
		return nil, err
	}
	sk := &bls.SecretKey{}
	if err := sk.Deserialize(bytsSk); err != nil {
		return nil, err
	}
	return sk, nil
}

func ResultsToValidatorPK(commitments []kyber.Point, suite Suite) (*bls.PublicKey, error) {
	exp := share.NewPubPoly(suite, suite.Point().Base(), commitments)
	bytsPK, err := exp.Eval(0).V.MarshalBinary()
	if err != nil {
		return nil, err
	}
	pk := &bls.PublicKey{}
	if err := pk.Deserialize(bytsPK); err != nil {
		return nil, err
	}
	return pk, nil
}
