package sshtls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"

	"golang.org/x/crypto/ed25519"
)

// Implements crypto.Signer
var _ crypto.Signer = (*SSHSigner)(nil)

type SSHSigner struct {
	Pubk crypto.PublicKey
}

func (s *SSHSigner) Public() crypto.PublicKey {
	log.Println("Public()")
	//return s.Pubk
	return &rsa.PublicKey{} // TODO This is dummy
}

func (s *SSHSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	log.Println("Sign()")
	return nil, nil
}

type Agent struct {
	// TODO these are dummy vals for testing
	Cert []byte
	Key  []byte
}

func (a *Agent) CertAgent(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	log.Println("CertAgent() called")
	/*
		ret := &tls.Certificate{
			Certificate: "",
		}*/
	//return ret, nil
	ret, err := Load(a.Cert, a.Key)
	ret.PrivateKey = &SSHSigner{
		Pubk: ret.Certificate, // TODO: Continue here, as Public() doesn't return a valid key. Should be *rsa.PublicKey, see tls/auth.go
	}
	return &ret, err
}

func Load(certPEMBlock, keyPEMBlock []byte) (tls.Certificate, error) {
	fail := func(err error) (tls.Certificate, error) { return tls.Certificate{}, err }

	var cert tls.Certificate
	var skippedBlockTypes []string

	for {
		var certDERBlock *pem.Block
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}

		if certDERBlock.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
		} else {
			skippedBlockTypes = append(skippedBlockTypes, certDERBlock.Type)
		}

	}

	if len(cert.Certificate) == 0 {
		if len(skippedBlockTypes) == 0 {
			return fail(errors.New("tls: failed to find any PEM data in certificate input"))
		}

		if len(skippedBlockTypes) == 1 && strings.HasSuffix(skippedBlockTypes[0], "PRIVATE KEY") {
			return fail(errors.New("tls: failed to find certificate PEM data in certificate input, but did find a private key; PEM inputs may have been switched"))
		}

		return fail(fmt.Errorf("tls: failed to find \"CERTIFICATE\" PEM block in certificate input after skipping PEM blocks of the following types: %v", skippedBlockTypes))
	}

	skippedBlockTypes = skippedBlockTypes[:0]

	var keyDERBlock *pem.Block
	for {
		keyDERBlock, keyPEMBlock = pem.Decode(keyPEMBlock)

		if keyDERBlock == nil {
			if len(skippedBlockTypes) == 0 {
				return fail(errors.New("tls: failed to find any PEM data in key input"))
			}

			if len(skippedBlockTypes) == 1 && skippedBlockTypes[0] == "CERTIFICATE" {
				return fail(errors.New("tls: found a certificate rather than a key in the PEM for the private key"))
			}

			return fail(fmt.Errorf("tls: failed to find PEM block with type ending in \"PRIVATE KEY\" in key input after skipping PEM blocks of the following types: %v", skippedBlockTypes))
		}

		if keyDERBlock.Type == "PRIVATE KEY" || strings.HasSuffix(keyDERBlock.Type, " PRIVATE KEY") {
			break
		}

		skippedBlockTypes = append(skippedBlockTypes, keyDERBlock.Type)
	}

	pk, err := parsePrivateKey(keyDERBlock.Bytes)
	cert.PrivateKey = pk
	if err != nil {
		return fail(err)
	}

	return cert, nil
}

func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}

	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("tls: found unknown private key type in PKCS#8 wrapping")
		}
	}

	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("tls: failed to parse private key")
}
