package sshtls

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"strings"
)

// Implements crypto.Signer
var _ crypto.Signer = (*SSHSigner)(nil)

type SSHSigner struct {
	Pubk  crypto.PublicKey
	Privk crypto.PrivateKey
}

func (s *SSHSigner) Public() crypto.PublicKey {
	log.Println("Public()")
	return s.Pubk
}

func (s *SSHSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	log.Println("Sign()")

	signer, ok := s.Privk.(crypto.Signer)
	if !ok {
		return nil, errors.New("private key is not a signer")
	}

	return signer.Sign(rand, digest, opts)
}

type Agent struct {
	Cert []byte
	Key  []byte
}

func (a *Agent) CertAgent(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	log.Println("CertAgent() called")

	// Parse certificate
	block, _ := pem.Decode(a.Cert)
	if block == nil {
		panic("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())

	}

	ret := tls.Certificate{
		Certificate: [][]byte{cert.Raw}, // TODO: is this valid?
	}

	// Parse private key
	keyDERBlock, _ := pem.Decode(a.Key)
	if keyDERBlock.Type != "PRIVATE KEY" && !strings.HasSuffix(keyDERBlock.Type, " PRIVATE KEY") {
		return nil, errors.New("Cannot load private key")
	}

	var key crypto.PrivateKey
	if key, err = x509.ParsePKCS1PrivateKey(keyDERBlock.Bytes); err == nil {
		log.Println("private key is PKCS1")
	} else if key, err = x509.ParsePKCS8PrivateKey(keyDERBlock.Bytes); err == nil {
		log.Println("private key is PKCS8")
	} else if key, err = x509.ParseECPrivateKey(keyDERBlock.Bytes); err == nil {
		log.Println("private key is EC")
	} else {
		return nil, errors.New("Cannot parse private key")
	}

	// Return tls.Certificate
	ret.PrivateKey = &SSHSigner{
		Pubk:  cert.PublicKey,
		Privk: key,
	}
	return &ret, err
}
