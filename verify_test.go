package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"
)

func generateCa(org string, parentCa *x509.Certificate, parentCaPrivateKey *rsa.PrivateKey) (pemBytes []byte, caPrivateKey *rsa.PrivateKey, err error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization: []string{org},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivateKey, err = rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	if parentCa == nil {
		parentCa = tmpl
		parentCaPrivateKey = caPrivateKey
	}

	pemBuffer := new(bytes.Buffer)
	if caPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096); err != nil {
		return nil, nil, err
	} else if caBytes, err := x509.CreateCertificate(rand.Reader, tmpl, parentCa, &caPrivateKey.PublicKey, parentCaPrivateKey); err != nil {
		return nil, nil, err
	} else if err := pem.Encode(pemBuffer, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	}); err != nil {
		return nil, nil, err
	} else {
		return pemBuffer.Bytes(), caPrivateKey, nil
	}
}

func generateCert(commonName, org string, ca *x509.Certificate, caPrivateKey *rsa.PrivateKey) (pemBytes []byte, err error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{org},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	pemBuffer := new(bytes.Buffer)
	if certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096); err != nil {
		return nil, err
	} else if certBytes, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &certPrivKey.PublicKey, caPrivateKey); err != nil {
		return nil, err
	} else if err := pem.Encode(pemBuffer, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}); err != nil {
		return nil, err
	} else {
		return pemBuffer.Bytes(), nil
	}
}

func getCertificateFromPem(pemBytes []byte) (*x509.Certificate, error) {
	if block, _ := pem.Decode(pemBytes); block == nil {
		return nil, fmt.Errorf("unexpected problem decoding cert: %v", pemBytes)
	} else if cert, err := x509.ParseCertificate(block.Bytes); err != nil {
		return nil, err
	} else {
		return cert, nil
	}
}

func Test_verify(t *testing.T) {
	rootCaPemBytes, rootCaPrivateKey, err := generateCa("foo root", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	rootCa, err := getCertificateFromPem(rootCaPemBytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	firstIntermediateCaPemBytes, firstIntermediateCaPrivateKey, err := generateCa("foo intermediate 1", rootCa, rootCaPrivateKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	firstIntermediateCa, err := getCertificateFromPem(firstIntermediateCaPemBytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	secondIntermediateCaPemBytes, secondIntermediateCaPrivateKey, err := generateCa("foo intermediate 2", firstIntermediateCa, firstIntermediateCaPrivateKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	secondIntermediateCa, err := getCertificateFromPem(secondIntermediateCaPemBytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	certPemBytes, err := generateCert("localhost", "foo bar", secondIntermediateCa, secondIntermediateCaPrivateKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cert, err := getCertificateFromPem(certPemBytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	roots := x509.NewCertPool()
	if ok := roots.AppendCertsFromPEM(rootCaPemBytes); !ok {
		t.Fatal("unexpected problem generating root CertPool...")
	}

	intermediates := x509.NewCertPool()
	if ok := intermediates.AppendCertsFromPEM(bytes.Join([][]byte{firstIntermediateCaPemBytes, secondIntermediateCaPemBytes}, []byte("\n"))); !ok {
		t.Fatal("unexpected problem generating root CertPool...")
	}

	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		DNSName:       "localhost",
		Intermediates: intermediates,
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:   roots,
		DNSName: "localhost",
		//Intermediates: intermediates,
	}); err == nil {
		t.Fatal("expected cert.Verify() error, but didn't get it")
	}
}
