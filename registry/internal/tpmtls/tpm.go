package tpmtls

import (
	"crypto"
	"crypto/tls"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

type tpmSigner struct {
	Key      crypto.PublicKey
	Pub      tpm2.TPMTPublic
	PubBlob  []byte
	PrivBlob []byte
	SrkName  tpm2.TPM2BName
}

func (s *tpmSigner) Public() crypto.PublicKey {
	return s.Key
}

func (s *tpmSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	tpmRwc, err := linuxtpm.Open("/dev/tpmrm0")
	if err != nil {
		return nil, fmt.Errorf("failed to open TPM for signing: %%w", err)
	}
	defer tpmRwc.Close()

	handleParentObj := tpm2.NamedHandle{
		Handle: srkHandle,
		Name:   s.SrkName,
	}

	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](s.PubBlob)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal public blob: %%w", err)
	}
	priv, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](s.PrivBlob)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal private blob: %%w", err)
	}

	loadCmd := tpm2.Load{
		ParentHandle: handleParentObj,
		InPrivate:    *priv,
		InPublic:     *pub,
	}
	loadResp, err := loadCmd.Execute(tpmRwc)
	if err != nil {
		return nil, fmt.Errorf("failed to load key for signing: %%w", err)
	}
	defer func() {
		flush := tpm2.FlushContext{FlushHandle: loadResp.ObjectHandle}
		flush.Execute(tpmRwc)
	}()

	hashAlg, err := hashToTPMAlg(opts.HashFunc())
	if err != nil {
		return nil, err
	}

	signCmd := tpm2.Sign{
		KeyHandle: tpm2.NamedHandle{
			Handle: loadResp.ObjectHandle,
			Name:   loadResp.Name,
		},
		Digest: tpm2.TPM2BDigest{Buffer: digest},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgECDSA,
				&tpm2.TPMSSchemeHash{HashAlg: hashAlg},
			),
		},
		Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck},
	}
	signResp, err := signCmd.Execute(tpmRwc)
	if err != nil {
		return nil, fmt.Errorf("failed to execute TPM sign command: %%w", err)
	}

	ecdsaSig, err := signResp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, fmt.Errorf("failed to get ECDSA signature from TPM response: %%w", err)
	}

	r := new(big.Int).SetBytes(ecdsaSig.SignatureR.Buffer)
	sv := new(big.Int).SetBytes(ecdsaSig.SignatureS.Buffer)

	return asn1.Marshal(struct{ R, S *big.Int }{r, sv})
}

func hashToTPMAlg(h crypto.Hash) (tpm2.TPMIAlgHash, error) {
	switch h {
	case crypto.SHA256:
		return tpm2.TPMAlgSHA256, nil
	case crypto.SHA384:
		return tpm2.TPMAlgSHA384, nil
	case crypto.SHA512:
		return tpm2.TPMAlgSHA512, nil
	default:
		return tpm2.TPMAlgNull, fmt.Errorf("unsupported hash algorithm: %%v", h)
	}
}

type tss2PrivateKey struct {
	Oid          asn1.ObjectIdentifier
	EmptyAuth    bool `asn1:"explicit,tag:0"`
	ParentHandle int
	Public       []byte
	Private      []byte
}

const srkHandle tpm2.TPMHandle = tpm2.TPMHandle(0x81000001)

func IsTSS2PEM(keyPEM []byte) bool {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return false
	}
	return block.Type == "TSS2 PRIVATE KEY"
}

func LoadCertificate(certFile, keyFile string) (tls.Certificate, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to read certificate file: %%w", err)
	}

	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to read key file: %%w", err)
	}

	if IsTSS2PEM(keyPEM) {
		return GetTSS2Certificate(certPEM, keyPEM)
	}

	return tls.X509KeyPair(certPEM, keyPEM)
}

func GetTSS2Certificate(certPEM, keyPEM []byte) (tls.Certificate, error) {
	var certDERs [][]byte
	rest := certPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			certDERs = append(certDERs, block.Bytes)
		}
	}
	if len(certDERs) == 0 {
		return tls.Certificate{}, fmt.Errorf("failed to decode any CERTIFICATE block from cert PEM")
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return tls.Certificate{}, fmt.Errorf("failed to decode key PEM")
	}

	var tssKey tss2PrivateKey
	if _, err := asn1.Unmarshal(keyBlock.Bytes, &tssKey); err != nil {
		return tls.Certificate{}, fmt.Errorf("couldn't unmarshal TSS2 key: %%w", err)
	}

	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](tssKey.Public)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("couldn't unmarshal public key: %%w", err)
	}

	pubC, err := pub.Contents()
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to get public key contents: %%w", err)
	}

	signer, err := NewTPMSigner(pubC, tssKey.Public, tssKey.Private)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create TPM signer: %%w", err)
	}

	return tls.Certificate{
		Certificate: certDERs,
		PrivateKey:  signer,
	}, nil
}

func NewTPMSigner(pub *tpm2.TPMTPublic, pubBlob, privBlob []byte) (*tpmSigner, error) {
	key, err := tpm2.Pub(*pub)
	if err != nil {
		return nil, err
	}

	tpmRwc, err := linuxtpm.Open("/dev/tpmrm0")
	if err != nil {
		return nil, fmt.Errorf("failed to open TPM to read SRK name: %%w", err)
	}
	readPrimResp, err := tpm2.ReadPublic{ObjectHandle: srkHandle}.Execute(tpmRwc)
	tpmRwc.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to read SRK public: %%w", err)
	}

	return &tpmSigner{
		Key:      key,
		Pub:      *pub,
		PubBlob:  pubBlob,
		PrivBlob: privBlob,
		SrkName:  readPrimResp.Name,
	}, nil
}