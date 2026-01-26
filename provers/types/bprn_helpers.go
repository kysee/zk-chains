package types

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/msp"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

func ParseDERSignature(sigDER []byte) (*big.Int, *big.Int, error) {
	var (
		r, s  = new(big.Int), new(big.Int)
		inner cryptobyte.String
	)
	input := cryptobyte.String(sigDER)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(r) ||
		!inner.ReadASN1Integer(s) ||
		!inner.Empty() {
		return nil, nil, errors.New("invalid DER signature")
	}
	return r, s, nil
}

func PubkeyFromCert(idBytes []byte) (*ecdsa.PublicKey, error) {
	// Creator is a SerializedIdentity protobuf, not raw PEM
	serializedIdentity := &msp.SerializedIdentity{}
	err := proto.Unmarshal(idBytes, serializedIdentity)
	if err != nil {
		return nil, err
	}

	// IdBytes contains the actual PEM certificate
	block, _ := pem.Decode(serializedIdentity.IdBytes)
	if block == nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert.PublicKey.(*ecdsa.PublicKey), nil
}
