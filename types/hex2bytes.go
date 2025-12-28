package types

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

func HexToBytes(hexStr string) ([]byte, error) {
	if strings.HasPrefix(hexStr, "0x") {
		hexStr = hexStr[2:]
	}
	return hex.DecodeString(hexStr)
}

type HexBytes []byte

func (b HexBytes) String() string {
	return hex.EncodeToString(b)
}

func (hb HexBytes) MarshalJSON() ([]byte, error) {
	s := "0x" + hex.EncodeToString(hb)
	jbz := make([]byte, len(s)+2)
	jbz[0] = '"'
	copy(jbz[1:], s)
	jbz[len(jbz)-1] = '"'
	return jbz, nil
}

// This is the point of Bytes.
func (hb *HexBytes) UnmarshalJSON(data []byte) error {
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return fmt.Errorf("invalid hex string: %s", data)
	}

	// escape double quote
	val := data[1 : len(data)-1]
	if isHex(string(val)) {
		// hex string
		str := strings.TrimPrefix(string(val), "0x")
		bz, err := hex.DecodeString(str)
		if err != nil {
			return err
		}
		*hb = bz
	} else {
		// base64
		bz, err := base64.StdEncoding.DecodeString(string(val))
		if err != nil {
			return err
		}
		*hb = bz
	}
	return nil
}

func isHex(s string) bool {
	v := s
	if len(v)%2 != 0 {
		return false
	}
	if strings.HasPrefix(v, "0x") {
		v = v[2:]
	}
	for _, b := range []byte(v) {
		if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F') {
			return false
		}
	}
	return true
}
