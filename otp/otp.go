package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"net/url"
	"strconv"
	"time"
)

type Algorithm string

const (
	SHA1   Algorithm = "SHA1"
	SHA256 Algorithm = "SHA256"
	SHA512 Algorithm = "SHA512"
)

type OTP struct {
	key       []byte
	algorithm Algorithm
	period    int64
}

type Option = func(o *OTP)

func WithAlgorithm(v Algorithm) Option {
	return func(o *OTP) {
		o.algorithm = v
	}
}

func WithPeriod(v int64) Option {
	return func(o *OTP) {
		if v <= 0 {
			v = 30
		}
		o.period = v
	}
}

func New(key []byte, options ...Option) *OTP {
	o := &OTP{key: key, algorithm: SHA1, period: 30}
	for _, opt := range options {
		opt(o)
	}
	return o
}

func (o *OTP) hotp(count int64) uint32 {
	var h hash.Hash
	switch o.algorithm {
	default:
		h = hmac.New(sha1.New, o.key)
	case SHA512:
		h = hmac.New(sha512.New, o.key)
	case SHA256:
		h = hmac.New(sha256.New, o.key)
	case SHA1:
		h = hmac.New(sha1.New, o.key)
	}

	_ = binary.Write(h, binary.BigEndian, count)
	value := h.Sum(nil)

	// Truncate
	offset := value[len(value)-1] & 0x0F
	value[offset] = value[offset] & 0x7F
	return binary.BigEndian.Uint32(value[offset : offset+4])
}

func (o *OTP) TOTP(time time.Time, digits int) string {
	totp := o.hotp(time.Unix() / o.period)
	return fmt.Sprintf("%0*.0f", digits, math.Mod(float64(totp), math.Pow10(digits)))
}

// https://github.com/google/google-authenticator/wiki/Key-Uri-Format#issuer
func (o *OTP) URL(issuer, user string) string {
	path := "/" + issuer
	if user != "" {
		path += ":" + user
	}
	u := &url.URL{
		Scheme: "otpauth",
		Host:   "totp",
		Path:   path,
	}
	q := make(url.Values)
	if user != "" {
		q.Add("issuer", issuer)
	}
	q.Add("secret", base32.StdEncoding.EncodeToString(o.key))
	q.Add("algorithm", string(o.algorithm))
	q.Add("period", strconv.FormatInt(o.period, 10))
	u.RawQuery = q.Encode()
	return u.String()
}
