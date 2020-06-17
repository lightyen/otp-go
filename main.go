package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
)

func otp(key []byte, value uint64) uint32 {
	message := make([]byte, 8)
	binary.BigEndian.PutUint64(message, value)
	hmacSha1 := hmac.New(sha1.New, key)
	_, _ = hmacSha1.Write(message)
	hash := hmacSha1.Sum(nil)
	offset := hash[len(hash)-1] & 0x0F
	hashParts := hash[offset : offset+4]
	hashParts[0] = hashParts[0] & 0x7F
	return binary.BigEndian.Uint32(hashParts)
}

func generateWithBase32(key string, interval uint64) (uint32, error) {
	e, err := base32.StdEncoding.DecodeString(key)
	if err != nil {
		return 0, err
	}
	return otp(e, uint64(time.Now().Unix())/interval), nil
}

func validate(key, pwd string) error {
	value, err := generateWithBase32(key, 30)
	if err != nil {
		return err
	}
	if pwd != fmt.Sprintf("%06d", value%1e6) {
		return fmt.Errorf("Invalid.")
	}
	return nil
}

func main() {
	e := gin.Default()
	e.LoadHTMLGlob("templates/*")

	e.GET("/", func(c *gin.Context) {
		secret := c.Query("secret")
		if secret == "" {
			// secret == 123456789
			c.Redirect(301, "?secret=GEZDGNBVGY3TQOI%3D")
			return
		}

		u := url.URL{
			Scheme: "otpauth",
			Host:   "totp",
			Path:   "/example.com:App",
		}
		v := url.Values{
			"secret": []string{secret},
			"issuer": []string{"example.com"},
		}
		u.RawQuery = v.Encode()

		values := struct {
			URL template.URL
		}{}
		values.URL = template.URL(u.String())
		c.HTML(http.StatusOK, "index.html", values)
	})

	_ = http.ListenAndServe(":8080", e)
}
