package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/skip2/go-qrcode"
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

func generate(key string, interval uint64) (uint32, error) {
	e, err := base32.StdEncoding.DecodeString(key)
	if err != nil {
		return 0, err
	}
	return otp(e, uint64(time.Now().Unix())/interval), nil
}

func main() {
	secret := base32.StdEncoding.EncodeToString([]byte("sdf@#wBfwa"))
	u := url.URL{
		Scheme: "otpauth",
		Host:   "totp",
		Path:   "/example.com:user",
	}
	v := url.Values{
		"secret": []string{secret},
		"issuer": []string{"example.com"},
	}
	u.RawQuery = v.Encode()
	png, err := qrcode.Encode(u.String(), qrcode.Medium, 256)
	if err != nil {
		fmt.Println(err)
		return
	}

	e := gin.Default()
	e.LoadHTMLGlob("templates/*")
	dataURL := "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
	e.GET("/", func(c *gin.Context) {

		values := struct {
			Value  string
			QRCode template.URL
		}{}

		values.QRCode = template.URL(dataURL)

		if pwd, err := generate(secret, 30); err == nil {
			values.Value = fmt.Sprintf("%06d", pwd%1e6)
		}

		c.HTML(http.StatusOK, "app.tmpl", values)
	})

	_ = e.Run(":8080")
}
