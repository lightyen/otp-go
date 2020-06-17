package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"html/template"
	"image/color"
	"image/png"
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

func generateWithBase32(key string, interval uint64) (uint32, error) {
	e, err := base32.StdEncoding.DecodeString(key)
	if err != nil {
		return 0, err
	}
	return otp(e, uint64(time.Now().Unix())/interval), nil
}

func PNG(q *qrcode.QRCode, size int) ([]byte, error) {
	img := q.Image(size)
	encoder := png.Encoder{CompressionLevel: png.BestCompression}
	var b bytes.Buffer
	err := encoder.Encode(&b, img)
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
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

		now := time.Now()
		q, err := qrcode.New(u.String(), qrcode.Medium)
		if err != nil {
			c.String(http.StatusInternalServerError, "%s", err)
			return
		}
		q.BackgroundColor = color.RGBA{237, 242, 247, 255}
		q.ForegroundColor = color.RGBA{26, 32, 44, 255}

		data, err := PNG(q, 256)
		if err != nil {
			c.String(http.StatusInternalServerError, "%s", err)
			return
		}

		values := struct {
			URL    template.URL
			Value  string
			QRCode template.URL
			Remain int64
			Spent  time.Duration
		}{}
		values.Spent = time.Since(now)
		values.URL = template.URL(u.String())
		values.QRCode = template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(data))
		values.Remain = 30 - time.Now().Unix()%30
		if pwd, err := generateWithBase32(secret, 30); err != nil {
			c.String(http.StatusInternalServerError, "%s", err)
			return
		} else {
			values.Value = fmt.Sprintf("%06d", pwd%1e6)
		}
		c.HTML(http.StatusOK, "index.html", values)
	})

	_ = http.ListenAndServe(":8080", e)
}
