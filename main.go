package main

import (
	"app/otp"
	"crypto/rand"
	"html/template"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

func randomBytes() []byte {
	var buf [20]byte
	_, err := io.ReadFull(rand.Reader, buf[:])
	if err != nil {
		panic(err)
	}
	return buf[:]
}

func main() {
	key := randomBytes()
	o := otp.New(key)
	e := gin.Default()
	e.LoadHTMLGlob("templates/*")
	e.POST("/", func(c *gin.Context) {
		type request struct {
			Code string `json:"code"`
		}
		req := &request{}
		if err := c.ShouldBindJSON(req); err != nil {
			c.Status(400)
			return
		}
		if req.Code != o.TOTP(time.Now(), 6) {
			c.Status(403)
			return
		}
		c.Status(200)
	})
	e.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", &struct {
			URL template.URL
		}{template.URL(o.URL("AppName", "user@gmail.com"))})
	})
	_ = http.ListenAndServe(":8080", e)
}
