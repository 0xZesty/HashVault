package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
)

func main() {

	r := gin.Default()

	r.GET("/hash", func(c *gin.Context) {

		password := c.Query("password")

		if password == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Password query parameter is required"})
			return
		}

		md5Hash := md5.Sum([]byte(password))
		md5HashString := hex.EncodeToString(md5Hash[:])

		sha1Hash := sha1.Sum([]byte(password))
		sha1String := hex.EncodeToString(sha1Hash[:])

		sha256hash := sha256.Sum256([]byte(password))
		sha256String := hex.EncodeToString(sha256hash[:])

		sha512Hash := sha512.Sum512([]byte(password))
		sha512String := hex.EncodeToString(sha512Hash[:])

		argonHash := argon2.IDKey([]byte(password), []byte("salt"), 3, 128*1024, 4, 32)
		argonHashString := hex.EncodeToString(argonHash)

		pbkdf2Hash := pbkdf2.Key([]byte(password), []byte("salt"), 100000, 32, sha256.New)
		pbkdf2HashString := hex.EncodeToString(pbkdf2Hash)

		bcryptHash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

		bcryptHashString := string(bcryptHash)

		c.String(http.StatusOK, "a senha é '%s' e as hashs são \nmd5: '%s' \nsha1: '%s' \nsha256: '%s' \nsha512: '%s' \nargon2: '%s' com salt 'salt' \npbkdf2: '%s' com salt 'salt' \nbcrypt: '%s'", password, md5HashString, sha1String, sha256String, sha512String, argonHashString, pbkdf2HashString, bcryptHashString)

	})

	r.Run(":8080")
}
