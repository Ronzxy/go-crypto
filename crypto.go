package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha256"
	"errors"
	"fmt"
	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/cast5"

	"github.com/skygangsta/chacha20"
)

type cipherInfo struct {
	keySize int
	ivSize  int
	stream  func(key, iv []byte, decrypt bool) (cipher.Stream, error)
}

func newCFBStream(block cipher.Block, iv []byte, decrypt bool) (cipher.Stream, error) {
	if !decrypt {
		return cipher.NewCFBEncrypter(block, iv), nil
	} else {
		return cipher.NewCFBDecrypter(block, iv), nil
	}
}

func newAESGCMStream(key, nonce []byte, decrypt bool) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return NewGCMStreamer(block, nonce, decrypt)
}

func newAESCFBStream(key, iv []byte, decrypt bool) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return newCFBStream(block, iv, decrypt)
}

func newAESCTRStream(key, iv []byte, decrypt bool) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(block, iv), nil
}

func newDESCFBStream(key, iv []byte, decrypt bool) (cipher.Stream, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return newCFBStream(block, iv, decrypt)
}

func newBlowFishStream(key, iv []byte, decrypt bool) (cipher.Stream, error) {
	block, err := blowfish.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return newCFBStream(block, iv, decrypt)
}

func newCast5Stream(key, iv []byte, decrypt bool) (cipher.Stream, error) {
	block, err := cast5.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return newCFBStream(block, iv, decrypt)
}

func newRC4MD5Stream(key, iv []byte, decrypt bool) (cipher.Stream, error) {
	h := md5.New()
	h.Write(key)
	h.Write(iv)
	rc4key := h.Sum(nil)

	return rc4.NewCipher(rc4key)
}

func newChaCha20Stream(key, iv []byte, decrypt bool) (cipher.Stream, error) {
	return chacha20.NewCipher(key, iv)
}

var cipherMethod = map[string]*cipherInfo{
	"aes-128-gcm":   {16, 32, newAESGCMStream},
	"aes-192-gcm":   {24, 32, newAESGCMStream},
	"aes-256-gcm":   {32, 32, newAESGCMStream},
	"aes-128-cfb":   {16, 16, newAESCFBStream},
	"aes-192-cfb":   {24, 16, newAESCFBStream},
	"aes-256-cfb":   {32, 16, newAESCFBStream},
	"aes-128-ctr":   {16, 16, newAESCTRStream},
	"aes-192-ctr":   {24, 16, newAESCTRStream},
	"aes-256-ctr":   {32, 16, newAESCTRStream},
	"des-cfb":       {8, 8, newDESCFBStream},
	"bf-cfb":        {16, 8, newBlowFishStream},
	"cast5-cfb":     {16, 8, newCast5Stream},
	"rc4-md5":       {16, 16, newRC4MD5Stream},
	"rc4-md5-6":     {16, 6, newRC4MD5Stream},
	"chacha20":      {32, 8, newChaCha20Stream},
	"chacha20-ietf": {32, 12, newChaCha20Stream},
}

type Cipher struct {
	WriteStream cipher.Stream
	ReadStream  cipher.Stream
	key         []byte
	info        *cipherInfo
}

func NewCipher(method string, key []byte) (c *Cipher, err error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("password can not be empty")
	}
	mi, ok := cipherMethod[method]
	if !ok {
		return nil, errors.New("Unsupported encryption method: " + method)
	}
	//key := evpBytesToKey(password, mi.keyLen)
	c = &Cipher{key: key, info: mi}
	if err != nil {
		return nil, err
	}
	//hash(key) -> read IV
	riv := sha256.New().Sum(c.key)[:c.info.ivSize]
	c.ReadStream, err = c.info.stream(c.key, riv, true)
	if err != nil {
		return nil, err
	} //hash(read IV) -> write IV
	wiv := sha256.New().Sum(riv)[:c.info.ivSize]
	c.WriteStream, err = c.info.stream(c.key, wiv, false)
	if err != nil {
		return nil, err
	}

	return c, nil
}
