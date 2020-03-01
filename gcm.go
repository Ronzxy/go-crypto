package crypto

import (
	"crypto/cipher"
	"github.com/skygangsta/go-logger"
)

type gcm struct {
	block   cipher.Block
	aead    cipher.AEAD
	nonce   []byte
	out     []byte
	decrypt bool
}

func (x *gcm) XORKeyStream(dst, src []byte) {
	if x.decrypt {
		// decrypt
		if cap(dst) < len(src)-16 {
			panic("crypto/cipher: output not enough for input")
		}
		var err error
		x.out, err = x.aead.Open(nil, x.nonce, src, nil)
		if err != nil {
			logger.Info(err.Error())
			return
		}

	} else {
		if cap(dst) < len(src)+16 {
			panic("crypto/cipher: output not enough for input")
		}

		x.out = x.aead.Seal(nil, x.nonce, src, nil)
	}
	copy(dst, x.out)
}

func (x *gcm) BlockSize() int {
	return x.block.BlockSize()
}

func NewGCMStreamer(block cipher.Block, nonce []byte, decrypt bool) (cipher.Stream, error) {
	aead, err := cipher.NewGCMWithNonceSize(block, len(nonce))
	if err != nil {
		return nil, err
	}

	x := &gcm{
		block:   block,
		aead:    aead,
		nonce:   make([]byte, aead.NonceSize()),
		decrypt: decrypt,
	}

	x.nonce = nonce

	return x, nil
}
