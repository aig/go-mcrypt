package rijndael

/*
#cgo LDFLAGS: -lmcrypt -L/usr/local/lib
#cgo CFLAGS: -I/usr/local/include
#include <stdlib.h>
#include <string.h>
#include <mcrypt.h>
*/
import "C"

import (
	"unsafe"
)

type cbcDecrypter struct {
  td C.MCRYPT
}

func getAlgorithm(keySize int) string {
	switch keySize {
	case 16:
		return "rijndael-128"
	case 24:
		return "rijndael-192"
	case 32:
		return "rijndael-256"
	default:
		panic("rijndael: unexpected key size")
	}
}

func NewCBCDecrypter(key, iv []byte) (*cbcDecrypter, error) {
	algorithm := C.CString(getAlgorithm(len(key)))
	defer C.free(unsafe.Pointer(algorithm))

	mode := C.CString("cbc")
	defer C.free(unsafe.Pointer(mode))

	td := C.mcrypt_module_open(algorithm, nil, mode, nil)

	if uintptr(unsafe.Pointer(td)) == C.MCRYPT_FAILED {
		panic("rijndael: mcrypt module open failed")
	}

	keySize := C.mcrypt_enc_get_key_size(td)
	//	ivSize := C.mcrypt_enc_get_iv_size(td)

	rv := C.mcrypt_generic_init(td, unsafe.Pointer(&key[0]), keySize, unsafe.Pointer(&iv[0]))

	if rv < 0 {
		panic("rijndael: mcrypt generic init failed")
	}

	c := cbcDecrypter{td}

	return &c, nil
}

func (c *cbcDecrypter) CryptBlocks(blocks []byte) {
  C.mdecrypt_generic(c.td, unsafe.Pointer(&blocks[0]), C.int(len(blocks)))
}

func (c *cbcDecrypter) Close() {
  C.mcrypt_generic_deinit(c.td)
  C.mcrypt_module_close(c.td)
}
