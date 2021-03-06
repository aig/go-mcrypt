package rijndael

import (
	"testing"
)

type CryptTest struct {
	key []byte
	iv  []byte
	in  []byte
	out []byte
}

var encryptTests = []CryptTest{
	{
		[]byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c},
		[]byte{0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a},
		[]byte{0x4d, 0x87, 0x6d, 0xf5, 0xd4, 0xc8, 0xf0, 0x96, 0x6c, 0x6f, 0xd0, 0x2d, 0xe9, 0x21, 0x27, 0x12},
		[]byte{0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32},
	},
	{
		[]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
		[]byte{0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32},
		[]byte{0xc9, 0x8b, 0x51, 0x4e, 0x46, 0xff, 0x17, 0x55, 0x35, 0x39, 0x7e, 0xfb, 0x91, 0x56, 0x02, 0xb6},
		[]byte{0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a},
	},
}

func TestCBCDecrypter(t *testing.T) {
	for i, tt := range encryptTests {
		cipher, err := NewCBCDecrypter(tt.key, tt.iv)
		if err != nil {
			t.Errorf("NewCBCDecrypter: %v", err)
		}

		plain := make([]byte, len(tt.out))
		copy(plain, tt.out)

		cipher.CryptBlocks(plain)
        cipher.Close()

		for j, v := range plain {
			if v != tt.in[j] {
				t.Errorf("CryptBlocks %d: plain[%d] = %#x, want %#x", i, j, v, tt.in[j])
				break
			}
		}
	}
}
