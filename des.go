// Package crypto DES对称加密，最流行的加密算法之一，
// 正逐渐被AES取代。

package crypto

import (
	"encoding/hex"

	"github.com/smart-unicom/crypto/wcipher"
)

// DesEncrypt DES加密，返回未转码的密文
func DesEncrypt(rawData []byte, opts ...DesOption) ([]byte, error) {
	o := defaultDesOptions()
	o.apply(opts...)

	return desEncryptByMode(o.mode, rawData, o.desKey)
}

// DesDecrypt DES解密，参数输入未转码的密文
func DesDecrypt(cipherData []byte, opts ...DesOption) ([]byte, error) {
	o := defaultDesOptions()
	o.apply(opts...)

	return desDecryptByMode(o.mode, cipherData, o.desKey)
}

// DesEncryptHex DES加密，返回已转码的密文
func DesEncryptHex(rawData string, opts ...DesOption) (string, error) {
	o := defaultDesOptions()
	o.apply(opts...)

	cipherData, err := desEncryptByMode(o.mode, []byte(rawData), o.desKey)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(cipherData), nil
}

// DesDecryptHex DES解密，参数输入已转码的密文字符串
func DesDecryptHex(cipherStr string, opts ...DesOption) (string, error) {
	o := defaultDesOptions()
	o.apply(opts...)

	cipherData, err := hex.DecodeString(cipherStr)
	if err != nil {
		return "", err
	}

	rawData, err := desDecryptByMode(o.mode, cipherData, o.desKey)
	if err != nil {
		return "", err
	}

	return string(rawData), nil
}

func desEncryptByMode(mode string, rawData []byte, key []byte) ([]byte, error) {
	cipherMode, err := getCipherMode(mode)
	if err != nil {
		return nil, err
	}

	cip, err := wcipher.NewDESWith(key, cipherMode)
	if err != nil {
		return nil, err
	}

	return cip.Encrypt(rawData), nil
}

func desDecryptByMode(mode string, cipherData []byte, key []byte) ([]byte, error) {
	cipherMode, err := getCipherMode(mode)
	if err != nil {
		return nil, err
	}

	cip, err := wcipher.NewDESWith(key, cipherMode)
	if err != nil {
		return nil, err
	}

	return cip.Decrypt(cipherData), nil
}
