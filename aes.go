// Package crypto AES对称加密，高级加密标准，具有最高级别的安全性，
// 已逐渐取代DES成为新一代对称加密标准。

package crypto

import (
	"encoding/hex"
	"errors"

	"github.com/smart-unicom/crypto/wcipher"
)

// AesEncrypt AES加密，返回未转码的密文
func AesEncrypt(rawData []byte, opts ...AesOption) ([]byte, error) {
	o := defaultAesOptions()
	o.apply(opts...)

	return aesEncryptByMode(o.mode, rawData, o.aesKey)
}

// AesDecrypt AES解密，参数输入未转码的密文
func AesDecrypt(cipherData []byte, opts ...AesOption) ([]byte, error) {
	o := defaultAesOptions()
	o.apply(opts...)

	return aesDecryptByMode(o.mode, cipherData, o.aesKey)
}

// AesEncryptHex AES加密，返回已转码的密文
func AesEncryptHex(rawData string, opts ...AesOption) (string, error) {
	o := defaultAesOptions()
	o.apply(opts...)

	cipherData, err := aesEncryptByMode(o.mode, []byte(rawData), o.aesKey)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(cipherData), nil
}

// AesDecryptHex AES解密，参数输入已转码的密文字符串
func AesDecryptHex(cipherStr string, opts ...AesOption) (string, error) {
	o := defaultAesOptions()
	o.apply(opts...)

	cipherData, err := hex.DecodeString(cipherStr)
	if err != nil {
		return "", err
	}

	rawData, err := aesDecryptByMode(o.mode, cipherData, o.aesKey)
	if err != nil {
		return "", err
	}

	return string(rawData), nil
}

func getCipherMode(mode string) (wcipher.CipherMode, error) {
	var cipherMode wcipher.CipherMode
	switch mode {
	case modeECB:
		cipherMode = wcipher.NewECBMode()
	case modeCBC:
		cipherMode = wcipher.NewCBCMode()
	case modeCFB:
		cipherMode = wcipher.NewCFBMode()
	case modeCTR:
		cipherMode = wcipher.NewCTRMode()
	default:
		return nil, errors.New("未知模式 = " + mode)
	}

	return cipherMode, nil
}

func aesEncryptByMode(mode string, rawData []byte, key []byte) ([]byte, error) {
	cipherMode, err := getCipherMode(mode)
	if err != nil {
		return nil, err
	}

	cip, err := wcipher.NewAESWith(key, cipherMode)
	if err != nil {
		return nil, err
	}

	return cip.Encrypt(rawData), nil
}

func aesDecryptByMode(mode string, cipherData []byte, key []byte) ([]byte, error) {
	cipherMode, err := getCipherMode(mode)
	if err != nil {
		return nil, err
	}

	cip, err := wcipher.NewAESWith(key, cipherMode)
	if err != nil {
		return nil, err
	}

	return cip.Decrypt(cipherData), nil
}
