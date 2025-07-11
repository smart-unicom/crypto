// Package crypto RSA非对称加密解密
// 1. 公钥加密，私钥解密获得原文
// 2. 私钥签名，公钥验证签名

package crypto

import (
	cr "crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
)

const (
	pkcs1 = "PKCS#1"
	pkcs8 = "PKCS#8"
)

// RsaEncrypt RSA加密，返回未转码的密文
func RsaEncrypt(publicKey []byte, rawData []byte, opts ...RsaOption) ([]byte, error) {
	o := defaultRsaOptions()
	o.apply(opts...)

	return rsaEncryptWithPublicKey(publicKey, rawData)
}

// RsaDecrypt RSA解密，参数输入未转码的密文
func RsaDecrypt(privateKey []byte, cipherData []byte, opts ...RsaOption) ([]byte, error) {
	o := defaultRsaOptions()
	o.apply(opts...)

	return rsaDecryptWithPrivateKey(privateKey, cipherData, o.format)
}

// RsaEncryptHex RSA加密，返回十六进制字符串
func RsaEncryptHex(publicKey []byte, rawData []byte, opts ...RsaOption) (string, error) {
	o := defaultRsaOptions()
	o.apply(opts...)

	cipherData, err := rsaEncryptWithPublicKey(publicKey, rawData)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(cipherData), nil
}

// RsaDecryptHex RSA解密，返回原文
func RsaDecryptHex(privateKey []byte, cipherHex string, opts ...RsaOption) (string, error) {
	o := defaultRsaOptions()
	o.apply(opts...)

	cipherData, err := hex.DecodeString(cipherHex)
	if err != nil {
		return "", err
	}

	rawData, err := rsaDecryptWithPrivateKey(privateKey, cipherData, o.format)
	if err != nil {
		return "", err
	}

	return string(rawData), nil
}

// RsaSign RSA签名，返回未转码的签名
func RsaSign(privateKey []byte, rawData []byte, opts ...RsaOption) ([]byte, error) {
	o := defaultRsaOptions()
	o.apply(opts...)

	return rsaSignWithPrivateKey(privateKey, o.hashType, rawData, o.format)
}

// RsaVerify RSA签名验证
func RsaVerify(publicKey []byte, rawData []byte, signData []byte, opts ...RsaOption) error {
	o := defaultRsaOptions()
	o.apply(opts...)

	return rsaVerifyWithPublicKey(publicKey, o.hashType, rawData, signData)
}

// RsaSignBase64 RSA签名，返回Base64字符串
func RsaSignBase64(privateKey []byte, rawData []byte, opts ...RsaOption) (string, error) {
	o := defaultRsaOptions()
	o.apply(opts...)

	cipherData, err := rsaSignWithPrivateKey(privateKey, o.hashType, rawData, o.format)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(cipherData), nil
}

// RsaVerifyBase64 RSA签名验证
func RsaVerifyBase64(publicKey []byte, rawData []byte, signBase64 string, opts ...RsaOption) error {
	o := defaultRsaOptions()
	o.apply(opts...)

	signData, err := base64.StdEncoding.DecodeString(signBase64)
	if err != nil {
		return err
	}

	return rsaVerifyWithPublicKey(publicKey, o.hashType, rawData, signData)
}

// 使用公钥加密
func rsaEncryptWithPublicKey(publicKey []byte, rawData []byte) ([]byte, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("公钥不是PEM格式")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	prk, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("这不是一个公钥")
	}

	return rsa.EncryptPKCS1v15(rand.Reader, prk, rawData)
}

// 使用私钥解密
func rsaDecryptWithPrivateKey(privateKey []byte, cipherData []byte, format string) ([]byte, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("私钥不是PEM格式")
	}

	prk, err := getPrivateKey(block.Bytes, format)
	if err != nil {
		return nil, err
	}

	return rsa.DecryptPKCS1v15(rand.Reader, prk, cipherData)
}

// 使用私钥签名
func rsaSignWithPrivateKey(privateKey []byte, hash cr.Hash, rawData []byte, format string) ([]byte, error) {
	if !hash.Available() {
		return nil, errors.New("不支持的哈希类型")
	}

	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("私钥不是PEM格式")
	}

	prk, err := getPrivateKey(block.Bytes, format)
	if err != nil {
		return nil, err
	}

	h := hash.New()
	_, err = h.Write(rawData)
	if err != nil {
		return nil, err
	}
	hashed := h.Sum(nil)

	return rsa.SignPKCS1v15(rand.Reader, prk, hash, hashed)
}

// 使用公钥验证
func rsaVerifyWithPublicKey(publicKey []byte, hash cr.Hash, rawData []byte, signData []byte) (err error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return errors.New("公钥不是PEM格式")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	prk, ok := pub.(*rsa.PublicKey)
	if !ok {
		return errors.New("这不是一个公钥")
	}

	h := hash.New()
	_, err = h.Write(rawData)
	if err != nil {
		return err
	}
	hashed := h.Sum(nil)

	return rsa.VerifyPKCS1v15(prk, hash, hashed, signData)
}

func getPrivateKey(der []byte, format string) (*rsa.PrivateKey, error) {
	var prk *rsa.PrivateKey
	switch format {
	case pkcs1:
		var err error
		prk, err = x509.ParsePKCS1PrivateKey(der)
		if err != nil {
			return nil, err
		}

	case pkcs8:
		priv, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return nil, err
		}
		var ok bool
		prk, ok = priv.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("这不是一个私钥")
		}

	default:
		return nil, errors.New("未知格式 = " + format)
	}

	return prk, nil
}
