package crypto

import (
	cr "crypto"
)

const (
	modeECB = "ECB"
	modeCBC = "CBC"
	modeCFB = "CFB"
	modeCTR = "CTR"
)

var (
	defaultAesKey = []byte("TskdM2_Flm;=") // AES密钥
	defaultDesKey = []byte("JkyV*2Q")      // DES密钥
	defaultMode   = "ECB"

	defaultRsaFormat   = "PKCS#1"
	defaultRsaHashType = cr.SHA1
)

type aesOptions struct {
	// 密钥长度必须是16、24、32之一，分别对应
	// AES-128、AES-192、AES-256
	aesKey []byte
	// 总共有四种操作模式：ECB CBC CFB CTR
	mode string
}

// AesOption 设置AES选项
type AesOption func(*aesOptions)

func (o *aesOptions) apply(opts ...AesOption) {
	for _, opt := range opts {
		opt(o)
	}
}

func defaultAesOptions() *aesOptions {
	return &aesOptions{
		aesKey: defaultAesKey,
		mode:   defaultMode,
	}
}

// WithAesKey 设置AES密钥
func WithAesKey(key []byte) AesOption {
	return func(o *aesOptions) {
		o.aesKey = key
	}
}

// WithAesModeCBC 设置模式为CBC
func WithAesModeCBC() AesOption {
	return func(o *aesOptions) {
		o.mode = modeCBC
	}
}

// WithAesModeECB 设置模式为ECB
func WithAesModeECB() AesOption {
	return func(o *aesOptions) {
		o.mode = modeECB
	}
}

// WithAesModeCFB 设置模式为CFB
func WithAesModeCFB() AesOption {
	return func(o *aesOptions) {
		o.mode = modeCFB
	}
}

// WithAesModeCTR 设置模式为CTR
func WithAesModeCTR() AesOption {
	return func(o *aesOptions) {
		o.mode = modeCTR
	}
}

type desOptions struct {
	desKey []byte // 密钥长度必须是8
	mode   string // 总共有四种操作模式：ECB CBC CFB CTR
}

// DesOption 设置DES选项
type DesOption func(*desOptions)

func (o *desOptions) apply(opts ...DesOption) {
	for _, opt := range opts {
		opt(o)
	}
}

func defaultDesOptions() *desOptions {
	return &desOptions{
		desKey: defaultDesKey,
		mode:   defaultMode,
	}
}

// WithDesKey 设置DES密钥
func WithDesKey(key []byte) DesOption {
	return func(o *desOptions) {
		o.desKey = key
	}
}

// WithDesModeCBC 设置模式为CBC
func WithDesModeCBC() DesOption {
	return func(o *desOptions) {
		o.mode = modeCBC
	}
}

// WithDesModeECB 设置模式为ECB
func WithDesModeECB() DesOption {
	return func(o *desOptions) {
		o.mode = modeECB
	}
}

// WithDesModeCFB 设置模式为CFB
func WithDesModeCFB() DesOption {
	return func(o *desOptions) {
		o.mode = modeCFB
	}
}

// WithDesModeCTR 设置模式为CTR
func WithDesModeCTR() DesOption {
	return func(o *desOptions) {
		o.mode = modeCTR
	}
}

type rsaOptions struct {
	// RSA密钥对格式
	format string
	// 用于签名和签名验证的哈希类型
	hashType cr.Hash
}

// RsaOption 设置RSA选项
type RsaOption func(*rsaOptions)

func (o *rsaOptions) apply(opts ...RsaOption) {
	for _, opt := range opts {
		opt(o)
	}
}

func defaultRsaOptions() *rsaOptions {
	return &rsaOptions{
		format:   defaultRsaFormat,
		hashType: defaultRsaHashType,
	}
}

// WithRsaFormatPKCS1 设置格式为PKCS1
func WithRsaFormatPKCS1() RsaOption {
	return func(o *rsaOptions) {
		o.format = pkcs1
	}
}

// WithRsaFormatPKCS8 设置格式为PKCS8
func WithRsaFormatPKCS8() RsaOption {
	return func(o *rsaOptions) {
		o.format = pkcs8
	}
}

// WithRsaHashTypeMd5 设置哈希类型为MD5
func WithRsaHashTypeMd5() RsaOption {
	return func(o *rsaOptions) {
		o.hashType = cr.MD5
	}
}

// WithRsaHashTypeSha1 设置哈希类型为SHA1
func WithRsaHashTypeSha1() RsaOption {
	return func(o *rsaOptions) {
		o.hashType = cr.SHA1
	}
}

// WithRsaHashTypeSha256 设置哈希类型为SHA256
func WithRsaHashTypeSha256() RsaOption {
	return func(o *rsaOptions) {
		o.hashType = cr.SHA256
	}
}

// WithRsaHashTypeSha512 设置哈希类型为SHA512
func WithRsaHashTypeSha512() RsaOption {
	return func(o *rsaOptions) {
		o.hashType = cr.SHA512
	}
}

// WithRsaHashType 设置哈希类型
func WithRsaHashType(hash cr.Hash) RsaOption {
	return func(o *rsaOptions) {
		o.hashType = hash
	}
}
