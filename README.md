# Crypto 加密组件库

一个功能完整的 Go 语言加密组件库，提供常用的**单向加密**、**对称加密解密**、**非对称加密解密**功能，包括哈希、AES、DES、RSA 等算法的实现。

## 特性

- 🔐 **哈希算法**：支持 MD5、SHA1、SHA256、SHA512、SHA3、BLAKE2 等多种哈希算法
- 🔑 **密码加密**：提供带盐值的密码哈希和验证功能
- 🛡️ **对称加密**：支持 AES 和 DES 加密，包含 ECB、CBC、CFB、CTR 四种模式
- 🔒 **非对称加密**：支持 RSA 加密解密和数字签名，兼容 PKCS#1 和 PKCS#8 格式
- 📦 **易于使用**：提供简洁的 API 接口和丰富的配置选项
- ✅ **完整测试**：包含全面的单元测试和性能基准测试

## 安装

```bash
go get github.com/smart-unicom/crypto
```

## 快速开始

```go
package main

import (
    "fmt"
    "github.com/smart-unicom/crypto"
)

func main() {
    // 哈希加密
    data := []byte("hello world")
    hash := crypto.Md5(data)
    fmt.Printf("MD5: %s\n", hash)
    
    // AES 加密
    plaintext := []byte("secret message")
    ciphertext, _ := crypto.AesEncrypt(plaintext)
    decrypted, _ := crypto.AesDecrypt(ciphertext)
    fmt.Printf("解密结果: %s\n", decrypted)
}
```

## 详细使用说明

### 1. 哈希单向加密

支持多种哈希算法，可以使用独立函数或统一的 Hash 函数。

```go
import "github.com/smart-unicom/crypto"

var hashRawData = []byte("hash_abcdefghijklmnopqrstuvwxyz0123456789")

// 独立哈希函数
hashMd5 := crypto.Md5(hashRawData)
hashSha1 := crypto.Sha1(hashRawData)
hashSha256 := crypto.Sha256(hashRawData)
hashSha512 := crypto.Sha512(hashRawData)

// 统一哈希函数，根据哈希类型执行对应的哈希算法
hashMd5, _ := crypto.Hash(crypto.MD5, hashRawData)
hashSha3, _ := crypto.Hash(crypto.SHA3_224, hashRawData)
hashSha256, _ := crypto.Hash(crypto.SHA256, hashRawData)
hashBlake2s, _ := crypto.Hash(crypto.BLAKE2s_256, hashRawData)
```

**支持的哈希算法：**
- MD4, MD5
- SHA1, SHA224, SHA256, SHA384, SHA512
- SHA3_224, SHA3_256, SHA3_384, SHA3_512
- SHA512_224, SHA512_256
- BLAKE2s_256, BLAKE2b_256, BLAKE2b_384, BLAKE2b_512
- MD5SHA1

### 2. 密码哈希和验证

用户注册的密码通过哈希存储在数据库中，登录时比较密码与哈希值来判断密码是否正确，确保只有用户知道密码明文。

```go
import "github.com/smart-unicom/crypto"

pwd := "123456"

// 密码哈希（带盐值）
hashStr, err := crypto.HashAndSaltPassword(pwd)
if err != nil {
    return err
}

// 密码验证
ok := crypto.VerifyPassword(pwd, hashStr)
if !ok {
    return errors.New("密码不匹配")
}
```

### 3. AES 对称加密解密

AES（高级加密标准）是用来替代 DES 的对称加密算法，支持四种分组加密模式：ECB、CBC、CFB、CTR。

提供四个函数：`AesEncrypt`、`AesDecrypt`、`AesEncryptHex`、`AesDecryptHex`。

```go
import "github.com/smart-unicom/crypto"

var (
    aesRawData = []byte("aes_abcdefghijklmnopqrstuvwxyz0123456789")
    aesKey     = []byte("aesKey0123456789aesKey0123456789")
)

// AesEncrypt 和 AesDecrypt 参数有默认值：
// 默认模式是 ECB，可修改为 CBC、CTR、CFB
// 默认密钥长度是 16，可修改为 24、32

// 默认模式 ECB，默认密钥长度 16
cypherData, _ := crypto.AesEncrypt(aesRawData) // 加密
raw, _ := crypto.AesDecrypt(cypherData) // 解密，返回原文

// 模式 ECB，密钥长度 32
cypherData, _ := crypto.AesEncrypt(aesRawData, crypto.WithAesKey(aesKey))  // 加密
raw, _ := crypto.AesDecrypt(cypherData, crypto.WithAesKey(aesKey)) // 解密

// 模式 CTR，默认密钥长度 16
cypherData, _ := crypto.AesEncrypt(aesRawData, crypto.WithAesModeCTR())  // 加密
raw, _ := crypto.AesDecrypt(cypherData, crypto.WithAesModeCTR())  // 解密

// 模式 CBC，密钥长度 32
cypherData, _ := crypto.AesEncrypt(aesRawData, crypto.WithAesModeCBC(), crypto.WithAesKey(aesKey)) // 加密
raw, _ := crypto.AesDecrypt(cypherData, crypto.WithAesModeCBC(), crypto.WithAesKey(aesKey))   // 解密

// AesEncryptHex 和 AesDecryptHex 函数，这两个函数的密文经过 hex 转码
// 使用方法与 AesEncrypt 和 AesDecrypt 完全相同
```

**配置选项：**
- `crypto.WithAesKey(key)` - 设置密钥（16/24/32 字节）
- `crypto.WithAesModeECB()` - ECB 模式
- `crypto.WithAesModeCBC()` - CBC 模式
- `crypto.WithAesModeCFB()` - CFB 模式
- `crypto.WithAesModeCTR()` - CTR 模式

### 4. DES 对称加密解密

DES（数据加密标准）是目前最流行的加密算法之一，支持四种分组加密模式：ECB、CBC、CFB、CTR。

提供四个函数：`DesEncrypt`、`DesDecrypt`、`DesEncryptHex`、`DesDecryptHex`。

```go
import "github.com/smart-unicom/crypto"

var (
    desRawData = []byte("des_abcdefghijklmnopqrstuvwxyz0123456789")
    desKey     = []byte("desKey0123456789desKey0123456789")
)

// DesEncrypt 和 DesDecrypt 参数有默认值：
// 默认模式是 ECB，可修改为 CBC、CTR、CFB
// 默认密钥长度是 16，可修改为 24、32

// 默认模式 ECB，默认密钥长度 16
cypherData, _ := crypto.DesEncrypt(desRawData) // 加密
raw, _ := crypto.DesDecrypt(cypherData) // 解密

// 模式 ECB，密钥长度 32
cypherData, _ := crypto.DesEncrypt(desRawData, crypto.WithDesKey(desKey)) // 加密
raw, _ := crypto.DesDecrypt(cypherData, crypto.WithDesKey(desKey)) // 解密

// 模式 CTR，默认密钥长度 16
cypherData, _ := crypto.DesEncrypt(desRawData, crypto.WithDesModeCTR()) // 加密
raw, _ := crypto.DesDecrypt(cypherData, crypto.WithDesModeCTR()) // 解密

// 模式 CBC，密钥长度 32
cypherData, _ := crypto.DesEncrypt(desRawData, crypto.WithDesModeCBC(), crypto.WithDesKey(desKey)) // 加密
raw, _ := crypto.DesDecrypt(cypherData, crypto.WithDesModeCBC(), crypto.WithDesKey(desKey))        // 解密

// DesEncryptHex 和 DesDecryptHex 函数，这两个函数的密文经过 hex 转码
// 使用方法与 DesEncrypt 和 DesDecrypt 完全相同
```

**配置选项：**
- `crypto.WithDesKey(key)` - 设置密钥（16/24/32 字节）
- `crypto.WithDesModeECB()` - ECB 模式
- `crypto.WithDesModeCBC()` - CBC 模式
- `crypto.WithDesModeCFB()` - CFB 模式
- `crypto.WithDesModeCTR()` - CTR 模式

### 5. RSA 非对称加密解密

#### RSA 加密解密

公钥用于加密，私钥用于解密。例如，别人用公钥加密信息发送给你，你用私钥解密信息内容。

提供四个函数：`RsaEncrypt`、`RsaDecrypt`、`RsaEncryptHex`、`RsaDecryptHex`。

```go
import "github.com/smart-unicom/crypto"

var rsaRawData = []byte("rsa_abcdefghijklmnopqrstuvwxyz0123456789")

// PKCS#1 格式密钥
var publicKey = []byte(`
-----BEGIN PUBLIC KEY-----
xxxxxx
-----END PUBLIC KEY-----
`)

var privateKey = []byte(`
-----BEGIN RSA PRIVATE KEY-----
xxxxxx
-----END RSA PRIVATE KEY-----
`)

// RsaEncrypt 和 RsaDecrypt 参数有默认值：
// 默认密钥对格式：PKCS#1，可修改为 PKCS#8

// 默认密钥对格式 PKCS#1
cypherData, _ := crypto.RsaEncrypt(publicKey, rsaRawData) // 加密
raw, _ := crypto.RsaDecrypt(privateKey, cypherData) // 解密

// 密钥对格式 PKCS#8
cypherData, _ := crypto.RsaEncrypt(publicKey, rsaRawData, crypto.WithRsaFormatPKCS8()) // 加密
raw, _ := crypto.RsaDecrypt(privateKey, cypherData, crypto.WithRsaFormatPKCS8()) // 解密

// RsaEncryptHex 和 RsaDecryptHex 函数，这两个函数的密文经过 hex 转码
// 使用方法与 RsaEncrypt 和 RsaDecrypt 完全相同
```

#### RSA 数字签名和验签

私钥用于签名，公钥用于验证签名。例如，你用私钥对身份进行签名，别人通过公钥验证你的身份是否可信。

提供四个函数：`RsaSign`、`RsaVerify`、`RsaSignBase64`、`RsaVerifyBase64`。

```go
import "github.com/smart-unicom/crypto"

var rsaRawData = []byte("rsa_abcdefghijklmnopqrstuvwxyz0123456789")

// RsaSign 和 RsaVerify 参数有默认值：
// 默认密钥对格式：PKCS#1，可修改为 PKCS#8
// 默认哈希算法：sha1，可修改为 sha256、sha512

// 默认密钥对格式 PKCS#1，默认哈希 sha1
signData, _ := crypto.RsaSign(privateKey, rsaRawData) // 签名
err := crypto.RsaVerify(publicKey, rsaRawData, signData) // 验签

// 默认密钥对格式 PKCS#1，哈希 sha256
signData, _ := crypto.RsaSign(privateKey, rsaRawData, crypto.WithRsaHashTypeSha256()) // 签名
err := crypto.RsaVerify(publicKey, rsaRawData, signData, crypto.WithRsaHashTypeSha256()) // 验签

// 密钥对格式 PKCS#8，默认哈希 sha1
signData, _ := crypto.RsaSign(privateKey, rsaRawData, crypto.WithRsaFormatPKCS8()) // 签名
err := crypto.RsaVerify(publicKey, rsaRawData, signData, crypto.WithRsaFormatPKCS8()) // 验签

// 密钥对格式 PKCS#8，哈希 sha512
signData, _ := crypto.RsaSign(privateKey, rsaRawData, crypto.WithRsaFormatPKCS8(), crypto.WithRsaHashTypeSha512()) // 签名
err := crypto.RsaVerify(publicKey, rsaRawData, signData, crypto.WithRsaFormatPKCS8(), crypto.WithRsaHashTypeSha512()) // 验签

// RsaSignBase64 和 RsaVerifyBase64 的密文经过 base64 转码
// 使用方法与 RsaSign 和 RsaVerify 完全相同
```

**RSA 配置选项：**
- `crypto.WithRsaFormatPKCS1()` - PKCS#1 格式（默认）
- `crypto.WithRsaFormatPKCS8()` - PKCS#8 格式
- `crypto.WithRsaHashTypeSha1()` - SHA1 哈希（默认）
- `crypto.WithRsaHashTypeSha256()` - SHA256 哈希
- `crypto.WithRsaHashTypeSha512()` - SHA512 哈希

## API 文档

### 哈希函数

```go
// 独立哈希函数
func Md5(rawData []byte) string
func Sha1(rawData []byte) string
func Sha256(rawData []byte) string
func Sha512(rawData []byte) string

// 统一哈希函数
func Hash(hashType crypto.Hash, rawData []byte) (string, error)
```

### 密码函数

```go
// 密码哈希和验证
func HashAndSaltPassword(password string) (string, error)
func VerifyPassword(password, hashedPassword string) bool
```

### AES 函数

```go
// AES 加密解密
func AesEncrypt(rawData []byte, opts ...AesOption) ([]byte, error)
func AesDecrypt(cypherData []byte, opts ...AesOption) ([]byte, error)
func AesEncryptHex(rawData []byte, opts ...AesOption) (string, error)
func AesDecryptHex(cypherHex string, opts ...AesOption) ([]byte, error)
```

### DES 函数

```go
// DES 加密解密
func DesEncrypt(rawData []byte, opts ...DesOption) ([]byte, error)
func DesDecrypt(cypherData []byte, opts ...DesOption) ([]byte, error)
func DesEncryptHex(rawData []byte, opts ...DesOption) (string, error)
func DesDecryptHex(cypherHex string, opts ...DesOption) ([]byte, error)
```

### RSA 函数

```go
// RSA 加密解密
func RsaEncrypt(publicKey, rawData []byte, opts ...RsaOption) ([]byte, error)
func RsaDecrypt(privateKey, cypherData []byte, opts ...RsaOption) ([]byte, error)
func RsaEncryptHex(publicKey, rawData []byte, opts ...RsaOption) (string, error)
func RsaDecryptHex(privateKey []byte, cypherHex string, opts ...RsaOption) ([]byte, error)

// RSA 签名验签
func RsaSign(privateKey, rawData []byte, opts ...RsaOption) ([]byte, error)
func RsaVerify(publicKey, rawData, signData []byte, opts ...RsaOption) error
func RsaSignBase64(privateKey, rawData []byte, opts ...RsaOption) (string, error)
func RsaVerifyBase64(publicKey, rawData []byte, signBase64 string, opts ...RsaOption) error
```

## 项目结构

```
crypto/
├── README.md           # 项目文档
├── go.mod             # Go 模块文件
├── aes.go             # AES 加密实现
├── aes_test.go        # AES 测试文件
├── des.go             # DES 加密实现
├── des_test.go        # DES 测试文件
├── hash.go            # 哈希算法实现
├── hash_test.go       # 哈希测试文件
├── password.go        # 密码加密实现
├── password_test.go   # 密码测试文件
├── rsa.go             # RSA 加密实现
├── rsa_test.go        # RSA 测试文件
├── option.go          # 配置选项
├── wcipher/           # 内部加密工具包
│   ├── cipher.go      # 加密器接口
│   ├── cipher_test.go # 加密器测试
│   ├── ecb.go         # ECB 模式实现
│   ├── factor.go      # 工厂模式
│   ├── mode.go        # 加密模式
│   └── padding.go     # 填充算法
└── 代码规范.md        # 代码规范文档
```

## 测试

运行所有测试：

```bash
go test ./...
```

运行性能基准测试：

```bash
go test -bench=.
```

查看测试覆盖率：

```bash
go test -cover ./...
```

## 依赖

- Go 1.23.0+
- golang.org/x/crypto v0.40.0
- github.com/stretchr/testify v1.10.0（测试依赖）

## 许可证

本项目采用 MIT 许可证。详情请参阅 LICENSE 文件。

## 贡献

欢迎提交 Issue 和 Pull Request 来改进这个项目。

## 更新日志

### v1.0.0
- 初始版本发布
- 支持哈希、AES、DES、RSA 加密算法
- 提供完整的测试覆盖
- 支持多种配置选项

---

如有问题或建议，请提交 [Issue](https://github.com/smart-unicom/crypto/issues)。
