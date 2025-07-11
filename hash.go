package crypto

import (
	cr "crypto"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"hash"
	"strconv"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/sha3"
)

var hashKey = []byte("fVy7UjMkO9_pLqs3")

// Md5 MD5哈希算法
func Md5(rawData []byte) string {
	h := md5.New()
	h.Write(rawData)
	return hex.EncodeToString(h.Sum(nil))
}

// Sha1 SHA1哈希算法
func Sha1(rawData []byte) string {
	h := sha1.New()
	h.Write(rawData)
	return hex.EncodeToString(h.Sum(nil))
}

// Sha256 SHA256哈希算法
func Sha256(rawData []byte) string {
	h := sha256.New()
	h.Write(rawData)
	return hex.EncodeToString(h.Sum(nil))
}

// Sha512 SHA512哈希算法
func Sha512(rawData []byte) string {
	h := sha512.New()
	h.Write(rawData)
	return hex.EncodeToString(h.Sum(nil))
}

func sha1Hash(slices [][]byte) []byte {
	h := sha1.New()
	for _, slice := range slices {
		h.Write(slice)
	}
	return h.Sum(nil)
}

func md5Sha1(slices [][]byte) string {
	md5sha1 := make([]byte, md5.Size+sha1.Size)
	hmd5 := md5.New()
	for _, slice := range slices {
		hmd5.Write(slice)
	}
	copy(md5sha1, hmd5.Sum(nil))
	copy(md5sha1[md5.Size:], sha1Hash(slices))
	return hex.EncodeToString(md5sha1[:])
}

// Hash 常用哈希算法集合
func Hash(hashType cr.Hash, rawData []byte) (string, error) {
	var (
		err    error
		hasher hash.Hash
	)

	switch hashType {
	case cr.MD5:
		hasher = md5.New()
	case cr.SHA1:
		hasher = sha1.New()
	case cr.SHA224:
		hasher = sha256.New224()
	case cr.SHA256:
		hasher = sha256.New()
	case cr.SHA384:
		hasher = sha512.New384()
	case cr.SHA512:
		hasher = sha512.New()
	case cr.MD5SHA1:
		return md5Sha1([][]byte{rawData}), nil
	case cr.SHA3_224:
		hasher = sha3.New224()
	case cr.SHA3_256:
		hasher = sha3.New256()
	case cr.SHA3_384:
		hasher = sha3.New384()
	case cr.SHA3_512:
		hasher = sha3.New512()
	case cr.SHA512_224:
		hasher = sha512.New512_224()
	case cr.SHA512_256:
		hasher = sha512.New512_256()
	case cr.BLAKE2s_256:
		hasher, err = blake2s.New256(hashKey)
		if err != nil {
			return "", err
		}
	case cr.BLAKE2b_256:
		hasher, err = blake2b.New256(hashKey)
		if err != nil {
			return "", err
		}
	case cr.BLAKE2b_384:
		hasher, err = blake2b.New384(hashKey)
		if err != nil {
			return "", err
		}
	case cr.BLAKE2b_512:
		hasher, err = blake2b.New512(hashKey)
		if err != nil {
			return "", err
		}
	default:
		return "", errors.New("未知哈希值 " + strconv.Itoa(int(hashType)))
	}

	_, err = hasher.Write(rawData)

	return hex.EncodeToString(hasher.Sum(nil)), err
}
