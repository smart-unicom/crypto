package crypto

import (
	"crypto"
	"testing"
)

var hashRawData = []byte("hash_abcdefghijklmnopqrstuvwxyz0123456789")

// TestMd5_WithValidData_ReturnsExpectedHash 测试MD5哈希算法的正常功能
func TestMd5(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{
			name: "正常数据",
			data: hashRawData,
			want: "98c0e2e94366eed32398f972e9742f4e",
		},
		{
			name: "空数据",
			data: []byte{},
			want: "d41d8cd98f00b204e9800998ecf8427e",
		},
		{
			name: "单字节数据",
			data: []byte("a"),
			want: "0cc175b9c0f1b6a831c399e269772661",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val := Md5(tt.data)
			if val != tt.want {
				t.Fatalf("Md5() = %v, want %v", val, tt.want)
			}
			t.Logf("MD5(%s) = %s", string(tt.data), val)
		})
	}
}

// TestSha1_WithValidData_ReturnsExpectedHash 测试SHA1哈希算法的正常功能
func TestSha1(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{
			name: "正常数据",
			data: hashRawData,
			want: "fec5700e21f47cb04127424cc09c99322925c15d",
		},
		{
			name: "空数据",
			data: []byte{},
			want: "da39a3ee5e6b4b0d3255bfef95601890afd80709",
		},
		{
			name: "单字节数据",
			data: []byte("a"),
			want: "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val := Sha1(tt.data)
			if val != tt.want {
				t.Fatalf("Sha1() = %v, want %v", val, tt.want)
			}
			t.Logf("SHA1(%s) = %s", string(tt.data), val)
		})
	}
}

// TestSha256_WithValidData_ReturnsExpectedHash 测试SHA256哈希算法的正常功能
func TestSha256(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{
			name: "正常数据",
			data: hashRawData,
			want: "229c782bcccf23fb5e2a3f382b388df3d8edaa5502ace49ab6c80976023ad637",
		},
		{
			name: "空数据",
			data: []byte{},
			want: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name: "单字节数据",
			data: []byte("a"),
			want: "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val := Sha256(tt.data)
			if val != tt.want {
				t.Fatalf("Sha256() = %v, want %v", val, tt.want)
			}
			t.Logf("SHA256(%s) = %s", string(tt.data), val)
		})
	}
}

// TestSha512_WithValidData_ReturnsExpectedHash 测试SHA512哈希算法的正常功能
func TestSha512(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{
			name: "正常数据",
			data: hashRawData,
			want: "c1871959522cac1004ee87aaf0111d1b4569e07ff30673929e3691b119bc635960cbe63ab0ffba5acb6976a6110bb45f7cd56916662d595eac754c5f191cedfe",
		},
		{
			name: "空数据",
			data: []byte{},
			want: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
		},
		{
			name: "单字节数据",
			data: []byte("a"),
			want: "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val := Sha512(tt.data)
			if val != tt.want {
				t.Fatalf("Sha512() = %v, want %v", val, tt.want)
			}
			t.Logf("SHA512(%s) = %s", string(tt.data), val)
		})
	}
}

func BenchmarkMd5(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Md5(hashRawData)
	}
}

func BenchmarkSha1(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Sha1(hashRawData)
	}
}

func BenchmarkSha256(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Sha256(hashRawData)
	}
}

func BenchmarkSha512(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Sha512(hashRawData)
	}
}

// TestHash_WithVariousHashTypes_ReturnsCorrectResults 测试Hash函数支持的各种哈希算法
func TestHash(t *testing.T) {
	type args struct {
		hashType crypto.Hash
		rawData  []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		desc    string // 测试用例描述
	}{
		{
			name: "MD5_正常数据",
			args: args{
				hashType: crypto.MD5,
				rawData:  hashRawData,
			},
			wantErr: false,
			desc:    "测试MD5哈希算法处理正常数据",
		},
		{
			name: "SHA1_正常数据",
			args: args{
				hashType: crypto.SHA1,
				rawData:  hashRawData,
			},
			wantErr: false,
			desc:    "测试SHA1哈希算法处理正常数据",
		},
		{
			name: "SHA224_正常数据",
			args: args{
				hashType: crypto.SHA224,
				rawData:  hashRawData,
			},
			wantErr: false,
			desc:    "测试SHA224哈希算法处理正常数据",
		},
		{
			name: "SHA256_正常数据",
			args: args{
				hashType: crypto.SHA256,
				rawData:  hashRawData,
			},
			wantErr: false,
			desc:    "测试SHA256哈希算法处理正常数据",
		},
		{
			name: "SHA384_正常数据",
			args: args{
				hashType: crypto.SHA384,
				rawData:  hashRawData,
			},
			wantErr: false,
			desc:    "测试SHA384哈希算法处理正常数据",
		},
		{
			name: "SHA512_正常数据",
			args: args{
				hashType: crypto.SHA512,
				rawData:  hashRawData,
			},
			wantErr: false,
			desc:    "测试SHA512哈希算法处理正常数据",
		},
		{
			name: "MD5SHA1_正常数据",
			args: args{
				hashType: crypto.MD5SHA1,
				rawData:  hashRawData,
			},
			wantErr: false,
			desc:    "测试MD5SHA1哈希算法处理正常数据",
		},
		{
			name: "SHA3_224_正常数据",
			args: args{
				hashType: crypto.SHA3_224,
				rawData:  hashRawData,
			},
			wantErr: false,
			desc:    "测试SHA3_224哈希算法处理正常数据",
		},
		{
			name: "SHA3_256_正常数据",
			args: args{
				hashType: crypto.SHA3_256,
				rawData:  hashRawData,
			},
			wantErr: false,
			desc:    "测试SHA3_256哈希算法处理正常数据",
		},
		{
			name: "SHA3_384_正常数据",
			args: args{
				hashType: crypto.SHA3_384,
				rawData:  hashRawData,
			},
			wantErr: false,
			desc:    "测试SHA3_384哈希算法处理正常数据",
		},
		{
			name: "SHA3_512_正常数据",
			args: args{
				hashType: crypto.SHA3_512,
				rawData:  hashRawData,
			},
			wantErr: false,
			desc:    "测试SHA3_512哈希算法处理正常数据",
		},
		{
			name: "SHA512_224_正常数据",
			args: args{
				hashType: crypto.SHA512_224,
				rawData:  hashRawData,
			},
			wantErr: false,
			desc:    "测试SHA512_224哈希算法处理正常数据",
		},
		{
			name: "SHA512_256_正常数据",
			args: args{
				hashType: crypto.SHA512_256,
				rawData:  hashRawData,
			},
			wantErr: false,
			desc:    "测试SHA512_256哈希算法处理正常数据",
		},
		{
			name: "BLAKE2s_256_正常数据",
			args: args{
				hashType: crypto.BLAKE2s_256,
				rawData:  hashRawData,
			},
			wantErr: false,
			desc:    "测试BLAKE2s_256哈希算法处理正常数据",
		},
		{
			name: "BLAKE2b_256_正常数据",
			args: args{
				hashType: crypto.BLAKE2b_256,
				rawData:  hashRawData,
			},
			wantErr: false,
			desc:    "测试BLAKE2b_256哈希算法处理正常数据",
		},
		{
			name: "BLAKE2b_384_正常数据",
			args: args{
				hashType: crypto.BLAKE2b_384,
				rawData:  hashRawData,
			},
			wantErr: false,
			desc:    "测试BLAKE2b_384哈希算法处理正常数据",
		},
		{
			name: "BLAKE2b_512_正常数据",
			args: args{
				hashType: crypto.BLAKE2b_512,
				rawData:  hashRawData,
			},
			wantErr: false,
			desc:    "测试BLAKE2b_512哈希算法处理正常数据",
		},
		{
			name: "MD5_空数据",
			args: args{
				hashType: crypto.MD5,
				rawData:  []byte{},
			},
			wantErr: false,
			desc:    "测试MD5哈希算法处理空数据",
		},
		{
			name: "不支持的哈希类型",
			args: args{
				hashType: crypto.Hash(999),
				rawData:  hashRawData,
			},
			wantErr: true,
			desc:    "测试不支持的哈希类型应返回错误",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Hash(tt.args.hashType, tt.args.rawData)
			if (err != nil) != tt.wantErr {
				t.Errorf("Hash() error = %v, wantErr %v, desc: %s", err, tt.wantErr, tt.desc)
				return
			}
			if !tt.wantErr {
				t.Logf("%s: Hash(%v) = %s", tt.desc, tt.args.hashType, got)
			} else {
				t.Logf("%s: 正确返回错误 = %v", tt.desc, err)
			}
		})
	}
}

func BenchmarkHash(b *testing.B) {
	b.Run("MD4", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Hash(crypto.MD4, hashRawData)
		}
	})

	b.Run("MD5", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Hash(crypto.MD5, hashRawData)
		}
	})

	b.Run("SHA1", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Hash(crypto.SHA1, hashRawData)
		}
	})

	b.Run("SHA224", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Hash(crypto.SHA224, hashRawData)
		}
	})

	b.Run("SHA256", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Hash(crypto.SHA256, hashRawData)
		}
	})

	b.Run("SHA384", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Hash(crypto.SHA384, hashRawData)
		}
	})

	b.Run("SHA512", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Hash(crypto.SHA512, hashRawData)
		}
	})

	b.Run("MD5SHA1", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Hash(crypto.MD5SHA1, hashRawData)
		}
	})

	b.Run("SHA3_224", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Hash(crypto.SHA3_224, hashRawData)
		}
	})

	b.Run("SHA3_256", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Hash(crypto.SHA3_256, hashRawData)
		}
	})

	b.Run("SHA3_384", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Hash(crypto.SHA3_384, hashRawData)
		}
	})

	b.Run("SHA3_512", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Hash(crypto.SHA3_512, hashRawData)
		}
	})

	b.Run("SHA512_224", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Hash(crypto.SHA512_224, hashRawData)
		}
	})

	b.Run("SHA512_256", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Hash(crypto.SHA512_256, hashRawData)
		}
	})

	b.Run("BLAKE2s_256", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Hash(crypto.BLAKE2s_256, hashRawData)
		}
	})

	b.Run("BLAKE2b_256", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Hash(crypto.BLAKE2b_256, hashRawData)
		}
	})

	b.Run("BLAKE2b_384", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Hash(crypto.BLAKE2b_384, hashRawData)
		}
	})

	b.Run("BLAKE2b_512", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Hash(crypto.BLAKE2b_512, hashRawData)
		}
	})
}
