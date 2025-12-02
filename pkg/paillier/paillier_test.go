package paillier

import (
	"crypto/rand"
	"math/big"
	"testing"
)

// ================= 辅助函数 =================

// verifyEncryptDecrypt 验证加密和解密的正确性
func verifyEncryptDecrypt(t *testing.T, priv *PrivateKey, m *big.Int) {
	pub := priv.Public()

	// 加密
	c, err := pub.Encrypt(rand.Reader, m)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}

	// 解密
	decrypted, err := priv.Decrypt(c)
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}

	// 验证
	if decrypted.Cmp(m) != 0 {
		t.Errorf("解密结果不正确: 期望 %v, 得到 %v", m, decrypted)
	}
}

// ================= 密钥生成测试 =================

func TestGenerateKey(t *testing.T) {
	t.Run("生成 2048 位密钥", func(t *testing.T) {
		priv, err := GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("生成密钥失败: %v", err)
		}

		if priv == nil {
			t.Fatal("私钥不应该为 nil")
		}
		if priv.N == nil || priv.N2 == nil || priv.G == nil {
			t.Error("公钥参数不应该为 nil")
		}
		if priv.Lambda == nil || priv.PhiN == nil {
			t.Error("私钥参数不应该为 nil")
		}
		if priv.P == nil || priv.Q == nil {
			t.Error("素数 p, q 不应该为 nil")
		}

		// 验证 N = p * q
		N := new(big.Int).Mul(priv.P, priv.Q)
		if N.Cmp(priv.N) != 0 {
			t.Error("N 应该等于 p * q")
		}

		// 验证 N^2
		N2 := new(big.Int).Mul(priv.N, priv.N)
		if N2.Cmp(priv.N2) != 0 {
			t.Error("N2 应该等于 N * N")
		}

		// 验证 G = N + 1
		G := new(big.Int).Add(priv.N, bigOne)
		if G.Cmp(priv.G) != 0 {
			t.Error("G 应该等于 N + 1")
		}
	})

	t.Run("生成安全素数密钥", func(t *testing.T) {
		priv, err := GenerateKeySafePrime(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("生成安全素数密钥失败: %v", err)
		}

		if priv == nil {
			t.Fatal("私钥不应该为 nil")
		}

		// 验证 p 和 q 是素数
		if !priv.P.ProbablyPrime(20) {
			t.Error("p 应该是素数")
		}
		if !priv.Q.ProbablyPrime(20) {
			t.Error("q 应该是素数")
		}
	})

	t.Run("密钥位数太小", func(t *testing.T) {
		_, err := GenerateKey(rand.Reader, 1024)
		if err == nil {
			t.Error("应该返回错误当密钥位数 < 2048")
		}
	})
}

func TestPublicKey(t *testing.T) {
	priv, err := GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}

	pub := priv.Public()
	if pub == nil {
		t.Fatal("公钥不应该为 nil")
	}

	// 验证公钥参数
	if pub.N.Cmp(priv.N) != 0 {
		t.Error("公钥的 N 应该与私钥相同")
	}
	if pub.N2.Cmp(priv.N2) != 0 {
		t.Error("公钥的 N2 应该与私钥相同")
	}
	if pub.G.Cmp(priv.G) != 0 {
		t.Error("公钥的 G 应该与私钥相同")
	}
}

// ================= 加密/解密测试 =================

func TestEncryptDecrypt(t *testing.T) {
	priv, err := GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}

	t.Run("加密解密小数字", func(t *testing.T) {
		m := big.NewInt(42)
		verifyEncryptDecrypt(t, priv, m)
	})

	t.Run("加密解密零", func(t *testing.T) {
		m := big.NewInt(0)
		verifyEncryptDecrypt(t, priv, m)
	})

	t.Run("加密解密大数字", func(t *testing.T) {
		m := new(big.Int).Sub(priv.N, bigOne)
		verifyEncryptDecrypt(t, priv, m)
	})

	t.Run("加密解密随机数", func(t *testing.T) {
		m, err := rand.Int(rand.Reader, priv.N)
		if err != nil {
			t.Fatalf("生成随机数失败: %v", err)
		}
		verifyEncryptDecrypt(t, priv, m)
	})

	t.Run("多次加密同一明文产生不同密文", func(t *testing.T) {
		pub := priv.Public()
		m := big.NewInt(123)

		c1, err := pub.Encrypt(rand.Reader, m)
		if err != nil {
			t.Fatalf("第一次加密失败: %v", err)
		}

		c2, err := pub.Encrypt(rand.Reader, m)
		if err != nil {
			t.Fatalf("第二次加密失败: %v", err)
		}

		// 密文应该不同（因为随机数不同）
		if c1.Cmp(c2) == 0 {
			t.Error("多次加密同一明文应该产生不同的密文")
		}

		// 但解密结果应该相同
		d1, _ := priv.Decrypt(c1)
		d2, _ := priv.Decrypt(c2)
		if d1.Cmp(d2) != 0 || d1.Cmp(m) != 0 {
			t.Error("解密结果应该相同且等于原始明文")
		}
	})
}

func TestEncryptWithRandomness(t *testing.T) {
	priv, err := GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	pub := priv.Public()

	t.Run("使用指定随机数加密", func(t *testing.T) {
		m := big.NewInt(100)
		r, err := randomRelativelyPrime(rand.Reader, pub.N)
		if err != nil {
			t.Fatalf("生成随机数失败: %v", err)
		}

		c, err := pub.EncryptWithRandomness(m, r)
		if err != nil {
			t.Fatalf("加密失败: %v", err)
		}

		decrypted, err := priv.Decrypt(c)
		if err != nil {
			t.Fatalf("解密失败: %v", err)
		}

		if decrypted.Cmp(m) != 0 {
			t.Errorf("解密结果不正确: 期望 %v, 得到 %v", m, decrypted)
		}
	})

	t.Run("明文超出范围", func(t *testing.T) {
		m := new(big.Int).Add(pub.N, bigOne) // m >= N
		r, _ := randomRelativelyPrime(rand.Reader, pub.N)

		_, err := pub.EncryptWithRandomness(m, r)
		if err == nil {
			t.Error("应该返回错误当明文 >= N")
		}
	})

	t.Run("明文为负数", func(t *testing.T) {
		m := big.NewInt(-1)
		r, _ := randomRelativelyPrime(rand.Reader, pub.N)

		_, err := pub.EncryptWithRandomness(m, r)
		if err == nil {
			t.Error("应该返回错误当明文为负数")
		}
	})

	t.Run("随机数为零", func(t *testing.T) {
		m := big.NewInt(50)
		r := big.NewInt(0)

		_, err := pub.EncryptWithRandomness(m, r)
		if err == nil {
			t.Error("应该返回错误当随机数为零")
		}
	})

	t.Run("随机数超出范围", func(t *testing.T) {
		m := big.NewInt(50)
		r := new(big.Int).Add(pub.N, bigOne) // r >= N

		_, err := pub.EncryptWithRandomness(m, r)
		if err == nil {
			t.Error("应该返回错误当随机数 >= N")
		}
	})
}

func TestDecryptInvalidCiphertext(t *testing.T) {
	priv, err := GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}

	t.Run("密文为零", func(t *testing.T) {
		c := big.NewInt(0)
		_, err := priv.Decrypt(c)
		if err == nil {
			t.Error("应该返回错误当密文为零")
		}
	})

	t.Run("密文超出范围", func(t *testing.T) {
		c := new(big.Int).Add(priv.N2, bigOne) // c >= N^2
		_, err := priv.Decrypt(c)
		if err == nil {
			t.Error("应该返回错误当密文 >= N^2")
		}
	})
}

// ================= 同态运算测试 =================

func TestHomomorphicAdd(t *testing.T) {
	priv, err := GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	pub := priv.Public()

	t.Run("同态加法基本测试", func(t *testing.T) {
		m1 := big.NewInt(100)
		m2 := big.NewInt(200)

		c1, _ := pub.Encrypt(rand.Reader, m1)
		c2, _ := pub.Encrypt(rand.Reader, m2)

		// 同态加法
		cSum, err := pub.Add(c1, c2)
		if err != nil {
			t.Fatalf("同态加法失败: %v", err)
		}

		// 解密结果
		result, err := priv.Decrypt(cSum)
		if err != nil {
			t.Fatalf("解密失败: %v", err)
		}

		// 验证结果
		expected := new(big.Int).Add(m1, m2)
		expected.Mod(expected, priv.N)
		if result.Cmp(expected) != 0 {
			t.Errorf("同态加法结果不正确: 期望 %v, 得到 %v", expected, result)
		}
	})

	t.Run("同态加法多个数", func(t *testing.T) {
		values := []*big.Int{
			big.NewInt(10),
			big.NewInt(20),
			big.NewInt(30),
			big.NewInt(40),
		}

		// 加密所有值
		var ciphertexts []*big.Int
		sum := big.NewInt(0)
		for _, v := range values {
			c, _ := pub.Encrypt(rand.Reader, v)
			ciphertexts = append(ciphertexts, c)
			sum.Add(sum, v)
		}

		// 同态加法
		result := ciphertexts[0]
		for i := 1; i < len(ciphertexts); i++ {
			result, _ = pub.Add(result, ciphertexts[i])
		}

		// 解密并验证
		decrypted, _ := priv.Decrypt(result)
		sum.Mod(sum, priv.N)
		if decrypted.Cmp(sum) != 0 {
			t.Errorf("多个数同态加法结果不正确: 期望 %v, 得到 %v", sum, decrypted)
		}
	})

	t.Run("同态加法与零", func(t *testing.T) {
		m := big.NewInt(123)
		zero := big.NewInt(0)

		c, _ := pub.Encrypt(rand.Reader, m)
		cZero, _ := pub.Encrypt(rand.Reader, zero)

		cSum, _ := pub.Add(c, cZero)
		result, _ := priv.Decrypt(cSum)

		if result.Cmp(m) != 0 {
			t.Errorf("与零的同态加法应该保持原值: 期望 %v, 得到 %v", m, result)
		}
	})
}

func TestHomomorphicMul(t *testing.T) {
	priv, err := GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	pub := priv.Public()

	t.Run("同态乘法基本测试", func(t *testing.T) {
		m := big.NewInt(50)
		k := big.NewInt(3)

		c, _ := pub.Encrypt(rand.Reader, m)

		// 同态乘法
		cMul, err := pub.Mul(c, k)
		if err != nil {
			t.Fatalf("同态乘法失败: %v", err)
		}

		// 解密结果
		result, err := priv.Decrypt(cMul)
		if err != nil {
			t.Fatalf("解密失败: %v", err)
		}

		// 验证结果
		expected := new(big.Int).Mul(m, k)
		expected.Mod(expected, priv.N)
		if result.Cmp(expected) != 0 {
			t.Errorf("同态乘法结果不正确: 期望 %v, 得到 %v", expected, result)
		}
	})

	t.Run("同态乘法乘以零", func(t *testing.T) {
		m := big.NewInt(100)
		k := big.NewInt(0)

		c, _ := pub.Encrypt(rand.Reader, m)
		cMul, _ := pub.Mul(c, k)
		result, _ := priv.Decrypt(cMul)

		if result.Cmp(big.NewInt(0)) != 0 {
			t.Errorf("乘以零应该得到零: 得到 %v", result)
		}
	})

	t.Run("同态乘法乘以一", func(t *testing.T) {
		m := big.NewInt(123)
		k := big.NewInt(1)

		c, _ := pub.Encrypt(rand.Reader, m)
		cMul, _ := pub.Mul(c, k)
		result, _ := priv.Decrypt(cMul)

		if result.Cmp(m) != 0 {
			t.Errorf("乘以一应该保持原值: 期望 %v, 得到 %v", m, result)
		}
	})

	t.Run("同态乘法大标量", func(t *testing.T) {
		m := big.NewInt(10)
		k := big.NewInt(1000000)

		c, _ := pub.Encrypt(rand.Reader, m)
		cMul, _ := pub.Mul(c, k)
		result, _ := priv.Decrypt(cMul)

		expected := new(big.Int).Mul(m, k)
		expected.Mod(expected, priv.N)
		if result.Cmp(expected) != 0 {
			t.Errorf("同态乘法大标量结果不正确: 期望 %v, 得到 %v", expected, result)
		}
	})
}

func TestHomomorphicCombined(t *testing.T) {
	priv, err := GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	pub := priv.Public()

	t.Run("组合运算: (m1 * k1) + (m2 * k2)", func(t *testing.T) {
		m1 := big.NewInt(10)
		m2 := big.NewInt(20)
		k1 := big.NewInt(3)
		k2 := big.NewInt(5)

		// 加密
		c1, _ := pub.Encrypt(rand.Reader, m1)
		c2, _ := pub.Encrypt(rand.Reader, m2)

		// 同态乘法
		c1k, _ := pub.Mul(c1, k1)
		c2k, _ := pub.Mul(c2, k2)

		// 同态加法
		cResult, _ := pub.Add(c1k, c2k)

		// 解密
		result, _ := priv.Decrypt(cResult)

		// 验证: (10 * 3) + (20 * 5) = 30 + 100 = 130
		expected := new(big.Int).Mul(m1, k1)
		tmp := new(big.Int).Mul(m2, k2)
		expected.Add(expected, tmp)
		expected.Mod(expected, priv.N)

		if result.Cmp(expected) != 0 {
			t.Errorf("组合运算结果不正确: 期望 %v, 得到 %v", expected, result)
		}
	})
}

// ================= 随机数恢复测试 =================

func TestRecoverRandomness(t *testing.T) {
	priv, err := GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	pub := priv.Public()

	t.Run("恢复随机数", func(t *testing.T) {
		m := big.NewInt(123)
		r, _ := randomRelativelyPrime(rand.Reader, pub.N)

		// 使用指定随机数加密
		c, _ := pub.EncryptWithRandomness(m, r)

		// 恢复随机数
		recoveredR, err := priv.RecoverRandomness(c, m)
		if err != nil {
			t.Fatalf("恢复随机数失败: %v", err)
		}

		// 验证恢复的随机数
		if recoveredR.Cmp(r) != 0 {
			t.Errorf("恢复的随机数不正确: 期望 %v, 得到 %v", r, recoveredR)
		}
	})

	t.Run("使用恢复的随机数重新加密", func(t *testing.T) {
		m := big.NewInt(456)
		r, _ := randomRelativelyPrime(rand.Reader, pub.N)

		c, _ := pub.EncryptWithRandomness(m, r)
		recoveredR, _ := priv.RecoverRandomness(c, m)

		// 使用恢复的随机数重新加密
		c2, _ := pub.EncryptWithRandomness(m, recoveredR)

		// 两个密文应该相同
		if c.Cmp(c2) != 0 {
			t.Error("使用相同的明文和随机数应该产生相同的密文")
		}
	})
}

// ================= 工具函数测试 =================

func TestLFunction(t *testing.T) {
	N := big.NewInt(100)

	t.Run("L(1) = 0", func(t *testing.T) {
		u := big.NewInt(1)
		result := L(u, N)
		if result.Cmp(big.NewInt(0)) != 0 {
			t.Errorf("L(1) 应该等于 0, 得到 %v", result)
		}
	})

	t.Run("L(N+1) = 1", func(t *testing.T) {
		u := new(big.Int).Add(N, bigOne)
		result := L(u, N)
		if result.Cmp(bigOne) != 0 {
			t.Errorf("L(N+1) 应该等于 1, 得到 %v", result)
		}
	})

	t.Run("L(2N+1) = 2", func(t *testing.T) {
		u := new(big.Int).Mul(N, big.NewInt(2))
		u.Add(u, bigOne)
		result := L(u, N)
		if result.Cmp(big.NewInt(2)) != 0 {
			t.Errorf("L(2N+1) 应该等于 2, 得到 %v", result)
		}
	})
}

func TestRandomRelativelyPrime(t *testing.T) {
	N := big.NewInt(100)

	t.Run("生成与 N 互质的随机数", func(t *testing.T) {
		r, err := randomRelativelyPrime(rand.Reader, N)
		if err != nil {
			t.Fatalf("生成随机数失败: %v", err)
		}

		// 验证范围
		if r.Sign() <= 0 || r.Cmp(N) >= 0 {
			t.Errorf("随机数应该在 (0, N) 范围内, 得到 %v", r)
		}

		// 验证互质
		gcd := new(big.Int).GCD(nil, nil, r, N)
		if gcd.Cmp(bigOne) != 0 {
			t.Errorf("随机数应该与 N 互质, gcd = %v", gcd)
		}
	})

	t.Run("多次生成产生不同的随机数", func(t *testing.T) {
		r1, _ := randomRelativelyPrime(rand.Reader, N)
		r2, _ := randomRelativelyPrime(rand.Reader, N)

		// 大概率不同（虽然理论上可能相同）
		if r1.Cmp(r2) == 0 {
			t.Log("警告: 两次生成了相同的随机数（小概率事件）")
		}
	})
}

// ================= 性能测试 =================

func BenchmarkGenerateKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GenerateKey(rand.Reader, 2048)
		if err != nil {
			b.Fatalf("生成密钥失败: %v", err)
		}
	}
}

func BenchmarkEncrypt(b *testing.B) {
	priv, _ := GenerateKey(rand.Reader, 2048)
	pub := priv.Public()
	m := big.NewInt(12345)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := pub.Encrypt(rand.Reader, m)
		if err != nil {
			b.Fatalf("加密失败: %v", err)
		}
	}
}

func BenchmarkDecrypt(b *testing.B) {
	priv, _ := GenerateKey(rand.Reader, 2048)
	pub := priv.Public()
	m := big.NewInt(12345)
	c, _ := pub.Encrypt(rand.Reader, m)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := priv.Decrypt(c)
		if err != nil {
			b.Fatalf("解密失败: %v", err)
		}
	}
}

func BenchmarkHomomorphicAdd(b *testing.B) {
	priv, _ := GenerateKey(rand.Reader, 2048)
	pub := priv.Public()
	c1, _ := pub.Encrypt(rand.Reader, big.NewInt(100))
	c2, _ := pub.Encrypt(rand.Reader, big.NewInt(200))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := pub.Add(c1, c2)
		if err != nil {
			b.Fatalf("同态加法失败: %v", err)
		}
	}
}

func BenchmarkHomomorphicMul(b *testing.B) {
	priv, _ := GenerateKey(rand.Reader, 2048)
	pub := priv.Public()
	c, _ := pub.Encrypt(rand.Reader, big.NewInt(100))
	k := big.NewInt(5)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := pub.Mul(c, k)
		if err != nil {
			b.Fatalf("同态乘法失败: %v", err)
		}
	}
}

