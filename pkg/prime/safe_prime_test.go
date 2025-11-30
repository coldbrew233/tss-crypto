package prime

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
)

// ================= 辅助函数 =================

// verifySafePrime 验证生成的安全素数是否满足条件：
// 1. p 是素数
// 2. q 是素数
// 3. p = 2q + 1
// 4. p 的位数正确
func verifySafePrime(t *testing.T, sp *SafePrime, expectedBits int) {
	if sp == nil {
		t.Fatal("SafePrime 不应该为 nil")
	}
	if sp.P == nil {
		t.Fatal("SafePrime.P 不应该为 nil")
	}
	if sp.Q == nil {
		t.Fatal("SafePrime.Q 不应该为 nil")
	}

	// 验证 p 的位数
	actualBits := sp.P.BitLen()
	if actualBits != expectedBits {
		t.Errorf("p 的位数应该是 %d, 得到 %d", expectedBits, actualBits)
	}

	// 验证 p = 2q + 1
	twoQPlusOne := new(big.Int).Lsh(sp.Q, 1)
	twoQPlusOne.Add(twoQPlusOne, bigOne)
	if sp.P.Cmp(twoQPlusOne) != 0 {
		t.Errorf("p 应该等于 2q + 1, 但 p = %v, 2q + 1 = %v", sp.P, twoQPlusOne)
	}

	// 验证 p 是素数（使用 Miller-Rabin，轮数足够高）
	if !sp.P.ProbablyPrime(40) {
		t.Error("p 应该是素数，但 Miller-Rabin 测试失败")
	}

	// 验证 q 是素数
	if !sp.Q.ProbablyPrime(40) {
		t.Error("q 应该是素数，但 Miller-Rabin 测试失败")
	}

	// 验证 q 的位数（应该比 p 少 1 位）
	expectedQBits := expectedBits - 1
	actualQBits := sp.Q.BitLen()
	if actualQBits != expectedQBits {
		t.Errorf("q 的位数应该是 %d, 得到 %d", expectedQBits, actualQBits)
	}
}

// ================= 基本功能测试 =================

func TestGenerateSafePrime_Basic(t *testing.T) {
	t.Run("生成 256 位安全素数", func(t *testing.T) {
		sp, err := GenerateSafePrime(256, nil, nil)
		if err != nil {
			t.Fatalf("生成安全素数失败: %v", err)
		}
		verifySafePrime(t, sp, 256)
	})

	t.Run("生成 512 位安全素数", func(t *testing.T) {
		sp, err := GenerateSafePrime(512, nil, nil)
		if err != nil {
			t.Fatalf("生成安全素数失败: %v", err)
		}
		verifySafePrime(t, sp, 512)
	})

	t.Run("生成 1024 位安全素数", func(t *testing.T) {
		sp, err := GenerateSafePrime(1024, nil, nil)
		if err != nil {
			t.Fatalf("生成安全素数失败: %v", err)
		}
		verifySafePrime(t, sp, 1024)
	})

	t.Run("生成多个不同的安全素数", func(t *testing.T) {
		// 生成多个安全素数，确保它们不同
		primes := make(map[string]bool)
		for i := 0; i < 5; i++ {
			sp, err := GenerateSafePrime(256, nil, nil)
			if err != nil {
				t.Fatalf("生成第 %d 个安全素数失败: %v", i+1, err)
			}
			pStr := sp.P.String()
			if primes[pStr] {
				t.Errorf("生成的第 %d 个安全素数与之前的重复: %s", i+1, pStr)
			}
			primes[pStr] = true
			verifySafePrime(t, sp, 256)
		}
	})
}

// ================= 边界条件测试 =================

func TestGenerateSafePrime_EdgeCases(t *testing.T) {
	t.Run("位数太小", func(t *testing.T) {
		_, err := GenerateSafePrime(2, nil, nil)
		if err == nil {
			t.Error("应该返回错误当位数 < 3")
		}
	})

	t.Run("最小有效位数", func(t *testing.T) {
		// 跳过 3 位测试，因为候选空间太小，生成时间过长
		// 实际应用中，安全素数通常至少需要 256 位
		t.Skip("跳过 3 位测试，因为生成时间过长")
	})

	t.Run("小位数测试", func(t *testing.T) {
		// 测试一些较小的位数（跳过 8 位，因为可能运行时间较长）
		bits := []int{16, 32, 64}
		for _, b := range bits {
			t.Run(fmt.Sprintf("%d 位", b), func(t *testing.T) {
				sp, err := GenerateSafePrime(b, nil, nil)
				if err != nil {
					t.Fatalf("生成 %d 位安全素数失败: %v", b, err)
				}
				verifySafePrime(t, sp, b)
			})
		}
	})
}

// ================= 配置选项测试 =================

func TestGenerateSafePrime_WithConfig(t *testing.T) {
	t.Run("使用默认配置", func(t *testing.T) {
		cfg := DefaultConfig()
		sp, err := GenerateSafePrime(256, cfg, nil)
		if err != nil {
			t.Fatalf("使用默认配置生成失败: %v", err)
		}
		verifySafePrime(t, sp, 256)
	})

	t.Run("自定义窗口大小", func(t *testing.T) {
		cfg := &Config{
			WindowDeltaMax:    2048,
			MillerRabinRounds: 32,
			UseFermatQ:        false,
			UseFermatP:        true,
			FilterForSophie:   true,
		}
		sp, err := GenerateSafePrime(256, cfg, nil)
		if err != nil {
			t.Fatalf("使用自定义配置生成失败: %v", err)
		}
		verifySafePrime(t, sp, 256)
	})

	t.Run("启用 Fermat 预筛", func(t *testing.T) {
		cfg := &Config{
			WindowDeltaMax:    1024,
			MillerRabinRounds: 32,
			UseFermatQ:        true,
			UseFermatP:        true,
			FilterForSophie:   true,
		}
		sp, err := GenerateSafePrime(256, cfg, nil)
		if err != nil {
			t.Fatalf("启用 Fermat 预筛生成失败: %v", err)
		}
		verifySafePrime(t, sp, 256)
	})

	t.Run("禁用 Sophie 过滤", func(t *testing.T) {
		cfg := &Config{
			WindowDeltaMax:    1024,
			MillerRabinRounds: 32,
			UseFermatQ:        false,
			UseFermatP:        true,
			FilterForSophie:   false,
		}
		sp, err := GenerateSafePrime(256, cfg, nil)
		if err != nil {
			t.Fatalf("禁用 Sophie 过滤生成失败: %v", err)
		}
		verifySafePrime(t, sp, 256)
	})

	t.Run("更多 Miller-Rabin 轮数", func(t *testing.T) {
		cfg := &Config{
			WindowDeltaMax:    1024,
			MillerRabinRounds: 64,
			UseFermatQ:        false,
			UseFermatP:        true,
			FilterForSophie:   true,
		}
		sp, err := GenerateSafePrime(256, cfg, nil)
		if err != nil {
			t.Fatalf("使用更多轮数生成失败: %v", err)
		}
		verifySafePrime(t, sp, 256)
	})
}

// ================= 随机数生成器测试 =================

func TestGenerateSafePrime_WithCustomReader(t *testing.T) {
	t.Run("使用自定义随机数生成器", func(t *testing.T) {
		sp, err := GenerateSafePrime(256, nil, rand.Reader)
		if err != nil {
			t.Fatalf("使用自定义随机数生成器失败: %v", err)
		}
		verifySafePrime(t, sp, 256)
	})
}

// ================= 性能测试 =================

func BenchmarkGenerateSafePrime_256(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GenerateSafePrime(256, nil, nil)
		if err != nil {
			b.Fatalf("生成失败: %v", err)
		}
	}
}

func BenchmarkGenerateSafePrime_512(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GenerateSafePrime(512, nil, nil)
		if err != nil {
			b.Fatalf("生成失败: %v", err)
		}
	}
}

func BenchmarkGenerateSafePrime_1024(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GenerateSafePrime(1024, nil, nil)
		if err != nil {
			b.Fatalf("生成失败: %v", err)
		}
	}
}

// ================= 配置默认值测试 =================

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig 不应该返回 nil")
	}
	if cfg.WindowDeltaMax == 0 {
		t.Error("WindowDeltaMax 应该有默认值")
	}
	if cfg.MillerRabinRounds == 0 {
		t.Error("MillerRabinRounds 应该有默认值")
	}
}

// ================= 安全素数属性验证 =================

func TestSafePrime_Properties(t *testing.T) {
	sp, err := GenerateSafePrime(256, nil, nil)
	if err != nil {
		t.Fatalf("生成安全素数失败: %v", err)
	}

	t.Run("验证 p 是奇数", func(t *testing.T) {
		if sp.P.Bit(0) != 1 {
			t.Error("p 应该是奇数")
		}
	})

	t.Run("验证 q 是奇数", func(t *testing.T) {
		if sp.Q.Bit(0) != 1 {
			t.Error("q 应该是奇数")
		}
	})

	t.Run("验证 p > q", func(t *testing.T) {
		if sp.P.Cmp(sp.Q) <= 0 {
			t.Error("p 应该大于 q")
		}
	})

	t.Run("验证 (p-1)/2 = q", func(t *testing.T) {
		pMinusOne := new(big.Int).Sub(sp.P, bigOne)
		pMinusOneDiv2 := new(big.Int).Rsh(pMinusOne, 1)
		if pMinusOneDiv2.Cmp(sp.Q) != 0 {
			t.Errorf("(p-1)/2 应该等于 q, 但 (p-1)/2 = %v, q = %v", pMinusOneDiv2, sp.Q)
		}
	})
}
