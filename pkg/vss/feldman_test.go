package vss

import (
	"crypto/elliptic"
	"math/big"
	"testing"
)

func TestSplitSecret(t *testing.T) {
	curve := elliptic.P256()
	secret := big.NewInt(12345)
	threshold := 3
	indices := []Index{
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(3),
		big.NewInt(4),
		big.NewInt(5),
	}

	t.Run("正常情况", func(t *testing.T) {
		commit, shares, err := SplitSecret(curve, threshold, secret, indices)
		if err != nil {
			t.Fatalf("SplitSecret 失败: %v", err)
		}

		if commit == nil {
			t.Fatal("commit 不应该为 nil")
		}
		if commit.Curve != curve {
			t.Error("commit.Curve 应该等于输入的 curve")
		}
		if len(commit.Coeffs) != threshold {
			t.Errorf("commit.Coeffs 长度应该是 %d, 得到 %d", threshold, len(commit.Coeffs))
		}

		if len(shares) != len(indices) {
			t.Errorf("shares 长度应该是 %d, 得到 %d", len(indices), len(shares))
		}

		// 验证每个 share
		for i, share := range shares {
			if share == nil {
				t.Fatalf("share[%d] 不应该为 nil", i)
			}
			if share.Index.Cmp(indices[i]) != 0 {
				t.Errorf("share[%d].Index 应该是 %v, 得到 %v", i, indices[i], share.Index)
			}
			if share.Threshold != threshold {
				t.Errorf("share[%d].Threshold 应该是 %d, 得到 %d", i, threshold, share.Threshold)
			}
			if share.Value == nil {
				t.Errorf("share[%d].Value 不应该为 nil", i)
			}
		}
	})

	t.Run("nil curve", func(t *testing.T) {
		_, _, err := SplitSecret(nil, threshold, secret, indices)
		if err == nil {
			t.Error("应该返回错误当 curve 为 nil")
		}
	})

	t.Run("nil secret", func(t *testing.T) {
		_, _, err := SplitSecret(curve, threshold, nil, indices)
		if err == nil {
			t.Error("应该返回错误当 secret 为 nil")
		}
	})

	t.Run("threshold < 1", func(t *testing.T) {
		_, _, err := SplitSecret(curve, 0, secret, indices)
		if err == nil {
			t.Error("应该返回错误当 threshold < 1")
		}
	})

	t.Run("空 indices", func(t *testing.T) {
		_, _, err := SplitSecret(curve, threshold, secret, []Index{})
		if err == nil {
			t.Error("应该返回错误当 indices 为空")
		}
	})

	t.Run("indices 长度 < threshold", func(t *testing.T) {
		shortIndices := []Index{big.NewInt(1), big.NewInt(2)}
		_, _, err := SplitSecret(curve, threshold, secret, shortIndices)
		if err == nil {
			t.Error("应该返回错误当 indices 长度 < threshold")
		}
	})
}

func TestReconstruct(t *testing.T) {
	curve := elliptic.P256()
	secret := big.NewInt(54321)
	threshold := 3
	indices := []Index{
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(3),
		big.NewInt(4),
		big.NewInt(5),
	}

	commit, shares, err := SplitSecret(curve, threshold, secret, indices)
	if err != nil {
		t.Fatalf("SplitSecret 失败: %v", err)
	}
	_ = commit // 用于后续验证

	t.Run("使用 t 个 shares 恢复", func(t *testing.T) {
		selectedShares := shares[:threshold]
		reconstructed, err := Reconstruct(curve, threshold, selectedShares)
		if err != nil {
			t.Fatalf("Reconstruct 失败: %v", err)
		}

		if reconstructed.Cmp(secret) != 0 {
			t.Errorf("恢复的 secret 应该是 %v, 得到 %v", secret, reconstructed)
		}
	})

	t.Run("使用超过 t 个 shares 恢复", func(t *testing.T) {
		selectedShares := shares[:threshold+1]
		reconstructed, err := Reconstruct(curve, threshold, selectedShares)
		if err != nil {
			t.Fatalf("Reconstruct 失败: %v", err)
		}

		if reconstructed.Cmp(secret) != 0 {
			t.Errorf("恢复的 secret 应该是 %v, 得到 %v", secret, reconstructed)
		}
	})

	t.Run("使用所有 shares 恢复", func(t *testing.T) {
		reconstructed, err := Reconstruct(curve, threshold, shares)
		if err != nil {
			t.Fatalf("Reconstruct 失败: %v", err)
		}

		if reconstructed.Cmp(secret) != 0 {
			t.Errorf("恢复的 secret 应该是 %v, 得到 %v", secret, reconstructed)
		}
	})

	t.Run("使用不同的 shares 子集恢复", func(t *testing.T) {
		// 使用索引 1, 3, 5 的 shares
		selectedShares := Shares{shares[0], shares[2], shares[4]}
		reconstructed, err := Reconstruct(curve, threshold, selectedShares)
		if err != nil {
			t.Fatalf("Reconstruct 失败: %v", err)
		}

		if reconstructed.Cmp(secret) != 0 {
			t.Errorf("恢复的 secret 应该是 %v, 得到 %v", secret, reconstructed)
		}
	})

	t.Run("shares 数量不足", func(t *testing.T) {
		selectedShares := shares[:threshold-1]
		_, err := Reconstruct(curve, threshold, selectedShares)
		if err == nil {
			t.Error("应该返回错误当 shares 数量不足")
		}
	})

	t.Run("nil curve", func(t *testing.T) {
		_, err := Reconstruct(nil, threshold, shares)
		if err == nil {
			t.Error("应该返回错误当 curve 为 nil")
		}
	})

	t.Run("threshold 不匹配的 shares", func(t *testing.T) {
		// 创建 threshold 不匹配的 shares
		wrongShares := make(Shares, threshold)
		for i := 0; i < threshold; i++ {
			wrongShares[i] = &Share{
				Index:     shares[i].Index,
				Value:     shares[i].Value,
				Threshold: threshold + 1, // 错误的 threshold
			}
		}
		_, err := Reconstruct(curve, threshold, wrongShares)
		if err == nil {
			t.Error("应该返回错误当 shares 的 threshold 不匹配")
		}
	})

	t.Run("包含 nil shares", func(t *testing.T) {
		sharesWithNil := make(Shares, threshold+1)
		copy(sharesWithNil, shares[:threshold])
		sharesWithNil[threshold] = nil // 添加一个 nil share
		reconstructed, err := Reconstruct(curve, threshold, sharesWithNil)
		if err != nil {
			t.Fatalf("Reconstruct 失败: %v", err)
		}

		if reconstructed.Cmp(secret) != 0 {
			t.Errorf("恢复的 secret 应该是 %v, 得到 %v", secret, reconstructed)
		}
	})
}

func TestShare_Verify(t *testing.T) {
	curve := elliptic.P256()
	secret := big.NewInt(99999)
	threshold := 3
	indices := []Index{
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(3),
		big.NewInt(4),
		big.NewInt(5),
	}

	commit, shares, err := SplitSecret(curve, threshold, secret, indices)
	if err != nil {
		t.Fatalf("SplitSecret 失败: %v", err)
	}

	t.Run("验证有效的 share", func(t *testing.T) {
		for i, share := range shares {
			if !share.Verify(curve, commit) {
				t.Errorf("share[%d] 应该验证通过", i)
			}
		}
	})

	t.Run("验证修改后的 share", func(t *testing.T) {
		// 修改 share 的 value
		modifiedShare := &Share{
			Index:     shares[0].Index,
			Value:     new(big.Int).Add(shares[0].Value, big.NewInt(1)),
			Threshold: shares[0].Threshold,
		}
		if modifiedShare.Verify(curve, commit) {
			t.Error("修改后的 share 不应该验证通过")
		}
	})

	t.Run("验证修改后的 index", func(t *testing.T) {
		// 修改 share 的 index
		modifiedShare := &Share{
			Index:     new(big.Int).Add(shares[0].Index, big.NewInt(1)),
			Value:     shares[0].Value,
			Threshold: shares[0].Threshold,
		}
		if modifiedShare.Verify(curve, commit) {
			t.Error("修改 index 后的 share 不应该验证通过")
		}
	})

	t.Run("nil share", func(t *testing.T) {
		var nilShare *Share
		if nilShare.Verify(curve, commit) {
			t.Error("nil share 不应该验证通过")
		}
	})

	t.Run("nil commit", func(t *testing.T) {
		if shares[0].Verify(curve, nil) {
			t.Error("nil commit 不应该验证通过")
		}
	})

	t.Run("曲线不一致", func(t *testing.T) {
		// 使用不同的曲线
		differentCurve := elliptic.P224()
		if shares[0].Verify(differentCurve, commit) {
			t.Error("曲线不一致时不应该验证通过")
		}
	})

	t.Run("threshold 不匹配", func(t *testing.T) {
		wrongShare := &Share{
			Index:     shares[0].Index,
			Value:     shares[0].Value,
			Threshold: threshold + 1,
		}
		if wrongShare.Verify(curve, commit) {
			t.Error("threshold 不匹配时不应该验证通过")
		}
	})

	t.Run("nil Index", func(t *testing.T) {
		wrongShare := &Share{
			Index:     nil,
			Value:     shares[0].Value,
			Threshold: shares[0].Threshold,
		}
		if wrongShare.Verify(curve, commit) {
			t.Error("nil Index 不应该验证通过")
		}
	})

	t.Run("nil Value", func(t *testing.T) {
		wrongShare := &Share{
			Index:     shares[0].Index,
			Value:     nil,
			Threshold: shares[0].Threshold,
		}
		if wrongShare.Verify(curve, commit) {
			t.Error("nil Value 不应该验证通过")
		}
	})
}

func TestCheckIndices(t *testing.T) {
	curve := elliptic.P256()
	N := curve.Params().N

	t.Run("正常情况", func(t *testing.T) {
		indices := []Index{
			big.NewInt(1),
			big.NewInt(2),
			big.NewInt(3),
		}
		normalized, err := CheckIndices(curve, indices)
		if err != nil {
			t.Fatalf("CheckIndices 失败: %v", err)
		}

		if len(normalized) != len(indices) {
			t.Errorf("normalized 长度应该是 %d, 得到 %d", len(indices), len(normalized))
		}

		for i, idx := range normalized {
			if idx.Cmp(indices[i]) != 0 {
				t.Errorf("normalized[%d] 应该是 %v, 得到 %v", i, indices[i], idx)
			}
		}
	})

	t.Run("大索引（会被 mod N）", func(t *testing.T) {
		largeIndex := new(big.Int).Add(N, big.NewInt(5))
		indices := []Index{
			big.NewInt(1),
			largeIndex,
			big.NewInt(3),
		}
		normalized, err := CheckIndices(curve, indices)
		if err != nil {
			t.Fatalf("CheckIndices 失败: %v", err)
		}

		// 检查大索引是否被正确 mod
		expected := new(big.Int).Mod(largeIndex, N)
		if normalized[1].Cmp(expected) != 0 {
			t.Errorf("normalized[1] 应该是 %v (mod N), 得到 %v", expected, normalized[1])
		}
	})

	t.Run("空列表", func(t *testing.T) {
		_, err := CheckIndices(curve, []Index{})
		if err == nil {
			t.Error("应该返回错误当 indices 为空")
		}
	})

	t.Run("重复索引", func(t *testing.T) {
		indices := []Index{
			big.NewInt(1),
			big.NewInt(2),
			big.NewInt(1), // 重复
		}
		_, err := CheckIndices(curve, indices)
		if err == nil {
			t.Error("应该返回错误当 indices 有重复")
		}
	})

	t.Run("索引为 0 (mod N)", func(t *testing.T) {
		// 创建一个 mod N 后为 0 的索引
		zeroIndex := new(big.Int).Set(N)
		indices := []Index{
			big.NewInt(1),
			zeroIndex,
			big.NewInt(3),
		}
		_, err := CheckIndices(curve, indices)
		if err == nil {
			t.Error("应该返回错误当索引 mod N 后为 0")
		}
	})

	t.Run("重复索引（mod N 后）", func(t *testing.T) {
		// 创建两个不同的索引，但 mod N 后相同
		index1 := big.NewInt(5)
		index2 := new(big.Int).Add(N, big.NewInt(5))
		indices := []Index{
			index1,
			index2,
		}
		_, err := CheckIndices(curve, indices)
		if err == nil {
			t.Error("应该返回错误当索引 mod N 后重复")
		}
	})
}

func TestIntegration(t *testing.T) {
	// 集成测试：完整的 VSS 流程
	curve := elliptic.P256()
	secret := big.NewInt(123456789)
	threshold := 5
	n := 10 // 总共 10 个参与方

	// 生成索引
	indices := make([]Index, n)
	for i := 0; i < n; i++ {
		indices[i] = big.NewInt(int64(i + 1))
	}

	// 拆分秘密
	commit, shares, err := SplitSecret(curve, threshold, secret, indices)
	if err != nil {
		t.Fatalf("SplitSecret 失败: %v", err)
	}

	// 验证所有 shares
	for i, share := range shares {
		if !share.Verify(curve, commit) {
			t.Errorf("share[%d] 验证失败", i)
		}
	}

	// 测试使用不同的 shares 子集恢复
	testCases := [][]int{
		{0, 1, 2, 3, 4},          // 前 5 个
		{5, 6, 7, 8, 9},          // 后 5 个
		{0, 2, 4, 6, 8},          // 偶数索引
		{1, 3, 5, 7, 9},          // 奇数索引
		{0, 1, 2, 3, 4, 5, 6, 7}, // 超过 threshold
	}

	for _, tc := range testCases {
		selectedShares := make(Shares, len(tc))
		for i, idx := range tc {
			selectedShares[i] = shares[idx]
		}

		reconstructed, err := Reconstruct(curve, threshold, selectedShares)
		if err != nil {
			t.Fatalf("Reconstruct 失败 (indices %v): %v", tc, err)
		}

		if reconstructed.Cmp(secret) != 0 {
			t.Errorf("恢复的 secret 不正确 (indices %v): 期望 %v, 得到 %v", tc, secret, reconstructed)
		}
	}
}

func TestDifferentCurves(t *testing.T) {
	// 测试不同的椭圆曲线
	curves := []elliptic.Curve{
		elliptic.P224(),
		elliptic.P256(),
		elliptic.P384(),
		elliptic.P521(),
	}

	secret := big.NewInt(42)
	threshold := 3
	indices := []Index{
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(3),
		big.NewInt(4),
	}

	for _, curve := range curves {
		t.Run(curve.Params().Name, func(t *testing.T) {
			commit, shares, err := SplitSecret(curve, threshold, secret, indices)
			if err != nil {
				t.Fatalf("SplitSecret 失败: %v", err)
			}

			// 验证所有 shares
			for i, share := range shares {
				if !share.Verify(curve, commit) {
					t.Errorf("share[%d] 验证失败", i)
				}
			}

			// 恢复 secret
			selectedShares := shares[:threshold]
			reconstructed, err := Reconstruct(curve, threshold, selectedShares)
			if err != nil {
				t.Fatalf("Reconstruct 失败: %v", err)
			}

			if reconstructed.Cmp(secret) != 0 {
				t.Errorf("恢复的 secret 不正确: 期望 %v, 得到 %v", secret, reconstructed)
			}
		})
	}
}

func TestLargeSecret(t *testing.T) {
	// 测试大秘密值
	curve := elliptic.P256()
	N := curve.Params().N

	// 使用接近 N 的秘密值
	secret := new(big.Int).Sub(N, big.NewInt(1))
	threshold := 3
	indices := []Index{
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(3),
		big.NewInt(4),
	}

	commit, shares, err := SplitSecret(curve, threshold, secret, indices)
	if err != nil {
		t.Fatalf("SplitSecret 失败: %v", err)
	}

	// 验证并恢复
	for _, share := range shares {
		if !share.Verify(curve, commit) {
			t.Error("share 验证失败")
		}
	}

	reconstructed, err := Reconstruct(curve, threshold, shares[:threshold])
	if err != nil {
		t.Fatalf("Reconstruct 失败: %v", err)
	}

	if reconstructed.Cmp(secret) != 0 {
		t.Errorf("恢复的 secret 不正确: 期望 %v, 得到 %v", secret, reconstructed)
	}
}
