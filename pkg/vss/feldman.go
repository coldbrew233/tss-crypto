package vss

import (
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"tss-crypto/pkg/ec"
	"tss-crypto/pkg/mod"
)

// Index 是参与方的 x 坐标，通常是 1,2,3... 这样的非零值
type Index = *big.Int

// Share 表示单个参与方拿到的秘密份额 f(x_i)
type Share struct {
	Index     Index    // x_i
	Value     *big.Int // f(x_i) mod N
	Threshold int      // t
}

// Shares 是 Share 的切片别名，便于给方法挂接接收者
type Shares []*Share

// Commitment 保存 Feldman VSS 的承诺：C_j = a_j * G
// 其中 a_0 = secret, deg(f) = Threshold-1
type Commitment struct {
	Curve  elliptic.Curve
	Coeffs []*ec.Point // C_0..C_{t-1}
}

// ---- 公开 API ----

// Split 对 secret 做 Shamir+Feldman VSS 拆分，返回多项式承诺和所有份额
// indices 长度 = 要发出去的 share 个数；如果为空你也可以选择内部自动生成 1..n
func SplitSecret(curve elliptic.Curve, threshold int, secret *big.Int, indices []Index) (*Commitment, Shares, error) {
	// 输入检查合并
	if curve == nil || secret == nil {
		return nil, nil, fmt.Errorf("curve or secret is nil")
	}
	if threshold < 1 {
		return nil, nil, fmt.Errorf("threshold must be at least 1")
	}
	if len(indices) == 0 {
		return nil, nil, fmt.Errorf("indices is nil or empty")
	}
	if len(indices) < threshold {
		return nil, nil, fmt.Errorf("indices length is less than threshold")
	}

	// 生成多项式
	polynomial := generateRandomPolynomial(curve, threshold, secret)

	// 计算承诺，复用 commitment := &Commitment{ ... }
	commitment := &Commitment{
		Curve:  curve,
		Coeffs: make([]*ec.Point, threshold),
	}
	for i, coeff := range polynomial {
		commitment.Coeffs[i] = ec.ScalarBaseMult(curve, coeff)
	}

	shares := make(Shares, len(indices))
	for i, index := range indices {
		shares[i] = &Share{
			Index:     index,
			Value:     computeShare(curve, polynomial, index, threshold),
			Threshold: threshold,
		}
	}

	return commitment, shares, nil
}

// Reconstruct 使用至少 t 个 share 恢复 secret
func Reconstruct(curve elliptic.Curve, threshold int, shares Shares) (*big.Int, error) {
	if curve == nil {
		return nil, fmt.Errorf("curve is nil")
	}
	if len(shares) < threshold {
		return nil, fmt.Errorf("need at least %d shares to reconstruct, got %d", threshold, len(shares))
	}
	N := curve.Params().N
	// 选取前 threshold 个非 nil 且 threshold 匹配的 share
	selected := make([]*Share, 0, threshold)
	for _, s := range shares {
		if s != nil && s.Threshold == threshold {
			selected = append(selected, s)
			if len(selected) == threshold {
				break
			}
		}
	}
	if len(selected) < threshold {
		return nil, fmt.Errorf("valid shares fewer than threshold")
	}

	// 计算所有拉格朗日插值系数
	lambdaCoeffs, err := lagrangeCoefficients(selected, N)
	if err != nil {
		return nil, err
	}

	secret := big.NewInt(0)
	for i := 0; i < threshold; i++ {
		si := selected[i]
		lagCoeff := lambdaCoeffs[i]
		part := mod.ModMul(si.Value, lagCoeff, N)
		secret = mod.ModAdd(secret, part, N)
	}
	return secret, nil
}

// Verify 验证 Feldman VSS 下某个 share 是否有效
// 验证思路：
// 给定承诺 C_i = a_i * G（G 为基点）和分片 (index, value=s(index))，
// 检查：G^{s(index)} 是否等于 C_0 + C_1·index + C_2·index^2 + ... + C_{t-1}·index^{t-1}
// 即：G^{s(index)} == \sum_{i=0}^{t-1} C_i * index^i
// 其中，C_i = a_i * G，是第 i 个多项式系数的椭圆曲线点承诺
func (s *Share) Verify(curve elliptic.Curve, commit *Commitment) bool {
	// 基本输入检查
	if s == nil || commit == nil ||
		s.Index == nil || s.Value == nil ||
		s.Threshold < 1 || s.Threshold != len(commit.Coeffs) {
		return false
	}

	// 检查曲线一致性
	if curve != commit.Curve {
		return false
	}

	N := curve.Params().N

	// 累加承诺多项式的点值：result = C_0
	result := commit.Coeffs[0].Copy()

	// exp = index，后续exp依次乘index得到 index^2, index^3, ...
	exp := new(big.Int).Set(s.Index)
	for _, c := range commit.Coeffs[1:] {
		// 计算 C_i * index^i
		// 公式：EC_point = c * exp
		pt := c.ScalarMult(exp)
		// 累加到总和上
		result = result.Add(pt)
		// exp = exp * index mod N，得到下一个index的幂
		exp = mod.ModMul(exp, s.Index, N)
	}

	// 计算左侧期望结果: 基点G * share_value
	expected := ec.ScalarBaseMult(curve, s.Value)

	// 判断两侧是否相等（椭圆曲线点相等）
	return result.Equal(expected)
}

// CheckIndices 规范化/检查索引：取 mod N，不能为 0，不能重复
func CheckIndices(curve elliptic.Curve, indices []Index) ([]Index, error) {
	if len(indices) == 0 {
		return nil, errors.New("indices list is empty")
	}
	N := curve.Params().N
	normalized := make([]Index, len(indices))
	uniq := make(map[string]bool)

	for i, idx := range indices {
		norm := mod.Mod(idx, N)
		if norm.Sign() == 0 {
			return nil, errors.New("index after mod N cannot be zero")
		}
		key := norm.String()
		if uniq[key] {
			return nil, errors.New("indices contain duplicates after normalization")
		}
		uniq[key] = true
		normalized[i] = norm
	}
	return normalized, nil
}

// ---- 内部实现 ----

// 生成随机多项式系数
func generateRandomPolynomial(curve elliptic.Curve, threshold int, secret *big.Int) []*big.Int {
	coefficients := make([]*big.Int, threshold)
	coefficients[0] = secret
	for i := 1; i < threshold; i++ {
		r, err := rand.Int(rand.Reader, curve.Params().N)
		if err != nil {
			panic(err) // Panic as a placeholder, consider handling error properly
		}
		coefficients[i] = r
	}
	return coefficients
}

// 计算多项式 f(index) = a0 + a1*index + a2*index^2 + ... + at*index^t (mod N)
func computeShare(curve elliptic.Curve, coefficients []*big.Int, index Index, threshold int) *big.Int {
	N := curve.Params().N
	share := big.NewInt(0)

	for i := 0; i < threshold; i++ {
		// term = a_i * index^i (mod N)
		exp := mod.ModExp(index, big.NewInt(int64(i)), N) // index^i mod N
		term := mod.ModMul(coefficients[i], exp, N)       // a_i * index^i mod N
		share = mod.ModAdd(share, term, N)
	}
	return share
}

// lagrangeCoefficients 计算拉格朗日插值系数 λ0, λ1, ..., λ_{n-1}
func lagrangeCoefficients(shares []*Share, N *big.Int) ([]*big.Int, error) {
	n := len(shares)
	lambdas := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		si := shares[i]
		num := big.NewInt(1)
		den := big.NewInt(1)
		for j := 0; j < n; j++ {
			if i == j {
				continue
			}
			sj := shares[j]
			num = mod.ModMul(num, sj.Index, N)
			tmp := mod.ModSub(sj.Index, si.Index, N) // Ensure positive modulo
			den = mod.ModMul(den, tmp, N)
		}
		denInv, err := mod.ModInverse(den, N)
		if err != nil {
			return nil, fmt.Errorf("failed to compute modular inverse in lagrangeCoefficients: %w", err)
		}
		lagCoeff := mod.ModMul(num, denInv, N)
		lambdas[i] = lagCoeff
	}
	return lambdas, nil
}
