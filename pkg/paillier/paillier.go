package paillier

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"
	"tss-crypto/pkg/mod"
	"tss-crypto/pkg/prime"
)

// 最小推荐模数位数
const MinModulusBits = 2048

var (
	errMessageTooLarge   = errors.New("paillier: plaintext must satisfy 0 <= m < N")
	errCiphertextInvalid = errors.New("paillier: ciphertext invalid")
	errRandomnessInvalid = errors.New("paillier: randomness must satisfy gcd(r, N) = 1 and 1 <= r < N")

	bigOne = big.NewInt(1)
)

// 公钥结构，Paillier 公钥（N, G = N+1）
type PublicKey struct {
	N  *big.Int
	N2 *big.Int // N^2
	G  *big.Int // G = N+1
}

// 私钥结构，Paillier 私钥
type PrivateKey struct {
	PublicKey
	Lambda *big.Int // lcm(p-1, q-1)
	PhiN   *big.Int // (p-1)*(q-1)
	P      *big.Int
	Q      *big.Int
}

// -----------------------------------------------------------------------------
// 密钥生成
// -----------------------------------------------------------------------------

// GenerateKey 使用普通素数生成 Paillier 密钥
func GenerateKey(random io.Reader, bits int) (*PrivateKey, error) {
	return generateKey(random, bits, false)
}

// GenerateKeySafePrime 生成 p,q 都为安全素数的 Paillier 密钥
func GenerateKeySafePrime(random io.Reader, bits int) (*PrivateKey, error) {
	return generateKey(random, bits, true)
}

// 获取公钥
func (priv *PrivateKey) Public() *PublicKey {
	return &PublicKey{
		N:  priv.N,
		N2: priv.N2,
		G:  priv.G,
	}
}

func generateKey(random io.Reader, bits int, safe bool) (*PrivateKey, error) {
	if bits < MinModulusBits {
		return nil, errors.New("paillier: modulus too small (min 2048 bits)")
	}

	half := bits / 2

	var p, q *big.Int
	var err error

	for {
		if safe {
			safePrime, err := prime.GenerateSafePrime(half, prime.DefaultConfig(), random)
			if err != nil {
				return nil, err
			}
			p, q = safePrime.P, safePrime.Q
		} else {
			p, err = rand.Prime(random, half)
			if err != nil {
				return nil, err
			}
			q, err = rand.Prime(random, half)
			if err != nil {
				return nil, err
			}
		}

		if p.Cmp(q) != 0 {
			break
		}
	}

	N := new(big.Int).Mul(p, q)
	N2 := new(big.Int).Mul(N, N)
	G := new(big.Int).Add(N, bigOne)

	pm1 := new(big.Int).Sub(p, bigOne)
	qm1 := new(big.Int).Sub(q, bigOne)
	phiN := new(big.Int).Mul(pm1, qm1)

	gcd := new(big.Int).GCD(nil, nil, pm1, qm1)
	lambda := new(big.Int).Div(phiN, gcd)

	pub := PublicKey{N: N, N2: N2, G: G}

	return &PrivateKey{
		PublicKey: pub,
		Lambda:    lambda,
		PhiN:      phiN,
		P:         p,
		Q:         q,
	}, nil
}

// -----------------------------------------------------------------------------
// 加密/解密
// -----------------------------------------------------------------------------

// Encrypt 用 Paillier 公钥加密 m，使用随机 r ∈ Z*_N
func (pub *PublicKey) Encrypt(random io.Reader, m *big.Int) (*big.Int, error) {
	r, err := randomRelativelyPrime(random, pub.N)
	if err != nil {
		return nil, err
	}
	return pub.EncryptWithRandomness(m, r)
}

// EncryptWithRandomness 用外部指定随机数 r 加密 m
func (pub *PublicKey) EncryptWithRandomness(m, r *big.Int) (*big.Int, error) {
	if m.Sign() < 0 || m.Cmp(pub.N) >= 0 {
		return nil, errMessageTooLarge
	}
	if r.Sign() <= 0 || r.Cmp(pub.N) >= 0 {
		return nil, errRandomnessInvalid
	}
	if new(big.Int).GCD(nil, nil, r, pub.N).Cmp(bigOne) != 0 {
		return nil, errRandomnessInvalid
	}

	// c = g^m * r^N mod N^2
	// 计算 g^m mod N^2
	gm := mod.ModExp(pub.G, m, pub.N2)
	// 计算 r^N mod N^2
	rN := mod.ModExp(r, pub.N, pub.N2)
	// 计算 (g^m * r^N) mod N^2
	c := mod.ModMul(gm, rN, pub.N2)
	return c, nil
}

// Decrypt 解密密文 c，返回明文 m
func (priv *PrivateKey) Decrypt(c *big.Int) (*big.Int, error) {
	if c.Sign() <= 0 || c.Cmp(priv.N2) >= 0 {
		return nil, errCiphertextInvalid
	}

	if new(big.Int).GCD(nil, nil, c, priv.N2).Cmp(bigOne) != 0 {
		return nil, errCiphertextInvalid
	}

	// 计算 c^lambda mod N^2
	u := mod.ModExp(c, priv.Lambda, priv.N2)
	// L(u) = (u - 1) / N
	Lc := L(u, priv.N)

	// 计算 g^lambda mod N^2
	ug := mod.ModExp(priv.G, priv.Lambda, priv.N2)

	// L(g^lambda) = (g^lambda - 1) / N
	Lg := L(ug, priv.N)

	// 计算 L(g^lambda) 的模逆元
	inv, err := mod.ModInverse(Lg, priv.N)
	if err != nil {
		return nil, errors.New("paillier: cannot invert L(g^lambda)")
	}

	// 计算 m = (L(u) * inv) mod N
	m := mod.ModMul(Lc, inv, priv.N)
	return m, nil
}

// -----------------------------------------------------------------------------
// 同态运算
// -----------------------------------------------------------------------------

// Add 同态加法：返回 Enc(m1 + m2)
// 对两个密文执行同态加法运算，结果对应于明文的加法
func (pub *PublicKey) Add(c1, c2 *big.Int) (*big.Int, error) {
	if c1.Sign() <= 0 || c1.Cmp(pub.N2) >= 0 {
		return nil, errCiphertextInvalid
	}
	if c2.Sign() <= 0 || c2.Cmp(pub.N2) >= 0 {
		return nil, errCiphertextInvalid
	}

	// 同态加法：Enc(m1) * Enc(m2) = Enc(m1 + m2)
	// 计算 (c1 * c2) mod N^2
	return mod.ModMul(c1, c2, pub.N2), nil
}

// Mul 同态乘法：返回 Enc(k * m)
// 对密文与明文标量执行同态乘法运算，结果对应于明文的标量乘法
func (pub *PublicKey) Mul(c, k *big.Int) (*big.Int, error) {
	if c.Sign() <= 0 || c.Cmp(pub.N2) >= 0 {
		return nil, errCiphertextInvalid
	}

	// 同态乘法：Enc(m)^k = Enc(k * m)
	// 计算 k mod N
	kMod := mod.Mod(k, pub.N)
	// 计算 c^k mod N^2
	return mod.ModExp(c, kMod, pub.N2), nil
}

// -----------------------------------------------------------------------------
// 随机数恢复
// -----------------------------------------------------------------------------

// RecoverRandomness 恢复随机数 r，根据 c 和 m 满足 c = g^m * r^N mod N^2
func (priv *PrivateKey) RecoverRandomness(c, m *big.Int) (*big.Int, error) {
	// C' = C * (1 - mN) mod N^2
	N2 := priv.N2

	// 计算 (m * N) mod N^2
	mN := mod.ModMul(m, priv.N, N2)

	// 计算 (1 - mN) mod N^2
	oneMinus := mod.ModSub(bigOne, mN, N2)

	// 计算 (C * (1 - mN)) mod N^2
	cDash := mod.ModMul(c, oneMinus, N2)

	// 计算 N^{-1} mod phi(N)
	M, err := mod.ModInverse(priv.N, priv.PhiN)
	if err != nil {
		return nil, errors.New("paillier: N^{-1} mod phi(N) undefined")
	}

	// 计算 r = C'^M mod N
	r := mod.ModExp(cDash, M, priv.N)
	return r, nil
}

// -----------------------------------------------------------------------------
// 工具函数
// -----------------------------------------------------------------------------

// L 计算 L(u) = (u - 1) / N
func L(u, N *big.Int) *big.Int {
	t := new(big.Int).Sub(u, bigOne)
	return t.Div(t, N)
}

// randomRelativelyPrime 生成一个与 N 互质的随机数
func randomRelativelyPrime(random io.Reader, N *big.Int) (*big.Int, error) {
	for {
		r, err := rand.Int(random, N)
		if err != nil {
			return nil, err
		}
		if r.Sign() == 0 {
			continue
		}
		g := new(big.Int).GCD(nil, nil, r, N)
		if g.Cmp(bigOne) == 0 {
			return r, nil
		}
	}
}
