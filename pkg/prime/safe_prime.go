package prime

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"
)

// 论文参考：https://eprint.iacr.org/2003/186.pdf

// ================= 公共类型 & 配置 =================

type SafePrime struct {
	P *big.Int // 安全素数
	Q *big.Int // (P-1)/2
}

type Config struct {
	// 每个随机起点 q0，局部窗口最大偏移量（按 delta 计），实际候选数约 WindowDeltaMax/6
	WindowDeltaMax uint64

	// Miller-Rabin 轮数（对 q 和 p 都使用）
	MillerRabinRounds int

	// 是否对 q/p 做 Fermat(base=2) 预筛
	UseFermatQ bool
	UseFermatP bool

	// 组合筛时是否额外剔除 q ≡ 1 (mod r)，提高 (q-1)/2 为素数的概率
	FilterForSophie bool
}

func DefaultConfig() *Config {
	return &Config{
		WindowDeltaMax:    1024,
		MillerRabinRounds: 32,
		UseFermatQ:        false,
		UseFermatP:        true,
		FilterForSophie:   true,
	}
}

// ================= 内部常量 =================

var (
	bigOne   = big.NewInt(1)
	bigTwo   = big.NewInt(2)
	bigThree = big.NewInt(3)
	bigFour  = big.NewInt(4)
)

// ================= 小素数分组（Wiener 组合筛） =================
//
// primesGroups[i] 是一组小素数，primeProductsBig[i] 是它们的乘积。

var primesGroups = [][]uint64{
	{5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53},
	{59, 61, 67, 71, 73, 79, 83, 89, 97},
	{101, 103, 107, 109, 113, 127, 131, 137, 139},
	{149, 151, 157, 163, 167, 173, 179, 181},
	{191, 193, 197, 199, 211, 223, 227, 229},
	{233, 239, 241, 251, 257, 263, 269},
	{271, 277, 281, 283, 293, 307, 311},
	{317, 331, 337, 347, 349, 353, 359},
	{367, 373, 379, 383, 389, 397, 401},
	{409, 419, 421, 431, 433, 439, 443},
	{449, 457, 461, 463, 467, 479, 487},
	{491, 499, 503, 509, 521, 523, 541},
	{557, 563, 569, 571, 577, 587},
	{593, 599, 601, 607, 613, 617},
	{619, 631, 641, 643, 647, 653},
	{659, 661, 673, 677, 683, 691},
	{701, 709, 719, 727, 733, 739},
	{743, 751, 757, 761, 769, 773},
	{787, 797, 809, 811, 821, 823},
	{827, 829, 839, 853, 857, 859},
	{863, 877, 881, 883, 887, 907},
	{911, 919, 929, 937, 941, 947},
	{953, 967, 971, 977, 983, 991},
}

var primeProductsBig = []*big.Int{
	new(big.Int).SetUint64(5431526412865007455),
	new(big.Int).SetUint64(6437928885641249269),
	new(big.Int).SetUint64(4343678784233766587),
	new(big.Int).SetUint64(538945254996352681),
	new(big.Int).SetUint64(3534749459194562711),
	new(big.Int).SetUint64(61247129307885343),
	new(big.Int).SetUint64(166996819598798201),
	new(big.Int).SetUint64(542676746453092519),
	new(big.Int).SetUint64(1230544604996048471),
	new(big.Int).SetUint64(2618501576975440661),
	new(big.Int).SetUint64(4771180125133726009),
	new(big.Int).SetUint64(9247077179230889629),
	new(big.Int).SetUint64(34508483876655991),
	new(big.Int).SetUint64(49010633640532829),
	new(big.Int).SetUint64(68015277240951437),
	new(big.Int).SetUint64(93667592535644987),
	new(big.Int).SetUint64(140726526226538479),
	new(big.Int).SetUint64(191079950785756457),
	new(big.Int).SetUint64(278064420037666463),
	new(big.Int).SetUint64(361197734649700343),
	new(big.Int).SetUint64(473672212426732757),
	new(big.Int).SetUint64(649424689916978839),
	new(big.Int).SetUint64(851648411420003101),
}

// uint64 形式的乘积，方便做 (baseRem+delta) % product。
var primeProductsUint64 = func() []uint64 {
	out := make([]uint64, len(primeProductsBig))
	for i, b := range primeProductsBig {
		out[i] = b.Uint64()
	}
	return out
}()

// 对 p 做一个非常便宜的小素数筛，用的表可以很小（例如前几十个）。
var smallPrimesForP = []*big.Int{
	big.NewInt(3), big.NewInt(5), big.NewInt(7), big.NewInt(11),
	big.NewInt(13), big.NewInt(17), big.NewInt(19), big.NewInt(23),
	big.NewInt(29), big.NewInt(31), big.NewInt(37), big.NewInt(41),
	big.NewInt(43), big.NewInt(47), big.NewInt(53),
}

// ================= 核心生成：面向调用者的入口 =================

// GenerateSafePrime 同步生成一个 bits 位的安全素数。
// p = 2q + 1，p,q 都是素数。
func GenerateSafePrime(bits int, cfg *Config, r io.Reader) (*SafePrime, error) {
	if bits < 3 {
		return nil, errors.New("bits too small")
	}
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if r == nil {
		r = rand.Reader
	}

	gen := &generator{cfg: cfg, rand: r}
	return gen.generate(bits)
}

// ================= 内部：generator 结构 & pipeline =================

type generator struct {
	cfg  *Config
	rand io.Reader
}

type candidate struct {
	q *big.Int
	p *big.Int
}

// generate 是最外层流程：随机 q0 → 窗口扫描 → 对每个候选跑 filter pipeline。
func (g *generator) generate(bits int) (*SafePrime, error) {
	qBits := bits - 1
	byteLen := (qBits + 7) / 8
	highBits := uint(qBits % 8)
	if highBits == 0 {
		highBits = 8
	}

	buf := make([]byte, byteLen)

	for {
		// 1. 生成 q0（bit 长度约 qBits，最高两位为 1，奇数）。
		q0, err := g.randomQ0(buf, qBits, highBits)
		if err != nil {
			return nil, err
		}

		// 2. 规范化到 q0 ≡ 2 (mod 3)（避免被 3 整除），保持奇性。
		normalizeMod3(q0)

		// 3. 预计算每个乘积下的余数 baseRemainders[i] = q0 mod product_i。
		baseRemainders := precomputeBaseRemainders(q0)

		// 4. 构造 filter pipeline（对每个候选 (q,p) 调用）。
		filters := g.buildFilters(bits)

		// 5. 在局部窗口里按 delta += 6 扫描候选。
		//    - q0 已经是奇数且 ≡ 2 (mod 3)
		//    - delta 按 6 递增 ⇒ q 始终是奇数且 ≡ 2 (mod 3)
		for delta := uint64(0); delta < g.cfg.WindowDeltaMax; delta += 6 {
			// 5.1 组合筛只依赖 q0/baseRemainders/delta，在构造 candidate 前先过滤掉大部分垃圾。
			if !passesCombinedSieve(baseRemainders, delta, g.cfg.FilterForSophie) {
				continue
			}

			// 5.2 构造当前候选 (q,p)。
			candidate := buildCandidate(q0, delta)

			// 5.3 依次执行所有 filter，只要有一个不过就换下一个 delta。
			if !runFilters(&candidate, filters) {
				continue
			}

			// 5.4 所有 filter 全通过，即成功。
			return &SafePrime{P: candidate.p, Q: candidate.q}, nil
		}

		// 这一轮 q0 的窗口没找到，回到 for 外层重新随机 q0。
	}
}

// ================= step 1：生成初始 q0 =================

func (g *generator) randomQ0(buf []byte, qBits int, highBits uint) (*big.Int, error) {
	if _, err := io.ReadFull(g.rand, buf); err != nil {
		return nil, err
	}

	// 限制最高 bit 不超过 qBits。
	mask := uint8((1 << highBits) - 1)
	buf[0] &= mask

	// 转换为 big.Int，使用 SetBit 方法更清晰地设置位
	q := new(big.Int).SetBytes(buf)

	// 设置最低位为 1，确保 q 是奇数
	q.SetBit(q, 0, 1)

	// 设置第 2 位（索引 1）为 1，鼓励 q 在 ≡ 3 (mod 4) 这一类起步
	//（后续 normalizeMod3 不依赖这个，只是让初始分布略微“厚一点”）
	if qBits > 1 {
		q.SetBit(q, 1, 1)
	}

	// 设置最高位为 1，确保位数正确，避免数太小
	q.SetBit(q, qBits-1, 1)

	// 如果位数 >= 2，也设置次高位为 1，进一步避免数太小
	if qBits >= 2 {
		q.SetBit(q, qBits-2, 1)
	}

	return q, nil
}

// ================= step 2：规范化 mod 3 =================

// 把 q 调整到 q ≡ 2 (mod 3)，这样后面 delta+=6 的候选都不会被 3 整除。
func normalizeMod3(q *big.Int) {
	mod3 := new(big.Int).Mod(q, bigThree).Int64()
	switch mod3 {
	case 1:
		q.Add(q, bigFour) // 1 -> 2
	case 0:
		q.Add(q, bigTwo) // 0 -> 2
	}
}

// ================= step 3：预计算 q0 在乘积下的余数 =================

func precomputeBaseRemainders(q0 *big.Int) []uint64 {
	remainders := make([]uint64, len(primeProductsBig))
	remainder := new(big.Int)
	for i, product := range primeProductsBig {
		remainder.Mod(q0, product)
		remainders[i] = remainder.Uint64()
	}
	return remainders
}

// ================= step 4：构建 filter pipeline =================

type filter func(*candidate) bool

func (g *generator) buildFilters(bits int) []filter {
	var filters []filter

	// 1) p bit 长度必须正确。
	filters = append(filters, bitLenFilter(bits))

	// 2) p 不能被小素数整除（简单筛，过滤明显合数）。
	filters = append(filters, smallPrimeFilterForP())

	// 3) 可选：Fermat base=2 预筛 q/p。
	if g.cfg.UseFermatQ {
		filters = append(filters, fermatFilterQ())
	}
	if g.cfg.UseFermatP {
		filters = append(filters, fermatFilterP())
	}

	// 4) 最终：对 q/p 做 Miller-Rabin。
	filters = append(filters, mrFilterQ(g.cfg.MillerRabinRounds))
	filters = append(filters, mrFilterP(g.cfg.MillerRabinRounds))

	return filters
}

// 按顺序执行 filters，有一个不过就返回 false。
func runFilters(c *candidate, filters []filter) bool {
	for _, f := range filters {
		if !f(c) {
			return false
		}
	}
	return true
}

// ================= step 5：构造 (q,p) 候选 =================

func buildCandidate(q0 *big.Int, delta uint64) candidate {
	deltaBig := new(big.Int).SetUint64(delta)

	// q = q0 + delta
	q := new(big.Int).Add(q0, deltaBig)

	// p = 2q + 1
	p := new(big.Int).Lsh(q, 1)
	p.Add(p, bigOne)

	return candidate{q: q, p: p}
}

// ================= 组合筛（只依赖 q 的 residue） =================

// passesCombinedSieve：Wiener + Naccache 风格组合筛。
// baseRemainders[i] = q0 mod product_i
// q = q0 + delta => q mod product_i = (baseRemainders[i] + delta) % product_i
//
// 对每个小素数 r：
//   - 剔除 q ≡ 0        (mod r)   -> q 被 r 整除
//   - 剔除 q ≡ (r-1)/2  (mod r)   -> 2q+1 被 r 整除
//
// 如 FilterForSophie=true：
//   - 剔除 q ≡ 1        (mod r)   -> (q-1)/2 被 r 整除
//
// 调用侧保证：
//   - q0 是奇数且 ≡ 2 (mod 3)
//   - delta 按 6 递增 ⇒ 所有 q 都是奇数且 ≡ 2 (mod 3)
func passesCombinedSieve(baseRemainders []uint64, delta uint64, filterForSophie bool) bool {
	for i, baseRemainder := range baseRemainders {
		product := primeProductsUint64[i]
		qModProduct := (baseRemainder + delta) % product

		for _, prime := range primesGroups[i] {
			residue := qModProduct % prime
			if residue == 0 {
				return false
			}
			if residue == (prime-1)/2 {
				return false
			}
			if filterForSophie && residue == 1 {
				return false
			}
		}
	}
	return true
}

// ================= 各种 filter 的具体实现 =================

// 1) p 的 bit 长度必须是 bits。
func bitLenFilter(bits int) filter {
	return func(c *candidate) bool {
		return c.p.BitLen() == bits
	}
}

// 2) 对 p 用一小批小素数做试除，过滤明显合数。
func smallPrimeFilterForP() filter {
	return func(c *candidate) bool {
		remainder := new(big.Int)
		for _, smallPrime := range smallPrimesForP {
			// 如果 p <= smallPrime，就没必要再试了。
			if c.p.Cmp(smallPrime) <= 0 {
				return true
			}
			remainder.Mod(c.p, smallPrime)
			if remainder.Sign() == 0 {
				return false
			}
		}
		return true
	}
}

// 3) Fermat base=2 对 q 的预筛。
func fermatFilterQ() filter {
	return func(c *candidate) bool {
		return fermatBase2(c.q)
	}
}

// 4) Fermat base=2 对 p 的预筛。
func fermatFilterP() filter {
	return func(c *candidate) bool {
		return fermatBase2(c.p)
	}
}

// 5) 对 q 做 Miller-Rabin。
func mrFilterQ(rounds int) filter {
	return func(c *candidate) bool {
		return c.q.ProbablyPrime(rounds)
	}
}

// 6) 对 p 做 Miller-Rabin。
func mrFilterP(rounds int) filter {
	return func(c *candidate) bool {
		return c.p.ProbablyPrime(rounds)
	}
}

// ================= Fermat base=2 预筛 =================

// fermatBase2：2^(n-1) ≡ 1 (mod n) ?
// 不通过 => 一定合数；通过 => 可能是素数，仅作预筛。
func fermatBase2(n *big.Int) bool {
	if n.Cmp(bigTwo) < 0 {
		return false
	}
	if n.Cmp(bigTwo) == 0 || n.Cmp(big.NewInt(3)) == 0 {
		return true
	}
	if n.Bit(0) == 0 { // 偶数
		return false
	}

	exponent := new(big.Int).Sub(n, bigOne)         // n-1
	result := new(big.Int).Exp(bigTwo, exponent, n) // 2^(n-1) mod n
	return result.Cmp(bigOne) == 0
}
