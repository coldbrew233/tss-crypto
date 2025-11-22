package mod

import "math/big"

// ModMul 计算 (a * b) mod m，返回新的大整数
func ModMul(a, b, m *big.Int) *big.Int {
	result := new(big.Int).Mul(a, b)
	result.Mod(result, m)
	return result
}

// ModAdd 计算 (a + b) mod m，返回新的大整数
func ModAdd(a, b, m *big.Int) *big.Int {
	result := new(big.Int).Add(a, b)
	result.Mod(result, m)
	return result
}

// ModSub 计算 (a - b) mod m，返回新的大整数（结果保证在 [0, m) 范围内）
func ModSub(a, b, m *big.Int) *big.Int {
	result := new(big.Int).Sub(a, b)
	result.Mod(result, m)
	return result
}

// ModExp 计算 (base^exp) mod m，返回新的大整数
func ModExp(base, exp, m *big.Int) *big.Int {
	return new(big.Int).Exp(base, exp, m)
}

// ModInverse 计算 a 在模 m 下的乘法逆元，如果逆元不存在则返回 nil 和错误
func ModInverse(a, m *big.Int) (*big.Int, error) {
	result := new(big.Int).ModInverse(a, m)
	if result == nil {
		return nil, &NoInverseError{A: a, M: m}
	}
	return result, nil
}

// Mod 计算 a mod m，返回新的大整数
func Mod(a, m *big.Int) *big.Int {
	return new(big.Int).Mod(a, m)
}

// NoInverseError 表示模逆元不存在的错误
type NoInverseError struct {
	A *big.Int
	M *big.Int
}

func (e *NoInverseError) Error() string {
	return "modular inverse does not exist"
}
