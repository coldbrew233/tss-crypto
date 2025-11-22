package ec

import (
	"crypto/elliptic"
	"math/big"
)

// Point 表示椭圆曲线上的点
type Point struct {
	Curve elliptic.Curve
	X     *big.Int
	Y     *big.Int
}

// NewPoint 创建一个新的椭圆曲线点
func NewPoint(curve elliptic.Curve, x, y *big.Int) *Point {
	return &Point{
		Curve: curve,
		X:     new(big.Int).Set(x),
		Y:     new(big.Int).Set(y),
	}
}

// ScalarBaseMult 计算 k * G，其中 G 是基点，k 是标量
// 返回新点，不修改原点
func ScalarBaseMult(curve elliptic.Curve, k *big.Int) *Point {
	x, y := curve.ScalarBaseMult(k.Bytes())
	return &Point{
		Curve: curve,
		X:     x,
		Y:     y,
	}
}

// ScalarMult 计算 k * P，其中 P 是当前点，k 是标量
// 返回新点，不修改原点
func (p *Point) ScalarMult(k *big.Int) *Point {
	if p == nil || p.Curve == nil {
		return nil
	}
	x, y := p.Curve.ScalarMult(p.X, p.Y, k.Bytes())
	return &Point{
		Curve: p.Curve,
		X:     x,
		Y:     y,
	}
}

// Add 计算 P + Q，返回新点，不修改原点
func (p *Point) Add(q *Point) *Point {
	if p == nil || q == nil || p.Curve == nil || q.Curve == nil {
		return nil
	}
	// 检查是否在同一曲线上
	if p.Curve != q.Curve {
		return nil
	}
	x, y := p.Curve.Add(p.X, p.Y, q.X, q.Y)
	return &Point{
		Curve: p.Curve,
		X:     x,
		Y:     y,
	}
}

// Equal 检查两个点是否相等
func (p *Point) Equal(q *Point) bool {
	if p == nil || q == nil {
		return p == q
	}
	return p.X.Cmp(q.X) == 0 && p.Y.Cmp(q.Y) == 0
}

// IsOnCurve 检查点是否在曲线上
func (p *Point) IsOnCurve() bool {
	if p == nil || p.Curve == nil || p.X == nil || p.Y == nil {
		return false
	}
	return p.Curve.IsOnCurve(p.X, p.Y)
}

// IsInfinity 检查点是否为无穷远点（通常 X 和 Y 都为 nil）
func (p *Point) IsInfinity() bool {
	if p == nil {
		return true
	}
	return p.X == nil && p.Y == nil
}

// Copy 返回点的副本
func (p *Point) Copy() *Point {
	if p == nil {
		return nil
	}
	return &Point{
		Curve: p.Curve,
		X:     new(big.Int).Set(p.X),
		Y:     new(big.Int).Set(p.Y),
	}
}
