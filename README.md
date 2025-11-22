# TSS Crypto

一个用 Go 语言实现的阈值签名密码学库

## 功能特性

- ✅ **Feldman VSS**: 基于 Shamir 秘密共享和椭圆曲线承诺的可验证秘密共享方案
- ✅ **模运算工具库**: 提供常用的模运算函数（模乘、模加、模减、模幂、模逆等）
- ✅ **椭圆曲线点运算**: 封装了椭圆曲线点的常用操作（标量乘法、点加法、点比较等）
- 🔜 **Paillier 加密**: 计划支持（开发中）
- 🔜 **零知识证明**: 计划支持（开发中）

## 项目结构

```
tss-crypto/
├── pkg/
│   ├── vss/          # 可验证秘密共享
│   │   ├── feldman.go
│   │   └── feldman_test.go
│   ├── mod/          # 模运算工具库
│   │   └── mod.go
│   ├── ec/           # 椭圆曲线点运算
│   │   └── point.go
│   ├── paillier/     # Paillier 加密（计划中）
│   └── zk/           # 零知识证明（计划中）
├── go.mod
└── README.md
```

## 算法说明

### Feldman VSS

Feldman VSS 是 Shamir 秘密共享的扩展，增加了可验证性：

1. **秘密拆分**：
   - 生成一个 `t-1` 次多项式 `f(x) = a₀ + a₁x + ... + aₜ₋₁xᵗ⁻¹`，其中 `a₀ = secret`
   - 为每个参与方计算份额 `sᵢ = f(xᵢ)`
   - 计算承诺 `Cⱼ = aⱼ * G`（椭圆曲线点）

2. **份额验证**：
   - 验证 `G^sᵢ = C₀ + C₁·xᵢ + C₂·xᵢ² + ... + Cₜ₋₁·xᵢᵗ⁻¹`

3. **秘密恢复**：
   - 使用拉格朗日插值从至少 `t` 个份额恢复秘密

## 安全注意事项

- ⚠️ 本库仅用于学习和研究目的
- ⚠️ 在生产环境使用前，请进行充分的安全审计
- ⚠️ 确保使用密码学安全的随机数生成器
- ⚠️ 妥善保管秘密和份额，避免泄露

## 参考

- [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing)
- [Feldman VSS](https://www.cs.umd.edu/~gasarch/TOPICS/secretsharing/feldmanVSS.pdf)
- [Elliptic Curve Cryptography](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography)

