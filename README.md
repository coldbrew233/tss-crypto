# TSS Crypto

一个用 Go 语言实现的阈值签名密码学库

## 功能特性

- ✅ **Feldman VSS**: 基于 Shamir 秘密共享和椭圆曲线承诺的可验证秘密共享方案
- ✅ **模运算工具库**: 提供常用的模运算函数（模乘、模加、模减、模幂、模逆等）
- ✅ **椭圆曲线点运算**: 封装了椭圆曲线点的常用操作（标量乘法、点加法、点比较等）
- ✅ **安全素数生成**: 高效生成安全素数（Safe Prime），支持 Wiener 组合筛优化
- ✅ **Paillier 同态加密**: 支持加法同态和标量乘法同态运算
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
│   ├── prime/        # 安全素数生成
│   │   ├── safe_prime.go
│   │   └── safe_prime_test.go
│   ├── paillier/     # Paillier 同态加密
│   │   ├── paillier.go
│   │   └── paillier_test.go
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

### 安全素数生成

高效生成安全素数 `p = 2q + 1`（p 和 q 都是素数）：

1. **优化策略**：
   - Wiener 组合筛：使用小素数快速过滤候选
   - 窗口扫描：在局部范围内搜索，提高缓存效率
   - 模 3 规范化：确保候选不被 3 整除

2. **配置选项**：
   - 窗口大小、Miller-Rabin 轮数可配置
   - 支持 Fermat 预筛和 Sophie Germain 过滤

### Paillier 同态加密

基于 Paillier 公钥加密系统，支持同态运算：

1. **基本操作**：
   - 加密：`Enc(m, r) = g^m · r^N mod N²`
   - 解密：`Dec(c) = L(c^λ mod N²) · μ mod N`

2. **同态性质**：
   - 加法同态：`Enc(m₁) · Enc(m₂) = Enc(m₁ + m₂)`
   - 标量乘法：`Enc(m)^k = Enc(k · m)`

3. **优化特性**：
   - 使用 `g = N + 1` 简化加密计算
   - 预计算 `μ = λ⁻¹ mod N` 加速解密
   - 支持普通素数和安全素数密钥生成

## 安全注意事项

- ⚠️ 本库仅用于学习和研究目的
- ⚠️ 在生产环境使用前，请进行充分的安全审计
- ⚠️ 确保使用密码学安全的随机数生成器
- ⚠️ 妥善保管秘密和份额，避免泄露

## 测试

运行所有测试：

```bash
go test ./pkg/... -v
```

运行性能测试：

```bash
go test ./pkg/... -bench=. -benchmem
```

## 参考

- [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing)
- [Feldman VSS](https://www.cs.umd.edu/~gasarch/TOPICS/secretsharing/feldmanVSS.pdf)
- [Paillier Cryptosystem](https://en.wikipedia.org/wiki/Paillier_cryptosystem)
- [Safe Prime](https://en.wikipedia.org/wiki/Safe_prime)
- [Elliptic Curve Cryptography](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography)
