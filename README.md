# Enterprise Zero-Knowledge Threshold Secret Sharing System

本项目提供了一个生产就绪的企业级零知识阈值秘密共享系统，集成多项高级安全特性、性能优化算法和完善的审计机制，适用于大规模分布式密钥管理与秘密恢复场景。

## 主要功能

- **阈值秘密共享（Shamir Secret Sharing）**  
  通过多项式分割的方式，将秘密 $s$ 分成 $n$ 份，每份为 $(i,\,f(i))$，仅当至少 $t$ 份有效分享聚合时，方可重构原始秘密.

- **FFT 加速拉格朗日插值（Optimized Lagrange FFT）**  
  采用并行化 Karatsuba 与 FFT 技术，在大规模多项式乘法与插值时显著提升性能，并提供完备的错误类型和性能度量.

- **企业级 BLAKE3 哈希适配器**  
  基于 BLAKE3，提供 64 字节增强输出、跨平台 SIMD 加速和审计上下文扩展，兼顾高吞吐与安全性.

- **全生命周期密钥管理**  
  从密钥生成、激活、退役到销毁，严格遵循 NIST SP 800-57，并在每一阶段记录安全审计事件.

- **零知识证明与 VSS 校验**  
  使用 Fiat–Shamir 变换生成非交互式零知识证明，验证每份分享的正确性；并实现批量并行恢复功能.

- **多方计算（MPC）集成示例**  
  演示多方多项式协议生成全局秘密切片，并进行聚合随机数示例，展现实际应用能力.

- **合规与审计**  
  支持 FIPS 140-2 Level 3、Common Criteria EAL4+ 等模式，可导出完整性能指标与审计日志，满足企业合规需求。

## 代码的实际用途

- **企业密钥管理系统（KMS/HSM增强）**：防止单点泄露，提升企业密钥安全与合规性。

- **区块链/多签钱包**：多方安全托管私钥，防止单点失效和内部作恶。

- **分布式身份认证与访问控制**：实现分布式身份、权限分割与联合恢复。

- **高合规行业（金融、医疗、政府）**：满足严格的审计、合规和生命周期管理要求。

- **DevOps与云原生安全**：安全分发和管理云端、微服务等敏感配置和密钥。

- **灾备与应急响应**：分片分布于不同地点，防止灾难导致数据丢失或泄露。

## 代码的主要创新点与优势

- **信息论安全**：基于Shamir秘密共享，低于阈值分片无法泄露任何秘密。
- **零知识证明**：每个分片都可独立验证，防止恶意分片和内部攻击。
- **高性能插值**：FFT/Karatsuba等算法提升恢复效率，适合大规模并发场景。
- **企业级合规**：详细审计、全生命周期管理、支持多种合规模式。
- **模块化设计**：易于集成、扩展，支持不同业务和合规需求

## 架构及模块

```text
├─ src/
│  ├─ error.rs            // CryptoError、ErrorHandler 与审计日志
│  ├─ hash_adapter.rs     // Blake3Adapter 与 SecurityValidator
│  ├─ key_lifecycle.rs    // Key 生命周期管理
│  ├─ lagrange_fft.rs     // 优化多项式运算与插值
│  ├─ sharing.rs          // Shamir 分享、更新与阈值调整
│  ├─ mpc.rs              // MPC 协议模拟
│  ├─ proof.rs            // 零知识证明生成与验证
│  ├─ vss.rs              // Verifiable Secret Sharing 校验
│  ├─ serialization.rs    // Scalar & RistrettoPoint 序列化
│  ├─ utils.rs            // 随机数、常量与幂运算
│  └─ main.rs             // 企业演示与 CLI
```

</br>

## 数学正确性证明

下面给出你系统的**完整数学正确性证明**，结合所有关键方法（Shamir秘密共享、FFT加速插值、Pedersen承诺与非交互式零知识证明、MPC多方密钥生成）。

## 1. Shamir秘密共享的正确性证明

设素数域 $\mathbb{F}_q$，秘密为 $s \in \mathbb{F}_q$，阈值为 $t$，参与者数为 $n$。

构造随机多项式：
$
f(X) = a_0 + a_1 X + \cdots + a_{t-1} X^{t-1}, \quad a_0 = s, \quad a_i \overset{\$}{\leftarrow} \mathbb{F}_q, i \geq 1.
$

分片为：
$
(x_i, y_i) = (i, f(i)), \quad i=1,\ldots,n.
$

**拉格朗日插值重构秘密**：

$
\ell_i(X) = \prod_{\substack{1 \le j \le t \\ j \neq i}} \frac{X - x_j}{x_i - x_j}, \quad \ell_i(x_j) = \delta_{ij}.
$

插值多项式：

$
F(X) = \sum_{i=1}^t y_i \ell_i(X).
$

由于 $F(x_i) = y_i = f(x_i)$ 且 $\deg(F), \deg(f) < t$，唯一性定理保证：

$
F(X) \equiv f(X).
$

因此秘密：

$
s = f(0) = F(0) = \sum_{i=1}^t y_i \ell_i(0) = \sum_{i=1}^t y_i \prod_{j \neq i} \frac{-x_j}{x_i - x_j}.
$

## 2. FFT加速插值的正确性

定义：

$
Q(X) = \prod_{i=1}^t (X - x_i), \quad Q'(X) = \frac{d}{dX} Q(X).
$

拉格朗日基函数在0点的值为：

$
\ell_i(0) = \prod_{j \neq i} \frac{0 - x_j}{x_i - x_j} = \frac{Q(0)}{(0 - x_i) Q'(x_i)} = -\frac{Q(0)}{x_i Q'(x_i)}.
$

秘密重构公式等价于：

$
s = \sum_{i=1}^t y_i \ell_i(0) = -Q(0) \sum_{i=1}^t \frac{y_i}{x_i Q'(x_i)}.
$

FFT和Karatsuba算法用于高效计算多项式乘法和求导，多项式 $Q(X)$、$Q'(X)$ 的构造和多点评估均正确，保证插值结果与传统拉格朗日插值一致。

## 3. Pedersen承诺与非交互式Schnorr零知识证明的正确性

### 3.1 Pedersen承诺

给定椭圆曲线群 $\mathbb{G}$及基点 $G, H \in \mathbb{G}$，且攻击者未知 $h$ 使 $H = hG$。

分片值 $s \in \mathbb{F}_q$ 和随机数 $r \in \mathbb{F}_q$ 的承诺为：

$
C = s G + r H.
$

### 3.2 非交互式Schnorr证明

- Prover随机选取 $k_s, k_r \overset{\$}{\leftarrow} \mathbb{F}_q$，计算

$
R = k_s G + k_r H.
$

- 计算挑战值

$
c = H_{\mathrm{FS}}(G \| H \| C \| R \| \mathrm{index}),
$

其中 $H_{\mathrm{FS}}$ 是基于BLAKE3的哈希函数。

- 计算响应

$
z_s = k_s + c s, \quad z_r = k_r + c r.
$

- 验证方检查

$
z_s G + z_r H \stackrel{?}{=} R + c C.
$

### 3.3 证明正确

代入响应表达式左侧：

$
z_s G + z_r H = (k_s + c s) G + (k_r + c r) H = k_s G + k_r H + c (s G + r H) = R + c C.
$

已将 G、H、C、R、index 全部纳入挑战哈希，满足 **强 Fiat–Shamir** 要求，并且已消除弱 FS 的主要风险，核心的安全性降至 **离散对数假设**：只要对 G、H 的离散对数始终不可获知，你的 ZKP 就在随机预言机模型里信息完备、可靠且零知识。同时 **zk-thresh-pro** 满足验证条件，证明完备性。

## 4. MPC多方密钥生成的正确性

每方 $i$ 随机生成多项式

$
f_i(X) = a_{i,0} + a_{i,1} X + \cdots + a_{i,t-1} X^{t-1},
$

其中 $a_{i,0} \overset{\$}{\leftarrow} \mathbb{F}_q$。

全局秘密为

$
s = \sum_{i=1}^m a_{i,0}.
$

每个分片索引 $j$ 的分片为

$
y_j = \sum_{i=1}^m f_i(j).
$

由于多项式相加仍是多项式，总多项式为

$
F(X) = \sum_{i=1}^m f_i(X),
$

满足

$
F(0) = s, \quad F(j) = y_j.
$

因此，秘密共享的正确性与安全性继承自单方Shamir秘密共享。

## 5. 信息论安全性证明

当已知少于阈值 $t$ 个分片时，秘密 $s$ 对攻击者保持完美保密。

证明：对于任意可能秘密 $s' \in \mathbb{F}_q$，存在多项式系数 $a_1', \ldots, a_{t-1}'$ 使得多项式

$
f'(X) = s' + a_1' X + \cdots + a_{t-1}' X^{t-1}
$

与已知分片值一致。故分片对秘密的条件概率分布不变。

## 6. 系统正确性：

- **秘密共享正确性**由拉格朗日插值唯一性保证；
- **FFT加速插值**保持数学等价，提升性能不影响正确性；
- **Pedersen承诺与非交互式Schnorr证明**保证分片承诺的绑定性和零知识性，防止伪造和泄露；
- **MPC多方密钥生成**通过多项式叠加保证全局秘密正确生成；
- **信息论安全**可以保证少于阈值分片无法泄露秘密。

</br>

## 与市场主流竞品对比

| 对比内容           |    zk-thresh-pro                       | HashiCorp Vault SSS      | Fireblocks MPC-CMP      | ZenGo TSS (GG18/20)       |
|----------------|-----------------------------------|--------------------------|-------------------------|---------------------------|
| 安全性         | 信息论安全+ZKP+MPC                | 信息论安全               | MPC签名安全             | MPC签名安全               |
| 分片可验证性   | 每片ZKP验证，防止恶意分片         | 无                       | 无                      | 仅签名阶段ZKP             |
| 动态阈值/更新  | 支持                              | 不支持                   | 不支持                  | 不支持                    |
| 性能           | FFT/Karatsuba并行        | 传统Lagrange插值         | 签名优化                | 主要签名优化              |
| 审计与合规     | 全生命周期、详细审计日志           | 有限日志                 | 无                      | 无                        |              |
| 应用范围       | 通用秘密共享、KMS、DevOps等        | KMS为主                  | 数字资产签名            | 数字资产签名              |

## 快速开始

1. 克隆仓库并构建：  
   ```bash
   git clone https://github.com/CryptographyTeam/zk-thresh-pro.git
   cd zk-thresh-pro
   cargo build --release
   ```

2. 演示运行：  
   ```bash
   cargo run --release
   ```
   将依次执行安全验证、密钥生成、分享分发、秘密恢复等流程，并输出性能指标与审计日志。

3. 在业务代码中集成示例：
   ```rust
   use zk-thresh-pro::{EnterpriseCryptoSystem, EnterpriseConfig, KeyState};

   let config = EnterpriseConfig::default();
   let mut system = EnterpriseCryptoSystem::new(config);

   // 安全校验
   system.validate_security()?;

   // 生成并激活主密钥
   let key = system.generate_enterprise_key("master-key-001")?;
   assert_eq!(key.state, KeyState::Active);

   // 创建并恢复秘密
   let secret = key.secret;
   let shares = system.create_secret_shares(secret, 3, 5, "op-123")?;
   let recovered = system.recover_secret_enterprise(&shares[..3], "op-123")?;
   assert_eq!(recovered, secret);
   ```

## 合规与审计

- 支持多种合规模式：Standard、FIPS 140-2 L3、Common Criteria EAL4+、自定义  
- 可导出完整 `PerformanceMetrics` 与 `SecurityEvent` 列表，用于上报与审计  
- 敏感字段在 `Drop` 和 `ZeroizeOnDrop` 中清零，最大程度减少侧信道风险  

## 典型应用场景

- **企业密钥管理系统（KMS/HSM增强）**：用于密钥分发、生命周期管理、合规审计。
- **区块链和多签钱包**：多方安全托管，防止单点失效和内部作恶。
- **分布式身份认证**：支持DID、SSO等新型身份管理。
- **高合规行业（金融、医疗、政府）**：满足严格审计和合规要求。
