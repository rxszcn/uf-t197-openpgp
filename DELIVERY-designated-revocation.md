# 指定吊销者（Designated Revoker）第三方密钥吊销

## 1. 背景与问题

密钥托管服务需要一个"保险丝"：持钥人丢失主键后，由事先授权的**吊销者密钥**（designated revoker）回收身份。
OpenPGP 协议里对应的机制是 RFC 4880 5.2.3.15 的 **Revocation Key** 子包（类型 12）：密钥在自签名中声明
"某把公钥有权吊销我"，此后该公钥签发的吊销签名（0x20 主键吊销 / 0x28 子密钥吊销）即被视为有效。

本库此前对这种情况做了**双重拒绝**：

- `src/packet/signature.js` 的 `SignaturePacket#verify()` 只要发现签名带 Revocation Key 子包就抛错
  （"This key is intended to be revoked with an authorized key, which OpenPGP.js does not support."）；
- `src/key/helper.js` 的 `isDataRevoked()` 把所有第三方吊销签名静默忽略，只认 issuer 与目标签名 issuer 相同的吊销。

后果是：吊销者签名被静默丢弃，**被吊销的密钥仍被判为有效，并继续被用于加密**（`getEncryptionKey()` →
`verifyPrimaryKey()` 检测不到吊销）。

## 2. 实现内容

### 2.1 声明路径（密钥所有者一侧）

- `PrivateKey#addRevoker(revoker, date?, config?)`：生成一条 **Direct Key 自签名（0x1F）**，其中带上
  Revocation Key 子包（class `0x80`、吊销者公钥算法、20 字节 v4 指纹）。返回带该声明的密钥副本，原对象不变。
  - `revoker` 可传公钥对象（`PublicKey` / `Subkey` / 公钥包），也可传十六进制指纹。传指纹时，
    吊销者公钥必须已放进 `config.designatedRevokers`，因为子包需要写入其公钥算法。
  - 仅支持 v4 密钥：子包格式规定是 20 字节 v4 指纹，RFC 9580 也已将该机制对 v6 标记为废弃。
    对 v6 密钥或 v6 吊销者会显式报错，避免生成别家无法解释的声明。
- `Key#getDesignatedRevokers(config?)`：读回该密钥声明的吊销者列表（指纹、算法、class），
  供应用侧核对"我的保险丝是否已就位"。

### 2.2 判定路径（接收被吊销密钥一侧）

- `helper.getDesignatedRevocationKeys(key, config)`：从 **Direct Key 自签名**中收集有效声明。
  - 只接受 issuer 为密钥自身、`0x80` 位已置、且**签名本身密码学有效**的声明。
  - 收集时**不检查声明的过期时间**：声明过期不应让已授权的吊销者失效（否则保险丝会自己熔断）。
  - 按指纹去重，保留**最早**一条，用于下面的时间先后校验。
- `helper.getDesignatedRevokerKeyPacket(declaration, revocationSignature, config)`：判定某条第三方吊销签名是否被授权：
  - 声明的 `0x80` 位必须已置；
  - **声明时间不得晚于吊销签名时间**（吊销者无法被事后追认授权）；
  - 声明的算法须与吊销签名的公钥算法一致；
  - `config.designatedRevokers` 中须有指纹匹配的公钥，且其 Key ID 等于签名的 issuer。
  - 满足后**真正做一次签名验签**（不是只看 issuer），才判定为有效吊销。
- `helper.isDataRevoked()` 的改动：
  - 自身吊销路径保持原语义不变；
  - 第三方吊销仅在**目标签名属于主键自身**且签名类型为 `keyRevocation`(0x20)/`subkeyRevocation`(0x28)
    时才考虑指定吊销者。**未声明的第三方吊销继续被忽略**（防误伤），且指定吊销者**不能**吊销第三方对该密钥的
    认证签名（防止吊销者越权影响信任网络），也不能吊销用户 ID 认证。
- `Key#isRevoked` / `Subkey#isRevoked` / `User#isRevoked`，以及 `update()` 的签名合并回调，
  都会把声明列表传进判定。因此 `verifyPrimaryKey()`、`getEncryptionKey()`、`getSigningKey()`、
  `getPrimaryUser()` 等既有入口无需改动即会认同指定吊销——被吊销密钥会以 `Primary key is revoked`
  或 `Subkey is revoked` 拒绝加密。

### 2.3 吊销者一侧与证书交换

- `Key#getDesignatedRevocationCertificate(revokerPrivateKey, reason?, date?, config?)`：
  用吊销者私钥为被吊销密钥签发 0x20 吊销签名，产出 armored 吊销证书。
  - 会先校验该吊销者**确实**在该密钥的声明列表里，否则拒绝（避免私钥被拿去给无关密钥签吊销）。
  - 证书**内嵌被吊销密钥的公钥包**（secret key 会转成 public key packet）。这一点是必要的：
    GnuPG 的 `gpg --import` 依据证书里的被吊销密钥公钥包定位目标；若省略而只放签名（issuer 是吊销者），
    GnuPG 会报 `invalid revocation certificate: Bad signature - rejected`。已用 GnuPG 2.4.9 实测：
    带公钥包后导入成功，`gpg --list-keys` 显示 `[revoked: ...]` 与 `Revocable by: <吊销者指纹>`。
- `Key#applyRevocationCertificate()`：接受**自身签发**或**已声明吊销者签发**的吊销证书；
  后者通过 `isDataRevoked` 复核，未声明/未提供吊销者公钥时仍按原语义报
  `Revocation signature does not match key`。若证书内嵌的公钥包与当前密钥指纹不符，同样拒绝。
  - 自身吊销的错误路径保持原样（`Could not verify revocation signature` 等）。

## 3. 设计决定与理由

**吊销者公钥从哪里来：`config.designatedRevokers`（`PublicKey[]`），而不是库内自带的密钥服务器/信任库。**

- 判定吊销是安全关键路径。声明里只有指纹，库必须拿到**真实公钥**才能做签名验签；若由库自行联网抓取，
  既引入网络依赖与不可控输入，也把"信任哪份公钥"的决定权从应用手里拿走。
- 采用数组而非 `Map`：`Config` 的 `checkConfig()` 以 `defaultConfig` 的属性名做白名单校验，
  数组可以安全地作为默认值且不易被误改共享状态；指纹匹配在 `helper.getConfiguredRevokerKeyPacket()`
  内逐项比对，调用方无需关心索引键格式（hex 大小写、空格）。
- 声明时既接受密钥对象也接受 hex 指纹；指纹形式下必须同时配置公钥，是为了能确定要写入子包的公钥算法。

**吊销时效语义。**

- 声明**不因自签名过期而失效**（收集时不看 `signatureExpirationTime`）：保险丝的有效期应与密钥寿命一致。
- 但**声明必须早于吊销签名**：否则攻击者可先拿到吊销者的一次无关签名、或事后诱使授权，再倒填时间，
  违背"预授权"的前提。
- 吊销签名本身仍按既有 `isDataRevoked` 逻辑区分硬/软吊销：`keyRetired`/`keySuperseded`/`userIDInvalid`
  这类软吊销会在吊销日期之后"失效"，其余按无期限的硬吊销处理。

**未声明的第三方吊销一律忽略。** 这是对既有语义的严格保持：没有声明的密钥，行为与改动前完全一致
（包括 `key_with_authorized_revocation_key` 这类在 User ID 自签名里放 Revocation Key 子包的旧样本——
该位置按 RFC 4880 属"未规定"，`SignaturePacket#verify()` 继续拒绝，既有测试不变）。

**v6 不支持的取舍。** Revocation Key 子包写死为 20 字节 v4 指纹，且 RFC 9580 明确 "MUST NOT generate"。
与其生成互操作可疑的 v6 声明，不如显式报错并把边界写清楚。

## 4. 兼容性

- 未声明吊销者的密钥：`isDataRevoked` 走原分支，判定结果与改动前一致。
- `getRevocationCertificate()`、`revoke()`、`applyRevocationCertificate()` 的自身吊销路径与输出字节不变。
- 新增 `config.designatedRevokers`（默认 `[]`）——默认空数组意味着**默认关闭**第三方吊销接受，需显式配置才生效。
- `SignaturePacket#verify()` 只对 0x1F 放行 Revocation Key 子包；其余签名类型行为不变。

## 5. 测试

新增 `test/general/designated_revoker.js`（已注册进 `test/general/index.js`），对照覆盖两条路径：

**声明路径（接受）**
- 声明写入 Direct Key 自签名，`getDesignatedRevokers()` 可读回；
- 配置吊销者公钥后，吊销证书被接受，`verifyPrimaryKey()` / `getEncryptionKey()` 拒绝该密钥；
- 已吊销密钥的密钥块（走 wire 格式往返，模拟从密钥服务器取得）拒绝用于 `encrypt()`；
- 吊销者可吊销子密钥，吊销后的子密钥不再被选为加密密钥；
- `update()` 能合入指定吊销签名，且合入后密钥被判为已吊销；
- 证书内嵌被吊销密钥公钥包（与 GnuPG 互操作格式一致）。

**声明路径（拒绝/边界）**
- 未配置吊销者公钥时，同样的吊销签名被忽略，密钥仍有效；
- 未声明的第三方（即便其公钥被配置）吊销无效；
- 吊销者不能吊销第三方对该密钥的用户 ID 认证；
- 声明晚于吊销签名的，不追认授权；
- 吊销者不是该密钥声明的对象时，`getDesignatedRevocationCertificate()` 拒绝；
- 为别的密钥生成的证书不能套用；
- 加密私钥不能 `addRevoker`。

**未声明路径（防误伤，语义不变）**
- 即便配置了吊销者公钥，未声明密钥的第三方吊销仍被忽略，密钥可继续用于加密；
- `applyRevocationCertificate()` 对未声明的第三方证书报 `Revocation signature does not match key`；
- User ID 自签名里的 Revocation Key 子包仍按原样被拒绝（既有夹具回归）。

## 6. 验证结果

- `npx mocha test/unittests.js`：**1063 passing / 3 pending / 1 failing**。
  唯一失败是改动前就存在的基线问题：`Streaming › Node: Encrypt and decrypt text message roundtrip`
  在 Windows 上因 `test/general/openpgp.js` 的 CRLF/LF 差异断言失败。已在**未改动的基线快照**（`git stash`）
  上复现同一失败，确认与本次改动无关。
- `npm run test-type-definitions`：通过（新增了 `addRevoker` / `getDesignatedRevokers` /
  `getDesignatedRevocationCertificate` 的类型声明与用法检查）。
- `npx eslint`：改动文件 0 error。
- GnuPG 2.4.9 互操作实测：
  - GnuPG 用 `addrevoker` 生成的声明，本库能读出并接受其指定吊销证书；
  - 本库生成的指定吊销证书，GnuPG `--import` 成功并把目标密钥标记为 `revoked`。
