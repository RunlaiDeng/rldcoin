"use client";

import Image from "next/image";
import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";

const RUNLAI_PER_RLD = 10n ** 24n;
const API = process.env.NEXT_PUBLIC_RLD_API ?? "http://127.0.0.1:7845";
const LEGACY_WALLET_STORAGE_KEY = "rldcoin-test-wallet-v1";
const ENCRYPTED_WALLET_STORAGE_KEY = "rldcoin-test-wallet-v2";
const WALLET_KDF_ITERATIONS = 310_000;
const MIN_WALLET_PASSWORD_LENGTH = 12;

type Language = "zh" | "en";

type Wallet = {
  publicKey: string;
  privateKeyPkcs8: string;
};

type EncryptedWallet = {
  version: 2;
  publicKey: string;
  kdf: {
    name: "PBKDF2";
    hash: "SHA-256";
    iterations: number;
    salt: string;
  };
  cipher: {
    name: "AES-GCM";
    iv: string;
    ciphertext: string;
  };
};

type Coin = {
  object_id: string;
  amount: string;
  state: string;
  version: number;
  lineage_root: string;
};

type Status = {
  descriptor: {
    zone_id: string;
    display_name: string;
    currency_genesis_root: string;
    protocol_era: number;
    crypto_era: number;
    testnet: boolean;
    validator_keys: string[];
    notary_keys: string[];
  };
  height: number;
  supply: {
    buckets: {
      reserve: string;
      spendable: string;
      in_transit: string;
      quarantined: string;
    };
    valid: boolean;
    merkle_sum_root: string;
  };
  causal_firewall: {
    accepted: number;
    pending: number;
    quarantined: number;
  };
  discovered_zones: number;
};

type FeeMarket = {
  local_payment: {
    schedule: { pricing_epoch: number };
    recommended_max_fee: string;
  };
};

type Payment = {
  intent: { payment_id: string; recipient: string; amount: string };
  status: string;
  updated_height: number;
  charged_fee?: string;
};

type PaymentRequest = {
  request_id: string;
  recipient: string;
  recipient_public_key: string;
  destination_zone: string;
  currency_genesis_root: string;
  protocol_era: number;
  crypto_era: number;
  amount: string;
  memo: string;
  expires_at_height: number;
  nonce: number;
  signature: string;
};

type Checkpoint = {
  zone_id: string;
  height: number;
  state_root: string;
  protocol_era: number;
  crypto_era: number;
  previous_checkpoint: string | null;
  checkpoint_hash: string;
  supply: {
    valid: boolean;
    merkle_sum_root: string;
    conservation_position: string;
    anchor_supply: string;
  };
};

const copy = {
  zh: {
    mission: "面向人类未来的全宇宙点对点快速支付系统",
    subtitle: "私钥只在本机 · 固定1000亿RLD · 节点服务获得RLD",
    connect: "节点连接",
    connected: "已连接",
    disconnected: "未连接",
    wallet: "我的测试钱包",
    createWallet: "创建加密钱包",
    unlockWallet: "解锁钱包",
    migrateWallet: "加密并迁移旧钱包",
    walletPassword: "钱包密码",
    confirmPassword: "确认钱包密码",
    legacyWallet: "检测到旧版明文测试私钥。设置密码后才能继续，迁移成功后明文副本会被删除。",
    passwordHint: "至少12个字符。密码不会发送到节点，也无法由Rldcoin恢复。",
    passwordMismatch: "两次输入的密码不一致。",
    passwordTooShort: "钱包密码至少需要12个字符。",
    unlockFailed: "密码错误或加密钱包已损坏。",
    lockWallet: "锁定",
    walletLocked: "钱包已锁定，私钥已从当前会话移除。",
    address: "RLD收款地址",
    copy: "复制",
    copied: "已复制",
    balance: "可用余额",
    earn: "完成观察服务，领取100测试RLD",
    earned: "服务奖励已到账",
    send: "点对点支付",
    recipient: "收款地址",
    amount: "数量（RLD）",
    coin: "选择币对象",
    pay: "本机签名并发送",
    feeCap: "网络费上限",
    feeCharged: "实际网络费",
    signedRequest: "已签名收款请求（可选）",
    requestHint: "粘贴收款人发来的 JSON，可锁定地址、金额、Zone 和一次性请求编号",
    requestLoaded: "一次性请求已载入",
    clearRequest: "清除请求",
    requestTitle: "创建一次性收款请求",
    requestMemo: "用途 / 备注",
    requestExpiry: "有效区块数",
    createRequest: "本机签名并登记",
    requestReady: "收款请求已登记，可复制给付款人",
    requestJson: "签名请求 JSON",
    download: "下载",
    settlementStates: "支付确定性状态",
    explorer: "连续性与证明浏览器",
    checkpoint: "连续性检查点",
    stateRoot: "状态根",
    causal: "因果防火墙",
    signers: "双QC签名集合",
    simulatedSafety: "当前测试Zone未配置签名集合，跨Zone QC使用模拟接口，禁止承载真实资产。",
    cryptographicSafety: "当前测试Zone已配置验证者与公证人集合；跨Zone导出必须取得真实双QC。",
    latest: "最近支付",
    noPayments: "还没有支付记录",
    network: "Zone网络",
    reserve: "服务储备",
    transit: "在途RLD",
    proof: "供应证明",
    valid: "守恒有效",
    invalid: "检查失败",
    localKey: "私钥使用PBKDF2和AES-256-GCM加密后保存在此浏览器，不会发送给节点。",
    refreshing: "同步中",
    refresh: "刷新",
  },
  en: {
    mission: "Peer-to-peer fast payment for humanity across the future universe",
    subtitle: "Local keys · Fixed 100B RLD · Nodes earn for verified service",
    connect: "Node connection",
    connected: "Connected",
    disconnected: "Disconnected",
    wallet: "My test wallet",
    createWallet: "Create encrypted wallet",
    unlockWallet: "Unlock wallet",
    migrateWallet: "Encrypt and migrate wallet",
    walletPassword: "Wallet password",
    confirmPassword: "Confirm wallet password",
    legacyWallet: "A legacy plaintext test key was found. Set a password to continue; the plaintext copy is deleted after migration succeeds.",
    passwordHint: "Use at least 12 characters. The password never reaches the node and cannot be recovered by Rldcoin.",
    passwordMismatch: "The two passwords do not match.",
    passwordTooShort: "The wallet password must contain at least 12 characters.",
    unlockFailed: "The password is incorrect or the encrypted wallet is damaged.",
    lockWallet: "Lock",
    walletLocked: "Wallet locked and private key removed from this session.",
    address: "RLD receiving address",
    copy: "Copy",
    copied: "Copied",
    balance: "Spendable balance",
    earn: "Perform observer service and earn 100 test RLD",
    earned: "Service reward received",
    send: "Peer payment",
    recipient: "Recipient address",
    amount: "Amount (RLD)",
    coin: "Coin object",
    pay: "Sign locally and send",
    feeCap: "Maximum network fee",
    feeCharged: "Network fee charged",
    signedRequest: "Signed payment request (optional)",
    requestHint: "Paste the recipient's JSON to bind the address, amount, Zone and one-time request ID",
    requestLoaded: "One-time request loaded",
    clearRequest: "Clear request",
    requestTitle: "Create a one-time payment request",
    requestMemo: "Purpose / memo",
    requestExpiry: "Valid block count",
    createRequest: "Sign locally and register",
    requestReady: "Payment request registered; share it with the payer",
    requestJson: "Signed request JSON",
    download: "Download",
    settlementStates: "Payment certainty states",
    explorer: "Continuity and proof explorer",
    checkpoint: "Continuity checkpoint",
    stateRoot: "State root",
    causal: "Causality firewall",
    signers: "Dual-QC signer sets",
    simulatedSafety: "This test Zone has no signer sets. Cross-Zone QCs are simulated and must not carry real assets.",
    cryptographicSafety: "This test Zone has validator and notary sets. Cross-Zone exports require cryptographic dual QCs.",
    latest: "Recent payments",
    noPayments: "No payments yet",
    network: "Zone network",
    reserve: "Service reserve",
    transit: "RLD in transit",
    proof: "Supply proof",
    valid: "Conserved",
    invalid: "Check failed",
    localKey: "The private key is stored in this browser under PBKDF2 and AES-256-GCM encryption and is never sent to the node.",
    refreshing: "Syncing",
    refresh: "Refresh",
  },
};

export function WalletDashboard() {
  const [language, setLanguage] = useState<Language>("zh");
  const [wallet, setWallet] = useState<Wallet | null>(null);
  const [encryptedWallet, setEncryptedWallet] = useState<EncryptedWallet | null>(null);
  const [legacyWalletAvailable, setLegacyWalletAvailable] = useState(false);
  const [walletPassword, setWalletPassword] = useState("");
  const [walletPasswordConfirmation, setWalletPasswordConfirmation] = useState("");
  const [status, setStatus] = useState<Status | null>(null);
  const [feeMarket, setFeeMarket] = useState<FeeMarket | null>(null);
  const [coins, setCoins] = useState<Coin[]>([]);
  const [payments, setPayments] = useState<Payment[]>([]);
  const [checkpoint, setCheckpoint] = useState<Checkpoint | null>(null);
  const [recipient, setRecipient] = useState("");
  const [amount, setAmount] = useState("1");
  const [coinId, setCoinId] = useState("");
  const [requestAmount, setRequestAmount] = useState("1");
  const [requestMemo, setRequestMemo] = useState("");
  const [requestExpiry, setRequestExpiry] = useState("10000");
  const [createdRequest, setCreatedRequest] = useState<PaymentRequest | null>(null);
  const [paymentRequestJson, setPaymentRequestJson] = useState("");
  const [boundRequest, setBoundRequest] = useState<PaymentRequest | null>(null);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [online, setOnline] = useState(false);
  const t = copy[language];

  useEffect(() => {
    const saved = window.localStorage.getItem(ENCRYPTED_WALLET_STORAGE_KEY);
    if (saved) {
      try {
        const parsed = JSON.parse(saved) as EncryptedWallet;
        if (!isEncryptedWallet(parsed)) throw new Error("invalid encrypted wallet");
        setEncryptedWallet(parsed);
      } catch {
        setMessage("Stored encrypted wallet is invalid; restore it from a trusted backup.");
      }
    }
    setLegacyWalletAvailable(Boolean(window.localStorage.getItem(LEGACY_WALLET_STORAGE_KEY)));
  }, []);

  const address = useMemo(() => {
    if (!wallet || !status) return "";
    return `rld:${status.descriptor.zone_id}:${wallet.publicKey}`;
  }, [wallet, status]);

  const refresh = useCallback(async () => {
    try {
      const [network, fees, paymentData, latestCheckpoint] = await Promise.all([
        fetchJson<Status>(`${API}/v1/status`),
        fetchJson<FeeMarket>(`${API}/v1/fees`),
        fetchJson<{ payments: Payment[] }>(`${API}/v1/payments`),
        fetchOptional<Checkpoint>(`${API}/v1/checkpoints/latest`),
      ]);
      setStatus(network);
      setFeeMarket(fees);
      setCheckpoint(latestCheckpoint);
      setOnline(true);
      setPayments(paymentData.payments.slice().reverse().slice(0, 6));
      if (wallet) {
        const owner = `rld:${network.descriptor.zone_id}:${wallet.publicKey}`;
        const coinData = await fetchJson<{ coins: Coin[] }>(
          `${API}/v1/coins?owner=${encodeURIComponent(owner)}`,
        );
        const spendable = coinData.coins.filter((coin) => coin.state === "SPENDABLE");
        setCoins(spendable);
        setCoinId((current) =>
          spendable.some((coin) => coin.object_id === current)
            ? current
            : (spendable[0]?.object_id ?? ""),
        );
      }
    } catch (error) {
      setOnline(false);
      setMessage(errorMessage(error));
    }
  }, [wallet]);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(), 8000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  async function handleWalletAccess(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setMessage("");
    try {
      if (encryptedWallet) {
        const unlocked = await decryptWallet(encryptedWallet, walletPassword);
        const legacyWallet = readLegacyWallet();
        if (legacyWallet?.publicKey === unlocked.publicKey) {
          window.localStorage.removeItem(LEGACY_WALLET_STORAGE_KEY);
          setLegacyWalletAvailable(false);
        }
        setWallet(unlocked);
        setWalletPassword("");
        setMessage(t.localKey);
        return;
      }
      if (walletPassword.length < MIN_WALLET_PASSWORD_LENGTH) {
        throw new Error(t.passwordTooShort);
      }
      if (walletPassword !== walletPasswordConfirmation) {
        throw new Error(t.passwordMismatch);
      }

      const legacyWallet = readLegacyWallet();
      if (legacyWalletAvailable && !legacyWallet) {
        throw new Error("Legacy wallet data is invalid; refusing to delete it.");
      }
      let created = legacyWallet;
      if (!created) {
        const keys = await crypto.subtle.generateKey(
          { name: "Ed25519" },
          true,
          ["sign", "verify"],
        );
        created = {
          publicKey: bytesToHex(
            new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey)),
          ),
          privateKeyPkcs8: bytesToBase64(
            new Uint8Array(await crypto.subtle.exportKey("pkcs8", keys.privateKey)),
          ),
        };
      }
      await verifyWalletKeyPair(created);
      const protectedWallet = await encryptWallet(created, walletPassword);
      window.localStorage.setItem(ENCRYPTED_WALLET_STORAGE_KEY, JSON.stringify(protectedWallet));
      window.localStorage.removeItem(LEGACY_WALLET_STORAGE_KEY);
      setEncryptedWallet(protectedWallet);
      setLegacyWalletAvailable(false);
      setWallet(created);
      setWalletPassword("");
      setWalletPasswordConfirmation("");
      setMessage(t.localKey);
    } catch (error) {
      setMessage(encryptedWallet ? t.unlockFailed : errorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  function lockWallet() {
    setWallet(null);
    setCoins([]);
    setCoinId("");
    setWalletPassword("");
    setWalletPasswordConfirmation("");
    setMessage(t.walletLocked);
  }

  async function earnTestnetReward() {
    if (!wallet || !address) return;
    setBusy(true);
    setMessage("");
    try {
      await postJson(`${API}/v1/testnet/bootstrap-reward`, {
        node_id: `observer-${wallet.publicKey.slice(0, 12)}`,
        owner: address,
        role: "OBSERVER",
        proof_hash: `web-observer-${crypto.randomUUID()}`,
        amount: (100n * RUNLAI_PER_RLD).toString(),
      });
      setMessage(t.earned);
      await refresh();
    } catch (error) {
      setMessage(errorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  async function sendPayment(event: FormEvent) {
    event.preventDefault();
    if (!wallet || !status || !feeMarket || !coinId) return;
    setBusy(true);
    setMessage("");
    try {
      const paymentId = `payment-${crypto.randomUUID()}`;
      const amountRunlai = boundRequest ? BigInt(boundRequest.amount) : parseRld(amount);
      const intent = {
        payment_id: paymentId,
        source_zone: status.descriptor.zone_id,
        destination_zone: boundRequest?.destination_zone ?? status.descriptor.zone_id,
        currency_genesis_root: status.descriptor.currency_genesis_root,
        protocol_era: status.descriptor.protocol_era,
        crypto_era: status.descriptor.crypto_era,
        pricing_epoch: feeMarket.local_payment.schedule.pricing_epoch,
        sender_public_key: wallet.publicKey,
        recipient: boundRequest?.recipient ?? recipient.trim(),
        coin_id: coinId,
        amount: amountRunlai.toString(),
        max_fee: feeMarket.local_payment.recommended_max_fee,
        nonce: 1,
        ...(boundRequest
          ? { payment_request_id: boundRequest.request_id, payment_request: boundRequest }
          : {}),
        signature: "",
      };
      if (intent.destination_zone !== status.descriptor.zone_id) {
        throw new Error("This screen supports same-Zone requests; use export for a cross-Zone request");
      }
      const privateKey = await crypto.subtle.importKey(
        "pkcs8",
        base64ToBytes(wallet.privateKeyPkcs8),
        { name: "Ed25519" },
        false,
        ["sign"],
      );
      const signature = await crypto.subtle.sign(
        { name: "Ed25519" },
        privateKey,
        await paymentSigningBytes(intent),
      );
      intent.signature = bytesToHex(new Uint8Array(signature));
      const payment = await postJson<Payment>(`${API}/v1/payments/local`, intent);
      setMessage(
        `${paymentId} · UNIVERSALLY_SETTLED · ${t.feeCharged} ${formatRldExact(payment.charged_fee ?? "0")} RLD`,
      );
      setRecipient("");
      setPaymentRequestJson("");
      setBoundRequest(null);
      await refresh();
    } catch (error) {
      setMessage(errorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  async function createPaymentRequest(event: FormEvent) {
    event.preventDefault();
    if (!wallet || !status || !address) return;
    setBusy(true);
    setMessage("");
    try {
      const request: PaymentRequest = {
        request_id: `request-${crypto.randomUUID()}`,
        recipient: address,
        recipient_public_key: wallet.publicKey,
        destination_zone: status.descriptor.zone_id,
        currency_genesis_root: status.descriptor.currency_genesis_root,
        protocol_era: status.descriptor.protocol_era,
        crypto_era: status.descriptor.crypto_era,
        amount: parseRld(requestAmount).toString(),
        memo: requestMemo.trim(),
        expires_at_height: status.height + parsePositiveInteger(requestExpiry),
        nonce: Date.now(),
        signature: "",
      };
      const privateKey = await crypto.subtle.importKey(
        "pkcs8",
        base64ToBytes(wallet.privateKeyPkcs8),
        { name: "Ed25519" },
        false,
        ["sign"],
      );
      const signature = await crypto.subtle.sign(
        { name: "Ed25519" },
        privateKey,
        paymentRequestSigningBytes(request),
      );
      request.signature = bytesToHex(new Uint8Array(signature));
      const registered = await postJson<PaymentRequest>(`${API}/v1/payment-requests`, request);
      setCreatedRequest(registered);
      setMessage(t.requestReady);
    } catch (error) {
      setMessage(errorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  async function loadPaymentRequest(value: string) {
    setPaymentRequestJson(value);
    if (!value.trim()) {
      setBoundRequest(null);
      return;
    }
    try {
      const request = JSON.parse(value) as PaymentRequest;
      if (
        !request.request_id ||
        !request.recipient ||
        !request.amount ||
        !request.signature ||
        !request.currency_genesis_root ||
        !request.protocol_era ||
        !request.crypto_era
      ) {
        throw new Error("incomplete request");
      }
      if (!status) throw new Error("node status unavailable");
      if (
        request.destination_zone !== status.descriptor.zone_id ||
        request.currency_genesis_root !== status.descriptor.currency_genesis_root ||
        request.protocol_era !== status.descriptor.protocol_era ||
        request.crypto_era !== status.descriptor.crypto_era
      ) {
        throw new Error("payment request belongs to another network or era");
      }
      if (request.expires_at_height <= status.height) {
        throw new Error("payment request has expired");
      }
      if (request.recipient !== `rld:${request.destination_zone}:${request.recipient_public_key}`) {
        throw new Error("payment request recipient does not match its signer");
      }
      const publicKey = await crypto.subtle.importKey(
        "raw",
        bytesToArrayBuffer(hexToBytes(request.recipient_public_key)),
        { name: "Ed25519" },
        false,
        ["verify"],
      );
      const signatureValid = await crypto.subtle.verify(
        { name: "Ed25519" },
        publicKey,
        bytesToArrayBuffer(hexToBytes(request.signature)),
        paymentRequestSigningBytes(request),
      );
      if (!signatureValid) throw new Error("payment request signature is invalid");
      setBoundRequest(request);
      setRecipient(request.recipient);
      setAmount(formatRldExact(request.amount));
      setMessage(t.requestLoaded);
    } catch (error) {
      setBoundRequest(null);
      setMessage(errorMessage(error));
    }
  }

  const balance = coins.reduce((sum, coin) => sum + BigInt(coin.amount), 0n);

  return (
    <main>
      <header className="topbar">
        <a className="brand" href="#top" aria-label="Rldcoin home">
          <Image className="brand-mark" src="/brand/rldcoin-coin-logo.png" alt="Rldcoin" width={38} height={38} priority />
          <span>Rldcoin</span>
        </a>
        <nav>
          <span className={`connection ${online ? "online" : ""}`}>
            <i /> {online ? t.connected : t.disconnected}
          </span>
          <button className="language" onClick={() => setLanguage(language === "zh" ? "en" : "zh")}>
            {language === "zh" ? "EN" : "中文"}
          </button>
        </nav>
      </header>

      <section className="hero" id="top">
        <div className="orbital orbital-one" />
        <div className="orbital orbital-two" />
        <p className="eyebrow">RLD · RELAY · LEDGER · DISTANCE</p>
        <h1>{t.mission}</h1>
        <p className="hero-copy">{t.subtitle}</p>
        <div className="unit-chip">
          <span>1 RLD</span>
          <b>=</b>
          <span>10²⁴ runlai</span>
        </div>
      </section>

      <aside className="testnet-notice">
        <span>TESTNET</span>
        <p>{status && status.descriptor.validator_keys.length > 0 && status.descriptor.notary_keys.length > 0 ? t.cryptographicSafety : t.simulatedSafety}</p>
      </aside>

      <section className="metrics" aria-label={t.network}>
        <Metric label="Zone" value={status?.descriptor.display_name ?? "—"} detail={short(status?.descriptor.zone_id)} />
        <Metric label="Height" value={status?.height.toLocaleString() ?? "—"} detail={`Era ${status?.descriptor.protocol_era ?? 1}.${status?.descriptor.crypto_era ?? 1}`} />
        <Metric label={t.reserve} value={formatRld(status?.supply.buckets.reserve ?? "0")} detail="RLD" />
        <Metric label={t.transit} value={formatRld(status?.supply.buckets.in_transit ?? "0")} detail="RLD" />
        <Metric
          label={t.proof}
          value={status?.supply.valid ? t.valid : t.invalid}
          detail={short(status?.supply.merkle_sum_root)}
          positive={Boolean(status?.supply.valid)}
        />
      </section>

      <section className="workspace">
        <article className="panel wallet-panel">
          <div className="panel-heading">
            <div>
              <p className="section-number">01 · WALLET</p>
              <h2>{t.wallet}</h2>
            </div>
            <div className="panel-actions">
              {wallet ? (
                <button className="button quiet" onClick={lockWallet} disabled={busy}>
                  {t.lockWallet}
                </button>
              ) : null}
              <button className="button quiet" onClick={() => void refresh()} disabled={busy}>
                {busy ? t.refreshing : t.refresh}
              </button>
            </div>
          </div>

          {!wallet ? (
            <div className="empty-wallet">
              <div className="key-glyph">⌁</div>
              <p>{legacyWalletAvailable && !encryptedWallet ? t.legacyWallet : t.localKey}</p>
              <form className="wallet-access" onSubmit={handleWalletAccess}>
                <label>
                  <span className="field-label">{t.walletPassword}</span>
                  <input
                    type="password"
                    value={walletPassword}
                    onChange={(event) => setWalletPassword(event.target.value)}
                    autoComplete={encryptedWallet ? "current-password" : "new-password"}
                    minLength={encryptedWallet ? undefined : MIN_WALLET_PASSWORD_LENGTH}
                    required
                  />
                </label>
                {!encryptedWallet ? (
                  <label>
                    <span className="field-label">{t.confirmPassword}</span>
                    <input
                      type="password"
                      value={walletPasswordConfirmation}
                      onChange={(event) => setWalletPasswordConfirmation(event.target.value)}
                      autoComplete="new-password"
                      minLength={MIN_WALLET_PASSWORD_LENGTH}
                      required
                    />
                  </label>
                ) : null}
                <small>{t.passwordHint}</small>
                <button className="button primary" disabled={busy}>
                  {encryptedWallet
                    ? t.unlockWallet
                    : legacyWalletAvailable
                      ? t.migrateWallet
                      : t.createWallet}
                </button>
              </form>
            </div>
          ) : (
            <>
              <label className="field-label">{t.address}</label>
              <div className="address-box">
                <code>{address}</code>
                <button
                  className="copy-button"
                  onClick={async () => {
                    await navigator.clipboard.writeText(address);
                    setMessage(t.copied);
                  }}
                >
                  {t.copy}
                </button>
              </div>
              <div className="balance-block">
                <span>{t.balance}</span>
                <strong>{formatRld(balance.toString())}</strong>
                <small>RLD</small>
              </div>
              <button className="button reward" onClick={() => void earnTestnetReward()} disabled={busy || !online}>
                <span>＋</span> {t.earn}
              </button>
            </>
          )}
        </article>

        <article className="panel payment-panel">
          <div className="panel-heading">
            <div>
              <p className="section-number">02 · PEER PAYMENT</p>
              <h2>{t.send}</h2>
            </div>
            <span className="route-badge">LOCAL · ≤3s</span>
          </div>
          <form onSubmit={sendPayment}>
            <label>
              <span className="field-label">{t.signedRequest}</span>
              <textarea
                className="request-input"
                value={paymentRequestJson}
                onChange={(event) => loadPaymentRequest(event.target.value)}
                placeholder={t.requestHint}
                rows={3}
              />
            </label>
            {boundRequest ? (
              <div className="bound-request">
                <span>✓ {t.requestLoaded} · {short(boundRequest.request_id)}</span>
                <button type="button" onClick={() => loadPaymentRequest("")}>{t.clearRequest}</button>
              </div>
            ) : null}
            <label>
              <span className="field-label">{t.recipient}</span>
              <input
                value={recipient}
                onChange={(event) => setRecipient(event.target.value)}
                placeholder={status ? `rld:${status.descriptor.zone_id}:…` : "rld:zone:…"}
                readOnly={Boolean(boundRequest)}
                required
              />
            </label>
            <div className="field-grid">
              <label>
                <span className="field-label">{t.amount}</span>
                <input value={amount} onChange={(event) => setAmount(event.target.value)} inputMode="decimal" readOnly={Boolean(boundRequest)} required />
              </label>
              <label>
                <span className="field-label">{t.coin}</span>
                <select value={coinId} onChange={(event) => setCoinId(event.target.value)} required>
                  <option value="">—</option>
                  {coins.map((coin) => (
                    <option value={coin.object_id} key={coin.object_id}>
                      {formatRld(coin.amount)} RLD · {short(coin.object_id)}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            <div className="fee-summary">
              <span>{t.feeCap}</span>
              <strong>{formatRldExact(feeMarket?.local_payment.recommended_max_fee ?? "0")} RLD</strong>
            </div>
            <button className="button primary wide" disabled={busy || !wallet || !online || !feeMarket || !coinId}>
              {t.pay} <span>→</span>
            </button>
          </form>
          {message ? <p className="message" role="status">{message}</p> : null}
        </article>
      </section>

      <section className="panel request-panel">
        <div className="panel-heading">
          <div>
            <p className="section-number">03 · PAYMENT REQUEST</p>
            <h2>{t.requestTitle}</h2>
          </div>
          <span className="route-badge">SIGNED · ONE-TIME</span>
        </div>
        <div className="request-layout">
          <form onSubmit={createPaymentRequest}>
            <div className="field-grid request-fields">
              <label>
                <span className="field-label">{t.amount}</span>
                <input value={requestAmount} onChange={(event) => setRequestAmount(event.target.value)} inputMode="decimal" required />
              </label>
              <label>
                <span className="field-label">{t.requestExpiry}</span>
                <input value={requestExpiry} onChange={(event) => setRequestExpiry(event.target.value)} inputMode="numeric" required />
              </label>
            </div>
            <label>
              <span className="field-label">{t.requestMemo}</span>
              <input value={requestMemo} onChange={(event) => setRequestMemo(event.target.value)} maxLength={512} placeholder="Order / invoice / purpose" />
            </label>
            <button className="button primary wide" disabled={busy || !wallet || !online}>
              {t.createRequest} <span>→</span>
            </button>
          </form>
          <div className="request-output">
            <span className="field-label">{t.requestJson}</span>
            {createdRequest ? (
              <>
                <code>{JSON.stringify(createdRequest, null, 2)}</code>
                <div className="output-actions">
                  <button className="button quiet" onClick={() => void copyText(JSON.stringify(createdRequest, null, 2), () => setMessage(t.copied))}>{t.copy}</button>
                  <button className="button quiet" onClick={() => downloadJson(createdRequest, `${createdRequest.request_id}.json`)}>{t.download}</button>
                </div>
              </>
            ) : <p>{t.requestHint}</p>}
          </div>
        </div>
      </section>

      <section className="panel ledger-panel">
        <div className="panel-heading">
          <div>
            <p className="section-number">04 · SETTLEMENT</p>
            <h2>{t.latest}</h2>
          </div>
          <span className="mono-hash">{short(status?.supply.merkle_sum_root)}</span>
        </div>
        {payments.length === 0 ? (
          <p className="empty-list">{t.noPayments}</p>
        ) : (
          <div className="payment-list">
            {payments.map((payment) => (
              <div className="payment-row" key={payment.intent.payment_id}>
                <span className="payment-icon">↗</span>
                <div>
                  <strong>{formatRld(payment.intent.amount)} RLD</strong>
                  <small>{short(payment.intent.recipient)}</small>
                </div>
                <div className="timeline" aria-label={t.settlementStates}>
                  {paymentStages.map((stage, index) => (
                    <span className={index <= paymentStageIndex(payment.status) ? "done" : ""} key={stage}>
                      <i />
                      <small>{stage}</small>
                    </span>
                  ))}
                </div>
                <span className="status-pill">{payment.status.replaceAll("_", " ")}</span>
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="panel explorer-panel">
        <div className="panel-heading">
          <div>
            <p className="section-number">05 · PROOF EXPLORER</p>
            <h2>{t.explorer}</h2>
          </div>
          <span className={`status-pill ${checkpoint?.supply.valid ? "" : "warning"}`}>{checkpoint?.supply.valid ? t.valid : "—"}</span>
        </div>
        <div className="proof-grid">
          <ProofFact label={t.checkpoint} value={checkpoint ? `#${checkpoint.height.toLocaleString()}` : "—"} detail={short(checkpoint?.checkpoint_hash)} />
          <ProofFact label={t.stateRoot} value={short(checkpoint?.state_root)} detail={short(checkpoint?.supply.merkle_sum_root)} />
          <ProofFact label={t.causal} value={`${status?.causal_firewall.accepted ?? 0} accepted`} detail={`${status?.causal_firewall.pending ?? 0} pending · ${status?.causal_firewall.quarantined ?? 0} quarantined`} />
          <ProofFact label={t.signers} value={`${status?.descriptor.validator_keys.length ?? 0}V · ${status?.descriptor.notary_keys.length ?? 0}N`} detail={`${status?.discovered_zones ?? 0} Zones · Protocol ${checkpoint?.protocol_era ?? 1} · Crypto ${checkpoint?.crypto_era ?? 1}`} />
        </div>
      </section>

      <footer>
        <span>Rldcoin v0.2 · Public Testnet Reference</span>
        <span>Fixed supply · Service mined · Causality safe</span>
      </footer>
    </main>
  );
}

const paymentStages = ["SOURCE_FINAL", "IN_TRANSIT", "LOCAL_SPENDABLE", "UNIVERSALLY_SETTLED"];

function paymentStageIndex(status: string) {
  const index = paymentStages.indexOf(status);
  if (index >= 0) return index;
  if (["RETURNING", "RETURNED", "ROUTE_EXHAUSTED", "QUARANTINED"].includes(status)) return 1;
  return -1;
}

function Metric({ label, value, detail, positive = false }: { label: string; value: string; detail?: string; positive?: boolean }) {
  return (
    <article className="metric-card">
      <span>{label}</span>
      <strong className={positive ? "positive" : ""}>{value}</strong>
      <small>{detail}</small>
    </article>
  );
}

function ProofFact({ label, value, detail }: { label: string; value: string; detail: string }) {
  return <article className="proof-fact"><span>{label}</span><strong>{value}</strong><code>{detail}</code></article>;
}

async function fetchJson<T>(url: string): Promise<T> {
  const response = await fetch(url, { cache: "no-store" });
  const body = await response.json();
  if (!response.ok) throw new Error(body.error ?? `HTTP ${response.status}`);
  return body as T;
}

async function fetchOptional<T>(url: string): Promise<T | null> {
  const response = await fetch(url, { cache: "no-store" });
  if (response.status === 404) return null;
  const body = await response.json();
  if (!response.ok) throw new Error(body.error ?? `HTTP ${response.status}`);
  return body as T;
}

async function postJson<T = unknown>(url: string, value: unknown): Promise<T> {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(value),
  });
  const body = await response.json();
  if (!response.ok) throw new Error(body.error ?? `HTTP ${response.status}`);
  return body as T;
}

async function paymentSigningBytes(intent: {
  payment_id: string;
  source_zone: string;
  destination_zone: string;
  currency_genesis_root: string;
  protocol_era: number;
  crypto_era: number;
  pricing_epoch: number;
  sender_public_key: string;
  recipient: string;
  coin_id: string;
  amount: string;
  max_fee: string;
  nonce: number;
  payment_request_id?: string;
  payment_request?: PaymentRequest;
  route_quote_id?: string;
}) {
  const bytes: number[] = [...new TextEncoder().encode("RLD-PAYMENT-V2")];
  for (const value of [
    intent.payment_id,
    intent.source_zone,
    intent.destination_zone,
    intent.currency_genesis_root,
  ]) {
    const encoded = new TextEncoder().encode(value);
    bytes.push((encoded.length >>> 24) & 255, (encoded.length >>> 16) & 255, (encoded.length >>> 8) & 255, encoded.length & 255);
    bytes.push(...encoded);
  }
  bytes.push(...bigIntBytes(BigInt(intent.protocol_era), 8));
  bytes.push(...bigIntBytes(BigInt(intent.crypto_era), 8));
  bytes.push(...bigIntBytes(BigInt(intent.pricing_epoch), 8));
  for (const value of [
    intent.sender_public_key,
    intent.recipient,
    intent.coin_id,
  ]) {
    const encoded = new TextEncoder().encode(value);
    bytes.push((encoded.length >>> 24) & 255, (encoded.length >>> 16) & 255, (encoded.length >>> 8) & 255, encoded.length & 255);
    bytes.push(...encoded);
  }
  bytes.push(...bigIntBytes(BigInt(intent.amount), 16));
  bytes.push(...bigIntBytes(BigInt(intent.max_fee), 16));
  bytes.push(...bigIntBytes(BigInt(intent.nonce), 8));
  if (intent.payment_request_id) {
    putString(bytes, "RLD-PAYMENT-REQUEST-BINDING-V1");
    putString(bytes, intent.payment_request_id);
    putString(bytes, intent.payment_request ? await paymentRequestCommitment(intent.payment_request) : "");
  }
  if (intent.route_quote_id) {
    putString(bytes, "RLD-ROUTE-QUOTE-BINDING-V1");
    putString(bytes, intent.route_quote_id);
  }
  return new Uint8Array(bytes);
}

function paymentRequestSigningBytes(request: PaymentRequest) {
  const bytes: number[] = [...new TextEncoder().encode("RLD-PAYMENT-REQUEST-V2")];
  putString(bytes, request.request_id);
  putString(bytes, request.recipient);
  putString(bytes, request.recipient_public_key);
  putString(bytes, request.destination_zone);
  putString(bytes, request.currency_genesis_root);
  bytes.push(...bigIntBytes(BigInt(request.protocol_era), 8));
  bytes.push(...bigIntBytes(BigInt(request.crypto_era), 8));
  bytes.push(...bigIntBytes(BigInt(request.amount), 16));
  putString(bytes, request.memo);
  bytes.push(...bigIntBytes(BigInt(request.expires_at_height), 8));
  bytes.push(...bigIntBytes(BigInt(request.nonce), 8));
  return new Uint8Array(bytes);
}

async function paymentRequestCommitment(request: PaymentRequest) {
  return sha256Parts([paymentRequestSigningBytes(request), new TextEncoder().encode(request.signature)]);
}

async function sha256Parts(parts: Uint8Array[]) {
  const bytes: number[] = [];
  for (const part of parts) {
    bytes.push(...bigIntBytes(BigInt(part.length), 8), ...part);
  }
  return bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array(bytes))));
}

function putString(bytes: number[], value: string) {
  const encoded = new TextEncoder().encode(value);
  bytes.push((encoded.length >>> 24) & 255, (encoded.length >>> 16) & 255, (encoded.length >>> 8) & 255, encoded.length & 255);
  bytes.push(...encoded);
}

function bigIntBytes(value: bigint, length: number) {
  const bytes = new Array<number>(length).fill(0);
  let remaining = value;
  for (let index = length - 1; index >= 0; index -= 1) {
    bytes[index] = Number(remaining & 255n);
    remaining >>= 8n;
  }
  if (remaining !== 0n) throw new Error("amount exceeds protocol integer size");
  return bytes;
}

function parseRld(value: string) {
  const match = value.trim().match(/^(\d+)(?:\.(\d{0,24}))?$/);
  if (!match) throw new Error("RLD amount must have at most 24 decimal places");
  const fraction = (match[2] ?? "").padEnd(24, "0");
  return BigInt(match[1]) * RUNLAI_PER_RLD + BigInt(fraction || "0");
}

function formatRld(runlai: string) {
  const value = BigInt(runlai || "0");
  const whole = value / RUNLAI_PER_RLD;
  const fraction = (value % RUNLAI_PER_RLD).toString().padStart(24, "0").slice(0, 4).replace(/0+$/, "");
  return `${whole.toLocaleString("en-US")}${fraction ? `.${fraction}` : ""}`;
}

function formatRldExact(runlai: string) {
  const value = BigInt(runlai);
  const whole = value / RUNLAI_PER_RLD;
  const fraction = (value % RUNLAI_PER_RLD).toString().padStart(24, "0").replace(/0+$/, "");
  return `${whole}${fraction ? `.${fraction}` : ""}`;
}

function parsePositiveInteger(value: string) {
  if (!/^\d+$/.test(value) || BigInt(value) === 0n || BigInt(value) > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error("expiry must be a positive safe integer");
  }
  return Number(value);
}

function bytesToHex(bytes: Uint8Array) {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
}

function bytesToBase64(bytes: Uint8Array) {
  let binary = "";
  bytes.forEach((value) => (binary += String.fromCharCode(value)));
  return window.btoa(binary);
}

function base64ToBytes(value: string) {
  return Uint8Array.from(window.atob(value), (character) => character.charCodeAt(0));
}

function isEncryptedWallet(value: unknown): value is EncryptedWallet {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<EncryptedWallet>;
  return (
    candidate.version === 2 &&
    typeof candidate.publicKey === "string" &&
    /^[0-9a-f]{64}$/.test(candidate.publicKey) &&
    candidate.kdf?.name === "PBKDF2" &&
    candidate.kdf.hash === "SHA-256" &&
    candidate.kdf.iterations === WALLET_KDF_ITERATIONS &&
    typeof candidate.kdf.salt === "string" &&
    candidate.cipher?.name === "AES-GCM" &&
    typeof candidate.cipher.iv === "string" &&
    typeof candidate.cipher.ciphertext === "string"
  );
}

function readLegacyWallet(): Wallet | null {
  const value = window.localStorage.getItem(LEGACY_WALLET_STORAGE_KEY);
  if (!value) return null;
  try {
    const wallet = JSON.parse(value) as Partial<Wallet>;
    if (
      typeof wallet.publicKey !== "string" ||
      !/^[0-9a-f]{64}$/.test(wallet.publicKey) ||
      typeof wallet.privateKeyPkcs8 !== "string" ||
      wallet.privateKeyPkcs8.length === 0
    ) {
      return null;
    }
    return wallet as Wallet;
  } catch {
    return null;
  }
}

async function deriveWalletKey(
  password: string,
  salt: ArrayBuffer,
  usages: KeyUsage[],
) {
  const material = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      iterations: WALLET_KDF_ITERATIONS,
      salt,
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    usages,
  );
}

function walletAdditionalData(publicKey: string) {
  return bytesToArrayBuffer(new TextEncoder().encode(`RLDCOIN-WALLET-V2:${publicKey}`));
}

async function encryptWallet(wallet: Wallet, password: string): Promise<EncryptedWallet> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveWalletKey(password, bytesToArrayBuffer(salt), ["encrypt"]);
  const plaintext = new TextEncoder().encode(JSON.stringify(wallet));
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: bytesToArrayBuffer(iv),
      additionalData: walletAdditionalData(wallet.publicKey),
      tagLength: 128,
    },
    key,
    bytesToArrayBuffer(plaintext),
  );
  return {
    version: 2,
    publicKey: wallet.publicKey,
    kdf: {
      name: "PBKDF2",
      hash: "SHA-256",
      iterations: WALLET_KDF_ITERATIONS,
      salt: bytesToBase64(salt),
    },
    cipher: {
      name: "AES-GCM",
      iv: bytesToBase64(iv),
      ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
    },
  };
}

async function decryptWallet(stored: EncryptedWallet, password: string): Promise<Wallet> {
  const key = await deriveWalletKey(
    password,
    bytesToArrayBuffer(base64ToBytes(stored.kdf.salt)),
    ["decrypt"],
  );
  const plaintext = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: bytesToArrayBuffer(base64ToBytes(stored.cipher.iv)),
      additionalData: walletAdditionalData(stored.publicKey),
      tagLength: 128,
    },
    key,
    bytesToArrayBuffer(base64ToBytes(stored.cipher.ciphertext)),
  );
  const wallet = JSON.parse(new TextDecoder().decode(plaintext)) as Wallet;
  if (wallet.publicKey !== stored.publicKey) throw new Error("wallet public key mismatch");
  await verifyWalletKeyPair(wallet);
  return wallet;
}

async function verifyWalletKeyPair(wallet: Wallet) {
  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    bytesToArrayBuffer(base64ToBytes(wallet.privateKeyPkcs8)),
    { name: "Ed25519" },
    false,
    ["sign"],
  );
  const publicKey = await crypto.subtle.importKey(
    "raw",
    bytesToArrayBuffer(hexToBytes(wallet.publicKey)),
    { name: "Ed25519" },
    false,
    ["verify"],
  );
  const challenge = new TextEncoder().encode("RLDCOIN-WALLET-KEY-CHECK-V2");
  const challengeBuffer = bytesToArrayBuffer(challenge);
  const signature = await crypto.subtle.sign({ name: "Ed25519" }, privateKey, challengeBuffer);
  const valid = await crypto.subtle.verify(
    { name: "Ed25519" },
    publicKey,
    signature,
    challengeBuffer,
  );
  if (!valid) throw new Error("wallet key pair does not match");
}

function hexToBytes(value: string) {
  if (!/^[0-9a-f]+$/.test(value) || value.length % 2 !== 0) {
    throw new Error("invalid hexadecimal key");
  }
  return Uint8Array.from(value.match(/.{2}/g) ?? [], (byte) => Number.parseInt(byte, 16));
}

function bytesToArrayBuffer(value: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(value.byteLength);
  copy.set(value);
  return copy.buffer;
}

function short(value?: string) {
  if (!value) return "—";
  return value.length > 24 ? `${value.slice(0, 12)}…${value.slice(-8)}` : value;
}

function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : String(error);
}

async function copyText(value: string, done: () => void) {
  await navigator.clipboard.writeText(value);
  done();
}

function downloadJson(value: unknown, filename: string) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: "application/json" }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}
