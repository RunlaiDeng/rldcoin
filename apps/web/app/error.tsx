"use client";

export default function ErrorPage({ reset }: { error: Error; reset: () => void }) {
  return (
    <main className="error-page">
      <p className="eyebrow">Rldcoin</p>
      <h1>界面暂时无法加载</h1>
      <p>钱包密钥仍保留在本机。请检查节点连接后重试。</p>
      <button className="button primary" onClick={reset}>
        重新加载
      </button>
    </main>
  );
}
