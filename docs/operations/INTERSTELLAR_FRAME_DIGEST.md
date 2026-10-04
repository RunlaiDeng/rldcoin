# Exact streamed frame commitments — ground candidate

The active state codec and complete-transit authentication witness calculate the
same SHA-256 and byte length as ordinary canonical JSON. For a frame string that
requires no JSON escaping, serialize every surrounding metadata field through
the ordinary canonical encoder and hash its exact prefix, frame bytes and suffix.
Unsafe strings/shapes take the original complete canonical path. This is byte
construction only; canonical Base64, frame/network, packet/route/hop signatures,
receipt binding and Native value checks remain mandatory.

The helper retains no cross-call object, decoded payload, signature result or
ledger. No supplied size/hash initializes state. Existing 512 exact immutable
transit witnesses and all validation domain/limit bindings remain unchanged.
Active shared-frame disk and signed wire bytes are identical, including Unicode,
control/DEL escaping, arbitrary metadata order and frame-like unrelated fields.
Cold decode recomputes every complete commitment, then normal transport validation
runs. An altered frame, hop, route or packet cannot hit an old authenticated
witness; storage digests never authorize signatures, custody, value or signing.

A stopped failed fixture's ordinary decode/validation was measured separately
from strict inspection's full archive reads. Its selected missing timeout packets
were durably queued upstream with a candidate route but no destination receipt.
Those observations locate retained carriage and quantify local CPU only; they do
not reconstruct past thread timing or uniquely establish the full fault cause.
Initial per-frame Base64 regex checking erased most serialization savings; the
revised helper checks JSON escape bytes only, leaving the existing Base64 checks
where they already belong. All original failed sources/reports remain preserved.

Native/Core are unchanged. Qualify the changed production Python code with a new
exact compiled default driver, fresh private no-value ordinary cycle, cold and
fault scopes. Preserve old failures without resuming or migrating their value or
custody. Never raise the 0.2-second acquisition, three-second socket, 600-second
campaign or existing admission/archive/history/wire bounds to obtain a pass.
The component candidate and measured savings do not qualify BFT liveness,
independent custody, power loss, physical stellar links or I1–I12 completion.

The [exact 384-file build and 475 complete process checks](evidence/regional-frame-stream-frozen-checks-20261004.json)
passed, along with three actual custody cases and a fresh four-node directed
unanimous offline-source native payment/cold sample. Native/Core exactly match
revision 47; its 181 Native/strict cases are reused, not rerun. The new default
driver embeds this frozen source. The fresh three-region BFT cycle and full fault
qualification remain separate and uncompleted. Published revision 50 preserves
that distinction; frozen guidance retains its original pre-check wording.

2026-10-04：该精确384文件运行时的新三地区joint ordinary完整价值返程实际736.749秒通过，严格停止cold65.780秒通过（12原生/12recipient/4单独caller保管组，784完整BFT消息、1824运输归档；全部私有字节与权限不变，300=300+0）。新的完整故障范围从这个成功源独立启动，仍未通过；有限同机循环不改变任何独立、物理、长历史或I1–I12资格。冻结源码继续保留其原文。
