# RLD-ISSUANCE-RESERVE-ERA-V1

Immutable issuance component for the frozen whitepaper section 6. This is a
component rule identity, not a complete protocol profile or a network adoption.
A successor changing these bytes has a different component hash and requires
explicit authenticated adoption with fresh implementation/genesis qualification.
No historical reserve, balances, keys or fixture authority migrate automatically.

The fixed cap C is 100000000000000000000000000000000000 runlai (10^35).
One RLD is 10^24 runlai. Genesis height 0 issues zero. Only the adopted origin
issues; every other region has zero native issuance. A selected origin height
is an unsigned checked integer, never elapsed time or a peer's status.

For h >= 1, L = 200000, j = (h-1) / L and k = (h-1) % L. R_0 = C.
At each era start B_j = floor(R_j / 2) if R_j >= 2, otherwise B_j = R_j.
Set q_j = B_j / L and m_j = B_j % L. Slot k issues q_j + 1 if k < m_j,
otherwise q_j. R_(j+1) = R_j - B_j. All operations use checked integers.
In an incomplete era, t selected blocks issue q_j*t + min(t,m_j).
The last one-runlai reserve is issued at slot 0 exactly once; subsequent rewards
are zero. Discarded unfinalized branches retain no issuance. Normal native
parent replay, state conservation, ownership and finality checks remain required.

Normative vectors: R=0 has budget/rewards 0; R=1,2,3 each has budget 1,
slot 0 reward 1 and all later slot rewards 0, with next reserves 0,1,2.
R=400003 has budget 200001, slot 0 reward 2 and each later reward 1.
R=C has budget 5*10^34 and each slot reward 250000*10^24.
Height 200001 has reward 125000*10^24. Each complete era issues exactly its
budget; cumulative issuance is monotonic, starts at zero and never exceeds C.

The component identity is SHA-256 of UTF-8 `RLD-ISSUANCE-RESERVE-ERA-V1`, a
single zero byte, then the complete exact bytes of this file. The direct Earth
value adoption includes this identity, its complete value-rule hash and exact
implementation source commitment under its separate signed admission domain.
Missing/old component bindings refuse; neither this hash nor an issuance vector
authorizes blocks, custody, initial allocation or a production network.
