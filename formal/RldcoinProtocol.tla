-------------------------- MODULE RldcoinProtocol --------------------------
EXTENDS Integers, Naturals, FiniteSets, TLC

\* This is a bounded protocol model, not an implementation refinement proof.
\* FaultMode selects exactly one deliberately unsafe mutation for a negative run.
CONSTANT FaultMode

TotalSupply == 3
TransferAmount == 1
FeeAmount == 1

Locations == {"SOURCE", "TRANSIT", "DESTINATION", "RETURN_ESCROW"}
TransitNullifierStates == {"UNUSED", "IMPORTED", "REJECTED"}
FeeNullifierStates == {"UNUSED", "CLAIMED"}

Validators == {"v1", "v2", "v3", "v4"}
ByzantineValidators == {"v4"}
HonestValidators == Validators \ ByzantineValidators
Blocks == {"block-a", "block-b"}
Quorum == 3

ValueActors == {"PROTOCOL", "FRONTEND", "ADMIN", "LEGACY_CLIENT"}
DirectUpgradeActors == {"FRONTEND", "ADMIN", "LEGACY_CLIENT"}
ValuePaths == {"LOCAL", "CROSS_ZONE", "DSC"}
MaxSingleValue == 1
MaxLocalValue == 1
MaxCrossZoneValue == 1
MaxDscValue == 1
MaxLogicalHeight == 4
ChallengePeriod == 1
SafetyCaseExpiresAt == 4
MainnetSafetyCaseHash == "R5-SAFETY-CASE"
GovernanceGroups == {"VALIDATORS", "NOTARIES"}
UpgradeAuthorizationThreshold == 2

CryptoSuites == {"CLASSIC", "HYBRID"}

SafeFaultMode == FaultMode = "SAFE"
UnsafeTimeoutRefundEnabled == FaultMode = "TIMEOUT_REFUND"
UnsafeLateImportEnabled == FaultMode = "LATE_IMPORT_AFTER_REJECTION"
UnsafeDuplicateFeeClaimEnabled == FaultMode = "DUPLICATE_FEE_CLAIM"
UnsafeWeakQuorumEnabled == FaultMode = "WEAK_QUORUM"
UnsafeValueBypassEnabled == FaultMode = "VALUE_CAP_BYPASS"
UnsafeCryptoDowngradeEnabled == FaultMode = "CRYPTO_DOWNGRADE"
UnsafeUnauthorizedUpgradeEnabled == FaultMode = "UNAUTHORIZED_UPGRADE"
UnsafeEarlyUpgradeEnabled == FaultMode = "CHALLENGE_NOT_MET"
UnsafeExpiredSafetyCaseUpgradeEnabled == FaultMode = "EXPIRED_SAFETY_CASE"
UnsafeExpiredValueAcceptanceEnabled == FaultMode = "EXPIRED_VALUE_ACCEPTANCE"

ASSUME FaultMode \in {
    "SAFE",
    "TIMEOUT_REFUND",
    "LATE_IMPORT_AFTER_REJECTION",
    "DUPLICATE_FEE_CLAIM",
    "WEAK_QUORUM",
    "VALUE_CAP_BYPASS",
    "CRYPTO_DOWNGRADE",
    "UNAUTHORIZED_UPGRADE",
    "CHALLENGE_NOT_MET",
    "EXPIRED_SAFETY_CASE",
    "EXPIRED_VALUE_ACCEPTANCE"
}
ASSUME 3 * Cardinality(ByzantineValidators) < Cardinality(Validators)
ASSUME Quorum * 2 > Cardinality(Validators) + Cardinality(ByzantineValidators)

VARIABLES ledger, consensus, valueState, cryptoState

vars == <<ledger, consensus, valueState, cryptoState>>

LedgerType == [
    sourceBalance : 0..(2 * TotalSupply),
    transitBalance : 0..(2 * TotalSupply),
    destinationBalance : 0..(2 * TotalSupply),
    returnEscrowBalance : 0..(2 * TotalSupply),
    feeEscrowBalance : 0..(2 * TotalSupply),
    feePoolBalance : 0..(2 * TotalSupply),
    coinLocations : SUBSET Locations,
    capsuleExists : BOOLEAN,
    transitNullifier : TransitNullifierStates,
    feeNullifier : FeeNullifierStates,
    importReceipt : BOOLEAN,
    rejectionCertificate : BOOLEAN,
    refunded : BOOLEAN,
    timeoutExpired : BOOLEAN,
    feeClaims : 0..2
]

ConsensusType == [
    votes : [Blocks -> SUBSET Validators],
    finalized : SUBSET Blocks
]

ValueStateType == [
    cap : 0..3,
    highestActivatedCap : 0..3,
    exposure : [ValuePaths -> 0..1],
    logicalHeight : 0..MaxLogicalHeight,
    pending : BOOLEAN,
    pendingTarget : 0..3,
    pendingActivationHeight : 0..MaxLogicalHeight,
    pendingSafetyCaseHash : {"NONE", MainnetSafetyCaseHash},
    approvals : SUBSET GovernanceGroups,
    safetyCaseValid : BOOLEAN,
    riskHealthy : BOOLEAN,
    newValueFrozen : BOOLEAN,
    frozenExposure : [ValuePaths -> 0..1],
    blockedDirectUpgradeAttempt : BOOLEAN,
    valueBypassAccepted : BOOLEAN,
    unauthorizedUpgradeAccepted : BOOLEAN,
    earlyUpgradeAccepted : BOOLEAN,
    expiredSafetyCaseUpgradeAccepted : BOOLEAN,
    expiredValueAcceptanceAccepted : BOOLEAN
]

CryptoStateType == [
    era : 1..2,
    disabled : SUBSET CryptoSuites,
    lastAcceptedSuite : CryptoSuites \cup {"NONE"},
    downgradeAccepted : BOOLEAN
]

Init ==
    /\ ledger = [
        sourceBalance |-> TotalSupply,
        transitBalance |-> 0,
        destinationBalance |-> 0,
        returnEscrowBalance |-> 0,
        feeEscrowBalance |-> 0,
        feePoolBalance |-> 0,
        coinLocations |-> {"SOURCE"},
        capsuleExists |-> FALSE,
        transitNullifier |-> "UNUSED",
        feeNullifier |-> "UNUSED",
        importReceipt |-> FALSE,
        rejectionCertificate |-> FALSE,
        refunded |-> FALSE,
        timeoutExpired |-> FALSE,
        feeClaims |-> 0
        ]
    /\ consensus = [
        votes |-> [block \in Blocks |-> {}],
        finalized |-> {}
        ]
    /\ valueState = [
        cap |-> 0,
        highestActivatedCap |-> 0,
        exposure |-> [path \in ValuePaths |-> 0],
        logicalHeight |-> 0,
        pending |-> FALSE,
        pendingTarget |-> 0,
        pendingActivationHeight |-> 0,
        pendingSafetyCaseHash |-> "NONE",
        approvals |-> {},
        safetyCaseValid |-> TRUE,
        riskHealthy |-> TRUE,
        newValueFrozen |-> FALSE,
        frozenExposure |-> [path \in ValuePaths |-> 0],
        blockedDirectUpgradeAttempt |-> FALSE,
        valueBypassAccepted |-> FALSE,
        unauthorizedUpgradeAccepted |-> FALSE,
        earlyUpgradeAccepted |-> FALSE,
        expiredSafetyCaseUpgradeAccepted |-> FALSE,
        expiredValueAcceptanceAccepted |-> FALSE
        ]
    /\ cryptoState = [
        era |-> 1,
        disabled |-> {},
        lastAcceptedSuite |-> "NONE",
        downgradeAccepted |-> FALSE
        ]

Export ==
    /\ ~ledger.capsuleExists
    /\ ledger.coinLocations = {"SOURCE"}
    /\ ledger.sourceBalance >= TransferAmount + FeeAmount
    /\ ledger' = [ledger EXCEPT
        !.sourceBalance = @ - TransferAmount - FeeAmount,
        !.transitBalance = @ + TransferAmount,
        !.feeEscrowBalance = @ + FeeAmount,
        !.coinLocations = {"TRANSIT"},
        !.capsuleExists = TRUE
        ]
    /\ UNCHANGED <<consensus, valueState, cryptoState>>

Import ==
    /\ ledger.capsuleExists
    /\ ledger.transitNullifier = "UNUSED"
    \* The destination relies on the shared Nullifier/proof contract. It cannot
    \* directly observe whether a buggy source refunded the canonical transit.
    /\ ledger' = [ledger EXCEPT
        !.transitBalance = IF @ >= TransferAmount THEN @ - TransferAmount ELSE @,
        !.destinationBalance = @ + TransferAmount,
        !.coinLocations = (@ \ {"TRANSIT"}) \cup {"DESTINATION"},
        !.transitNullifier = "IMPORTED",
        !.importReceipt = TRUE
        ]
    /\ UNCHANGED <<consensus, valueState, cryptoState>>

RejectAtDestination ==
    /\ ledger.capsuleExists
    /\ ledger.transitNullifier = "UNUSED"
    /\ ledger' = [ledger EXCEPT
        !.transitNullifier = "REJECTED",
        !.rejectionCertificate = TRUE
        ]
    /\ UNCHANGED <<consensus, valueState, cryptoState>>

BeginReturnAfterRejection ==
    /\ ledger.rejectionCertificate
    /\ ledger.transitNullifier = "REJECTED"
    /\ ~ledger.refunded
    /\ "TRANSIT" \in ledger.coinLocations
    /\ ledger.transitBalance >= TransferAmount
    /\ ledger' = [ledger EXCEPT
        !.transitBalance = @ - TransferAmount,
        !.returnEscrowBalance = @ + TransferAmount,
        !.coinLocations = {"RETURN_ESCROW"}
        ]
    /\ UNCHANGED <<consensus, valueState, cryptoState>>

FinalizeReturnAfterRejection ==
    /\ ledger.rejectionCertificate
    /\ ledger.transitNullifier = "REJECTED"
    /\ ~ledger.refunded
    /\ "RETURN_ESCROW" \in ledger.coinLocations
    /\ ledger.returnEscrowBalance >= TransferAmount
    /\ ledger' = [ledger EXCEPT
        !.sourceBalance = @ + TransferAmount,
        !.returnEscrowBalance = @ - TransferAmount,
        !.coinLocations = {"SOURCE"},
        !.refunded = TRUE
        ]
    /\ UNCHANGED <<consensus, valueState, cryptoState>>

ExpireTimeout ==
    /\ ledger.capsuleExists
    /\ ~ledger.timeoutExpired
    /\ ledger' = [ledger EXCEPT !.timeoutExpired = TRUE]
    /\ UNCHANGED <<consensus, valueState, cryptoState>>

ClaimFee ==
    /\ ledger.capsuleExists
    /\ ledger.feeNullifier = "UNUSED"
    /\ ledger.feeEscrowBalance >= FeeAmount
    /\ ledger' = [ledger EXCEPT
        !.feeEscrowBalance = @ - FeeAmount,
        !.feePoolBalance = @ + FeeAmount,
        !.feeNullifier = "CLAIMED",
        !.feeClaims = @ + 1
        ]
    /\ UNCHANGED <<consensus, valueState, cryptoState>>

UnsafeTimeoutRefund ==
    /\ UnsafeTimeoutRefundEnabled
    /\ ledger.timeoutExpired
    /\ ledger.transitNullifier = "UNUSED"
    /\ ~ledger.refunded
    /\ "TRANSIT" \in ledger.coinLocations
    /\ ledger.transitBalance >= TransferAmount
    /\ ledger' = [ledger EXCEPT
        !.sourceBalance = @ + TransferAmount,
        !.transitBalance = @ - TransferAmount,
        !.coinLocations = {"SOURCE"},
        !.refunded = TRUE
        ]
    /\ UNCHANGED <<consensus, valueState, cryptoState>>

UnsafeLateImportAfterRejection ==
    /\ UnsafeLateImportEnabled
    /\ ledger.rejectionCertificate
    /\ ledger.transitNullifier = "REJECTED"
    /\ ~ledger.importReceipt
    /\ ledger' = [ledger EXCEPT
        !.transitBalance = IF @ >= TransferAmount THEN @ - TransferAmount ELSE @,
        !.destinationBalance = @ + TransferAmount,
        !.coinLocations = (@ \ {"TRANSIT"}) \cup {"DESTINATION"},
        !.importReceipt = TRUE
        ]
    /\ UNCHANGED <<consensus, valueState, cryptoState>>

UnsafeDuplicateFeeClaim ==
    /\ UnsafeDuplicateFeeClaimEnabled
    /\ ledger.feeNullifier = "CLAIMED"
    /\ ledger.feeClaims = 1
    /\ ledger' = [ledger EXCEPT
        !.feePoolBalance = @ + FeeAmount,
        !.feeClaims = @ + 1
        ]
    /\ UNCHANGED <<consensus, valueState, cryptoState>>

VotedForOtherBlock(voter, block) ==
    \E other \in Blocks \ {block} : voter \in consensus.votes[other]

CastVote(voter, block) ==
    /\ voter \in Validators
    /\ block \in Blocks
    /\ voter \notin consensus.votes[block]
    /\ (voter \in ByzantineValidators \/ ~VotedForOtherBlock(voter, block))
    /\ consensus' = [consensus EXCEPT !.votes[block] = @ \cup {voter}]
    /\ UNCHANGED <<ledger, valueState, cryptoState>>

EffectiveQuorum == IF UnsafeWeakQuorumEnabled THEN Quorum - 1 ELSE Quorum

Finalize(block) ==
    /\ block \in Blocks
    /\ block \notin consensus.finalized
    /\ Cardinality(consensus.votes[block]) >= EffectiveQuorum
    /\ consensus' = [consensus EXCEPT !.finalized = @ \cup {block}]
    /\ UNCHANGED <<ledger, valueState, cryptoState>>

PathLimit(path) ==
    CASE path = "LOCAL" -> MaxLocalValue
      [] path = "CROSS_ZONE" -> MaxCrossZoneValue
      [] path = "DSC" -> MaxDscValue

PathEnabledAtCap(path, cap) ==
    CASE path = "LOCAL" -> cap >= 1
      [] path = "CROSS_ZONE" -> cap >= 2
      [] path = "DSC" -> cap >= 3

TickLogicalHeight ==
    /\ valueState.logicalHeight < MaxLogicalHeight
    /\ valueState' = [valueState EXCEPT !.logicalHeight = @ + 1]
    /\ UNCHANGED <<ledger, consensus, cryptoState>>

ProposeCapUpgrade ==
    /\ ~valueState.pending
    /\ valueState.cap < 3
    /\ valueState.riskHealthy
    /\ ~valueState.newValueFrozen
    /\ valueState.safetyCaseValid
    /\ valueState.logicalHeight < SafetyCaseExpiresAt
    /\ valueState.logicalHeight + ChallengePeriod < SafetyCaseExpiresAt
    /\ valueState.logicalHeight + ChallengePeriod <= MaxLogicalHeight
    /\ valueState' = [valueState EXCEPT
        !.pending = TRUE,
        !.pendingTarget = valueState.cap + 1,
        !.pendingActivationHeight = valueState.logicalHeight + ChallengePeriod,
        !.pendingSafetyCaseHash = MainnetSafetyCaseHash,
        !.approvals = {}
        ]
    /\ UNCHANGED <<ledger, consensus, cryptoState>>

AuthorizeCapUpgrade(group) ==
    /\ group \in GovernanceGroups
    /\ valueState.pending
    /\ group \notin valueState.approvals
    /\ valueState' = [valueState EXCEPT !.approvals = @ \cup {group}]
    /\ UNCHANGED <<ledger, consensus, cryptoState>>

ActivatePendingCapUpgrade ==
    /\ valueState.pending
    /\ valueState.pendingTarget = valueState.cap + 1
    /\ valueState.logicalHeight >= valueState.pendingActivationHeight
    /\ valueState.logicalHeight < SafetyCaseExpiresAt
    /\ valueState.pendingSafetyCaseHash = MainnetSafetyCaseHash
    /\ valueState.safetyCaseValid
    /\ valueState.riskHealthy
    /\ ~valueState.newValueFrozen
    /\ Cardinality(valueState.approvals) >= UpgradeAuthorizationThreshold
    /\ valueState' = [valueState EXCEPT
        !.cap = valueState.pendingTarget,
        !.highestActivatedCap = valueState.pendingTarget,
        !.pending = FALSE,
        !.pendingTarget = 0,
        !.pendingActivationHeight = 0,
        !.pendingSafetyCaseHash = "NONE",
        !.approvals = {}
        ]
    /\ UNCHANGED <<ledger, consensus, cryptoState>>

AttemptDirectCapUpgrade(actor) ==
    /\ actor \in DirectUpgradeActors
    /\ ~valueState.blockedDirectUpgradeAttempt
    /\ valueState' = [valueState EXCEPT !.blockedDirectUpgradeAttempt = TRUE]
    /\ UNCHANGED <<ledger, consensus, cryptoState>>

RiskDeteriorates ==
    /\ valueState.riskHealthy
    /\ valueState' = [valueState EXCEPT
        !.cap = 0,
        !.pending = FALSE,
        !.pendingTarget = 0,
        !.pendingActivationHeight = 0,
        !.pendingSafetyCaseHash = "NONE",
        !.approvals = {},
        !.safetyCaseValid = FALSE,
        !.riskHealthy = FALSE,
        !.newValueFrozen = TRUE,
        !.frozenExposure = valueState.exposure
        ]
    /\ UNCHANGED <<ledger, consensus, cryptoState>>

AcceptValue(actor, path) ==
    /\ actor \in ValueActors
    /\ path \in ValuePaths
    /\ valueState.riskHealthy
    /\ ~valueState.newValueFrozen
    /\ valueState.safetyCaseValid
    /\ valueState.logicalHeight < SafetyCaseExpiresAt
    /\ PathEnabledAtCap(path, valueState.cap)
    /\ valueState.exposure[path] + MaxSingleValue <= PathLimit(path)
    /\ valueState' = [valueState EXCEPT
        !.exposure[path] = @ + MaxSingleValue
        ]
    /\ UNCHANGED <<ledger, consensus, cryptoState>>

UnsafeValueCapBypass(actor, path) ==
    /\ UnsafeValueBypassEnabled
    /\ actor \in ValueActors
    /\ path \in ValuePaths
    /\ valueState.cap = 0
    /\ ~valueState.newValueFrozen
    /\ valueState.exposure[path] = 0
    /\ valueState' = [valueState EXCEPT
        !.exposure[path] = @ + MaxSingleValue,
        !.valueBypassAccepted = TRUE
        ]
    /\ UNCHANGED <<ledger, consensus, cryptoState>>

UnsafeUnauthorizedCapUpgrade(actor) ==
    /\ UnsafeUnauthorizedUpgradeEnabled
    /\ actor \in DirectUpgradeActors
    /\ valueState.cap = 0
    /\ ~valueState.pending
    /\ valueState' = [valueState EXCEPT
        !.cap = 1,
        !.highestActivatedCap = 1,
        !.unauthorizedUpgradeAccepted = TRUE
        ]
    /\ UNCHANGED <<ledger, consensus, cryptoState>>

UnsafeEarlyCapUpgrade ==
    /\ UnsafeEarlyUpgradeEnabled
    /\ valueState.pending
    /\ valueState.pendingTarget = valueState.cap + 1
    /\ valueState.logicalHeight < valueState.pendingActivationHeight
    /\ valueState.logicalHeight < SafetyCaseExpiresAt
    /\ valueState.pendingSafetyCaseHash = MainnetSafetyCaseHash
    /\ valueState.safetyCaseValid
    /\ Cardinality(valueState.approvals) >= UpgradeAuthorizationThreshold
    /\ valueState' = [valueState EXCEPT
        !.cap = valueState.pendingTarget,
        !.highestActivatedCap = valueState.pendingTarget,
        !.pending = FALSE,
        !.pendingTarget = 0,
        !.pendingActivationHeight = 0,
        !.pendingSafetyCaseHash = "NONE",
        !.approvals = {},
        !.earlyUpgradeAccepted = TRUE
        ]
    /\ UNCHANGED <<ledger, consensus, cryptoState>>

UnsafeExpiredSafetyCaseCapUpgrade ==
    /\ UnsafeExpiredSafetyCaseUpgradeEnabled
    /\ valueState.pending
    /\ valueState.pendingTarget = valueState.cap + 1
    /\ valueState.logicalHeight >= valueState.pendingActivationHeight
    /\ valueState.logicalHeight >= SafetyCaseExpiresAt
    /\ valueState.pendingSafetyCaseHash = MainnetSafetyCaseHash
    /\ Cardinality(valueState.approvals) >= UpgradeAuthorizationThreshold
    /\ valueState' = [valueState EXCEPT
        !.cap = valueState.pendingTarget,
        !.highestActivatedCap = valueState.pendingTarget,
        !.pending = FALSE,
        !.pendingTarget = 0,
        !.pendingActivationHeight = 0,
        !.pendingSafetyCaseHash = "NONE",
        !.approvals = {},
        !.expiredSafetyCaseUpgradeAccepted = TRUE
        ]
    /\ UNCHANGED <<ledger, consensus, cryptoState>>

UnsafeExpiredSafetyCaseValueAcceptance(actor, path) ==
    /\ UnsafeExpiredValueAcceptanceEnabled
    /\ actor \in ValueActors
    /\ path \in ValuePaths
    /\ valueState.cap > 0
    /\ valueState.logicalHeight >= SafetyCaseExpiresAt
    /\ PathEnabledAtCap(path, valueState.cap)
    /\ valueState.exposure[path] = 0
    /\ valueState' = [valueState EXCEPT
        !.exposure[path] = @ + MaxSingleValue,
        !.expiredValueAcceptanceAccepted = TRUE
        ]
    /\ UNCHANGED <<ledger, consensus, cryptoState>>

AdvanceCryptoEra ==
    /\ cryptoState.era = 1
    /\ cryptoState' = [cryptoState EXCEPT
        !.era = 2,
        !.disabled = {"CLASSIC"},
        !.lastAcceptedSuite = "NONE"
        ]
    /\ UNCHANGED <<ledger, consensus, valueState>>

AcceptCryptoSuite(suite) ==
    /\ suite \in CryptoSuites
    /\ suite \notin cryptoState.disabled
    /\ cryptoState.lastAcceptedSuite # suite
    /\ cryptoState' = [cryptoState EXCEPT !.lastAcceptedSuite = suite]
    /\ UNCHANGED <<ledger, consensus, valueState>>

UnsafeCryptoDowngrade ==
    /\ UnsafeCryptoDowngradeEnabled
    /\ cryptoState.era = 2
    /\ "CLASSIC" \in cryptoState.disabled
    /\ ~cryptoState.downgradeAccepted
    /\ cryptoState' = [cryptoState EXCEPT
        !.lastAcceptedSuite = "CLASSIC",
        !.downgradeAccepted = TRUE
        ]
    /\ UNCHANGED <<ledger, consensus, valueState>>

Next ==
    \/ Export
    \/ Import
    \/ RejectAtDestination
    \/ BeginReturnAfterRejection
    \/ FinalizeReturnAfterRejection
    \/ ExpireTimeout
    \/ ClaimFee
    \/ UnsafeTimeoutRefund
    \/ UnsafeLateImportAfterRejection
    \/ UnsafeDuplicateFeeClaim
    \/ \E voter \in Validators : \E block \in Blocks : CastVote(voter, block)
    \/ \E block \in Blocks : Finalize(block)
    \/ TickLogicalHeight
    \/ ProposeCapUpgrade
    \/ \E group \in GovernanceGroups : AuthorizeCapUpgrade(group)
    \/ ActivatePendingCapUpgrade
    \/ \E actor \in DirectUpgradeActors : AttemptDirectCapUpgrade(actor)
    \/ RiskDeteriorates
    \/ \E actor \in ValueActors :
           \E path \in ValuePaths : AcceptValue(actor, path)
    \/ \E actor \in ValueActors :
           \E path \in ValuePaths : UnsafeValueCapBypass(actor, path)
    \/ \E actor \in DirectUpgradeActors : UnsafeUnauthorizedCapUpgrade(actor)
    \/ UnsafeEarlyCapUpgrade
    \/ UnsafeExpiredSafetyCaseCapUpgrade
    \/ \E actor \in ValueActors :
           \E path \in ValuePaths : UnsafeExpiredSafetyCaseValueAcceptance(actor, path)
    \/ AdvanceCryptoEra
    \/ \E suite \in CryptoSuites : AcceptCryptoSuite(suite)
    \/ UnsafeCryptoDowngrade

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ ledger \in LedgerType
    /\ consensus \in ConsensusType
    /\ valueState \in ValueStateType
    /\ cryptoState \in CryptoStateType

SupplyConserved ==
    ledger.sourceBalance
    + ledger.transitBalance
    + ledger.destinationBalance
    + ledger.returnEscrowBalance
    + ledger.feeEscrowBalance
    + ledger.feePoolBalance
    = TotalSupply

UmcoHasSingleCanonicalLocation == Cardinality(ledger.coinLocations) = 1

TransitNullifierUnique ==
    /\ (ledger.transitNullifier = "IMPORTED") = ledger.importReceipt
    /\ (ledger.transitNullifier = "REJECTED") = ledger.rejectionCertificate
    /\ ~(ledger.importReceipt /\ ledger.rejectionCertificate)

FeeNullifierUnique ==
    /\ ledger.feeClaims <= 1
    /\ (ledger.feeClaims = 1) = (ledger.feeNullifier = "CLAIMED")

RefundRequiresDestinationRejection ==
    (ledger.refunded \/ "RETURN_ESCROW" \in ledger.coinLocations)
        => ledger.rejectionCertificate

LateImportAfterRejectionFails ==
    ledger.rejectionCertificate => ~ledger.importReceipt

NoDoubleFinality == Cardinality(consensus.finalized) <= 1

ValueCapCannotBeBypassed ==
    /\ ~valueState.valueBypassAccepted
    /\ \A path \in ValuePaths : valueState.exposure[path] <= PathLimit(path)
    /\ (~valueState.newValueFrozen =>
           \A path \in ValuePaths :
               valueState.exposure[path] > 0 => PathEnabledAtCap(path, valueState.cap))

PendingCapUpgradeWellFormed ==
    IF valueState.pending
    THEN /\ valueState.cap < 3
         /\ valueState.pendingTarget = valueState.cap + 1
         /\ valueState.pendingActivationHeight >= ChallengePeriod
         /\ valueState.pendingActivationHeight
                <= valueState.logicalHeight + ChallengePeriod
         /\ valueState.pendingSafetyCaseHash = MainnetSafetyCaseHash
    ELSE /\ valueState.pendingTarget = 0
         /\ valueState.pendingActivationHeight = 0
         /\ valueState.pendingSafetyCaseHash = "NONE"
         /\ valueState.approvals = {}

NoUnauthorizedCapUpgrade == ~valueState.unauthorizedUpgradeAccepted

ChallengePeriodEnforced == ~valueState.earlyUpgradeAccepted

SafetyCaseFreshOnUpgrade == ~valueState.expiredSafetyCaseUpgradeAccepted

RuntimeSafetyCaseExpiryBlocksNewValue ==
    ~valueState.expiredValueAcceptanceAccepted

DirectUpgradeCallersAreBlocked ==
    ~valueState.unauthorizedUpgradeAccepted

RiskDownshiftIsFailClosed ==
    ~valueState.riskHealthy =>
        /\ valueState.newValueFrozen
        /\ ~valueState.safetyCaseValid
        /\ ~valueState.pending
        /\ valueState.cap = 0
        /\ valueState.exposure = valueState.frozenExposure
        /\ valueState.highestActivatedCap >= valueState.cap

CryptoEraCannotDowngrade ==
    /\ ~cryptoState.downgradeAccepted
    /\ (cryptoState.lastAcceptedSuite = "NONE"
        \/ cryptoState.lastAcceptedSuite \notin cryptoState.disabled)

=============================================================================
