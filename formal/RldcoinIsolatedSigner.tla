------------------------- MODULE RldcoinIsolatedSigner -------------------------
EXTENDS Integers, Naturals, FiniteSets, TLC

\* Bounded safety model for the reference isolated consensus signer.  The
\* untrusted node may present conflicting, stale, malformed, or wrong-key
\* requests.  This is an abstract state machine, not a Rust refinement, a
\* cryptographic proof, an HSM model, or a transport-security model.
CONSTANT FaultMode

Proposals == {"proposal-a", "proposal-b"}
Locks == Proposals \cup {"NONE"}
RequestKinds == {"NONE", "PROPOSAL", "VOTE"}

UnsafeRawSigningEnabled == FaultMode = "RAW_SIGNING_API"
UnsafeQuorumBypassEnabled == FaultMode = "BYPASS_WITNESS_QUORUM"
UnsafeSignBeforePersistEnabled == FaultMode = "SIGN_BEFORE_PERSIST"
UnsafeLoseLocksEnabled == FaultMode = "LOSE_LOCKS_ON_RECOVERY"
UnsafeRollbackEnabled == FaultMode = "ROLLBACK_SIGNER_STATE"
UnsafeKeyPinBypassEnabled == FaultMode = "BYPASS_KEY_PIN"

ASSUME FaultMode \in {
    "SAFE",
    "RAW_SIGNING_API",
    "BYPASS_WITNESS_QUORUM",
    "SIGN_BEFORE_PERSIST",
    "LOSE_LOCKS_ON_RECOVERY",
    "ROLLBACK_SIGNER_STATE",
    "BYPASS_KEY_PIN"
}

VARIABLES node, signer

vars == <<node, signer>>

NodeType == [
    durableHead : 0..2,
    durableVoteLock : Locks,
    witnessProposal : Locks,
    witnessHead : 0..2,
    witnessExact : BOOLEAN
]

SignerType == [
    crashed : BOOLEAN,
    pendingKind : RequestKinds,
    pendingProposal : Locks,
    pendingHead : 0..2,
    pendingAuthorizationExact : BOOLEAN,
    proposalLock : Locks,
    voteLock : Locks,
    persistentHead : 0..2,
    maximumPersistentHead : 0..2,
    durableProposalAuthorizations : SUBSET Proposals,
    durableVoteAuthorizations : SUBSET Proposals,
    exactWitnessAuthorizations : SUBSET Proposals,
    issuedProposals : SUBSET Proposals,
    issuedVotes : SUBSET Proposals,
    rawSignatureIssued : BOOLEAN,
    wrongKeySignatureIssued : BOOLEAN
]

Init ==
    /\ node = [
        durableHead |-> 0,
        durableVoteLock |-> "NONE",
        witnessProposal |-> "NONE",
        witnessHead |-> 0,
        witnessExact |-> FALSE
        ]
    /\ signer = [
        crashed |-> FALSE,
        pendingKind |-> "NONE",
        pendingProposal |-> "NONE",
        pendingHead |-> 0,
        pendingAuthorizationExact |-> FALSE,
        proposalLock |-> "NONE",
        voteLock |-> "NONE",
        persistentHead |-> 0,
        maximumPersistentHead |-> 0,
        durableProposalAuthorizations |-> {},
        durableVoteAuthorizations |-> {},
        exactWitnessAuthorizations |-> {},
        issuedProposals |-> {},
        issuedVotes |-> {},
        rawSignatureIssued |-> FALSE,
        wrongKeySignatureIssued |-> FALSE
        ]

\* The node lock is durable before an honest witness authorization exists.
PersistInitialNodeVoteLock(proposal) ==
    /\ proposal \in Proposals
    /\ node.durableHead = 0
    /\ node.durableVoteLock = "NONE"
    /\ node' = [node EXCEPT
        !.durableHead = 1,
        !.durableVoteLock = proposal
        ]
    /\ UNCHANGED signer

AcquireExactWitnessAuthorization ==
    /\ node.durableHead > 0
    /\ node.durableVoteLock \in Proposals
    /\ ~node.witnessExact
    /\ node' = [node EXCEPT
        !.witnessProposal = node.durableVoteLock,
        !.witnessHead = node.durableHead,
        !.witnessExact = TRUE
        ]
    /\ UNCHANGED signer

\* The environment may be fully hostile and present a second syntactically
\* valid-looking authorization for the same parent instance.  The signer lock,
\* not trust in the node, must still prevent a second vote.
PresentConflictingAuthorizedVote(proposal) ==
    /\ proposal \in Proposals
    /\ signer.issuedVotes # {}
    /\ proposal \notin signer.issuedVotes
    /\ node' = [node EXCEPT
        !.durableHead = 2,
        !.durableVoteLock = proposal,
        !.witnessProposal = proposal,
        !.witnessHead = 2,
        !.witnessExact = TRUE
        ]
    /\ UNCHANGED signer

QueueTypedProposal(proposal) ==
    /\ proposal \in Proposals
    /\ ~signer.crashed
    /\ signer.pendingKind = "NONE"
    /\ signer.proposalLock \in {"NONE", proposal}
    /\ signer' = [signer EXCEPT
        !.pendingKind = "PROPOSAL",
        !.pendingProposal = proposal,
        !.pendingHead = node.durableHead,
        !.pendingAuthorizationExact = TRUE
        ]
    /\ UNCHANGED node

PersistTypedProposalAuthorization ==
    /\ ~signer.crashed
    /\ signer.pendingKind = "PROPOSAL"
    /\ signer.pendingProposal \in Proposals
    /\ signer.proposalLock \in {"NONE", signer.pendingProposal}
    /\ signer' = [signer EXCEPT
        !.proposalLock = signer.pendingProposal,
        !.durableProposalAuthorizations = @ \cup {signer.pendingProposal}
        ]
    /\ UNCHANGED node

ReleaseProposalSignature ==
    /\ ~signer.crashed
    /\ signer.pendingKind = "PROPOSAL"
    /\ signer.pendingProposal \in signer.durableProposalAuthorizations
    /\ signer.proposalLock = signer.pendingProposal
    /\ signer' = [signer EXCEPT
        !.issuedProposals = @ \cup {signer.pendingProposal},
        !.pendingKind = "NONE",
        !.pendingProposal = "NONE",
        !.pendingHead = 0,
        !.pendingAuthorizationExact = FALSE
        ]
    /\ UNCHANGED node

QueueTypedVote(proposal) ==
    /\ proposal \in Proposals
    /\ ~signer.crashed
    /\ signer.pendingKind = "NONE"
    /\ signer.voteLock \in {"NONE", proposal}
    /\ node.witnessExact
    /\ node.witnessProposal = proposal
    /\ node.durableVoteLock = proposal
    /\ node.witnessHead = node.durableHead
    /\ node.durableHead >= signer.persistentHead
    /\ signer' = [signer EXCEPT
        !.pendingKind = "VOTE",
        !.pendingProposal = proposal,
        !.pendingHead = node.durableHead,
        !.pendingAuthorizationExact = TRUE,
        !.exactWitnessAuthorizations = @ \cup {proposal}
        ]
    /\ UNCHANGED node

PersistTypedVoteAuthorization ==
    /\ ~signer.crashed
    /\ signer.pendingKind = "VOTE"
    /\ signer.pendingProposal \in Proposals
    /\ signer.pendingAuthorizationExact
    /\ signer.voteLock \in {"NONE", signer.pendingProposal}
    /\ signer.pendingHead >= signer.persistentHead
    /\ signer' = [signer EXCEPT
        !.voteLock = signer.pendingProposal,
        !.persistentHead = signer.pendingHead,
        !.maximumPersistentHead = signer.pendingHead,
        !.durableVoteAuthorizations = @ \cup {signer.pendingProposal}
        ]
    /\ UNCHANGED node

ReleaseVoteSignature ==
    /\ ~signer.crashed
    /\ signer.pendingKind = "VOTE"
    /\ signer.pendingProposal \in signer.durableVoteAuthorizations
    /\ signer.pendingProposal \in signer.exactWitnessAuthorizations
    /\ signer.voteLock = signer.pendingProposal
    /\ signer.persistentHead = signer.pendingHead
    /\ signer' = [signer EXCEPT
        !.issuedVotes = @ \cup {signer.pendingProposal},
        !.pendingKind = "NONE",
        !.pendingProposal = "NONE",
        !.pendingHead = 0,
        !.pendingAuthorizationExact = FALSE
        ]
    /\ UNCHANGED node

CrashSigner ==
    /\ ~signer.crashed
    /\ signer' = [signer EXCEPT
        !.crashed = TRUE,
        !.pendingKind = "NONE",
        !.pendingProposal = "NONE",
        !.pendingHead = 0,
        !.pendingAuthorizationExact = FALSE
        ]
    /\ UNCHANGED node

RecoverSigner ==
    /\ signer.crashed
    /\ signer' = [signer EXCEPT !.crashed = FALSE]
    /\ UNCHANGED node

\* Safe probes represent inputs the typed API rejects without producing a
\* signature or mutating monotonic authorization state.
ProbeRawSigningRequest == UNCHANGED vars

ProbeWrongKeyRequest == UNCHANGED vars

UnsafeRawSigning ==
    /\ UnsafeRawSigningEnabled
    /\ ~signer.crashed
    /\ ~signer.rawSignatureIssued
    /\ signer' = [signer EXCEPT !.rawSignatureIssued = TRUE]
    /\ UNCHANGED node

UnsafeQueueVoteWithoutExactQuorum(proposal) ==
    /\ UnsafeQuorumBypassEnabled
    /\ proposal \in Proposals
    /\ ~signer.crashed
    /\ signer.pendingKind = "NONE"
    /\ signer.voteLock \in {"NONE", proposal}
    /\ signer' = [signer EXCEPT
        !.pendingKind = "VOTE",
        !.pendingProposal = proposal,
        !.pendingHead = signer.persistentHead,
        !.pendingAuthorizationExact = FALSE
        ]
    /\ UNCHANGED node

UnsafeReleaseVoteWithoutQuorum ==
    /\ UnsafeQuorumBypassEnabled
    /\ ~signer.crashed
    /\ signer.pendingKind = "VOTE"
    /\ ~signer.pendingAuthorizationExact
    /\ signer' = [signer EXCEPT
        !.issuedVotes = @ \cup {signer.pendingProposal},
        !.pendingKind = "NONE",
        !.pendingProposal = "NONE",
        !.pendingHead = 0
        ]
    /\ UNCHANGED node

UnsafeReleaseBeforePersistence(proposal) ==
    /\ UnsafeSignBeforePersistEnabled
    /\ proposal \in Proposals
    /\ ~signer.crashed
    /\ signer.pendingKind = "VOTE"
    /\ signer.pendingProposal = proposal
    /\ proposal \notin signer.durableVoteAuthorizations
    /\ signer' = [signer EXCEPT
        !.issuedVotes = @ \cup {proposal},
        !.pendingKind = "NONE",
        !.pendingProposal = "NONE",
        !.pendingHead = 0,
        !.pendingAuthorizationExact = FALSE
        ]
    /\ UNCHANGED node

UnsafeRecoverLosesLocks ==
    /\ UnsafeLoseLocksEnabled
    /\ signer.crashed
    /\ signer' = [signer EXCEPT
        !.crashed = FALSE,
        !.proposalLock = "NONE",
        !.voteLock = "NONE"
        ]
    /\ UNCHANGED node

UnsafeRollbackSignerState ==
    /\ UnsafeRollbackEnabled
    /\ ~signer.crashed
    /\ signer.persistentHead > 0
    /\ signer' = [signer EXCEPT
        !.persistentHead = 0,
        !.proposalLock = "NONE",
        !.voteLock = "NONE"
        ]
    /\ UNCHANGED node

UnsafeSignForWrongPinnedKey ==
    /\ UnsafeKeyPinBypassEnabled
    /\ ~signer.crashed
    /\ ~signer.wrongKeySignatureIssued
    /\ signer' = [signer EXCEPT !.wrongKeySignatureIssued = TRUE]
    /\ UNCHANGED node

Next ==
    \/ \E proposal \in Proposals : PersistInitialNodeVoteLock(proposal)
    \/ AcquireExactWitnessAuthorization
    \/ \E proposal \in Proposals : PresentConflictingAuthorizedVote(proposal)
    \/ \E proposal \in Proposals : QueueTypedProposal(proposal)
    \/ PersistTypedProposalAuthorization
    \/ ReleaseProposalSignature
    \/ \E proposal \in Proposals : QueueTypedVote(proposal)
    \/ PersistTypedVoteAuthorization
    \/ ReleaseVoteSignature
    \/ CrashSigner
    \/ RecoverSigner
    \/ ProbeRawSigningRequest
    \/ ProbeWrongKeyRequest
    \/ UnsafeRawSigning
    \/ \E proposal \in Proposals : UnsafeQueueVoteWithoutExactQuorum(proposal)
    \/ UnsafeReleaseVoteWithoutQuorum
    \/ \E proposal \in Proposals : UnsafeReleaseBeforePersistence(proposal)
    \/ UnsafeRecoverLosesLocks
    \/ UnsafeRollbackSignerState
    \/ UnsafeSignForWrongPinnedKey

Spec == Init /\ [][Next]_vars

TypeOK == node \in NodeType /\ signer \in SignerType

NoRawSigningCapability == ~signer.rawSignatureIssued

PinnedValidatorKeyIsMandatory == ~signer.wrongKeySignatureIssued

EveryVoteHasExactWitnessAuthorization ==
    signer.issuedVotes \subseteq signer.exactWitnessAuthorizations

EveryVoteHasDurableSignerAuthorization ==
    signer.issuedVotes \subseteq signer.durableVoteAuthorizations

EveryProposalHasDurableSignerAuthorization ==
    signer.issuedProposals \subseteq signer.durableProposalAuthorizations

AtMostOneVotePerParentInstance == Cardinality(signer.issuedVotes) <= 1

AtMostOneProposalPerParentInstance == Cardinality(signer.issuedProposals) <= 1

SignerMonotonicHeadNeverRegresses ==
    signer.persistentHead = signer.maximumPersistentHead

NoSignatureWhileSignerUnavailable ==
    signer.crashed => signer.pendingKind = "NONE"

=============================================================================
