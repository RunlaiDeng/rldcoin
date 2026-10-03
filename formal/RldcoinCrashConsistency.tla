---------------------- MODULE RldcoinCrashConsistency ----------------------
EXTENDS Integers, Naturals, FiniteSets, TLC

\* Bounded crash-consistency and vote-lock model. It is not a Rust refinement,
\* filesystem model, or liveness proof. FaultMode enables one unsafe mutation.
CONSTANT FaultMode

Roots == {"OLD", "NEW"}
Proposals == {"proposal-a", "proposal-b"}
Locks == Proposals \cup {"NONE"}

WalStatuses == {
    "EMPTY",
    "VOLATILE_RECORD_1",
    "VOLATILE_COMPLETE",
    "FSYNCED_COMPLETE",
    "STABLE_TRUNCATED",
    "STABLE_OUT_OF_ORDER",
    "STABLE_BAD_PREV_ROOT",
    "STABLE_BAD_RECORD_HASH",
    "OLD_CHECKPOINT_SHORT_WAL"
}

CorruptWalStatuses == {
    "STABLE_TRUNCATED",
    "STABLE_OUT_OF_ORDER",
    "STABLE_BAD_PREV_ROOT",
    "STABLE_BAD_RECORD_HASH",
    "OLD_CHECKPOINT_SHORT_WAL"
}

CheckpointStatuses == {"OLD_COMPLETE", "NEW_PARTIAL", "NEW_COMPLETE"}
RecoveryOutcomes == {"NONE", "FAIL_CLOSED", "OLD_COMPLETE", "NEW_COMPLETE", "MIXED"}

UnsafeSignBeforeLockEnabled == FaultMode = "SIGN_BEFORE_LOCK"
UnsafeIgnorePartialWalEnabled == FaultMode = "IGNORE_PARTIAL_WAL"
UnsafeAnchorRollbackEnabled == FaultMode = "ANCHOR_ROLLBACK"
UnsafeCheckpointOverwriteEnabled == FaultMode = "CHECKPOINT_OVERWRITE_WAL"
UnsafeLoseVoteLockEnabled == FaultMode = "LOSE_VOTE_LOCK_ON_RECOVERY"
WholeDirectoryRollbackEnabled == FaultMode = "WHOLE_DIRECTORY_ROLLBACK"

ASSUME FaultMode \in {
    "SAFE",
    "SIGN_BEFORE_LOCK",
    "IGNORE_PARTIAL_WAL",
    "ANCHOR_ROLLBACK",
    "CHECKPOINT_OVERWRITE_WAL",
    "LOSE_VOTE_LOCK_ON_RECOVERY",
    "WHOLE_DIRECTORY_ROLLBACK"
}

VARIABLES storage, voter

vars == <<storage, voter>>

StorageType == [
    walStatus : WalStatuses,
    walEverCommitted : BOOLEAN,
    checkpointStatus : CheckpointStatuses,
    checkpointFailed : BOOLEAN,
    anchorEpoch : 0..1,
    maxAnchorEpoch : 0..1,
    publishedRoot : Roots,
    runtimeRoot : Roots,
    recoveryAttempted : BOOLEAN,
    recoveryOutcome : RecoveryOutcomes,
    directoryRollbackOccurred : BOOLEAN,
    externalRollbackWitnessAvailable : BOOLEAN
]

VoterType == [
    crashed : BOOLEAN,
    volatileLock : Locks,
    persistentLock : Locks,
    issuedSignatures : SUBSET Proposals
]

Init ==
    /\ storage = [
        walStatus |-> "EMPTY",
        walEverCommitted |-> FALSE,
        checkpointStatus |-> "OLD_COMPLETE",
        checkpointFailed |-> FALSE,
        anchorEpoch |-> 0,
        maxAnchorEpoch |-> 0,
        publishedRoot |-> "OLD",
        runtimeRoot |-> "OLD",
        recoveryAttempted |-> FALSE,
        recoveryOutcome |-> "NONE",
        directoryRollbackOccurred |-> FALSE,
        externalRollbackWitnessAvailable |-> FALSE
        ]
    /\ voter = [
        crashed |-> FALSE,
        volatileLock |-> "NONE",
        persistentLock |-> "NONE",
        issuedSignatures |-> {}
        ]

AppendWalRecord1 ==
    /\ storage.walStatus = "EMPTY"
    /\ ~storage.recoveryAttempted
    /\ storage' = [storage EXCEPT !.walStatus = "VOLATILE_RECORD_1"]
    /\ UNCHANGED voter

AppendWalRecord2 ==
    /\ storage.walStatus = "VOLATILE_RECORD_1"
    /\ ~storage.recoveryAttempted
    /\ storage' = [storage EXCEPT !.walStatus = "VOLATILE_COMPLETE"]
    /\ UNCHANGED voter

FsyncCompleteWal ==
    /\ storage.walStatus = "VOLATILE_COMPLETE"
    /\ ~storage.recoveryAttempted
    /\ storage' = [storage EXCEPT
        !.walStatus = "FSYNCED_COMPLETE",
        !.walEverCommitted = TRUE
        ]
    /\ UNCHANGED voter

AdvanceRollbackAnchor ==
    /\ storage.walStatus = "FSYNCED_COMPLETE"
    /\ storage.anchorEpoch = 0
    /\ ~storage.recoveryAttempted
    /\ storage' = [storage EXCEPT
        !.anchorEpoch = 1,
        !.maxAnchorEpoch = 1
        ]
    /\ UNCHANGED voter

PublishNewState ==
    /\ storage.walStatus = "FSYNCED_COMPLETE"
    /\ storage.anchorEpoch = 1
    /\ storage.publishedRoot = "OLD"
    /\ ~storage.recoveryAttempted
    /\ storage' = [storage EXCEPT
        !.publishedRoot = "NEW",
        !.runtimeRoot = "NEW"
        ]
    /\ UNCHANGED voter

CheckpointSucceeds ==
    /\ storage.publishedRoot = "NEW"
    /\ storage.walStatus = "FSYNCED_COMPLETE"
    /\ storage.checkpointStatus # "NEW_COMPLETE"
    /\ ~storage.recoveryAttempted
    /\ storage' = [storage EXCEPT
        !.checkpointStatus = "NEW_COMPLETE",
        !.checkpointFailed = FALSE
        ]
    /\ UNCHANGED voter

CheckpointFails ==
    /\ storage.publishedRoot = "NEW"
    /\ storage.walStatus = "FSYNCED_COMPLETE"
    /\ storage.checkpointStatus = "OLD_COMPLETE"
    /\ ~storage.checkpointFailed
    /\ ~storage.recoveryAttempted
    /\ storage' = [storage EXCEPT
        !.checkpointStatus = "NEW_PARTIAL",
        !.checkpointFailed = TRUE
        ]
    /\ UNCHANGED voter

InjectStableWalCorruption(status) ==
    /\ status \in CorruptWalStatuses
    /\ storage.walStatus \in {"EMPTY", "VOLATILE_RECORD_1", "VOLATILE_COMPLETE"}
    /\ storage.checkpointStatus = "OLD_COMPLETE"
    /\ storage.publishedRoot = "OLD"
    /\ ~storage.recoveryAttempted
    /\ storage' = [storage EXCEPT !.walStatus = status]
    /\ UNCHANGED voter

RecoveryDecision ==
    CASE storage.checkpointStatus = "NEW_COMPLETE" -> "NEW_COMPLETE"
      [] storage.walStatus = "FSYNCED_COMPLETE" -> "NEW_COMPLETE"
      [] storage.walStatus = "EMPTY"
            /\ storage.checkpointStatus = "OLD_COMPLETE"
            /\ storage.publishedRoot = "OLD" -> "OLD_COMPLETE"
      [] OTHER -> "FAIL_CLOSED"

RecoverStorage ==
    /\ ~storage.recoveryAttempted
    /\ storage' = [storage EXCEPT
        !.recoveryAttempted = TRUE,
        !.recoveryOutcome = RecoveryDecision,
        !.runtimeRoot =
            IF RecoveryDecision = "NEW_COMPLETE" THEN "NEW"
            ELSE IF RecoveryDecision = "OLD_COMPLETE" THEN "OLD"
            ELSE @
        ]
    /\ UNCHANGED voter

SelectProposal(proposal) ==
    /\ proposal \in Proposals
    /\ ~voter.crashed
    /\ voter.volatileLock = "NONE"
    /\ voter.persistentLock \in {"NONE", proposal}
    /\ proposal \notin voter.issuedSignatures
    /\ voter' = [voter EXCEPT !.volatileLock = proposal]
    /\ UNCHANGED storage

FsyncVoteLock(proposal) ==
    /\ proposal \in Proposals
    /\ ~voter.crashed
    /\ voter.volatileLock = proposal
    /\ voter.persistentLock = "NONE"
    /\ voter' = [voter EXCEPT !.persistentLock = proposal]
    /\ UNCHANGED storage

SignLockedVote(proposal) ==
    /\ proposal \in Proposals
    /\ ~voter.crashed
    /\ voter.volatileLock = proposal
    /\ voter.persistentLock = proposal
    /\ proposal \notin voter.issuedSignatures
    /\ voter' = [voter EXCEPT !.issuedSignatures = @ \cup {proposal}]
    /\ UNCHANGED storage

CrashVoter ==
    /\ ~voter.crashed
    /\ voter' = [voter EXCEPT
        !.crashed = TRUE,
        !.volatileLock = "NONE"
        ]
    /\ UNCHANGED storage

RecoverVoter ==
    /\ voter.crashed
    /\ voter' = [voter EXCEPT
        !.crashed = FALSE,
        !.volatileLock = voter.persistentLock
        ]
    /\ UNCHANGED storage

UnsafeSignBeforeLock(proposal) ==
    /\ UnsafeSignBeforeLockEnabled
    /\ proposal \in Proposals
    /\ ~voter.crashed
    /\ voter.volatileLock = proposal
    /\ voter.persistentLock = "NONE"
    /\ proposal \notin voter.issuedSignatures
    /\ voter' = [voter EXCEPT !.issuedSignatures = @ \cup {proposal}]
    /\ UNCHANGED storage

UnsafeRecoverIgnoringPartialWal ==
    /\ UnsafeIgnorePartialWalEnabled
    /\ storage.walStatus \in CorruptWalStatuses
    /\ ~storage.recoveryAttempted
    /\ storage' = [storage EXCEPT
        !.recoveryAttempted = TRUE,
        !.recoveryOutcome = "OLD_COMPLETE",
        !.runtimeRoot = "OLD"
        ]
    /\ UNCHANGED voter

UnsafeRollbackAnchor ==
    /\ UnsafeAnchorRollbackEnabled
    /\ storage.anchorEpoch = 1
    /\ storage.maxAnchorEpoch = 1
    /\ storage' = [storage EXCEPT !.anchorEpoch = 0]
    /\ UNCHANGED voter

UnsafeCheckpointOverwritesCommittedWal ==
    /\ UnsafeCheckpointOverwriteEnabled
    /\ storage.publishedRoot = "NEW"
    /\ storage.walStatus = "FSYNCED_COMPLETE"
    /\ ~storage.recoveryAttempted
    /\ storage' = [storage EXCEPT
        !.walStatus = "EMPTY",
        !.checkpointStatus = "NEW_PARTIAL",
        !.checkpointFailed = TRUE
        ]
    /\ UNCHANGED voter

UnsafeRecoverLosesVoteLock ==
    /\ UnsafeLoseVoteLockEnabled
    /\ voter.crashed
    /\ voter.persistentLock # "NONE"
    /\ voter' = [voter EXCEPT
        !.crashed = FALSE,
        !.volatileLock = "NONE",
        !.persistentLock = "NONE"
        ]
    /\ UNCHANGED storage

\* This mutation resets every locally persisted freshness value together. The
\* ghost directoryRollbackOccurred is outside the local directory; local fields
\* alone are intentionally indistinguishable from Init. Closing this gate needs
\* an external monotonic witness, hardware counter, or independent checkpoint.
WholeDirectoryConsistentRollback ==
    /\ WholeDirectoryRollbackEnabled
    /\ storage.publishedRoot = "NEW"
    /\ storage.checkpointStatus = "NEW_COMPLETE"
    /\ storage.anchorEpoch = 1
    /\ storage.maxAnchorEpoch = 1
    /\ storage' = [
        walStatus |-> "EMPTY",
        walEverCommitted |-> FALSE,
        checkpointStatus |-> "OLD_COMPLETE",
        checkpointFailed |-> FALSE,
        anchorEpoch |-> 0,
        maxAnchorEpoch |-> 0,
        publishedRoot |-> "OLD",
        runtimeRoot |-> "OLD",
        recoveryAttempted |-> FALSE,
        recoveryOutcome |-> "NONE",
        directoryRollbackOccurred |-> TRUE,
        externalRollbackWitnessAvailable |-> FALSE
        ]
    /\ voter' = [voter EXCEPT
        !.crashed = FALSE,
        !.volatileLock = "NONE",
        !.persistentLock = "NONE"
        ]

Next ==
    \/ AppendWalRecord1
    \/ AppendWalRecord2
    \/ FsyncCompleteWal
    \/ AdvanceRollbackAnchor
    \/ PublishNewState
    \/ CheckpointSucceeds
    \/ CheckpointFails
    \/ \E status \in CorruptWalStatuses : InjectStableWalCorruption(status)
    \/ RecoverStorage
    \/ \E proposal \in Proposals : SelectProposal(proposal)
    \/ \E proposal \in Proposals : FsyncVoteLock(proposal)
    \/ \E proposal \in Proposals : SignLockedVote(proposal)
    \/ CrashVoter
    \/ RecoverVoter
    \/ \E proposal \in Proposals : UnsafeSignBeforeLock(proposal)
    \/ UnsafeRecoverIgnoringPartialWal
    \/ UnsafeRollbackAnchor
    \/ UnsafeCheckpointOverwritesCommittedWal
    \/ UnsafeRecoverLosesVoteLock
    \/ WholeDirectoryConsistentRollback

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ storage \in StorageType
    /\ voter \in VoterType

UnfsyncedStateNeverPublished ==
    storage.publishedRoot = "NEW" => storage.walEverCommitted

PublishedStateHasDurableRecoverySource ==
    storage.publishedRoot = "NEW" =>
        storage.walStatus = "FSYNCED_COMPLETE"
        \/ storage.checkpointStatus = "NEW_COMPLETE"

CompleteWalRecoveryIsAtomic ==
    storage.recoveryAttempted
    /\ storage.walStatus = "FSYNCED_COMPLETE"
    /\ storage.checkpointStatus \in {"OLD_COMPLETE", "NEW_PARTIAL"}
    => storage.recoveryOutcome \in {"OLD_COMPLETE", "NEW_COMPLETE"}

RecoveryNeverMixesStates ==
    storage.recoveryOutcome # "MIXED"

CorruptWalFailsClosed ==
    storage.recoveryAttempted
    /\ storage.walStatus \in CorruptWalStatuses
    => storage.recoveryOutcome = "FAIL_CLOSED"

CheckpointFailurePreservesCommittedWal ==
    storage.checkpointFailed
    /\ storage.walEverCommitted
    => storage.walStatus = "FSYNCED_COMPLETE"

AnchorNeverRollsBack == storage.anchorEpoch = storage.maxAnchorEpoch

NoHonestDoubleVote == Cardinality(voter.issuedSignatures) <= 1

EveryIssuedVoteHasDurableLock ==
    voter.issuedSignatures # {} => voter.persistentLock \in voter.issuedSignatures

WholeDirectoryRollbackNeedsExternalWitness ==
    storage.directoryRollbackOccurred => storage.externalRollbackWitnessAvailable

=============================================================================

