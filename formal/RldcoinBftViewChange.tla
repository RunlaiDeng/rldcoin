-------------------------- MODULE RldcoinBftViewChange --------------------------
EXTENDS Integers, Naturals, FiniteSets, TLC

\* A bounded fixed-validator BFT view-change and certified catch-up model.
\* This is not a Rust refinement, cryptographic proof, or unbounded liveness proof.
CONSTANT FaultMode

Validators == {"v1", "v2", "v3", "v4"}
ByzantineValidators == {"v4"}
HonestValidators == Validators \ ByzantineValidators

Views == 0..3
Heights == 1..2
NetworkModes == {"PARTITIONED", "SYNCHRONOUS"}

Proposals == {"A1V1", "B1V1", "A1V2", "A2V3"}
ProposalOrNone == Proposals \cup {"NONE"}
Roots == {"GENESIS", "A1", "B1", "A2"}

Leader(view) ==
    CASE view = 0 -> "v1"
      [] view = 1 -> "v4"
      [] view = 2 -> "v2"
      [] OTHER -> "v3"

ProposalHeight(proposal) ==
    CASE proposal \in {"A1V1", "B1V1", "A1V2"} -> 1
      [] OTHER -> 2

ProposalView(proposal) ==
    CASE proposal \in {"A1V1", "B1V1"} -> 1
      [] proposal = "A1V2" -> 2
      [] OTHER -> 3

ProposalRoot(proposal) ==
    CASE proposal \in {"A1V1", "A1V2"} -> "A1"
      [] proposal = "B1V1" -> "B1"
      [] OTHER -> "A2"

ProposalParentRoot(proposal) ==
    IF ProposalHeight(proposal) = 1 THEN "GENESIS" ELSE "A1"

ProposalLeader(proposal) == Leader(ProposalView(proposal))

ProposalIsWellFormed(proposal) ==
    /\ proposal \in Proposals
    /\ ProposalView(proposal) \in Views
    /\ ProposalHeight(proposal) \in Heights
    /\ ProposalLeader(proposal) = Leader(ProposalView(proposal))

LockHeight(lock) == IF lock = "NONE" THEN 0 ELSE ProposalHeight(lock)
LockRoot(lock) == IF lock = "NONE" THEN "GENESIS" ELSE ProposalRoot(lock)

VoteRecord(validator, proposal) == [v |-> validator, p |-> proposal]
VoteRecords == [v : Validators, p : Proposals]

VARIABLES
    currentView,
    networkMode,
    knownProposals,
    votes,
    timeoutVotes,
    timeoutCerts,
    voteQCs,
    commitQCs,
    pendingLock,
    persistentLock,
    durableVoteLocks,
    maxLockHeight,
    persistentHighQC,
    maxHighQCHeight,
    crashed,
    staleMessageCount,
    receivedCatchupCerts,
    catchupAccepted,
    catchupHeight,
    catchupRoot,
    scenarioStep

coreVars == <<
    currentView,
    networkMode,
    knownProposals,
    votes,
    timeoutVotes,
    timeoutCerts,
    voteQCs,
    commitQCs,
    pendingLock,
    persistentLock,
    durableVoteLocks,
    maxLockHeight,
    persistentHighQC,
    maxHighQCHeight,
    crashed,
    staleMessageCount,
    receivedCatchupCerts,
    catchupAccepted,
    catchupHeight,
    catchupRoot
>>

vars == <<
    currentView,
    networkMode,
    knownProposals,
    votes,
    timeoutVotes,
    timeoutCerts,
    voteQCs,
    commitQCs,
    pendingLock,
    persistentLock,
    durableVoteLocks,
    maxLockHeight,
    persistentHighQC,
    maxHighQCHeight,
    crashed,
    staleMessageCount,
    receivedCatchupCerts,
    catchupAccepted,
    catchupHeight,
    catchupRoot,
    scenarioStep
>>

SafeFaultMode == FaultMode = "SAFE"
DeletePersistentLockEnabled == FaultMode = "DELETE_PERSISTENT_LOCK"
SkipQcValidationEnabled == FaultMode = "SKIP_QC_VALIDATION"
SkipParentRootCheckEnabled == FaultMode = "SKIP_PARENT_ROOT_CHECK"
BadTimeoutRuleEnabled == FaultMode = "BAD_TIMEOUT_RULE"
DropHighQcEnabled == FaultMode = "DROP_HIGH_QC_ON_RECOVERY"
CatchupWithoutCertEnabled == FaultMode = "CATCHUP_WITHOUT_CERT"

ASSUME FaultMode \in {
    "SAFE",
    "DELETE_PERSISTENT_LOCK",
    "SKIP_QC_VALIDATION",
    "SKIP_PARENT_ROOT_CHECK",
    "BAD_TIMEOUT_RULE",
    "DROP_HIGH_QC_ON_RECOVERY",
    "CATCHUP_WITHOUT_CERT"
}

Init ==
    /\ currentView = 0
    /\ networkMode = "PARTITIONED"
    /\ knownProposals = {}
    /\ votes = {}
    /\ timeoutVotes = [view \in Views |-> {}]
    /\ timeoutCerts = {}
    /\ voteQCs = {}
    /\ commitQCs = {}
    /\ pendingLock = [validator \in Validators |-> "NONE"]
    /\ persistentLock = [validator \in Validators |-> "NONE"]
    /\ durableVoteLocks = {}
    /\ maxLockHeight = [validator \in Validators |-> 0]
    /\ persistentHighQC = [validator \in Validators |-> "NONE"]
    /\ maxHighQCHeight = [validator \in Validators |-> 0]
    /\ crashed = {}
    /\ staleMessageCount = 0
    /\ receivedCatchupCerts = {}
    /\ catchupAccepted = [height \in Heights |-> "NONE"]
    /\ catchupHeight = 0
    /\ catchupRoot = "GENESIS"
    /\ scenarioStep = 0

VotersFor(proposal) ==
    {validator \in Validators : VoteRecord(validator, proposal) \in votes}

HasVotedInView(validator, view) ==
    \E proposal \in Proposals :
        /\ ProposalView(proposal) = view
        /\ VoteRecord(validator, proposal) \in votes

SafeExtendsPersistentLock(validator, proposal) ==
    LET lock == persistentLock[validator]
    IN
        \/ lock = "NONE"
        \/ /\ ProposalHeight(proposal) = LockHeight(lock)
           /\ ProposalRoot(proposal) = LockRoot(lock)
        \/ /\ ProposalHeight(proposal) = LockHeight(lock) + 1
           /\ ProposalParentRoot(proposal) = LockRoot(lock)

ParentHasCommittedCertificate(proposal) ==
    \/ ProposalHeight(proposal) = 1
    \/ \E parent \in commitQCs :
        /\ ProposalHeight(parent) = ProposalHeight(proposal) - 1
        /\ ProposalRoot(parent) = ProposalParentRoot(proposal)

ReceiveStaleMessages ==
    /\ staleMessageCount = 0
    /\ staleMessageCount' = 2
    /\ UNCHANGED <<
        currentView, networkMode, knownProposals, votes, timeoutVotes,
        timeoutCerts, voteQCs, commitQCs, pendingLock, persistentLock,
        durableVoteLocks, maxLockHeight, persistentHighQC, maxHighQCHeight,
        crashed, receivedCatchupCerts, catchupAccepted, catchupHeight,
        catchupRoot
        >>

HealNetwork ==
    /\ networkMode = "PARTITIONED"
    /\ networkMode' = "SYNCHRONOUS"
    /\ UNCHANGED <<
        currentView, knownProposals, votes, timeoutVotes, timeoutCerts,
        voteQCs, commitQCs, pendingLock, persistentLock, durableVoteLocks,
        maxLockHeight, persistentHighQC, maxHighQCHeight, crashed,
        staleMessageCount, receivedCatchupCerts, catchupAccepted,
        catchupHeight, catchupRoot
        >>

CollectHonestTimeoutVotes(view) ==
    /\ view = currentView
    /\ ~(HonestValidators \subseteq timeoutVotes[view])
    /\ timeoutVotes' =
        [timeoutVotes EXCEPT ![view] = @ \cup HonestValidators]
    /\ UNCHANGED <<
        currentView, networkMode, knownProposals, votes, timeoutCerts,
        voteQCs, commitQCs, pendingLock, persistentLock, durableVoteLocks,
        maxLockHeight, persistentHighQC, maxHighQCHeight, crashed,
        staleMessageCount, receivedCatchupCerts, catchupAccepted,
        catchupHeight, catchupRoot
        >>

CastByzantineTimeoutVote(view) ==
    /\ view = currentView
    /\ "v4" \notin timeoutVotes[view]
    /\ timeoutVotes' = [timeoutVotes EXCEPT ![view] = @ \cup {"v4"}]
    /\ UNCHANGED <<
        currentView, networkMode, knownProposals, votes, timeoutCerts,
        voteQCs, commitQCs, pendingLock, persistentLock, durableVoteLocks,
        maxLockHeight, persistentHighQC, maxHighQCHeight, crashed,
        staleMessageCount, receivedCatchupCerts, catchupAccepted,
        catchupHeight, catchupRoot
        >>

FormTimeoutCertificate(view) ==
    /\ view = currentView
    /\ view < 3
    /\ view \notin timeoutCerts
    /\ Cardinality(timeoutVotes[view]) >= 3
    /\ timeoutCerts' = timeoutCerts \cup {view}
    /\ currentView' = view + 1
    /\ pendingLock' = [validator \in Validators |-> "NONE"]
    /\ UNCHANGED <<
        networkMode, knownProposals, votes, timeoutVotes, voteQCs,
        commitQCs, persistentLock, durableVoteLocks,
        maxLockHeight, persistentHighQC, maxHighQCHeight, crashed,
        staleMessageCount, receivedCatchupCerts, catchupAccepted,
        catchupHeight, catchupRoot
        >>

ByzantineLeaderEquivocates ==
    /\ currentView = 1
    /\ Leader(currentView) \in ByzantineValidators
    /\ ~({"A1V1", "B1V1"} \subseteq knownProposals)
    /\ knownProposals' = knownProposals \cup {"A1V1", "B1V1"}
    /\ UNCHANGED <<
        currentView, networkMode, votes, timeoutVotes, timeoutCerts,
        voteQCs, commitQCs, pendingLock, persistentLock, durableVoteLocks,
        maxLockHeight, persistentHighQC, maxHighQCHeight, crashed,
        staleMessageCount, receivedCatchupCerts, catchupAccepted,
        catchupHeight, catchupRoot
        >>

ProposeHonest(proposal) ==
    /\ proposal \in {"A1V2", "A2V3"}
    /\ proposal \notin knownProposals
    /\ ProposalView(proposal) = currentView
    /\ ProposalLeader(proposal) \in HonestValidators
    /\ ProposalIsWellFormed(proposal)
    /\ ParentHasCommittedCertificate(proposal)
    /\ knownProposals' = knownProposals \cup {proposal}
    /\ UNCHANGED <<
        currentView, networkMode, votes, timeoutVotes, timeoutCerts,
        voteQCs, commitQCs, pendingLock, persistentLock, durableVoteLocks,
        maxLockHeight, persistentHighQC, maxHighQCHeight, crashed,
        staleMessageCount, receivedCatchupCerts, catchupAccepted,
        catchupHeight, catchupRoot
        >>

SelectHonestProposal(validator, proposal) ==
    /\ validator \in HonestValidators
    /\ validator \notin crashed
    /\ proposal \in knownProposals
    /\ ProposalView(proposal) = currentView
    /\ pendingLock[validator] = "NONE"
    /\ ~HasVotedInView(validator, currentView)
    /\ SafeExtendsPersistentLock(validator, proposal)
    /\ pendingLock' = [pendingLock EXCEPT ![validator] = proposal]
    /\ UNCHANGED <<
        currentView, networkMode, knownProposals, votes, timeoutVotes,
        timeoutCerts, voteQCs, commitQCs, persistentLock, durableVoteLocks,
        maxLockHeight, persistentHighQC, maxHighQCHeight, crashed,
        staleMessageCount, receivedCatchupCerts, catchupAccepted,
        catchupHeight, catchupRoot
        >>

FsyncSelectedVoteLock(validator) ==
    /\ validator \in HonestValidators
    /\ validator \notin crashed
    /\ pendingLock[validator] # "NONE"
    /\ ProposalHeight(pendingLock[validator]) >= maxLockHeight[validator]
    /\ persistentLock' =
        [persistentLock EXCEPT ![validator] = pendingLock[validator]]
    /\ durableVoteLocks' =
        durableVoteLocks \cup {VoteRecord(validator, pendingLock[validator])}
    /\ maxLockHeight' =
        [maxLockHeight EXCEPT ![validator] = ProposalHeight(pendingLock[validator])]
    /\ UNCHANGED <<
        currentView, networkMode, knownProposals, votes, timeoutVotes,
        timeoutCerts, voteQCs, commitQCs, pendingLock, persistentHighQC,
        maxHighQCHeight, crashed, staleMessageCount, receivedCatchupCerts,
        catchupAccepted, catchupHeight, catchupRoot
        >>

CastHonestVote(validator) ==
    LET proposal == pendingLock[validator]
    IN
        /\ validator \in HonestValidators
        /\ validator \notin crashed
        /\ proposal # "NONE"
        /\ persistentLock[validator] = proposal
        /\ VoteRecord(validator, proposal) \in durableVoteLocks
        /\ VoteRecord(validator, proposal) \notin votes
        /\ votes' = votes \cup {VoteRecord(validator, proposal)}
        /\ UNCHANGED <<
            currentView, networkMode, knownProposals, timeoutVotes,
            timeoutCerts, voteQCs, commitQCs, pendingLock, persistentLock,
            durableVoteLocks, maxLockHeight, persistentHighQC,
            maxHighQCHeight, crashed, staleMessageCount,
            receivedCatchupCerts, catchupAccepted, catchupHeight, catchupRoot
            >>

ClearVolatileAfterVote(validator) ==
    /\ validator \in HonestValidators
    /\ pendingLock[validator] # "NONE"
    /\ VoteRecord(validator, pendingLock[validator]) \in votes
    /\ pendingLock' = [pendingLock EXCEPT ![validator] = "NONE"]
    /\ UNCHANGED <<
        currentView, networkMode, knownProposals, votes, timeoutVotes,
        timeoutCerts, voteQCs, commitQCs, persistentLock, durableVoteLocks,
        maxLockHeight, persistentHighQC, maxHighQCHeight, crashed,
        staleMessageCount, receivedCatchupCerts, catchupAccepted,
        catchupHeight, catchupRoot
        >>

CastByzantineVote(proposal) ==
    /\ proposal \in knownProposals
    /\ ProposalView(proposal) = currentView
    /\ VoteRecord("v4", proposal) \notin votes
    /\ votes' = votes \cup {VoteRecord("v4", proposal)}
    /\ UNCHANGED <<
        currentView, networkMode, knownProposals, timeoutVotes,
        timeoutCerts, voteQCs, commitQCs, pendingLock, persistentLock,
        durableVoteLocks, maxLockHeight, persistentHighQC,
        maxHighQCHeight, crashed, staleMessageCount,
        receivedCatchupCerts, catchupAccepted, catchupHeight, catchupRoot
        >>

FormVoteQC(proposal) ==
    /\ proposal \in knownProposals
    /\ proposal \notin voteQCs
    /\ ProposalIsWellFormed(proposal)
    /\ Cardinality(VotersFor(proposal)) >= 3
    /\ voteQCs' = voteQCs \cup {proposal}
    /\ UNCHANGED <<
        currentView, networkMode, knownProposals, votes, timeoutVotes,
        timeoutCerts, commitQCs, pendingLock, persistentLock,
        durableVoteLocks, maxLockHeight, persistentHighQC,
        maxHighQCHeight, crashed, staleMessageCount,
        receivedCatchupCerts, catchupAccepted, catchupHeight, catchupRoot
        >>

ObserveAndPersistHighQC(proposal) ==
    /\ proposal \in voteQCs
    /\ \A validator \in HonestValidators :
        ProposalHeight(proposal) >= maxHighQCHeight[validator]
    /\ persistentHighQC' =
        [validator \in Validators |->
            IF validator \in HonestValidators THEN proposal
            ELSE persistentHighQC[validator]]
    /\ maxHighQCHeight' =
        [validator \in Validators |->
            IF validator \in HonestValidators THEN ProposalHeight(proposal)
            ELSE maxHighQCHeight[validator]]
    /\ UNCHANGED <<
        currentView, networkMode, knownProposals, votes, timeoutVotes,
        timeoutCerts, voteQCs, commitQCs, pendingLock, persistentLock,
        durableVoteLocks, maxLockHeight, crashed, staleMessageCount,
        receivedCatchupCerts, catchupAccepted, catchupHeight, catchupRoot
        >>

FinalizeProposal(proposal) ==
    /\ proposal \in voteQCs
    /\ proposal \notin commitQCs
    /\ ParentHasCommittedCertificate(proposal)
    /\ commitQCs' = commitQCs \cup {proposal}
    /\ UNCHANGED <<
        currentView, networkMode, knownProposals, votes, timeoutVotes,
        timeoutCerts, voteQCs, pendingLock, persistentLock,
        durableVoteLocks, maxLockHeight, persistentHighQC,
        maxHighQCHeight, crashed, staleMessageCount,
        receivedCatchupCerts, catchupAccepted, catchupHeight, catchupRoot
        >>

CrashHonestValidator(validator) ==
    /\ validator = "v1"
    /\ validator \notin crashed
    /\ \/ persistentLock[validator] # "NONE"
       \/ persistentHighQC[validator] # "NONE"
    /\ crashed' = crashed \cup {validator}
    /\ pendingLock' = [pendingLock EXCEPT ![validator] = "NONE"]
    /\ UNCHANGED <<
        currentView, networkMode, knownProposals, votes, timeoutVotes,
        timeoutCerts, voteQCs, commitQCs, persistentLock,
        durableVoteLocks, maxLockHeight, persistentHighQC,
        maxHighQCHeight, staleMessageCount, receivedCatchupCerts,
        catchupAccepted, catchupHeight, catchupRoot
        >>

RestartHonestValidator(validator) ==
    /\ validator = "v1"
    /\ validator \in crashed
    /\ crashed' = crashed \ {validator}
    /\ pendingLock' =
        [pendingLock EXCEPT ![validator] = persistentLock[validator]]
    /\ UNCHANGED <<
        currentView, networkMode, knownProposals, votes, timeoutVotes,
        timeoutCerts, voteQCs, commitQCs, persistentLock,
        durableVoteLocks, maxLockHeight, persistentHighQC,
        maxHighQCHeight, staleMessageCount, receivedCatchupCerts,
        catchupAccepted, catchupHeight, catchupRoot
        >>

ReceiveCatchupCertificateSet(certificates) ==
    /\ certificates \in {
        {"A1V2", "A2V3"},
        {"B1V1", "A2V3"}
        }
    /\ ~(certificates \subseteq receivedCatchupCerts)
    /\ receivedCatchupCerts' = receivedCatchupCerts \cup certificates
    /\ UNCHANGED <<
        currentView, networkMode, knownProposals, votes, timeoutVotes,
        timeoutCerts, voteQCs, commitQCs, pendingLock, persistentLock,
        durableVoteLocks, maxLockHeight, persistentHighQC,
        maxHighQCHeight, crashed, staleMessageCount, catchupAccepted,
        catchupHeight, catchupRoot
        >>

AcceptCertifiedCatchup(proposal) ==
    /\ proposal \in receivedCatchupCerts
    /\ ProposalHeight(proposal) = catchupHeight + 1
    /\ ProposalParentRoot(proposal) = catchupRoot
    /\ catchupAccepted[ProposalHeight(proposal)] = "NONE"
    /\ catchupAccepted' =
        [catchupAccepted EXCEPT ![ProposalHeight(proposal)] = proposal]
    /\ catchupHeight' = ProposalHeight(proposal)
    /\ catchupRoot' = ProposalRoot(proposal)
    /\ UNCHANGED <<
        currentView, networkMode, knownProposals, votes, timeoutVotes,
        timeoutCerts, voteQCs, commitQCs, pendingLock, persistentLock,
        durableVoteLocks, maxLockHeight, persistentHighQC,
        maxHighQCHeight, crashed, staleMessageCount, receivedCatchupCerts
        >>

UnsafeRestartDropsPersistentLock(validator) ==
    /\ DeletePersistentLockEnabled
    /\ validator \in crashed
    /\ persistentLock[validator] # "NONE"
    /\ crashed' = crashed \ {validator}
    /\ pendingLock' = [pendingLock EXCEPT ![validator] = "NONE"]
    /\ persistentLock' = [persistentLock EXCEPT ![validator] = "NONE"]
    /\ UNCHANGED <<
        currentView, networkMode, knownProposals, votes, timeoutVotes,
        timeoutCerts, voteQCs, commitQCs, durableVoteLocks,
        maxLockHeight, persistentHighQC, maxHighQCHeight,
        staleMessageCount, receivedCatchupCerts, catchupAccepted,
        catchupHeight, catchupRoot
        >>

UnsafeFormVoteQCFromStale(proposal) ==
    /\ SkipQcValidationEnabled
    /\ proposal \in knownProposals
    /\ proposal \notin voteQCs
    /\ VoteRecord("v4", proposal) \in votes
    /\ Cardinality(VotersFor(proposal)) < 3
    /\ staleMessageCount >= 2
    /\ voteQCs' = voteQCs \cup {proposal}
    /\ UNCHANGED <<
        currentView, networkMode, knownProposals, votes, timeoutVotes,
        timeoutCerts, commitQCs, pendingLock, persistentLock,
        durableVoteLocks, maxLockHeight, persistentHighQC,
        maxHighQCHeight, crashed, staleMessageCount,
        receivedCatchupCerts, catchupAccepted, catchupHeight, catchupRoot
        >>

UnsafeAcceptWrongParent(proposal) ==
    /\ SkipParentRootCheckEnabled
    /\ proposal \in receivedCatchupCerts
    /\ ProposalHeight(proposal) = catchupHeight + 1
    /\ ProposalParentRoot(proposal) # catchupRoot
    /\ catchupAccepted[ProposalHeight(proposal)] = "NONE"
    /\ catchupAccepted' =
        [catchupAccepted EXCEPT ![ProposalHeight(proposal)] = proposal]
    /\ catchupHeight' = ProposalHeight(proposal)
    /\ catchupRoot' = ProposalRoot(proposal)
    /\ UNCHANGED <<
        currentView, networkMode, knownProposals, votes, timeoutVotes,
        timeoutCerts, voteQCs, commitQCs, pendingLock, persistentLock,
        durableVoteLocks, maxLockHeight, persistentHighQC,
        maxHighQCHeight, crashed, staleMessageCount, receivedCatchupCerts
        >>

UnsafeFormTimeoutFromStale(view) ==
    /\ BadTimeoutRuleEnabled
    /\ view = currentView
    /\ view < 3
    /\ view \notin timeoutCerts
    /\ staleMessageCount >= 2
    /\ Cardinality(timeoutVotes[view]) < 3
    /\ timeoutCerts' = timeoutCerts \cup {view}
    /\ currentView' = view + 1
    /\ UNCHANGED <<
        networkMode, knownProposals, votes, timeoutVotes, voteQCs,
        commitQCs, pendingLock, persistentLock, durableVoteLocks,
        maxLockHeight, persistentHighQC, maxHighQCHeight, crashed,
        staleMessageCount, receivedCatchupCerts, catchupAccepted,
        catchupHeight, catchupRoot
        >>

UnsafeRestartDropsHighQC(validator) ==
    /\ DropHighQcEnabled
    /\ validator \in crashed
    /\ persistentHighQC[validator] # "NONE"
    /\ crashed' = crashed \ {validator}
    /\ pendingLock' =
        [pendingLock EXCEPT ![validator] = persistentLock[validator]]
    /\ persistentHighQC' =
        [persistentHighQC EXCEPT ![validator] = "NONE"]
    /\ UNCHANGED <<
        currentView, networkMode, knownProposals, votes, timeoutVotes,
        timeoutCerts, voteQCs, commitQCs, persistentLock,
        durableVoteLocks, maxLockHeight, maxHighQCHeight,
        staleMessageCount, receivedCatchupCerts, catchupAccepted,
        catchupHeight, catchupRoot
        >>

UnsafeCatchupWithoutCertificate(proposal) ==
    /\ CatchupWithoutCertEnabled
    /\ proposal \in Proposals \ receivedCatchupCerts
    /\ ProposalHeight(proposal) = catchupHeight + 1
    /\ ProposalParentRoot(proposal) = catchupRoot
    /\ catchupAccepted[ProposalHeight(proposal)] = "NONE"
    /\ catchupAccepted' =
        [catchupAccepted EXCEPT ![ProposalHeight(proposal)] = proposal]
    /\ catchupHeight' = ProposalHeight(proposal)
    /\ catchupRoot' = ProposalRoot(proposal)
    /\ UNCHANGED <<
        currentView, networkMode, knownProposals, votes, timeoutVotes,
        timeoutCerts, voteQCs, commitQCs, pendingLock, persistentLock,
        durableVoteLocks, maxLockHeight, persistentHighQC,
        maxHighQCHeight, crashed, staleMessageCount, receivedCatchupCerts
        >>

ConsensusSafetyNext ==
    /\ \/ ReceiveStaleMessages
       \/ HealNetwork
       \/ \E view \in Views : CollectHonestTimeoutVotes(view)
       \/ \E view \in Views : CastByzantineTimeoutVote(view)
       \/ \E view \in Views : FormTimeoutCertificate(view)
       \/ ByzantineLeaderEquivocates
       \/ ProposeHonest("A1V2")
       \/ \E validator \in HonestValidators, proposal \in Proposals :
            SelectHonestProposal(validator, proposal)
       \/ \E validator \in HonestValidators : FsyncSelectedVoteLock(validator)
       \/ \E validator \in HonestValidators : CastHonestVote(validator)
       \/ \E proposal \in Proposals : CastByzantineVote(proposal)
       \/ \E proposal \in Proposals : FormVoteQC(proposal)
       \/ \E proposal \in Proposals : ObserveAndPersistHighQC(proposal)
       \/ \E proposal \in Proposals : FinalizeProposal(proposal)
       \/ \E validator \in HonestValidators : CrashHonestValidator(validator)
       \/ \E validator \in HonestValidators : RestartHonestValidator(validator)
       \/ \E validator \in HonestValidators :
            UnsafeRestartDropsPersistentLock(validator)
       \/ \E proposal \in Proposals : UnsafeFormVoteQCFromStale(proposal)
       \/ \E view \in Views : UnsafeFormTimeoutFromStale(view)
       \/ \E validator \in HonestValidators : UnsafeRestartDropsHighQC(validator)
    /\ UNCHANGED scenarioStep

ConsensusSafetySpec == Init /\ [][ConsensusSafetyNext]_vars

CatchupSafetyNext ==
    /\ \/ \E certificates \in {
            {"A1V2", "A2V3"},
            {"B1V1", "A2V3"}
            } : ReceiveCatchupCertificateSet(certificates)
       \/ \E proposal \in Proposals : AcceptCertifiedCatchup(proposal)
       \/ \E proposal \in Proposals : UnsafeAcceptWrongParent(proposal)
       \/ \E proposal \in Proposals : UnsafeCatchupWithoutCertificate(proposal)
    /\ UNCHANGED scenarioStep

CatchupSafetySpec == Init /\ [][CatchupSafetyNext]_vars

\* The progress specification is a single finite fair schedule. It witnesses
\* partition recovery, Byzantine equivocation tolerance, two commits, and
\* ordered catch-up; it deliberately does not claim arbitrary-network liveness.

ScenarioCollectTimeouts(view) ==
    /\ view = currentView
    /\ timeoutVotes' = [timeoutVotes EXCEPT ![view] = HonestValidators]
    /\ UNCHANGED <<
        currentView, networkMode, knownProposals, votes, timeoutCerts,
        voteQCs, commitQCs, pendingLock, persistentLock, durableVoteLocks,
        maxLockHeight, persistentHighQC, maxHighQCHeight, crashed,
        staleMessageCount, receivedCatchupCerts, catchupAccepted,
        catchupHeight, catchupRoot
        >>

ScenarioFormTimeoutAndSetNetwork(view, nextNetwork) ==
    /\ view = currentView
    /\ view < 3
    /\ Cardinality(timeoutVotes[view]) >= 3
    /\ timeoutCerts' = timeoutCerts \cup {view}
    /\ currentView' = view + 1
    /\ networkMode' = nextNetwork
    /\ pendingLock' = [validator \in Validators |-> "NONE"]
    /\ UNCHANGED <<
        knownProposals, votes, timeoutVotes, voteQCs, commitQCs,
        persistentLock, durableVoteLocks, maxLockHeight,
        persistentHighQC, maxHighQCHeight, crashed, staleMessageCount,
        receivedCatchupCerts, catchupAccepted, catchupHeight, catchupRoot
        >>

ScenarioRecordStaleMessages ==
    /\ staleMessageCount = 0
    /\ staleMessageCount' = 2
    /\ UNCHANGED <<
        currentView, networkMode, knownProposals, votes, timeoutVotes,
        timeoutCerts, voteQCs, commitQCs, pendingLock, persistentLock,
        durableVoteLocks, maxLockHeight, persistentHighQC,
        maxHighQCHeight, crashed, receivedCatchupCerts, catchupAccepted,
        catchupHeight, catchupRoot
        >>

ScenarioPersistAllHonestLocks(proposal) ==
    /\ proposal \in knownProposals
    /\ ProposalView(proposal) = currentView
    /\ \A validator \in HonestValidators :
        /\ validator \notin crashed
        /\ ~HasVotedInView(validator, currentView)
        /\ SafeExtendsPersistentLock(validator, proposal)
    /\ pendingLock' =
        [validator \in Validators |->
            IF validator \in HonestValidators THEN proposal
            ELSE pendingLock[validator]]
    /\ persistentLock' =
        [validator \in Validators |->
            IF validator \in HonestValidators THEN proposal
            ELSE persistentLock[validator]]
    /\ durableVoteLocks' = durableVoteLocks \cup
        {VoteRecord(validator, proposal) : validator \in HonestValidators}
    /\ maxLockHeight' =
        [validator \in Validators |->
            IF validator \in HonestValidators THEN ProposalHeight(proposal)
            ELSE maxLockHeight[validator]]
    /\ UNCHANGED <<
        currentView, networkMode, knownProposals, votes, timeoutVotes,
        timeoutCerts, voteQCs, commitQCs, persistentHighQC,
        maxHighQCHeight, crashed, staleMessageCount, receivedCatchupCerts,
        catchupAccepted, catchupHeight, catchupRoot
        >>

ScenarioVoteQcCommitAndPersistHighQC(proposal) ==
    LET allVotes == {VoteRecord(validator, proposal) : validator \in Validators}
    IN
        /\ proposal \in knownProposals
        /\ \A validator \in HonestValidators :
            VoteRecord(validator, proposal) \in durableVoteLocks
        /\ ParentHasCommittedCertificate(proposal)
        /\ votes' = votes \cup allVotes
        /\ voteQCs' = voteQCs \cup {proposal}
        /\ commitQCs' = commitQCs \cup {proposal}
        /\ pendingLock' =
            [validator \in Validators |->
                IF validator \in HonestValidators THEN "NONE"
                ELSE pendingLock[validator]]
        /\ persistentHighQC' =
            [validator \in Validators |->
                IF validator \in HonestValidators THEN proposal
                ELSE persistentHighQC[validator]]
        /\ maxHighQCHeight' =
            [validator \in Validators |->
                IF validator \in HonestValidators THEN ProposalHeight(proposal)
                ELSE maxHighQCHeight[validator]]
        /\ UNCHANGED <<
            currentView, networkMode, knownProposals, timeoutVotes,
            timeoutCerts, persistentLock, durableVoteLocks, maxLockHeight,
            crashed, staleMessageCount, receivedCatchupCerts,
            catchupAccepted, catchupHeight, catchupRoot
            >>

ScenarioReceiveCommittedChain ==
    /\ {"A1V2", "A2V3"} \subseteq commitQCs
    /\ receivedCatchupCerts' =
        receivedCatchupCerts \cup {"A1V2", "A2V3"}
    /\ UNCHANGED <<
        currentView, networkMode, knownProposals, votes, timeoutVotes,
        timeoutCerts, voteQCs, commitQCs, pendingLock, persistentLock,
        durableVoteLocks, maxLockHeight, persistentHighQC,
        maxHighQCHeight, crashed, staleMessageCount, catchupAccepted,
        catchupHeight, catchupRoot
        >>

ProgressNext ==
    \/ /\ scenarioStep = 0
       /\ ScenarioCollectTimeouts(0)
       /\ scenarioStep' = 1
    \/ /\ scenarioStep = 1
       /\ ScenarioFormTimeoutAndSetNetwork(0, "SYNCHRONOUS")
       /\ scenarioStep' = 2
    \/ /\ scenarioStep = 2
       /\ ByzantineLeaderEquivocates
       /\ scenarioStep' = 3
    \/ /\ scenarioStep = 3
       /\ ScenarioRecordStaleMessages
       /\ scenarioStep' = 4
    \/ /\ scenarioStep = 4
       /\ ScenarioCollectTimeouts(1)
       /\ scenarioStep' = 5
    \/ /\ scenarioStep = 5
       /\ ScenarioFormTimeoutAndSetNetwork(1, "SYNCHRONOUS")
       /\ scenarioStep' = 6
    \/ /\ scenarioStep = 6
       /\ ProposeHonest("A1V2")
       /\ scenarioStep' = 7
    \/ /\ scenarioStep = 7
       /\ ScenarioPersistAllHonestLocks("A1V2")
       /\ scenarioStep' = 8
    \/ /\ scenarioStep = 8
       /\ ScenarioVoteQcCommitAndPersistHighQC("A1V2")
       /\ scenarioStep' = 9
    \/ /\ scenarioStep = 9
       /\ ScenarioCollectTimeouts(2)
       /\ scenarioStep' = 10
    \/ /\ scenarioStep = 10
       /\ ScenarioFormTimeoutAndSetNetwork(2, "SYNCHRONOUS")
       /\ scenarioStep' = 11
    \/ /\ scenarioStep = 11
       /\ ProposeHonest("A2V3")
       /\ scenarioStep' = 12
    \/ /\ scenarioStep = 12
       /\ ScenarioPersistAllHonestLocks("A2V3")
       /\ scenarioStep' = 13
    \/ /\ scenarioStep = 13
       /\ ScenarioVoteQcCommitAndPersistHighQC("A2V3")
       /\ scenarioStep' = 14
    \/ /\ scenarioStep = 14
       /\ ScenarioReceiveCommittedChain
       /\ scenarioStep' = 15
    \/ /\ scenarioStep = 15
       /\ AcceptCertifiedCatchup("A1V2")
       /\ scenarioStep' = 16
    \/ /\ scenarioStep = 16
       /\ AcceptCertifiedCatchup("A2V3")
       /\ scenarioStep' = 17

ProgressSpec == Init /\ [][ProgressNext]_vars /\ WF_vars(ProgressNext)

ProgressComplete ==
    /\ scenarioStep = 17
    /\ "A1V2" \in commitQCs
    /\ "A2V3" \in commitQCs
    /\ catchupHeight = 2
    /\ catchupRoot = "A2"

BoundedFairProgress == <>ProgressComplete

TypeOK ==
    /\ currentView \in Views
    /\ networkMode \in NetworkModes
    /\ knownProposals \subseteq Proposals
    /\ votes \subseteq VoteRecords
    /\ timeoutVotes \in [Views -> SUBSET Validators]
    /\ timeoutCerts \subseteq Views
    /\ voteQCs \subseteq Proposals
    /\ commitQCs \subseteq Proposals
    /\ pendingLock \in [Validators -> ProposalOrNone]
    /\ persistentLock \in [Validators -> ProposalOrNone]
    /\ durableVoteLocks \subseteq VoteRecords
    /\ maxLockHeight \in [Validators -> 0..2]
    /\ persistentHighQC \in [Validators -> ProposalOrNone]
    /\ maxHighQCHeight \in [Validators -> 0..2]
    /\ crashed \subseteq HonestValidators
    /\ staleMessageCount \in {0, 2}
    /\ receivedCatchupCerts \subseteq Proposals
    /\ catchupAccepted \in [Heights -> ProposalOrNone]
    /\ catchupHeight \in 0..2
    /\ catchupRoot \in Roots
    /\ scenarioStep \in 0..17

PersistentLockNeverRegresses ==
    \A validator \in HonestValidators :
        LockHeight(persistentLock[validator]) = maxLockHeight[validator]

PersistentHighQCNeverRegresses ==
    \A validator \in HonestValidators :
        LockHeight(persistentHighQC[validator]) = maxHighQCHeight[validator]

HighQCIsCertified ==
    \A validator \in HonestValidators :
        persistentHighQC[validator] # "NONE" =>
            persistentHighQC[validator] \in voteQCs

EveryHonestVoteWasDurablyLocked ==
    \A vote \in votes :
        vote.v \in HonestValidators => vote \in durableVoteLocks

NoHonestDoubleVoteInView ==
    \A validator \in HonestValidators :
        \A first, second \in Proposals :
            /\ VoteRecord(validator, first) \in votes
            /\ VoteRecord(validator, second) \in votes
            /\ ProposalView(first) = ProposalView(second)
            => first = second

HonestVotesStayOnOneRootPerHeight ==
    \A validator \in HonestValidators :
        \A first, second \in Proposals :
            /\ VoteRecord(validator, first) \in votes
            /\ VoteRecord(validator, second) \in votes
            /\ ProposalHeight(first) = ProposalHeight(second)
            => ProposalRoot(first) = ProposalRoot(second)

ByzantineAndStaleMessagesCannotMakeQC ==
    \A proposal \in voteQCs :
        /\ ProposalIsWellFormed(proposal)
        /\ Cardinality(VotersFor(proposal)) >= 3
        /\ Cardinality(VotersFor(proposal) \cap HonestValidators) >= 2

TimeoutCertificatesNeedQuorum ==
    \A view \in timeoutCerts :
        /\ Cardinality(timeoutVotes[view]) >= 3
        /\ Cardinality(timeoutVotes[view] \cap HonestValidators) >= 2

NoDoubleFinality ==
    \A first, second \in commitQCs :
        ProposalHeight(first) = ProposalHeight(second) =>
            ProposalRoot(first) = ProposalRoot(second)

CommittedChainIsContinuous ==
    \A child \in commitQCs :
        ProposalHeight(child) = 2 =>
            \E parent \in commitQCs :
                /\ ProposalHeight(parent) = 1
                /\ ProposalRoot(parent) = ProposalParentRoot(child)

CatchupOnlyAcceptsCertifiedCommits ==
    \A height \in Heights :
        catchupAccepted[height] # "NONE" =>
            catchupAccepted[height] \in receivedCatchupCerts

CatchupHasNoHeightHoles ==
    /\ (catchupHeight = 0) =>
        /\ catchupAccepted[1] = "NONE"
        /\ catchupAccepted[2] = "NONE"
    /\ (catchupHeight = 1) =>
        /\ catchupAccepted[1] # "NONE"
        /\ catchupAccepted[2] = "NONE"
    /\ (catchupHeight = 2) =>
        /\ catchupAccepted[1] # "NONE"
        /\ catchupAccepted[2] # "NONE"

CatchupChainIsContinuous ==
    /\ (catchupAccepted[1] # "NONE") =>
        ProposalParentRoot(catchupAccepted[1]) = "GENESIS"
    /\ (catchupAccepted[2] # "NONE") =>
        /\ catchupAccepted[1] # "NONE"
        /\ ProposalParentRoot(catchupAccepted[2]) =
            ProposalRoot(catchupAccepted[1])
    /\ catchupRoot =
        CASE catchupHeight = 0 -> "GENESIS"
          [] catchupHeight = 1 -> ProposalRoot(catchupAccepted[1])
          [] OTHER -> ProposalRoot(catchupAccepted[2])

=============================================================================
