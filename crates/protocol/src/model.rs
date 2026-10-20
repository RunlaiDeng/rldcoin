use crate::{
    codec::{Amount, Blob, Id, hash, sorted_unique},
    record,
};
use anyhow::{Result, ensure};
use minicbor::{Decode, Encode};
use serde::{Deserialize, Serialize};

record!(Owner {threshold:u16  =>  0,keys:Vec<Id>  =>  1});
impl Owner {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.keys.is_empty()
                && self.keys.len() <= 16
                && self.threshold > 0
                && self.threshold as usize <= self.keys.len()
                && sorted_unique(&self.keys),
            "owner policy"
        );
        Ok(())
    }
    pub fn id(&self, c: Id) -> Id {
        hash("RLD-OWNER", c, self)
    }
}
record!(Signature {key:Id  =>  0,bytes:Blob  =>  1});
record!(Authorization {owner:Owner  =>  0,signatures:Vec<Signature>  =>  1});
record!(Component {cover:Id  =>  0,amount:Amount  =>  1});
record!(Allocation {owner:Owner  =>  0,components:Vec<Component>  =>  1});
record!(Output {id:Id  =>  0,owner:Owner  =>  1,home:Id  =>  2,components:Vec<Component>  =>  3});
record!(Lift {from:Id  =>  0,to:Id  =>  1,amount:Amount  =>  2});
record!(FamilyRule {family:Id  =>  0,anchor:Id  =>  1,succession:Vec<Id>  =>  2,signatures:Vec<Id>  =>  3,custody:Id  =>  4});
record!(Cover {families:Vec<FamilyRule>  =>  0,proof_suites:Vec<Id>  =>  1,custody_rules:Vec<Id>  =>  2,incident_rule:Id  =>  3});
impl Cover {
    pub fn id(&self, c: Id) -> Id {
        hash("RLD-COVER", c, self)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.families.is_empty()
                && self.families.len() <= 4096
                && self.families.windows(2).all(|w| w[0].family < w[1].family),
            "cover families"
        );
        ensure!(
            sorted_unique(&self.proof_suites) && sorted_unique(&self.custody_rules),
            "cover suites"
        );
        for f in &self.families {
            ensure!(
                !f.succession.is_empty()
                    && !f.signatures.is_empty()
                    && sorted_unique(&f.succession)
                    && sorted_unique(&f.signatures),
                "family profiles"
            )
        }
        Ok(())
    }
    pub fn subset_of(&self, b: &Self) -> Result<()> {
        self.validate()?;
        b.validate()?;
        ensure!(
            self.incident_rule == b.incident_rule
                && self.proof_suites.iter().all(|v| b.proof_suites.contains(v))
                && self.custody_rules == b.custody_rules,
            "cover security change"
        );
        for a in &self.families {
            let x = b
                .families
                .iter()
                .find(|f| f.family == a.family)
                .ok_or_else(|| anyhow::anyhow!("cover missing family"))?;
            ensure!(
                x.anchor == a.anchor
                    && x.custody == a.custody
                    && a.succession.iter().all(|v| x.succession.contains(v))
                    && a.signatures.iter().all(|v| x.signatures.contains(v)),
                "unsafe cover lift"
            )
        }
        Ok(())
    }
}
record!(Limits {inputs:u16  =>  0,outputs:u16  =>  1,components:u16  =>  2,families:u32  =>  3,controllers:u32  =>  4,capsule_bytes:u32  =>  5,receipt_bytes:u32  =>  6,objects:u32  =>  7});
impl Default for Limits {
    fn default() -> Self {
        Self {
            inputs: 64,
            outputs: 64,
            components: 64,
            families: 4096,
            controllers: 4096,
            capsule_bytes: crate::MAX_CAPSULE as u32,
            receipt_bytes: crate::MAX_RECEIPT as u32,
            objects: 4096,
        }
    }
}
impl Limits {
    pub fn validate(&self) -> Result<()> {
        let m = Self::default();
        ensure!(
            self.inputs > 0
                && self.inputs <= m.inputs
                && self.outputs > 0
                && self.outputs <= m.outputs
                && self.components > 0
                && self.components <= m.components
                && self.families > 0
                && self.families <= m.families
                && self.controllers > 0
                && self.controllers <= m.controllers
                && self.capsule_bytes > 0
                && self.capsule_bytes <= m.capsule_bytes
                && self.receipt_bytes > 0
                && self.receipt_bytes <= m.receipt_bytes
                && self.objects > 0
                && self.objects <= m.objects,
            "resource limits"
        );
        Ok(())
    }
}
record!(ProofProfile {native_image:Id  =>  0,controller_image:Id  =>  1,control_root:Id  =>  2,verifier_parameters:Id  =>  3,backend:String  =>  4});
record!(Currency {bootstrap:Id  =>  0,roots:u32  =>  1,slots:u32  =>  2,reward:Amount  =>  3,atoms:Amount  =>  4,cap:Amount  =>  5,proof:ProofProfile  =>  6,limits:Limits  =>  7,succession:Id  =>  8,work_profile:Id  =>  9,encoding:String  =>  10,bootstrap_validators:Vec<Id> => 11,network:String => 12});
impl Currency {
    pub fn id(&self) -> Id {
        Id::digest(&crate::codec::encode(&(
            "RLD-CURRENCY",
            crate::PROTOCOL,
            self,
        )))
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.roots == crate::ROOTS
                && self.slots == crate::SLOTS
                && self.reward.0 == crate::REWARD
                && self.atoms.0 == crate::ATOMS
                && self.cap.0 == crate::CAP,
            "monetary constants"
        );
        ensure!(
            self.encoding == crate::ENCODING
                && self.proof.backend == "risc0-zkvm-3.0.6-succinct"
                && self.proof.native_image != Id::ZERO
                && self.proof.controller_image != Id::ZERO
                && self.proof.control_root != Id::ZERO
                && self.proof.verifier_parameters != Id::ZERO,
            "unbound proof programs"
        );
        ensure!(
            self.work_profile == crate::work::profile_id(),
            "work profile"
        );
        ensure!(
            !self.bootstrap_validators.is_empty()
                && self.bootstrap_validators.len() <= 127
                && (self.bootstrap_validators.len() - 1) % 3 == 0
                && sorted_unique(&self.bootstrap_validators),
            "bootstrap identities"
        );
        ensure!(
            self.network == "research" || self.network == "monetary",
            "network purpose"
        );
        self.limits.validate()
    }
}
record!(DomainIdentity {key:Id  =>  0,nonce:Id  =>  1});
impl DomainIdentity {
    pub fn id(&self) -> Id {
        Id::digest(&crate::codec::encode(&(
            "RLD-DOMAIN",
            crate::PROTOCOL,
            self,
        )))
    }
}
record!(Validator {identity:Id  =>  0,native_root:Id  =>  1,controller_root:Id  =>  2});
record!(FeePolicy {service_owner:Owner => 0,archive_owner:Owner => 1,archive_custodians:Owner => 2,minimum_service:Amount => 3,minimum_archive:Amount => 4,minimum_work_author:Amount => 5});
impl FeePolicy {
    pub fn id(&self, c: Id) -> Id {
        hash("RLD-FEE-POLICY", c, self)
    }
    pub fn validate(&self) -> Result<()> {
        self.service_owner.validate()?;
        self.archive_owner.validate()?;
        self.archive_custodians.validate()?;
        ensure!(
            self.minimum_service.0 > 0
                && self.minimum_archive.0 > 0
                && self.minimum_work_author.0 > 0,
            "positive fee policy"
        );
        Ok(())
    }
}
record!(Configuration {currency:Id  =>  0,domain:Id  =>  1,epoch:u64  =>  2,first_sequence:u64  =>  3,pool_epoch:u64  =>  4,validators:Vec<Validator>  =>  5,initial_anchor:Id  =>  6,succession:Id  =>  7,signature_profile:Id  =>  8,custody_profile:Id  =>  9,limits:Limits  =>  10,fee_policy:FeePolicy => 11});
impl Configuration {
    pub fn id(&self) -> Id {
        hash("RLD-CONFIG", self.currency, self)
    }
    pub fn quorum(&self) -> Result<usize> {
        self.validate()?;
        Ok(2 * ((self.validators.len() - 1) / 3) + 1)
    }
    pub fn validate(&self) -> Result<()> {
        self.fee_policy.validate()?;
        let n = self.validators.len();
        ensure!(
            n >= 1
                && n <= 127
                && (n - 1) % 3 == 0
                && self
                    .validators
                    .windows(2)
                    .all(|w| w[0].identity < w[1].identity),
            "validator roster"
        );
        ensure!(
            self.signature_profile == Id::digest(b"RLD-ED25519-HEIGHT-POOL-1")
                && self.succession == Id::digest(b"RLD-HANDOFF-1"),
            "unsupported executable consensus/signature profile"
        );
        for v in &self.validators {
            crate::crypto::validate_public_key(v.identity)?;
            ensure!(
                v.identity != Id::ZERO
                    && v.native_root != Id::ZERO
                    && v.controller_root != Id::ZERO
                    && v.native_root != v.controller_root,
                "key roots"
            )
        }
        self.limits.validate()
    }
    pub fn accepts(&self, cover: &Cover) -> Result<()> {
        let f = cover
            .families
            .iter()
            .find(|f| f.family == self.domain)
            .ok_or_else(|| anyhow::anyhow!("executing family not covered"))?;
        ensure!(
            f.anchor == self.initial_anchor
                && f.succession.contains(&self.succession)
                && f.signatures.contains(&self.signature_profile)
                && f.custody == self.custody_profile,
            "authority cover mismatch"
        );
        Ok(())
    }
}
record!(PublicInventory {validator:Id  =>  0,native:Vec<Id>  =>  1,controller:Vec<Id>  =>  2});
record!(DomainGenesis {identity:DomainIdentity  =>  0,configuration:Configuration  =>  1,attestations:Vec<Signature>  =>  2,admission:InventoryAdmission => 3,identity_signature:Signature => 4});
record!(FeeSchedule {minimum_service:Amount  =>  0,minimum_archive:Amount  =>  1,minimum_work_author:Amount  =>  2,cancel_max:Amount  =>  3,recovery_max:Amount  =>  4});
record!(Fee {kind:u8  =>  0,payout:Allocation  =>  1,mint:Option<MintEvidence>  =>  2,reserve:Option<Service> => 3});
record!(MintRecord {event:Id  =>  0,grant:Id  =>  1,root:u32  =>  2,slot:u32  =>  3,owner:Owner  =>  4});
record!(MintEvidence {record:MintRecord  =>  0,certified:Option<Certified>  =>  1,inclusion:Option<StateWitness>  =>  2});
record!(Grant {id:Id  =>  0,root:u32  =>  1,lo:u32  =>  2,hi:u32  =>  3,home:Id  =>  4,creation:Id  =>  5,cover:Id  =>  6});
record!(Segment {grant:Id  =>  0,lo:u32  =>  1,hi:u32  =>  2,cursor:u32  =>  3,mint_anchor:Id  =>  4});
record!(Range {grant:Id  =>  0,root:u32  =>  1,lo:u32  =>  2,hi:u32  =>  3,cover:Id  =>  4});
record!(Work {grant:Id  =>  0,slot:u32  =>  1,home:Id  =>  2,anchor:Id  =>  3,payout:Owner  =>  4,cover:Id  =>  5,nonce:Id  =>  6,signature:Signature  =>  7});
record!(PlacementWork {range:Range  =>  0,source:Id  =>  1,destination:Id  =>  2,coupon:Id  =>  3,claimant:Owner  =>  4,nonce:Id  =>  5,authorization:Authorization  =>  6});
record!(Coupon {family:Id  =>  0,index:u32  =>  1,source:Id  =>  2,destination:Id  =>  3,recipient:Owner  =>  4,kind:u8  =>  5,max_amount:Amount  =>  6,max_slots:u32  =>  7,roots:Vec<u32>  =>  8,covers:Vec<Id>  =>  9,use_policy:Owner  =>  10,source_family:FamilyRule  =>  11,fees:FeeSchedule  =>  12,cancel_policy:Owner  =>  13,recovery_policy:Owner  =>  14,proof:ProofProfile  =>  15,limits:Limits  =>  16,source_fee_policy:FeePolicy => 17,source_sponsor:Id => 18,destination_fee_policy:FeePolicy => 19,close_policy:Owner => 20});
pub fn is_public_policy(policy: &Owner) -> bool {
    policy.threshold == 0 && policy.keys.is_empty()
}
pub fn validate_use_policy(policy: &Owner) -> Result<()> {
    if is_public_policy(policy) {
        Ok(())
    } else {
        policy.validate()
    }
}
pub fn bound_claim_policy(template: &Owner, creator: &Owner, kind: u8) -> Owner {
    if kind == 1 && is_public_policy(template) {
        creator.clone()
    } else {
        template.clone()
    }
}
impl Coupon {
    pub fn id(&self, c: Id) -> Id {
        hash("RLD-COUPON", c, &(self.family, self.index))
    }
    pub fn digest(&self, c: Id) -> Id {
        hash("RLD-COUPON-TERMS", c, self)
    }
}
record!(Family {id:Id  =>  0,source:Id  =>  1,destination:Id  =>  2,nonce:Id  =>  3,issuer:Owner  =>  4,leaf_root:Id  =>  5,count:u32  =>  6,funding:Id  =>  7,units:u64  =>  8,source_funding:Id => 9});
record!(CouponEvidence {coupon:Coupon  =>  0,family:Family  =>  1,leaf:crate::merkle::Membership  =>  2,certified:Certified  =>  3,reservation:StateWitness  =>  4});
record!(CapabilityClosure {coupon:CouponEvidence => 0,source:Certified => 1,delegation:Delegation => 2,inclusion:StateWitness => 3});
record!(Ticket {id:Id  =>  0,coupon:Id  =>  1,source:Id  =>  2,destination:Id  =>  3,creator:Owner  =>  4,kind:u8  =>  5,inputs:Vec<Id>  =>  6,range:Option<Range>  =>  7,recipient:Allocation  =>  8,destination_fee:Allocation  =>  9,fees:Vec<Fee>  =>  10,change:Vec<Allocation>  =>  11,lifts:Vec<Lift>  =>  12,cancel_policy:Owner  =>  13,recovery_policy:Owner  =>  14,cancel_fee:Amount  =>  15,recovery_fee:Amount  =>  16,nonce:Id  =>  17,cancel_fee_payout:Owner  =>  18,recovery_fee_payout:Owner  =>  19});
impl Ticket {
    pub fn identity(&self, c: Id) -> Id {
        hash(
            "RLD-CONTROLLER-ID",
            c,
            &(self.source, &self.creator, self.nonce),
        )
    }
    pub fn digest(&self, c: Id) -> Id {
        hash("RLD-TICKET", c, self)
    }
}
record!(KeyLeaf {validator:Id  =>  0,key:Id  =>  1,path:Vec<Id>  =>  2});
record!(Controller {id:Id  =>  0,source:Id  =>  1,ticket:Ticket  =>  2,coupon:Coupon  =>  3,configuration:Configuration  =>  4,pool_index:u32  =>  5,keys:Vec<KeyLeaf>  =>  6,escrow:Vec<Component>  =>  7,material_root:Id  =>  8,limits:Limits  =>  9});
record!(Checkpoint {profile:String  =>  0,currency:Id  =>  1,domain:Id  =>  2,sequence:u64  =>  3,predecessor:Id  =>  4,old_root:Id  =>  5,new_root:Id  =>  6,batch:Id  =>  7,configuration:Id  =>  8,material_root:Id  =>  9});
impl Checkpoint {
    pub fn id(&self) -> Id {
        hash("RLD-CHECKPOINT", self.currency, self)
    }
}
record!(Terminal {currency:Id  =>  0,controller:Id  =>  1,initial:Id  =>  2,source_checkpoint:Id  =>  3,decision:u8  =>  4,ticket_or_return:Id  =>  5,material_root:Id  =>  6});
impl Terminal {
    pub fn id(&self) -> Id {
        hash("RLD-TERMINAL", self.currency, self)
    }
}
record!(Vote {currency:Id  =>  0,namespace:Id  =>  1,configuration:Id  =>  2,sequence:u64  =>  3,view:u64  =>  4,phase:u8  =>  5,statement:Id  =>  6,validator:Id  =>  7,key:KeyLeaf  =>  8,signature:Signature  =>  9});
record!(Quorum {votes:Vec<Vote>  =>  0});
record!(Certified {header:Checkpoint  =>  0,receipt:Blob  =>  1,qc:Quorum  =>  2,configuration:Configuration  =>  3});
record!(StateWitness {collection:String  =>  0,entry:crate::merkle::Membership  =>  1,top:crate::merkle::Membership  =>  2});
record!(Creation {controller:Controller  =>  0,source:Certified  =>  1,delegation:StateWitness  =>  2,coupon_use:StateWitness  =>  3});
record!(Release {creation:Creation  =>  0,terminal:Terminal  =>  1,receipt:Blob  =>  2,qc:Quorum  =>  3,covers:Vec<Cover>  =>  4,material:Blob  =>  5});
record!(Rejected {release:Release  =>  0,destination:Certified  =>  1,decision:StateWitness  =>  2,leaf_decision:StateWitness  =>  3});
record!(Cancellation {controller:Id  =>  0,terminal:Terminal  =>  1,qc:Quorum  =>  2,authorization:Authorization  =>  3,source_header:Checkpoint  =>  4,source_qc:Quorum  =>  5,delegation:StateWitness  =>  6,coupon_use:StateWitness  =>  7});
record!(Service {id:Id  =>  0,owner:Owner  =>  1,beneficiary:Id  =>  2,family:Id  =>  3,balance:Vec<Component>  =>  4,capacity:u64  =>  5,reserved:u64  =>  6,renewal_payer:Owner  =>  7,custodians:Owner  =>  8,horizon:u64  =>  9,fee_policy:Id => 10});
record!(Funding {source:Certified  =>  0,service:Service  =>  1,inclusion:StateWitness  =>  2});
record!(FamilyFunding {family:Family  =>  0,funding:Funding  =>  1,coupons:Vec<Coupon> => 2,covers:Vec<Cover> => 3,source_funding:Funding => 4});
record!(Handoff {next:Configuration  =>  0,new_acknowledgments:Vec<Signature>  =>  1,admission:InventoryAdmission => 2,old_authorizations:Vec<Signature> => 3});

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub enum Command {
    #[n(0)]
    LocalTransfer {
        #[n(0)]
        inputs: Vec<Id>,
        #[n(1)]
        outputs: Vec<Allocation>,
        #[n(2)]
        fees: Vec<Fee>,
        #[n(3)]
        lifts: Vec<Lift>,
    },
    #[n(1)]
    Mint(#[n(0)] Work),
    #[n(2)]
    PreparePayment {
        #[n(0)]
        ticket: Ticket,
        #[n(1)]
        coupon: CouponEvidence,
        #[n(2)]
        keys: Vec<KeyLeaf>,
        #[n(3)]
        material: Blob,
    },
    #[n(3)]
    PrepareClaim {
        #[n(0)]
        ticket: Ticket,
        #[n(1)]
        coupon: CouponEvidence,
        #[n(2)]
        work: PlacementWork,
        #[n(3)]
        keys: Vec<KeyLeaf>,
        #[n(4)]
        material: Blob,
    },
    #[n(4)]
    CloseUnusedCoupon(#[n(0)] CouponEvidence),
    #[n(5)]
    RedeemCancel(#[n(0)] Cancellation),
    #[n(6)]
    Import(#[n(0)] Release),
    #[n(7)]
    Reject(#[n(0)] Release),
    #[n(8)]
    RedeemRejected(#[n(0)] Rejected),
    #[n(9)]
    FundService {
        #[n(0)]
        inputs: Vec<Id>,
        #[n(1)]
        change: Vec<Allocation>,
        #[n(2)]
        service: Service,
    },
    #[n(10)]
    RenewService {
        #[n(0)]
        id: Id,
        #[n(1)]
        inputs: Vec<Id>,
        #[n(2)]
        change: Vec<Allocation>,
        #[n(3)]
        added: Vec<Component>,
        #[n(4)]
        horizon: u64,
    },
    #[n(11)]
    CreateFamily(#[n(0)] FamilyFunding),
    #[n(12)]
    Handoff(#[n(0)] Handoff),
    #[n(13)]
    Retire {
        #[n(0)]
        inputs: Vec<Id>,
        #[n(1)]
        change: Vec<Allocation>,
        #[n(2)]
        retired: Vec<Component>,
    },
    #[n(15)]
    ObserveExport(#[n(0)] Release),
    #[n(16)]
    PayService {
        #[n(0)]
        service: Id,
        #[n(1)]
        payouts: Vec<Allocation>,
        #[n(2)]
        fees: Vec<Fee>,
    },

    #[n(17)]
    CloseDestinationCapacity(#[n(0)] CapabilityClosure),
    #[n(14)]
    ReportIncident {
        #[n(0)]
        first: Certified,
        #[n(1)]
        second: Certified,
    },
}
record!(Operation {currency:Id  =>  0,home:Id  =>  1,nonce:Id  =>  2,command:Command  =>  3,covers:Vec<Cover>  =>  4,authorizations:Vec<Authorization>  =>  5});
impl Operation {
    pub fn signing_bytes(&self) -> Vec<u8> {
        crate::codec::tagged(
            "RLD-OPERATION",
            self.currency,
            &(self.home, self.nonce, &self.command, &self.covers),
        )
    }
    pub fn id(&self) -> Id {
        Id::digest(&self.signing_bytes())
    }
}
record!(Batch {operations:Vec<Operation>  =>  0});
record!(Decision {object:Id  =>  0,coupon:Id  =>  1,outcome:u8  =>  2,digest:Id  =>  3});
record!(Delegation {coupon:Id  =>  0,controller:Option<Id>  =>  1,closed:bool  =>  2});
record!(Redemption {controller:Id  =>  0,kind:u8  =>  1,operation:Id  =>  2});
record!(Incident {family:Id  =>  0,anchor:Id => 1,first:Blob  =>  2,second:Blob  =>  3});
record!(Applied {id:Id  =>  0,digest:Id  =>  1});
record!(Material {ticket:Ticket  =>  0,coupon:Coupon  =>  1,covers:Vec<Cover>  =>  2,outputs:Vec<Allocation>  =>  3});
record!(Birth {controller:Id  =>  0,sequence:u64  =>  1});

record!(InventoryAdmission {configuration:Id => 0,receipt:Blob => 1});
record!(AdmissionWitness {currency:Currency => 0,configuration:Configuration => 1,inventories:Vec<PublicInventory> => 2});
