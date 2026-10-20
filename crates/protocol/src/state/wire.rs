use crate::{
    codec::{Amount, Id},
    model::*,
    record,
};
record!(StateWire {
 currency:Id => 0,domain:Id => 1,sequence:u64 => 2,configuration:Configuration => 3,
 outputs:Vec<Output> => 4,grants:Vec<Grant> => 5,segments:Vec<Segment> => 6,
 controllers:Vec<Controller> => 7,births:Vec<Birth> => 8,coupon_uses:Vec<Delegation> => 9,
 families:Vec<Family> => 10,decisions:Vec<Decision> => 11,redemptions:Vec<Redemption> => 12,
 services:Vec<Service> => 13,covers:Vec<Cover> => 14,mints:Vec<MintRecord> => 15,
 applied:Vec<Applied> => 16,incidents:Vec<Incident> => 17,pool_next:u32 => 18,
 minted:Amount => 19,retired:Amount => 20,used_funding:Vec<Id> => 21,resolutions:Vec<Decision> => 22,fee_policies:Vec<FeePolicy> => 23
});
