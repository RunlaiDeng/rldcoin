use std::{env, fs, path::Path};
use rld_core::{generate_identity, sign_bytes, AdmissionHash32 as Hash, Amount, Identity,
    M0GenesisManifestFile, SignedM0GenesisManifestV3};
use rld_pow::{transition::{self, Adoption, Approval}, Chain};
use rld_value_successor::{adoption::{EarthSuccessorAdoption, EarthSuccessorAdoptionStatement},
    transition::TransitionPreview, chain::{CandidateChain, Block, mine_batch}};

fn approvals(keys: &[Identity], bytes: &[u8]) -> Vec<Approval> {
    let mut rows: Vec<_> = keys.iter().map(|k| Approval { public_key: k.public_key.clone(),
        signature: sign_bytes(&k.secret_key, bytes).unwrap() }).collect();
    rows.sort_by(|a,b| a.public_key.cmp(&b.public_key)); rows
}
fn save(p: &Path, value: &impl serde::Serialize) {
    assert!(!p.exists()); fs::write(p, serde_json::to_vec(value).unwrap()).unwrap();
}
fn read<T: serde::de::DeserializeOwned>(p: &Path) -> T {
    serde_json::from_slice(&fs::read(p).unwrap()).unwrap()
}
fn main() {
    let args: Vec<_> = env::args().collect(); let p = Path::new(&args[2]);
    let source = Hash::from_hex(rld_core::implementation_source::IMPLEMENTATION_SOURCE_COMMITMENT).unwrap();
    if args[1] == "create" {
        let old = M0GenesisManifestFile::decode_json(include_bytes!("../../vectors/m0-genesis-v3/manifest.json")).unwrap();
        let founder = generate_identity(); let keys: Vec<_> = (0..4).map(|_| generate_identity()).collect();
        let manifest = M0GenesisManifestFile::V3(SignedM0GenesisManifestV3::create_earth(
            "RESERVE-ERA-ISSUANCE-NO-VALUE-20261004", keys.iter().map(|k| k.public_key.clone()).collect(),
            vec![], "same-host-single-controller-public-fixture-no-value", old.admission_genesis().config.clone(),
            old.admission_genesis().benchmark_report_sha256, &founder).unwrap());
        assert_ne!(manifest.manifest_sha256(), old.manifest_sha256());
        let genesis = serde_json::to_vec(&manifest).unwrap();
        let pin = Hash::from_hex(manifest.manifest_sha256()).unwrap();
        let statement = transition::draft(&genesis, b"[]", pin, rld_pow::target_limit(), 1_000_000).unwrap();
        assert_eq!(statement.implementation_source_sha256, source);
        let pow = Adoption { approvals: approvals(&keys, &statement.signing_bytes().unwrap()), statement };
        let chain = Chain::new(pow.verify(&genesis,b"[]",pin,pow.statement.id().unwrap()).unwrap()).unwrap();
        let preview = TransitionPreview::from_replayed_v1(&chain,source).unwrap();
        let statement = EarthSuccessorAdoptionStatement::from_replayed_fresh_chain(&chain,&preview).unwrap();
        let adoption = EarthSuccessorAdoption { approvals: approvals(&keys,&statement.signing_bytes().unwrap()), statement };
        adoption.verify(&genesis,b"[]",&pow,&chain,&preview,adoption.statement.id().unwrap()).unwrap();
        let mut wrong = adoption.clone(); wrong.statement.issuance_rules_sha256 = Hash([7;32]);
        wrong.approvals = approvals(&keys,&wrong.statement.signing_bytes().unwrap());
        assert!(wrong.verify(&genesis,b"[]",&pow,&chain,&preview,wrong.statement.id().unwrap()).is_err());
        let mut old_domain = adoption.clone(); let mut bytes = b"RLD-EARTH-SUCCESSOR-ADOPTION\0".to_vec();
        bytes.extend(serde_json::to_vec(&old_domain.statement).unwrap()); old_domain.approvals = approvals(&keys,&bytes);
        assert!(old_domain.verify(&genesis,b"[]",&pow,&chain,&preview,adoption.statement.id().unwrap()).is_err());
        let mut value = CandidateChain::from_replayed_pow_chain(&chain).unwrap();
        assert_eq!(value.height(),0); assert_eq!(value.state().commitment().unwrap().emitted,Amount::ZERO);
        let mut block = value.template(keys[0].public_key.clone(),1_000_001,vec![]).unwrap();
        let mut found = false; for _ in 0..64 { if mine_batch(&mut block,100_000).unwrap() { found=true;break; } }
        assert!(found); assert!(value.accept(block.clone(),1_000_001).unwrap());
        assert_eq!(value.state().commitment().unwrap().emitted,rld_pow::subsidy(1).unwrap());
        save(&p.join("manifest.json"),&manifest); save(&p.join("pow-adoption.json"),&pow);
        save(&p.join("preview.json"),&preview); save(&p.join("value-adoption.json"),&adoption);
        save(&p.join("first-block.json"),&block);
    } else { assert_eq!(args[1],"cold"); }
    let genesis = fs::read(p.join("manifest.json")).unwrap();
    let manifest = M0GenesisManifestFile::decode_json(&genesis).unwrap();
    let pin = Hash::from_hex(manifest.manifest_sha256()).unwrap();
    let pow: Adoption = read(&p.join("pow-adoption.json"));
    let chain = Chain::new(pow.verify(&genesis,b"[]",pin,pow.statement.id().unwrap()).unwrap()).unwrap();
    let preview: TransitionPreview = read(&p.join("preview.json"));
    let adoption: EarthSuccessorAdoption = read(&p.join("value-adoption.json"));
    adoption.verify(&genesis,b"[]",&pow,&chain,&preview,adoption.statement.id().unwrap()).unwrap();
    assert_eq!(adoption.statement.successor_source_sha256,source);
    assert_eq!(adoption.statement.issuance_rules_sha256,rld_pow::issuance_rules_hash());
    let block: Block = read(&p.join("first-block.json"));
    let mut value = CandidateChain::from_replayed_pow_chain(&chain).unwrap();
    assert_eq!(value.state().commitment().unwrap().emitted,Amount::ZERO);
    assert!(value.accept(block.clone(),1_000_001).unwrap());
    assert_eq!(value.height(),1);
    assert_eq!(value.state().commitment().unwrap().emitted,Amount::from_rld_whole(250_000).unwrap());
    let before = value.state().commitment().unwrap(); let tip = value.tip();
    let mut invalid = value.template(block.header.miner.clone(),1_000_601,vec![]).unwrap();
    invalid.header.state_root = Hash([8;32]);
    assert!(value.accept(invalid,1_000_601).is_err());
    assert_eq!(value.state().commitment().unwrap(),before); assert_eq!(value.tip(),tip);
    println!("{}",serde_json::json!({"mode":args[1],"source_commitment":source.to_hex(),
        "issuance_rules_sha256":rld_pow::issuance_rules_hash().to_hex(),"fresh_manifest_pin":pin.to_hex(),
        "adoption_id":adoption.statement.id().unwrap().to_hex(),"height":"1","genesis_emitted":"0",
        "emitted":before.emitted.0.to_string(),"invalid_tail_state_unchanged":true,
        "new_signed_fixture_component_only":true,"whole_protocol_qualified":false,"live_rld":false}));
}
