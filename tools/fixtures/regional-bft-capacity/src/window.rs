//! Source-bound native capacity discriminator; public fixture signatures only.
//! Full Store replay/finality is authoritative. Never resume an old fixture.
use rld_regional_ledger_candidate::{bft::{self,Certificate,Context,Phase,Quorum,Vote},storage::Store,*,};
use rld_core::{AdmissionHash32 as Hash,Amount,sign_bytes};
use ed25519_dalek::SigningKey;
use sha2::{Digest,Sha256};
use std::{fs,path::{Path,PathBuf},time::Instant};
fn public(seed:u8)->String {hex::encode(SigningKey::from_bytes(&[seed;32]).verifying_key().to_bytes())}
fn sign(seed:u8,bytes:&[u8])->String {sign_bytes(&hex::encode([seed;32]),bytes).unwrap()}
fn digest(bytes:&[u8])->String {hex::encode(Sha256::digest(bytes))}
fn vote(seed:u8,context:&Context,value:Hash,phase:Phase)->Vote {
 let mut vote=Vote {context:context.clone(),round:0,value,phase,approval:Approval{key:public(seed),signature:String::new()}};
 let mut bytes=b"RLD-REGIONAL-FIXTURE-V1:bft-vote-v1\0".to_vec();
 bytes.extend(serde_json::to_vec(&(&vote.context,vote.round,vote.value,vote.phase,&vote.approval.key)).unwrap());
 vote.approval.signature=sign(seed,&bytes);vote
}
fn inventory(root:&Path)->String {
 fn walk(root:&Path,p:&Path,rows:&mut Vec<serde_json::Value>) {
  use std::os::unix::fs::MetadataExt;
  let meta=fs::symlink_metadata(p).unwrap();assert!(!meta.file_type().is_symlink());
  rows.push(serde_json::json!([p.strip_prefix(root).unwrap().to_str().unwrap(),meta.mode(),if meta.is_file(){Some(meta.len())}else{None},meta.mtime(),meta.mtime_nsec(),if meta.is_file(){Some(digest(&fs::read(p).unwrap()))}else{None}]));
  if meta.is_dir(){let mut files=fs::read_dir(p).unwrap().map(|e|e.unwrap().path()).collect::<Vec<_>>();files.sort();for file in files{walk(root,&file,rows);}}
 }
 let mut rows=vec![];walk(root,root,&mut rows);digest(&serde_json::to_vec(&rows).unwrap())
}
fn state(node:&Store)->String {
 digest(&serde_json::to_vec(&(&node.journal,&node.chain.blocks,&node.chain.ledger,node.chain.height(),node.chain.finalized,node.chain.epoch)).unwrap())
}
fn main(){
 let started=Instant::now();let args=std::env::args().collect::<Vec<_>>();assert_eq!(args.len(),3);
 let root=PathBuf::from(&args[1]);let expected=&args[2];assert_eq!(implementation().unwrap().to_hex(),*expected);
 fs::create_dir(&root).unwrap();
 {use std::os::unix::fs::PermissionsExt;fs::set_permissions(&root,fs::Permissions::from_mode(0o700)).unwrap();}
 let authority=public(61);let mut currency=Currency{format:"RLD-REGIONAL-FIXTURE-V1".into(),fixture_only:true,implementation:implementation().unwrap(),origin:"earth".into(),authority:authority.clone(),cap:Amount::TOTAL_SUPPLY,block_reward:rld_pow::subsidy(1).unwrap(),maturity:2,signature:String::new()};
 currency.signature=sign(61,&currency.bytes().unwrap());let pin=currency.id().unwrap();
 let mut seeds=vec![2u8,3,4,5];seeds.sort_by_key(|s|public(*s));
 let mut admission=Admission{currency:pin,region:"earth".into(),rules:channels::BFT_RULES.into(),value_rules:Some(channels::profile_hash().unwrap()),validators:seeds.iter().map(|s|public(*s)).collect(),signature:String::new()};
 admission.signature=sign(61,&admission.bytes().unwrap());let region=admission.id().unwrap();
 let mut node=Store::create(&root.join("node"),Bootstrap{currency,admissions:vec![admission]},region,&authority,pin).unwrap();
 println!("{}",serde_json::json!({"phase":"fresh-native-zero-allocation-genesis","height":node.chain.height(),"currency":pin,"implementation":implementation().unwrap(),"value_profile":channels::profile_hash().unwrap(),"snapshot_limit":MAX_SNAPSHOTS,"block_limit":MAX_BLOCKS,"window":channels::WINDOW}));
 let mut failure=None;let mut refused_height=None;let mut capacity_unchanged=false;
 for height in 1..=MAX_SNAPSHOTS+1 {
  let before_state=state(&node);let before_inventory=inventory(&root.join("node"));
  let result=(||->Result<Hash>{
   let context=Context::current(&node)?;let mut snapshot=node.bft_candidate(vec![],public(10))?;
   assert_eq!(snapshot.statement.height,height as u64);
   let value=snapshot.statement.id()?;
   let prepared=Quorum::combine(seeds[..3].iter().map(|s|vote(*s,&context,value,Phase::Prepare)).collect(),&node.trust,&node.evidence)?;
   let committed=Quorum::combine(seeds[..3].iter().map(|s|vote(*s,&context,value,Phase::Commit)).collect(),&node.trust,&node.evidence)?;
   snapshot.bft=Some(Certificate{prepared,committed});
   // Full ordinary native validation, journal replay and atomic persistence.
   node.finalize(snapshot)
  })();
  match result {
   Ok(_)=>{assert_eq!(node.chain.height(),height as u64);if height%4==0 || height==1 {println!("{}",serde_json::json!({"phase":"native-certified-progress","height":height,"complete_snapshots":node.journal.evidence.snapshots.len(),"elapsed_seconds":started.elapsed().as_secs_f64()}));}},
   Err(error)=>{capacity_unchanged=state(&node)==before_state && inventory(&root.join("node"))==before_inventory;refused_height=Some(height);failure=Some(error);break;}
  }
 }
 let height=node.chain.height();let snapshots=node.journal.evidence.snapshots.len();let book=node.chain.ledger.channel_state.clone();let head=history::manifest(&root.join("node")).unwrap().head().unwrap();let before_cold=inventory(&root.join("node"));let ledger_root=node.chain.ledger.root().unwrap();drop(node);
 let cold=Store::open_pinned(&root.join("node"),&authority,pin,head).unwrap();assert_eq!(cold.chain.height(),height);assert_eq!(cold.chain.ledger.root().unwrap(),ledger_root);assert_eq!(cold.chain.ledger.channel_state,book);assert_eq!(history::manifest(&root.join("node")).unwrap().head().unwrap(),head);drop(cold);assert_eq!(inventory(&root.join("node")),before_cold);
 let completed=refused_height==Some(MAX_SNAPSHOTS+1) && height==MAX_SNAPSHOTS as u64 && failure.as_deref()==Some("snapshot bound") && capacity_unchanged;
 let report=serde_json::json!({"format":"RLD-NATIVE-BFT-WINDOW-CAPACITY-V1","completed_discriminator":completed,"native_refusal":failure,"attempted_height":refused_height,"retained_height":height,"retained_complete_snapshots":snapshots,"capacity_refusal_state_and_disk_unchanged":capacity_unchanged,"full_pinned_cold_replay_passed":true,"no_serialized_ledger_or_fake_height":true,"no_channel_owner_or_BFT_signer_custody_created":true,"native_implementation":implementation().unwrap(),"value_profile":channels::profile_hash().unwrap(),"currency":pin,"window_blocks":channels::WINDOW,"ordinary_window_settlement_qualified":false,"elapsed_seconds":started.elapsed().as_secs_f64()});
 fs::write(root.join("result.json"),serde_json::to_vec_pretty(&report).unwrap()).unwrap();println!("{}",report);assert!(completed);
}
