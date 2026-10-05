//! Source-bound native capacity discriminator; public fixture signatures only.
//! Full Store replay/finality is authoritative. Never resume an old fixture.
use rld_regional_ledger_candidate::{bft::{self,Certificate,Context,Quorum},storage::Store,*,};
use rld_core::{AdmissionHash32 as Hash,Amount,sign_bytes};
use ed25519_dalek::SigningKey;
use sha2::{Digest,Sha256};
use std::{fs,path::{Path,PathBuf},time::Instant};
use bft::{Agent,Request,Message};
use std::io::Write;
fn public(seed:u8)->String {hex::encode(SigningKey::from_bytes(&[seed;32]).verifying_key().to_bytes())}
fn sign(seed:u8,bytes:&[u8])->String {sign_bytes(&hex::encode([seed;32]),bytes).unwrap()}
fn digest(bytes:&[u8])->String {hex::encode(Sha256::digest(bytes))}
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
 let authority=public(63);let mut currency=Currency{format:"RLD-REGIONAL-FIXTURE-V1".into(),fixture_only:true,implementation:implementation().unwrap(),origin:"earth".into(),authority:authority.clone(),cap:Amount::TOTAL_SUPPLY,block_reward:rld_pow::subsidy(1).unwrap(),maturity:2,signature:String::new()};
 currency.signature=sign(63,&currency.bytes().unwrap());let pin=currency.id().unwrap();
 let mut seeds=vec![2u8,3,4,5];seeds.sort_by_key(|s|public(*s));
 let mut admission=Admission{currency:pin,region:"earth".into(),rules:channels::BFT_RULES.into(),value_rules:Some(channels::profile_hash().unwrap()),validators:seeds.iter().map(|s|public(*s)).collect(),signature:String::new()};
 admission.signature=sign(63,&admission.bytes().unwrap());let region=admission.id().unwrap();
 let mut node=Store::create(&root.join("node"),Bootstrap{currency,admissions:vec![admission]},region,&authority,pin).unwrap();
 println!("{}",serde_json::json!({"phase":"fresh-native-zero-allocation-genesis","height":node.chain.height(),"currency":pin,"implementation":implementation().unwrap(),"value_profile":channels::profile_hash().unwrap(),"snapshot_limit":MAX_SNAPSHOTS,"block_limit":MAX_BLOCKS,"window":channels::WINDOW}));
 let mut agents=vec![];let mut heads=vec![];
 for (n,seed) in seeds.iter().enumerate(){
  {use std::os::unix::fs::OpenOptionsExt;let mut file=fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(root.join(format!("key-{n}.json"))).unwrap();file.write_all(serde_json::to_vec(&serde_json::json!({"secret_key":hex::encode([*seed;32])})).unwrap().as_slice()).unwrap();file.sync_all().unwrap();fs::File::open(&root).unwrap().sync_all().unwrap();}
  let agent=Agent::create(&root.join(format!("voter-{n}")),&node,public(*seed)).unwrap();heads.push(agent.journal.head().unwrap());agents.push(agent);
 }
 fn retain_head(root:&Path,n:usize,head:Hash){
  use std::os::unix::fs::OpenOptionsExt;
  let path=root.join(format!("caller-{n}.json"));let temp=root.join(format!("caller-{n}.next"));
  let mut file=fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temp).unwrap();file.write_all(serde_json::to_string(&head).unwrap().as_bytes()).unwrap();file.sync_all().unwrap();fs::rename(&temp,&path).unwrap();fs::File::open(root).unwrap().sync_all().unwrap();
 }
 for (n,head) in heads.iter().enumerate(){retain_head(&root,n,*head);}
 let mut refusal_atomic=false;let mut failed_signer=None;let mut failed_action=None;
 let mut step=|node:&Store,agents:&mut Vec<Agent>,heads:&mut Vec<Hash>,n:usize,request:Request|->Result<Message>{
  let before=inventory(&root);let node_before=state(node);let old_head=agents[n].journal.head()?;
  let action=match &request{Request::Propose{..}=>"Propose",Request::Prepare(_)=>"Prepare",Request::Commit{..}=>"Commit",Request::Timeout{..}=>"Timeout",Request::EpochFence{..}=>"EpochFence"};
  assert_eq!(old_head,heads[n]);
  let result=agents[n].sign(node,request,Some(&root.join(format!("key-{n}.json"))),heads[n]);
  match result{
   Ok(value)=>{heads[n]=value.head;retain_head(&root,n,value.head);Ok(value.message)},
   Err(error)=>{refusal_atomic=inventory(&root)==before && state(node)==node_before && agents[n].journal.head()?==old_head;failed_signer=Some(n);failed_action=Some(action);Err(error)}
  }
 };
 let mut failure=None;let mut refused_height=None;
 for height in 1..=MAX_SNAPSHOTS+1 {
  let result=(||->Result<Hash>{
   let context=Context::current(&node)?;let snapshot=node.bft_candidate(vec![],public(10))?;
   assert_eq!(snapshot.statement.height,height as u64);
   let keys=seeds.iter().map(|s|public(*s)).collect::<Vec<_>>();let leader=bft::leader(&context,0,&keys)?;let n=keys.iter().position(|key|key==&leader).unwrap();
   let Message::Proposal(proposal)=step(&node,&mut agents,&mut heads,n,Request::Propose{round:0,snapshot:Box::new(snapshot),timeout:None})? else{panic!("proposal kind")};
   let mut votes=vec![];for n in 0..3{let Message::Vote(vote)=step(&node,&mut agents,&mut heads,n,Request::Prepare(proposal.clone()))? else{panic!("prepare kind")};votes.push(*vote);}
   let prepared=Quorum::combine(votes,&node.trust,&node.evidence)?;
   let mut votes=vec![];for n in 0..3{let Message::Vote(vote)=step(&node,&mut agents,&mut heads,n,Request::Commit{proposal:proposal.clone(),prepared:prepared.clone()})? else{panic!("commit kind")};votes.push(*vote);}
   let committed=Quorum::combine(votes,&node.trust,&node.evidence)?;
   let mut snapshot=*proposal.snapshot;snapshot.bft=Some(Certificate{prepared,committed});node.finalize(snapshot)
  })();
  match result{
   Ok(_)=>{assert_eq!(node.chain.height(),height as u64);if height%4==0 || height==1{println!("{}",serde_json::json!({"phase":"native-custody-certified-progress","height":height,"signer_records":agents.iter().map(|agent|agent.journal.records.len()).collect::<Vec<_>>(),"elapsed_seconds":started.elapsed().as_secs_f64()}));}},
   Err(error)=>{refused_height=Some(height);failure=Some(error);break;}
  }
 }
 drop(step);
 let records=agents.iter().map(|agent|agent.journal.records.len()).collect::<Vec<_>>();
 for (n,head) in heads.iter().enumerate(){assert_eq!(agents[n].journal.head().unwrap(),*head);assert_eq!(serde_json::from_slice::<Hash>(&fs::read(root.join(format!("caller-{n}.json"))).unwrap()).unwrap(),*head);}
 drop(agents);
 let height=node.chain.height();let snapshots=node.journal.evidence.snapshots.len();let book=node.chain.ledger.channel_state.clone();let head=history::manifest(&root.join("node")).unwrap().head().unwrap();let before_cold=inventory(&root.join("node"));let ledger_root=node.chain.ledger.root().unwrap();drop(node);
 let cold=Store::open_pinned(&root.join("node"),&authority,pin,head).unwrap();assert_eq!(cold.chain.height(),height);assert_eq!(cold.chain.ledger.root().unwrap(),ledger_root);assert_eq!(cold.chain.ledger.channel_state,book);assert_eq!(history::manifest(&root.join("node")).unwrap().head().unwrap(),head);for (n,head) in heads.iter().enumerate(){let agent=Agent::open(&root.join(format!("voter-{n}")),&cold).unwrap();assert_eq!(agent.journal.head().unwrap(),*head);assert_eq!(agent.journal.records.len(),records[n]);}
 drop(cold);assert_eq!(inventory(&root.join("node")),before_cold);
 let completed=refused_height.is_some_and(|h|h<=MAX_SNAPSHOTS) && failed_signer.is_some() && matches!(failure.as_deref(),Some("BFT signer record capacity; keep old votes"|"BFT signer byte capacity")) && refusal_atomic;
 let report=serde_json::json!({"format":"RLD-NATIVE-BFT-CUSTODY-CAPACITY-V1","completed_discriminator":completed,"native_refusal":failure,"attempted_height":refused_height,"retained_height":height,"retained_complete_snapshots":snapshots,"capacity_refusal_state_and_disk_unchanged":refusal_atomic,"failed_signer":failed_signer,"failed_action":failed_action,"signer_records":records,"all_separate_native_voter_and_caller_heads_verified":true,"native_signer_record_limit":bft::MAX_RECORDS,"full_pinned_cold_replay_passed":true,"no_serialized_ledger_or_fake_height":true,"no_channel_owner_custody_created":true,"four_native_BFT_signer_journals_and_separate_fsynced_caller_heads_created":true,"native_implementation":implementation().unwrap(),"value_profile":channels::profile_hash().unwrap(),"currency":pin,"window_blocks":channels::WINDOW,"ordinary_window_settlement_qualified":false,"elapsed_seconds":started.elapsed().as_secs_f64()});
 fs::write(root.join("result.json"),serde_json::to_vec_pretty(&report).unwrap()).unwrap();println!("{}",report);assert!(completed);
}
