#![no_main]
risc0_zkvm::guest::entry!(main);
fn main() {
    let bytes: Vec<u8> = risc0_zkvm::guest::env::read();
    let input: rld_protocol::proof::NativeInput =
        rld_protocol::codec::decode(&bytes, 1024 * 1024 * 1024)
            .expect("canonical bounded native input");
    let journal = match input {
        rld_protocol::proof::NativeInput::Execution(w) => rld_protocol::proof::native_journal(
            &rld_protocol::proof::execute_native(&w).expect("complete native execution"),
        ),
        rld_protocol::proof::NativeInput::IndexedExecution(w)=>rld_protocol::proof::native_journal(
            &rld_protocol::proof::execute_indexed_native(&w).expect("complete indexed native execution"),
        ),
        rld_protocol::proof::NativeInput::IndexedPermanent(w)=>rld_protocol::proof::native_journal(
            &rld_protocol::proof::execute_indexed_permanent(&w).expect("complete indexed permanent execution"),
        ),
        rld_protocol::proof::NativeInput::IndexedUtxo(w)=>rld_protocol::proof::native_journal(
            &rld_protocol::proof::execute_indexed_utxo(&w).expect("complete indexed UTXO execution"),
        ),
        rld_protocol::proof::NativeInput::IndexedMint(w)=>rld_protocol::proof::native_journal(
            &rld_protocol::proof::execute_indexed_mint(&w).expect("complete indexed Mint execution"),
        ),
        rld_protocol::proof::NativeInput::IndexedDefinitions(w)=>rld_protocol::proof::native_journal(
            &rld_protocol::proof::execute_indexed_definitions(&w).expect("complete indexed definition execution"),
        ),
        rld_protocol::proof::NativeInput::IndexedService(w)=>rld_protocol::proof::native_journal(
            &rld_protocol::proof::execute_indexed_service(&w).expect("complete indexed service execution"),
        ),
        rld_protocol::proof::NativeInput::MintIndex(w)=>rld_protocol::mints::index::journal(
            &rld_protocol::mints::index::execute(&w).expect("complete Mint index correspondence"),
        ),
        rld_protocol::proof::NativeInput::Admission(w) => {
            rld_protocol::proof::execute_admission(&w)
                .expect("complete public key inventory admission")
        }
    };
    risc0_zkvm::guest::env::commit_slice(&journal);
}
