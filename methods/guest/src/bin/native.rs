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
        rld_protocol::proof::NativeInput::Admission(w) => {
            rld_protocol::proof::execute_admission(&w)
                .expect("complete public key inventory admission")
        }
    };
    risc0_zkvm::guest::env::commit_slice(&journal);
}
