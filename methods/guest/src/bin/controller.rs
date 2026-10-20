#![no_main]
risc0_zkvm::guest::entry!(main);
fn main() {
    let bytes: Vec<u8> = risc0_zkvm::guest::env::read();
    let witness: rld_protocol::proof::ControllerWitness =
        rld_protocol::codec::decode(&bytes, 1024 * 1024 * 1024)
            .expect("canonical bounded controller input");
    let result =
        rld_protocol::proof::execute_controller(&witness).expect("complete controller execution");
    risc0_zkvm::guest::env::commit_slice(&rld_protocol::proof::terminal_journal(&result));
}
