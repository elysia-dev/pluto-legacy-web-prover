// client/src/contracts/mod.rs
mod common;
pub mod transfer_usdt_to_vault;
pub mod claim;
pub mod enroll;
pub mod check_usdt_balance;
pub mod has_valid_payment_history;

pub use transfer_usdt_to_vault::transfer_usdt_to_vault;
pub use claim::claim;
pub use enroll::enroll;
pub use check_usdt_balance::check_usdt_balance;
pub use has_valid_payment_history::has_valid_payment_history;
