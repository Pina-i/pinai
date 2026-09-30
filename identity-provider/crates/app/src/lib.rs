//! The identity provider, assembled: its configuration and `Application`, which the binary runs
//! and the end-to-end tests spawn.

pub mod configuration;
mod keys;
mod startup;

pub use startup::Application;
