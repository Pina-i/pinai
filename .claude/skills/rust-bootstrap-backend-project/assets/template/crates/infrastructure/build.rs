// `sqlx::migrate!` embeds the directory at compile time; rebuild when a migration is added.
fn main() {
    println!("cargo:rerun-if-changed=../../migrations");
}
