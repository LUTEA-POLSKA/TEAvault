// Keep `cargo check` working without a frontend build or a Tauri context.
fn main() {
    tauri_build::build()
}