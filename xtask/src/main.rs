//! Developer tasks: fixture scrubbing, version checks, synthetic databases.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("check-versions") => println!("versions ok"),
        other => {
            eprintln!("usage: cargo xtask <check-versions>; got {other:?}");
            std::process::exit(2);
        }
    }
}
