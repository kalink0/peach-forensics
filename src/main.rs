fn main() {
    if let Err(err) = peach::app::run() {
        eprintln!("peach: {err:#}");
        std::process::exit(1);
    }
}
