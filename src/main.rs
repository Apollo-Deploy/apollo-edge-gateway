fn main() {
    if let Err(error) = apollo_edge_gateway::run() {
        eprintln!("Apollo Edge Gateway stopped: {error:#}");
        std::process::exit(1);
    }
}
