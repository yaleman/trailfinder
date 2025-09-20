use trailfinder::cli::main_func;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(
            std::thread::available_parallelism()
                .map(|t| t.get())
                .unwrap_or_else(|_e| {
                    eprintln!("WARNING: Unable to read number of available CPUs, defaulting to 4");
                    4
                }),
        )
        .enable_all()
        .build()
        .unwrap()
        .block_on(main_func())
}
