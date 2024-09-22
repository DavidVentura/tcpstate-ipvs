use log::info;
use ipvs_tcpstate::ConnectionWatcher;
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    info!("Waiting for Ctrl-C...");
    let mut watcher = ConnectionWatcher::new()?;
    let mut rx = watcher.get_events().await?;
    while let Some(i) = rx.recv().await {
        println!("got = {:?}", i);
    }
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
