use alloy::providers::Provider; // RootProvider for new_builtin
use eyre::{Result, WrapErr};
use futures_util::StreamExt;
use std::sync::Arc;

pub async fn subscribe_to_new_blocks_example(provider: Arc<impl Provider>) -> Result<()> {
    // Ensure the provider's transport supports PubSub. WsTransport does.
    // The `RootProvider` itself might not directly expose `subscribe`.
    // You might need to access the underlying PubSub capable transport/client.
    // This part of Alloy's API can be a bit tricky depending on the exact version and setup.

    // One way to get a subscription stream for new blocks:
    // This assumes `provider` is already a `PubSubFrontend` or can be converted/accessed.
    // The exact method depends on the alloy version and how `RootProvider` wraps things.
    // If `RootProvider` doesn't directly implement `PubSubFrontend`, you might need to
    // use the `ProviderLayer` trait or similar to get to the pubsub client.

    let subscription = provider
        .subscribe_blocks()
        .await
        .wrap_err("Failed to subscribe to new blocks")?;
    println!(
        "Successfully subscribed to new blocks with ID: {:?}",
        subscription.local_id()
    );
    let mut stream = subscription.into_stream();

    println!("Listening for new blocks...");
    while let Some(header) = stream.next().await {
        println!("New block header: {}", hex::encode(header.hash.as_slice()));
    }
    Ok(())
}
