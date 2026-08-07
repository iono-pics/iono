use bytes::Bytes;
use futures_util::stream;
use iono_core::error::{AppError, AppResult};
use iono_core::storage::{S3Storage, Storage};
use iono_core::Config;

const BIG: usize = 20 * 1024 * 1024;

async fn storage() -> S3Storage {
    dotenvy::from_path("../../../.env").ok();
    S3Storage::new(&Config::from_env())
        .await
        .expect("could not reach the S3 endpoint")
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn chunks(data: &[u8], size: usize) -> Vec<AppResult<Bytes>> {
    data.chunks(size)
        .map(|c| Ok(Bytes::copy_from_slice(c)))
        .collect()
}

async fn read_back(storage: &S3Storage, key: &str) -> Vec<u8> {
    use futures_util::StreamExt;
    let object = storage.get(key, None).await.expect("get failed");
    let mut out = Vec::new();
    let mut body = object.stream;
    while let Some(chunk) = body.next().await {
        out.extend_from_slice(&chunk.expect("stream chunk failed"));
    }
    out
}

#[tokio::test]
#[ignore = "needs a live S3 endpoint"]
async fn a_multi_part_object_reads_back_byte_for_byte() {
    let storage = storage().await;
    let key = format!("test-multipart-{}", uuid::Uuid::new_v4());
    let data = pattern(BIG);

    storage
        .save_stream(
            &key,
            "application/octet-stream",
            Box::pin(stream::iter(chunks(&data, 64 * 1024))),
        )
        .await
        .expect("save_stream failed");

    assert_eq!(read_back(&storage, &key).await, data);
    storage.delete(&key).await.unwrap();
}

#[tokio::test]
#[ignore = "needs a live S3 endpoint"]
async fn a_single_part_object_reads_back_byte_for_byte() {
    let storage = storage().await;
    let key = format!("test-small-{}", uuid::Uuid::new_v4());
    let data = pattern(3 * 1024 * 1024);

    storage
        .save_stream(
            &key,
            "application/octet-stream",
            Box::pin(stream::iter(chunks(&data, 7919))),
        )
        .await
        .expect("save_stream failed");

    assert_eq!(read_back(&storage, &key).await, data);
    storage.delete(&key).await.unwrap();
}

#[tokio::test]
#[ignore = "needs a live S3 endpoint"]
async fn part_boundaries_do_not_depend_on_chunk_size() {
    let storage = storage().await;
    let data = pattern(BIG);

    for size in [1024usize, 64 * 1024, 8 * 1024 * 1024 + 1] {
        let key = format!("test-chunk-{size}-{}", uuid::Uuid::new_v4());
        storage
            .save_stream(
                &key,
                "application/octet-stream",
                Box::pin(stream::iter(chunks(&data, size))),
            )
            .await
            .expect("save_stream failed");

        assert_eq!(read_back(&storage, &key).await, data, "differed at {size}");
        storage.delete(&key).await.unwrap();
    }
}

#[tokio::test]
#[ignore = "needs a live S3 endpoint"]
async fn a_stream_error_after_a_part_leaves_no_object() {
    let storage = storage().await;
    let key = format!("test-abort-{}", uuid::Uuid::new_v4());
    let data = pattern(BIG);

    let mut items = chunks(&data, 64 * 1024);
    items.push(Err(AppError::PaymentRequired("too large".into())));

    let err = storage
        .save_stream(
            &key,
            "application/octet-stream",
            Box::pin(stream::iter(items)),
        )
        .await
        .expect_err("a failing stream must not complete the upload");

    assert!(
        matches!(err, AppError::PaymentRequired(_)),
        "the caller's error must survive, got {err:?}"
    );
    assert!(
        storage.get(&key, None).await.is_err(),
        "the aborted upload must not be readable"
    );
}

#[tokio::test]
#[ignore = "needs a live S3 endpoint"]
async fn an_empty_stream_writes_an_empty_object() {
    let storage = storage().await;
    let key = format!("test-empty-{}", uuid::Uuid::new_v4());

    storage
        .save_stream(
            &key,
            "application/octet-stream",
            Box::pin(stream::iter(Vec::<AppResult<Bytes>>::new())),
        )
        .await
        .expect("save_stream failed");

    assert!(read_back(&storage, &key).await.is_empty());
    storage.delete(&key).await.unwrap();
}
