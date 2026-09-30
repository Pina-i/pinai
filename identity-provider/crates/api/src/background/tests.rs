use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

#[tokio::test(start_paused = true)]
async fn a_timer_runs_at_once_then_every_period_until_stopped() {
    let (runs, stop) = (Arc::new(AtomicUsize::new(0)), CancellationToken::new());
    let timer = tokio::spawn({
        let (runs, stop) = (runs.clone(), stop.clone());
        async move {
            every(Duration::from_secs(60), stop, || async {
                runs.fetch_add(1, Ordering::SeqCst);
            })
            .await
        }
    });

    tokio::time::sleep(Duration::from_secs(150)).await;
    stop.cancel();
    timer.await.unwrap();

    assert_eq!(runs.load(Ordering::SeqCst), 3, "at 0, 60 and 120 s");
}

#[tokio::test(start_paused = true)]
async fn a_run_under_way_finishes_before_the_timer_stops() {
    let (finished, stop) = (Arc::new(AtomicUsize::new(0)), CancellationToken::new());
    let timer = tokio::spawn({
        let (finished, stop) = (finished.clone(), stop.clone());
        async move {
            every(Duration::from_secs(60), stop, || async {
                tokio::time::sleep(Duration::from_secs(5)).await;
                finished.fetch_add(1, Ordering::SeqCst);
            })
            .await
        }
    });

    tokio::time::sleep(Duration::from_secs(1)).await;
    stop.cancel();
    timer.await.unwrap();

    assert_eq!(finished.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_relay_stops_even_while_its_stream_is_silent() {
    let stop = CancellationToken::new();
    let mut silent: BoxStream<'static, u8> = futures_util::stream::pending().boxed();
    let waiting = tokio::spawn({
        let stop = stop.clone();
        async move { next(&mut silent, &stop).await }
    });

    stop.cancel();

    assert_eq!(waiting.await.unwrap(), None);
}
