use std::{convert::TryFrom, sync::{Arc, atomic::{AtomicU64, Ordering}}, thread::{self}, time::{self, Duration}};

use bee_crypto::ternary::{sponge::{BATCH_SIZE, CurlP, CurlPRounds, Sponge}};
use bee_pow::providers::miner::MinerCancel;
use bee_ternary::{T1B1Buf, Trit, TritBuf, Tryte, b1t6::{self}};
use structopt::StructOpt;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BenchmarkCPUError {
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Debug, StructOpt)]
pub struct BenchmarkCPUTool {
    threads: Option<usize>
}

pub fn exec(tool: &BenchmarkCPUTool) -> Result<(), BenchmarkCPUError> {
    let threads = match tool.threads {
        Some(threads) => threads,
        None => num_cpus::get()
    };
    println!("Benchmarking CPU with {} threads", threads);

    let cancel = MinerCancel::new();
    let cancel_2 = cancel.clone();
    let cancel_3 = cancel.clone();
    let counter = Arc::new(AtomicU64::new(0));
    let counter_2 = counter.clone();

    let time_start = std::time::Instant::now();

    let pow_digest: [u8;32] = rand::random();

    let mut workers = Vec::with_capacity(threads+2);

    //Stop if the timeout has exceeded
    let time_thread = thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(120));
        cancel.trigger();
    });

    let process_thread = thread::spawn(move || {
        while !cancel_2.is_cancelled() {
            std::thread::sleep(Duration::from_secs(10));

            let elapsed = time_start.elapsed();
			let (percentage, remaining) = estimate_remaining_time(time_start, elapsed.as_millis() as i64, 60_000);
            let megahashes_per_second = counter.load(Ordering::Relaxed) as f64 / (elapsed.as_secs_f64() * 1_000_000 as f64);
            println!("{}", counter.load(Ordering::Relaxed));
            println!("Average CPU speed: {:.2}MH/s ({} thread(s), {:.2}%. {:.2?} left...)", megahashes_per_second, threads, percentage, remaining);
        }
        println!("Timed out");
    });

    let worker_width = u64::MAX / threads as u64;
    for i in 0..threads {
        let start_nonce = i as u64 * worker_width;
        let benchmark_cancel = cancel_3.clone();
        let benchmark_counter = counter_2.clone();
        let _pow_digest = pow_digest.clone();

        //workers.push(thread::spawn(move || {
            cpu_benchmark_worker(&pow_digest, start_nonce, benchmark_cancel, benchmark_counter).unwrap()
        //}));
    }

    workers.push(time_thread);
    workers.push(process_thread);

    for worker in workers {
        worker.join().expect("");
    }
    
    Ok(())
}

fn encode_group(byte: u8) -> (i8, i8) {
    let v = (byte as i8) as i16 + (27 / 2) * 27 + 27 / 2;
    let quo = (v / 27) as i8;
    let rem = (v % 27) as i8;

    (rem + -13 as i8, quo + -13 as i8)
}

fn cpu_benchmark_worker(_pow_digest: &[u8], start_nonce: u64, cancel: MinerCancel, counter: Arc<AtomicU64>) -> Result<(), BenchmarkCPUError> {
    let mut pow_digest = TritBuf::<T1B1Buf>::new();
    b1t6::encode::<T1B1Buf>(&_pow_digest).iter().for_each(|t| pow_digest.push(t));

    let mut nonce = start_nonce;
    //let hasher = BatchHasher::<T1B1Buf>::new(HASH_LENGTH, CurlPRounds::Rounds81);
    let mut curlp = CurlP::new(CurlPRounds::Rounds81);
    //let mut buffers = Vec::<TritBuf<T1B1Buf>>::with_capacity(BATCH_SIZE);
    let mut buffers = TritBuf::<T1B1Buf>::new();

    let mut trits: TritBuf<T1B1Buf> = TritBuf::new();
    let time_start = std::time::Instant::now();
    let test_trits = Tryte::N.as_trits();
    for i in 0..1_000_000_000 {
        //let nonce_trits = b1t6::encode::<T1B1Buf>(&(nonce + i as u64).to_le_bytes());
        //buffers.append(&pow_digest);
        //buffers.append(&nonce_trits);
        //println!("POW_DIGEST");
        let (t1, t2) = encode_group(127);
        //let test = Tryte::try_from(t1).unwrap();
        //let test2 = test.as_trits();
        //println!("Trits: {} Len:{}", test2, test2.len());
        trits.append(test_trits);
        trits.append(test_trits);
        //trits.append(Tryte::try_from(t2).unwrap().as_trits());
        //[t1, t2]
        //    .iter()
            // Unwrap is safe, `encode_group` is valid for all inputs
        //    .for_each(|b| trits.append(Tryte::try_from(*b).unwrap().as_trits()));
    }
    println!("Elapsed Time: {:?}", time_start.elapsed());
    //eturn Ok(());

    //let mut test_count: u64 = 0;
    while !cancel.is_cancelled() {
        for i in 0..BATCH_SIZE {
            let nonce_trits = b1t6::encode::<T1B1Buf>(&(nonce + i as u64).to_le_bytes()); 

            //println!("{}:{}", pow_digest.len(), nonce_trits.len());
            let offset = i * 240;
            buffers[offset+pow_digest.len()..offset + pow_digest.len() + nonce_trits.len()].copy_from(&nonce_trits);
            //hasher.add(buffer.clone());
            //println!("NONCE");
        }

        //buffers.join();
        curlp.absorb(&*buffers).unwrap();
        counter.fetch_add(BATCH_SIZE as u64, Ordering::Release);
        //for (i, hash) in hasher.hash_batched().enumerate() {

        nonce += BATCH_SIZE as u64;
        //test_count += BATCH_SIZE as u64;
        //println!("test_count: {}", test_count);
    }
    
    /* while !cancel.is_cancelled(){
        sleep(Duration::from_secs(20));
        counter.fetch_add(BATCH_SIZE as u64, Ordering::Release);
    } */

    println!("Stopped miner");
    Ok(())
}

// estimate_remaining_time estimates the remaining time for a running operation and returns the finished percentage.
fn estimate_remaining_time(time_start: std::time::Instant, current: i64, total: i64) -> (f64, std::time::Duration) {
	let ratio = current as f64 / total as f64;
    let total_time = time::Duration::from_secs_f64(time_start.elapsed().as_secs_f64() / ratio);
    let remaining = (time_start + total_time).duration_since(std::time::Instant::now());
	return (ratio * 100.0, remaining)
}
