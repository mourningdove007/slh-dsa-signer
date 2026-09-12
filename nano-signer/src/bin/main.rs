#![no_std]
#![no_main]
#![deny(
    clippy::mem_forget,
    reason = "mem::forget is generally not safe to do with esp_hal types, especially those \
    holding buffers for the duration of a data transfer."
)]
#![deny(clippy::large_stack_frames)]

use core::fmt::Write as _;

use esp_hal::clock::CpuClock;
use esp_hal::gpio::{Level, Output, OutputConfig};
use esp_hal::main;
use esp_hal::rng::{Trng, TrngSource};
use esp_hal::sha::Sha;
use esp_hal::time::{Duration, Instant};
use esp_hal::usb_serial_jtag::UsbSerialJtag;
use esp_hal::Blocking;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256 as SwSha256, Sha512 as SwSha512};
use slh_dsa::signature::Signer;
use slh_dsa::SigningKey;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}


#[cfg(feature = "param-128s")]
type SelectedParams = slh_dsa::Sha2_128s;
#[cfg(feature = "param-128f")]
type SelectedParams = slh_dsa::Sha2_128f;
#[cfg(feature = "param-192s")]
type SelectedParams = slh_dsa::Sha2_192s;
#[cfg(feature = "param-192f")]
type SelectedParams = slh_dsa::Sha2_192f;
#[cfg(feature = "param-256s")]
type SelectedParams = slh_dsa::Sha2_256s;
#[cfg(feature = "param-256f")]
type SelectedParams = slh_dsa::Sha2_256f;

#[cfg(not(any(
    feature = "param-128s",
    feature = "param-128f",
    feature = "param-192s",
    feature = "param-192f",
    feature = "param-256s",
    feature = "param-256f",
)))]
compile_error!("enable exactly one param-* feature, e.g. --features param-192f");

#[cfg(feature = "param-128s")]
const PARAM_SET_NAME: &str = "128s";
#[cfg(feature = "param-128f")]
const PARAM_SET_NAME: &str = "128f";
#[cfg(feature = "param-192s")]
const PARAM_SET_NAME: &str = "192s";
#[cfg(feature = "param-192f")]
const PARAM_SET_NAME: &str = "192f";
#[cfg(feature = "param-256s")]
const PARAM_SET_NAME: &str = "256s";
#[cfg(feature = "param-256f")]
const PARAM_SET_NAME: &str = "256f";

const CORPUS_MESSAGE_COUNT: usize = 100;

const HASH_BENCH_COUNT: usize = 1000;
const HASH_BENCH_MIN_LEN: usize = 100;
const HASH_BENCH_MAX_LEN: usize = 200;
static HASH_BENCH_DATA: [u8; HASH_BENCH_MAX_LEN] = [0xA5; HASH_BENCH_MAX_LEN];
const HMAC_BENCH_KEY: [u8; 24] = [0x5A; 24];

fn hash_bench_len(i: usize) -> usize {
    HASH_BENCH_MIN_LEN + (i % (HASH_BENCH_MAX_LEN - HASH_BENCH_MIN_LEN + 1))
}

fn run_hash_bench(
    usb_serial: &mut UsbSerialJtag<'static, Blocking>,
    label: &str,
    mut op: impl FnMut(&[u8]),
) {
    op(&HASH_BENCH_DATA[..hash_bench_len(0)]);

    let mut timings_us = [0u64; HASH_BENCH_COUNT];
    let mut total_bytes: u64 = 0;
    let wall_start = Instant::now();

    for (i, timing) in timings_us.iter_mut().enumerate() {
        let len = hash_bench_len(i);
        let data = &HASH_BENCH_DATA[..len];

        let start = Instant::now();
        op(data);
        *timing = start.elapsed().as_micros();
        total_bytes += len as u64;
    }

    let wall_elapsed_us = wall_start.elapsed().as_micros();

    timings_us.sort_unstable();
    let min = timings_us[0];
    let max = timings_us[HASH_BENCH_COUNT - 1];
    let sum: u64 = timings_us.iter().sum();
    let average = sum / HASH_BENCH_COUNT as u64;
    let median = (timings_us[HASH_BENCH_COUNT / 2 - 1] + timings_us[HASH_BENCH_COUNT / 2]) / 2;
    let throughput = total_bytes * 1_000_000 / wall_elapsed_us.max(1);

    let _ = write!(
        usb_serial,
        "{label}: min {min} us, max {max} us, median {median} us, average {average} us\r\n\
         {total_bytes} bytes in {wall_elapsed_us} us wall clock ({throughput} bytes/sec)\r\n"
    );
    let _ = usb_serial.flush_tx();
}

static SECRET_KEY_BYTES: &[u8] = include_bytes!("../../keys/sec.key");
static PUBLIC_KEY_BYTES: &[u8] = include_bytes!("../../keys/pub.key");
static MESSAGE_CORPUS: &[u8] = include_bytes!("../../messages/corpus.bin");
static MESSAGE: &[u8] = b"hello from the nano-signer bring-up test";

struct CorpusMessages<'a> {
    remaining: &'a [u8],
}

impl<'a> CorpusMessages<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { remaining: data }
    }
}

impl<'a> Iterator for CorpusMessages<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let (len_bytes, rest) = self.remaining.split_at_checked(4)?;
        let len = u32::from_le_bytes(len_bytes.try_into().unwrap()) as usize;
        let (message, rest) = rest.split_at_checked(len)?;
        self.remaining = rest;
        Some(message)
    }
}

esp_bootloader_esp_idf::esp_app_desc!();

#[allow(
    clippy::large_stack_frames,
    reason = "it's not unusual to allocate larger buffers etc. in main"
)]
#[main]
fn main() -> ! {
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    let _ = peripherals.GPIO27;
    let _ = peripherals.GPIO28;
    let _ = peripherals.GPIO29;
    let _ = peripherals.GPIO30;
    let _ = peripherals.GPIO31;
    let _ = peripherals.GPIO32;

    let mut red = Output::new(peripherals.GPIO46, Level::High, OutputConfig::default());
    let mut green = Output::new(peripherals.GPIO0, Level::High, OutputConfig::default());
    let mut blue = Output::new(peripherals.GPIO45, Level::High, OutputConfig::default());
    let mut orange = Output::new(peripherals.GPIO48, Level::High, OutputConfig::default());

    let mut usb_serial = UsbSerialJtag::new(peripherals.USB_DEVICE);

    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);

    slh_dsa::init_hw_sha(Sha::new(peripherals.SHA));

    loop {
        let Ok(byte) = usb_serial.read_byte() else {
            continue;
        };

        match byte {
            b'r' => red.toggle(),
            b'g' => green.toggle(),
            b'b' => blue.toggle(),
            b'o' => orange.toggle(),
            b't' => {
                
                blue.set_low();

                let signing_key = SigningKey::<SelectedParams>::try_from(SECRET_KEY_BYTES)
                    .expect("embedded secret key must be well-formed");

                let _ = write!(
                    usb_serial,
                    "benchmarking {PARAM_SET_NAME} over {CORPUS_MESSAGE_COUNT} messages\r\n"
                );
                let _ = usb_serial.flush_tx();

                let mut timings_ms = [0u64; CORPUS_MESSAGE_COUNT];
                let mut count = 0;

                for message in CorpusMessages::new(MESSAGE_CORPUS).take(CORPUS_MESSAGE_COUNT) {
                    let start = Instant::now();
                    let Ok(_signature) = signing_key.try_sign(message) else {
                        blue.set_high();
                        let _ = write!(usb_serial, "signing failed on message {}\r\n", count + 1);
                        let _ = usb_serial.flush_tx();

                        red.set_low();
                        let hold_until = Instant::now() + Duration::from_millis(500);
                        while Instant::now() < hold_until {}
                        red.set_high();
                        break;
                    };
                    let elapsed_ms = start.elapsed().as_millis();
                    timings_ms[count] = elapsed_ms;

                    let _ = write!(
                        usb_serial,
                        "[{:>3}/{CORPUS_MESSAGE_COUNT}] {} bytes -> {elapsed_ms} ms\r\n",
                        count + 1,
                        message.len(),
                    );
                    let _ = usb_serial.flush_tx();
                    count += 1;
                }

                if count == CORPUS_MESSAGE_COUNT {
                    blue.set_high();

                    let timings = &mut timings_ms[..count];
                    timings.sort_unstable();
                    let min = timings[0];
                    let max = timings[count - 1];
                    let sum: u64 = timings.iter().sum();
                    let average = sum / count as u64;
                    let median = if count % 2 == 0 {
                        (timings[count / 2 - 1] + timings[count / 2]) / 2
                    } else {
                        timings[count / 2]
                    };

                    let _ = write!(
                        usb_serial,
                        "{PARAM_SET_NAME} over {count} messages: min {min} ms, max {max} ms, median {median} ms, average {average} ms\r\n"
                    );
                    let _ = usb_serial.flush_tx();

                    green.set_low();
                    let hold_until = Instant::now() + Duration::from_millis(500);
                    while Instant::now() < hold_until {}
                    green.set_high();
                }
            }
            b's' => {
                blue.set_low();

                let signing_key = SigningKey::<SelectedParams>::try_from(SECRET_KEY_BYTES)
                    .expect("embedded secret key must be well-formed");

                match signing_key.try_sign(MESSAGE) {
                    Ok(signature) => {
                        blue.set_high();

                        let sig_bytes = signature.to_bytes();
                        let _ = write!(
                            usb_serial,
                            "signed {} bytes with public key ({PARAM_SET_NAME}) ",
                            MESSAGE.len(),
                        );
                        for b in PUBLIC_KEY_BYTES.iter() {
                            let _ = write!(usb_serial, "{b:02x}");
                        }
                        let _ = write!(usb_serial, "\r\nsignature ({} bytes): ", sig_bytes.len());
                        for b in sig_bytes.iter() {
                            let _ = write!(usb_serial, "{b:02x}");
                        }
                        let _ = write!(usb_serial, "\r\n");
                        let _ = usb_serial.flush_tx();

                        green.set_low();
                        let hold_until = Instant::now() + Duration::from_millis(500);
                        while Instant::now() < hold_until {}
                        green.set_high();
                    }
                    Err(_) => {
                        blue.set_high();
                        let _ = write!(usb_serial, "signing failed\r\n");
                        let _ = usb_serial.flush_tx();

                        red.set_low();
                        let hold_until = Instant::now() + Duration::from_millis(500);
                        while Instant::now() < hold_until {}
                        red.set_high();
                    }
                }
            }
            b'k' => {
                red.set_low();
                blue.set_low();

                let Ok(mut trng) = Trng::try_new() else {
                    red.set_high();
                    blue.set_high();
                    let _ = write!(usb_serial, "TRNG unavailable\r\n");
                    let _ = usb_serial.flush_tx();
                    continue;
                };

                let signing_key = SigningKey::<SelectedParams>::new(&mut trng);
                let sec_bytes = signing_key.to_bytes();
                let pub_bytes = signing_key.as_ref().to_bytes();

                red.set_high();
                blue.set_high();

                let _ = write!(
                    usb_serial,
                    "generated with {PARAM_SET_NAME}\r\nsec.key ({} bytes): ",
                    sec_bytes.len()
                );
                for b in sec_bytes.iter() {
                    let _ = write!(usb_serial, "{b:02x}");
                }
                let _ = write!(usb_serial, "\r\npub.key ({} bytes): ", pub_bytes.len());
                for b in pub_bytes.iter() {
                    let _ = write!(usb_serial, "{b:02x}");
                }
                let _ = write!(usb_serial, "\r\nnot written to storage yet\r\n");
                let _ = usb_serial.flush_tx();

                green.set_low();
                let hold_until = Instant::now() + Duration::from_millis(500);
                while Instant::now() < hold_until {}
                green.set_high();
            }
            b'1' => {
                blue.set_low();

                let _ = write!(
                    usb_serial,
                    "SHA-256 over {HASH_BENCH_COUNT} hashes, {HASH_BENCH_MIN_LEN}-{HASH_BENCH_MAX_LEN} bytes\r\n"
                );
                let _ = usb_serial.flush_tx();

                run_hash_bench(&mut usb_serial, "software SHA-256", |data| {
                    let mut hasher = SwSha256::new();
                    hasher.update(data);
                    let _output = hasher.finalize();
                });
                run_hash_bench(&mut usb_serial, "hardware SHA-256", |data| {
                    let _output = slh_dsa::hw_sha256(data);
                });

                blue.set_high();
                green.set_low();
                let hold_until = Instant::now() + Duration::from_millis(500);
                while Instant::now() < hold_until {}
                green.set_high();
            }
            b'2' => {
                blue.set_low();

                let _ = write!(
                    usb_serial,
                    "SHA-512 over {HASH_BENCH_COUNT} hashes, {HASH_BENCH_MIN_LEN}-{HASH_BENCH_MAX_LEN} bytes\r\n"
                );
                let _ = usb_serial.flush_tx();

                run_hash_bench(&mut usb_serial, "software SHA-512", |data| {
                    let mut hasher = SwSha512::new();
                    hasher.update(data);
                    let _output = hasher.finalize();
                });
                run_hash_bench(&mut usb_serial, "hardware SHA-512", |data| {
                    let _output = slh_dsa::hw_sha512(data);
                });

                blue.set_high();
                green.set_low();
                let hold_until = Instant::now() + Duration::from_millis(500);
                while Instant::now() < hold_until {}
                green.set_high();
            }
            b'3' => {
                blue.set_low();

                let _ = write!(
                    usb_serial,
                    "HMAC-SHA-512 over {HASH_BENCH_COUNT} hashes, {HASH_BENCH_MIN_LEN}-{HASH_BENCH_MAX_LEN} bytes\r\n"
                );
                let _ = usb_serial.flush_tx();

                run_hash_bench(&mut usb_serial, "software HMAC-SHA-512", |data| {
                    let mut mac = Hmac::<SwSha512>::new_from_slice(&HMAC_BENCH_KEY).unwrap();
                    mac.update(data);
                    let _output = mac.finalize();
                });
                run_hash_bench(&mut usb_serial, "hardware HMAC-SHA-512", |data| {
                    let _output = slh_dsa::hw_hmac512(&HMAC_BENCH_KEY, data);
                });

                blue.set_high();
                green.set_low();
                let hold_until = Instant::now() + Duration::from_millis(500);
                while Instant::now() < hold_until {}
                green.set_high();
            }
            b'x' => {
                red.set_high();
                green.set_high();
                blue.set_high();
                orange.set_high();
            }
            b'?' => {
                let profile = if cfg!(debug_assertions) { "dev" } else { "release" };
                let _ = write!(
                    usb_serial,
                    "profile={profile} param={PARAM_SET_NAME} red={:?} green={:?} blue={:?} orange={:?}\r\n",
                    red.output_level(),
                    green.output_level(),
                    blue.output_level(),
                    orange.output_level(),
                );
                let _ = usb_serial.flush_tx();
            }
            _ => {}
        }
    }
}
