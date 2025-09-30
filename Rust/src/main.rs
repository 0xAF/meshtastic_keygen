use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use rand::rngs::SmallRng;
use rand::{RngCore, SeedableRng};
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};
use std::env;
use std::io::{self, Write};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;

const DEFAULT_THREADS: usize = 4;

#[derive(Clone)]
struct Pattern {
    prefix: Vec<u8>,
    suffix: Vec<u8>, // prefix + '='
    suffix_off: usize,
}

#[derive(Clone)]
struct Config {
    threads: usize,
    patterns: Vec<Pattern>,
    count: u64,
    quiet: bool,
    affinity: bool,
}

fn is_base64_search(s: &str) -> bool {
    if s.is_empty() { return false; }
    s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/')
}

fn human(n: u64) -> String {
    const SUF: [&str; 7] = ["", "K", "M", "G", "T", "P", "E"];
    let mut v = n as f64;
    let mut i = 0usize;
    while v >= 1000.0 && i < SUF.len()-1 { v /= 1000.0; i += 1; }
    if n >= 1000 && v < 10.0 { format!("{:.2}{}", v, SUF[i]) }
    else if n >= 1000 && v < 100.0 { format!("{:.1}{}", v, SUF[i]) }
    else { format!("{:.0}{}", v, SUF[i]) }
}

fn parse_args() -> Result<Config, String> {
    let args: Vec<String> = env::args().collect();
    let mut threads = DEFAULT_THREADS;
    let mut searches: Vec<String> = Vec::new();
    let mut count: u64 = 1;
    let mut quiet: bool = false;
    let mut affinity: bool = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-t" | "--threads" => {
                i += 1; if i >= args.len() { return Err("missing value for --threads".into()); }
                threads = usize::from_str(&args[i]).map_err(|_| "invalid threads value".to_string())?;
                if threads == 0 { return Err("threads must be > 0".into()); }
            }
            "-s" | "--search" => {
                i += 1; if i >= args.len() { return Err("missing value for --search".into()); }
                searches.push(args[i].clone());
            }
            "-c" | "--count" => {
                i += 1; if i >= args.len() { return Err("missing value for --count".into()); }
                count = u64::from_str(&args[i]).map_err(|_| "invalid count value".to_string())?;
                if count == 0 { return Err("count must be > 0".into()); }
            }
            "-q" | "--quiet" => {
                quiet = true;
            }
            "--affinity" => {
                affinity = true;
            }
            "-h" | "--help" => {
                print_usage(&args[0]);
                std::process::exit(0);
            }
            _ => return Err(format!("unknown argument: {}", args[i])),
        }
        i += 1;
    }

    if searches.is_empty() { return Err("--search is required (can be specified multiple times)".into()); }
    let mut patterns = Vec::with_capacity(searches.len());
    for s in searches {
        if !is_base64_search(&s) { return Err("search must contain only Base64 chars [A-Za-z0-9+/]".into()); }
        let prefix = s.into_bytes();
        let mut suffix = prefix.clone();
        suffix.push(b'=');
        let suffix_off = if suffix.len() <= 44 { 44 - suffix.len() } else { 0 };
        patterns.push(Pattern { prefix, suffix, suffix_off });
    }

    Ok(Config { threads, patterns, count, quiet, affinity })
}

fn print_usage(prog: &str) {
    eprintln!(
        "Usage: {} -s STR [-s STR]... [-t N] [-c C] [-q] [--affinity]\n  -s, --search  STR: Base64 chars only [A-Za-z0-9+/] (no '='); can be given multiple times\n  -t, --threads N  : worker threads (default {})\n  -c, --count   C  : stop after C matches (default 1)\n  -q, --quiet      : disable periodic reporting\n      --affinity   : pin worker threads to CPU cores",
        prog, DEFAULT_THREADS
    );
}

#[inline]
fn clamp_x25519_scalar(sk: &mut [u8; 32]) {
    sk[0] &= 248;
    sk[31] &= 127;
    sk[31] |= 64;
}

fn worker(cfg: Arc<Config>, stop: Arc<AtomicBool>, total: Arc<AtomicU64>, found: Arc<AtomicU64>, tid: usize) {
    // Pre-allocate buffers
    let mut rng = SmallRng::from_entropy();
    let mut sk = [0u8; 32];
    let mut b64_pub = [0u8; 44];  // public b64
    let mut b64_priv = [0u8; 44]; // private b64 (only used on match)
    let patterns = cfg.patterns.clone();
    let mut local = 0u64;

    // Optional: set thread affinity for better cache locality
    if cfg.affinity {
        if let Some(cores) = core_affinity::get_core_ids() {
            if !cores.is_empty() {
                let core = cores[tid % cores.len()];
                let _ = core_affinity::set_for_current(core);
            }
        }
    }

    while !stop.load(Ordering::Relaxed) {
    rng.fill_bytes(&mut sk);
    clamp_x25519_scalar(&mut sk);
    // Compute public key from private
    let pub_bytes = x25519(sk, X25519_BASEPOINT_BYTES);

    // Encode public key to base64
    let n = STANDARD.encode_slice(&pub_bytes, &mut b64_pub).unwrap();
    debug_assert_eq!(n, 44);

    // Safety: buffer is ASCII; compare as bytes to avoid allocation
    let enc = &b64_pub[..n];
        if { local += 1; local >= 1024 } {
            total.fetch_add(local, Ordering::Relaxed);
            local = 0;
        }

        let mut matches_any = false;
        for p in &patterns {
            if (enc.len() >= p.prefix.len() && &enc[..p.prefix.len()] == &*p.prefix) ||
               (enc.len() >= p.suffix.len() && &enc[p.suffix_off..] == &*p.suffix) {
                matches_any = true; break;
            }
        }
        if matches_any {
            // Encode private key only when needed and print both
            let n_priv = STANDARD.encode_slice(&sk, &mut b64_priv).unwrap();
            debug_assert_eq!(n_priv, 44);
            let pub_str = std::str::from_utf8(enc).unwrap();
            let priv_str = std::str::from_utf8(&b64_priv[..n_priv]).unwrap();
            let line = format!("FOUND: pub={} priv={}", pub_str, priv_str);
            safe_println(&line);
            safe_eprintln(&line);
            let c = found.fetch_add(1, Ordering::Relaxed) + 1;
            if c >= cfg.count {
                stop.store(true, Ordering::Relaxed);
                break;
            }
        }
    }

    if local > 0 { total.fetch_add(local, Ordering::Relaxed); }
}

#[inline]
fn safe_println(line: &str) {
    let mut out = io::stdout();
    let _ = writeln!(out, "{}", line);
}

#[inline]
fn safe_eprintln(line: &str) {
    let mut err = io::stderr();
    let _ = writeln!(err, "{}", line);
}

fn main() {
    let cfg = match parse_args() {
        Ok(c) => Arc::new(c),
        Err(e) => { eprintln!("Error: {}", e); print_usage(&env::args().next().unwrap()); std::process::exit(1); }
    };

    // Track start time
    let start_instant = std::time::Instant::now();
    let start_wall: chrono::DateTime<chrono::Local> = chrono::Local::now();
    // println!("Start: {}", start_wall.format("%Y-%m-%d %H:%M:%S%:z"));
    safe_eprintln(&format!("Start: {}", start_wall.format("%Y-%m-%d %H:%M:%S%:z")));

    let stop = Arc::new(AtomicBool::new(false));
    let total = Arc::new(AtomicU64::new(0));
    let found = Arc::new(AtomicU64::new(0));

    // Ctrl-C handler for clean shutdown
    {
        let stop_c = Arc::clone(&stop);
        ctrlc::set_handler(move || {
            stop_c.store(true, Ordering::Relaxed);
        }).expect("failed to set Ctrl-C handler");
    }

    // Reporter thread (5s interval, per-second rate)
    let reporter = if !cfg.quiet {
        let stop_r = Arc::clone(&stop);
        let total_r = Arc::clone(&total);
        Some(thread::spawn(move || {
            let mut last = 0u64;
            while !stop_r.load(Ordering::Relaxed) {
                thread::sleep(std::time::Duration::from_secs(5));
                let t = total_r.load(Ordering::Relaxed);
                let d = t - last; last = t;
                let per_sec = d / 5;
                safe_eprintln(&format!("Keys: total={}, {}/s", human(t), human(per_sec)));
            }
        }))
    } else { None };

    // Workers
    let mut handles = Vec::with_capacity(cfg.threads);
    for i in 0..cfg.threads {
        let cfg_c = Arc::clone(&cfg);
        let stop_c = Arc::clone(&stop);
        let total_c = Arc::clone(&total);
        let found_c = Arc::clone(&found);
        handles.push(thread::spawn(move || worker(cfg_c, stop_c, total_c, found_c, i)));
    }

    for h in handles { let _ = h.join(); }
    stop.store(true, Ordering::Relaxed);
    if let Some(r) = reporter { let _ = r.join(); }

    // Final summary
    let elapsed = start_instant.elapsed();
    let secs = elapsed.as_secs_f64();
    let total_final = total.load(Ordering::Relaxed);
    let found_final = found.load(Ordering::Relaxed);
    // println!(
    //     "Done. Elapsed: {:.3}s | total keys: {} | found: {} | rate: {}/s",
    //     secs, human(total_final), found_final, human((total_final as f64 / secs.max(1e-9)) as u64)
    // );
    safe_eprintln(&format!(
        "Done. Elapsed: {:.3}s | total keys: {} | found: {} | rate: {}/s",
        secs, human(total_final), found_final, human((total_final as f64 / secs.max(1e-9)) as u64)
    ));
}
