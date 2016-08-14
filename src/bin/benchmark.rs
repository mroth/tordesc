extern crate tordesc;

use std::env;
use std::fs::File;
use std::io::{Read,BufReader};
use std::cmp::min;
use std::time::Instant;


// TODO: for another good example, see also: https://github.com/shepmaster/sxd-document

fn measure_average_advertised_bandwidth(filename: String) {
    // Open the path in read-only mode, returns `io::Result<File>`
    let file = match File::open(&filename) {
        Err(e) => panic!("{}", e),
        Ok(file) => file,
    };

    let mut data = String::new();
    let mut br = BufReader::new(file);
    br.read_to_string(&mut data).unwrap();

    let start = Instant::now();
    let (mut total_bw, mut count) = (0, 0);
    for sd in tordesc::server_descriptor::parse_all(&data) {
        total_bw += min( min(sd.bandwidth_avg, sd.bandwidth_burst), sd.bandwidth_observed);
        count += 1;
    }
    let duration = start.elapsed();
    let nanos = duration.as_secs() * 100000000 + duration.subsec_nanos() as u64;

    println!("Finished measure_average_advertised_bandwidth('{}')", filename);
    println!("  Total time: {:.2}ms", nanos as f64 / 1_000_000f64);
    println!("  Processed server descriptors: {}", count);
    println!("  Average advertised bandwidth: {}", (total_bw / count));
    println!("  Time per server descriptor: {}ns", (nanos / count));
}

fn main() {
    let mut args: Vec<_> = env::args().collect();
    let filename = args.remove(1);

    measure_average_advertised_bandwidth(filename);
}
