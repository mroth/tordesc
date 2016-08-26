extern crate tordesc;

use std::env;
use std::fs::File;
use std::io::{Read,BufReader};
use std::cmp::min;
use std::time::Instant;
use std::collections::HashMap;

fn measure_average_advertised_bandwidth(for_filename: &str) {
    let data = file_data(for_filename);

    let start = Instant::now();
    let (mut total_bw, mut count) = (0, 0);
    for sd in tordesc::server_descriptor::parse_all(&data) {
        total_bw += min( min(sd.bandwidth_avg, sd.bandwidth_burst), sd.bandwidth_observed);
        count += 1;
    }
    let duration = start.elapsed();
    let nanos = duration.as_secs() * 100000000 + duration.subsec_nanos() as u64;

    println!("Finished measure_average_advertised_bandwidth('{}')", for_filename);
    println!("  Total time: {:.2}ms", nanos as f64 / 1_000_000f64);
    println!("  Processed server descriptors: {}", count);
    println!("  Average advertised bandwidth: {}", (total_bw / count));
    println!("  Time per server descriptor: {}ns", (nanos / count));
}

fn find_unprocessed_items(for_filename: &str) {
    let data = file_data(for_filename);

    let (mut total_count, mut unprocessed_count) = (0, 0);
    let mut unprocessed_keys = HashMap::new();

    for sd in tordesc::server_descriptor::parse_all(&data) {
        total_count += 1;
        if sd.unprocessed_items.len() >= 1 {
            unprocessed_count += 1;
            for item in sd.unprocessed_items {
                *unprocessed_keys.entry(item.key).or_insert(0) += 1;
            }
        }
    }

    println!("Finished find_unparsed_items('{}')", for_filename);
    println!("  Processed server descriptors:    {}", total_count);
    println!("  Descriptors with unparsed items: {}", unprocessed_count);
    println!("  -------------------------------------");

    let mut count_keys: Vec<_> = unprocessed_keys.iter().collect();
    count_keys.sort_by(|a,b| a.1.cmp(b.1).reverse());
    for (key, count) in count_keys {
        println!("    {:28} {:5}", key, count);
    }
}

fn file_data(filename: &str) -> String {
    // Open the path in read-only mode, returns `io::Result<File>`
    let file = match File::open(&filename) {
        Err(e) => panic!("{}", e),
        Ok(file) => file,
    };
    let mut data = String::new();
    let mut br = BufReader::new(file);
    br.read_to_string(&mut data).unwrap();
    return data;
}

fn main() {
    let mut args: Vec<_> = env::args().collect();
    let filename = args.remove(1);

    find_unprocessed_items(&filename); println!("");
    measure_average_advertised_bandwidth(&filename);
}
