extern crate tordesc;

use tordesc::server_descriptor::*;

use std::fs::File;
use std::io::{Read,BufReader};
use std::net::Ipv4Addr;
use std::path::Path;

// use the same sample as zoossh to try to ensure compatibility
static SAMPLE: &'static str = r#"@type server-descriptor 1.0
router LetFreedomRing 24.233.74.111 9001 0 0
platform Tor 0.2.6.1-alpha on Linux
protocols Link 1 2 Circuit 1
published 2014-12-05 22:01:13
fingerprint DA4D EC93 C8D2 F187 C027 A96D 3925 C153 1D90 A89E
uptime 339587
bandwidth 20480 20480 16996
extra-info-digest 15FA36289DD75D89B389CED0BE23D80FB50629BD
onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALD6Dbj1okBj4mmz/sCgIGFJk/CTWlMsT3CS1kP7Q2gAaDewEbo1+me3
X5f3QpvZ9Yh2l5Q+btU4a/Yib3pg/KhyX96Z5zrvz9dGPPXGORpwawMIH7Aa+jtp
v2l0misfGCloIamfI5dzayTu9gR4emuKm34tipkfIz6hLkO7xW1nAgMBAAE=
-----END RSA PUBLIC KEY-----
signing-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAM6sVv1ASHBuLe8l3+cF4xATk1n/CqNRqML0Gra0S9UaBnKakm9tk7Vw
PJifL3B318lRDjAE2wTVyM+437TLaROLNBrQOF2apjgJYH661vPFG5Uw6+8CXv6w
tHeXU1pvc/E7SA0IpUjm80z0HhSA3oGwuP4IEB1U1IxxiJNFaBk7AgMBAAE=
-----END RSA PUBLIC KEY-----
hidden-service-dir
contact 0xCDD0190B Craig Andrews <candrews@integralblue.com>
ntor-onion-key q8Qg9PaoBm59j7cEJcOrzTUazVt3D8Ax4L3oaO8PaxU=
reject 0.0.0.0/8:*
reject 169.254.0.0/16:*
reject 127.0.0.0/8:*
reject 192.168.0.0/16:*
reject 10.0.0.0/8:*
reject 172.16.0.0/12:*
reject 24.233.74.111:*
accept *:22
accept *:465
accept *:993
accept *:994
accept *:995
accept *:6660-6697
reject *:*
router-signature
-----BEGIN SIGNATURE-----
vKWlPhEDoRHOKgDNXE07HFl39b4SmGUDo8DStSzzza+CKVw2RnV41wYBpjRJvu2Q
VcQb00bfqWP/DK38GmVMgzKRZ7e1k2TpzaeL3ssD3gS6wJPzbIbcL++yUhtPukk/
tWJ53g/ru8Hiy+h9Wa5gI+Eog/z4hj36GBiaTXJoG3M=
-----END SIGNATURE-----
"#;

#[test]
fn dump_server_descriptor() {
    match parse(SAMPLE) {
        Ok(sd) => println!("{:?}", sd),
        Err(e) => println!("GOT AN ERROR LOL: {:?}", e)
    }
}

#[test]
fn parse_router() {
    let sd = parse(SAMPLE).unwrap();
    assert_eq!(sd.nickname,     "LetFreedomRing");
    assert_eq!(sd.address,      Some(Ipv4Addr::new(24,233,74,111)));
    assert_eq!(sd.or_port,      9001);
    assert_eq!(sd.socks_port,   0);
    assert_eq!(sd.dir_port,     0);
}

#[test]
fn parse_platform() {
    assert_eq!(
        parse(SAMPLE).unwrap().platform,
        Some("Tor 0.2.6.1-alpha on Linux")
    );
}

#[test]
fn parse_protocols() {
    assert_eq!(
        parse(SAMPLE).unwrap().protocols,
        Some("Link 1 2 Circuit 1")
    );
}

#[test]
fn parse_published() {
    assert_eq!(
        parse(SAMPLE).unwrap().published,
        Some("2014-12-05 22:01:13")
    );
}

#[test]
fn parse_fingerprint() {
    assert_eq!(
        parse(SAMPLE).unwrap().fingerprint,
        Some("DA4D EC93 C8D2 F187 C027 A96D 3925 C153 1D90 A89E")
    );
}

#[test]
fn parse_bandwidth() {
    let sd = parse(SAMPLE).unwrap();
    assert_eq!(sd.bandwidth_avg,        20480);
    assert_eq!(sd.bandwidth_burst,      20480);
    assert_eq!(sd.bandwidth_observed,   16996);
}

#[test]
fn parse_extra_info_digest() {
    assert_eq!(
        parse(SAMPLE).unwrap().extra_info_digest,
        Some("15FA36289DD75D89B389CED0BE23D80FB50629BD")
    );
}

#[test]
fn parse_uptime() {
    assert_eq!(parse(SAMPLE).unwrap().uptime, Some(339587));
}

#[test]
fn parse_onion_key() {
    let expected = Some(r#"-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALD6Dbj1okBj4mmz/sCgIGFJk/CTWlMsT3CS1kP7Q2gAaDewEbo1+me3
X5f3QpvZ9Yh2l5Q+btU4a/Yib3pg/KhyX96Z5zrvz9dGPPXGORpwawMIH7Aa+jtp
v2l0misfGCloIamfI5dzayTu9gR4emuKm34tipkfIz6hLkO7xW1nAgMBAAE=
-----END RSA PUBLIC KEY-----
"#);
    assert_eq!(parse(SAMPLE).unwrap().onion_key, expected);
}

#[test]
fn parse_signing_key() {
    let expected = Some(r#"-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAM6sVv1ASHBuLe8l3+cF4xATk1n/CqNRqML0Gra0S9UaBnKakm9tk7Vw
PJifL3B318lRDjAE2wTVyM+437TLaROLNBrQOF2apjgJYH661vPFG5Uw6+8CXv6w
tHeXU1pvc/E7SA0IpUjm80z0HhSA3oGwuP4IEB1U1IxxiJNFaBk7AgMBAAE=
-----END RSA PUBLIC KEY-----
"#);
    assert_eq!(parse(SAMPLE).unwrap().signing_key, expected);
}

#[test]
fn parse_hidden_service_dir() {
    assert_eq!(
        parse(SAMPLE).unwrap().hidden_service_dir,
        None
    );
}

#[test]
fn parse_contact() {
    assert_eq!(
        parse(SAMPLE).unwrap().contact,
        Some("0xCDD0190B Craig Andrews <candrews@integralblue.com>")
    );
}

#[test]
fn parse_all_in_file() {
    let path = Path::new("sample/2016-08-06-03-06-03-server-descriptors");
    // Open the path in read-only mode, returns `io::Result<File>`
    let file = match File::open(&path) {
        Err(why) => panic!("couldn't open {:?}: {}", path, why),
        Ok(file) => file,
    };
    let mut data = String::new();
    let mut br = BufReader::new(file);
    br.read_to_string(&mut data).unwrap();

    let descriptors = parse_all(&data);
    assert_eq!(descriptors.len(), 681);

    // dump everything to stdout, wasted except for when running tests with `--nocapture`
    for d in descriptors {
        println!("{:#?}", d);
    }
}
