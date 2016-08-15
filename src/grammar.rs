//! Common parsing grammar that doesn't belong anywhere else topically, but is accessed
//! in multiple modules.
//!
//! Really just a grab-bag of sorts.
//!
//! TODO: Either figure out how to extract all this back into topical areas,
//! or clean it up and encapsulate it more properly.

use std::str;
use std::str::FromStr;
use std::net::Ipv4Addr;

use nom::{digit};

named!(pub ipv4_addr <Ipv4Addr>,
    chain!(
        a: u8_digit  ~
        tag!(".") ~
        b: u8_digit  ~
        tag!(".") ~
        c: u8_digit  ~
        tag!(".") ~
        d: u8_digit  ,
        || {
            Ipv4Addr::new(a,b,c,d)
        }
    )
);

named!(pub u8_digit<u8>,
    map_res!(
        map_res!(digit, str::from_utf8),
        FromStr::from_str
    )
);

named!(pub u16_digit<u16>,
    map_res!(
        map_res!(digit, str::from_utf8),
        FromStr::from_str
    )
);

named!(pub u64_digit<u64>,
    map_res!(
        map_res!(digit, str::from_utf8),
        FromStr::from_str
    )
);
