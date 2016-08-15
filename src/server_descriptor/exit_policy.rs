//! Module related to defining the exit policy for an OR.
//!
//! An exit policy is really just a collection of one or more exit patterns,
//! with significant ordering.

use std::str;
use std::net::{Ipv4Addr, Ipv6Addr};
use nom::hex_digit;
use nom::IResult;

use grammar::*;

// 2.1.3. Nonterminals in server descriptors
//
//    nickname ::= between 1 and 19 alphanumeric characters ([A-Za-z0-9]),
//       case-insensitive.
//    hexdigest ::= a '$', followed by 40 hexadecimal characters
//       ([A-Fa-f0-9]). [Represents a relay by the digest of its identity
//       key.]
//
//    exitpattern ::= addrspec ":" portspec
//    portspec ::= "*" | port | port "-" port
//    port ::= an integer between 1 and 65535, inclusive.
//
//       [Some implementations incorrectly generate ports with value 0.
//        Implementations SHOULD accept this, and SHOULD NOT generate it.
//        Connections to port 0 are never permitted.]
//
//    addrspec ::= "*" | ip4spec | ip6spec
//    ipv4spec ::= ip4 | ip4 "/" num_ip4_bits | ip4 "/" ip4mask
//    ip4 ::= an IPv4 address in dotted-quad format
//    ip4mask ::= an IPv4 mask in dotted-quad format
//    num_ip4_bits ::= an integer between 0 and 32
//    ip6spec ::= ip6 | ip6 "/" num_ip6_bits
//    ip6 ::= an IPv6 address, surrounded by square brackets.
//    num_ip6_bits ::= an integer between 0 and 128
//
//    bool ::= "0" | "1"

/// A order-sensitive collection of `ExitPattern`, defining an OR exit policy.
///
/// The ordering is significant and should be processed accordingly.
pub type ExitPolicy = Vec<ExitPattern>;

/// Defines a single directive in the OR's exit policy.
#[derive(Debug)]
pub struct ExitPattern {
    /// Whether the pattern indicates network traffic that should be accepted or rejected.
    pub rule: Rule,
    /// Specification for network addresses to apply this pattern.
    pub addr: AddrSpec,
    /// Specification for ports to apply this pattern.
    pub port: PortSpec,
}

/// Indicates if a pattern accepts or rejects network traffic.
#[derive(Debug)]
pub enum Rule { Accept, Reject }


#[doc(hidden)]
pub fn parse_exit_pattern(i: &[u8]) -> IResult<&[u8], (AddrSpec, PortSpec)> {
    exit_pattern(i)
}
named!(exit_pattern <(AddrSpec, PortSpec)>,
    chain!(
        a: addr_spec ~
        tag!(":")    ~
        p: port_spec ,
        || { (a, p) }
    )
);

//-----------------------------------------------------------------------------------------------

/// Specification for different ways to define a possible network address or range.
#[derive(Debug, PartialEq)]
pub enum AddrSpec {
    /// Applies to any address.
    Wildcard,
    /// Applies to a defined IPv4 network address or range.
    Ipv4(Ipv4Spec),
    /// Applies to a defined IPv6 network address or range.
    Ipv6(Ipv6Spec),
}

named!(addr_spec <AddrSpec>,
    alt!(
        map!(tag!("*"), |_| AddrSpec::Wildcard) |
        map!(ipv4_spec, |x| AddrSpec::Ipv4(x))  |
        map!(ipv6_spec, |x| AddrSpec::Ipv6(x))
    )
);

//-----------------------------------------------------------------------------------------------

/// Specification for an IPv4 network address or range.
#[derive(Debug, PartialEq)]
pub enum Ipv4Spec {
    /// A single IPv4 network address.
    Addr(Ipv4Addr),
    /// A IPv4 network range defined via CIDR syntax.
    CIDR { addr: Ipv4Addr, prefix: u8 },
    /// A IPv4 network range defined via a bitmask.
    Mask { addr: Ipv4Addr, mask: Ipv4Addr },
}

named!(ipv4_spec <Ipv4Spec>,
    alt!(ipv4_spec_cidr | ipv4_spec_addr)
);
named!(ipv4_spec_addr <Ipv4Spec>,
    map!(ipv4_addr, |x| Ipv4Spec::Addr(x) )
);
// TODO: ipv4_spec_mask
named!(ipv4_spec_cidr <Ipv4Spec>,
    chain!(
        addr: ipv4_addr ~
        tag!("/") ~
        bits: ipv4_numbits ,
        || { Ipv4Spec::CIDR{ addr: addr, prefix: bits } }
    )
);
named!(ipv4_numbits <u8>,
    call!(u8_digit) // TODO: verify in range 0..32
);

//-----------------------------------------------------------------------------------------------

/// Specification for an IPv6 network address or range.
#[derive(Debug, PartialEq)]
pub enum Ipv6Spec {
    /// A single IPv6 network address.
    Addr(Ipv6Addr),
    /// A IPv6 network range defined via CIDR syntax.
    CIDR { addr: Ipv6Addr, prefix: u8 },
}

named!(ipv6_spec <Ipv6Spec>,
    alt!(ipv6_spec_cidr | ipv6_spec_addr)
);
named!(ipv6_spec_addr <Ipv6Spec>,
    map!(ipv6_addr, |x| Ipv6Spec::Addr(x) )
);
named!(ipv6_spec_cidr <Ipv6Spec>,
    chain!(
        addr: ipv6_addr ~
        tag!("/") ~
        bits: ipv6_numbits ,
        || { Ipv6Spec::CIDR{ addr: addr, prefix: bits } }
    )
);

// tor claims to wrap ipv6 addr in [] in this context
// TODO: this is not robust, as Ipv6 addresses can be encoded in many different shorthands,
// including omitting sections with "::".  Eventually this should be replaced with a robust
// address parser (or just parse the string and offload to external libray), if people start
// actually using these....
named!(ipv6_addr <Ipv6Addr>,
    chain!(
           tag!("[")     ~
        a: u16_hex_digit ~
           tag!(":")     ~
        b: u16_hex_digit ~
           tag!(":")     ~
        c: u16_hex_digit ~
           tag!(":")     ~
        d: u16_hex_digit ~
           tag!(":")     ~
        e: u16_hex_digit ~
           tag!(":")     ~
        f: u16_hex_digit ~
           tag!(":")     ~
        g: u16_hex_digit ~
           tag!(":")     ~
        h: u16_hex_digit ~
           tag!("]")     ,
        || { Ipv6Addr::new(a,b,c,d,e,f,g,h) }
    )
);

named!(u16_hex_digit <u16>,
    map_res!(
        map_res!(hex_digit, str::from_utf8),
        |h| u16::from_str_radix(h, 16)
    )
);

named!(ipv6_numbits <u8>,
    call!(u8_digit) // TODO: verify in range 0..128
);

//-----------------------------------------------------------------------------------------------

/// Specification for a socket port or port range.
#[derive(Debug, PartialEq)]
pub enum PortSpec {
    /// Any valid port number.
    Wildcard,
    /// A specific port number.
    Port(u16),
    /// All port numbers contained in range.
    Range(::std::ops::Range<u16>),
}

named!(port_spec <PortSpec>,
    alt_complete!( port_spec_range | port_spec_port | map!(tag!("*"), |_| PortSpec::Wildcard) )
);
named!(port_spec_range <PortSpec>,
    chain!(
        start: u16_digit ~
        tag!("-") ~
        end: u16_digit ,
        || { PortSpec::Range(start..end) } )
);
named!(port_spec_port <PortSpec>, map!(u16_digit, |d| PortSpec::Port(d)) );

//-----------------------------------------------------------------------------------------------


// TODO: this should be hidden away...
#[test]
fn test_exit_pattern() {
    let test_cases = vec![
        (
            "0.0.0.0/8:*",
            AddrSpec::Ipv4(Ipv4Spec::CIDR { addr: Ipv4Addr::new(0,0,0,0), prefix: 8 }),
            PortSpec::Wildcard
        ),
        (
            "169.254.0.0/16:*",
            AddrSpec::Ipv4(Ipv4Spec::CIDR { addr: Ipv4Addr::new(169,254,0,0), prefix: 16 }),
            PortSpec::Wildcard
        ),
        (
            "*:666",
            AddrSpec::Wildcard,
            PortSpec::Port(666)
        ),
        (
            "*:6660-6697",
            AddrSpec::Wildcard,
            PortSpec::Range(6660..6697)
        ),
        (
            "*:*",
            AddrSpec::Wildcard,
            PortSpec::Wildcard
        ),
        (
            "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:*",
            AddrSpec::Ipv6(Ipv6Spec::Addr(
                Ipv6Addr::new(0x2001,0x0db8,0x85a3,0x0000,0x0000,0x8a2e,0x0370,0x7334)
            )),
            PortSpec::Wildcard
        ),
    ];

    for (input, expected_addr, expected_port) in test_cases {
        // matches into IResult::Done successfully
        let (remaining, (res_addr, res_port)) = exit_pattern(input.as_bytes()).unwrap();
        // no input remaining
        assert_eq!(remaining, []);
        // expected results
        assert_eq!(res_addr, expected_addr);
        assert_eq!(res_port, expected_port);
    }
}
