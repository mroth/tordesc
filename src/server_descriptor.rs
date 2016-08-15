use std::net::Ipv4Addr;
use std::str;
use std::str::FromStr;
use nom::{line_ending, not_line_ending, alphanumeric, digit, space};
use nom::IResult;

use document::*;

#[derive(Default, Debug)]
pub struct ServerDescriptor<'a> {
    pub nickname: &'a str,
    pub address: Option<Ipv4Addr>, // TODO: figure out how to make this non-optional?

    /// Port at which this OR accepts TLS connections for the main OR protocol
    pub or_port: u16,
    /// SOCKSPort is deprecated and should always be 0
    pub socks_port: u16,
    /// Port at which this OR accepts directory-related HTTP connections
    pub dir_port: u16,

    /// A human-readable string describing the system on which this OR is running.  This MAY
    /// include the operating system, and SHOULD include the name and version of the software
    /// implementing the Tor protocol. [At most once]
    pub platform: Option<&'a str>,

    /// List of protocols supporter by the server.
    ///
    ///   `"Link" SP LINK-VERSION-LIST SP "Circuit" SP CIRCUIT-VERSION-LIST NL`
    ///
    /// Both lists are space-separated sequences of numbers, to indicate which protocols the server
    /// supports.  As of 30 Mar 2008, specified protocols are "Link 1 2 Circuit 1".  See section
    /// 4.1 of `tor-spec.txt` for more information about link protocol versions.
    ///
    /// NOTE: No version of Tor uses this protocol list.  It will be removed in a future version of
    /// Tor. (Because of this, we don't bother to parse it into structured data in this library.)
    pub protocols: Option<&'a str>,

    /// The time, in UTC, when this descriptor (and its corresponding extra-info document if any)
    /// was generated.
    ///
    /// The format for the time is YYYY-MM-DD HH:MM:SS.
    ///
    /// Since Rust does not have a standard datetime in the stdlib (yet), this is left as ASCII so
    /// that the consumer of this library can pick their desired time representation.
    pub published: Option<&'a str>,

    /// A fingerprint (a HASH_LEN-byte of asn1 encoded public key, encoded in hex, with a single
    /// space after every 4 characters) for this router's identity key. A descriptor is considered
    /// invalid (and MUST be rejected) if the fingerprint line does not match the public key.
    pub fingerprint: Option<&'a str>,

    /// The number of seconds that this OR process has been running. [At most once]
    pub uptime: Option<u64>,

    /// Bytes per second that the OR is willing to sustain over long periods
    pub bandwidth_avg: u64,
    /// Bytes per second that the OR is willing to sustain in very short intervals
    pub bandwidth_burst: u64,

    /// The "observed" bandwidth value is an estimate of the capacity this relay can handle.
    ///
    /// The relay remembers the max bandwidth sustained output over any ten second period in the
    /// past day, and another sustained input.  The "observed" value is the lesser of these two
    /// numbers.
    pub bandwidth_observed: u64,

    /// "Digest" is a hex-encoded digest (using upper-case characters) of the router's extra-info
    /// document, as signed in the router's extra-info (that is, not including the signature).  (If
    /// this field is absent, the router is not uploading a corresponding extra-info document.)
    ///
    /// Tor versions before 0.2.0.1-alpha don't recognize this.
    pub extra_info_digest: Option<&'a str>,

    /// This key is used to encrypt CREATE cells for this OR.  The key MUST be accepted for at
    /// least 1 week after any new key is published in a subsequent descriptor. It MUST be 1024
    /// bits.
    ///
    /// The key encoding is the encoding of the key as a PKCS#1 RSAPublicKey structure, encoded in
    /// base64, and wrapped in "-----BEGIN RSA PUBLIC KEY-----" and "-----END RSA PUBLIC KEY-----".
    pub onion_key: Option<&'a str>,

    /// The OR's long-term RSA identity key.  It MUST be 1024 bits
    ///
    /// The encoding is as for "onion-key" above.
    pub signing_key: Option<&'a str>,

    /// Present only if this router stores and serves hidden service descriptors. If any
    /// VersionNum(s) are specified, this router supports those descriptor versions. If none are
    /// specified, it defaults to version 2 descriptors.
    pub hidden_service_dir: Option<&'a str>,

    /// Describes a way to contact the relay's administrator, preferably including an email
    /// address and a PGP key fingerprint.
    pub contact: Option<&'a str>,

    /// A curve25519 public key used for the ntor circuit extended handshake.  It's the standard
    /// encoding of the OR's curve25519 public key, encoded in base 64.  The trailing `=` sign may
    /// be omitted from the base64 encoding.  The key MUST be accepted for at least 1 week after
    /// any new key is published in a subsequent descriptor.
    pub ntor_onion_key: Option<&'a str>,

    /// The `SIGNATURE` object contains a signature of the PKCS1-padded hash of the entire server
    /// descriptor.
    ///
    /// The server descriptor is invalid unless the signature is performed with the router's
    /// identity key.
    pub router_signature: Option<&'a str>, // TODO: make non-Optional and pre-parse as last Item?

    // we own unprocessed items here, for later debugging...
    // they will show up when we dump the items, so easy to visualize what we're not handling.
    unprocessed_items: Vec<Item<'a>>,
}
// TODO: implement Validate() to check things at end?

pub type ParseError = u32;
type Port = u16;


pub fn parse(input: &str) -> Result<ServerDescriptor, ParseError> {
    // dont need to have a parse_item function if we understand named macro return type?
    match server_descriptor_bucket(&input.as_bytes()[..]) {
        IResult::Done(_i, sd)  => Ok(transmogrify(sd)),
        IResult::Error(_)      => Err(1),
        IResult::Incomplete(_) => Err(2),
    }
}

pub fn parse_all(input: &str) -> Vec<ServerDescriptor> {
    parse_all_items(input).into_iter().map(transmogrify).collect()
}

pub fn parse_all_items(input: &str) -> Vec<Vec<Item>> { //TODO: tmp
    match server_descriptor_bucket_aggregator(&input.as_bytes()[..]) {
        IResult::Done(_i, sda) => sda,
        _ => Vec::new()
    }
}

/// Transform a "bucket of items" returns from the parser into a ServiceDescriptor struct.
fn transmogrify(item_bucket: Vec<Item>) -> ServerDescriptor { // TODO: make this a result
    let mut sd: ServerDescriptor = Default::default();
    for item in item_bucket {
        match item {
            Item { key: "router", args: Some(args), ..} => {
                if let IResult::Done(_, p) = router(args.as_bytes()) {
                    let (nickname, address, or_port, socks_port, dir_port) = p;
                    sd.nickname   = nickname;
                    sd.address    = Some(address);
                    sd.or_port    = or_port;
                    sd.socks_port = socks_port;
                    sd.dir_port   = dir_port;
                }
            },

            Item { key: "platform", args: Some(args), ..} => {
                if let IResult::Done(_, p) = platform(args.as_bytes()) {
                    sd.platform = Some(p);
                }
            },

            Item { key: "protocols", args: Some(args), ..} => {
                sd.protocols = Some(args);
            }

            Item { key: "published", args: Some(args), ..} => {
                sd.published = Some(args);
            }

            Item { key: "fingerprint", args: Some(args), ..} => {
                sd.fingerprint = Some(args);
            }

            Item { key: "bandwidth", args: Some(args), ..} => {
                if let IResult::Done(_, p) = bandwidth(args.as_bytes()) {
                    let (avg, bur, obs) = p;
                    sd.bandwidth_avg      = avg;
                    sd.bandwidth_burst    = bur;
                    sd.bandwidth_observed = obs;
                }
            },

            Item { key: "extra-info-digest", args: Some(args), ..} => {
                sd.extra_info_digest = Some(args);
            }

            Item { key: "uptime", args: Some(args), ..} => {
                if let IResult::Done(_, p) = uptime(args.as_bytes()) {
                    sd.uptime = Some(p);
                }
            }

            Item { key: "onion-key", args: None, obj: Some(o)} => {
                sd.onion_key = Some(o);
            }

            Item { key: "signing-key", args: None, obj: Some(o)} => {
                sd.signing_key = Some(o);
            }

            Item { key: "hidden-service-dir", args, ..} => {
                sd.hidden_service_dir = args;
            }

            Item { key: "contact", args: Some(args), ..} => {
                sd.contact = Some(args);
            }

            Item { key: "ntor-onion-key", args: Some(args), ..} => {
                sd.ntor_onion_key = Some(args);
            }

            Item { key: "router-signature", args: None, obj: Some(o)} => {
                sd.router_signature = Some(o);
            }

            _ => {
                sd.unprocessed_items.push(item);
            }
        }
    }
    sd
}



named!(server_descriptor_bucket_aggregator < Vec<Vec<Item>> >, many0!(server_descriptor_bucket));
named!(server_descriptor_bucket < Vec<Item> >,
    chain!(
        tag!("@type server-descriptor 1.0") ~ line_ending ~
        items: many1!(item) ,
        || { items }
    )
);


// "router" nickname address ORPort SOCKSPort DirPort NL
//
//   [At start, exactly once.]
//
//   Indicates the beginning of a server descriptor.  "nickname" must be a
//   valid router nickname as specified in section 2.1.3.  "address" must
//   be an IPv4
//   address in dotted-quad format.  The last three numbers indicate the
//   TCP ports at which this OR exposes functionality. ORPort is a port at
//   which this OR accepts TLS connections for the main OR protocol;
//   SOCKSPort is deprecated and should always be 0; and DirPort is the
//   port at which this OR accepts directory-related HTTP connections.  If
//   any port is not supported, the value 0 is given instead of a port
//   number.  (At least one of DirPort and ORPort SHOULD be set;
//   authorities MAY reject any descriptor with both DirPort and ORPort of
//   0.)
named!(router <&[u8], (&str, Ipv4Addr, Port, Port, Port)>,
    chain!(
                    // tag!("router") ~
                    // space ~
        nickname:   map_res!(alphanumeric, str::from_utf8) ~
                    space ~
        address:    ipv4_addr ~
                    space ~
        or_port:    u16_digit ~
                    space ~
        socks_port: u16_digit ~
                    space ~
        dir_port:   u16_digit ,
                    // space? ~
                    // line_ending ,
        || { (
            nickname,
            address,
            or_port,
            socks_port,
            dir_port,
        ) }
    )
);

// "bandwidth" bandwidth-avg bandwidth-burst bandwidth-observed NL
//
//    [Exactly once]
//
//    Estimated bandwidth for this router, in bytes per second.  The
//    "average" bandwidth is the volume per second that the OR is willing to
//    sustain over long periods; the "burst" bandwidth is the volume that
//    the OR is willing to sustain in very short intervals.  The "observed"
//    value is an estimate of the capacity this relay can handle.  The
//    relay remembers the max bandwidth sustained output over any ten
//    second period in the past day, and another sustained input.  The
//    "observed" value is the lesser of these two numbers.
named!(bandwidth <(u64, u64, u64)>,
    chain!(
        // tag!("bandwidth") ~ space ~
        avg: u64_digit    ~ space ~
        bur: u64_digit    ~ space ~
        obs: u64_digit    ,
        // line_ending       ,
        || { (avg, bur, obs) }
    )
);

// "platform" string NL
//
//    [At most once]
//
//    A human-readable string describing the system on which this OR is
//    running.  This MAY include the operating system, and SHOULD include
//    the name and version of the software implementing the Tor protocol.
named!(platform <&str>,
    map_res!(not_line_ending, str::from_utf8)
);
// named!(platform <&[u8], String>,
//     chain!(
//         tag!("platform") ~ space ~
//         p: map_res!(not_line_ending, str::from_utf8) ,
//         || { p }
//     )
// );

// "uptime" number NL
//
//    [At most once]
//
//    The number of seconds that this OR process has been running.
named!(uptime <u64>,
    call!(u64_digit)
);

// "published" YYYY-MM-DD HH:MM:SS NL
//
//    [Exactly once]
//
//    The time, in UTC, when this descriptor (and its corresponding
//    extra-info document if any)  was generated.

// TODO: implement me



named!(ipv4_addr <Ipv4Addr>,
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

named!(u8_digit<u8>,
    map_res!(
        map_res!(digit, str::from_utf8),
        FromStr::from_str
    )
);

named!(u16_digit<u16>,
    map_res!(
        map_res!(digit, str::from_utf8),
        FromStr::from_str
    )
);

named!(u64_digit<u64>,
    map_res!(
        map_res!(digit, str::from_utf8),
        FromStr::from_str
    )
);
