//! Relay Server Descriptors (`@type server-descriptor 1.0`).

use std::str;
use std::net::Ipv4Addr;
use nom::{line_ending, alphanumeric, space};
use nom::IResult;

pub mod exit_policy;
use self::exit_policy::*;

use document::*;
use grammar::*;

/// Common data from a parsed server descriptor.
#[derive(Default, Debug)]
pub struct ServerDescriptor<'a> {
    /// Router nickname.
    pub nickname: &'a str,

    /// IPv4 network address for the OR.
    pub address: Option<Ipv4Addr>, // TODO: figure out how to make this non-optional?

    /// Port at which this OR accepts TLS connections for the main OR protocol.
    pub or_port: u16,
    /// SOCKSPort is deprecated and should always be 0.
    pub socks_port: u16,
    /// Port at which this OR accepts directory-related HTTP connections.
    pub dir_port: u16,

    /// The certificate is a base64-encoded Ed25519 certificate (see `cert-spec.txt`) with
    /// terminating =s removed.  When this element is present, it MUST appear as the first or
    /// second element in the router descriptor.
    ///
    /// The certificate has CERT_TYPE of [04].  It must include a signed-with-ed25519-key extension
    /// (see `cert-spec.txt`, section `2.2.1`), so that we can extract the master identity key.
    pub identity_ed25519: Option<&'a str>,

    /// Contains the base-64 encoded ed25519 master key.
    ///
    /// If it is present, it MUST match the identity key in the identity-ed25519 entry.
    pub master_key_ed25519: Option<&'a str>,

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
    /// _NOTE: No version of Tor uses this protocol list.  It will be removed in a future version
    /// of Tor. (Because of this, we don't bother to parse it into structured data in this
    /// library.)_
    pub protocols: Option<&'a str>,

    /// The time, in UTC, when this descriptor (and its corresponding extra-info document if any)
    /// was generated.
    ///
    /// The format for the time is `YYYY-MM-DD HH:MM:SS`.
    ///
    /// Since Rust does not have a standard datetime in the stdlib (yet), this is left as ASCII so
    /// that the consumer of this library can pick their desired time representation.
    pub published: Option<&'a str>,

    /// A fingerprint (a `HASH_LEN`-byte of asn1 encoded public key, encoded in hex, with a single
    /// space after every 4 characters) for this router's identity key. A descriptor is considered
    /// invalid (and MUST be rejected) if the fingerprint line does not match the public key.
    pub fingerprint: Option<&'a str>,

    /// The number of seconds that this OR process has been running.
    pub uptime: Option<u64>,

    /// Bytes per second that the OR is willing to sustain over long periods.
    pub bandwidth_avg: u64,

    /// Bytes per second that the OR is willing to sustain in very short intervals.
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
    /// Tor versions before `0.2.0.1-alpha` don't recognize this.
    pub extra_info_digest: Option<&'a str>,

    /// This key is used to encrypt CREATE cells for this OR.  The key MUST be accepted for at
    /// least 1 week after any new key is published in a subsequent descriptor. It MUST be 1024
    /// bits.
    ///
    /// The key encoding is the encoding of the key as a PKCS#1 RSAPublicKey structure, encoded in
    /// base64, and wrapped in `-----BEGIN RSA PUBLIC KEY-----` and `-----END RSA PUBLIC KEY-----`.
    pub onion_key: Option<&'a str>,

    /// The OR's long-term RSA identity key.  It MUST be 1024 bits.
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

    /// Contains an Ed25519 signature of a SHA256 digest of the entire document, from the first
    /// character up to and including the first space after the "router-sig-ed25519" string,
    /// prefixed with the string "Tor router descriptor signature v1".
    ///
    /// Required when identity-ed25519 is present; forbidden otherwise.
    ///
    /// The signature is encoded in Base64 with terminating `=`s removed.
    ///
    /// The signing key in the identity-ed25519 certificate MUST be the one used to sign the
    /// document.
    pub router_sig_ed25519: Option<&'a str>,

    /// The `SIGNATURE` object contains a signature of the PKCS1-padded hash of the entire server
    /// descriptor.
    ///
    /// The server descriptor is invalid unless the signature is performed with the router's
    /// identity key.
    pub router_signature: Option<&'a str>, // TODO: make non-Optional and pre-parse as last Item?

    /// The rules this OR follows when deciding whether to allow a new stream to a given address.
    pub exit_policy: ExitPolicy,

    /// Items we have successfully parsed from a ServerDescriptor, but have not been processed
    /// into structured data.
    ///
    /// This is most likely either something not built in to this library yet, or third-party
    /// extensions to the format.
    ///
    /// Extensions, wat? Yep:
    ///  > Other implementations that want to extend Tor's directory format MAY
    ///  > introduce their own items.  The keywords for extension items SHOULD start
    ///  > with the characters `x-` or `X-`, to guarantee that they will not conflict
    ///  > with keywords used by future versions of Tor.
    ///
    /// This is primarily provided for debugging purposes, or if you want to get access to
    /// something strange.
    pub unprocessed_items: Vec<Item<'a>>,
}
// TODO: implement Validate() to check things at end?

// TODO: we can do better than this for communicating error handling.
pub type ParseError = u32;

pub fn parse(input: &str) -> Result<ServerDescriptor, ParseError> {
    // dont need to have a parse_item function if we understand named macro return type?
    match server_descriptor_bucket(&input.as_bytes()[..]) {
        IResult::Done(_i, sd)  => Ok(transmogrify(sd)),
        IResult::Error(_)      => Err(1),
        IResult::Incomplete(_) => Err(2),
    }
}

pub fn parse_all(input: &str) -> Vec<ServerDescriptor> {
    extract_all_item_buckets(input).into_iter().map(transmogrify).collect()
}

fn extract_all_item_buckets(input: &str) -> Vec<Vec<Item>> {
    match server_descriptor_bucket_aggregator(&input.as_bytes()[..]) {
        IResult::Done(_i, sda) => sda,
        _ => Vec::new()
    }
}

/// Transform a "bucket of items" returns from the parser into a ServiceDescriptor struct.
fn transmogrify(item_bucket: Vec<Item>) -> ServerDescriptor { // TODO: make this a result
    let mut sd: ServerDescriptor = Default::default();

    for item in item_bucket {
        // common pattern for an Item with a KeywordLine consisting of one REQUIRED arg that is
        // simply treated as a blob of text, with no additional processing required, just store it
        // in `$field`.
        macro_rules! singleton_arg { (.$field:ident) => {{
            if let (Some(args), 0) = (item.args, item.objs.len()) {
                sd.$field = Some(args);
            } else {
                sd.unprocessed_items.push(item);
            }
        }}}

        // common pattern for an Item that contains exactly one object (& no args), which will be
        // simply treated as a blob of text, with no additional processing required, just store it
        // in `$field`.
        macro_rules! first_obj { (.$field:ident) => {{
            if (None, 1) == (item.args, item.objs.len()) {
                sd.$field = Some(item.objs[0]); //safe because of above len() check
            } else {
                sd.unprocessed_items.push(item);
            }
        }}}

        // common pattern for an Item where the KeywordLine args will parsed with an additional
        // Nom parser.  Takes the identifier of the parser,  and a closure which will function
        // as the results handler for the return value of a successful parse.
        //
        // If the parser fails for any reason (error, incompete data), the Item is merely added
        // to the unprocessed_items list.
        macro_rules! use_parser { ($parser:ident, $results_handler:expr) => {{
            if let Some(args) = item.args {
                if let IResult::Done(_, res) = $parser(args.as_bytes()) {
                    $results_handler(res);
                    continue;
                }
            }
            sd.unprocessed_items.push(item);
        }}}

        match item.key {
            "platform"             => singleton_arg!(.platform),
            "identity-ed25519"     => first_obj!(.identity_ed25519),
            "master-key-ed25519"   => singleton_arg!(.master_key_ed25519),
            "protocols"            => singleton_arg!(.protocols),
            "fingerprint"          => singleton_arg!(.fingerprint),
            "published"            => singleton_arg!(.published),
            "extra-info-digest"    => singleton_arg!(.extra_info_digest),
            "onion-key"            => first_obj!(.onion_key),
            "signing-key"          => first_obj!(.signing_key),
            "contact"              => singleton_arg!(.contact),
            "ntor-onion-key"       => singleton_arg!(.ntor_onion_key),
            "router-sig-ed25519"   => singleton_arg!(.router_sig_ed25519),
            "router-signature"     => first_obj!(.router_signature),

            "router" => use_parser!(router, |r| {
                let (nickname, address, or_port, socks_port, dir_port) = r;
                sd.nickname   = nickname;
                sd.address    = Some(address);
                sd.or_port    = or_port;
                sd.socks_port = socks_port;
                sd.dir_port   = dir_port;
            }),

            "bandwidth" => use_parser!(bandwidth, |r| {
                let (avg, bur, obs)   = r;
                sd.bandwidth_avg      = avg;
                sd.bandwidth_burst    = bur;
                sd.bandwidth_observed = obs;
            }),

            "uptime" => {
                use_parser!(uptime, |r| sd.uptime = Some(r) )
            }

            "hidden-service-dir" => {
                sd.hidden_service_dir = item.args;
            }

            "accept" | "reject" => {
                let rule = match item.key {
                    "accept" => Rule::Accept,
                    "reject" => Rule::Reject,
                    _ => unreachable!(),
                };

                use_parser!(parse_exit_pattern, |(a,p)| {
                    sd.exit_policy.push( ExitPattern{ rule: rule, addr: a, port: p } );
                })
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
named!(router <&[u8], (&str, Ipv4Addr, u16, u16, u16)>,
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

// "uptime" number NL
//
//    [At most once]
//
//    The number of seconds that this OR process has been running.
named!(uptime <u64>,
    call!(u64_digit)
);
