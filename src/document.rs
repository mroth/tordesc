//  1.2. Document meta-format
//
//  Server descriptors, directories, and running-routers documents all obey the
//  following lightweight extensible information format.
//
//  The highest level object is a Document, which consists of one or more
//  Items.  Every Item begins with a KeywordLine, followed by zero or more
//  Objects. A KeywordLine begins with a Keyword, optionally followed by
//  whitespace and more non-newline characters, and ends with a newline.  A
//  Keyword is a sequence of one or more characters in the set [A-Za-z0-9-].
//  An Object is a block of encoded data in pseudo-Open-PGP-style
//  armor. (cf. RFC 2440)
//
//  More formally:
//
//    NL = The ascii LF character (hex value 0x0a).
//    Document ::= (Item | NL)+
//    Item ::= KeywordLine Object*
//    KeywordLine ::= Keyword NL | Keyword WS ArgumentChar+ NL
//    Keyword = KeywordChar+
//    KeywordChar ::= 'A' ... 'Z' | 'a' ... 'z' | '0' ... '9' | '-'
//    ArgumentChar ::= any printing ASCII character except NL.
//    WS = (SP | TAB)+
//    Object ::= BeginLine Base64-encoded-data EndLine
//    BeginLine ::= "-----BEGIN " Keyword "-----" NL
//    EndLine ::= "-----END " Keyword "-----" NL
//
//    The BeginLine and EndLine of an Object must use the same keyword.
//
//  When interpreting a Document, software MUST ignore any KeywordLine that
//  starts with a keyword it doesn't recognize; future implementations MUST NOT
//  require current clients to understand any KeywordLine not currently
//  described.
//
//  Other implementations that want to extend Tor's directory format MAY
//  introduce their own items.  The keywords for extension items SHOULD start
//  with the characters "x-" or "X-", to guarantee that they will not conflict
//  with keywords used by future versions of Tor.

use std::str;
use nom::{line_ending, not_line_ending, space, alphanumeric};

#[derive(Debug)]
pub struct Item<'a> { pub key: &'a str, pub args: Option<&'a str>, pub obj: Option<&'a str> }
named!(pub item <Item>,
    chain!(
        kl:   keyword_line ~
        obj:  opt!(map_res!(object, str::from_utf8)) ,
        || { Item{ key: kl.key,  args: kl.args, obj: obj } }
    )
);


#[derive(Debug)]
struct KeywordLine<'a> { key: &'a str, args: Option<&'a str> }
named!(keyword_line <KeywordLine>,
    chain!(
        key:  map_res!(keyword, str::from_utf8) ~
        args: opt!( map_res!(keyword_args, str::from_utf8) ) ~
        line_ending ,
        || { KeywordLine{ key: key, args: args } }
    )
);

named!(keyword_args,
    chain!(
        space ~
        args: not_line_ending ,
        || { args }
    )
);
named!(keyword, recognize!(many1!(keyword_char)));
named!(keyword_char,
    alt!(alphanumeric | tag!("-"))
);


named!(object,
    recognize!(
        chain!(
            object_beginline ~
            base64_encoding ~
            object_endline ,
            || {}
        )
    )
);

named!(base64_encoding,
    recognize!(many1!(alt!(base64_char | line_ending)))
);
named!(base64_char,
    alt!(alphanumeric | tag!("/") | tag!("+") | tag!("="))
);
named!(object_beginline,
    recognize!( chain!( tag!("-----BEGIN ") ~ object_type ~ tag!("-----") ~ line_ending , || {}))
);
named!(object_endline,
    recognize!( chain!( tag!("-----END ")   ~ object_type ~ tag!("-----") ~ line_ending , || {}))
);
// the torspec documentation says this is a KeywordChar, but it's different!
named!(object_type, recognize!(many1!(object_char)));
named!(object_char,
    alt!(alphanumeric | space)
);


// #[cfg(test)]
// mod tests {
//     use super::*;
//
//     #[test]
//     fn it_works() {
//     }
// }
