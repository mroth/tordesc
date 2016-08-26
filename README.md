# tordesc-rs
> Tor network descriptor parsing library, written in Rust.

An experimental proof-of-concept implementation of parsing Tor network
descriptors via a Rust library.

Why?

1. Written with the excellent [Nom] zero-copy parser combinator framework, which
allows for parsing rules to be written in a more formal, precise format — while
still being quite performant. (In my toy benchmarks, it already appears to
parse a server descriptor a bit faster than zoossh.)
2. Rust supposedly is quite easy to produce libraries for other languages, so
this could be used to power a fast extension Python or Ruby, etc. There
currently is a project idea[[1]] from the Tor project suggesting doing this for
zoossh/stem, which is what originally prompted me to look at this.
3. Since Rust can produce C ABI compatible libraries, in theory this could serve
as a prototype of guaranteed memory-safe parsing that could eventually be
utilized in Tor itself (maybe?).

Currently, only `@type server-descriptor-1.0` is supported.

**Big caveat**: I am fairly new to both Rust and Tor data formats. Therefore I
believe this code will require significant auditing.

[1]: https://www.torproject.org/getinvolved/volunteer.html.en#descriptor_parsing_in_go
[Nom]: https://github.com/

