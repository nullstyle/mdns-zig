//! mdns.wire: the zero-allocation DNS / mDNS codec (plan section 6).
//!
//! - `name`: `Name` (wire-form names, bounded compression decode, RFC 6763
//!   section 4.3 escaping), `validateServiceName`, `validateInstance`.
//! - `message`: `Message.parse`, header, question and record iterators,
//!   `RType`, QU and cache-flush bits.
//! - `rdata`: A/AAAA/PTR/SRV/TXT/NSEC/HINFO codecs and the RFC 6762
//!   section 8.2 comparison.
//! - `txt`: `Txt` / `TxtPair` / `View` with RFC 6763 section 6 semantics
//!   and the 400-octet limit.
//! - `builder`: `Builder` with compression, size rules and legacy mode.
const std = @import("std");

pub const bounded = @import("bounded.zig");
pub const name = @import("name.zig");
pub const message = @import("message.zig");
pub const rdata = @import("rdata.zig");
pub const txt = @import("txt.zig");
pub const builder = @import("builder.zig");

pub const Bounded = bounded.Bounded;

pub const Name = name.Name;
pub const validateServiceName = name.validateServiceName;
pub const validateInstance = name.validateInstance;
pub const ServiceNameError = name.ServiceNameError;
pub const InstanceError = name.InstanceError;

pub const Message = message.Message;
pub const Header = message.Header;
pub const Question = message.Question;
pub const Record = message.Record;
pub const RType = message.RType;
pub const Section = message.Section;
pub const class_in = message.class_in;
pub const qu_bit = message.qu_bit;
pub const cache_flush_bit = message.cache_flush_bit;
pub const max_message_len = message.max_message_len;

pub const Srv = rdata.Srv;
pub const Nsec = rdata.Nsec;
pub const Hinfo = rdata.Hinfo;

pub const Txt = txt.Txt;
pub const TxtPair = txt.TxtPair;
pub const TxtView = txt.View;

pub const Builder = builder.Builder;
pub const Family = builder.Family;
pub const Rdata = builder.Rdata;

test {
    std.testing.refAllDecls(@This());
    _ = bounded;
    _ = name;
    _ = message;
    _ = rdata;
    _ = txt;
    _ = builder;
}
