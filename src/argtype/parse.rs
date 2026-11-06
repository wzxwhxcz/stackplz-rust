//! Userspace argument parsing: TLV bytes -> rendered value text.
//!
//! Faithful port of the Go `Parse` methods that turn one saved argument into
//! the string printed after `name=`. The kernel side (`ebpf/utils.h`
//! `read_args`) walks a `PointArg`'s op list and appends TLVs; this module
//! walks the *same* TLVs in the same order and applies the same formatting.
//!
//! Per-argument TLV order (see `ebpf/common/buffer.h`):
//!
//! 1. always one `save_to_submit_buf` entry `[u8 idx][u64 value]` emitted by
//!    the `Add_READ_SAVE_REG` + `OPC_MOVE_REG_VALUE` pair that every `PointArg`
//!    starts with (`config_point_arg.go:138-139`). Go reads it as
//!    `argtype.Arg_reg` (`argtype/config_struct.go:24-27`) *before* calling
//!    `Parse`, so this module's callers do the same and pass `ptr`.
//! 2. type-specific entries, only when the argument is read on this side
//!    (`PointArg::read_more()`, i.e. `point_type == all/enter/exit` match):
//!    - `save_bytes_to_buf` / `save_str_to_buf` -> `[u8 idx][u32 len][payload]`
//!      (strings, buffers, structs, arrays, iovec payloads)
//!    - `save_to_submit_buf` -> `[u8 idx][u64 ...]` (pointer values, counts)
//!
//! # Deliberate deviations from Go
//!
//! Go turns every malformed record into a `panic` (the whole process dies).
//! Here every failure is an [`anyhow::Error`]; the module poll callbacks log
//! `decode error: ...` and keep polling. The rendered text for *well-formed*
//! values is byte-identical to Go, which the differential oracle
//! (`~/workspace/stackplz-round4-oracle`) checks case by case.
//!
//! Not ported: the flags-table suffixes (`argtype_flags.go`, e.g.
//! `0x100(PROT_READ|...)`) because this crate has no flags configs; values are
//! rendered as plain numbers/hex.

use anyhow::{anyhow, bail, Context, Result};

use super::consts::*;
use super::registry::{try_get_arg_type, ArgType};
use super::render;
use super::struct_formatters::format_struct;
use crate::config::point_arg::{PointArg, EBPF_SYS_ALL};
use crate::contract::args::ArgsCursor;
use crate::contract::consts::STRARR_MAGIC_LEN;
use crate::util::hexdump::pretty_byte_slice;

/// Parse one argument and render its value. `ptr` is the value read from the
/// leading `Arg_reg` TLV; `render_point` is `EBPF_SYS_ENTER` / `EBPF_SYS_EXIT`.
pub fn parse_point_arg(
    point_arg: &PointArg,
    ptr: u64,
    cur: &mut ArgsCursor<'_>,
    render_point: u32,
    dump_hex: bool,
) -> Result<String> {
    let at = try_get_arg_type(point_arg.type_index).ok_or_else(|| {
        anyhow!(
            "unknown argtype (type_index={}) for argument {:?}",
            point_arg.type_index,
            point_arg.name
        )
    })?;
    // `PointArg.Parse` (`config_point_arg.go:111-117`).
    let parse_more = point_arg.point_type == EBPF_SYS_ALL || point_arg.point_type == render_point;
    parse_value(&at, ptr, cur, parse_more, dump_hex)
        .with_context(|| format!("argument {:?} (type {:?})", point_arg.name, at.name))
}

/// Dispatch one value by its argtype, mirroring Go's concrete-type switch.
pub fn parse_value(
    at: &ArgType,
    ptr: u64,
    cur: &mut ArgsCursor<'_>,
    parse_more: bool,
    dump_hex: bool,
) -> Result<String> {
    match at.base_type {
        TYPE_INT | TYPE_INT8 | TYPE_INT16 | TYPE_INT32 | TYPE_INT64 | TYPE_UINT | TYPE_UINT8
        | TYPE_UINT16 | TYPE_UINT32 | TYPE_UINT64 => {
            Ok(render::format_num(at.base_type, at.format_type, ptr))
        }
        TYPE_POINTER => parse_pointer(at, ptr, cur, parse_more, dump_hex),
        TYPE_STRING => {
            if !parse_more {
                return Ok(render::format_ptr(ptr));
            }
            let (_, _, payload) = cur.next_length_prefixed()?;
            Ok(render::format_ptr(ptr)
                + &match at.name.as_str() {
                    // `ARG_STRING16` / `ARG_STRING16`-based il2cpp string.
                    "string16" | "il2cpp_string" => render::format_string16(payload),
                    _ => render::format_string(payload),
                })
        }
        TYPE_BUFFER => {
            if !parse_more {
                return Ok(render::format_ptr(ptr));
            }
            let (_, _, payload) = cur.next_length_prefixed()?;
            Ok(render::format_ptr(ptr) + &render::format_buffer(payload, dump_hex || at.dump_hex))
        }
        TYPE_ARRAY => parse_array(at, ptr, cur, parse_more),
        TYPE_STRUCT => parse_struct(at, ptr, cur, parse_more, dump_hex),
        other => Err(anyhow!(
            "unknown argtype base_type {other} for type {:?}",
            at.name
        )),
    }
}

/// `ARG_PTR.Parse` (`argtype_base.go:195-215`).
fn parse_pointer(
    at: &ArgType,
    ptr: u64,
    cur: &mut ArgsCursor<'_>,
    parse_more: bool,
    dump_hex: bool,
) -> Result<String> {
    if !parse_more {
        return Ok(render::format_ptr(ptr));
    }
    let Some(child_idx) = at.ptr_type_index else {
        return Ok(render::format_ptr(ptr));
    };
    let child = try_get_arg_type(child_idx)
        .ok_or_else(|| anyhow!("pointer child argtype {child_idx} is not registered"))?;
    if at.is_num {
        // A pointer to a number saves the pointee as an 8-byte struct.
        let (_, len, data) = cur.next_length_prefixed()?;
        let value = if len == 8 && data.len() == 8 {
            u64::from_le_bytes(data.try_into().expect("checked length"))
        } else {
            0
        };
        let inner = parse_value(&child, value, cur, parse_more, dump_hex)?;
        Ok(format!("{}({inner})", render::format_ptr(ptr)))
    } else {
        // A pointer to a buffer/string/etc. reads its payload into the TLV
        // stream; the pointee type parses it with the pointer as `ptr`.
        parse_value(&child, ptr, cur, parse_more, dump_hex)
    }
}

/// `ARG_ARRAY.Parse` / `parse_ARRAY` (`argtype_base.go:516-548`,
/// `argtype_complex.go:151-212`).
fn parse_array(
    at: &ArgType,
    ptr: u64,
    cur: &mut ArgsCursor<'_>,
    parse_more: bool,
) -> Result<String> {
    if !parse_more {
        return Ok(render::format_ptr(ptr));
    }
    let (_, len) = cur.next_arg_str_header()?;
    // `GetStructLen()`: an empty payload means "nothing was read".
    if len == 0 {
        return Ok(format!("{}[]", render::format_ptr(ptr)));
    }
    if at.size != 0 && len != at.size {
        bail!(
            "array {:?} size mismatch: declared {len}, expected {}",
            at.name,
            at.size
        );
    }
    let data = cur.next_bytes(len as usize)?;
    let elem_idx = at
        .array_type_index
        .ok_or_else(|| anyhow!("array {:?} has no element type", at.name))?;
    let elem = try_get_arg_type(elem_idx)
        .ok_or_else(|| anyhow!("array element argtype {elem_idx} is not registered"))?;
    if !is_numeric(elem.base_type) {
        // Go panics ("parse method for X array not impl").
        bail!(
            "array {:?} element type {:?} is not renderable",
            at.name,
            elem.name
        );
    }
    let elem_size = elem.size as usize;
    if elem_size == 0 || data.len() < at.array_len as usize * elem_size {
        bail!(
            "array {:?} payload is {} bytes, needs {} x {elem_size}",
            at.name,
            data.len(),
            at.array_len
        );
    }
    let mut values = Vec::with_capacity(at.array_len as usize);
    for chunk in data.chunks_exact(elem_size).take(at.array_len as usize) {
        let raw = match elem_size {
            1 => u64::from(chunk[0]),
            2 => u64::from(u16::from_le_bytes([chunk[0], chunk[1]])),
            4 => u64::from(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])),
            8 => u64::from_le_bytes(chunk.try_into().expect("checked chunk size")),
            _ => bail!("unsupported array element size {elem_size}"),
        };
        values.push(render::format_num(elem.base_type, elem.format_type, raw));
    }
    Ok(format!(
        "{}[{}]",
        render::format_ptr(ptr),
        values.join(", ")
    ))
}

fn is_numeric(base_type: u32) -> bool {
    matches!(
        base_type,
        TYPE_INT
            | TYPE_INT8
            | TYPE_INT16
            | TYPE_INT32
            | TYPE_INT64
            | TYPE_UINT
            | TYPE_UINT8
            | TYPE_UINT16
            | TYPE_UINT32
            | TYPE_UINT64
    )
}

/// `ARG_STRUCT.ParseArg` (`argtype_base.go:661-700`) plus the custom
/// `ParseCB` parsers for the multi-TLV struct types.
fn parse_struct(
    at: &ArgType,
    ptr: u64,
    cur: &mut ArgsCursor<'_>,
    parse_more: bool,
    dump_hex: bool,
) -> Result<String> {
    if !parse_more {
        return Ok(render::format_ptr(ptr));
    }
    match at.name.as_str() {
        // `parse_IOVEC`: a count register then `count` x (iovec struct + payload).
        "iovec" => parse_iovec(ptr, cur),
        // `parse_MSGHDR`: msghdr struct, control buffer, then the iov array.
        "msghdr" => parse_msghdr(ptr, cur),
        // `parse_STRING_ARRAY`: (pointer, string) pairs until the magic marker.
        "string_array" => parse_string_array(ptr, cur),
        // Upstream `r_DIRENT()` wires `SetParseCB(parse_POLLFD)` — a real
        // upstream defect we reproduce (`argtype_complex.go:694-701`): a dirent
        // payload is formatted as if it were `struct pollfd`, reading only the
        // first 8 payload bytes and leaving the other 272 unconsumed. The
        // resulting desync of later arguments matches Go.
        "dirent" => parse_dirent_as_pollfd(at, ptr, cur),
        _ => {
            let Some(payload) = read_struct_payload(at, cur)? else {
                return Ok(render::format_ptr(ptr));
            };
            match format_struct(&at.name, payload) {
                Some(text) => Ok(render::format_ptr(ptr) + &text),
                // Go panics for a struct type without a formatter. We keep the
                // event printable with a lossless-ish fallback instead.
                None => {
                    let _ = dump_hex;
                    Ok(format!(
                        "{}({})",
                        render::format_ptr(ptr),
                        pretty_byte_slice(payload)
                    ))
                }
            }
        }
    }
}

/// Read `[u8 idx][u32 len]` + `len` payload bytes, applying Go's
/// `GetStructLen` rules: `len == 0` -> nothing was read, otherwise the declared
/// length must equal the type's `sizeof`.
fn read_struct_payload<'a>(at: &ArgType, cur: &mut ArgsCursor<'a>) -> Result<Option<&'a [u8]>> {
    let (_, len) = cur.next_arg_str_header()?;
    if len == 0 {
        return Ok(None);
    }
    if at.size != 0 && len != at.size {
        bail!(
            "struct {:?} size mismatch: declared {len}, expected {}",
            at.name,
            at.size
        );
    }
    Ok(Some(cur.next_bytes(len as usize)?))
}

/// `parse_DIREnt` as wired upstream: read `Arg_struct` (index+len), then
/// `binary.Read` of a `Pollfd` (8 bytes) and format it as pollfd.
fn parse_dirent_as_pollfd(at: &ArgType, ptr: u64, cur: &mut ArgsCursor<'_>) -> Result<String> {
    let (_, len) = cur.next_arg_str_header()?;
    if len == 0 {
        return Ok(render::format_ptr(ptr));
    }
    if at.size != 0 && len != at.size {
        bail!(
            "struct \"dirent\" size mismatch: declared {len}, expected {}",
            at.size
        );
    }
    let pollfd = cur.next_bytes(8)?;
    let text = format_struct("pollfd", pollfd)
        .ok_or_else(|| anyhow!("failed to format dirent-as-pollfd payload"))?;
    Ok(render::format_ptr(ptr) + &text)
}

/// `parse_IOVEC` (`argtype_complex.go:703-734`).
fn parse_iovec(ptr: u64, cur: &mut ArgsCursor<'_>) -> Result<String> {
    // Arg_reg is `[u8 index][u64 value]`; `next_raw_borrow` asks for the 8
    // payload bytes after the index (same convention as `event::render`).
    let (_, raw) = cur.next_raw_borrow(8)?;
    let iovcnt = u64::from_le_bytes(raw.try_into().expect("Arg_reg value is 8 bytes"));
    let read_count = (iovcnt as usize).min(MAX_IOV_COUNT as usize);
    let mut parts = Vec::with_capacity(read_count);
    for i in 0..read_count {
        // `Arg_Iovec_Fix`: [idx][len][base u64][buflen u64]; Go's binary.Read
        // consumes 16 payload bytes regardless of the declared len.
        let _ = cur.next_arg_str_header()?;
        let fix = cur.next_bytes(16)?;
        let base = u64::from_le_bytes(fix[0..8].try_into().expect("8 bytes"));
        let buflen = u64::from_le_bytes(fix[8..16].try_into().expect("8 bytes"));
        let (_, _, payload) = cur.next_length_prefixed()?;
        parts.push(format!(
            "iov_{i}=(base=0x{base:x}({}), buflen=0x{buflen:x})",
            pretty_byte_slice(payload)
        ));
    }
    Ok(format!(
        "{}(\n\t{}\n)",
        render::format_ptr(ptr),
        parts.join("\n\t")
    ))
}

/// `parse_MSGHDR` (`argtype_complex.go:777-834`).
fn parse_msghdr(ptr: u64, cur: &mut ArgsCursor<'_>) -> Result<String> {
    // `Arg_Msghdr` = index + len + `syscall.Msghdr` (56 bytes); the struct read
    // is unconditional in Go, with the length only validated separately.
    let (_, len) = cur.next_arg_str_header()?;
    let _ = len;
    let raw = cur.next_bytes(SIZEOF_MSGHDR as usize)?;
    let name = u64::from_le_bytes(raw[0..8].try_into().expect("8 bytes"));
    let namelen = u32::from_le_bytes(raw[8..12].try_into().expect("4 bytes"));
    let iov = u64::from_le_bytes(raw[16..24].try_into().expect("8 bytes"));
    let iovlen = u64::from_le_bytes(raw[24..32].try_into().expect("8 bytes"));
    let control = u64::from_le_bytes(raw[32..40].try_into().expect("8 bytes"));
    let controllen = u64::from_le_bytes(raw[40..48].try_into().expect("8 bytes"));
    let flags = i32::from_le_bytes(raw[48..52].try_into().expect("4 bytes"));

    // Control buffer: `Arg_buffer` (index + len + payload).
    let (_, _, control_payload) = cur.next_length_prefixed()?;

    let iov_count = (iovlen as usize).min(MAX_IOV_COUNT as usize);
    let mut iov_parts = Vec::with_capacity(iov_count);
    for i in 0..iov_count {
        let _ = cur.next_arg_str_header()?;
        let fix = cur.next_bytes(SIZEOF_IOVEC as usize)?;
        let base = u64::from_le_bytes(fix[0..8].try_into().expect("8 bytes"));
        let buflen = u64::from_le_bytes(fix[8..16].try_into().expect("8 bytes"));
        let (_, _, payload) = cur.next_length_prefixed()?;
        iov_parts.push(format!(
            "iov_{i}=(base=0x{base:x}({}), buflen=0x{buflen:x})",
            pretty_byte_slice(payload)
        ));
    }
    let iov_fmt = format!("(\n\t{}\n)", iov_parts.join(", \n\t"));
    let control_fmt = format!("({})", pretty_byte_slice(control_payload));

    // `Arg_Msghdr.FormatFull(iov_fmt, control_fmt)`; the trailing flags suffix
    // from `MsgFlagsConfig` is not ported (no flags configs in this crate).
    let fields = [
        format!("name=0x{name:x}"),
        format!("namelen=0x{namelen:x}"),
        format!("*iov=0x{iov:x}{iov_fmt}"),
        format!("iovlen=0x{iovlen:x}"),
        format!("*control=0x{control:x}{control_fmt}"),
        format!("controllen=0x{controllen:x}"),
        format!("flags=0x{flags:x}"),
    ];
    Ok(format!(
        "{}({})",
        render::format_ptr(ptr),
        fields.join(", ")
    ))
}

/// `parse_STRING_ARRAY` (`argtype_complex.go:110-138`).
fn parse_string_array(ptr: u64, cur: &mut ArgsCursor<'_>) -> Result<String> {
    let mut results = Vec::new();
    for _ in 0..MAX_LOOP_COUNT {
        let (_, raw) = cur.next_raw_borrow(8)?;
        let addr = u64::from_le_bytes(raw.try_into().expect("Arg_reg value is 8 bytes"));
        let (_, len) = cur.next_arg_str_header()?;
        if len == STRARR_MAGIC_LEN {
            break;
        }
        let payload = cur.next_bytes(len as usize)?;
        if addr == 0 {
            break;
        }
        results.push(format!("0x{addr:x}({})", render::b2s_trim(payload)));
    }
    Ok(format!(
        "{}[\n\t{}\n]",
        render::format_ptr(ptr),
        results.join(",\n\t")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::point_arg::EBPF_SYS_ENTER;
    use crate::config::point_arg::EBPF_SYS_EXIT;

    fn point_arg(type_name: &str, more: &str) -> PointArg {
        crate::argtype::init_argtypes();
        let mut pa = PointArg::new("arg", 0, 0);
        pa.set_type_by_name(type_name);
        pa.point_type = match more {
            "" | "enter" => EBPF_SYS_ENTER,
            "exit" => EBPF_SYS_EXIT,
            "all" => EBPF_SYS_ALL,
            other => panic!("bad more {other}"),
        };
        pa
    }

    /// TLV writer matching `save_to_submit_buf` (`[idx][bytes]`).
    fn raw(idx: u8, bytes: &[u8]) -> Vec<u8> {
        let mut v = vec![idx];
        v.extend_from_slice(bytes);
        v
    }

    /// TLV writer matching `save_bytes_to_buf` / `save_str_to_buf`
    /// (`[idx][u32 len][bytes]`).
    fn prefixed(idx: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![idx];
        v.extend_from_slice(&(payload.len() as i32).to_le_bytes());
        v.extend_from_slice(payload);
        v
    }

    /// The leading `Arg_reg` every PointArg emits.
    fn reg(idx: u8, value: u64) -> Vec<u8> {
        raw(idx, &value.to_le_bytes())
    }

    fn parse(
        type_name: &str,
        more: &str,
        render_point: u32,
        ptr: u64,
        tlvs: &[u8],
    ) -> Result<String> {
        let pa = point_arg(type_name, more);
        let mut cur = ArgsCursor::new(tlvs);
        parse_point_arg(&pa, ptr, &mut cur, render_point, false)
    }

    #[test]
    fn int_renders_the_register_value() {
        let out = parse("int", "", EBPF_SYS_ENTER, 42, &[]).unwrap();
        assert_eq!(out, "42");
        // Signed int32 semantics, exactly like Go's `int32(ptr)`.
        let out = parse("int", "", EBPF_SYS_ENTER, u64::from(0xffff_ffffu32), &[]).unwrap();
        assert_eq!(out, "-1");
        let out = parse("uint64", "", EBPF_SYS_ENTER, 0x1_0000_0000, &[]).unwrap();
        assert_eq!(out, "4294967296");
    }

    #[test]
    fn string_reads_its_length_prefixed_payload() {
        let tlvs = prefixed(1, b"hello\0\0");
        let out = parse("str", "", EBPF_SYS_ENTER, 0x7fff_1234, &tlvs).unwrap();
        assert_eq!(out, "0x7fff1234(hello)");
    }

    #[test]
    fn enter_only_arg_is_not_parsed_on_exit() {
        // more=enter => on sys_exit `parse_more` is false, so no payload is
        // consumed and the pointer form is printed.
        let tlvs = prefixed(1, b"ignored");
        let out = parse("str", "enter", EBPF_SYS_EXIT, 0x1234, &tlvs).unwrap();
        assert_eq!(out, "0x1234");
    }

    #[test]
    fn exit_only_arg_is_a_bare_pointer_on_enter() {
        let tlvs = prefixed(1, b"buf");
        let out = parse("buf", "exit", EBPF_SYS_ENTER, 0x1234, &tlvs).unwrap();
        assert_eq!(out, "0x1234");
    }

    #[test]
    fn buffer_renders_pretty_or_hexdump() {
        let tlvs = prefixed(1, b"hi\x00x");
        let out = parse("buf", "", EBPF_SYS_ENTER, 0x10, &tlvs).unwrap();
        assert_eq!(out, "0x10(hi\\x00x)");
        let pa = point_arg("buf", "");
        let mut cur = ArgsCursor::new(&tlvs);
        let out = parse_point_arg(&pa, 0x10, &mut cur, EBPF_SYS_ENTER, true).unwrap();
        assert_eq!(
            out,
            "0x10(\n0000  68 69 00 78                                      |hi.x            |\n)"
        );
    }

    #[test]
    fn struct_renders_its_formatter() {
        let mut payload = vec![0u8; 16];
        payload[0..8].copy_from_slice(&1i64.to_le_bytes());
        payload[8..16].copy_from_slice(&2i64.to_le_bytes());
        let tlvs = prefixed(1, &payload);
        let out = parse("timespec", "", EBPF_SYS_ENTER, 0x20, &tlvs).unwrap();
        assert_eq!(out, "0x20(sec=1, nsec=2)");
    }

    #[test]
    fn array_renders_each_element() {
        crate::argtype::init_argtypes();
        // int_arr[2] => 2 x i32, decimal per element (`--config` default format).
        let mut payload = vec![0u8; 8];
        payload[0..4].copy_from_slice(&(7i32).to_le_bytes());
        payload[4..8].copy_from_slice(&(-1i32).to_le_bytes());
        let pa = crate::config::point_arg::PointArg::new_uprobe(
            "arg",
            crate::argtype::r_num_array_fmt(crate::argtype::consts::INT, 2, "num"),
            0,
        );
        let tlvs = prefixed(1, &payload);
        let mut cur = ArgsCursor::new(&tlvs);
        let out = parse_point_arg(
            &pa,
            0x30,
            &mut cur,
            crate::config::point_arg::EBPF_UPROBE_ENTER,
            false,
        )
        .unwrap();
        assert_eq!(out, "0x30[7, -1]");
    }

    #[test]
    fn numeric_pointer_reads_a_single_8_byte_value() {
        // *uint: the kernel saves the pointee as SaveStruct(8).
        let mut payload = vec![0u8; 8];
        payload[0..8].copy_from_slice(&(0xabc_u64).to_le_bytes());
        let mut pa = point_arg("uint", "");
        pa.to_pointer_type();
        let tlvs = prefixed(1, &payload);
        let mut cur = ArgsCursor::new(&tlvs);
        let out = parse_point_arg(&pa, 0x4000, &mut cur, EBPF_SYS_ENTER, false).unwrap();
        assert_eq!(out, "0x4000(2748)");
    }

    #[test]
    fn truncated_payload_is_an_error_not_a_panic() {
        // Declares 16 payload bytes but the record ends after 3 of them.
        let mut tlvs = vec![1u8];
        tlvs.extend_from_slice(&16i32.to_le_bytes());
        tlvs.extend_from_slice(b"abc");
        let err = parse("str", "", EBPF_SYS_ENTER, 1, &tlvs).unwrap_err();
        assert!(format!("{err:#}").contains("args underflow"), "{err:#}");
    }

    #[test]
    fn unknown_argtype_index_is_an_error_not_a_panic() {
        crate::argtype::init_argtypes();
        let mut pa = PointArg::new("arg", 0, 0);
        pa.type_index = u32::MAX; // never registered
        let mut cur = ArgsCursor::new(&[]);
        let err = parse_point_arg(&pa, 0, &mut cur, EBPF_SYS_ENTER, false).unwrap_err();
        assert!(format!("{err:#}").contains("unknown argtype"), "{err:#}");
    }

    #[test]
    fn string_array_stops_at_the_magic_marker() {
        let mut tlvs = Vec::new();
        tlvs.extend_from_slice(&reg(1, 0x1000));
        tlvs.extend_from_slice(&prefixed(2, b"/bin/sh\0"));
        // A truncated tail element: the kernel writes the address reg first,
        // then `[idx][u32 STRARR_MAGIC_LEN]` with no payload (`OP_SAVE_PTR_STRING`).
        tlvs.extend_from_slice(&reg(3, 0x2000));
        let mut magic = vec![3u8];
        magic.extend_from_slice(&(STRARR_MAGIC_LEN as i32).to_le_bytes());
        tlvs.extend_from_slice(&magic);
        let out = parse("string_array", "", EBPF_SYS_ENTER, 0x5000, &tlvs).unwrap();
        assert_eq!(out, "0x5000[\n\t0x1000(/bin/sh)\n]");
    }
}
