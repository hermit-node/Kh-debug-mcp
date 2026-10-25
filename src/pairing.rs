//! Experimental independent A/B PNG pairing (not the Windows StegoSplit v0.6 codec).
//! A contains SHA-256(key); B contains the random 64-bit key.
//! Both are derived from the same default KernelHermit PNG or a selected RGB PNG.
use sha2::{Digest, Sha256};
use std::{io::Cursor, path::Path};
use subtle::ConstantTimeEq;

const W: usize = 640;
const H: usize = 360;
const PIXELS: usize = W * H;
// This artwork is prepared as RGB PNG before any pairing data is written.
const DEFAULT_ART: &[u8] = include_bytes!("../assets/kernelhermit-default.png");
const MASK_PIXELS: usize = 288; // 36 bytes in A, 12 bytes in B
const PNG_MAX: usize = 10 * 1024 * 1024;
const A_TAG: &[u8; 4] = b"KHA1";
const B_TAG: &[u8; 4] = b"KHB1";

fn random(buf: &mut [u8]) -> Result<(), String> {
    getrandom::fill(buf).map_err(|e| format!("OS randomness unavailable: {e:?}"))
}
fn insert_bits(mut pixels: Vec<u8>, message: &[u8]) -> Vec<u8> {
    for (i, bit) in message
        .iter()
        .flat_map(|b| (0..8).map(move |j| (b >> j) & 1))
        .enumerate()
    {
        pixels[i * 3] = (pixels[i * 3] & !1) | bit;
    }
    pixels
}
fn read_bits(pixels: &[u8], count: usize) -> Vec<u8> {
    (0..count)
        .map(|byte| {
            (0..8).fold(0u8, |value, bit| {
                value | ((pixels[(byte * 8 + bit) * 3] & 1) << bit)
            })
        })
        .collect()
}
fn encode(pixels: &[u8]) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut bytes, W as u32, H as u32);
        encoder.set_color(png::ColorType::Rgb);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().map_err(|e| e.to_string())?;
        writer.write_image_data(pixels).map_err(|e| e.to_string())?;
    }
    Ok(bytes)
}
fn decode(png_bytes: &[u8]) -> Result<Vec<u8>, String> {
    if png_bytes.len() > PNG_MAX {
        return Err("PNG exceeds 10 MiB".into());
    }
    // Expand an indexed-color default PNG to RGB8 *before* embedding.
    // Credential PNGs are always written as lossless RGB PNGs.
    let mut decoder = png::Decoder::new(Cursor::new(png_bytes));
    decoder.set_transformations(png::Transformations::EXPAND);
    let mut reader = decoder.read_info().map_err(|e| e.to_string())?;
    let info = reader.info();
    if info.width as usize != W || info.height as usize != H {
        return Err("Image must be 640x360 pixels".into());
    }
    let mut buf = vec![0; reader.output_buffer_size()];
    let output = reader.next_frame(&mut buf).map_err(|e| e.to_string())?;
    if output.color_type != png::ColorType::Rgb
        || output.bit_depth != png::BitDepth::Eight
        || output.buffer_size() != PIXELS * 3
    {
        return Err("Image must decode to RGB8 pixels".into());
    }
    buf.truncate(output.buffer_size());
    Ok(buf)
}
/// Generate the A/B images from a previously prepared 640x360 RGB PNG.
/// Never resizes, quantizes, or otherwise transforms source pixels after embedding.
pub fn generate_from_source(source: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let base = decode(source)?;
    let mut key = [0u8; 8];
    random(&mut key)?;
    let mut a_message = Vec::from(*A_TAG);
    a_message.extend_from_slice(&Sha256::digest(key));
    let mut b_message = Vec::from(*B_TAG);
    b_message.extend_from_slice(&key);
    Ok((
        encode(&insert_bits(base.clone(), &a_message))?,
        encode(&insert_bits(base, &b_message))?,
    ))
}

/// Bundled default artwork is the geometric KernelHermit design in lossless RGB PNG.
pub fn generate() -> Result<(Vec<u8>, Vec<u8>), String> {
    generate_from_source(DEFAULT_ART)
}
pub fn verify(a: &[u8], b: &[u8]) -> bool {
    let (Ok(mut first), Ok(mut second)) = (decode(a), decode(b)) else {
        return false;
    };
    let a_msg = read_bits(&first, 36);
    let b_msg = read_bits(&second, 12);
    if &a_msg[..4] != A_TAG || &b_msg[..4] != B_TAG {
        return false;
    }
    let hash = Sha256::digest(&b_msg[4..12]);
    if !bool::from(hash.as_slice().ct_eq(&a_msg[4..36])) {
        return false;
    }
    // The underlying artwork must match exactly, ignoring only embedded red LSBs.
    for i in 0..MASK_PIXELS {
        first[i * 3] &= !1;
        second[i * 3] &= !1;
    }
    first == second
}
pub fn verify_files(a: &Path, b: &[u8]) -> bool {
    std::fs::read(a).is_ok_and(|master| verify(&master, b))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn valid_and_mismatched_pairs() {
        let (a, b) = generate().unwrap();
        assert!(verify(&a, &b));
        let (_, other) = generate().unwrap();
        assert!(!verify(&a, &other));
        assert!(!verify(&b, &a));
        assert!(!verify(&a, &[1, 2, 3]));
    }
    #[test]
    fn kernelhermit_art_is_preserved_except_embedded_bits() {
        let source = decode(DEFAULT_ART).unwrap();
        let (a, b) = generate().unwrap();
        assert!(verify(&a, &b));
        for result in [&a, &b] {
            let reader = png::Decoder::new(std::io::Cursor::new(result))
                .read_info()
                .unwrap();
            assert_eq!(reader.info().color_type, png::ColorType::Rgb);
            assert_eq!(reader.info().bit_depth, png::BitDepth::Eight);
            let pixels = decode(result).unwrap();
            for i in 0..PIXELS {
                for channel in 0..3 {
                    if i < MASK_PIXELS && channel == 0 {
                        continue;
                    }
                    assert_eq!(pixels[i * 3 + channel], source[i * 3 + channel]);
                }
            }
        }
    }
    #[test]
    fn alternate_prepared_rgb_png_can_be_used() {
        let prepared = encode(&decode(DEFAULT_ART).unwrap()).unwrap();
        let (a, b) = generate_from_source(&prepared).unwrap();
        assert!(verify(&a, &b));
        assert!(generate_from_source(b"not a PNG").is_err());
    }
}
