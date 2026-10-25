//! Experimental independent A/B PNG pairing (not the Windows StegoSplit v0.6 codec).
//! A contains SHA-256(key); B contains the random 64-bit key.
//! Both are derived from the same mathematically drawn background.
use sha2::{Digest, Sha256};
use std::{io::Cursor, path::Path};
use subtle::ConstantTimeEq;

const W: usize = 320;
const H: usize = 240;
const PIXELS: usize = W * H;
const MASK_PIXELS: usize = 288; // 36 bytes in A, 12 bytes in B
const PNG_MAX: usize = 10 * 1024 * 1024;
const A_TAG: &[u8; 4] = b"KHA1";
const B_TAG: &[u8; 4] = b"KHB1";

fn random(buf: &mut [u8]) -> Result<(), String> {
    getrandom::fill(buf).map_err(|e| format!("OS randomness unavailable: {e:?}"))
}
struct Stream(u64);
impl Stream {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn range(&mut self, max: usize) -> usize {
        (self.next() as usize) % max
    }
}
fn draw(seed: u64) -> Vec<u8> {
    let mut p = vec![0u8; PIXELS * 3];
    for pixel in p.chunks_exact_mut(3) {
        pixel.copy_from_slice(&[239, 233, 219]);
    }
    let mut rng = Stream(seed | 1);
    let colors: [[u8; 3]; 6] = [
        [40, 82, 100],
        [162, 84, 62],
        [97, 114, 79],
        [204, 148, 68],
        [94, 73, 122],
        [60, 125, 140],
    ];
    for _ in 0..38 {
        let x0 = rng.range(W) as f64;
        let y0 = rng.range(H) as f64;
        let phase = rng.range(628) as f64 / 100.0;
        let len = 14.0 + rng.range(95) as f64;
        let width = 1.0 + rng.range(9) as f64;
        let color = colors[rng.range(colors.len())];
        for n in 0..(len as usize) {
            let t = n as f64;
            let x = (x0 + phase.cos() * t + (t / 11.0).sin() * 7.0).round() as i32;
            let y = (y0 + phase.sin() * t + (t / 13.0).cos() * 6.0).round() as i32;
            let radius = width * (0.2 + 0.8 * (std::f64::consts::PI * t / len).sin().abs());
            for dy in -(radius as i32)..=(radius as i32) {
                for dx in -(radius as i32)..=(radius as i32) {
                    if (dx * dx + dy * dy) as f64 > radius * radius {
                        continue;
                    }
                    let px = x + dx;
                    let py = y + dy;
                    if px < 0 || py < 0 || px >= W as i32 || py >= H as i32 {
                        continue;
                    }
                    let i = ((py as usize * W + px as usize) * 3) as usize;
                    for c in 0..3 {
                        p[i + c] = ((p[i + c] as u16 + 2 * color[c] as u16) / 3) as u8;
                    }
                }
            }
        }
    }
    p
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
    let decoder = png::Decoder::new(Cursor::new(png_bytes));
    let mut reader = decoder.read_info().map_err(|e| e.to_string())?;
    let info = reader.info();
    if info.width as usize != W
        || info.height as usize != H
        || info.color_type != png::ColorType::Rgb
        || info.bit_depth != png::BitDepth::Eight
    {
        return Err("Unexpected image dimensions or pixel type".into());
    }
    let mut buf = vec![0; PIXELS * 3];
    let output = reader.next_frame(&mut buf).map_err(|e| e.to_string())?;
    if output.buffer_size() != buf.len() {
        return Err("Incorrect pixel count".into());
    }
    Ok(buf)
}
pub fn generate() -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut entropy = [0u8; 16];
    random(&mut entropy)?;
    let mut key = [0u8; 8];
    key.copy_from_slice(&entropy[..8]);
    let seed = u64::from_le_bytes(entropy[8..].try_into().unwrap());
    let base = draw(seed);
    let mut a_message = Vec::from(*A_TAG);
    a_message.extend_from_slice(&Sha256::digest(key));
    let mut b_message = Vec::from(*B_TAG);
    b_message.extend_from_slice(&key);
    Ok((
        encode(&insert_bits(base.clone(), &a_message))?,
        encode(&insert_bits(base, &b_message))?,
    ))
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
    // The underlying painting must match exactly, ignoring only embedded red LSBs.
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
}
