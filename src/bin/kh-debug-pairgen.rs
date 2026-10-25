//! Single-use provisioning container. Generate A and B only on first Compose startup.
use kh_debug_mcp::pairing;
use std::{fs, path::Path};

fn save_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let a = Path::new("/provision/auth/A.png");
    let b = Path::new("/provision/mcp/B.png");
    let token = Path::new("/provision/state/auth_api_token");
    for path in [a, b, token] {
        fs::create_dir_all(path.parent().unwrap())?;
    }
    match (a.exists(), b.exists()) {
        (false, false) => {
            // An explicit path may be supplied by the future UI. The default
            // is the bundled geometric KernelHermit artwork, not a random painting.
            let (master, client) = match std::env::var("KH_PAIR_SOURCE_IMAGE") {
                Ok(path) => {
                    let source = Path::new(&path);
                    if !source.is_absolute() {
                        return Err("Source image path must be absolute".into());
                    }
                    pairing::generate_from_source(&fs::read(source)?)
                }
                Err(std::env::VarError::NotPresent) => pairing::generate(),
                Err(_) => return Err("Invalid source image path".into()),
            }
            .map_err(std::io::Error::other)?;
            save_new(a, &master)?;
            save_new(b, &client)?;
            println!("Generated lossless A/B PNG pair using the selected artwork");
        }
        (true, true) => {
            if !pairing::verify_files(a, &fs::read(b)?) {
                return Err("Existing A/B images are not a valid pair".into());
            }
            println!("Using existing A/B pair (not regenerating)");
        }
        _ => return Err("Only one pairing image exists; refusing to replace either".into()),
    }
    if !token.exists() {
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret)
            .map_err(|e| std::io::Error::other(format!("random generator failure: {e:?}")))?;
        let mut hex = String::new();
        for byte in secret {
            hex.push_str(&format!("{byte:02x}"));
        }
        save_new(token, hex.as_bytes())?;
    }
    Ok(())
}
