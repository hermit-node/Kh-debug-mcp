//! PNG store with a fixed capacity of 96; Docker volume persists across updates.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::path::PathBuf;
use tokio::{fs, io::AsyncWriteExt, sync::Mutex};

const MAX_IMAGES: usize = 96;
const MAX_BYTES: usize = 4 * 1024 * 1024;
const PNG: [u8; 8] = [137, 80, 78, 71, 13, 10, 26, 10];

pub struct ImageStore {
    folder: PathBuf,
    lock: Mutex<()>,
}
fn valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 48
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}
impl ImageStore {
    pub async fn new(folder: PathBuf) -> std::io::Result<Self> {
        fs::create_dir_all(&folder).await?;
        let store = Self {
            folder,
            lock: Mutex::new(()),
        };
        if store.list().await?.len() > MAX_IMAGES {
            return Err(std::io::Error::other("more than five PNGs in image volume"));
        }
        Ok(store)
    }
    pub async fn list(&self) -> std::io::Result<Vec<Value>> {
        let mut dir = fs::read_dir(&self.folder).await?;
        let mut out = vec![];
        while let Some(item) = dir.next_entry().await? {
            let name = item.file_name().to_string_lossy().into_owned();
            if !name.ends_with(".png") || !item.file_type().await?.is_file() {
                continue;
            }
            out.push(json!({"name":name,"bytes":item.metadata().await?.len()}));
        }
        out.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
        Ok(out)
    }
    pub async fn save(&self, name: &str, encoded: &str) -> Result<Value, String> {
        if !valid(name) {
            return Err("invalid name: use 1-48 letters, digits, - or _".into());
        }
        if encoded.len() > MAX_BYTES * 4 / 3 + 16 {
            return Err("image too large".into());
        }
        let bytes = STANDARD
            .decode(encoded)
            .map_err(|_| "invalid base64 data")?;
        if bytes.len() > MAX_BYTES || !bytes.starts_with(&PNG) {
            return Err("PNG data required (maximum 4 MiB)".into());
        }
        let _guard = self.lock.lock().await;
        if self.list().await.map_err(|e| e.to_string())?.len() >= MAX_IMAGES {
            return Err("image volume is full (96 PNG files)".into());
        }
        let file = self.folder.join(format!("{name}.png"));
        let mut dest = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&file)
            .await
            .map_err(|_| "image already exists or cannot be created")?;
        if let Err(err) = dest.write_all(&bytes).await.and_then(|_| Ok(())) {
            drop(dest);
            let _ = fs::remove_file(&file).await;
            return Err(err.to_string());
        }
        dest.sync_all().await.map_err(|e| e.to_string())?;
        Ok(json!({"stored":true,"name":format!("{name}.png"),"bytes":bytes.len()}))
    }
    pub async fn delete(&self, name: &str) -> Result<(), String> {
        if !valid(name) {
            return Err("invalid name".into());
        }
        let _guard = self.lock.lock().await;
        fs::remove_file(self.folder.join(format!("{name}.png")))
            .await
            .map_err(|_| "image not found or deletion failed".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn filenames_are_confined() {
        assert!(valid("sample_1"));
        assert!(!valid("../escape"));
        assert!(!valid("a.png"));
        assert!(!valid(""));
    }
    #[tokio::test]
    async fn persists_and_limits_to_96() {
        let folder = std::env::temp_dir().join(format!("kh-debug-img-{}", std::process::id()));
        let _ = fs::remove_dir_all(&folder).await;
        let encoded = STANDARD.encode(PNG);
        {
            let store = ImageStore::new(folder.clone()).await.unwrap();
            for i in 0..96 {
                store.save(&format!("image{i}"), &encoded).await.unwrap();
            }
            assert_eq!(store.list().await.unwrap().len(), 96);
            assert!(store.save("image96", &encoded).await.is_err());
            assert!(store.save("image0", &encoded).await.is_err());
        }
        {
            let store = ImageStore::new(folder.clone()).await.unwrap();
            assert_eq!(store.list().await.unwrap().len(), 96);
            store.delete("image0").await.unwrap();
            assert_eq!(store.list().await.unwrap().len(), 95);
            store.save("image96", &encoded).await.unwrap();
            assert_eq!(store.list().await.unwrap().len(), 96);
        }
        fs::remove_dir_all(folder).await.unwrap();
    }
}