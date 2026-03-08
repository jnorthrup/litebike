use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Generic metadata about a model that may be needed for routing/conversion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metamodel {
    pub id: String,
    pub provider: String,
    pub context_window: u64,
    pub max_tokens: u64,
    pub conversions: Vec<String>, // e.g. allowed upstream formats or conversion hints
    pub cached_at: u64,
    pub expires_at: Option<u64>,
}

impl Metamodel {
    pub fn is_expired(&self) -> bool {
        if let Some(exp) = self.expires_at {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            now > exp
        } else {
            false
        }
    }
}

/// Simple filesystem-backed blob store keyed by digest (filename-safe string).
pub struct BlobStore {
    base_dir: PathBuf,
}

impl BlobStore {
    pub fn new(base_dir: PathBuf) -> Self {
        let _ = fs::create_dir_all(&base_dir);
        BlobStore { base_dir }
    }

    fn path_for(&self, key: &str) -> PathBuf {
        let safe = key.replace('/', "_").replace(':', "_");
        self.base_dir.join(safe)
    }

    /// Write raw data into the store.
    pub fn put(&self, key: &str, data: &[u8]) -> io::Result<()> {
        let path = self.path_for(key);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut f = fs::File::create(path)?;
        f.write_all(data)
    }

    /// Read raw data from the store.
    pub fn get(&self, key: &str) -> io::Result<Option<Vec<u8>>> {
        let path = self.path_for(key);
        if !path.exists() {
            return Ok(None);
        }
        let mut buf = Vec::new();
        let mut f = fs::File::open(path)?;
        f.read_to_end(&mut buf)?;
        Ok(Some(buf))
    }

    /// Write data under a content-addressed key. Returns the hex digest.
    pub fn put_cas(&self, data: &[u8]) -> io::Result<String> {
        // compute sha256 digest
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let digest = hasher.finalize();
        let key = hex::encode(digest);
        self.put(&key, data)?;
        Ok(key)
    }

    /// Replicate a blob to IPFS (requires IPFS_API_URL env).
    pub async fn replicate_ipfs(&self, key: &str) -> Result<String, String> {
        let api = std::env::var("IPFS_API_URL").unwrap_or_else(|_| "http://127.0.0.1:5001".to_string());
        let path = self.path_for(key);
        if !path.exists() {
            return Err(format!("blob {} not found", key));
        }
        let client = reqwest::Client::new();
        // read the file ourselves and attach as bytes, since async Part::file isn't available
        let data = fs::read(&path).map_err(|e| e.to_string())?;
        let part = reqwest::multipart::Part::bytes(data).file_name(
            PathBuf::from(&path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("blob")
                .to_string(),
        );
        let form = reqwest::multipart::Form::new().part("file", part);
        let resp = client.post(&format!("{}/api/v0/add", api))
            .multipart(form)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let body: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
        Ok(body.get("Hash").and_then(|v| v.as_str()).unwrap_or("").to_string())
    }

    /// Replicate a blob to S3 (requires AWS_BUCKET env and AWS credentials).
    pub async fn replicate_s3(&self, key: &str) -> Result<String, String> {
        let bucket = std::env::var("AWS_BUCKET").map_err(|_| "AWS_BUCKET not set".to_string())?;
        let path = self.path_for(key);
        if !path.exists() {
            return Err(format!("blob {} not found", key));
        }
        // using rusoto or aws-sdk-s3 would normally be better, but keep simple via CLI
        // for now just build a public URL stub
        Ok(format!("s3://{}/{}", bucket, key))
    }

    /// Delete an entry.
    pub fn delete(&self, key: &str) -> io::Result<()> {
        let path = self.path_for(key);
        if path.exists() {
            fs::remove_file(path)?;
        }
        Ok(())
    }
}

/// Load a HuggingFace model sheet (public endpoint) and return a list of metamodels.
pub async fn fetch_huggingface_sheet(api_token: &str) -> Result<Vec<Metamodel>, reqwest::Error> {
    // The HF inference API for model list can be hit at https://huggingface.co/api/models
    let client = reqwest::Client::new();
    let mut req = client.get("https://huggingface.co/api/models");
    if !api_token.is_empty() {
        req = req.header("Authorization", format!("Bearer {}", api_token));
    }
    let resp = req.send().await?.json::<serde_json::Value>().await?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let mut out = Vec::new();
    if let Some(array) = resp.as_array() {
        for entry in array {
            if let Some(model_id) = entry.get("modelId").and_then(|v| v.as_str()) {
                // context_window may not be directly available; default to 1M
                let ctx = entry
                    .get("max_context_size")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(1_048_576);
                let max_tok = entry
                    .get("max_length")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(ctx);
                let conversions = vec![];
                out.push(Metamodel {
                    id: format!("huggingface/{}", model_id),
                    provider: "huggingface".to_string(),
                    context_window: ctx,
                    max_tokens: max_tok,
                    conversions,
                    cached_at: now,
                    expires_at: Some(now + 86_400 * 7), // 1 week default
                });
            }
        }
    }
    Ok(out)
}

/// Content-addressable cache for metamodels.
pub struct MetamodelCache {
    blob_store: BlobStore,
    index: HashMap<String, String>, // id -> digest
}

impl MetamodelCache {
    pub fn new(base_dir: PathBuf) -> Self {
        Self {
            blob_store: BlobStore::new(base_dir),
            index: HashMap::new(),
        }
    }

    pub fn insert(&mut self, meta: Metamodel) -> io::Result<String> {
        let bytes = serde_json::to_vec(&meta).unwrap();
        let digest = self.blob_store.put_cas(&bytes)?;
        self.index.insert(meta.id.clone(), digest.clone());
        Ok(digest)
    }

    pub fn get(&self, model_id: &str) -> io::Result<Option<Metamodel>> {
        if let Some(digest) = self.index.get(model_id) {
            if let Some(data) = self.blob_store.get(digest)? {
                let m: Metamodel = serde_json::from_slice(&data).unwrap();
                if !m.is_expired() {
                    return Ok(Some(m));
                }
            }
        }
        Ok(None)
    }

    pub fn replicate_all(&self) {
        for digest in self.index.values() {
            // spawn async tasks to replicate
            let bs = self.blob_store.clone();
            let d = digest.clone();
            tokio::spawn(async move {
                let _ = bs.replicate_ipfs(&d).await;
                let _ = bs.replicate_s3(&d).await;
            });
        }
    }
}

impl Clone for BlobStore {
    fn clone(&self) -> Self {
        BlobStore { base_dir: self.base_dir.clone() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    #[tokio::test]
    async fn blobstore_cas_roundtrip() {
        let dir = tempdir().unwrap();
        let bs = BlobStore::new(dir.path().to_path_buf());
        let data = b"hello world";
        let digest = bs.put_cas(data).unwrap();
        assert_eq!(bs.get(&digest).unwrap().unwrap(), data);
    }

    #[test]
    fn metamodel_cache_basic() {
        let dir = tempdir().unwrap();
        let mut mc = MetamodelCache::new(dir.path().to_path_buf());
        let m = Metamodel {
            id: "test/model".into(),
            provider: "provider".into(),
            context_window: 1024,
            max_tokens: 1024,
            conversions: vec!["other/format".into()],
            cached_at: 0,
            expires_at: None,
        };
        let d = mc.insert(m.clone()).unwrap();
        let fetched = mc.get("test/model").unwrap().unwrap();
        assert_eq!(fetched.id, m.id);
        assert_eq!(d.len(), 64); // sha256
    }
}
