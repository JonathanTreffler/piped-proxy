use qstring::QString;
use reqwest::Url;
use aes_gcm::{Aes128Gcm, Key, Nonce};  // AES-GCM with 128-bit key
use aes_gcm::aead::{Aead, NewAead};
use base64::{engine::general_purpose::STANDARD, engine::general_purpose::URL_SAFE, Engine as _};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::error::Error;
use std::env;

pub fn read_buf(buf: &[u8], pos: &mut usize) -> u8 {
    let byte = buf[*pos];
    *pos += 1;
    byte
}

fn finalize_url(path: &str, query: BTreeMap<String, String>) -> String {
    #[cfg(feature = "qhash")]
    {
        use std::collections::BTreeSet;

        let qhash = {
            let secret = env::var("HASH_SECRET");
            if let Ok(secret) = secret {
                let set = query
                    .iter()
                    .filter(|(key, _)| !matches!(key.as_str(), "qhash" | "range" | "rewrite"))
                    .map(|(key, value)| (key.as_bytes().to_owned(), value.as_bytes().to_owned()))
                    .collect::<BTreeSet<_>>();

                let mut hasher = blake3::Hasher::new();

                for (key, value) in set {
                    hasher.update(&key);
                    hasher.update(&value);
                }

                hasher.update(path.as_bytes());

                hasher.update(secret.as_bytes());

                let hash = hasher.finalize().to_hex();

                Some(hash[..8].to_owned())
            } else {
                None
            }
        };

        if let Some(qhash) = qhash {
            let mut query = QString::new(query.into_iter().collect::<Vec<_>>());
            query.add_pair(("qhash", qhash));
            return format!("{}?{}", path, query);
        }
    }

    let query = QString::new(query.into_iter().collect::<Vec<_>>());
    format!("{}?{}", path, query)
}

pub fn localize_url(url: &str, host: &str) -> String {
    if url.starts_with("https://") {
        let url = Url::parse(url).unwrap();
        let host = url.host().unwrap().to_string();

        let mut query = url.query_pairs().into_owned().collect::<BTreeMap<_, _>>();

        query.insert("host".to_string(), host.clone());

        return finalize_url(url.path(), query);
    } else if url.ends_with(".m3u8") || url.ends_with(".ts") {
        let mut query = BTreeMap::new();
        query.insert("host".to_string(), host.to_string());

        return finalize_url(url, query);
    }

    url.to_string()
}

pub fn escape_xml(raw: &str) -> Cow<'_, str> {
    if !raw.contains(&['<', '>', '&', '\'', '"'][..]) {
        // If there are no characters to escape, return the original string.
        Cow::Borrowed(raw)
    } else {
        // If there are characters to escape, build a new string with the replacements.
        let mut escaped = String::with_capacity(raw.len());
        for c in raw.chars() {
            match c {
                '<' => escaped.push_str("&lt;"),
                '>' => escaped.push_str("&gt;"),
                '&' => escaped.push_str("&amp;"),
                '\'' => escaped.push_str("&apos;"),
                '"' => escaped.push_str("&quot;"),
                _ => escaped.push(c),
            }
        }
        Cow::Owned(escaped)
    }
}

pub fn get_env_bool(key: &str) -> bool {
    match env::var(key) {
        Ok(val) => val.to_lowercase() == "true" || val == "1",
        Err(_) => false,
    }
}

pub fn decrypt_data(encrypted_data: &str, encryption_key_base64: &str) -> Result<String, Box<dyn Error>> {
    let decoded_key = STANDARD.decode(encryption_key_base64)
        .map_err(|_| Box::<dyn Error>::from("Decryption failed"))?;

    if decoded_key.len() != 16 {
        return Err("Invalid key size. AES-128 requires a 16-byte key.".into());
    }

    let key = Key::from_slice(&decoded_key);

    let decoded_data = URL_SAFE.decode(encrypted_data)
        .map_err(|_| Box::<dyn Error>::from("Decryption failed"))?;

    let nonce = &decoded_data[..12];
    let ciphertext = &decoded_data[12..];

    let cipher = Aes128Gcm::new(key);
    let nonce = Nonce::from_slice(nonce); // 96-bit nonce

    let decrypted_data = cipher.decrypt(nonce, ciphertext)
        .map_err(|_| Box::<dyn Error>::from("Decryption failed"))?;

    String::from_utf8(decrypted_data)
        .map_err(|_| Box::<dyn Error>::from("Decryption failed"))
}