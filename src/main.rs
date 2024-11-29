use aes::cipher::BlockDecryptMut;
use aes::cipher::KeyIvInit;
use base64::Engine;
use cbc::cipher::block_padding::Pkcs7;
use serde_json::Value;

use std::env;
use std::error::Error;
use std::fs::File;
use std::io;
use std::io::Write;
use std::path::Path;
use std::process::exit;

type Decryptor = cbc::Decryptor<aes::Aes256>;

fn main() -> Result<(), Box<dyn Error>> {
    let program = env::args().nth(0).unwrap();
    let target = match env::args().nth(1) {
        Some(t) => t,
        None => {
            eprintln!("Usage: {program} [FILE]");
            exit(1);
        }
    };

    let mut rom_file = File::open(&target)?;

    let mut xor_writer = XorWriter::new(Vec::new(), 0xff);
    io::copy(&mut rom_file, &mut xor_writer)?;
    let buf = xor_writer.into_inner();

    let result = match String::from_utf8(buf) {
        Ok(decoded) => decoded,
        Err(_) => {
            eprintln!("Error: cannot decode romfile as utf-8");
            exit(1);
        }
    };

    let mut value: Value = quick_xml::de::from_str(&result)?;

    scan_and_decode(&mut value);

    let dest = replace_ext(&target, "json");
    let mut out = File::create(&dest)?;
    serde_json::to_writer_pretty(&mut out, &value)?;

    println!("{dest} saved!");
    Ok(())
}

fn replace_ext(from: &str, ext: &str) -> String {
    let path = Path::new(from);
    path.with_extension(ext)
        .file_name()
        .and_then(|b| b.to_str())
        .map(|b| String::from(b))
        .unwrap()
}

fn scan_and_decode(value: &mut Value) {
    match value {
        Value::Object(object) => {
            for (key, val) in object {
                if let Value::String(str_val) = val {
                    if let Some(decoded) = try_decode_password(key, str_val) {
                        str_val.clone_from(&decoded);
                    }
                }
                scan_and_decode(val)
            }
        }
        _ => {}
    }
}

fn is_base64(val: &str) -> bool {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    !val.is_empty() && val.as_bytes().iter().all(|&b| alphabet.contains(&b))
}

fn try_decode_password(key: &str, value: &str) -> Option<String> {
    if !is_base64(&value) {
        return None;
    }

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value.as_bytes())
        .ok()?;

    if decoded.iter().all(|&b| b.is_ascii_graphic()) {
        println!("decoded {key}");
        Some(String::from_utf8(decoded).unwrap())
    } else if decoded.len() % 16 == 0 {
        let result = try_decrypt_password(&decoded);
        if let Some(_) = result {
            println!("decrypted {key}");
        }
        result
    } else {
        None
    }
}

fn try_decrypt_password(buf: &[u8]) -> Option<String> {
    let key = b"0123456789012345\x0a\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    let iv = b"0123456789012345";
    let decryptor = Decryptor::new(key.into(), iv.into());

    let mut new_buf = buf.to_vec();
    let result = decryptor.decrypt_padded_mut::<Pkcs7>(&mut new_buf);

    match result {
        Ok(decrypted) => Some(String::from_utf8(decrypted.to_vec()).unwrap()),
        Err(_) => None,
    }
}

struct XorWriter<W: Write> {
    inner: W,
    key: u8,
}

impl<W: Write> XorWriter<W> {
    fn new(inner: W, key: u8) -> Self {
        Self { inner, key }
    }

    fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for XorWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let xored: Vec<u8> = buf.iter().map(|&b| b ^ self.key).collect();

        self.inner.write(&xored)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
