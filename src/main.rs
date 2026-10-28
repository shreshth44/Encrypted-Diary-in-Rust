use std::io;
use argon2::Argon2;

use aes_gcm::{
    aead::{Aead, Generate, KeyInit},
    Aes256Gcm, Nonce, 
};

use rand::{rngs::OsRng, RngCore};

use std::fs;
use std::path::Path;
use std::process::Command;
use std::error::Error;

type FnResult<T> = Result<T, Box<dyn Error>>;

const MAGIC: &[u8; 6] = b"DIARY\0";
const MAGIC_END: usize = 6;
const SALT_END: usize = 22;
const NONCE_END: usize = 34;

fn derive_key(password: &str, salt: &[u8; 16]) -> FnResult<[u8; 32]>{
    let mut output_key_material = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut output_key_material)
        .map_err(|_| "failed to hash password")?;

    Ok(output_key_material)
}
 
fn encrypt_file(source_path: &Path, dest_path: &Path, password: &str) -> FnResult<()>{
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let key = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| "Invalid key length")?;

    let nonce = Nonce::generate(); 
    let plaintext = fs::read(source_path)?;
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_slice()).map_err(|_| "failed to encrypt.")?;

    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    
    fs::write(dest_path, out)?;
    Ok(())
}

fn decrypt_file(source_path: &Path, dest_path: &Path, password: &str) -> FnResult<()>{
    if !source_path.exists() {
        fs::write(dest_path, b"")?;
        return Ok(());
    }
    
    let file_data = fs::read(source_path)?;
    if file_data.len() < NONCE_END || &file_data[..MAGIC_END] != MAGIC {
        return Err("Invalid encrypted file".into());
    }
    let salt: &[u8; 16] = &file_data[MAGIC_END..SALT_END].try_into()?;
    let key = derive_key(password, salt)?;

    let nonce_bytes = &file_data[SALT_END..NONCE_END];
    let nonce = Nonce::try_from(nonce_bytes).map_err(|_| "Invalid nonce length")?;

    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| "Invalid key length")?;
    let plaintext = cipher.decrypt(&nonce, &file_data[34..]).map_err(|_| "Wrong password or file is corrupted.")?;

    fs::write(dest_path, plaintext)?;
    Ok(())
}
fn read() -> FnResult<()>{
    println!("Enter filename: ");
    let mut fname = String::new();

    io::stdin()
        .read_line(&mut fname)?;

    let fname = fname.trim();
    let filepath = Path::new(&fname);
    if !filepath.exists() {
        return Err("File not found".into());
    }
    let pass = rpassword::prompt_password("Enter your password: ")?;
    let pass = pass.trim();
    
    let destpath = Path::new("/tmp/to_read.txt");
    decrypt_file(&filepath, &destpath, &pass)?;
    
    let _output = Command::new("cat")
        .arg("/tmp/to_read.txt")
        .status()?; 
    let _output = Command::new("rm")
        .arg("/tmp/to_read.txt")
        .status()?; 
    Ok(())    
}
fn edit() -> FnResult<()>{
    println!("Enter filename: ");
    let mut fname = String::new();

    io::stdin()
        .read_line(&mut fname)?;

    let fname = fname.trim();
    let filepath = Path::new(&fname);
    let pass = rpassword::prompt_password("Enter your password: ")?;
    let pass = pass.trim();
    let destpath = Path::new("/tmp/to_edit.txt");
    decrypt_file(&filepath, &destpath, &pass)?;
    let _output = Command::new("vim")
        .arg("/tmp/to_edit.txt")
        .status()?; 
    encrypt_file(&destpath, &filepath, &pass)?;
    let _output = Command::new("rm")
        .arg("/tmp/to_edit.txt")
        .status()?;
    Ok(())
}

fn main() {

    loop{
        println!("Put 'read' to read, 'edit' to edit or write new file, 'stop' to stop: ");
        let mut command = String::new();

        io::stdin()
            .read_line(&mut command)
            .expect("Failed to read line");

        let command = command.trim();
        if command == "read"{
            let result = read();
            match result{
                Ok(_) => println!("Read successful"),
                Err(e) => println!("Error occurred: {e}"),
            }
        }
        else if command == "edit"{
            let result = edit();
            match result{
                Ok(_) => println!("Write successful"),
                Err(e) => println!("Error occurred: {e}"),
            }
        }
        else if command == "stop"{
            break;
        }
        else{
            println!("Invalid command");
        }
    }
}
