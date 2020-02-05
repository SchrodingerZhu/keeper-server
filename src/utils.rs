use std::fmt::Debug;
use std::process::exit;
use botan::base64_decode;
use crate::Response;

pub static SERVER_PRIVATE: &'static str = include_str!("/code/server/server.pem");
pub static USER_PUBLIC : &'static str = include_str!("/code/keys/keeper_pub.pem");

#[inline(always)]
pub fn get_private() -> botan::Privkey {
    botan::Privkey::load_pem(SERVER_PRIVATE).unwrap()
}

#[inline(always)]
pub fn get_public() -> botan::Pubkey {
    botan::Pubkey::load_pem(USER_PUBLIC).unwrap()
}

#[inline(always)]
pub fn decrypt_message(message: &str) -> String {
    let msg = base64_decode(message).unwrap();
    let decrypter = botan::Decryptor::new(&get_private(), "OAEP(SHA-256)").unwrap();
    let decrypted = decrypter.decrypt(msg.as_slice()).unwrap();
    unsafe { String::from_utf8_unchecked(decrypted) }
}

#[inline(always)]
pub fn empty_response(signature: String) -> Response {
    Response {
        signature,
        boxed_content: vec![]
    }
}
#[inline(always)]
pub fn failed_with<T  : Debug  + 'static, U>(message: &str) -> Box<dyn FnOnce(T) -> U>{
    let message = String::from(message);
    Box::new(move |_| {
        eprintln!("[ERROR] {}", message);
        exit(1)
    })
}

#[inline(always)]
pub fn get_var(key: &str) -> String {
    std::env::var(key)
        .unwrap_or_else(failed_with(format!("unable to get {}", key).as_str()))
}
