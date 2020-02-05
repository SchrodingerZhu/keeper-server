#![feature(proc_macro_hygiene, decl_macro)]
use mimalloc::MiMalloc;
use rocket_contrib::json::Json;
use serde::*;

#[global_allocator]
static ALLOC: MiMalloc = MiMalloc;

use rocket::*;
use crate::utils::{get_public, get_private, decrypt_message, empty_response};
use crate::database::get_database;
use rocksdb::IteratorMode;
use botan::*;


mod utils;
mod database;

#[derive(Debug, Serialize, Deserialize)]
struct Request {
    what: String,
    signature: String,
    content: String
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    pub signature: String,
    pub boxed_content: Vec<String>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Insertion {
    pub name: String,
    pub content: String
}


#[post("/", data = "<req>")]
fn service(req: Json<Request>) -> Option<Json<Response>> {
    let verifier = botan::Verifier::new(&get_public(), "PKCS1v15(SHA-256)")
        .unwrap();
    verifier.update(req.what.as_bytes()).unwrap();
    let res = verifier.finish(base64_decode(req.signature.as_str()).unwrap().as_slice());
    let verification = match res {
        Ok(true) => Ok(()),
        _ => Err(())
    };
    let encrypter = botan::Encryptor::new(&get_public(), "OAEP(SHA-256)")
        .unwrap();
    let signer = botan::Signer::new(&get_private(), "PKCS1v15(SHA-256)")
        .unwrap();
    let rng = botan::RandomNumberGenerator::new().unwrap();
    signer.update(req.what.as_bytes()).unwrap();
    let signature = signer.finish(&rng).and_then(|x|base64_encode(x.as_slice())).unwrap();
    verification.map(|_| match req.what.as_str() {
        "list" => {
            let boxed_content = get_database().iterator(IteratorMode::Start)
                .map(|(key, _)| encrypter.encrypt(key.as_ref(), &rng).unwrap())
                .map(|x| base64_encode(x.as_slice()).unwrap())
                .collect();
            Json(Response {
                signature,
                boxed_content
            })
        },
        "fetch" => fetch_handler(signature, req.content.as_str()),
        "add" => insertion_handler(signature, req.content.as_str(), &rng, &encrypter),
        "delete" => delete_handler(signature, req.content.as_str(), &rng, &encrypter),
        "generate" => generate_handler(signature, req.content.as_str(), &rng, &encrypter),
        _ => Json(empty_response(signature))
    }).ok()
}

#[inline(always)]
fn fetch_handler(signature: String, name: &str) -> Json<Response> {
    let name = decrypt_message(name);
    let res = match get_database().get(name.as_bytes()) {
        Ok(Some(content)) => {
            let content = base64_encode(content.as_slice()).unwrap();
            Response {
                signature,
                boxed_content: vec![content]
            }
        },
        _ => empty_response(signature)
    };
    Json(res)
}

#[inline(always)]
fn delete_handler(signature: String, deletion: &str, rng: &RandomNumberGenerator, encrypter: &Encryptor) -> Json<Response> {
    let deletion = decrypt_message(deletion);
    let success = encrypter.encrypt("success".as_bytes(), &rng)
        .and_then(|x|base64_encode(x.as_slice())).unwrap();
    let res = match get_database().delete(deletion.as_bytes()) {
        Ok(_) => {
            Response {
                signature,
                boxed_content: vec![success]
            }
        },
        _ => empty_response(signature)
    };
    Json(res)
}

#[inline(always)]
fn insertion_handler(signature: String, insertion: &str, rng: &RandomNumberGenerator, encrypter: &Encryptor) -> Json<Response> {
    let msg_box = decrypt_message(insertion);
    let insertion = serde_json::from_str::<Insertion>(msg_box.as_str())
        .unwrap();
    let content = encrypter.encrypt(insertion.content.as_bytes(), &rng)
        .unwrap();
    let success = encrypter.encrypt("success".as_bytes(), &rng)
        .and_then(|x|base64_encode(x.as_slice())).unwrap();
    let res = match get_database().put(insertion.name.as_bytes(), content.as_slice()) {
        Ok(_) => {
            Response {
                signature,
                boxed_content: vec![success]
            }
        },
        _ => empty_response(signature)
    };
    Json(res)
}


#[inline(always)]
fn generate_handler(signature: String, name: &str, rng: &RandomNumberGenerator, encrypter: &Encryptor) -> Json<Response> {
    let name = decrypt_message(name);
    let content = match get_database().get(name.as_bytes()) {
        Ok(Some(_)) => String::from("exists"),
        Err(_) => String::from("error"),
        _ => {
            let mut buffer = [0;16];
            rng.fill(&mut buffer).and_then(|_| base64_encode(buffer.as_ref()))
                .unwrap_or(String::from("error"))
        }
    };
    let content = encrypter.encrypt(content.as_bytes(), &rng).unwrap();
    let success = base64_encode(content.as_slice()).unwrap();
    let res = match get_database().put(name.as_bytes(), content.as_slice()) {
        Ok(_) => {
            Response {
                signature,
                boxed_content: vec![success]
            }
        },
        _ => empty_response(signature)
    };
    Json(res)
}

fn main() {
    rocket::ignite()
        .mount("/", routes![service])
        .launch();
}

