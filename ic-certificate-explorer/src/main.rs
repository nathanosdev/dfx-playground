use anyhow::Result;
use flate2::read::{DeflateDecoder, GzDecoder};
use ic_agent::{agent::http_transport::ReqwestTransport, export::Principal, Agent};
use ic_http_certification::{HttpRequest, HttpResponse};
use ic_response_verification::verify_request_response_pair;
use ic_utils::call::SyncCall;
use ic_utils::interfaces::http_request::HeaderField;
use ic_utils::interfaces::HttpRequestCanister;
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_CERT_TIME_OFFSET_NS: u128 = 300_000_000_000;
const MAX_CHUNK_SIZE_TO_DECOMPRESS: usize = 1024;
const MAX_CHUNKS_TO_DECOMPRESS: u64 = 10_240;

pub fn decode_body(body: &Vec<u8>, encoding: &Option<&str>) -> Option<Vec<u8>> {
    return match encoding.as_deref() {
        Some("gzip") => body_from_decoder(GzDecoder::new(body.as_slice())),
        Some("deflate") => body_from_decoder(DeflateDecoder::new(body.as_slice())),
        _ => Some(body.to_owned()),
    };
}

fn body_from_decoder<D: Read>(mut decoder: D) -> Option<Vec<u8>> {
    let mut decoded = Vec::new();
    let mut buffer = [0u8; MAX_CHUNK_SIZE_TO_DECOMPRESS];

    for _ in 0..MAX_CHUNKS_TO_DECOMPRESS {
        let bytes = decoder.read(&mut buffer).ok()?;

        if bytes == 0 {
            return Some(decoded);
        }

        decoded.extend_from_slice(&buffer[..bytes]);
    }

    if decoder.bytes().next().is_some() {
        // [TODO] throw "body too big" exception here
        return None;
    }

    Some(decoded)
}

pub fn hash<T: AsRef<[u8]>>(data: T) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let data_hash = hasher.finalize();

    hex::encode(data_hash)
}

pub async fn create_agent(url: &str) -> Result<Agent> {
    let transport = ReqwestTransport::create(url)?;

    let agent = Agent::builder().with_transport(transport).build()?;
    agent.fetch_root_key().await?;

    Ok(agent)
}

fn get_current_time_in_ns() -> u128 {
    let start = SystemTime::now();

    start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_nanos()
}

#[tokio::main]
async fn main() -> Result<()> {
    const REPLICA_ADDRESS: &str = "http://localhost:4943";
    const CANISTER_ID: &str = "bkyz2-fmaaa-aaaaa-qaaaq-cai";

    const PATH: &str = "/todos/";
    const HTTP_METHOD: &str = "GET";
    let headers: Vec<HeaderField> = vec![];

    let agent = create_agent(REPLICA_ADDRESS).await?;
    let root_key = agent.read_root_key();
    let canister_id = Principal::from_text(CANISTER_ID)?;
    let canister_interface = HttpRequestCanister::create(&agent, canister_id);

    let (response,) = canister_interface
        .http_request(HTTP_METHOD, PATH, headers.clone(), &[], Some(&2))
        .call()
        .await?;

    let mut encoding: Option<&str> = None;
    for HeaderField(name, value) in response.headers.iter() {
        if name.eq_ignore_ascii_case("Content-Encoding") {
            encoding = Some(value);
        }
    }

    let result = verify_request_response_pair(
        HttpRequest {
            method: HTTP_METHOD.to_string(),
            url: PATH.to_string(),
            headers: headers
                .iter()
                .map(|HeaderField(k, v)| (k.clone().into_owned(), v.clone().into_owned()))
                .collect(),
            body: vec![],
        },
        HttpResponse {
            status_code: response.status_code,
            headers: response
                .headers
                .iter()
                .map(|HeaderField(k, v)| (k.clone().into_owned(), v.clone().into_owned()))
                .collect(),
            body: response.body.clone(),
            upgrade: None,
        },
        canister_id.as_slice(),
        get_current_time_in_ns(),
        MAX_CERT_TIME_OFFSET_NS,
        root_key.as_slice(),
        2,
    );
    println!("Verification result: {:?}", result);
    println!("Response: {:?}", response);

    let body = response.body.as_slice();
    let decoded_body = decode_body(&response.body, &encoding).unwrap();

    let body_hash = hash(body);
    let decoded_body_hash = hash(decoded_body.as_slice());

    println!("Body hash: {}", body_hash);
    println!("Decoded body hash: {}", decoded_body_hash);

    Ok(())
}
