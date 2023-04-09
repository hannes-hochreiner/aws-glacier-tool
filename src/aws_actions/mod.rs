use chrono::{DateTime, Utc};
use hyper::{
    client::ResponseFuture,
    header::{InvalidHeaderName, InvalidHeaderValue},
    http::{HeaderName, HeaderValue},
    Body, Client, Method, Request, StatusCode,
};
use hyper_tls::HttpsConnector;
use ring::{digest, hmac};
use std::{collections::HashMap, convert::Infallible};
use thiserror::Error;

pub mod vault;

#[derive(Debug)]
pub struct Config {
    pub region: String,
    pub secret_key: String,
    pub key_id: String,
}

#[derive(Error, Debug)]
pub enum AwsActionsError {
    #[error("invalid header value")]
    InvalidHeaderValue(#[from] InvalidHeaderValue),
    #[error("invalid header name")]
    InvalidHeaderName(#[from] InvalidHeaderName),
    #[error("hyper http error")]
    HyperHttpError(#[from] hyper::http::Error),
    #[error("hyper  error")]
    HyperError(#[from] hyper::Error),
    #[error("request builder error")]
    RequestBuilderError,
    #[error("infallible")]
    Infallible(#[from] Infallible),
    #[error("io error")]
    IoError(#[from] std::io::Error),
    #[error("unexpected status code: {0}")]
    StatusCodeError(StatusCode),
    #[error("serde json error")]
    SerdeJsonError(#[from] serde_json::Error),
}

fn request(
    config: &Config,
    method: &Method,
    service: &str,
    headers: HashMap<String, String>,
    path: &str,
    query: &HashMap<String, String>,
    data: Vec<u8>,
    streaming: bool,
) -> Result<ResponseFuture, AwsActionsError> {
    let client = Client::builder().build::<_, hyper::Body>(HttpsConnector::new());
    let timestamp = Utc::now();
    let req = build_request(
        config, method, service, headers, path, query, data, streaming, &timestamp,
    )?;

    Ok(client.request(req))
}

fn build_request(
    config: &Config,
    method: &Method,
    service: &str,
    headers: HashMap<String, String>,
    path: &str,
    query: &HashMap<String, String>,
    data: Vec<u8>,
    streaming: bool,
    timestamp: &DateTime<Utc>,
) -> Result<Request<Body>, AwsActionsError> {
    let data_hash_hex = hash_hex(&data);
    let content_length = data.len();
    let host = format!("{service}.{region}.amazonaws.com", region = &config.region);
    let mut headers: HashMap<String, String> = headers
        .iter()
        .map(|(k, v)| (k.trim().to_lowercase(), v.trim().to_lowercase()))
        .collect();

    // add common headers
    // https://docs.aws.amazon.com/amazonglacier/latest/dev/api-common-request-headers.html
    headers.insert("host".into(), host.clone());
    headers.insert(
        "x-amz-date".into(),
        timestamp.format("%Y%m%dT%H%M%SZ").to_string(),
    );
    headers.insert("content-length".into(), format!("{content_length}"));
    headers.insert("x-amz-glacier-version".into(), "2012-06-01".into());

    if streaming {
        headers.insert("x-amz-content-sha256".into(), data_hash_hex.clone());
    }

    // create canonical string
    let query_string = create_query_string(query);
    let (canonical_string, canonical_header_list) =
        create_canonical_string(method, path, &data_hash_hex, &headers, &query_string);
    let canonical_hash_hex = hash_hex(canonical_string);

    // create string to sign
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n\
        {}\n\
        {}/{region}/{service}/aws4_request\n\
        {canonical_hash_hex}",
        timestamp.format("%Y%m%dT%H%M%SZ"),
        timestamp.format("%Y%m%d"),
        region = &config.region
    );

    // create signature
    let signature = create_signature(
        &config.secret_key,
        timestamp,
        &config.region,
        string_to_sign,
    )?;

    // insert signature header
    headers.insert(
        "authorization".into(),
        format!(
            "AWS4-HMAC-SHA256 Credential={key_id}/{ts}/{region}/{service}/aws4_request, \
            SignedHeaders={canonical_header_list}, \
            Signature={signature}",
            key_id = &config.key_id,
            ts = timestamp.format("%Y%m%d"),
            region = &config.region,
        ),
    );

    // build request
    let mut req_builder = Request::builder()
        .method(method)
        .uri(format!("https://{host}{path}?{query_string}"));

    let req_headers = req_builder
        .headers_mut()
        .ok_or(AwsActionsError::RequestBuilderError)?;

    headers
        .iter()
        .map(|(k, v)| {
            let v = HeaderValue::from_str(v)?;
            let k = HeaderName::from_bytes(k.as_bytes())?;
            Ok((k, v))
        })
        .collect::<Result<HashMap<HeaderName, HeaderValue>, AwsActionsError>>()?
        .iter()
        .for_each(|(k, v)| {
            req_headers.insert(k.to_owned(), v.to_owned());
        });

    Ok(req_builder.body(Body::try_from(data)?)?)
}

fn hash_hex(data: impl AsRef<[u8]>) -> String {
    hex::encode(digest::digest(&digest::SHA256, data.as_ref()).as_ref())
}

fn create_canonical_string(
    method: &Method,
    path: &str,
    data_hash_hex: &str,
    headers: &HashMap<String, String>,
    query_string: &str,
) -> (String, String) {
    let mut canonical_headers: Vec<(&String, &String)> = headers
        .iter()
        .filter(|&(k, _)| k == "host" || k.starts_with("x-amz-"))
        .collect();

    canonical_headers.sort_by_key(|&(k, _)| k);

    let header_string = canonical_headers
        .iter()
        .map(|&(k, v)| format!("{k}:{v}"))
        .collect::<Vec<String>>()
        .join("\n");
    let header_list = canonical_headers
        .iter()
        .map(|&(k, _)| k.to_owned())
        .collect::<Vec<String>>()
        .join(";");

    (
        format!(
            "{method}\n{path}\n{query_string}\n{header_string}\n\n{header_list}\n{data_hash_hex}"
        ),
        header_list,
    )
}

fn create_query_string(query: &HashMap<String, String>) -> String {
    let mut query_vec = query.iter().collect::<Vec<(&String, &String)>>();
    query_vec.sort_by_key(|&(k, _)| k);
    query_vec
        .iter()
        .map(|&(k, v)| {
            let k = urlencoding::encode(k);
            let v = urlencoding::encode(v);

            format!("{k}={v}")
        })
        .collect::<Vec<String>>()
        .join("&")
}

/// https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html
/// https://docs.aws.amazon.com/amazonglacier/latest/dev/amazon-glacier-signing-requests.html
fn create_signature(
    secret_key: impl AsRef<str>,
    timestamp: &DateTime<Utc>,
    region: impl AsRef<str>,
    string_to_sign: impl AsRef<str>,
) -> Result<String, AwsActionsError> {
    let key_date = hmac::sign(
        &hmac::Key::new(
            hmac::HMAC_SHA256,
            format!("AWS4{}", secret_key.as_ref()).as_bytes(),
        ),
        timestamp.format("%Y%m%d").to_string().as_bytes(),
    );
    let key_region = hmac::sign(
        &hmac::Key::new(hmac::HMAC_SHA256, key_date.as_ref()),
        region.as_ref().as_bytes(),
    );
    let key_glacier = hmac::sign(
        &hmac::Key::new(hmac::HMAC_SHA256, key_region.as_ref()),
        b"glacier",
    );
    let key_request = hmac::sign(
        &hmac::Key::new(hmac::HMAC_SHA256, key_glacier.as_ref()),
        b"aws4_request",
    );

    Ok(hex::encode(
        hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, key_request.as_ref()),
            string_to_sign.as_ref().as_bytes(),
        )
        .as_ref(),
    ))
}

#[cfg(test)]
mod test {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_digest_hex() {
        assert_eq!(
            hash_hex(&[]),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
    }

    #[test]
    fn test_create_query_string() {
        assert_eq!(
            create_query_string(&HashMap::from([
                ("key1".into(), "value 1".into()),
                ("key2".into(), "".into())
            ])),
            "key1=value%201&key2="
        )
    }

    #[test]
    fn test_create_canonical_string() {
        let timestamp = Utc.with_ymd_and_hms(2012, 5, 25, 0, 24, 53).unwrap();
        let (canonical_string, header_list) = create_canonical_string(
            &Method::PUT,
            "/-/vaults/examplevault",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            &HashMap::from([
                ("host".into(), "glacier.us-east-1.amazonaws.com".into()),
                (
                    "x-amz-date".into(),
                    timestamp.format("%Y%m%dT%H%M%SZ").to_string(),
                ),
                ("x-amz-glacier-version".into(), "2012-06-01".into()),
            ]),
            "",
        );

        assert_eq!(
            canonical_string,
            "PUT\n\
        /-/vaults/examplevault\n\
        \n\
        host:glacier.us-east-1.amazonaws.com\n\
        x-amz-date:20120525T002453Z\n\
        x-amz-glacier-version:2012-06-01\n\
        \n\
        host;x-amz-date;x-amz-glacier-version\n\
        e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(header_list, "host;x-amz-date;x-amz-glacier-version");
    }

    #[test]
    fn test_create_signature() {
        let secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let timestamp = Utc.with_ymd_and_hms(2012, 5, 25, 0, 24, 53).unwrap();
        let region = "us-east-1";
        let string_to_sign = "AWS4-HMAC-SHA256\n\
            20120525T002453Z\n\
            20120525/us-east-1/glacier/aws4_request\n\
            5f1da1a2d0feb614dd03d71e87928b8e449ac87614479332aced3a701f916743";

        assert_eq!(
            create_signature(secret_key, &timestamp, region, string_to_sign).unwrap(),
            "3ce5b2f2fffac9262b4da9256f8d086b4aaf42eba5f111c21681a65a127b7c2a"
        )
    }

    #[test]
    fn test_build_request_1() {
        let secret_key = String::from("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
        let timestamp = Utc.with_ymd_and_hms(2012, 5, 7, 0, 0, 0).unwrap();
        let region = String::from("us-east-1");
        let key_id = String::from("AKIAIOSFODNN7EXAMPLE");
        let data_string = String::from("Welcome to S3 Glacier.");
        let headers: HashMap<String, String> = HashMap::from([
            ("x-amz-archive-description".into(), "my archive".into()),
            (
                "x-amz-sha256-tree-hash".into(),
                hex::encode(aws_tree_hash::calculate_tree_hash(data_string.as_bytes())),
            ),
        ]);
        let req = build_request(
            &Config {
                region,
                secret_key,
                key_id,
            },
            &Method::POST,
            "glacier",
            headers,
            "/-/vaults/examplevault",
            &HashMap::new(),
            data_string.into_bytes(),
            true,
            &timestamp,
        )
        .unwrap();

        assert_eq!(req.method(), "POST");
        assert_eq!(
            req.uri(),
            "https://glacier.us-east-1.amazonaws.com/-/vaults/examplevault"
        );
        let headers = req.headers();
        assert_eq!(headers.len(), 8);
        assert_eq!(
            headers.get("authorization").unwrap(),
            "AWS4-HMAC-SHA256 \
            Credential=AKIAIOSFODNN7EXAMPLE/20120507/us-east-1/glacier/aws4_request, \
            SignedHeaders=host;x-amz-archive-description;x-amz-content-sha256;x-amz-date;x-amz-glacier-version;x-amz-sha256-tree-hash, \
            Signature=040b2a2842acd4467953f58c43b12a3639e4af0eeeedddf5bb26d654ef1b05bc"
        );
    }

    #[test]
    fn test_build_request_2() {
        let secret_key = String::from("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
        let timestamp = Utc.with_ymd_and_hms(2012, 5, 25, 0, 24, 53).unwrap();
        let region = String::from("us-east-1");
        let key_id = String::from("AKIAIOSFODNN7EXAMPLE");
        let data_string = String::from("");
        let headers: HashMap<String, String> = HashMap::new();
        let req = build_request(
            &Config {
                region,
                secret_key,
                key_id,
            },
            &Method::PUT,
            "glacier",
            headers,
            "/-/vaults/examplevault",
            &HashMap::new(),
            data_string.into_bytes(),
            false,
            &timestamp,
        )
        .unwrap();

        assert_eq!(req.method(), "PUT");
        assert_eq!(
            req.uri(),
            "https://glacier.us-east-1.amazonaws.com/-/vaults/examplevault"
        );
        let headers = req.headers();
        assert_eq!(headers.len(), 5);
        assert_eq!(
            headers.get("authorization").unwrap(),
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20120525/us-east-1/glacier/aws4_request, \
            SignedHeaders=host;x-amz-date;x-amz-glacier-version, \
            Signature=3ce5b2f2fffac9262b4da9256f8d086b4aaf42eba5f111c21681a65a127b7c2a"
        );
    }
}
