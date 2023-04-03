use chrono::{DateTime, Utc};
use hyper::{
    header::{InvalidHeaderValue, ToStrError},
    http::{HeaderName, HeaderValue},
    Request,
};
use ring::digest;
use std::collections::HashMap;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum AwsActionsError {
    #[error("could not convert header value")]
    HeaderValueConversion(#[from] ToStrError),
    #[error("header {0} not found")]
    MissingHeader(String),
    #[error("invalid header value")]
    InvalidHeaderValue(#[from] InvalidHeaderValue),
}

fn digest_hex<T: AsRef<[u8]>>(data: T) -> String {
    hex::encode(digest::digest(&digest::SHA256, data.as_ref()).as_ref())
}

fn convert_header(
    header_name: &HeaderName,
    header_value: &HeaderValue,
) -> Result<(String, String), AwsActionsError> {
    Ok((
        header_name.to_string().trim().to_lowercase(),
        header_value.to_str()?.trim().to_owned(),
    ))
}

fn canonize_request<T: AsRef<[u8]>>(req: &Request<T>) -> Result<String, AwsActionsError> {
    let query = req.uri().query().unwrap_or("");

    if !req.headers().contains_key("Host") {
        Err(AwsActionsError::MissingHeader(String::from("Host")))?
    }

    if !req.headers().contains_key("x-amz-date") {
        Err(AwsActionsError::MissingHeader(String::from("x-amz-date")))?
    }

    let headers: HashMap<String, String> = req
        .headers()
        .iter()
        .filter_map(|(header_name, header_value)| {
            match header_name.as_str() == "host" || header_name.as_str().starts_with("x-amz-") {
                true => Some(convert_header(header_name, header_value)),
                false => None,
            }
        })
        .collect::<Result<Vec<(String, String)>, AwsActionsError>>()?
        .into_iter()
        .collect();

    let mut keys: Vec<String> = headers.keys().cloned().collect();

    keys.sort();

    Ok(format!(
        "{method}\n{uri}\n{query}\n{headers}\n\n{header_list}\n{payload_hash}",
        method = req.method(),
        uri = req.uri().path(),
        query = query,
        headers = keys
            .iter()
            .map(|k| {
                let v = headers
                    .get(k)
                    .ok_or_else(|| AwsActionsError::MissingHeader(k.to_owned()))?;
                Ok(format!("{}:{}", k, v))
            })
            .collect::<Result<Vec<String>, AwsActionsError>>()?
            .join("\n"),
        header_list = keys.join(";"),
        payload_hash = digest_hex(req.body())
    ))
}

/// https://docs.aws.amazon.com/amazonglacier/latest/dev/api-common-request-headers.html
fn fix_request<T>(req: &mut Request<T>, timestamp: &DateTime<Utc>) -> Result<(), AwsActionsError> {
    let host = req
        .uri()
        .host()
        .ok_or_else(|| AwsActionsError::MissingHeader("host".to_string()))?
        .to_owned();
    let headers = req.headers_mut();

    headers.insert("Host", HeaderValue::from_str(&host)?);
    headers.insert(
        "x-amz-date",
        HeaderValue::from_str(&timestamp.format("%Y%m%dT%H%M%SZ").to_string())?,
    );

    Ok(())
}

/// https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html
/// https://docs.aws.amazon.com/amazonglacier/latest/dev/amazon-glacier-signing-requests.html
pub fn sign_request<T: AsRef<[u8]>>(req: &mut Request<T>) -> Result<(), AwsActionsError> {
    let timestamp = Utc::now();

    fix_request(req, &timestamp)?;

    let canonical_string = canonize_request(req);

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_digest_hex() {
        assert_eq!(
            digest_hex(&[]),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
    }

    // #[test]
    // fn test_signing() {
    //     assert_eq!(sign_request(), ())
    // }

    #[test]
    fn test_canonization() {
        // Example taken from: https://docs.aws.amazon.com/amazonglacier/latest/dev/amazon-glacier-signing-requests.html
        // PUT /-/vaults/examplevault HTTP/1.1
        // Host: glacier.us-east-1.amazonaws.com
        // Date: Fri, 25 May 2012 00:24:53 GMT
        // Authorization: SignatureToBeCalculated
        // x-amz-glacier-version: 2012-06-01
        let mut req = Request::builder()
            .method("PUT")
            .uri("https://glacier.us-east-1.amazonaws.com/-/vaults/examplevault")
            .header("x-amz-glacier-version", "2012-06-01")
            .header("Date", "Fri, 25 May 2012 00:24:53 GMT")
            .body("")
            .unwrap();

        fix_request(
            &mut req,
            &Utc.with_ymd_and_hms(2012, 5, 25, 0, 24, 53).unwrap(),
        )
        .unwrap();

        assert_eq!(
            canonize_request(&req).unwrap(),
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
    }
}
