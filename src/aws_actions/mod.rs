use chrono::{DateTime, Utc};
use hyper::{
    header::{InvalidHeaderValue, ToStrError},
    http::{HeaderName, HeaderValue},
    Request,
};
use ring::{digest, hmac};
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
    #[error("header list not found")]
    MissingHeaderList,
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

fn create_string_to_sign(
    canonical_request: &impl AsRef<str>,
    timestamp: &DateTime<Utc>,
    region: &impl AsRef<str>,
) -> Result<String, AwsActionsError> {
    Ok(format!(
        "AWS4-HMAC-SHA256\n\
        {}\n\
        {}/{}/glacier/aws4_request\n\
        {}",
        timestamp.format("%Y%m%dT%H%M%SZ"),
        timestamp.format("%Y%m%d"),
        region.as_ref(),
        digest_hex(canonical_request.as_ref().as_bytes())
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
pub fn sign_request(
    req: &mut Request<impl AsRef<[u8]>>,
    region: &impl AsRef<str>,
    secret_key: &impl AsRef<str>,
    key_id: &impl AsRef<str>,
    timestamp: &DateTime<Utc>,
) -> Result<(), AwsActionsError> {
    fix_request(req, timestamp)?;

    let canonical_request = canonize_request(req)?;
    let string_to_sign =
        create_string_to_sign(&canonical_request.as_str(), timestamp, &region.as_ref())?;
    let signature = create_signature(secret_key, timestamp, region, string_to_sign)?;
    let headers = req.headers_mut();

    headers.insert(
        "Authorization",
        HeaderValue::from_str(
            format!(
                "AWS4-HMAC-SHA256 Credential={}/{}/{}/glacier/aws4_request, \
            SignedHeaders={}, \
            Signature={}",
                key_id.as_ref(),
                timestamp.format("%Y%m%d"),
                region.as_ref(),
                canonical_request
                    .split('\n')
                    .into_iter()
                    .nth(7)
                    .ok_or(AwsActionsError::MissingHeaderList)?,
                signature
            )
            .as_str(),
        )?,
    );

    Ok(())
}

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
            digest_hex(&[]),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
    }

    #[test]
    fn test_signing() {
        // Example taken from https://docs.aws.amazon.com/amazonglacier/latest/dev/amazon-glacier-signing-requests.html
        let mut req = Request::builder()
            .method("PUT")
            .uri("https://glacier.us-east-1.amazonaws.com/-/vaults/examplevault")
            .header("x-amz-glacier-version", "2012-06-01")
            .header("Date", "Fri, 25 May 2012 00:24:53 GMT")
            .body("")
            .unwrap();

        sign_request(
            &mut req,
            &"us-east-1",
            &"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            &"AKIAIOSFODNN7EXAMPLE",
            &Utc.with_ymd_and_hms(2012, 5, 25, 0, 24, 53).unwrap(),
        )
        .unwrap();

        assert_eq!(
            req.headers().get("Authorization").unwrap(),
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20120525/us-east-1/glacier/aws4_request, \
            SignedHeaders=host;x-amz-date;x-amz-glacier-version, \
            Signature=3ce5b2f2fffac9262b4da9256f8d086b4aaf42eba5f111c21681a65a127b7c2a"
        )
    }

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

    #[test]
    fn test_string_to_sign() {
        let canonical_request = "PUT\n\
        /-/vaults/examplevault\n\
        \n\
        host:glacier.us-east-1.amazonaws.com\n\
        x-amz-date:20120525T002453Z\n\
        x-amz-glacier-version:2012-06-01\n\
        \n\
        host;x-amz-date;x-amz-glacier-version\n\
        e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let timestamp = Utc.with_ymd_and_hms(2012, 5, 25, 0, 24, 53).unwrap();
        let region = "us-east-1";

        assert_eq!(
            create_string_to_sign(&canonical_request, &timestamp, &region).unwrap(),
            "AWS4-HMAC-SHA256\n\
            20120525T002453Z\n\
            20120525/us-east-1/glacier/aws4_request\n\
            5f1da1a2d0feb614dd03d71e87928b8e449ac87614479332aced3a701f916743"
        );
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
}
