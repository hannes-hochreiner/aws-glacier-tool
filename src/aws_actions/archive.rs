use super::{check_response, get_header_value, AwsActionsError, Config};
use crate::aws_actions::request;
use hyper::{Method, StatusCode};
use serde::Serialize;
use std::{collections::HashMap, time::Duration};
use tokio::{
    fs::{self, File},
    io::{AsyncReadExt, AsyncSeekExt},
};

#[derive(Debug, Serialize)]
pub struct ArchiveUploadInformation {
    tree_hash: String,
    location: String,
    archive_id: String,
}

#[derive(Debug, PartialEq)]
struct Part {
    offset: u64,
    tries: usize,
    part_size: u64,
    vault_name: String,
    upload_id: String,
    filename: String,
}

enum WorkerRequest {
    Upload { config: Config, part: Part },
    End,
}

enum WorkerResponse {
    Idle,
    Done {
        part: Part,
        result: Result<Vec<u8>, AwsActionsError>,
    },
}

// https://docs.aws.amazon.com/amazonglacier/latest/dev/uploading-archive-mpu.html
fn calculate_minimum_part_size(file_size: u64) -> u64 {
    (file_size / 10485760000).next_power_of_two() * 1048576
}

fn generate_part_list(
    file_size: u64,
    part_size: u64,
    vault: &str,
    upload_id: &str,
    filename: &str,
) -> Vec<Part> {
    let mut offset = 0;
    let mut parts = Vec::new();

    while offset < file_size {
        parts.push(Part {
            offset,
            tries: 0,
            filename: filename.to_owned(),
            part_size,
            upload_id: upload_id.to_owned(),
            vault_name: vault.to_owned(),
        });

        offset += part_size;
    }

    parts
}

// https://docs.aws.amazon.com/amazonglacier/latest/dev/uploading-an-archive.html
pub async fn upload_file(
    config: &Config,
    filename: &str,
    vault: &str,
    archive_description: &str,
) -> Result<ArchiveUploadInformation, AwsActionsError> {
    log::debug!("uploading \"{filename}\"");

    // get file size
    let file_size = fs::metadata(filename).await?.len();

    log::debug!("file size: {file_size}");

    // check that the file size is not larger than the maximum (40_000 GiB)
    if file_size > 42_949_672_960_000 {
        return Err(AwsActionsError::FileTooLarge);
    }

    // calculate part size
    let part_size = calculate_minimum_part_size(file_size);

    log::debug!("part size: {part_size}");

    // initiate multipart upload
    check_7bit_ascii_without_control(archive_description)?;

    let mut resp = tokio::time::timeout(
        Duration::from_secs(1),
        request(
            config,
            &Method::POST,
            "glacier",
            HashMap::from([
                (
                    "x-amz-archive-description".into(),
                    archive_description.into(),
                ),
                ("x-amz-part-size".into(), format!("{part_size}")),
            ]),
            &format!("/-/vaults/{vault}/multipart-uploads"),
            &HashMap::new(),
            Vec::new(),
            false,
        )?,
    )
    .await??;

    check_response(&mut resp, StatusCode::CREATED).await?;

    log::debug!("request to initiate multipart upload succeeded");

    let request_id = get_header_value(&resp, "x-amzn-requestid")?;
    let location = get_header_value(&resp, "location")?;
    let upload_id = get_header_value(&resp, "x-amz-multipart-upload-id")?;

    log::info!("multipart upload: request id: \"{request_id}\", location: \"{location}\", upload_id: \"{upload_id}\"");

    // upload parts
    let mut new_parts = generate_part_list(file_size, part_size, vault, &upload_id, filename);
    let part_cnt = new_parts.len();
    let mut completed_parts: Vec<(Part, Vec<u8>)> = Vec::new();
    let mut tasks = Vec::new();
    let (req_s, req_r) = async_channel::unbounded::<WorkerRequest>();
    let (res_s, res_r) = async_channel::unbounded::<WorkerResponse>();

    // // create workers
    for _ in 0..5 {
        let r = req_r.clone();
        let s = res_s.clone();

        tasks.push(tokio::spawn(async move {
            if let Err(e) = s.send(WorkerResponse::Idle).await {
                log::error!("{e:?}");
                return;
            };

            loop {
                match r.recv().await {
                    Ok(msg) => match msg {
                        WorkerRequest::Upload { config, part } => {
                            if let Err(e) = {
                                let upload_res = upload_part(&config, &part).await;

                                s.send(WorkerResponse::Done {
                                    part,
                                    result: upload_res,
                                })
                                .await
                            } {
                                log::error!("{e}");
                            }
                        }
                        WorkerRequest::End => return,
                    },
                    Err(e) => {
                        log::error!("{e:?}");
                        return;
                    }
                }
            }
        }))
    }

    while completed_parts.len() != part_cnt {
        match res_r.recv().await {
            Ok(msg) => {
                if let Some(mut part) = {
                    match msg {
                        WorkerResponse::Idle => new_parts.pop(),
                        WorkerResponse::Done { part, result } => match result {
                            Ok(tree_hash) => {
                                log::debug!("upload of part succeeded: {part:?}");
                                completed_parts.push((part, tree_hash));
                                new_parts.pop()
                            }
                            Err(e) => {
                                log::warn!("uploading part failed: {e}");
                                Some(part)
                            }
                        },
                    }
                } {
                    if part.tries >= 10 {
                        return Err(AwsActionsError::MaxRetry);
                    }

                    part.tries += 1;

                    if let Err(e) = req_s
                        .send(WorkerRequest::Upload {
                            config: config.clone(),
                            part,
                        })
                        .await
                    {
                        log::error!("{e}");
                    }
                }
            }
            Err(e) => log::error!("{e}"),
        }
    }

    for _ in 0..tasks.len() {
        if let Err(e) = req_s.send(WorkerRequest::End).await {
            log::error!("{e:?}");
        }
    }

    for task in tasks {
        task.await?;
    }

    // complete multipart upload
    // https://docs.aws.amazon.com/amazonglacier/latest/dev/api-multipart-complete-upload.html
    completed_parts.sort_by(|a, b| a.0.offset.cmp(&b.0.offset));
    let archive_tree_hash_hex = hex::encode(aws_tree_hash::combine_hashes(
        completed_parts
            .iter()
            .map(|(_, tree_hash)| tree_hash.to_owned())
            .collect(),
    ));

    let mut resp = tokio::time::timeout(
        Duration::from_secs(1),
        request(
            config,
            &Method::POST,
            "glacier",
            HashMap::from([
                (
                    String::from("x-amz-sha256-tree-hash"),
                    archive_tree_hash_hex.clone(),
                ),
                (String::from("x-amz-archive-size"), format!("{file_size}")),
            ]),
            &format!("/-/vaults/{vault}/multipart-uploads/{upload_id}"),
            &HashMap::new(),
            Vec::new(),
            false,
        )?,
    )
    .await??;

    check_response(&mut resp, StatusCode::CREATED).await?;

    Ok(ArchiveUploadInformation {
        tree_hash: archive_tree_hash_hex,
        location: get_header_value(&resp, "location")?,
        archive_id: get_header_value(&resp, "x-amz-archive-id")?,
    })
}

// https://docs.aws.amazon.com/amazonglacier/latest/dev/api-upload-part.html
async fn upload_part(config: &Config, part: &Part) -> Result<Vec<u8>, AwsActionsError> {
    // read data
    let mut file = File::open(&part.filename).await?;
    let mut buffer = vec![0u8; part.part_size as usize];

    file.seek(std::io::SeekFrom::Start(part.offset)).await?;

    let len = file.read(buffer.as_mut_slice()).await?;

    buffer.truncate(len);

    // calculate tree hash
    let tree_hash = aws_tree_hash::calculate_tree_hash(buffer.as_slice());
    let tree_hash_hex = hex::encode(tree_hash.clone());

    // send request
    // set "content-range", "x-amz-sha256-tree-hash"
    let mut resp = tokio::time::timeout(
        Duration::from_secs_f64((len * 8) as f64 / (1024 * 1024) as f64),
        request(
            config,
            &Method::PUT,
            "glacier",
            HashMap::from([
                (
                    String::from("content-range"),
                    format!(
                        "bytes {start}-{end}/*",
                        start = part.offset,
                        end = part.offset + len as u64 - 1
                    ),
                ),
                (
                    String::from("x-amz-sha256-tree-hash"),
                    tree_hash_hex.clone(),
                ),
                (
                    String::from("content-type"),
                    String::from("application/octet-stream"),
                ),
            ]),
            &format!(
                "/-/vaults/{vault}/multipart-uploads/{upload_id}",
                vault = part.vault_name,
                upload_id = part.upload_id
            ),
            &HashMap::new(),
            buffer,
            true,
        )?,
    )
    .await??;

    // check response
    check_response(&mut resp, StatusCode::NO_CONTENT).await?;

    if tree_hash_hex != get_header_value(&resp, "x-amz-sha256-tree-hash")? {
        return Err(AwsActionsError::CheckSumError);
    }

    Ok(tree_hash)
}

// check whether the description only has characters in the range of 32-126 (7-bit ASCII without control codes)
fn check_7bit_ascii_without_control(str: &str) -> Result<(), AwsActionsError> {
    str.chars().try_for_each(|c| {
        let c_digit = c as u32;

        // allowed range 32-126
        match (32..=126).contains(&c_digit) {
            true => Ok(()),
            false => Err(AwsActionsError::CharError {
                string: str.to_owned(),
                char: c,
            }),
        }
    })
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_calculate_minimum_part_size_100_gib() {
        assert_eq!(
            calculate_minimum_part_size(100 * 1024 * 1024 * 1024),
            16 * 1024 * 1024
        )
    }

    #[test]
    fn test_calculate_minimum_part_size_100_mib() {
        assert_eq!(
            calculate_minimum_part_size(100 * 1024 * 1024),
            1 * 1024 * 1024
        )
    }

    #[test]
    fn test_calculate_minimum_part_size_exact() {
        assert_eq!(
            calculate_minimum_part_size(20000 * 1024 * 1024),
            2 * 1024 * 1024
        )
    }

    #[test]
    fn test_calculate_minimum_part_size_max() {
        assert_eq!(
            calculate_minimum_part_size(10000 * 1024 * 1024 * 1024 * 4),
            4 * 1024 * 1024 * 1024
        )
    }

    #[test]
    fn test_generate_part_list() {
        assert_eq!(
            generate_part_list(3, 1, "vault_name", "upload_id", "filename"),
            vec![
                Part {
                    offset: 0,
                    tries: 0,
                    vault_name: String::from("vault_name"),
                    filename: String::from("filename"),
                    upload_id: String::from("upload_id"),
                    part_size: 1
                },
                Part {
                    offset: 1,
                    tries: 0,
                    vault_name: String::from("vault_name"),
                    filename: String::from("filename"),
                    upload_id: String::from("upload_id"),
                    part_size: 1
                },
                Part {
                    offset: 2,
                    tries: 0,
                    vault_name: String::from("vault_name"),
                    filename: String::from("filename"),
                    upload_id: String::from("upload_id"),
                    part_size: 1
                }
            ]
        );
    }

    #[test]
    fn test_check_7bit_ascii_without_control_ok() {
        assert!(check_7bit_ascii_without_control("this is a test !%#@}~|").is_ok());
    }

    #[test]
    fn test_check_7bit_ascii_without_control_error() {
        assert!(check_7bit_ascii_without_control("this is a test\n").is_err());
    }
}
