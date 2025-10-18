use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "status", content = "payload", rename_all = "lowercase")]
pub enum RunResponse {
    #[serde(rename = "in_progress")]
    InProgress,
    #[serde(rename = "success")]
    Success { gas_usage: u32 },
    #[serde(rename = "failed")]
    Failed { message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "status", content = "payload", rename_all = "lowercase")]
pub enum DecryptResponse {
    #[serde(rename = "in_progress")]
    InProgress,
    #[serde(rename = "success")]
    Success { value: Vec<u64> },
    #[serde(rename = "failed")]
    Failed { message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessCheckResponse {
    pub signature: String,
    pub ciphertext_id: String,
    pub bit_size: u8,
}
