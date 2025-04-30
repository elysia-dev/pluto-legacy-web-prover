use dotenv::dotenv;
use hmac::{Hmac, Mac};
use reqwest::header::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::env;
use std::error::Error;
use url::form_urlencoded;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Serialize, Deserialize)]
struct PaymentTransaction {
    uid: Option<i64>,
    #[serde(rename = "orderId")]
    order_id: Option<String>,
    #[serde(rename = "transactionId")]
    transaction_id: Option<String>,
    #[serde(rename = "transactionTime")]
    transaction_time: Option<i64>,
    amount: Option<String>,
    currency: Option<String>,
    #[serde(rename = "orderType")]
    order_type: Option<String>,
    note: Option<String>,
    #[serde(rename = "walletType")]
    wallet_type: Option<i32>,
    #[serde(rename = "walletTypes")]
    wallet_types: Option<Vec<String>>,
    #[serde(rename = "totalPaymentFee")]
    total_payment_fee: Option<String>,
    #[serde(rename = "counterpartyId")]
    counterparty_id: Option<i64>,
    #[serde(rename = "payerInfo")]
    payer_info: Option<HashMap<String, serde_json::Value>>,
    #[serde(rename = "receiverInfo")]
    receiver_info: Option<HashMap<String, serde_json::Value>>,
    #[serde(rename = "fundsDetail")]
    funds_detail: Option<Vec<HashMap<String, serde_json::Value>>>,
    #[serde(flatten)]
    extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct BinanceApiResponse<T> {
    code: Option<String>,
    message: Option<String>,
    data: Option<Vec<T>>,
    success: Option<bool>,
    #[serde(flatten)]
    extra: HashMap<String, serde_json::Value>,
}

async fn generate_signature(query_string: &str, api_secret: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(api_secret.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(query_string.as_bytes());
    let result = mac.finalize();
    let code_bytes = result.into_bytes();
    hex::encode(code_bytes)
}

async fn make_request(
    endpoint: &str,
    query_params: &HashMap<String, String>,
    api_key: &str,
    api_secret: &str,
) -> Result<Vec<PaymentTransaction>, Box<dyn Error>> {
    let base_url = "https://api.binance.com";
    
    // Build query string
    let mut pairs = form_urlencoded::Serializer::new(String::new());
    for (key, value) in query_params {
        pairs.append_pair(key, value);
    }
    let query_string = pairs.finish();
    
    // Generate signature
    let signature = generate_signature(&query_string, api_secret).await;
    
    // Create final URL
    let url = format!("{}{}?{}&signature={}", base_url, endpoint, query_string, signature);
    
    // Set up headers
    let mut headers = HeaderMap::new();
    headers.insert("X-MBX-APIKEY", HeaderValue::from_str(api_key)?);
    
    // Make the request
    let client = reqwest::Client::new();

    // print curl url
    println!("curl -X GET \"{}\" -H \"X-MBX-APIKEY: {}\"", url, api_key);

    let response = client
        .get(&url)
        .headers(headers)
        .send()
        .await?;
    
    // Check for errors
    if !response.status().is_success() {
        let error_message = response.text().await?;
        println!("Error from API: {}", error_message);
        return Ok(vec![]);
    }
    
    // Print raw response for debugging
    let response_text = response.text().await?;
    // println!("Raw API response: {}", response_text);
    
    // Parse the response
    let response: BinanceApiResponse<PaymentTransaction> = serde_json::from_str(&response_text)?;
    
    // Return the data or empty vector
    Ok(response.data.unwrap_or_default())
}

async fn get_all_transaction_history() -> Result<(), Box<dyn Error>> {
    // Load environment variables
    dotenv().ok();
    
    let api_key = env::var("BINANCE_API_KEY").expect("API_KEY not found in environment");
    let api_secret = env::var("BINANCE_SECRET").expect("SECRET not found in environment");
    
    let payment_endpoint = "/sapi/v1/pay/transactions";
    let timestamp = chrono::Utc::now().timestamp_millis().to_string();
    let recv_window = "60000"; // Increased to allow for multiple API calls
    
    let mut params = HashMap::new();
    params.insert("timestamp".to_string(), timestamp);
    params.insert("recvWindow".to_string(), recv_window.to_string());
    
    
    match make_request(payment_endpoint, &params, &api_key, &api_secret).await {
        Ok(payments) => {
            // println!("Payment details: {}", serde_json::to_string_pretty(&payments)?);
            println!("Success");


        }
        Err(e) => {
            println!("Failed to get transaction history: {}", e);
        }
    }
    
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    get_all_transaction_history().await
} 