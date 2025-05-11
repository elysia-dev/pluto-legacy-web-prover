use std::str;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Response {
    code: String,
    data: Vec<Payment>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Payment {
    order_id: String,
    amount: String,
    currency: String,
    payer_info: PayerInfo,
    receiver_info: ReceiverInfo,
    _other: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PayerInfo {
  name: Option<String>,
  binance_id: Option<u64>,
  _other: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReceiverInfo {
  binance_id: u64,
  _other: Option<serde_json::Value>,
}



// Checks if there is a valid Binance payment history for a specific from and receiver_id pair in the HTTP response body.
/// We use this because complex logic cannot be included in the JSON extractor.
///
/// # Arguments
///
/// * `http_body` - API response body (Vec<u8>)
/// * `from_binance_id` - Payer from_binance_id to check
/// * `receiver_id` - Receiver ID to check
///
/// # Returns
///
/// * `Result<bool, String>` - Ok(true) if valid payment history exists, Ok(false) if not, Err on error
pub fn has_valid_payment_history(
    http_body: &[u8],
    from_binance_id: String,
    amount: String,
    currency: String,
    receiver_binance_id: String,
) -> Result<bool, String> {
    // Convert byte array to string
    let body_str = match str::from_utf8(http_body) {
        Ok(s) => s,
        Err(e) => return Err(format!("UTF-8 conversion error: {}", e)),
    };

    let response: Response = match serde_json::from_str(body_str) {
      Ok(resp) => resp,
      Err(e) => {
          println!("Failed to parse response: {}", e);
          return Err(format!("Failed to parse response: {}", e));
      }
  };

  if response.code != "000000" {
      println!("Invalid response code: {}", response.code);
      return Err(format!("Invalid response code: {}", response.code));
  }

  if response.data.is_empty() {
      println!("No payment data found");
      return Err(format!("No payment data found"));
  }

  // Find any transaction that matches our criteria
  for payment in response.data {

    let payer_binance_id_from_json = payment.payer_info.binance_id.unwrap_or(0).to_string();

    if payer_binance_id_from_json != from_binance_id {
      continue
    }
    // TODO: check already used payment

    println!("payment.payer_info: {:?}", payment.payer_info);
    println!("payment.receiver_info: {:?}", payment.receiver_info);
    let receiver_binance_id_from_json = payment.receiver_info.binance_id.to_string();
    let amount_from_json = payment.amount;
    let currency_from_json = payment.currency;

    println!("payer_binance_id_from_json: {:?}", payer_binance_id_from_json);
    println!("from_binance_id: {:?}", from_binance_id);
    println!("receiver_binance_id_from_json: {:?}", receiver_binance_id_from_json);
    println!("receiver_binance_id: {:?}", receiver_binance_id);
    println!("currency_from_json: {:?}", currency_from_json);
    println!("currency: {:?}", currency);

    // !NOTE: skip amount check: for demo
    // amount_from_json == amount
    if  payer_binance_id_from_json == from_binance_id && receiver_binance_id_from_json == receiver_binance_id && currency_from_json == currency {
        return Ok(true);
    }
  }

  // No matching payment history found
  Ok(false)
}
