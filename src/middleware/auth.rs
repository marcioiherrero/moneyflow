use actix_web::{Error, HttpMessage, body::BoxBody,
  dev::{ServiceRequest, ServiceResponse},
  error::ErrorUnauthorized, middleware::Next, web};
use jsonwebtoken::{DecodingKey, Validation, decode};
use serde_json::json;

use crate::{AppState, controllers::auth::Claims};

pub async fn verify_jwt(
  req: ServiceRequest,
  next: Next<BoxBody>) -> Result<ServiceResponse, Error>
{
  let auth_header = req.headers().get("Authorization").ok_or_else(|| {
    ErrorUnauthorized(json!(
      {
        "status": "error",
        "message": "Authorization header is missing"
      }))
  })?;
  
  let auth_str = auth_header.to_str().map_err(|_| {
    ErrorUnauthorized(json!(
      {
        "status": "error",
        "message": "Authorization header is missing"
      }))
  })?;
  
  if !auth_str.starts_with("Bearer ") {
    return Err(
      ErrorUnauthorized(json!(
        {
          "status": "error",
          "message": "Authorization header is missing"
        }))
    );
  }
  
  let token = auth_str.strip_prefix("Bearer ").unwrap();
  
  let state = req.app_data::<web::Data<AppState>>().unwrap();
  
  let key = DecodingKey::from_secret(state.jwt_secret.as_bytes());
  
  // O método '.extensions()' permite acessar um armazenamento associado à requisição,
  // no qual middlewares e outras partes da aplicação podem guardar dados temporários
  // para que outras partes do processamento os recuperem.
  // 
  // No exemplo abaixo, nas extensões desta requisição irá armazenar o campo 'claims.sub'
  // do token que contém o ID do usuário.
  
  match decode::<Claims>(token, &key, &Validation::default()) {
    Ok(token_data) => {
      req.extensions_mut().insert(token_data.claims.sub);
      next.call(req).await
    },
    Err(_) => Err(ErrorUnauthorized(json!(
      {
        "status": "error",
        "message": "Invalid token"
      }
    ))),
  }
}
