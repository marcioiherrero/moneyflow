use std::time::SystemTime;

use actix_web::{HttpResponse, Responder, post, web};
use jsonwebtoken::{EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{AppState, db};

#[derive(Deserialize, Debug)]
pub struct SignUpRequest {
  pub email: String,
  pub password: String,
  pub firstname: String,
  pub lastname: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Claims {
  pub sub: i64,
  pub role: String,
  pub exp: u64,
}

#[post("/auth/sign-up")]
pub async fn sign_up(
  state: web::Data<AppState>, data: web::Json<SignUpRequest>,
) -> impl Responder {
  let db = state.db.lock().await;
  
  if db::user::has_with_email(&db, &data.email).await {
    return HttpResponse::UnprocessableEntity().json(json!({
      "status": "error",
      "message": "Email already exists."
    }));
  }
  
  db::user::create(&db, &data).await;
  
  HttpResponse::Created().json(json!({
    "status": "success",
    "message": "Account created successfully."
  }))
}

#[derive(Deserialize, Debug)]
pub struct SignInRequest {
  pub email: String,
  pub password: String,
}

#[post("/auth/sign-in")]
pub async fn sign_in(
  state: web::Data<AppState>,
  data: web::Json<SignInRequest>) -> impl Responder
{
  let db = state.db.lock().await;
  
  let Some(user) = db::user::get_by_email(&db, &data.email).await else {
    // este bloco só executa caso não retorna 'Some(user)', ou seja, 'None'
    return HttpResponse::Unauthorized().json(json!(
      {
        "status": "error",
        "message": "Invalid email or password."
      }
    ));
  };
  
  if !bcrypt::verify(&data.password, &user.password).unwrap() {
    return HttpResponse::Unauthorized().json(json!(
      {
        "status": "error",
        "message": "Invalid email or password."
      }
    ));
  }
  
  let claims = Claims {
    sub: user.id, // Armazenando o id do usuário no campo 'sub' do token.
    role: "user".to_string(),
    exp: SystemTime::now()
      .duration_since(SystemTime::UNIX_EPOCH)
      .unwrap()
      .as_secs() * 4 * 60 * 60,
  };
  
  let token = jsonwebtoken::encode(
    &Header::default(),
    &claims,
    &EncodingKey::from_secret(state.jwt_secret.as_bytes()),
  ).unwrap();
  
  HttpResponse::Ok().json(json!(
    {
      "status": "success",
      "token": token
    }
  ))
  
}
