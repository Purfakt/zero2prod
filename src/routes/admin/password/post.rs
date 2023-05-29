use actix_web::{web, HttpResponse};
use secrecy::Secret;

use crate::{
    session_state::TypedSession,
    utils::{e500, see_other},
};
#[derive(serde::Deserialize)]

pub struct FormData {
    _current_password: Secret<String>,
    _new_password: Secret<String>,
    _new_password_check: Secret<String>,
}

pub async fn change_password(
    _form: web::Form<FormData>,
    session: TypedSession,
) -> Result<HttpResponse, actix_web::Error> {
    if session.get_user_id().map_err(e500)?.is_none() {
        return Ok(see_other("/login"));
    };
    todo!()
}
