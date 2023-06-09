use actix_web::{web, HttpResponse};
use actix_web_flash_messages::FlashMessage;
use sqlx::PgPool;

use crate::{
    authentication::{validate_credentials, AuthError, Credentials, UserId},
    domain::Password,
    routes::admin::dashboard::get_username,
    utils::{e500, see_other},
};
#[derive(serde::Deserialize)]
pub struct FormData {
    current_password: Password,
    new_password: Password,
    new_password_check: Password,
}

pub async fn change_password(
    web::Form(form): web::Form<FormData>,
    pool: web::Data<PgPool>,
    user_id: web::ReqData<UserId>,
) -> Result<HttpResponse, actix_web::Error> {
    let user_id = user_id.into_inner();

    if form.new_password.expose() != form.new_password_check.expose() {
        FlashMessage::error(
            "You entered two different new passwords - the field values must match.",
        )
        .send();
        return Ok(see_other("/admin/password"));
    };

    let username = get_username(*user_id, &pool).await.map_err(e500)?;

    let credentials = Credentials {
        username,
        password: form.current_password,
    };

    if let Err(e) = validate_credentials(credentials, &pool).await {
        return match e {
            AuthError::InvalidCredentials(_) => {
                FlashMessage::error("The current password is incorrect.").send();
                Ok(see_other("/admin/password"))
            }
            AuthError::UnexpectedError(_) => Err(e500(e)),
        };
    };

    crate::authentication::change_password(*user_id, form.new_password, &pool)
        .await
        .map_err(e500)?;
    FlashMessage::error("Your password has been changed.").send();
    Ok(see_other("/admin/password"))
}
