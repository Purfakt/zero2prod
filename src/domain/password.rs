use secrecy::{ExposeSecret, Secret};

#[derive(Debug, serde::Deserialize)]
pub struct Password(Secret<String>);

impl Password {
    pub fn parse(password: String) -> Result<Password, String> {
        let password_length = password.len();
        match password_length {
            0..=11 => Err("Password must be at least 12 characters long.".into()),
            12..=128 => Ok(Self(Secret::new(password))),
            _ => Err("Password must be at most 128 characters long.".into()),
        }
    }

    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }
}

impl AsRef<Secret<String>> for Password {
    fn as_ref(&self) -> &Secret<String> {
        &self.0
    }
}

impl std::fmt::Display for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        "redacted".to_string().fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::Password;
    use claims::assert_err;
    use fake::Fake;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[derive(Debug, Clone)]
    struct ValidPasswordFixture(pub String);

    impl quickcheck::Arbitrary for ValidPasswordFixture {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            let mut rng = StdRng::seed_from_u64(u64::arbitrary(g));
            let password = fake::faker::internet::en::Password(12..128).fake_with_rng(&mut rng);

            Self(password)
        }
    }

    #[quickcheck_macros::quickcheck]
    fn valid_passwords_are_parsed_successfully(valid_password: ValidPasswordFixture) -> bool {
        Password::parse(valid_password.0).is_ok()
    }

    #[test]
    fn empty_string_is_rejected() {
        let password = "".to_string();
        assert_err!(Password::parse(password));
    }

    #[test]
    fn long_string_is_rejected() {
        let password = "fdjskfdsajof98324123jh4r79pn3uyb41q$97846y23174Y1732$Rejadur2184yklfhd9789fy9a36y412hjq43khjr9as87fuvyn923qy45123q9n4yopinf689ase6yf783y14n78n460798qpfyoisdanfH".to_string();
        assert_err!(Password::parse(password));
    }
}
