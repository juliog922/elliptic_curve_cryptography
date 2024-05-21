pub use num_bigint::{
    BigUint,
    RandBigInt
};
pub use rand::{
    self,
    Rng
};
pub use sha256::{
    digest,
    try_digest,
};
pub use ec_generic::{
    EllipticCurve,
    FiniteField,
    Point
};

pub struct ECDSA {
    pub elliptic_curve: EllipticCurve,
    pub a_gen: Point,
    pub q_order: BigUint,
}

#[derive(Debug)]
pub enum ECDSAErrors {
    BadArgument(String),
    OperationFailure(String),
}

impl ECDSA {
    // Generates: d, B where B = d A
    pub fn generate_key_pair(&self) -> Result<(BigUint, Point), ECDSAErrors> {
        let priv_key = self.generate_priv_key();
        let pub_key = self.generate_pub_key(&priv_key)?;
        Ok((priv_key, pub_key))
    }

    pub fn generate_priv_key(&self) -> BigUint {
        self.generate_random_positive_number_less_than(&self.q_order)
    }

    pub fn generate_pub_key(&self, priv_key: &BigUint) -> Result<Point, ECDSAErrors> {
        self.elliptic_curve
            .scalar_mul(&self.a_gen, priv_key)
            .map_err(|_| ECDSAErrors::OperationFailure("Error computing priv_key * a_gen".into()))
    }

    // (0, max)
    pub fn generate_random_positive_number_less_than(&self, max: &BigUint) -> BigUint {
        let mut rng = rand::thread_rng();
        rng.gen_biguint_range(&BigUint::from(1u32), max)
    }

    ///
    /// R = k A -> take `r = x` component
    /// s = (hash(message) + d * r) * k^(-1) mod q
    ///
    pub fn sign(
        &self,
        hash: &BigUint,
        priv_key: &BigUint,
        k_random: &BigUint,
    ) -> Result<(BigUint, BigUint), ECDSAErrors> {
        if *hash >= self.q_order {
            return Err(ECDSAErrors::BadArgument(
                "Hash is bigger than the order of the EC group".into(),
            ));
        }

        if *priv_key >= self.q_order {
            return Err(ECDSAErrors::BadArgument(
                "Private key is bigger than the order of the EC group".into(),
            ));
        }

        if *k_random >= self.q_order {
            return Err(ECDSAErrors::BadArgument(
                "Random number `k` is bigger than the order of the EC group".into(),
            ));
        }

        let r_point = self
            .elliptic_curve
            .scalar_mul(&self.a_gen, k_random)
            .map_err(|_| {
                ECDSAErrors::OperationFailure("Error computing k_random * a_gen".into())
            })?;

        if let Point::Coor(r, _) = r_point {
            let s = FiniteField::mult(&r, priv_key, &self.q_order).map_err(|_| {
                ECDSAErrors::OperationFailure("Error multiplying r * priv_key".into())
            })?;

            let s = FiniteField::add(&s, hash, &self.q_order).map_err(|_| {
                ECDSAErrors::OperationFailure("Error adding hash + r * priv_key".into())
            })?;

            let k_inv = FiniteField::inv_mult_prime(k_random, &self.q_order)
                .map_err(|_| ECDSAErrors::OperationFailure("Error computing k_inv".into()))?;

            let s = FiniteField::mult(&s, &k_inv, &self.q_order).map_err(|_| {
                ECDSAErrors::OperationFailure(
                    "Error computing (hash + r * priv_key) * k_inv".into(),
                )
            })?;

            return Ok((r, s));
        }

        Err(ECDSAErrors::OperationFailure(
            "Result k_random * a_gen is the identity".into(),
        ))
    }

    ///
    /// Verifies if a signature is valid for a particular message hash and public key.
    ///
    /// (s, r) = signature
    /// u1 = s^(-1) * hash(message) mod q
    /// u2 = s^(-1) * r mod q
    /// P = u1 A + u2 B mod q = (xp, yp)
    /// if r == xp then verified!
    ///
    pub fn verify(
        &self,
        hash: &BigUint,
        pub_key: &Point,
        signature: &(BigUint, BigUint),
    ) -> Result<bool, ECDSAErrors> {
        if *hash >= self.q_order {
            return Err(ECDSAErrors::BadArgument(
                "Hash value >= q (EC group order)".to_string(),
            ));
        }

        let (r, s) = signature;

        let s_inv = FiniteField::inv_mult_prime(s, &self.q_order)
            .map_err(|_| ECDSAErrors::OperationFailure("Error computing s_inv".into()))?;

        let u1 = FiniteField::mult(&s_inv, hash, &self.q_order).map_err(|_| {
            ECDSAErrors::OperationFailure("Error multiplying s_inv and hash".into())
        })?;

        let u2 = FiniteField::mult(&s_inv, r, &self.q_order)
            .map_err(|_| ECDSAErrors::OperationFailure("Error multiplying s_inv and r".into()))?;

        let u1a = self
            .elliptic_curve
            .scalar_mul(&self.a_gen, &u1)
            .map_err(|_| ECDSAErrors::OperationFailure("Error in u1 * a_gen".into()))?;

        let u2b = self
            .elliptic_curve
            .scalar_mul(pub_key, &u2)
            .map_err(|_| ECDSAErrors::OperationFailure("Error in u2 * pub_key".into()))?;

        let p = self
            .elliptic_curve
            .add(&u1a, &u2b)
            .map_err(|_| ECDSAErrors::OperationFailure("Error in u1a + u2b".into()))?;

        if let Point::Coor(xp, _) = p {
            return Ok(xp == *r);
        }

        Err(ECDSAErrors::OperationFailure(
            "Result is the identity".into(),
        ))
    }

    /// 0 < hash < max
    pub fn generate_hash_less_than(&self, message: &str, max: &BigUint) -> BigUint {
        let digest = digest(message);
        let hash_bytes = hex::decode(digest).expect("Could not convert hash to Vec<u8>");
        let hash = BigUint::from_bytes_be(&hash_bytes);
        let hash = hash.modpow(&BigUint::from(1u32), &(max - BigUint::from(1u32)));
        hash + BigUint::from(1u32)
    }
}

