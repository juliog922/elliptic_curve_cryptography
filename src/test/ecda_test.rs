use crate::ecda::*;

#[test]
fn test_sign_verify() {
    let elliptic_curve = EllipticCurve {
        a: BigUint::from(2u32),
        b: BigUint::from(2u32),
        p: BigUint::from(17u32),
    };

    let a_gen = Point::Coor(BigUint::from(5u32), BigUint::from(1u32));

    let q_order = BigUint::from(19u32);

    let ecdsa = ECDSA {
        elliptic_curve,
        a_gen,
        q_order,
    };

    let priv_key = BigUint::from(7u32);
    let pub_key = ecdsa
        .generate_pub_key(&priv_key)
        .expect("Could not compute PubKey");

    let k_random = BigUint::from(18u32);

    let message = "Bob -> 1 BTC -> Alice";
    let hash = ecdsa.generate_hash_less_than(message, &ecdsa.q_order);

    let signature = ecdsa
        .sign(&hash, &priv_key, &k_random)
        .expect("Could not sign");

    let verify_result = ecdsa
        .verify(&hash, &pub_key, &signature)
        .expect("Could not verify");

    assert!(verify_result, "Verification should success");
}
#[test]
fn test_secp256_sign_verify() {
    let p = BigUint::parse_bytes(
        b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
        16,
    )
    .expect("could not convert p");

    let q_order = BigUint::parse_bytes(
        b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        16,
    )
    .expect("could not convert n");

    let gx = BigUint::parse_bytes(
        b"79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
        16,
    )
    .expect("could not convert gx");

    let gy = BigUint::parse_bytes(
        b"483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
        16,
    )
    .expect("could not convert gy");

    let elliptic_curve = EllipticCurve {
        a: BigUint::from(0u32),
        b: BigUint::from(7u32),
        p,
    };

    let a_gen = Point::Coor(gx, gy);

    let ecdsa = ECDSA {
        elliptic_curve,
        a_gen,
        q_order,
    };

    let priv_key = BigUint::parse_bytes(
        b"483ADB7726A3C4655DA4FBFC0E1208A8F017B448A68554199C47D08FFB10E4B9",
        16,
    )
    .expect("Could not convert hex to private key");

    let pub_key = ecdsa
        .generate_pub_key(&priv_key)
        .expect("Could not compute PubKey");

    let k_random = BigUint::parse_bytes(
        b"19BE666EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B15E81798",
        16,
    )
    .expect("Could not convert hex to private key");

    let message = "Bob -> 1 BTC -> Alice";
    let hash = ecdsa.generate_hash_less_than(message, &ecdsa.q_order);

    let signature = ecdsa
        .sign(&hash, &priv_key, &k_random)
        .expect("Could not sign");

    let verify_result = ecdsa
        .verify(&hash, &pub_key, &signature)
        .expect("Could not verify");

    assert!(verify_result, "Verification should have succeed");
}

#[test]
fn test_secp256_sign_verify_tempered_message() {
    let p = BigUint::parse_bytes(
        b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
        16,
    )
    .expect("could not convert p");

    let q_order = BigUint::parse_bytes(
        b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        16,
    )
    .expect("could not convert n");

    let gx = BigUint::parse_bytes(
        b"79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
        16,
    )
    .expect("could not convert gx");

    let gy = BigUint::parse_bytes(
        b"483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
        16,
    )
    .expect("could not convert gy");

    let elliptic_curve = EllipticCurve {
        a: BigUint::from(0u32),
        b: BigUint::from(7u32),
        p,
    };

    let a_gen = Point::Coor(gx, gy);

    let ecdsa = ECDSA {
        elliptic_curve,
        a_gen,
        q_order,
    };

    let priv_key = BigUint::parse_bytes(
        b"483ADB7726A3C4655DA4FBFC0E1208A8F017B448A68554199C47D08FFB10E4B9",
        16,
    )
    .expect("Could not convert hex to private key");

    let pub_key = ecdsa
        .generate_pub_key(&priv_key)
        .expect("Could not compute PubKey");

    let k_random = BigUint::parse_bytes(
        b"19BE666EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B15E81798",
        16,
    )
    .expect("Could not convert hex to private key");

    let message = "Bob -> 1 BTC -> Alice";
    let hash = ecdsa.generate_hash_less_than(message, &ecdsa.q_order);

    let signature = ecdsa
        .sign(&hash, &priv_key, &k_random)
        .expect("Could not sign");

    let message = "Bob -> 2 BTC -> Alice";
    let hash = ecdsa.generate_hash_less_than(message, &ecdsa.q_order);

    let verify_result = ecdsa
        .verify(&hash, &pub_key, &signature)
        .expect("Could not verify");

    assert!(
        !verify_result,
        "Verification should have failed due to tempered message"
    );
}

#[test]
fn test_secp256_sign_verify_tempered_signature() {
    let p = BigUint::parse_bytes(
        b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
        16,
    )
    .expect("could not convert p");

    let q_order = BigUint::parse_bytes(
        b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        16,
    )
    .expect("could not convert n");

    let gx = BigUint::parse_bytes(
        b"79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
        16,
    )
    .expect("could not convert gx");

    let gy = BigUint::parse_bytes(
        b"483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
        16,
    )
    .expect("could not convert gy");

    let elliptic_curve = EllipticCurve {
        a: BigUint::from(0u32),
        b: BigUint::from(7u32),
        p,
    };

    let a_gen = Point::Coor(gx, gy);

    let ecdsa = ECDSA {
        elliptic_curve,
        a_gen,
        q_order,
    };

    let priv_key = BigUint::parse_bytes(
        b"483ADB7726A3C4655DA4FBFC0E1208A8F017B448A68554199C47D08FFB10E4B9",
        16,
    )
    .expect("Could not convert hex to private key");

    let pub_key = ecdsa
        .generate_pub_key(&priv_key)
        .expect("Could not compute PubKey");

    let k_random = BigUint::parse_bytes(
        b"19BE666EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B15E81798",
        16,
    )
    .expect("Could not convert hex to private key");

    let message = "Bob -> 1 BTC -> Alice";
    let hash = ecdsa.generate_hash_less_than(message, &ecdsa.q_order);

    let signature = ecdsa
        .sign(&hash, &priv_key, &k_random)
        .expect("Could not sign");
    let (r, s) = signature;

    let tempered_signature = (
        (r + BigUint::from(1u32)).modpow(&BigUint::from(1u32), &ecdsa.q_order),
        s,
    );

    let verify_result = ecdsa
        .verify(&hash, &pub_key, &tempered_signature)
        .expect("Could not verify");

    assert!(
        !verify_result,
        "Verification should have failed due to tempered signature"
    );
}
