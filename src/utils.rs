use crate::PqmagicSig;
use crate::sig::*;
use crate::kem::*;
use rand::Rng;


pub fn sig_instances() -> Vec<Box<dyn Sig>> {
    vec![
        (Box::new(PqmagicSig::new("ML_DSA_44").unwrap())),
        (Box::new(PqmagicSig::new("ML_DSA_65").unwrap())),
        (Box::new(PqmagicSig::new("ML_DSA_87").unwrap())),

        (Box::new(PqmagicSig::new("AIGIS_SIG_1").unwrap())),
        (Box::new(PqmagicSig::new("AIGIS_SIG_2").unwrap())),
        (Box::new(PqmagicSig::new("AIGIS_SIG_3").unwrap())),

        (Box::new(PqmagicSig::new("DILITHIUM_2").unwrap())),
        (Box::new(PqmagicSig::new("DILITHIUM_3").unwrap())),
        (Box::new(PqmagicSig::new("DILITHIUM_5").unwrap())),

        (Box::new(PqmagicSig::new("SLH_DSA_SHA2_128_F" ).unwrap())),
        (Box::new(PqmagicSig::new("SLH_DSA_SHA2_128_S" ).unwrap())),
        (Box::new(PqmagicSig::new("SLH_DSA_SHA2_192_F" ).unwrap())),
        (Box::new(PqmagicSig::new("SLH_DSA_SHA2_192_S" ).unwrap())),
        (Box::new(PqmagicSig::new("SLH_DSA_SHA2_256_F" ).unwrap())),
        (Box::new(PqmagicSig::new("SLH_DSA_SHA2_256_S" ).unwrap())),

        (Box::new(PqmagicSig::new("SLH_DSA_SHAKE_128_F").unwrap())),
        (Box::new(PqmagicSig::new("SLH_DSA_SHAKE_128_S").unwrap())),
        (Box::new(PqmagicSig::new("SLH_DSA_SHAKE_192_F").unwrap())),
        (Box::new(PqmagicSig::new("SLH_DSA_SHAKE_192_S").unwrap())),
        (Box::new(PqmagicSig::new("SLH_DSA_SHAKE_256_F").unwrap())),
        (Box::new(PqmagicSig::new("SLH_DSA_SHAKE_256_S").unwrap())),

        (Box::new(PqmagicSig::new("SLH_DSA_SM3_128_F"  ).unwrap())),
        (Box::new(PqmagicSig::new("SLH_DSA_SM3_128_S"  ).unwrap())),

        (Box::new(PqmagicSig::new("SPHINCS_A_SHA2_128_F" ).unwrap())),
        (Box::new(PqmagicSig::new("SPHINCS_A_SHA2_128_S" ).unwrap())),
        (Box::new(PqmagicSig::new("SPHINCS_A_SHA2_192_F" ).unwrap())),
        (Box::new(PqmagicSig::new("SPHINCS_A_SHA2_192_S" ).unwrap())),
        (Box::new(PqmagicSig::new("SPHINCS_A_SHA2_256_F" ).unwrap())),
        (Box::new(PqmagicSig::new("SPHINCS_A_SHA2_256_S" ).unwrap())),

        (Box::new(PqmagicSig::new("SPHINCS_A_SHAKE_128_F").unwrap())),
        (Box::new(PqmagicSig::new("SPHINCS_A_SHAKE_128_S").unwrap())),
        (Box::new(PqmagicSig::new("SPHINCS_A_SHAKE_192_F").unwrap())),
        (Box::new(PqmagicSig::new("SPHINCS_A_SHAKE_192_S").unwrap())),
        (Box::new(PqmagicSig::new("SPHINCS_A_SHAKE_256_F").unwrap())),
        (Box::new(PqmagicSig::new("SPHINCS_A_SHAKE_256_S").unwrap())),

        (Box::new(PqmagicSig::new("SPHINCS_A_SM3_128_F" ).unwrap())),
        (Box::new(PqmagicSig::new("SPHINCS_A_SM3_128_S" ).unwrap())),
        
    ]
}

pub fn kem_instances() -> Vec<Box<dyn Kem>> {
    vec![
        (Box::new(PqmagicKem::new("ML_KEM_512").unwrap())),
        (Box::new(PqmagicKem::new("ML_KEM_768").unwrap())),
        (Box::new(PqmagicKem::new("ML_KEM_1024").unwrap())),

        (Box::new(PqmagicKem::new("AIGIS_ENC_1").unwrap())),
        (Box::new(PqmagicKem::new("AIGIS_ENC_2").unwrap())),
        (Box::new(PqmagicKem::new("AIGIS_ENC_3").unwrap())),
        (Box::new(PqmagicKem::new("AIGIS_ENC_4").unwrap())),

        (Box::new(PqmagicKem::new("KYBER_512").unwrap())),
        (Box::new(PqmagicKem::new("KYBER_768").unwrap())),
        (Box::new(PqmagicKem::new("KYBER_1024").unwrap())),
    ]
}

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut rng = rand::rng();
    (0..len).map(|_| rng.random()).collect()
}

pub fn test_context() -> Option<Vec<u8>> {
    Some(b"PQCRYPTO_TEST_CONTEXT".to_vec())
}

pub fn test_message() -> Vec<u8> {
    let mut rng = rand::rng();
    (0..1024).map(|_| rng.random()).collect()
}


