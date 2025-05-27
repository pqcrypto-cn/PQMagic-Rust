use super::r#trait::{
    Kem, KemParams, KemAlgorithm, 
    MlkemMode, AigisEncMode, KyberMode,
};
use crate::error::{Result, PqmagicError};
use crate::bindings;

macro_rules! impl_kem_algorithm {
    (
        $struct_name:ident,
        $mode_type:ty,
        $keypair_match:expr,
        $encaps_match:expr,
        $decaps_match:expr
    ) => {
        pub struct $struct_name {
            mode: $mode_type,
            params: KemParams,
        }

        impl $struct_name {
            pub fn new(mode: $mode_type) -> Self {
                let params = mode.params();
                Self { mode, params }
            }
        }

        impl KemAlgorithm for $struct_name {
            fn name(&self) -> &'static str {
                self.mode.name()
            }

            fn params(&self) -> &KemParams {
                &self.params
            }
        }

        impl Kem for $struct_name {
            fn keypair(&self) -> Result<(Vec<u8>, Vec<u8>)> {
                let mut pk = vec![0u8; self.params.pk_len];
                let mut sk = vec![0u8; self.params.sk_len];

                let ret = unsafe { ($keypair_match)(self.mode, pk.as_mut_ptr(), sk.as_mut_ptr()) };
                match ret {
                    0 => Ok((pk, sk)),
                    code => Err(PqmagicError::Keygen(code)),
                }
            }

            fn encaps(&self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
                if pk.len() != self.params.pk_len {
                    return Err(PqmagicError::BufferLength { 
                        expected: self.params.pk_len, 
                        actual: pk.len() 
                    });
                }

                let mut ct = vec![0u8; self.params.ct_len];
                let mut ss = vec![0u8; 32];

                let ret = unsafe {
                    ($encaps_match)(
                        self.mode, 
                        ct.as_mut_ptr(),
                        ss.as_mut_ptr(),
                        pk.as_ptr()
                    )
                };

                match ret {
                    0 => Ok((ct, ss)),
                    code => Err(PqmagicError::Encapsulation(code)),
                }
            }

            fn decaps(&self, ct: &[u8], sk: &[u8]) -> Result<Vec<u8>> {
                if sk.len() != self.params.sk_len {
                    return Err(PqmagicError::BufferLength { 
                        expected: self.params.sk_len, 
                        actual: sk.len() 
                    });
                }
                if ct.len() != self.params.ct_len {
                    return Err(PqmagicError::BufferLength { 
                        expected: self.params.ct_len, 
                        actual: ct.len() 
                    });
                }

                let mut ss = vec![0u8; 32];

                let ret = unsafe {
                    ($decaps_match)(
                        self.mode, 
                        ss.as_mut_ptr(),
                        ct.as_ptr(),
                        sk.as_ptr()
                    )
                };

                match ret {
                    0 => Ok(ss),
                    code => Err(PqmagicError::Decapsulation(code)),
                }
            }
        }
    };
}

// ML-KEM impl
impl_kem_algorithm!(
    MlKem,
    MlkemMode,
    |mode, pk, sk| match mode {
        MlkemMode::MLKEM512 => bindings::pqmagic_ml_kem_512_std_keypair(pk, sk),
        MlkemMode::MLKEM768 => bindings::pqmagic_ml_kem_768_std_keypair(pk, sk),
        MlkemMode::MLKEM1024 => bindings::pqmagic_ml_kem_1024_std_keypair(pk, sk),
    },
    |mode, ct, ss, pk| match mode {
        MlkemMode::MLKEM512  => bindings::pqmagic_ml_kem_512_std_enc(ct, ss, pk),
        MlkemMode::MLKEM768  => bindings::pqmagic_ml_kem_768_std_enc(ct, ss, pk),
        MlkemMode::MLKEM1024 => bindings::pqmagic_ml_kem_1024_std_enc(ct, ss, pk),
    },
    |mode, ss, ct, sk| match mode {
        MlkemMode::MLKEM512  => bindings::pqmagic_ml_kem_512_std_dec(ss, ct, sk),
        MlkemMode::MLKEM768  => bindings::pqmagic_ml_kem_768_std_dec(ss, ct, sk),
        MlkemMode::MLKEM1024 => bindings::pqmagic_ml_kem_1024_std_dec(ss, ct, sk),
    }
);

// Aigis-enc impl
impl_kem_algorithm!(
    AigisEnc,
    AigisEncMode,
    |mode, pk, sk| match mode {
        AigisEncMode::AIGISENC1 => bindings::pqmagic_aigis_enc_1_std_keypair(pk, sk),
        AigisEncMode::AIGISENC2 => bindings::pqmagic_aigis_enc_2_std_keypair(pk, sk),
        AigisEncMode::AIGISENC3 => bindings::pqmagic_aigis_enc_3_std_keypair(pk, sk),
        AigisEncMode::AIGISENC4 => bindings::pqmagic_aigis_enc_4_std_keypair(pk, sk),
    },
    |mode, ct, ss, pk| match mode {
        AigisEncMode::AIGISENC1 => bindings::pqmagic_aigis_enc_1_std_enc(ct, ss, pk),
        AigisEncMode::AIGISENC2 => bindings::pqmagic_aigis_enc_2_std_enc(ct, ss, pk),
        AigisEncMode::AIGISENC3 => bindings::pqmagic_aigis_enc_3_std_enc(ct, ss, pk),
        AigisEncMode::AIGISENC4 => bindings::pqmagic_aigis_enc_4_std_enc(ct, ss, pk),
    },
    |mode, ss, ct, sk| match mode {
        AigisEncMode::AIGISENC1 => bindings::pqmagic_aigis_enc_1_std_dec(ss, ct, sk),
        AigisEncMode::AIGISENC2 => bindings::pqmagic_aigis_enc_2_std_dec(ss, ct, sk),
        AigisEncMode::AIGISENC3 => bindings::pqmagic_aigis_enc_3_std_dec(ss, ct, sk),
        AigisEncMode::AIGISENC4 => bindings::pqmagic_aigis_enc_4_std_dec(ss, ct, sk),
    }
);

// Kyber impl
impl_kem_algorithm!(
    Kyber,
    KyberMode,
    |mode, pk, sk| match mode {
        KyberMode::KYBER512  => bindings::pqmagic_kyber512_std_keypair(pk, sk),
        KyberMode::KYBER768  => bindings::pqmagic_kyber768_std_keypair(pk, sk),
        KyberMode::KYBER1024 => bindings::pqmagic_kyber1024_std_keypair(pk, sk),
    },
    |mode, ct, ss, pk| match mode {
        KyberMode::KYBER512  => bindings::pqmagic_kyber512_std_enc(ct, ss, pk),
        KyberMode::KYBER768  => bindings::pqmagic_kyber768_std_enc(ct, ss, pk),
        KyberMode::KYBER1024 => bindings::pqmagic_kyber1024_std_enc(ct, ss, pk),
    },
    |mode, ss, ct, sk| match mode {
        KyberMode::KYBER512  => bindings::pqmagic_kyber512_std_dec(ss, ct, sk),
        KyberMode::KYBER768  => bindings::pqmagic_kyber768_std_dec(ss, ct, sk),
        KyberMode::KYBER1024 => bindings::pqmagic_kyber1024_std_dec(ss, ct, sk),
    }
);






