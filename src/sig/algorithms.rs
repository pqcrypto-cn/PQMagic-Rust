use super::r#trait::{
    Sig, SigParams, SigAlgorithm, 
    MldsaMode, AigisSigMode, DilithiumMode,
    SlhdsaMode, SphincsAMode
};
use crate::error::{Result, PqmagicError};
use crate::bindings;

macro_rules! impl_sign_algorithm {
    (
        $struct_name:ident,
        $mode_type:ty,
        $keypair_match:expr,
        $signature_match:expr,
        $verify_match:expr,
        $sign_msg_match:expr,
        $open_msg_match:expr
    ) => {
        pub struct $struct_name {
            mode: $mode_type,
            params: SigParams,
        }

        impl $struct_name {
            pub fn new(mode: $mode_type) -> Self {
                let params = mode.params();
                Self { mode, params }
            }
        }

        impl SigAlgorithm for $struct_name {
            fn name(&self) -> &'static str {
                self.mode.name()
            }

            fn params(&self) -> &SigParams {
                &self.params
            }
        }

        impl Sig for $struct_name {
            fn keypair(&self) -> Result<(Vec<u8>, Vec<u8>)> {
                let mut pk = vec![0u8; self.params.pk_len];
                let mut sk = vec![0u8; self.params.sk_len];

                let ret = unsafe { ($keypair_match)(self.mode, pk.as_mut_ptr(), sk.as_mut_ptr()) };
                match ret {
                    0 => Ok((pk, sk)),
                    code => Err(PqmagicError::Keygen(code)),
                }
            }

            fn sign(&self, msg: &[u8], ctx: Option<&[u8]>, sk: &[u8]) -> Result<Vec<u8>> {
                if sk.len() != self.params.sk_len {
                    return Err(PqmagicError::BufferLength { expected: self.params.sk_len, actual: sk.len() });
                }

                let mut sig = vec![0u8; self.params.sig_len];
                let mut sig_len = 0;
                let (ctx_ptr, ctx_len) = ctx.map_or((std::ptr::null(), 0), |c| (c.as_ptr(), c.len()));

                let ret = unsafe {
                    ($signature_match)(
                        self.mode,
                        sig.as_mut_ptr(),
                        &mut sig_len,
                        msg.as_ptr(),
                        msg.len(),
                        ctx_ptr,
                        ctx_len,
                        sk.as_ptr(),
                    )
                };

                match ret {
                    0 => {
                        sig.truncate(sig_len);
                        Ok(sig)
                    },
                    code => Err(PqmagicError::Signing(code)),
                }
            }

            fn verify(&self, sig: &[u8], msg: &[u8], ctx: Option<&[u8]>, pk: &[u8]) -> Result<bool> {
                if pk.len() != self.params.pk_len {
                    return Err(PqmagicError::BufferLength { expected: self.params.pk_len, actual: pk.len() });
                }

                let (ctx_ptr, ctx_len) = ctx.map_or((std::ptr::null(), 0), |c| (c.as_ptr(), c.len()));
                let ret = unsafe {
                    ($verify_match)(
                        self.mode,
                        sig.as_ptr(),
                        sig.len(),
                        msg.as_ptr(),
                        msg.len(),
                        ctx_ptr,
                        ctx_len,
                        pk.as_ptr(),
                    )
                };

                match ret {
                    0 => Ok(true),
                    -1 => Ok(false),
                    code => Err(PqmagicError::Verification(code)),
                }
            }

            fn sign_message(&self, msg: &[u8], ctx: Option<&[u8]>, sk: &[u8]) -> Result<Vec<u8>> {
                if sk.len() != self.params.sk_len {
                    return Err(PqmagicError::BufferLength { expected: self.params.sk_len, actual: sk.len() });
                }

                let mut signed_msg = vec![0u8; self.params.sig_len + msg.len()];
                let mut sig_len = 0;
                let (ctx_ptr, ctx_len) = ctx.map_or((std::ptr::null(), 0), |c| (c.as_ptr(), c.len()));

                let ret = unsafe {
                    ($sign_msg_match)(
                        self.mode,
                        signed_msg.as_mut_ptr(),
                        &mut sig_len,
                        msg.as_ptr(),
                        msg.len(),
                        ctx_ptr,
                        ctx_len,
                        sk.as_ptr(),
                    )
                };

                match ret {
                    0 => {
                        signed_msg.truncate(sig_len);
                        Ok(signed_msg)
                    },
                    code => Err(PqmagicError::SignMessage(code)),
                }
            }

            fn open_signed_message(&self, signed_msg: &[u8], ctx: Option<&[u8]>, pk: &[u8]) -> Result<Vec<u8>> {
                let mut msg = vec![0u8; signed_msg.len()];
                let mut msg_len = 0;
                let (ctx_ptr, ctx_len) = ctx.map_or((std::ptr::null(), 0), |c| (c.as_ptr(), c.len()));

                let ret = unsafe {
                    ($open_msg_match)(
                        self.mode,
                        msg.as_mut_ptr(),
                        &mut msg_len,
                        signed_msg.as_ptr(),
                        signed_msg.len(),
                        ctx_ptr,
                        ctx_len,
                        pk.as_ptr(),
                    )
                };

                match ret {
                    0 => {
                        msg.truncate(msg_len);
                        Ok(msg)
                    },
                    code => Err(PqmagicError::VerifyMessage(code)),
                }
            }
        }
    };
}

// ML-DSA 
impl_sign_algorithm!(
    MlDsa,
    MldsaMode,
    |mode, pk, sk| match mode {
        MldsaMode::MLDSA44 => bindings::pqmagic_ml_dsa_44_std_keypair(pk, sk),
        MldsaMode::MLDSA65 => bindings::pqmagic_ml_dsa_65_std_keypair(pk, sk),
        MldsaMode::MLDSA87 => bindings::pqmagic_ml_dsa_87_std_keypair(pk, sk),
    },
    |mode, sig, sig_len, msg, msg_len, ctx, ctx_len, sk| match mode {
        MldsaMode::MLDSA44 => bindings::pqmagic_ml_dsa_44_std_signature(sig, sig_len, msg, msg_len, ctx, ctx_len, sk),
        MldsaMode::MLDSA65 => bindings::pqmagic_ml_dsa_65_std_signature(sig, sig_len, msg, msg_len, ctx, ctx_len, sk),
        MldsaMode::MLDSA87 => bindings::pqmagic_ml_dsa_87_std_signature(sig, sig_len, msg, msg_len, ctx, ctx_len, sk),
    },
    |mode, sig, sig_len, msg, msg_len, ctx, ctx_len, pk| match mode {
        MldsaMode::MLDSA44 => bindings::pqmagic_ml_dsa_44_std_verify(sig, sig_len, msg, msg_len, ctx, ctx_len, pk),
        MldsaMode::MLDSA65 => bindings::pqmagic_ml_dsa_65_std_verify(sig, sig_len, msg, msg_len, ctx, ctx_len, pk),
        MldsaMode::MLDSA87 => bindings::pqmagic_ml_dsa_87_std_verify(sig, sig_len, msg, msg_len, ctx, ctx_len, pk),
    },
    |mode, signed_msg, sig_len, msg, msg_len, ctx, ctx_len, sk| match mode {
        MldsaMode::MLDSA44 => bindings::pqmagic_ml_dsa_44_std(signed_msg, sig_len, msg, msg_len, ctx, ctx_len, sk),
        MldsaMode::MLDSA65 => bindings::pqmagic_ml_dsa_65_std(signed_msg, sig_len, msg, msg_len, ctx, ctx_len, sk),
        MldsaMode::MLDSA87 => bindings::pqmagic_ml_dsa_87_std(signed_msg, sig_len, msg, msg_len, ctx, ctx_len, sk),
    },
    |mode, msg, msg_len, signed_msg, signed_msg_len, ctx, ctx_len, pk| match mode {
        MldsaMode::MLDSA44 => bindings::pqmagic_ml_dsa_44_std_open(msg, msg_len, signed_msg, signed_msg_len, ctx, ctx_len, pk),
        MldsaMode::MLDSA65 => bindings::pqmagic_ml_dsa_65_std_open(msg, msg_len, signed_msg, signed_msg_len, ctx, ctx_len, pk),
        MldsaMode::MLDSA87 => bindings::pqmagic_ml_dsa_87_std_open(msg, msg_len, signed_msg, signed_msg_len, ctx, ctx_len, pk),
    }
);

// Aigis-sig 
impl_sign_algorithm!(
    AigisSig,
    AigisSigMode,
    |mode: AigisSigMode, pk, sk| match mode {
        AigisSigMode::AIGISSIG1 => bindings::pqmagic_aigis_sig1_std_keypair(pk, sk),
        AigisSigMode::AIGISSIG2 => bindings::pqmagic_aigis_sig2_std_keypair(pk, sk),
        AigisSigMode::AIGISSIG3 => bindings::pqmagic_aigis_sig3_std_keypair(pk, sk),
    },
    |mode: AigisSigMode, sig, sig_len, msg, msg_len, ctx, ctx_len, sk| match mode {
        AigisSigMode::AIGISSIG1 => bindings::pqmagic_aigis_sig1_std_signature(sig, sig_len, msg, msg_len, ctx, ctx_len, sk),
        AigisSigMode::AIGISSIG2 => bindings::pqmagic_aigis_sig2_std_signature(sig, sig_len, msg, msg_len, ctx, ctx_len, sk),
        AigisSigMode::AIGISSIG3 => bindings::pqmagic_aigis_sig3_std_signature(sig, sig_len, msg, msg_len, ctx, ctx_len, sk),
    },
    |mode: AigisSigMode, sig, sig_len, msg, msg_len, ctx, ctx_len, pk| match mode {
        AigisSigMode::AIGISSIG1 => bindings::pqmagic_aigis_sig1_std_verify(sig, sig_len, msg, msg_len, ctx, ctx_len, pk),
        AigisSigMode::AIGISSIG2 => bindings::pqmagic_aigis_sig2_std_verify(sig, sig_len, msg, msg_len, ctx, ctx_len, pk),
        AigisSigMode::AIGISSIG3 => bindings::pqmagic_aigis_sig3_std_verify(sig, sig_len, msg, msg_len, ctx, ctx_len, pk),
    },
    |mode: AigisSigMode, signed_msg, sig_len, msg, msg_len, ctx, ctx_len, sk| match mode {
        AigisSigMode::AIGISSIG1 => bindings::pqmagic_aigis_sig1_std(signed_msg, sig_len, msg, msg_len, ctx, ctx_len, sk),
        AigisSigMode::AIGISSIG2 => bindings::pqmagic_aigis_sig2_std(signed_msg, sig_len, msg, msg_len, ctx, ctx_len, sk),
        AigisSigMode::AIGISSIG3 => bindings::pqmagic_aigis_sig3_std(signed_msg, sig_len, msg, msg_len, ctx, ctx_len, sk),
    },
    |mode: AigisSigMode, msg, msg_len, signed_msg, signed_msg_len, ctx, ctx_len, pk| match mode {
        AigisSigMode::AIGISSIG1 => bindings::pqmagic_aigis_sig1_std_open(msg, msg_len, signed_msg, signed_msg_len, ctx, ctx_len, pk),
        AigisSigMode::AIGISSIG2 => bindings::pqmagic_aigis_sig2_std_open(msg, msg_len, signed_msg, signed_msg_len, ctx, ctx_len, pk),
        AigisSigMode::AIGISSIG3 => bindings::pqmagic_aigis_sig3_std_open(msg, msg_len, signed_msg, signed_msg_len, ctx, ctx_len, pk),
    }
);

// Dilithium 
impl_sign_algorithm!(
    Dilithium,
    DilithiumMode,
    |mode, pk, sk| match mode {
        DilithiumMode::Dilithium2 => bindings::pqmagic_dilithium2_std_keypair(pk, sk),
        DilithiumMode::Dilithium3 => bindings::pqmagic_dilithium3_std_keypair(pk, sk),
        DilithiumMode::Dilithium5 => bindings::pqmagic_dilithium5_std_keypair(pk, sk),
    },
    |mode, sig, sig_len, msg, msg_len, _ctx, _ctx_len, sk| match mode {
        DilithiumMode::Dilithium2 => bindings::pqmagic_dilithium2_std_signature(sig, sig_len, msg, msg_len, sk),
        DilithiumMode::Dilithium3 => bindings::pqmagic_dilithium3_std_signature(sig, sig_len, msg, msg_len, sk),
        DilithiumMode::Dilithium5 => bindings::pqmagic_dilithium5_std_signature(sig, sig_len, msg, msg_len, sk),
    },
    |mode, sig, sig_len, msg, msg_len, _ctx, _ctx_len, pk| match mode {
        DilithiumMode::Dilithium2 => bindings::pqmagic_dilithium2_std_verify(sig, sig_len, msg, msg_len, pk),
        DilithiumMode::Dilithium3 => bindings::pqmagic_dilithium3_std_verify(sig, sig_len, msg, msg_len, pk),
        DilithiumMode::Dilithium5 => bindings::pqmagic_dilithium5_std_verify(sig, sig_len, msg, msg_len, pk),
    },
    |mode, signed_msg, sig_len, msg, msg_len, _ctx, _ctx_len, sk| match mode {
        DilithiumMode::Dilithium2 => bindings::pqmagic_dilithium2_std(signed_msg, sig_len, msg, msg_len, sk),
        DilithiumMode::Dilithium3 => bindings::pqmagic_dilithium3_std(signed_msg, sig_len, msg, msg_len, sk),
        DilithiumMode::Dilithium5 => bindings::pqmagic_dilithium5_std(signed_msg, sig_len, msg, msg_len, sk),
    },
    |mode, msg, msg_len, signed_msg, signed_msg_len, _ctx, _ctx_len, pk| match mode {
        DilithiumMode::Dilithium2 => bindings::pqmagic_dilithium2_std_open(msg, msg_len, signed_msg, signed_msg_len, pk),
        DilithiumMode::Dilithium3 => bindings::pqmagic_dilithium3_std_open(msg, msg_len, signed_msg, signed_msg_len, pk),
        DilithiumMode::Dilithium5 => bindings::pqmagic_dilithium5_std_open(msg, msg_len, signed_msg, signed_msg_len, pk),
    }
);

// Slhdsa 
impl_sign_algorithm!(
    Slhdsa,
    SlhdsaMode,
    |mode, pk, sk| match mode {
        SlhdsaMode::SlhdsaSha2_128F => bindings:: pqmagic_slh_dsa_sha2_128f_simple_std_sign_keypair(pk, sk),
        SlhdsaMode::SlhdsaSha2_128S => bindings:: pqmagic_slh_dsa_sha2_128s_simple_std_sign_keypair(pk, sk),
        SlhdsaMode::SlhdsaSha2_192F => bindings:: pqmagic_slh_dsa_sha2_192f_simple_std_sign_keypair(pk, sk),
        SlhdsaMode::SlhdsaSha2_192S => bindings:: pqmagic_slh_dsa_sha2_192s_simple_std_sign_keypair(pk, sk),
        SlhdsaMode::SlhdsaSha2_256F => bindings:: pqmagic_slh_dsa_sha2_256f_simple_std_sign_keypair(pk, sk),
        SlhdsaMode::SlhdsaSha2_256S => bindings:: pqmagic_slh_dsa_sha2_256s_simple_std_sign_keypair(pk, sk),

        SlhdsaMode::SlhdsaShake128F => bindings::pqmagic_slh_dsa_shake_128f_simple_std_sign_keypair(pk, sk),
        SlhdsaMode::SlhdsaShake128S => bindings::pqmagic_slh_dsa_shake_128s_simple_std_sign_keypair(pk, sk),
        SlhdsaMode::SlhdsaShake192F => bindings::pqmagic_slh_dsa_shake_192f_simple_std_sign_keypair(pk, sk),
        SlhdsaMode::SlhdsaShake192S => bindings::pqmagic_slh_dsa_shake_192s_simple_std_sign_keypair(pk, sk),
        SlhdsaMode::SlhdsaShake256F => bindings::pqmagic_slh_dsa_shake_256f_simple_std_sign_keypair(pk, sk),
        SlhdsaMode::SlhdsaShake256S => bindings::pqmagic_slh_dsa_shake_256s_simple_std_sign_keypair(pk, sk),

        SlhdsaMode::SlhdsaSm3_128F  => bindings::  pqmagic_slh_dsa_sm3_128f_simple_std_sign_keypair(pk, sk),
        SlhdsaMode::SlhdsaSm3_128S  => bindings::  pqmagic_slh_dsa_sm3_128s_simple_std_sign_keypair(pk, sk),
    },
    |mode, sig, sig_len, msg, msg_len, _ctx, _ctx_len, sk| match mode {
        SlhdsaMode::SlhdsaSha2_128F => bindings:: pqmagic_slh_dsa_sha2_128f_simple_std_sign_signature(sig, sig_len, msg, msg_len, sk),
        SlhdsaMode::SlhdsaSha2_128S => bindings:: pqmagic_slh_dsa_sha2_128s_simple_std_sign_signature(sig, sig_len, msg, msg_len, sk),
        SlhdsaMode::SlhdsaSha2_192F => bindings:: pqmagic_slh_dsa_sha2_192f_simple_std_sign_signature(sig, sig_len, msg, msg_len, sk),
        SlhdsaMode::SlhdsaSha2_192S => bindings:: pqmagic_slh_dsa_sha2_192s_simple_std_sign_signature(sig, sig_len, msg, msg_len, sk),
        SlhdsaMode::SlhdsaSha2_256F => bindings:: pqmagic_slh_dsa_sha2_256f_simple_std_sign_signature(sig, sig_len, msg, msg_len, sk),
        SlhdsaMode::SlhdsaSha2_256S => bindings:: pqmagic_slh_dsa_sha2_256s_simple_std_sign_signature(sig, sig_len, msg, msg_len, sk),

        SlhdsaMode::SlhdsaShake128F => bindings::pqmagic_slh_dsa_shake_128f_simple_std_sign_signature(sig, sig_len, msg, msg_len, sk),
        SlhdsaMode::SlhdsaShake128S => bindings::pqmagic_slh_dsa_shake_128s_simple_std_sign_signature(sig, sig_len, msg, msg_len, sk),
        SlhdsaMode::SlhdsaShake192F => bindings::pqmagic_slh_dsa_shake_192f_simple_std_sign_signature(sig, sig_len, msg, msg_len, sk),
        SlhdsaMode::SlhdsaShake192S => bindings::pqmagic_slh_dsa_shake_192s_simple_std_sign_signature(sig, sig_len, msg, msg_len, sk),
        SlhdsaMode::SlhdsaShake256F => bindings::pqmagic_slh_dsa_shake_256f_simple_std_sign_signature(sig, sig_len, msg, msg_len, sk),
        SlhdsaMode::SlhdsaShake256S => bindings::pqmagic_slh_dsa_shake_256s_simple_std_sign_signature(sig, sig_len, msg, msg_len, sk),

        SlhdsaMode::SlhdsaSm3_128F  => bindings::  pqmagic_slh_dsa_sm3_128f_simple_std_sign_signature(sig, sig_len, msg, msg_len, sk),
        SlhdsaMode::SlhdsaSm3_128S  => bindings::  pqmagic_slh_dsa_sm3_128s_simple_std_sign_signature(sig, sig_len, msg, msg_len, sk),
    },
    |mode, sig, sig_len, msg, msg_len, _ctx, _ctx_len, pk| match mode {
        SlhdsaMode::SlhdsaSha2_128F => bindings:: pqmagic_slh_dsa_sha2_128f_simple_std_sign_verify(sig, sig_len, msg, msg_len, pk),
        SlhdsaMode::SlhdsaSha2_128S => bindings:: pqmagic_slh_dsa_sha2_128s_simple_std_sign_verify(sig, sig_len, msg, msg_len, pk),
        SlhdsaMode::SlhdsaSha2_192F => bindings:: pqmagic_slh_dsa_sha2_192f_simple_std_sign_verify(sig, sig_len, msg, msg_len, pk),
        SlhdsaMode::SlhdsaSha2_192S => bindings:: pqmagic_slh_dsa_sha2_192s_simple_std_sign_verify(sig, sig_len, msg, msg_len, pk),
        SlhdsaMode::SlhdsaSha2_256F => bindings:: pqmagic_slh_dsa_sha2_256f_simple_std_sign_verify(sig, sig_len, msg, msg_len, pk),
        SlhdsaMode::SlhdsaSha2_256S => bindings:: pqmagic_slh_dsa_sha2_256s_simple_std_sign_verify(sig, sig_len, msg, msg_len, pk),

        SlhdsaMode::SlhdsaShake128F => bindings::pqmagic_slh_dsa_shake_128f_simple_std_sign_verify(sig, sig_len, msg, msg_len, pk),
        SlhdsaMode::SlhdsaShake128S => bindings::pqmagic_slh_dsa_shake_128s_simple_std_sign_verify(sig, sig_len, msg, msg_len, pk),
        SlhdsaMode::SlhdsaShake192F => bindings::pqmagic_slh_dsa_shake_192f_simple_std_sign_verify(sig, sig_len, msg, msg_len, pk),
        SlhdsaMode::SlhdsaShake192S => bindings::pqmagic_slh_dsa_shake_192s_simple_std_sign_verify(sig, sig_len, msg, msg_len, pk),
        SlhdsaMode::SlhdsaShake256F => bindings::pqmagic_slh_dsa_shake_256f_simple_std_sign_verify(sig, sig_len, msg, msg_len, pk),
        SlhdsaMode::SlhdsaShake256S => bindings::pqmagic_slh_dsa_shake_256s_simple_std_sign_verify(sig, sig_len, msg, msg_len, pk),

        SlhdsaMode::SlhdsaSm3_128F  => bindings::  pqmagic_slh_dsa_sm3_128f_simple_std_sign_verify(sig, sig_len, msg, msg_len, pk),
        SlhdsaMode::SlhdsaSm3_128S  => bindings::  pqmagic_slh_dsa_sm3_128s_simple_std_sign_verify(sig, sig_len, msg, msg_len, pk),
    },
    |mode, signed_msg, sig_len, msg, msg_len, _ctx, _ctx_len, sk| match mode {
        SlhdsaMode::SlhdsaSha2_128F => bindings:: pqmagic_slh_dsa_sha2_128f_simple_std_sign(signed_msg, sig_len, msg, msg_len, sk),
        SlhdsaMode::SlhdsaSha2_128S => bindings:: pqmagic_slh_dsa_sha2_128s_simple_std_sign(signed_msg, sig_len, msg, msg_len, sk),
        SlhdsaMode::SlhdsaSha2_192F => bindings:: pqmagic_slh_dsa_sha2_192f_simple_std_sign(signed_msg, sig_len, msg, msg_len, sk),
        SlhdsaMode::SlhdsaSha2_192S => bindings:: pqmagic_slh_dsa_sha2_192s_simple_std_sign(signed_msg, sig_len, msg, msg_len, sk),
        SlhdsaMode::SlhdsaSha2_256F => bindings:: pqmagic_slh_dsa_sha2_256f_simple_std_sign(signed_msg, sig_len, msg, msg_len, sk),
        SlhdsaMode::SlhdsaSha2_256S => bindings:: pqmagic_slh_dsa_sha2_256s_simple_std_sign(signed_msg, sig_len, msg, msg_len, sk),

        SlhdsaMode::SlhdsaShake128F => bindings::pqmagic_slh_dsa_shake_128f_simple_std_sign(signed_msg, sig_len, msg, msg_len, sk),
        SlhdsaMode::SlhdsaShake128S => bindings::pqmagic_slh_dsa_shake_128s_simple_std_sign(signed_msg, sig_len, msg, msg_len, sk),
        SlhdsaMode::SlhdsaShake192F => bindings::pqmagic_slh_dsa_shake_192f_simple_std_sign(signed_msg, sig_len, msg, msg_len, sk),
        SlhdsaMode::SlhdsaShake192S => bindings::pqmagic_slh_dsa_shake_192s_simple_std_sign(signed_msg, sig_len, msg, msg_len, sk),
        SlhdsaMode::SlhdsaShake256F => bindings::pqmagic_slh_dsa_shake_256f_simple_std_sign(signed_msg, sig_len, msg, msg_len, sk),
        SlhdsaMode::SlhdsaShake256S => bindings::pqmagic_slh_dsa_shake_256s_simple_std_sign(signed_msg, sig_len, msg, msg_len, sk),

        SlhdsaMode::SlhdsaSm3_128F  => bindings::  pqmagic_slh_dsa_sm3_128f_simple_std_sign(signed_msg, sig_len, msg, msg_len, sk),
        SlhdsaMode::SlhdsaSm3_128S  => bindings::  pqmagic_slh_dsa_sm3_128s_simple_std_sign(signed_msg, sig_len, msg, msg_len, sk),
    },
    |mode, msg, msg_len, signed_msg, signed_msg_len, _ctx, _ctx_len, pk| match mode {
        SlhdsaMode::SlhdsaSha2_128F => bindings:: pqmagic_slh_dsa_sha2_128f_simple_std_sign_open(msg, msg_len, signed_msg, signed_msg_len, pk),
        SlhdsaMode::SlhdsaSha2_128S => bindings:: pqmagic_slh_dsa_sha2_128s_simple_std_sign_open(msg, msg_len, signed_msg, signed_msg_len, pk),
        SlhdsaMode::SlhdsaSha2_192F => bindings:: pqmagic_slh_dsa_sha2_192f_simple_std_sign_open(msg, msg_len, signed_msg, signed_msg_len, pk),
        SlhdsaMode::SlhdsaSha2_192S => bindings:: pqmagic_slh_dsa_sha2_192s_simple_std_sign_open(msg, msg_len, signed_msg, signed_msg_len, pk),
        SlhdsaMode::SlhdsaSha2_256F => bindings:: pqmagic_slh_dsa_sha2_256f_simple_std_sign_open(msg, msg_len, signed_msg, signed_msg_len, pk),
        SlhdsaMode::SlhdsaSha2_256S => bindings:: pqmagic_slh_dsa_sha2_256s_simple_std_sign_open(msg, msg_len, signed_msg, signed_msg_len, pk),

        SlhdsaMode::SlhdsaShake128F => bindings::pqmagic_slh_dsa_shake_128f_simple_std_sign_open(msg, msg_len, signed_msg, signed_msg_len, pk),
        SlhdsaMode::SlhdsaShake128S => bindings::pqmagic_slh_dsa_shake_128s_simple_std_sign_open(msg, msg_len, signed_msg, signed_msg_len, pk),
        SlhdsaMode::SlhdsaShake192F => bindings::pqmagic_slh_dsa_shake_192f_simple_std_sign_open(msg, msg_len, signed_msg, signed_msg_len, pk),
        SlhdsaMode::SlhdsaShake192S => bindings::pqmagic_slh_dsa_shake_192s_simple_std_sign_open(msg, msg_len, signed_msg, signed_msg_len, pk),
        SlhdsaMode::SlhdsaShake256F => bindings::pqmagic_slh_dsa_shake_256f_simple_std_sign_open(msg, msg_len, signed_msg, signed_msg_len, pk),
        SlhdsaMode::SlhdsaShake256S => bindings::pqmagic_slh_dsa_shake_256s_simple_std_sign_open(msg, msg_len, signed_msg, signed_msg_len, pk),

        SlhdsaMode::SlhdsaSm3_128F  => bindings::  pqmagic_slh_dsa_sm3_128f_simple_std_sign_open(msg, msg_len, signed_msg, signed_msg_len, pk),
        SlhdsaMode::SlhdsaSm3_128S  => bindings::  pqmagic_slh_dsa_sm3_128s_simple_std_sign_open(msg, msg_len, signed_msg, signed_msg_len, pk),
    }
);

// SphincsA 
impl_sign_algorithm!(
    SphincsA,
    SphincsAMode,
    |mode, pk, sk| match mode {
        SphincsAMode::SphincsASha2_128F => bindings::pqmagic_sphincs_a_sha2_128f_simple_std_sign_keypair(pk, sk),
        SphincsAMode::SphincsASha2_128S => bindings::pqmagic_sphincs_a_sha2_128s_simple_std_sign_keypair(pk, sk),
        SphincsAMode::SphincsASha2_192F => bindings::pqmagic_sphincs_a_sha2_192f_simple_std_sign_keypair(pk, sk),
        SphincsAMode::SphincsASha2_192S => bindings::pqmagic_sphincs_a_sha2_192s_simple_std_sign_keypair(pk, sk),
        SphincsAMode::SphincsASha2_256F => bindings::pqmagic_sphincs_a_sha2_256f_simple_std_sign_keypair(pk, sk),
        SphincsAMode::SphincsASha2_256S => bindings::pqmagic_sphincs_a_sha2_256s_simple_std_sign_keypair(pk, sk),

        SphincsAMode::SphincsAShake128F => bindings::pqmagic_sphincs_a_shake_128f_simple_std_sign_keypair(pk, sk),
        SphincsAMode::SphincsAShake128S => bindings::pqmagic_sphincs_a_shake_128s_simple_std_sign_keypair(pk, sk),
        SphincsAMode::SphincsAShake192F => bindings::pqmagic_sphincs_a_shake_192f_simple_std_sign_keypair(pk, sk),
        SphincsAMode::SphincsAShake192S => bindings::pqmagic_sphincs_a_shake_192s_simple_std_sign_keypair(pk, sk),
        SphincsAMode::SphincsAShake256F => bindings::pqmagic_sphincs_a_shake_256f_simple_std_sign_keypair(pk, sk),
        SphincsAMode::SphincsAShake256S => bindings::pqmagic_sphincs_a_shake_256s_simple_std_sign_keypair(pk, sk),

        SphincsAMode::SphincsASm3_128F  => bindings::pqmagic_sphincs_a_sm3_128f_simple_std_sign_keypair(pk, sk),
        SphincsAMode::SphincsASm3_128S  => bindings::pqmagic_sphincs_a_sm3_128s_simple_std_sign_keypair(pk, sk),
    },
    |mode, sig, sig_len, msg, msg_len, _ctx, _ctx_len, sk| match mode {
        SphincsAMode::SphincsASha2_128F => bindings::pqmagic_sphincs_a_sha2_128f_simple_std_sign_signature(sig, sig_len, msg, msg_len, sk),
        SphincsAMode::SphincsASha2_128S => bindings::pqmagic_sphincs_a_sha2_128s_simple_std_sign_signature(sig, sig_len, msg, msg_len, sk),
        SphincsAMode::SphincsASha2_192F => bindings::pqmagic_sphincs_a_sha2_192f_simple_std_sign_signature(sig, sig_len, msg, msg_len, sk),
        SphincsAMode::SphincsASha2_192S => bindings::pqmagic_sphincs_a_sha2_192s_simple_std_sign_signature(sig, sig_len, msg, msg_len, sk),
        SphincsAMode::SphincsASha2_256F => bindings::pqmagic_sphincs_a_sha2_256f_simple_std_sign_signature(sig, sig_len, msg, msg_len, sk),
        SphincsAMode::SphincsASha2_256S => bindings::pqmagic_sphincs_a_sha2_256s_simple_std_sign_signature(sig, sig_len, msg, msg_len, sk),

        SphincsAMode::SphincsAShake128F => bindings::pqmagic_sphincs_a_shake_128f_simple_std_sign_signature(sig, sig_len, msg, msg_len, sk),
        SphincsAMode::SphincsAShake128S => bindings::pqmagic_sphincs_a_shake_128s_simple_std_sign_signature(sig, sig_len, msg, msg_len, sk),
        SphincsAMode::SphincsAShake192F => bindings::pqmagic_sphincs_a_shake_192f_simple_std_sign_signature(sig, sig_len, msg, msg_len, sk),
        SphincsAMode::SphincsAShake192S => bindings::pqmagic_sphincs_a_shake_192s_simple_std_sign_signature(sig, sig_len, msg, msg_len, sk),
        SphincsAMode::SphincsAShake256F => bindings::pqmagic_sphincs_a_shake_256f_simple_std_sign_signature(sig, sig_len, msg, msg_len, sk),
        SphincsAMode::SphincsAShake256S => bindings::pqmagic_sphincs_a_shake_256s_simple_std_sign_signature(sig, sig_len, msg, msg_len, sk),

        SphincsAMode::SphincsASm3_128F  => bindings::pqmagic_sphincs_a_sm3_128f_simple_std_sign_signature(sig, sig_len, msg, msg_len, sk),
        SphincsAMode::SphincsASm3_128S  => bindings::pqmagic_sphincs_a_sm3_128s_simple_std_sign_signature(sig, sig_len, msg, msg_len, sk),
    },
    |mode, sig, sig_len, msg, msg_len, _ctx, _ctx_len, pk| match mode {
        SphincsAMode::SphincsASha2_128F => bindings::pqmagic_sphincs_a_sha2_128f_simple_std_sign_verify(sig, sig_len, msg, msg_len, pk),
        SphincsAMode::SphincsASha2_128S => bindings::pqmagic_sphincs_a_sha2_128s_simple_std_sign_verify(sig, sig_len, msg, msg_len, pk),
        SphincsAMode::SphincsASha2_192F => bindings::pqmagic_sphincs_a_sha2_192f_simple_std_sign_verify(sig, sig_len, msg, msg_len, pk),
        SphincsAMode::SphincsASha2_192S => bindings::pqmagic_sphincs_a_sha2_192s_simple_std_sign_verify(sig, sig_len, msg, msg_len, pk),
        SphincsAMode::SphincsASha2_256F => bindings::pqmagic_sphincs_a_sha2_256f_simple_std_sign_verify(sig, sig_len, msg, msg_len, pk),
        SphincsAMode::SphincsASha2_256S => bindings::pqmagic_sphincs_a_sha2_256s_simple_std_sign_verify(sig, sig_len, msg, msg_len, pk),

        SphincsAMode::SphincsAShake128F => bindings::pqmagic_sphincs_a_shake_128f_simple_std_sign_verify(sig, sig_len, msg, msg_len, pk),
        SphincsAMode::SphincsAShake128S => bindings::pqmagic_sphincs_a_shake_128s_simple_std_sign_verify(sig, sig_len, msg, msg_len, pk),
        SphincsAMode::SphincsAShake192F => bindings::pqmagic_sphincs_a_shake_192f_simple_std_sign_verify(sig, sig_len, msg, msg_len, pk),
        SphincsAMode::SphincsAShake192S => bindings::pqmagic_sphincs_a_shake_192s_simple_std_sign_verify(sig, sig_len, msg, msg_len, pk),
        SphincsAMode::SphincsAShake256F => bindings::pqmagic_sphincs_a_shake_256f_simple_std_sign_verify(sig, sig_len, msg, msg_len, pk),
        SphincsAMode::SphincsAShake256S => bindings::pqmagic_sphincs_a_shake_256s_simple_std_sign_verify(sig, sig_len, msg, msg_len, pk),

        SphincsAMode::SphincsASm3_128F  => bindings::pqmagic_sphincs_a_sm3_128f_simple_std_sign_verify(sig, sig_len, msg, msg_len, pk),
        SphincsAMode::SphincsASm3_128S  => bindings::pqmagic_sphincs_a_sm3_128s_simple_std_sign_verify(sig, sig_len, msg, msg_len, pk),
    },
    |mode, signed_msg, sig_len, msg, msg_len, _ctx, _ctx_len, sk| match mode {
        SphincsAMode::SphincsASha2_128F => bindings::pqmagic_sphincs_a_sha2_128f_simple_std_sign(signed_msg, sig_len, msg, msg_len, sk),
        SphincsAMode::SphincsASha2_128S => bindings::pqmagic_sphincs_a_sha2_128s_simple_std_sign(signed_msg, sig_len, msg, msg_len, sk),
        SphincsAMode::SphincsASha2_192F => bindings::pqmagic_sphincs_a_sha2_192f_simple_std_sign(signed_msg, sig_len, msg, msg_len, sk),
        SphincsAMode::SphincsASha2_192S => bindings::pqmagic_sphincs_a_sha2_192s_simple_std_sign(signed_msg, sig_len, msg, msg_len, sk),
        SphincsAMode::SphincsASha2_256F => bindings::pqmagic_sphincs_a_sha2_256f_simple_std_sign(signed_msg, sig_len, msg, msg_len, sk),
        SphincsAMode::SphincsASha2_256S => bindings::pqmagic_sphincs_a_sha2_256s_simple_std_sign(signed_msg, sig_len, msg, msg_len, sk),

        SphincsAMode::SphincsAShake128F => bindings::pqmagic_sphincs_a_shake_128f_simple_std_sign(signed_msg, sig_len, msg, msg_len, sk),
        SphincsAMode::SphincsAShake128S => bindings::pqmagic_sphincs_a_shake_128s_simple_std_sign(signed_msg, sig_len, msg, msg_len, sk),
        SphincsAMode::SphincsAShake192F => bindings::pqmagic_sphincs_a_shake_192f_simple_std_sign(signed_msg, sig_len, msg, msg_len, sk),
        SphincsAMode::SphincsAShake192S => bindings::pqmagic_sphincs_a_shake_192s_simple_std_sign(signed_msg, sig_len, msg, msg_len, sk),
        SphincsAMode::SphincsAShake256F => bindings::pqmagic_sphincs_a_shake_256f_simple_std_sign(signed_msg, sig_len, msg, msg_len, sk),
        SphincsAMode::SphincsAShake256S => bindings::pqmagic_sphincs_a_shake_256s_simple_std_sign(signed_msg, sig_len, msg, msg_len, sk),

        SphincsAMode::SphincsASm3_128F  => bindings::pqmagic_sphincs_a_sm3_128f_simple_std_sign(signed_msg, sig_len, msg, msg_len, sk),
        SphincsAMode::SphincsASm3_128S  => bindings::pqmagic_sphincs_a_sm3_128s_simple_std_sign(signed_msg, sig_len, msg, msg_len, sk),
    },
    |mode, msg, msg_len, signed_msg, signed_msg_len, _ctx, _ctx_len, pk| match mode {
        SphincsAMode::SphincsASha2_128F => bindings::pqmagic_sphincs_a_sha2_128f_simple_std_sign_open(msg, msg_len, signed_msg, signed_msg_len, pk),
        SphincsAMode::SphincsASha2_128S => bindings::pqmagic_sphincs_a_sha2_128s_simple_std_sign_open(msg, msg_len, signed_msg, signed_msg_len, pk),
        SphincsAMode::SphincsASha2_192F => bindings::pqmagic_sphincs_a_sha2_192f_simple_std_sign_open(msg, msg_len, signed_msg, signed_msg_len, pk),
        SphincsAMode::SphincsASha2_192S => bindings::pqmagic_sphincs_a_sha2_192s_simple_std_sign_open(msg, msg_len, signed_msg, signed_msg_len, pk),
        SphincsAMode::SphincsASha2_256F => bindings::pqmagic_sphincs_a_sha2_256f_simple_std_sign_open(msg, msg_len, signed_msg, signed_msg_len, pk),
        SphincsAMode::SphincsASha2_256S => bindings::pqmagic_sphincs_a_sha2_256s_simple_std_sign_open(msg, msg_len, signed_msg, signed_msg_len, pk),

        SphincsAMode::SphincsAShake128F => bindings::pqmagic_sphincs_a_shake_128f_simple_std_sign_open(msg, msg_len, signed_msg, signed_msg_len, pk),
        SphincsAMode::SphincsAShake128S => bindings::pqmagic_sphincs_a_shake_128s_simple_std_sign_open(msg, msg_len, signed_msg, signed_msg_len, pk),
        SphincsAMode::SphincsAShake192F => bindings::pqmagic_sphincs_a_shake_192f_simple_std_sign_open(msg, msg_len, signed_msg, signed_msg_len, pk),
        SphincsAMode::SphincsAShake192S => bindings::pqmagic_sphincs_a_shake_192s_simple_std_sign_open(msg, msg_len, signed_msg, signed_msg_len, pk),
        SphincsAMode::SphincsAShake256F => bindings::pqmagic_sphincs_a_shake_256f_simple_std_sign_open(msg, msg_len, signed_msg, signed_msg_len, pk),
        SphincsAMode::SphincsAShake256S => bindings::pqmagic_sphincs_a_shake_256s_simple_std_sign_open(msg, msg_len, signed_msg, signed_msg_len, pk),

        SphincsAMode::SphincsASm3_128F  => bindings::pqmagic_sphincs_a_sm3_128f_simple_std_sign_open(msg, msg_len, signed_msg, signed_msg_len, pk),
        SphincsAMode::SphincsASm3_128S  => bindings::pqmagic_sphincs_a_sm3_128s_simple_std_sign_open(msg, msg_len, signed_msg, signed_msg_len, pk),
    }
);





