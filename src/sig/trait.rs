use crate::error::{Result, PqmagicError};
use crate::{
    AlgorithmSelector, 
    MlDsa, AigisSig, 
    Dilithium, Slhdsa, SphincsA,
};


#[derive(Debug, Clone, Copy)]
pub struct SigParams {
    pub pk_len: usize,
    pub sk_len: usize,
    pub sig_len: usize,
}

pub trait SigAlgorithm {
    fn name(&self) -> &'static str;
    fn params(&self) -> &SigParams;
}

pub trait Sig: SigAlgorithm {
    fn keypair(&self) -> Result<(Vec<u8>, Vec<u8>)>;
    fn sign(&self, msg: &[u8], ctx: Option<&[u8]>, sk: &[u8]) -> Result<Vec<u8>>;
    fn verify(&self, sig: &[u8], msg: &[u8], ctx: Option<&[u8]>, pk: &[u8]) -> Result<bool>;
    fn sign_message(&self, msg: &[u8], ctx: Option<&[u8]>, sk: &[u8]) -> Result<Vec<u8>>;
    fn open_signed_message(&self, signed_msg: &[u8], ctx: Option<&[u8]>, pk: &[u8]) -> Result<Vec<u8>>;
}

pub struct PqmagicSig {
    inner: Box<dyn Sig>,
}

impl PqmagicSig {

    pub fn new(name: &str) -> Result<Self> {
        let selector = name.parse::<AlgorithmSelector>()
            .map_err(|e| PqmagicError::UnknownAlgorithm(e.0))?;
        let inner: Box<dyn Sig> = match selector {
            AlgorithmSelector::MlDsa(mode) => Box::new(MlDsa::new(mode)),
            AlgorithmSelector::AigisSig(mode) => Box::new(AigisSig::new(mode)),
            AlgorithmSelector::Dilithium(mode) => Box::new(Dilithium::new(mode)),
            AlgorithmSelector::SlhDsa(mode) => Box::new(Slhdsa::new(mode)),
            AlgorithmSelector::SphincsA(mode) => Box::new(SphincsA::new(mode)),
            _ => return Err(PqmagicError::NotASigAlgorithm(name.to_string())),
        };
        Ok(Self { inner })
    }
}

impl Sig for PqmagicSig {
    fn keypair(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        self.inner.keypair()
    }
    fn sign(&self, msg: &[u8], ctx: Option<&[u8]>, sk: &[u8]) -> Result<Vec<u8>> {
        self.inner.sign(msg, ctx, sk)
    }
    fn verify(&self, sig: &[u8], msg: &[u8], ctx: Option<&[u8]>, pk: &[u8]) -> Result<bool> {
        self.inner.verify(sig, msg, ctx, pk)
    }
    fn sign_message(&self, msg: &[u8], ctx: Option<&[u8]>, sk: &[u8]) -> Result<Vec<u8>> {
        self.inner.sign_message(msg, ctx, sk)
    }
    fn open_signed_message(&self, signed_msg: &[u8], ctx: Option<&[u8]>, pk: &[u8]) -> Result<Vec<u8>> {
        self.inner.open_signed_message(signed_msg, ctx, pk)
    }
}

impl SigAlgorithm for PqmagicSig {
    fn name(&self) -> &'static str {
        self.inner.name()
    }
    fn params(&self) -> &SigParams {
        self.inner.params()
    }
}



/// Sig algorithms mode
#[derive(Debug, Clone, Copy)]
pub enum MldsaMode {
    MLDSA44,
    MLDSA65,
    MLDSA87,
}

#[derive(Debug, Clone, Copy)]
pub enum AigisSigMode {
    AIGISSIG1,
    AIGISSIG2,
    AIGISSIG3,
}

#[derive(Debug, Clone, Copy)]
pub enum DilithiumMode {
    Dilithium2,
    Dilithium3,
    Dilithium5,
}

#[derive(Debug, Clone, Copy)]
pub enum SlhdsaMode {
    SlhdsaSha2_128F,
    SlhdsaSha2_128S,
    SlhdsaSha2_192F,
    SlhdsaSha2_192S,
    SlhdsaSha2_256F,
    SlhdsaSha2_256S,

    SlhdsaShake128F,
    SlhdsaShake128S,
    SlhdsaShake192F,
    SlhdsaShake192S,
    SlhdsaShake256F,
    SlhdsaShake256S,

    SlhdsaSm3_128F,
    SlhdsaSm3_128S,
}

#[derive(Debug, Clone, Copy)]
pub enum SphincsAMode {
    SphincsASha2_128F,
    SphincsASha2_128S,
    SphincsASha2_192F,
    SphincsASha2_192S,
    SphincsASha2_256F,
    SphincsASha2_256S,

    SphincsAShake128F,
    SphincsAShake128S,
    SphincsAShake192F,
    SphincsAShake192S,
    SphincsAShake256F,
    SphincsAShake256S,

    SphincsASm3_128F,
    SphincsASm3_128S,
}



impl MldsaMode {

    pub fn name(&self) -> &'static str {
        match self {
            MldsaMode::MLDSA44 => "ML_DSA_44",
            MldsaMode::MLDSA65 => "ML_DSA_65",
            MldsaMode::MLDSA87 => "ML_DSA_87",
        }
    }

    pub fn params(&self) -> SigParams {
        match self {
            MldsaMode::MLDSA44 => SigParams { pk_len: 1312, sk_len: 2560, sig_len: 2420 },
            MldsaMode::MLDSA65 => SigParams { pk_len: 1952, sk_len: 4032, sig_len: 3309 },
            MldsaMode::MLDSA87 => SigParams { pk_len: 2592, sk_len: 4896, sig_len: 4627 },
        }
    }
}

impl AigisSigMode {

    pub fn name(&self) -> &'static str {
        match self {
            AigisSigMode::AIGISSIG1 => "AIGIS_SIG_1",
            AigisSigMode::AIGISSIG2 => "AIGIS_SIG_2",
            AigisSigMode::AIGISSIG3 => "AIGIS_SIG_3",
        }
    }

    pub fn params(&self) -> SigParams {
        match self {
            AigisSigMode::AIGISSIG1 => SigParams { pk_len: 1056, sk_len: 2448, sig_len: 1852 },
            AigisSigMode::AIGISSIG2 => SigParams { pk_len: 1312, sk_len: 3376, sig_len: 2445 },
            AigisSigMode::AIGISSIG3 => SigParams { pk_len: 1568, sk_len: 3888, sig_len: 3046 },
        }
    }
}

impl DilithiumMode {

    pub fn name(&self) -> &'static str {
        match self {
            DilithiumMode::Dilithium2 => "DILITHIUM_2",
            DilithiumMode::Dilithium3 => "DILITHIUM_3",
            DilithiumMode::Dilithium5 => "DILITHIUM_5",
        }
    }

    pub fn params(&self) -> SigParams {
        match self {
            DilithiumMode::Dilithium2 => SigParams { pk_len: 1312, sk_len: 2528, sig_len: 2420 },
            DilithiumMode::Dilithium3 => SigParams { pk_len: 1952, sk_len: 4000, sig_len: 3293 },
            DilithiumMode::Dilithium5 => SigParams { pk_len: 2592, sk_len: 4864, sig_len: 4595 },
        }
    }
}

impl SlhdsaMode {

    pub fn name(&self) -> &'static str {
        match self {
            SlhdsaMode::SlhdsaSha2_128F => "SLH_DSA_SHA2_128_F",
            SlhdsaMode::SlhdsaSha2_128S => "SLH_DSA_SHA2_128_S",
            SlhdsaMode::SlhdsaSha2_192F => "SLH_DSA_SHA2_192_F",
            SlhdsaMode::SlhdsaSha2_192S => "SLH_DSA_SHA2_192_S",
            SlhdsaMode::SlhdsaSha2_256F => "SLH_DSA_SHA2_256_F",
            SlhdsaMode::SlhdsaSha2_256S => "SLH_DSA_SHA2_256_S",

            SlhdsaMode::SlhdsaShake128F => "SLH_DSA_SHAKE_128_F",
            SlhdsaMode::SlhdsaShake128S => "SLH_DSA_SHAKE_128_S",
            SlhdsaMode::SlhdsaShake192F => "SLH_DSA_SHAKE_192_F",
            SlhdsaMode::SlhdsaShake192S => "SLH_DSA_SHAKE_192_S",
            SlhdsaMode::SlhdsaShake256F => "SLH_DSA_SHAKE_256_F",
            SlhdsaMode::SlhdsaShake256S => "SLH_DSA_SHAKE_256_S",

            SlhdsaMode::SlhdsaSm3_128F => "SLH_DSA_SM3_128_F ",
            SlhdsaMode::SlhdsaSm3_128S => "SLH_DSA_SM3_128_S ",
        }
    }

    pub fn params(&self) -> SigParams {
        match self {
            SlhdsaMode::SlhdsaSha2_128F => SigParams { pk_len: 32, sk_len: 64, sig_len: 17088 },
            SlhdsaMode::SlhdsaSha2_128S => SigParams { pk_len: 32, sk_len: 64, sig_len: 7856 },
            SlhdsaMode::SlhdsaSha2_192F => SigParams { pk_len: 48, sk_len: 96, sig_len: 35664 },
            SlhdsaMode::SlhdsaSha2_192S => SigParams { pk_len: 48, sk_len: 96, sig_len: 16224 },
            SlhdsaMode::SlhdsaSha2_256F => SigParams { pk_len: 64, sk_len: 128, sig_len: 49856 },
            SlhdsaMode::SlhdsaSha2_256S => SigParams { pk_len: 64, sk_len: 128, sig_len: 29792 },

            SlhdsaMode::SlhdsaShake128F => SigParams { pk_len: 32, sk_len: 64, sig_len: 17088 },
            SlhdsaMode::SlhdsaShake128S => SigParams { pk_len: 32, sk_len: 64, sig_len: 7856 },
            SlhdsaMode::SlhdsaShake192F => SigParams { pk_len: 48, sk_len: 96, sig_len: 35664 },
            SlhdsaMode::SlhdsaShake192S => SigParams { pk_len: 48, sk_len: 96, sig_len: 16224 },
            SlhdsaMode::SlhdsaShake256F => SigParams { pk_len: 64, sk_len: 128, sig_len: 49856 },
            SlhdsaMode::SlhdsaShake256S => SigParams { pk_len: 64, sk_len: 128, sig_len: 29792 },

            SlhdsaMode::SlhdsaSm3_128F  => SigParams { pk_len: 32, sk_len: 64, sig_len: 17088 },
            SlhdsaMode::SlhdsaSm3_128S  => SigParams { pk_len: 32, sk_len: 64, sig_len: 7856 },
        }
    }
}

impl SphincsAMode {

    pub fn name(&self) -> &'static str {
        match self {
            SphincsAMode::SphincsASha2_128F => "SPHINCS_A_SHA2_128_F",
            SphincsAMode::SphincsASha2_128S => "SPHINCS_A_SHA2_128_S",
            SphincsAMode::SphincsASha2_192F => "SPHINCS_A_SHA2_192_F",
            SphincsAMode::SphincsASha2_192S => "SPHINCS_A_SHA2_192_S",
            SphincsAMode::SphincsASha2_256F => "SPHINCS_A_SHA2_256_F",
            SphincsAMode::SphincsASha2_256S => "SPHINCS_A_SHA2_256_S",

            SphincsAMode::SphincsAShake128F => "SPHINCS_A_SHAKE_128_F",
            SphincsAMode::SphincsAShake128S => "SPHINCS_A_SHAKE_128_S",
            SphincsAMode::SphincsAShake192F => "SPHINCS_A_SHAKE_192_F",
            SphincsAMode::SphincsAShake192S => "SPHINCS_A_SHAKE_192_S",
            SphincsAMode::SphincsAShake256F => "SPHINCS_A_SHAKE_256_F",
            SphincsAMode::SphincsAShake256S => "SPHINCS_A_SHAKE_256_S",

            SphincsAMode::SphincsASm3_128F  => "SPHINCS_A_SM3_128_F ",
            SphincsAMode::SphincsASm3_128S  => "SPHINCS_A_SM3_128_S ",
        }
    }

    pub fn params(&self) -> SigParams {
        match self {
            SphincsAMode::SphincsASha2_128F => SigParams { pk_len: 32, sk_len: 64, sig_len: 16720 },
            SphincsAMode::SphincsASha2_128S => SigParams { pk_len: 32, sk_len: 64, sig_len: 6880 },
            SphincsAMode::SphincsASha2_192F => SigParams { pk_len: 48, sk_len: 96, sig_len: 34896 },
            SphincsAMode::SphincsASha2_192S => SigParams { pk_len: 48, sk_len: 96, sig_len: 14568 },
            SphincsAMode::SphincsASha2_256F => SigParams { pk_len: 64, sk_len: 128, sig_len: 49312 },
            SphincsAMode::SphincsASha2_256S => SigParams { pk_len: 64, sk_len: 128, sig_len: 27232 },

            SphincsAMode::SphincsAShake128F => SigParams { pk_len: 32, sk_len: 64, sig_len: 16720 },
            SphincsAMode::SphincsAShake128S => SigParams { pk_len: 32, sk_len: 64, sig_len: 6880 },
            SphincsAMode::SphincsAShake192F => SigParams { pk_len: 48, sk_len: 96, sig_len: 34896 },
            SphincsAMode::SphincsAShake192S => SigParams { pk_len: 48, sk_len: 96, sig_len: 14568 },
            SphincsAMode::SphincsAShake256F => SigParams { pk_len: 64, sk_len: 128, sig_len: 49312 },
            SphincsAMode::SphincsAShake256S => SigParams { pk_len: 64, sk_len: 128, sig_len: 27232 },

            SphincsAMode::SphincsASm3_128F  => SigParams { pk_len: 32, sk_len: 64, sig_len: 16720 },
            SphincsAMode::SphincsASm3_128S  => SigParams { pk_len: 32, sk_len: 64, sig_len: 6880 },
        }
    }
}
