use std::str::FromStr;
use std::fmt;

pub mod bindings;
pub mod error;
pub mod sig;
pub mod kem;

pub mod utils;

pub use error::{PqmagicError, Result};

pub use sig::{
    PqmagicSig, Sig, SigParams, 
    MlDsa, MldsaMode, 
    AigisSig, AigisSigMode, 
    Dilithium, DilithiumMode, 
    Slhdsa, SlhdsaMode, 
    SphincsA, SphincsAMode, 
};

pub use kem::{
    PqmagicKem, Kem, KemParams, 
    MlKem, MlkemMode, 
    AigisEnc, AigisEncMode, 
    Kyber, KyberMode
};



#[derive(Debug, Clone, Copy)]
pub enum AlgorithmSelector {
    // SIG
    MlDsa(MldsaMode),
    AigisSig(AigisSigMode),
    Dilithium(DilithiumMode), 
    SlhDsa(SlhdsaMode), 
    SphincsA(SphincsAMode),
    
    // KEM
    MlKem(MlkemMode),
    AigisEnc(AigisEncMode),
    Kyber(KyberMode),
}

#[derive(Debug)]
pub struct SelectorParseError(pub String);

impl fmt::Display for SelectorParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Unknown algorithm: {}", self.0)
    }
}

impl std::error::Error for SelectorParseError {}

impl FromStr for AlgorithmSelector {
    type Err = SelectorParseError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "ML_DSA_44" => Ok(AlgorithmSelector::MlDsa(MldsaMode::MLDSA44)),
            "ML_DSA_65" => Ok(AlgorithmSelector::MlDsa(MldsaMode::MLDSA65)),
            "ML_DSA_87" => Ok(AlgorithmSelector::MlDsa(MldsaMode::MLDSA87)),

            "AIGIS_SIG_1" => Ok(AlgorithmSelector::AigisSig(AigisSigMode::AIGISSIG1)),
            "AIGIS_SIG_2" => Ok(AlgorithmSelector::AigisSig(AigisSigMode::AIGISSIG2)),
            "AIGIS_SIG_3" => Ok(AlgorithmSelector::AigisSig(AigisSigMode::AIGISSIG3)),

            "DILITHIUM_2" => Ok(AlgorithmSelector::Dilithium(DilithiumMode::Dilithium2)),
            "DILITHIUM_3" => Ok(AlgorithmSelector::Dilithium(DilithiumMode::Dilithium3)),
            "DILITHIUM_5" => Ok(AlgorithmSelector::Dilithium(DilithiumMode::Dilithium5)),

            "SLH_DSA_SHA2_128_F"  => Ok(AlgorithmSelector::SlhDsa(SlhdsaMode::SlhdsaSha2_128F)),
            "SLH_DSA_SHA2_128_S"  => Ok(AlgorithmSelector::SlhDsa(SlhdsaMode::SlhdsaSha2_128S)),
            "SLH_DSA_SHA2_192_F"  => Ok(AlgorithmSelector::SlhDsa(SlhdsaMode::SlhdsaSha2_192F)),
            "SLH_DSA_SHA2_192_S"  => Ok(AlgorithmSelector::SlhDsa(SlhdsaMode::SlhdsaSha2_192S)),
            "SLH_DSA_SHA2_256_F"  => Ok(AlgorithmSelector::SlhDsa(SlhdsaMode::SlhdsaSha2_256F)),
            "SLH_DSA_SHA2_256_S"  => Ok(AlgorithmSelector::SlhDsa(SlhdsaMode::SlhdsaSha2_256S)),

            "SLH_DSA_SHAKE_128_F" => Ok(AlgorithmSelector::SlhDsa(SlhdsaMode::SlhdsaShake128F)),
            "SLH_DSA_SHAKE_128_S" => Ok(AlgorithmSelector::SlhDsa(SlhdsaMode::SlhdsaShake128S)),
            "SLH_DSA_SHAKE_192_F" => Ok(AlgorithmSelector::SlhDsa(SlhdsaMode::SlhdsaShake192F)),
            "SLH_DSA_SHAKE_192_S" => Ok(AlgorithmSelector::SlhDsa(SlhdsaMode::SlhdsaShake192S)),
            "SLH_DSA_SHAKE_256_F" => Ok(AlgorithmSelector::SlhDsa(SlhdsaMode::SlhdsaShake256F)),
            "SLH_DSA_SHAKE_256_S" => Ok(AlgorithmSelector::SlhDsa(SlhdsaMode::SlhdsaShake256S)),

            "SLH_DSA_SM3_128_F"   => Ok(AlgorithmSelector::SlhDsa(SlhdsaMode::SlhdsaSm3_128F )),
            "SLH_DSA_SM3_128_S"   => Ok(AlgorithmSelector::SlhDsa(SlhdsaMode::SlhdsaSm3_128S )),

            "SPHINCS_A_SHA2_128_F"  => Ok(AlgorithmSelector::SphincsA(SphincsAMode::SphincsASha2_128F)),
            "SPHINCS_A_SHA2_128_S"  => Ok(AlgorithmSelector::SphincsA(SphincsAMode::SphincsASha2_128S)),
            "SPHINCS_A_SHA2_192_F"  => Ok(AlgorithmSelector::SphincsA(SphincsAMode::SphincsASha2_192F)),
            "SPHINCS_A_SHA2_192_S"  => Ok(AlgorithmSelector::SphincsA(SphincsAMode::SphincsASha2_192S)),
            "SPHINCS_A_SHA2_256_F"  => Ok(AlgorithmSelector::SphincsA(SphincsAMode::SphincsASha2_256F)),
            "SPHINCS_A_SHA2_256_S"  => Ok(AlgorithmSelector::SphincsA(SphincsAMode::SphincsASha2_256S)),

            "SPHINCS_A_SHAKE_128_F" => Ok(AlgorithmSelector::SphincsA(SphincsAMode::SphincsAShake128F)),
            "SPHINCS_A_SHAKE_128_S" => Ok(AlgorithmSelector::SphincsA(SphincsAMode::SphincsAShake128S)),
            "SPHINCS_A_SHAKE_192_F" => Ok(AlgorithmSelector::SphincsA(SphincsAMode::SphincsAShake192F)),
            "SPHINCS_A_SHAKE_192_S" => Ok(AlgorithmSelector::SphincsA(SphincsAMode::SphincsAShake192S)),
            "SPHINCS_A_SHAKE_256_F" => Ok(AlgorithmSelector::SphincsA(SphincsAMode::SphincsAShake256F)),
            "SPHINCS_A_SHAKE_256_S" => Ok(AlgorithmSelector::SphincsA(SphincsAMode::SphincsAShake256S)),

            "SPHINCS_A_SM3_128_F"  => Ok(AlgorithmSelector::SphincsA(SphincsAMode::SphincsASm3_128F )),
            "SPHINCS_A_SM3_128_S"  => Ok(AlgorithmSelector::SphincsA(SphincsAMode::SphincsASm3_128S )),

            "ML_KEM_512" => Ok(AlgorithmSelector::MlKem(MlkemMode::MLKEM512)),
            "ML_KEM_768" => Ok(AlgorithmSelector::MlKem(MlkemMode::MLKEM768)),
            "ML_KEM_1024" => Ok(AlgorithmSelector::MlKem(MlkemMode::MLKEM1024)),

            "AIGIS_ENC_1" => Ok(AlgorithmSelector::AigisEnc(AigisEncMode::AIGISENC1)),
            "AIGIS_ENC_2" => Ok(AlgorithmSelector::AigisEnc(AigisEncMode::AIGISENC2)),
            "AIGIS_ENC_3" => Ok(AlgorithmSelector::AigisEnc(AigisEncMode::AIGISENC3)),
            "AIGIS_ENC_4" => Ok(AlgorithmSelector::AigisEnc(AigisEncMode::AIGISENC4)),

            "KYBER_512" => Ok(AlgorithmSelector::Kyber(KyberMode::KYBER512)),
            "KYBER_768" => Ok(AlgorithmSelector::Kyber(KyberMode::KYBER768)),
            "KYBER_1024" => Ok(AlgorithmSelector::Kyber(KyberMode::KYBER1024)),

            other => Err(SelectorParseError(other.to_string())),
        }
    }
}
