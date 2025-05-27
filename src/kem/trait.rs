use crate::error::{Result, PqmagicError};
use crate::{
    AlgorithmSelector, 
    MlKem, AigisEnc, Kyber, 
};


#[derive(Debug, Clone, Copy)]
pub struct KemParams {
    pub pk_len: usize,
    pub sk_len: usize,
    pub ct_len: usize,
}

pub trait KemAlgorithm {
    fn name(&self) -> &'static str;
    fn params(&self) -> &KemParams;
}

pub trait Kem: KemAlgorithm {
    /// Generate a keypair (public key and secret key)
    fn keypair(&self) -> Result<(Vec<u8>, Vec<u8>)>;
    
    /// Encapsulate a secret using the public key
    /// Returns (ciphertext, shared secret)
    fn encaps(&self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>)>;
    
    /// Decapsulate the shared secret using the secret key
    /// Returns the shared secret
    fn decaps(&self, ct: &[u8], sk: &[u8]) -> Result<Vec<u8>>;
}


pub struct PqmagicKem {
    inner: Box<dyn Kem>,
}

impl PqmagicKem {

    pub fn new(name: &str) -> Result<Self> {
        let selector = name.parse::<AlgorithmSelector>()
            .map_err(|e| PqmagicError::UnknownAlgorithm(e.0))?;
        let inner: Box<dyn Kem> = match selector {
            AlgorithmSelector::MlKem(mode) => Box::new(MlKem::new(mode)),
            AlgorithmSelector::AigisEnc(mode) => Box::new(AigisEnc::new(mode)),
            AlgorithmSelector::Kyber(mode) => Box::new(Kyber::new(mode)),
            _ => return Err(PqmagicError::NotAKemAlgorithm(name.to_string())),
        };
        Ok(Self { inner })
    }
}

impl Kem for PqmagicKem {
    fn keypair(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        self.inner.keypair()
    }
    fn encaps(&self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        self.inner.encaps(pk)
    }
    fn decaps(&self, ct: &[u8], sk: &[u8]) -> Result<Vec<u8>> {
        self.inner.decaps(ct, sk)
    }
}

impl KemAlgorithm for PqmagicKem {
    fn name(&self) -> &'static str {
        self.inner.name()
    }
    fn params(&self) -> &KemParams {
        self.inner.params()
    }
}


/// KEM algorithms mode
#[derive(Debug, Clone, Copy)]
pub enum MlkemMode {
    MLKEM512,
    MLKEM768,
    MLKEM1024,
}

#[derive(Debug, Clone, Copy)]
pub enum AigisEncMode {
    AIGISENC1,
    AIGISENC2,
    AIGISENC3,
    AIGISENC4,
}

#[derive(Debug, Clone, Copy)]
pub enum KyberMode {
    KYBER512,
    KYBER768,
    KYBER1024,
}



impl MlkemMode {

    pub fn name(&self) -> &'static str {
        match self {
            MlkemMode::MLKEM512 =>  "ML_KEM_512",
            MlkemMode::MLKEM768 =>  "ML_KEM_768",
            MlkemMode::MLKEM1024 => "ML_KEM_1024",
        }
    }

    pub fn params(&self) -> KemParams {
        match self {
            MlkemMode::MLKEM512 => KemParams { pk_len: 800, sk_len: 1632, ct_len: 768 },
            MlkemMode::MLKEM768 => KemParams { pk_len: 1184, sk_len: 2400, ct_len: 1088 },
            MlkemMode::MLKEM1024 => KemParams { pk_len: 1568, sk_len: 3168, ct_len: 1568 },
        }
    }
}

impl AigisEncMode {

    pub fn name(&self) -> &'static str {
        match self {
            AigisEncMode::AIGISENC1 => "AIGIS_ENC_1",
            AigisEncMode::AIGISENC2 => "AIGIS_ENC_2",
            AigisEncMode::AIGISENC3 => "AIGIS_ENC_3",
            AigisEncMode::AIGISENC4 => "AIGIS_ENC_4",
        }
    }

    pub fn params(&self) -> KemParams {
        match self {
            AigisEncMode::AIGISENC1 => KemParams { pk_len: 672, sk_len: 1568, ct_len: 736 },
            AigisEncMode::AIGISENC2 => KemParams { pk_len: 896, sk_len: 2208, ct_len: 992 },
            AigisEncMode::AIGISENC3 => KemParams { pk_len: 992, sk_len: 2304, ct_len: 1056 },
            AigisEncMode::AIGISENC4 => KemParams { pk_len: 1440, sk_len: 3168, ct_len: 1568 },
        }
    }
}

impl KyberMode {

    pub fn name(&self) -> &'static str {
        match self {
            KyberMode::KYBER512 => "KYBER_512",
            KyberMode::KYBER768 => "KYBER_768",
            KyberMode::KYBER1024 => "KYBER_1024",
        }
    }

    pub fn params(&self) -> KemParams {
        match self {
            KyberMode::KYBER512 => KemParams { pk_len: 800, sk_len: 1632, ct_len: 768 },
            KyberMode::KYBER768 => KemParams { pk_len: 1184, sk_len: 2400, ct_len: 1088 },
            KyberMode::KYBER1024 => KemParams { pk_len: 1568, sk_len: 3168, ct_len: 1568 },
        }
    }
}
