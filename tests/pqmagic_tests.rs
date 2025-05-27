use pqmagic::{
    utils::*, error::Result, 
    PqmagicSig, sig::*,
    PqmagicKem, kem::*,
};


#[test]
fn sig_example() -> Result<()> {
    // 创建算法实例
    let signer = PqmagicSig::new("ML_DSA_44")?;

    // 生成密钥对
    let (pk, sk) = signer.keypair()?;

    // 签名
    let msg = b"Test message";
    let sig = signer.sign(msg, None, &sk)?;

    // 验签
    assert!(signer.verify(&sig, msg, None, &pk)?, "{}: Verification failed", signer.name());

    Ok(())
}

#[test]
fn kem_example() -> Result<()> {
    // 创建算法实例
    let kemer = PqmagicKem::new("ML_KEM_512")?;

    // 生成密钥对
    let (pk, sk) = kemer.keypair()?;

    // 封装阶段（生成密文和共享密钥）
    let (ct, ss1) = kemer.encaps(&pk)?;

    // 解封阶段（恢复共享密钥）
    let ss2 = kemer.decaps(&ct, &sk)?;
    
    // 验证两个共享密钥是否相同
    assert_eq!(
        ss1, ss2,
        "Shared secrets don't match! Encaps produced {:?} but decaps produced {:?}",
        ss1, ss2
    );

    Ok(())
}


#[test]
fn sig_test() -> Result<()> {
    for signer in sig_instances() {

        let (pk, sk) = signer.keypair()?;
        
        assert_eq!(pk.len(), signer.params().pk_len, "{}: Invalid pk length", signer.name());
        assert_eq!(sk.len(), signer.params().sk_len, "{}: Invalid sk length", signer.name());
        
        let msg = b"Cross-algorithm test message";
        
        // Basic signature verification
        let sig = signer.sign(msg, None, &sk)?;
        assert!(signer.verify(&sig, msg, None, &pk)?, "{}: Verification failed", signer.name());

        // with context
        if let Some(ctx) = test_context() {
            let sig_ctx = signer.sign(msg, Some(&ctx), &sk)?;
            assert!(signer.verify(&sig_ctx, msg, Some(&ctx), &pk)?, "{}: Context verification failed", signer.name());
        }
        
        // Tamper detection
        let mut bad_sig = sig.clone();
        if !bad_sig.is_empty() {
            bad_sig[0] = bad_sig[0].wrapping_add(1);
            assert!(!signer.verify(&bad_sig, msg, None, &pk)?, "{}: Tampered sig passed", signer.name());
        }
    }
    Ok(())
}

#[test]
fn kem_test() -> Result<()> {
    for kemer in kem_instances() {

        let (pk, sk) = kemer.keypair()?;
        
        assert_eq!(pk.len(), kemer.params().pk_len, "{}: Invalid pk length", kemer.name());
        assert_eq!(sk.len(), kemer.params().sk_len, "{}: Invalid sk length", kemer.name());
        
        let (ct, ss1) = kemer.encaps(&pk)?;
        let ss2 = kemer.decaps(&ct, &sk)?;

        assert_eq!(
            ss1, ss2,
            "{}: Shared secrets don't match! Encaps produced {:?} but decaps produced {:?}",
            kemer.name(), ss1, ss2
        );
    }
    Ok(())
}
