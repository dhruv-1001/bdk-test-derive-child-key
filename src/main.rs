use bdk::bitcoin::secp256k1::Secp256k1;
use bdk::bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey, KeySource};
use bdk::descriptor::Segwitv0;
use bdk::keys::{DerivableKey, DescriptorKey, DescriptorKey::Secret};
use bdk::keys::KeyError::Message;
use bdk::{Error};
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct DescriptorKeyInfo{
    xprv: String,
    xpub: String,
}

fn main() {

    let xprv = "tprv8ZgxMBicQKsPdMTRB73kkTfC665bK3JL33eAFZ3MUiGZj8jniKQroG2yuamoQcRb24GG8dKRmVgaisjcZrDc9L3fyMf2NW19oajw8iWSwMV".to_string();
    let path = "m/84'/1'/0'/0".to_string();

    let result = derive_child_key_pair(xprv, path).unwrap();

    println!("xprv - {}", result.clone().xprv);
    println!("xpub - {}", result.xpub);

}

fn derive_child_key_pair(
    xprv: String,
    path: String
) -> Result<DescriptorKeyInfo, Error> {
    let secp = Secp256k1::new();
    let xprv = ExtendedPrivKey::from_str(&xprv)?;
    let path = DerivationPath::from_str(&path)?;
    let derived_xprv = &xprv.derive_priv(&secp, &path)?;
    let origin: KeySource = (xprv.fingerprint(&secp), path);
    let derived_xprv_desc_key: DescriptorKey<Segwitv0> = derived_xprv.into_descriptor_key(Some(origin), DerivationPath::default())?;
    if let Secret(desc_seckey, _, _) = derived_xprv_desc_key {
        let desc_pubkey = desc_seckey
            .as_public(&secp)
            .map_err(|e| Error::Generic(e.to_string()))?;
        Ok(
            DescriptorKeyInfo{
                xprv: desc_seckey.to_string(),
                xpub: desc_pubkey.to_string(),
            }
        )
    } else {
        Err(Error::Key(Message("Invalid key variant".to_string())))
    }

}


// from code
// xprv - tprv8hZWYaWfKprzVnSVaaxwYun2yVp9TgpvcosjrGYwgL9hKMU1Jsrp3xKsNCpxSNBSEgUPp7c8A1MYLQcMcq7Ab9eafzNZUHQaBtGBvfCQiMg/*
// xpub - tpubDEFYgzYuUCYfPFUHUEdXxKS9YXL5d21qC7UX8nbF6bx69qimwGgQESwjYN52awKwDd5PWGKXWAw27EBUk6QzSK3eEwsK8odY8FxVn4poRDp/*

// from bdk-cli
// xprv - tprv8hZWYaWfKprzVnSVaaxwYun2yVp9TgpvcosjrGYwgL9hKMU1Jsrp3xKsNCpxSNBSEgUPp7c8A1MYLQcMcq7Ab9eafzNZUHQaBtGBvfCQiMg
// xpub - tpubDEFYgzYuUCYfPFUHUEdXxKS9YXL5d21qC7UX8nbF6bx69qimwGgQESwjYN52awKwDd5PWGKXWAw27EBUk6QzSK3eEwsK8odY8FxVn4poRDp

// comparison - xprv
// tprv8hZWYaWfKprzVnSVaaxwYun2yVp9TgpvcosjrGYwgL9hKMU1Jsrp3xKsNCpxSNBSEgUPp7c8A1MYLQcMcq7Ab9eafzNZUHQaBtGBvfCQiMg/* (cli)
// tprv8hZWYaWfKprzVnSVaaxwYun2yVp9TgpvcosjrGYwgL9hKMU1Jsrp3xKsNCpxSNBSEgUPp7c8A1MYLQcMcq7Ab9eafzNZUHQaBtGBvfCQiMg   (code)

// comparison - xpub
// tpubDEFYgzYuUCYfPFUHUEdXxKS9YXL5d21qC7UX8nbF6bx69qimwGgQESwjYN52awKwDd5PWGKXWAw27EBUk6QzSK3eEwsK8odY8FxVn4poRDp/* (cli)
// tpubDEFYgzYuUCYfPFUHUEdXxKS9YXL5d21qC7UX8nbF6bx69qimwGgQESwjYN52awKwDd5PWGKXWAw27EBUk6QzSK3eEwsK8odY8FxVn4poRDp   (code)
