// Copyright © 2017-2022 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Rust interfaces to wallet-core
// Could be auto-generated

use libc::c_char;

// signatures
extern "C" {
    fn TWStringCreateWithUTF8Bytes(twstring: *const c_char) -> *const u8;
    fn TWStringDelete(twstring: *const u8);
    fn TWStringUTF8Bytes(twstring: *const u8) -> *const c_char;

    fn TWDataCreateWithBytes(bytes: *const u8, size: usize) -> *const u8;
    fn TWDataDelete(data: *const u8);
    fn TWDataSize(data: *const u8) -> usize;
    fn TWDataBytes(data: *const u8) -> *const u8;

    fn TWPrivateKeyData(private_key: *const u8) -> *const u8;
    fn TWPrivateKeyCreateWithData(data: *const u8) -> *const u8;
    fn TWPrivateKeyGetPublicKeySecp256k1(private_key: *const u8, compressed: bool) -> *const u8;
    fn TWPrivateKeyDelete(private_key: *const u8);

    fn TWPublicKeyData(public_key: *const u8) -> *const u8;
    fn TWPublicKeyDelete(public_key: *const u8);

    fn TWHDWalletCreateWithMnemonic(mnemonic: *const u8, passphrase: *const u8) -> *const u8;
    fn TWHDWalletDelete(wallet: *const u8);
    fn TWHDWalletGetAddressForCoin(wallet: *const u8, coin: u32) -> *const u8;
    fn TWHDWalletGetKeyForCoin(wallet: *const u8, coin: u32) -> *const u8;
    fn TWHDWalletGetKey(wallet: *const u8, coin: u32, derivation: *const u8) -> *const u8;

    fn TWAnyAddressCreateWithPublicKey(public_key: *const u8, coin: u8) -> *const u8;
    fn TWAnyAddressCreateWithPublicKeyDerivation(public_key: *const u8, coin: u8, derivation: u8) -> *const u8;
    fn TWAnyAddressDescription(address: *const u8) -> *const u8;
    fn TWAnyAddressDelete(public_key: *const u8);

    fn TWAnySignerSign(input: *const u8, coin: u32) -> *const u8;

    fn TWMnemonicIsValid(mnemonic: *const u8) -> bool;
}


// Types
pub struct TWString {
    wrapped: *const u8
}

pub fn tw_string_create_with_utf8_bytes(bytes: *const c_char) -> TWString {
    let ptr = unsafe { TWStringCreateWithUTF8Bytes(bytes) };
    TWString { wrapped: ptr }
}

pub fn tw_string_utf8_bytes(twstring: &TWString) -> *const c_char {
    unsafe { TWStringUTF8Bytes(twstring.wrapped) }
}

impl Drop for TWString {
    fn drop(&mut self) {
        unsafe { TWStringDelete(self.wrapped) };
    }
}


pub struct TWData {
    wrapped: *const u8
}

pub fn tw_data_create_with_bytes(bytes: &Vec<u8>) -> TWData {
    let ptr = unsafe { TWDataCreateWithBytes(bytes.as_ptr(), bytes.len()) };
    TWData { wrapped: ptr }
}

pub fn tw_data_size(data: &TWData) -> usize {
    unsafe { TWDataSize(data.wrapped) }
}

pub fn tw_data_bytes(data: &TWData) -> Vec<u8> {
    let size = tw_data_size(data);
    let ptr = unsafe { TWDataBytes(data.wrapped) };
    let slice: &[u8] = unsafe { std::slice::from_raw_parts(ptr, size) };
    slice.to_vec()
}

impl Drop for TWData {
    fn drop(&mut self) {
        unsafe { TWDataDelete(self.wrapped) };
    }
}


pub struct PrivateKey {
    wrapped: *const u8
}

pub fn private_key_data(private_key: &PrivateKey) -> TWData {
    let ptr = unsafe { TWPrivateKeyData(private_key.wrapped) };
    TWData { wrapped: ptr }
}

pub fn private_key_create_with_data(data: &TWData) -> PrivateKey {
    let ptr = unsafe { TWPrivateKeyCreateWithData(data.wrapped) };
    PrivateKey { wrapped: ptr }
}

pub fn private_key_get_public_key_secp256k1(private_key: &PrivateKey, compressed: bool) -> PublicKey {
    let ptr = unsafe { TWPrivateKeyGetPublicKeySecp256k1(private_key.wrapped, compressed) };
    PublicKey { wrapped: ptr }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        unsafe { TWPrivateKeyDelete(self.wrapped) };
    }
}


pub struct PublicKey {
    wrapped: *const u8
}

pub fn public_key_data(public_key: &PublicKey) -> TWData {
    let ptr = unsafe { TWPublicKeyData(public_key.wrapped) };
    TWData { wrapped: ptr }
}

impl Drop for PublicKey {
    fn drop(&mut self) {
        unsafe { TWPublicKeyDelete(self.wrapped) };
    }
}


pub struct HDWallet {
    wrapped: *const u8
}

pub fn hd_wallet_create_with_mnemonic(mnemonic: &TWString, passphrase: &TWString) -> HDWallet {
    let ptr = unsafe { TWHDWalletCreateWithMnemonic(mnemonic.wrapped, passphrase.wrapped) };
    HDWallet { wrapped: ptr }
}

pub fn hd_wallet_get_address_for_coin(wallet: &HDWallet, coin: u32) -> TWString {
    let ptr = unsafe { TWHDWalletGetAddressForCoin(wallet.wrapped, coin) };
    TWString { wrapped: ptr }
}

pub fn hd_wallet_get_key_for_coin(wallet: &HDWallet, coin: u32) -> PrivateKey {
    let ptr = unsafe { TWHDWalletGetKeyForCoin(wallet.wrapped, coin) };
    PrivateKey { wrapped: ptr }
}

pub fn hd_wallet_get_key(wallet: &HDWallet, coin: u32, derivation_path: &TWString) -> PrivateKey {
    let ptr = unsafe { TWHDWalletGetKey(wallet.wrapped, coin, derivation_path.wrapped) };
    PrivateKey { wrapped: ptr }
}

impl Drop for HDWallet {
    fn drop(&mut self) {
        unsafe { TWHDWalletDelete(self.wrapped) };
    }
}


pub struct AnyAddress {
    wrapped: *const u8
}

pub fn any_address_create_with_public_key(public_key: &PublicKey, coin: u8) -> AnyAddress {
    let ptr = unsafe { TWAnyAddressCreateWithPublicKey(public_key.wrapped, coin) };
    return AnyAddress { wrapped: ptr };
}

pub fn any_address_create_with_public_key_derivation(public_key: &PublicKey, coin: u8, derivation: u8) -> AnyAddress {
    let ptr = unsafe { TWAnyAddressCreateWithPublicKeyDerivation(public_key.wrapped, coin, derivation) };
    return AnyAddress { wrapped: ptr };
}

pub fn any_address_description(address: &AnyAddress) -> TWString {
    let ptr = unsafe { TWAnyAddressDescription(address.wrapped) };
    return TWString { wrapped: ptr };
}

impl Drop for AnyAddress {
    fn drop(&mut self) {
        unsafe { TWAnyAddressDelete(self.wrapped) };
    }
}


pub fn any_signer_sign(input: &TWData, coin: u32) -> TWData {
    let ptr = unsafe { TWAnySignerSign(input.wrapped, coin) };
    TWData { wrapped: ptr }
}


pub fn mnemonic_is_valid(mnemonic: &TWString) -> bool {
    unsafe { TWMnemonicIsValid(mnemonic.wrapped) }
}
