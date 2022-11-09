use crate::wc_proto::Bitcoin;
use crate::walletcore_iface::*;
use crate::walletcore_extra::*;
use crate::convert::Unspents;
use crate::bitcoind_client::BitcoindClient;
use protobuf::Message;
use lightning::chain::keysinterface::{KeysInterface, KeysManager, KeyMaterial, Recipient, InMemorySigner, SpendableOutputDescriptor};
use lightning::chain::keysinterface::SpendableOutputDescriptor::{StaticOutput, DelayedPaymentOutput, StaticPaymentOutput};
use lightning::ln::msgs::DecodeError;
use lightning::ln::script::ShutdownScript;
use bitcoin::network::constants::Network;
use bitcoin::bech32::u5;
use bitcoin::blockdata::script::Script;
use bitcoin::blockdata::transaction::{Transaction, TxOut};
use bitcoin::secp256k1::{SecretKey, Signing, Secp256k1};
use bitcoin::secp256k1::ecdsa::RecoverableSignature;
use std::sync::Arc;
use std::fs;

const PK_FILENAME: &str = ".pk_secret";
const LN_SEED_DERIVATION_PATH: &str = "m/2121'/9735'/0'/0/0";
const LN_SEED_DERIVATION_PATH_TESTNET: &str = "m/2121'/9735'/1'/0/0";

pub struct Wallet {
    // own address
    pub address: String,
    // private key, private field
    private_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub utxos: Unspents,
    pub balance: f64,
    // 32-byte seed to be used by Lightning hot wallet, derived from mnemonic in a reproducible way
    pub seed_for_ldk: Vec<u8>,
}

// given a mnemonic derive private keys and save them
pub fn import_wallet_mnemonic(mnemonic: &str, network: Network) -> Option<Wallet> {
    if !is_mnemonic_valid(mnemonic) {
		println!("Mnemonic is invalid! {}", mnemonic);
		return None;
	}
	println!("Mnemonic is valid");
    let hd_wallet = hd_wallet_create_with_mnemonic(&TWString::from_str(mnemonic), &TWString::from_str(""));
    let priv_key = priv_key_from_hdwallet(&hd_wallet, network);
	println!("Private key derived ({} bytes)", priv_key.len());

    let ldk_seed = ldk_seed_from_hdwallet(&hd_wallet, network);
    println!("LDK seed derived ({} bytes)", ldk_seed.len());

    if !save_private_keys(&priv_key, &ldk_seed) {
		println!("Could not save private keys");
		return None
	}
	// check back
	match read_private_keys() {
		None => {
			println!("Could not read back saved private keys");
			return None;
		},
		Some((_, _)) => println!("Private keys saved"),
	}

    Some(Wallet::from_pk(&priv_key, &ldk_seed, network))
}

pub fn load_wallet(network: Network) -> Option<Wallet> {
    match read_private_keys() {
        None => {
		    println!("Could not read wallet (private keys, {})", PK_FILENAME);
            return None;
        },
        Some((key1, key2)) => Some(Wallet::from_pk(&key1, &key2, network)),
    }
}

// Read the private keys from a file, 2x32 bytes, as hex string, concatenated
fn read_private_keys() -> Option<(Vec<u8>, Vec<u8>)> {
    let contents = fs::read_to_string(PK_FILENAME);
    match contents {
        Err(_e) => None,
        Ok(sraw) => {
            let s = sraw.trim();
            if s.len() < 2*2*32 {
                return None;
            }
            let key1_decode = hex::decode(s[0..2*32].to_string());
            match key1_decode {
                Err(_e) => None,
                Ok(key1) => {
                    let key2_decode = hex::decode(s[2*32..2*2*32].to_string());
                    match key2_decode {
                        Err(_e) => None,
                        Ok(key2) => {
                            Some((key1, key2))
                        },
                    }
                },
            }
        },
    }
}

fn save_private_keys(key1: &Vec<u8>, key2: &Vec<u8>) -> bool {
    let hex_string1 = hex::encode(key1);
    let hex_string2 = hex::encode(key2);
    match fs::write(PK_FILENAME, hex_string1.to_string() + &hex_string2) {
        Err(_) => return false,
        Ok(_) => return true,
    }
}

pub fn is_mnemonic_valid(mnemonic: &str) -> bool {
    return mnemonic_is_valid(&TWString::from_str(mnemonic));
}

pub fn priv_key_from_hdwallet_with_derivation(hd_wallet: &HDWallet, derivation_path: &str) -> Vec<u8> {
    let dp_twstring = TWString::from_str(derivation_path);
    let key = hd_wallet_get_key(&hd_wallet, 0, &dp_twstring);
    private_key_data(&key).to_vec()
}

pub fn priv_key_from_hdwallet(hd_wallet: &HDWallet, network: Network) -> Vec<u8> {
    let derivation_path = if network == Network::Testnet { "m/84'/1'/0'/0/0" } else { "m/84'/0'/0'/0/0" };
    priv_key_from_hdwallet_with_derivation(hd_wallet, derivation_path)
}

pub fn ldk_seed_from_hdwallet(hd_wallet: &HDWallet, network: Network) -> Vec<u8> {
    let derivation_path = if network == Network::Testnet { LN_SEED_DERIVATION_PATH_TESTNET } else { LN_SEED_DERIVATION_PATH };
    priv_key_from_hdwallet_with_derivation(hd_wallet, derivation_path)
}

pub fn priv_key_from_mnemonic(mnemonic: &str, network: Network) -> Vec<u8> {
    let wallet = hd_wallet_create_with_mnemonic(&TWString::from_str(mnemonic), &TWString::from_str(""));
    priv_key_from_hdwallet(&wallet, network)
}

fn derive_pubkey_from_pk_intern(priv_key: &Vec<u8>) -> PublicKey {
    let priv_key_obj = private_key_create_with_data(&TWData::from_vec(&priv_key));
    private_key_get_public_key_secp256k1(&priv_key_obj, true)
}

fn derive_pubkey_from_pk(priv_key: &Vec<u8>) -> Vec<u8> {
    let pub_key = derive_pubkey_from_pk_intern(priv_key);
    public_key_data(&pub_key).to_vec()
}

pub fn derive_address_from_pk(priv_key: &Vec<u8>, network: Network) -> String {
    let pub_key = derive_pubkey_from_pk_intern(priv_key);
    let derivation = match network {
        Network::Testnet => 4, // DerivationBitcoinTestnet
        Network::Bitcoin |
        _ => 0, // DerivationDefault
    };
    let any_addr = any_address_create_with_public_key_derivation(&pub_key, 0, derivation);
    let addr_twstring = any_address_description(&any_addr);
    addr_twstring.to_string()
}

impl Wallet {
    pub fn from_pk(priv_key: &Vec<u8>, ldk_seed: &Vec<u8>, network: Network) -> Wallet {
        Wallet {
            address: derive_address_from_pk(priv_key, network),
            private_key: priv_key.clone(),
            public_key: derive_pubkey_from_pk(&priv_key.clone()),
            utxos: Unspents { utxos: Vec::new() },
            balance: 0.0,
            seed_for_ldk: ldk_seed.clone(),
        }
    }

    pub fn print_address(&self) {
        println!("L1 wallet address: {}    pubkey:  {}", self.address, hex::encode(self.public_key.clone()));
    }

    pub fn print_balance(&self) {
        println!("L1 balance:  {}   utxos: {}", self.balance, self.utxos.utxos.len());
    }

    pub fn print(&self) {
        self.print_address();
        self.print_balance();
    }

    pub async fn retrieve_unspent(&self, bitcoind_client: &BitcoindClient) -> Unspents {
        bitcoind_client.list_unspent(0, self.address.as_str()).await
    }

    pub async fn retrieve_and_store_unspent(&mut self, bitcoind_client: &BitcoindClient)  {
        self.utxos = self.retrieve_unspent(bitcoind_client).await;
        self.balance = 0.0;
        for u in &self.utxos.utxos {
            self.balance += u.amount;
        }
    }

    pub fn create_send_tx(&self, to_address: &str, output_amount: u64) -> Vec<u8> {
        let mut signing_input = Bitcoin::SigningInput::new();
        signing_input.hash_type = 1; // hashTypeAll
        signing_input.amount = output_amount as i64;
        signing_input.use_max_amount = false;
        signing_input.byte_fee = 1; // TODO
        signing_input.to_address = to_address.to_string();
        signing_input.change_address = self.address.clone();
        signing_input.coin_type = 0;
        signing_input.private_key.push(self.private_key.clone());

        let mut sum_amount: i64 = 0;
        for u in &self.utxos.utxos {
            if u.address != self.address {
                println!("discarding utxo, not own-address {} {}", u.address, self.address);
            } else {
                let mut utxo = Bitcoin::UnspentTransaction::new();
                let mut outpoint = Bitcoin::OutPoint::new();
                let mut hash = hex::decode(u.tx_id.clone()).unwrap();
                hash.reverse();
                outpoint.hash = hash;
                outpoint.index = u.vout;
                outpoint.sequence = u32::MAX - 1;
                utxo.out_point = ::protobuf::MessageField::some(outpoint);
                utxo.script = hex::decode(&u.script_pub_key).unwrap();
                let amount_sat = (u.amount * 100_000_000.0) as i64;
                utxo.amount = amount_sat;
                //println!("input utxo  '{}' '{}' '{}' {}", u.address, u.script_pub_key, u.witness_script, utxo.amount);
                signing_input.utxo.push(utxo);
                sum_amount += amount_sat;
            }
        }
        if signing_input.utxo.len() == 0 {
            println!("Error: 0 utxos to consider");
            return Vec::new();
        }
        if signing_input.amount - 1 >= sum_amount {
            signing_input.use_max_amount = true;
        }

        let input_ser = signing_input.write_to_bytes().unwrap();
        let input_ser_data = TWData::from_vec(&input_ser);

        let output_ser_data = any_signer_sign(&input_ser_data, 0);

        let outputp: Bitcoin::SigningOutput = protobuf::Message::parse_from_bytes(&output_ser_data.to_vec()).unwrap();

        //println!("tx encoded: {}", hex::encode(outputp.encoded.clone()));
        println!("tx tx_id:   {}", outputp.transaction_id);
        //println!("tx error:   {} {}", outputp.error.unwrap() as u16, outputp.error_message);

        outputp.encoded
    }
}

// Replaces KeysManager, overriding get_shutdown_scriptpubkey()
pub struct WalletKeysManager {
    pub keys_manager: KeysManager,
    //wallet: Arc<Wallet>,
    shutdown_pubkey: bitcoin::secp256k1::PublicKey,
}

impl WalletKeysManager {
    pub fn new(wallet: &Arc<Wallet>, seed: &[u8; 32], starting_time_secs: u64, starting_time_nanos: u32) -> Self {
        WalletKeysManager {
            keys_manager: KeysManager::new(seed, starting_time_secs, starting_time_nanos),
            //wallet: wallet.clone(),
            shutdown_pubkey: bitcoin::secp256k1::PublicKey::from_slice(&wallet.public_key).unwrap(),
        }
    }

    /*
    fn derive_channel_keys(&self, channel_value_satoshis: u64, params: &[u8; 32]) -> InMemorySigner {
        self.keys_manager.derive_channel_keys(channel_value_satoshis, params)
    }
    */

    pub fn spend_spendable_outputs<C: Signing>(&self, descriptors: &[&SpendableOutputDescriptor], outputs: Vec<TxOut>, change_destination_script: Script, feerate_sat_per_1000_weight: u32, secp_ctx: &Secp256k1<C>) -> Option<Result<Transaction, ()>> {
        let shutdown_script: Script = ShutdownScript::new_p2wpkh_from_pubkey(self.shutdown_pubkey).into_inner();
        let mut is_any_different = false;
		for out in descriptors {
            let output = match out {
                StaticOutput { outpoint: _, output } => output,
                DelayedPaymentOutput(delayed) => &delayed.output,
                StaticPaymentOutput(static_o) => &static_o.output,
            };
            is_any_different |= output.script_pubkey != shutdown_script;
        }

        if !is_any_different {
            // output(s) is the shutdown pubkey, which does not need a sweep transfer
            println!("Output(s) became spendable, but it is (all are) to shutdown pubkey, no sweep tx needed ({})", descriptors.len());
            None
        } else {
            Some(self.keys_manager.spend_spendable_outputs(descriptors, outputs, change_destination_script, feerate_sat_per_1000_weight, secp_ctx))
        }
    }
}

impl KeysInterface for WalletKeysManager {
    type Signer = InMemorySigner;

	fn get_node_secret(&self, recipient: Recipient) -> Result<SecretKey, ()> {
        self.keys_manager.get_node_secret(recipient)
    }

	fn get_destination_script(&self) -> Script {
        self.keys_manager.get_destination_script()
    }

	fn get_shutdown_scriptpubkey(&self) -> ShutdownScript {
        // Overriden behavior: use 'external' L1 wallet address here, instead of shutdown address derived from LDK master key
        //self.keys_manager.get_shutdown_scriptpubkey()
        //let pubkey = bitcoin::secp256k1::PublicKey::from_slice(&self.wallet.public_key).unwrap();
        ShutdownScript::new_p2wpkh_from_pubkey(self.shutdown_pubkey)
    }

    fn get_channel_signer(&self, inbound: bool, channel_value_satoshis: u64) -> Self::Signer {
        self.keys_manager.get_channel_signer(inbound, channel_value_satoshis)
    }

    fn get_secure_random_bytes(&self) -> [u8; 32] {
        self.keys_manager.get_secure_random_bytes()
    }

	fn read_chan_signer(&self, reader: &[u8]) -> Result<Self::Signer, DecodeError> {
        self.keys_manager.read_chan_signer(reader)
    }

	fn sign_invoice(&self, hrp_bytes: &[u8], invoice_data: &[u5], receipient: Recipient) -> Result<RecoverableSignature, ()> {
        self.keys_manager.sign_invoice(hrp_bytes, invoice_data, receipient)
    }

	fn get_inbound_payment_key_material(&self) -> KeyMaterial {
        self.keys_manager.get_inbound_payment_key_material()
    }
}
