use std::{collections::BTreeMap, str::FromStr};

use hex_literal::hex;
// Substrate
use sc_chain_spec::{ChainType, Properties};
use sp_consensus_babe::AuthorityId as BabeId;
use sp_consensus_grandpa::AuthorityId as GrandpaId;
#[allow(unused_imports)]
use sp_core::ecdsa;
use sp_core::{Pair, Public, H160, U256, sr25519};
use sp_runtime::traits::{IdentifyAccount, Verify};
// Frontier
use bolarity_runtime::{
	AccountId, Balance, RuntimeGenesisConfig, SS58Prefix, Signature, WASM_BINARY,
};
use pallet_im_online::sr25519::AuthorityId as ImOnlineId;
use sp_authority_discovery::AuthorityId as AuthorityDiscoveryId;
use sp_mixnet::types::AuthorityId as MixnetId;
use sp_consensus_beefy::ecdsa_crypto::AuthorityId as BeefyId;
use bolarity_runtime::{ opaque::SessionKeys, BABE_GENESIS_EPOCH_CONFIG };

// The URL for the telemetry server.
// const STAGING_TELEMETRY_URL: &str = "wss://telemetry.polkadot.io/submit/";

/// Specialized `ChainSpec`. This is a specialization of the general Substrate ChainSpec type.
pub type ChainSpec = sc_service::GenericChainSpec<RuntimeGenesisConfig>;

/// Generate a crypto pair from seed.
pub fn get_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
	TPublic::Pair::from_string(&format!("//{}", seed), None)
		.expect("static values are valid; qed")
		.public()
}

#[allow(dead_code)]
type AccountPublic = <Signature as Verify>::Signer;

/// Generate an account ID from seed.
/// For use with `AccountId32`, `dead_code` if `AccountId20`.
#[allow(dead_code)]
pub fn get_account_id_from_seed<TPublic: Public>(seed: &str) -> AccountId
where
	AccountPublic: From<<TPublic::Pair as Pair>::Public>,
{
	AccountPublic::from(get_from_seed::<TPublic>(seed)).into_account()
}

pub fn authority_keys_from_seed(
	seed: &str,
) -> (GrandpaId, BabeId, ImOnlineId, AuthorityDiscoveryId, MixnetId, BeefyId)
{
	(
		get_from_seed::<GrandpaId>(seed),
		get_from_seed::<BabeId>(seed),
		get_from_seed::<ImOnlineId>(seed),
		get_from_seed::<AuthorityDiscoveryId>(seed),
		get_from_seed::<MixnetId>(seed),
		get_from_seed::<BeefyId>(seed),
	)
}

fn properties() -> Properties {
	let mut properties = Properties::new();
	properties.insert("tokenDecimals".into(), 18.into());
	properties.insert("ss58Format".into(), SS58Prefix::get().into());
	properties
}

const UNITS: Balance = 1_000_000_000_000_000_000;

fn session_keys(
	grandpa: GrandpaId,
	babe: BabeId,
	im_online: ImOnlineId,
	authority_discovery: AuthorityDiscoveryId,
	mixnet: MixnetId,
	beefy: BeefyId,
) -> SessionKeys {
	SessionKeys { grandpa, babe, im_online, authority_discovery, mixnet, beefy }
}

pub fn development_config(enable_manual_seal: bool) -> ChainSpec {
	ChainSpec::builder(WASM_BINARY.expect("WASM not available"), Default::default())
		.with_name("Development")
		.with_id("dev")
		.with_chain_type(ChainType::Development)
		.with_properties(properties())
		.with_genesis_config_patch(testnet_genesis(
			// Sudo account (Alith)
			AccountId::from(hex!("f24FF3a9CF04c71Dbc94D0b566f7A27B94566cac")),
			// Pre-funded accounts
			vec![
				AccountId::from(hex!("f24FF3a9CF04c71Dbc94D0b566f7A27B94566cac")), // Alith
				AccountId::from(hex!("3Cd0A705a2DC65e5b1E1205896BaA2be8A07c6e0")), // Baltathar
				AccountId::from(hex!("798d4Ba9baf0064Ec19eB4F0a1a45785ae9D6DFc")), // Charleth
				AccountId::from(hex!("773539d4Ac0e786233D90A233654ccEE26a613D9")), // Dorothy
				AccountId::from(hex!("Ff64d3F6efE2317EE2807d223a0Bdc4c0c49dfDB")), // Ethan
				AccountId::from(hex!("C0F0f4ab324C46e55D02D0033343B4Be8A55532d")), // Faith
			],
			// Initial PoA authorities
			vec![authority_keys_from_seed("Alice")],
			// Ethereum chain ID
			SS58Prefix::get() as u64,
			enable_manual_seal,
		))
		.build()
}

pub fn local_testnet_config() -> ChainSpec {
	ChainSpec::builder(WASM_BINARY.expect("WASM not available"), Default::default())
		.with_name("Local Testnet")
		.with_id("local_testnet")
		.with_chain_type(ChainType::Local)
		.with_properties(properties())
		.with_genesis_config_patch(testnet_genesis(
			// Sudo account (Alith)
			AccountId::from(hex!("f24FF3a9CF04c71Dbc94D0b566f7A27B94566cac")),
			// Pre-funded accounts
			vec![
				AccountId::from(hex!("f24FF3a9CF04c71Dbc94D0b566f7A27B94566cac")), // Alith
				AccountId::from(hex!("3Cd0A705a2DC65e5b1E1205896BaA2be8A07c6e0")), // Baltathar
				AccountId::from(hex!("798d4Ba9baf0064Ec19eB4F0a1a45785ae9D6DFc")), // Charleth
				AccountId::from(hex!("773539d4Ac0e786233D90A233654ccEE26a613D9")), // Dorothy
				AccountId::from(hex!("Ff64d3F6efE2317EE2807d223a0Bdc4c0c49dfDB")), // Ethan
				AccountId::from(hex!("C0F0f4ab324C46e55D02D0033343B4Be8A55532d")), // Faith
			],
			vec![
				authority_keys_from_seed("Alice"),
				authority_keys_from_seed("Bob"),
			],
			42,
			false,
		))
		.build()
}

/// Configure initial storage state for FRAME modules.
fn testnet_genesis(
	sudo_key: AccountId,
	endowed_accounts: Vec<AccountId>,
	initial_authorities: Vec<(GrandpaId, BabeId, ImOnlineId, AuthorityDiscoveryId, MixnetId, BeefyId)>,
	chain_id: u64,
	enable_manual_seal: bool,
) -> serde_json::Value {
	let evm_accounts = {
		let mut map = BTreeMap::new();
		map.insert(
			// H160 address of Alice dev account
			// Derived from SS58 (42 prefix) address
			// SS58: 5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY
			// hex: 0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d
			// Using the full hex key, truncating to the first 20 bytes (the first 40 hex chars)
			H160::from_str("d43593c715fdd31c61141abd04a99fd6822c8558")
				.expect("internal H160 is valid; qed"),
			fp_evm::GenesisAccount {
				balance: U256::from_str("0xffffffffffffffffffffffffffffffff")
					.expect("internal U256 is valid; qed"),
				code: Default::default(),
				nonce: Default::default(),
				storage: Default::default(),
			},
		);
		map.insert(
			// H160 address of CI test runner account
			H160::from_str("6be02d1d3665660d22ff9624b7be0551ee1ac91b")
				.expect("internal H160 is valid; qed"),
			fp_evm::GenesisAccount {
				balance: U256::from_str("0xffffffffffffffffffffffffffffffff")
					.expect("internal U256 is valid; qed"),
				code: Default::default(),
				nonce: Default::default(),
				storage: Default::default(),
			},
		);
		map.insert(
			// H160 address for benchmark usage
			H160::from_str("1000000000000000000000000000000000000001")
				.expect("internal H160 is valid; qed"),
			fp_evm::GenesisAccount {
				nonce: U256::from(1),
				balance: U256::from(1_000_000_000_000_000_000_000_000u128),
				storage: Default::default(),
				code: vec![0x00],
			},
		);
		map
	};

	serde_json::json!({
		"sudo": { "key": Some(sudo_key) },
		"session": {
			"keys": initial_authorities
				.iter()
				.map(|x| {
					(
						session_keys(
							x.0.clone(),
							x.1.clone(),
							x.2.clone(),
							x.3.clone(),
							x.4.clone(),
							x.5.clone(),
						)
					)
				})
				.collect::<Vec<_>>()
		},
		"balances": {
			"balances": endowed_accounts
				.iter()
				.cloned()
				.map(|k| (k, 1_000_000 * UNITS))
				.collect::<Vec<_>>()
		},
		"babe": { "epochConfig": Some(BABE_GENESIS_EPOCH_CONFIG) },
		// "grandpa": { "authorities": initial_authorities.iter().map(|x| (x.1.clone(), 1)).collect::<Vec<_>>() },
		"evmChainId": { "chainId": chain_id },
		"evm": { "accounts": evm_accounts },
		"manualSeal": { "enable": enable_manual_seal }
	})
}
