// Copyright (C) HybridVM.
// This file is part of HybridVM.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::*;

use fp_evm::{CallInfo, ExitSucceed, UsedGas};
use hp_system::{AccountIdMapping, U256BalanceMapping};
use pallet_contracts::{CollectEvents, DebugInfo, Determinism};
use pallet_evm::AddressMapping;
use pallet_hybrid_vm::UnifiedAddress;
use precompile_utils::{
	prelude::*,
	solidity::codec::{
		bytes::{BoundedBytesString, BytesKind, StringKind},
		Reader, Writer,
	},
};
use sp_runtime::{traits::ConstU32, DispatchError};
use crate::alloc::{boxed::Box, string::ToString};

fn str2s(s: String) -> &'static str {
	Box::leak(s.into_boxed_str())
}

macro_rules! b {
	($data_type:ident, $winput:ident, $reader:ident, $err_data:ident, $($s:expr, $t:ty)*) => {
		$(
			if $data_type == $s {
				<$t>::read(&mut $reader).map_err(|_| $err_data)?.encode_to(&mut $winput);
                continue;
			}
		)*
	}
}

macro_rules! c {
	($data_type:ident, $writer:ident, $woutput:ident, $($s:expr, $t:ty)*) => {
		$(
			if $data_type == $s {
				$writer = $writer.write(<$t as Decode>::decode(&mut $woutput).map_err(|_| 2)?);
				continue;
			}
		)*
	}
}
impl<T: Config> Pallet<T> {
	pub fn is_hybrid_vm_transaction(transaction: Transaction) -> bool {
		let action = {
			match transaction {
				Transaction::Legacy(t) => t.action,
				Transaction::EIP2930(t) => t.action,
				Transaction::EIP1559(t) => t.action,
			}
		};

		match action {
			ethereum::TransactionAction::Call(target) => {
				if pallet_hybrid_vm::HvmContracts::<T>::contains_key(target) {
					return true;
				}
			},
			_ => {},
		}

		false
	}

	fn build_wasm_call<'a>(
		input: &Vec<u8>,
		abi0: [u8; 4],
		abi_fun: &'a str,
	) -> Result<(Vec<u8>, Vec<&'a str>), DispatchErrorWithPostInfo> {
		let err = DispatchErrorWithPostInfo {
			post_info: PostDispatchInfo { actual_weight: None, pays_fee: Pays::Yes },
			error: DispatchError::from("Fun abi error(REVERT)"),
		};

		let err_data = DispatchErrorWithPostInfo {
			post_info: PostDispatchInfo { actual_weight: None, pays_fee: Pays::Yes },
			error: DispatchError::from("Decode input data error(REVERT)"),
		};

		let index_s1 = abi_fun.find('(').ok_or(err)?;
		let index_e1 = abi_fun.find(')').ok_or(err)?;

		let mut index_s2: usize = 0;
		let mut index_e2: usize = 1;

		if abi_fun.len() > index_e1 {
			if abi_fun[index_e1 + 1..].find('(').is_some() {
				index_s2 = abi_fun[index_e1 + 1..].find('(').ok_or(err)? + index_e1 + 1;
				index_e2 = abi_fun[index_e1 + 1..].find(')').ok_or(err)? + index_e1 + 1;
			}
		}

		if index_e1 < index_s1 || index_e2 < index_s2 {
			return Err(err);
		}

		let input_type: Vec<&str> = abi_fun[index_s1 + 1..index_e1].split(',').collect();
		let output_type: Vec<&str> = abi_fun[index_s2 + 1..index_e2].split(',').collect();

		// wasm type: AccountId,bool,Vec<u8>,H256,String,u8,u16,u32,u64,u128,U256,Vec<T>
		let data_type = "address,bool,bytes,bytes32,string,uint8,uint16,uint32,uint64,uint128,uint256,address[],bool[],bytes32[],uint8[],uint16[],uint32[],uint64[],uint128[],uint256[]";

		if input_type.iter().find(|&x| data_type.find(x).is_none()).is_some() {
			return Err(err);
		}
		if output_type.iter().find(|&x| data_type.find(x).is_none()).is_some() {
			return Err(err);
		}

		let mut winput: Vec<u8> = vec![];
		abi0.encode_to(&mut winput);

		let mut reader = Reader::new_skip_selector(input).map_err(|_| err_data)?;

		for data_type in input_type {
			if data_type == "address" {
				let address = Address::read(&mut reader).map_err(|_| err_data)?;
				let account_id =
					<T as pallet_evm::Config>::AddressMapping::into_account_id(address.into());
				account_id.encode_to(&mut winput);
				continue;
			} else if data_type == "address[]" {
				let addresses = Vec::<Address>::read(&mut reader).map_err(|_| err_data)?;
				let account_ids: Vec<_> = addresses
					.iter()
					.map(|&x| <T as pallet_evm::Config>::AddressMapping::into_account_id(x.into()))
					.collect();
				account_ids.encode_to(&mut winput);
				continue;
			} else if data_type == "bytes" {
				Vec::<u8>::from(
					BoundedBytesString::<BytesKind, ConstU32<{ u32::MAX }>>::read(&mut reader)
						.map_err(|_| err_data)?,
				)
				.encode_to(&mut winput);
				continue;
			} else if data_type == "string" {
				String::try_from(
					BoundedBytesString::<StringKind, ConstU32<{ u32::MAX }>>::read(&mut reader)
						.map_err(|_| err_data)?,
				)
				.map_err(|_| err_data)?
				.encode_to(&mut winput);
				continue;
			}

			b!(data_type, winput, reader, err_data, "bool", bool "bytes32", H256 "uint8", u8 "uint16", u16 "uint32", u32 "uint64", u64 "uint128", u128 "uint256", U256);
			b!(data_type, winput, reader, err_data, "bool[]", bool "bytes32[]", H256 "uint8[]", u8 "uint16[]", u16 "uint32[]", u32 "uint64[]", u64 "uint128[]", u128 "uint256[]", U256);

			return Err(err_data);
		}

		Ok((winput, output_type))
	}

	fn convert_wasm_return(wasm_output: Vec<u8>, output_type: Vec<&str>) -> Result<Vec<u8>, u8> {
		let mut woutput = wasm_output.as_slice();
		_ = <Result<(), ()> as Decode>::decode(&mut woutput).map_err(|_| 1)?;

		let mut writer = Writer::new();
		for data_type in output_type {
			if data_type == "address" {
				let account_id =
					<<T as frame_system::Config>::AccountId as Decode>::decode(&mut woutput)
						.map_err(|_| 3)?;
				// address: H160
				let address =
					<T as pallet_hybrid_vm::Config>::AccountIdMapping::into_address(account_id);
				writer = writer.write(Address::from(address));
				continue;
			} else if data_type == "address[]" {
				let account_ids =
					<Vec<<T as frame_system::Config>::AccountId> as Decode>::decode(&mut woutput)
						.map_err(|_| 4)?;
				for account_id in account_ids {
					let address =
						<T as pallet_hybrid_vm::Config>::AccountIdMapping::into_address(account_id);
					writer = writer.write(Address::from(address));
				}
				continue;
			} else if data_type == "bytes" {
				let bounded_bytes = BoundedBytesString::<BytesKind, ConstU32<{ u32::MAX }>>::from(
					<Vec<u8> as Decode>::decode(&mut woutput).map_err(|_| 5)?,
				);
				writer = writer.write(bounded_bytes);
				continue;
			} else if data_type == "string" {
				let bounded_string =
					BoundedBytesString::<StringKind, ConstU32<{ u32::MAX }>>::try_from(
						<String as Decode>::decode(&mut woutput).map_err(|_| 5)?,
					)
					.map_err(|_| 5)?;
				writer = writer.write(bounded_string);
				continue;
			}

			c!(data_type, writer, woutput, "bool", bool "bytes32", H256 "uint8", u8 "uint16", u16 "uint32", u32 "uint64", u64 "uint128", u128 "uint256", U256);
			c!(data_type, writer, woutput, "bool[]", bool "bytes32[]", H256 "uint8[]", u8 "uint16[]", u16 "uint32[]", u32 "uint64[]", u64 "uint128[]", u128 "uint256[]", U256);

			return Err(6);
		}

		Ok(writer.build())
	}

	pub fn call_hybrid_vm(
		source: H160,
		transaction: Transaction,
	) -> Result<(PostDispatchInfo, CallOrCreateInfo), DispatchErrorWithPostInfo> {
		let (
			input,
			value,
			gas_limit,
			_max_fee_per_gas,
			_max_priority_fee_per_gas,
			_nonce,
			action,
			_access_list,
		) = {
			match transaction {
				// max_fee_per_gas and max_priority_fee_per_gas in legacy and 2930 transactions is
				// the provided gas_price.
				Transaction::Legacy(t) => (
					t.input.clone(),
					t.value,
					t.gas_limit,
					Some(t.gas_price),
					Some(t.gas_price),
					Some(t.nonce),
					t.action,
					Vec::new(),
				),
				Transaction::EIP2930(t) => {
					let access_list: Vec<(H160, Vec<H256>)> = t
						.access_list
						.iter()
						.map(|item| (item.address, item.storage_keys.clone()))
						.collect();
					(
						t.input.clone(),
						t.value,
						t.gas_limit,
						Some(t.gas_price),
						Some(t.gas_price),
						Some(t.nonce),
						t.action,
						access_list,
					)
				},
				Transaction::EIP1559(t) => {
					let access_list: Vec<(H160, Vec<H256>)> = t
						.access_list
						.iter()
						.map(|item| (item.address, item.storage_keys.clone()))
						.collect();
					(
						t.input.clone(),
						t.value,
						t.gas_limit,
						Some(t.max_fee_per_gas),
						Some(t.max_priority_fee_per_gas),
						Some(t.nonce),
						t.action,
						access_list,
					)
				},
			}
		};

		match action {
			ethereum::TransactionAction::Call(target) => {
				let vm_target = pallet_hybrid_vm::Pallet::<T>::hvm_contracts(target);
				match vm_target {
					Some(UnifiedAddress::<T>::WasmVM(t)) => {
						let selector = if input.len() < 4 {
							0
						} else {
							let mut a: [u8; 4] = Default::default();
							a.copy_from_slice(&input[0..4]);
							u32::from_be_bytes(a)
						};

						let abi = pallet_hybrid_vm::Pallet::<T>::evm_fun_abi(target, selector)
							.ok_or(DispatchErrorWithPostInfo {
								post_info: PostDispatchInfo {
									actual_weight: None,
									pays_fee: Pays::Yes,
								},
								error: DispatchError::from("No abi of the selector(REVERT)"),
							})?;

						let err = DispatchErrorWithPostInfo {
							post_info: PostDispatchInfo {
								actual_weight: None,
								pays_fee: Pays::Yes,
							},
							error: DispatchError::from("Fun abi error(REVERT)"),
						};
						let abi_fun = String::from_utf8(abi.1.to_vec()).map_err(|_| err)?;
						let (wasm_call, output_type) =
							Self::build_wasm_call(&input, abi.0, &abi_fun)?;

						let mut gas_limit_u64 = u64::max_value();
						if gas_limit.lt(&U256::from(gas_limit_u64)) {
							gas_limit_u64 = gas_limit.as_u64();
						}
						let weight_limit: Weight =
							<T as pallet_evm::Config>::GasWeightMapping::gas_to_weight(
								gas_limit_u64,
								false,
							);

						let origin =
							<T as pallet_evm::Config>::AddressMapping::into_account_id(source);
						let balance_result =
							<T as pallet_hybrid_vm::Config>::U256BalanceMapping::u256_to_balance(
								value,
							);
						let balance = match balance_result {
							Ok(t) => t,
							Err(_) => {
								return Err(DispatchErrorWithPostInfo {
									post_info: PostDispatchInfo {
										actual_weight: None,
										pays_fee: Pays::Yes,
									},
									error: DispatchError::from(
										"Call HybridVM Contract value is error(REVERT)",
									),
								})
							},
						};

						let info = pallet_contracts::Pallet::<T>::bare_call(
							origin,
							t.into(),
							balance,
							weight_limit,
							None,
							wasm_call,
							DebugInfo::Skip,
							CollectEvents::Skip,
							Determinism::Enforced,
						);

						match info.result {
							Ok(return_value) => {
								if !return_value.did_revert() {
									// because return_value.data = MessageResult<T, E>, so, the
									// first byte is zhe Ok() Code, be removed
									let err_data = DispatchErrorWithPostInfo {
										post_info: PostDispatchInfo {
											actual_weight: Some(info.gas_consumed),
											pays_fee: Pays::Yes,
										},
										error: DispatchError::from("Return data decode error!"),
									};
									let output =
										Self::convert_wasm_return(return_value.data, output_type)
											.map_err(|_| err_data)?;

									let call_info = CallInfo {
								        exit_reason: ExitReason::Succeed(ExitSucceed::Returned),
								        value: output,
								        used_gas: UsedGas {
									        standard: U256::from(
										        <T as pallet_evm::Config>::GasWeightMapping::weight_to_gas(
											    info.gas_consumed,
										        ),
									        ),
									        effective: U256::from(0u64),
								        },
								        weight_info: None,
								        logs: vec![],
							        };
									return Ok((
										PostDispatchInfo {
											actual_weight: Some(info.gas_consumed),
											pays_fee: Pays::Yes,
										},
										CallOrCreateInfo::Call(call_info),
									));
								} else {
									let mut return_code = String::from("None");
									if return_value.data.len() > 1 {
										return_code = return_value.data[1].to_string();
									}
									return Err(DispatchErrorWithPostInfo {
										post_info: PostDispatchInfo {
											actual_weight: Some(info.gas_consumed),
											pays_fee: Pays::Yes,
										},
										error: DispatchError::from(str2s(
											["Call wasm contract failed(REVERT):", &return_code]
												.concat(),
										)),
									});
								}
							},
							Err(e) => {
								return Err(DispatchErrorWithPostInfo {
									post_info: PostDispatchInfo {
										actual_weight: None,
										pays_fee: Pays::Yes,
									},
									error: e,
								});
							},
						}
					},
					None => {
						return Err(DispatchErrorWithPostInfo {
							post_info: PostDispatchInfo {
								actual_weight: None,
								pays_fee: Pays::Yes,
							},
							error: DispatchError::from("Not HybridVM Contract(REVERT)"),
						});
					},
				};
			},
			_ => {
				return Err(DispatchErrorWithPostInfo {
					post_info: PostDispatchInfo { actual_weight: None, pays_fee: Pays::Yes },
					error: DispatchError::from("Not HybridVM Contract Call(REVERT)"),
				});
			},
		}
	}
}