// Modified by 2024 HybridVM

// Modified by 2021 Cycan Technologies 

// Copyright 2018-2021 Parity Technologies (UK) Ltd.
//
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

// Modified by Alex Wang
#![recursion_limit = "256"]

#![cfg_attr(not(feature = "std"), no_std, no_main)]

use scale_info::{build, MetaType, Path, Type, TypeInfo};
use ink_env::{Environment};
use ink_metadata::layout::{Layout, LayoutKey, LeafLayout};
use ink_prelude::string::String;
// use scale_info::TypeInfo;
use sp_core::H160;
use ink_prelude::vec::Vec;
use ink_primitives::Key;
use ink_storage::traits::StorageLayout;
use scale_encode::{EncodeAsType};
use scale_decode::{visitor, DecodeAsType, IntoVisitor, Visitor, Error};
use scale::{Encode, Decode, MaxEncodedLen};
use scale_decode::error::ErrorKind::WrongLength;
use scale_decode::visitor::{DecodeAsTypeResult, DecodeError, TypeIdFor, Unexpected};
use scale_type_resolver::TypeResolver;
// use ink_metadata::TypeInfo as InkTypeInfo;

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Default, Hash, Debug)]
#[derive(Encode, Decode, MaxEncodedLen)]
pub struct AccountId20(pub [u8; 20]);

#[cfg(feature = "serde")]
impl_serde::impl_fixed_hash_serde!(AccountId20, 20);

impl StorageLayout for AccountId20 {
    fn layout(key: &u32) -> Layout {
        Layout::Leaf(LeafLayout::from_key::<AccountId20>(LayoutKey::from(key)))
    }
}

impl EncodeAsType for AccountId20 {
    fn encode_as_type_to<R: TypeResolver>(
        &self,
        _type_id: &R::TypeId,
        _types: &R,
        out: &mut Vec<u8>,
    ) -> Result<(), scale_encode::Error> {
        out.extend_from_slice(&self.0);
        Ok(())
    }
}

impl TypeInfo for AccountId20 {
    type Identity = Self;

    fn type_info() -> Type {
        Type::builder()
            .path(Path::new("AccountId20", "my_crate::path"))
            .composite(
                build::Fields::unnamed()
                    .field(|f| f.ty::<[u8; 20]>())
            )
    }
}


pub struct AccountId20Visitor<R: TypeResolver> {
    _marker: std::marker::PhantomData<R>,
}

impl<R: TypeResolver> AccountId20Visitor<R> {
    pub fn new() -> Self {
        Self {
            _marker: std::marker::PhantomData,
        }
    }
}


impl<'scale, 'resolver, R: TypeResolver> Visitor for AccountId20Visitor<R> {
    type Value<'s, 'r> = AccountId20;
    type Error = scale_decode::Error;
    type TypeResolver = R;

    fn unchecked_decode_as_type<'s, 'r>(
        self,
        input: &mut &'s [u8],
        _type_id: &TypeIdFor<Self>,
        _types: &'r Self::TypeResolver,
    ) -> DecodeAsTypeResult<Self, Result<Self::Value<'s, 'r>, Self::Error>> {
        let mut array = [0u8; 20];
        if input.len() < 20 {
            return DecodeAsTypeResult::Decoded(Err(Error::new(WrongLength{expected_len: 20, actual_len: input.len()})));
        }
        array.copy_from_slice(&input[..20]);
        *input = &input[20..];
        DecodeAsTypeResult::Decoded(Ok(AccountId20(array)))
    }

    fn visit_unexpected<'s, 'r>(
        self,
        unexpected: Unexpected,
    ) -> Result<Self::Value<'s, 'r>, Self::Error> {
        Err(DecodeError::Unexpected(unexpected).into())
    }

    fn visit_bool<'s, 'r>(
        self,
        _value: bool,
        _type_id: &TypeIdFor<Self>,
    ) -> Result<Self::Value<'s, 'r>, Self::Error> {
        self.visit_unexpected(Unexpected::Bool)
    }

    fn visit_char<'s, 'r>(
        self,
        _value: char,
        _type_id: &TypeIdFor<Self>,
    ) -> Result<Self::Value<'s, 'r>, Self::Error> {
        self.visit_unexpected(Unexpected::Char)
    }

    fn visit_u8<'s, 'r>(
        self,
        _value: u8,
        _type_id: &TypeIdFor<Self>,
    ) -> Result<Self::Value<'s, 'r>, Self::Error> {
        self.visit_unexpected(Unexpected::U8)
    }

    fn visit_u16<'s, 'r>(
        self,
        _value: u16,
        _type_id: &TypeIdFor<Self>,
    ) -> Result<Self::Value<'s, 'r>, Self::Error> {
        self.visit_unexpected(Unexpected::U16)
    }

    fn visit_u32<'s, 'r>(
        self,
        _value: u32,
        _type_id: &TypeIdFor<Self>,
    ) -> Result<Self::Value<'s, 'r>, Self::Error> {
        self.visit_unexpected(Unexpected::U32)
    }

    fn visit_u64<'s, 'r>(
        self,
        _value: u64,
        _type_id: &TypeIdFor<Self>,
    ) -> Result<Self::Value<'s, 'r>, Self::Error> {
        self.visit_unexpected(Unexpected::U64)
    }

    fn visit_u128<'s, 'r>(
        self,
        _value: u128,
        _type_id: &TypeIdFor<Self>,
    ) -> Result<Self::Value<'s, 'r>, Self::Error> {
        self.visit_unexpected(Unexpected::U128)
    }

    fn visit_u256<'s, 'r>(
        self,
        _value: &'s [u8; 32],
        _type_id: &TypeIdFor<Self>,
    ) -> Result<Self::Value<'s, 'r>, Self::Error> {
        self.visit_unexpected(Unexpected::U256)
    }

    fn visit_i8<'s, 'r>(
        self,
        _value: i8,
        _type_id: &TypeIdFor<Self>,
    ) -> Result<Self::Value<'s, 'r>, Self::Error> {
        self.visit_unexpected(Unexpected::I8)
    }

    fn visit_i16<'s, 'r>(
        self,
        _value: i16,
        _type_id: &TypeIdFor<Self>,
    ) -> Result<Self::Value<'s, 'r>, Self::Error> {
        self.visit_unexpected(Unexpected::I16)
    }

    fn visit_i32<'s, 'r>(
        self,
        _value: i32,
        _type_id: &TypeIdFor<Self>,
    ) -> Result<Self::Value<'s, 'r>, Self::Error> {
        self.visit_unexpected(Unexpected::I32)
    }

    fn visit_i64<'s, 'r>(
        self,
        _value: i64,
        _type_id: &TypeIdFor<Self>,
    ) -> Result<Self::Value<'s, 'r>, Self::Error> {
        self.visit_unexpected(Unexpected::I64)
    }

    fn visit_i128<'s, 'r>(
        self,
        _value: i128,
        _type_id: &TypeIdFor<Self>,
    ) -> Result<Self::Value<'s, 'r>, Self::Error> {
        self.visit_unexpected(Unexpected::I128)
    }

    fn visit_i256<'s, 'r>(
        self,
        _value: &'s [u8; 32],
        _type_id: &TypeIdFor<Self>,
    ) -> Result<Self::Value<'s, 'r>, Self::Error> {
        self.visit_unexpected(Unexpected::I256)
    }

    fn visit_sequence<'s, 'r>(
        self,
        _value: &mut scale_decode::visitor::types::Sequence<'s, 'r, Self::TypeResolver>,
        _type_id: &TypeIdFor<Self>,
    ) -> Result<Self::Value<'s, 'r>, Self::Error> {
        self.visit_unexpected(Unexpected::Sequence)
    }

    fn visit_composite<'s, 'r>(
        self,
        _value: &mut scale_decode::visitor::types::Composite<'s, 'r, Self::TypeResolver>,
        _type_id: &TypeIdFor<Self>,
    ) -> Result<Self::Value<'s, 'r>, Self::Error> {
        self.visit_unexpected(Unexpected::Composite)
    }

    fn visit_tuple<'s, 'r>(
        self,
        _value: &mut scale_decode::visitor::types::Tuple<'s, 'r, Self::TypeResolver>,
        _type_id: &TypeIdFor<Self>,
    ) -> Result<Self::Value<'s, 'r>, Self::Error> {
        self.visit_unexpected(Unexpected::Tuple)
    }

    fn visit_str<'s, 'r>(
        self,
        _value: &mut scale_decode::visitor::types::Str<'s>,
        _type_id: &TypeIdFor<Self>,
    ) -> Result<Self::Value<'s, 'r>, Self::Error> {
        self.visit_unexpected(Unexpected::Str)
    }

    fn visit_variant<'s, 'r>(
        self,
        _value: &mut scale_decode::visitor::types::Variant<'s, 'r, Self::TypeResolver>,
        _type_id: &TypeIdFor<Self>,
    ) -> Result<Self::Value<'s, 'r>, Self::Error> {
        self.visit_unexpected(Unexpected::Variant)
    }

    fn visit_array<'s, 'r>(
        self,
        _value: &mut scale_decode::visitor::types::Array<'s, 'r, Self::TypeResolver>,
        _type_id: &TypeIdFor<Self>,
    ) -> Result<Self::Value<'s, 'r>, Self::Error> {
        self.visit_unexpected(Unexpected::Array)
    }

    fn visit_bitsequence<'s, 'r>(
        self,
        _value: &mut scale_decode::visitor::types::BitSequence<'s>,
        _type_id: &TypeIdFor<Self>,
    ) -> Result<Self::Value<'s, 'r>, Self::Error> {
        self.visit_unexpected(Unexpected::Bitsequence)
    }
}

impl IntoVisitor for AccountId20 {
    type AnyVisitor<R: TypeResolver> = AccountId20Visitor<R>;

    fn into_visitor<R: TypeResolver>() -> Self::AnyVisitor<R> {
        AccountId20Visitor::new()
    }
}

// impl DecodeAsType for AccountId20 {
//     fn decode_as_type<R: TypeResolver>(
//         input: &mut &[u8],
//         type_id: &R::TypeId,
//         types: &R,
//     ) -> Result<Self, scale_decode::Error> {
//         Self::decode_as_type_maybe_compact(input, type_id, types, false)
//     }
//
//     fn decode_as_type_maybe_compact<R: TypeResolver>(
//         input: &mut &[u8],
//         _type_id: &R::TypeId,
//         _types: &R,
//         _is_compact: bool,
//     ) -> Result<Self, scale_decode::Error> {
//         let mut array = [0u8; 20];
//         if input.len() < 20 {
//             return Err(scale_decode::Error::custom_str("Invalid length for AccountId20"));
//         }
//         array.copy_from_slice(&input[..20]);
//         *input = &input[20..];
//         Ok(AccountId20(array))
//     }
// }


// impl core::str::FromStr for AccountId20 {
//     type Err = &'static str;
//
//     fn from_str(s: &str) -> Result<Self, Self::Err> {
//         H160::from_str(s)
//             .map(Into::into)
//             .map_err(|_| "invalid hex address.")
//     }
// }
//
// impl fmt::Display for AccountId20 {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         let address = hex::encode(self.0).trim_start_matches("0x").to_lowercase();
//         let address_hash = hex::encode(keccak_256(address.as_bytes()));
//
//         let checksum: String =
//             address
//                 .char_indices()
//                 .fold(String::from("0x"), |mut acc, (index, address_char)| {
//                     let n = u16::from_str_radix(&address_hash[index..index + 1], 16)
//                         .expect("Keccak256 hashed; qed");
//
//                     if n > 7 {
//                         // make char uppercase if ith character is 9..f
//                         acc.push_str(&address_char.to_uppercase().to_string())
//                     } else {
//                         // already lowercased
//                         acc.push(address_char)
//                     }
//
//                     acc
//                 });
//         write!(f, "{checksum}")
//     }
// }
//
// impl fmt::Debug for AccountId20 {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         write!(f, "{:?}", H160(self.0))
//     }
// }
//
// impl From<[u8; 20]> for AccountId20 {
//     fn from(bytes: [u8; 20]) -> Self {
//         Self(bytes)
//     }
// }
//
// impl<'a> TryFrom<&'a [u8]> for AccountId20 {
//     type Error = ();
//     fn try_from(x: &'a [u8]) -> Result<AccountId20, ()> {
//         if x.len() == 20 {
//             let mut data = [0; 20];
//             data.copy_from_slice(x);
//             Ok(AccountId20(data))
//         } else {
//             Err(())
//         }
//     }
// }
//
// impl From<AccountId20> for [u8; 20] {
//     fn from(val: AccountId20) -> Self {
//         val.0
//     }
// }
//
// impl From<H160> for AccountId20 {
//     fn from(h160: H160) -> Self {
//         Self(h160.0)
//     }
// }
//
// impl From<AccountId20> for H160 {
//     fn from(val: AccountId20) -> Self {
//         H160(val.0)
//     }
// }

impl AsRef<[u8]> for AccountId20 {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl AsMut<[u8]> for AccountId20 {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0[..]
    }
}

impl AsRef<[u8; 20]> for AccountId20 {
    fn as_ref(&self) -> &[u8; 20] {
        &self.0
    }
}

impl AsMut<[u8; 20]> for AccountId20 {
    fn as_mut(&mut self) -> &mut [u8; 20] {
        &mut self.0
    }
}

// impl From<ecdsa::Public> for AccountId20 {
//     fn from(pk: ecdsa::Public) -> Self {
//         let decompressed = libsecp256k1::PublicKey::parse_compressed(&pk.0)
//             .expect("Wrong compressed public key provided")
//             .serialize();
//         let mut m = [0u8; 64];
//         m.copy_from_slice(&decompressed[1..65]);
//         let account = H160::from(H256::from(keccak_256(&m)));
//         Self(account.into())
//     }
// }

impl From<[u8; 32]> for AccountId20 {
    fn from(bytes: [u8; 32]) -> Self {
        let mut buffer = [0u8; 20];
        buffer.copy_from_slice(&bytes[..20]);
        Self(buffer)
    }
}

// impl From<AccountId32> for AccountId20 {
//     fn from(account: AccountId32) -> Self {
//         let bytes: &[u8; 32] = account.as_ref();
//         Self::from(*bytes)
//     }
// }

type AccountId = AccountId20;

#[ink::chain_extension( extension = 0 )]
pub trait MyChainExtension {
        type ErrorCode = i32;
		
        #[ink(function = 5, handle_status = false)]
        fn call_evm_extension(vm_input: Vec<u8>) -> String;
		#[ink(function = 6, handle_status = false)]
        fn h160_to_accountid(evm_address: H160) -> AccountId;
}


#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub enum CustomEnvironment {}

impl Environment for CustomEnvironment {
    const MAX_EVENT_TOPICS: usize =
        <ink_env::DefaultEnvironment as Environment>::MAX_EVENT_TOPICS;

    type AccountId = AccountId;
    type Balance = <ink_env::DefaultEnvironment as Environment>::Balance;
    type Hash = <ink_env::DefaultEnvironment as Environment>::Hash;
    type BlockNumber = <ink_env::DefaultEnvironment as Environment>::BlockNumber;
    type Timestamp = <ink_env::DefaultEnvironment as Environment>::Timestamp;
    //type RentFraction = <ink_env::DefaultEnvironment as Environment>::RentFraction;

    type ChainExtension = MyChainExtension;
}

#[ink::contract(env = crate::CustomEnvironment)]
mod erc20 {
    //#[cfg(not(feature = "ink-as-dependency"))]
    use ink::storage::Lazy;
	use ink::storage::Mapping as StorageHashMap;
	
	use ink_env::{hash, ReturnFlags};
    use ink_prelude::string::String;
    use ink_prelude::string::ToString;
	use ink_prelude::vec;
	use ink_prelude::vec::Vec;
	use precompile_utils::prelude::*;
    use sp_core::U256;
	
	
    /// A simple ERC-20 contract.
    #[ink(storage)]
    pub struct Erc20 {
        /// Total token supply.
        total_supply: Balance,  //Lazy(Balance),
        /// Mapping from owner to number of owned token.
        balances: StorageHashMap<AccountId, Balance>,
        /// Mapping of the token amount which an account is allowed to withdraw
        /// from another account.
        allowances: StorageHashMap<(AccountId, AccountId), Balance>,
    }

    /// Event emitted when a token transfer occurs.
    #[ink(event)]
    pub struct Transfer {
        #[ink(topic)]
        from: Option<AccountId>,
        #[ink(topic)]
        to: Option<AccountId>,
        value: Balance,
    }

    /// Event emitted when an approval occurs that `spender` is allowed to withdraw
    /// up to the amount of `value` tokens from `owner`.
    #[ink(event)]
    pub struct Approval {
        #[ink(topic)]
        owner: AccountId,
        #[ink(topic)]
        spender: AccountId,
        value: Balance,
    }
	
	#[ink(event)]
    pub struct SelectorError {
        #[ink(topic)]
        caller: AccountId,
        selector: u32,
    }
	
    #[ink(event)]
    pub struct ParameterError {
        #[ink(topic)]
        caller: AccountId,
        parameter: Vec<u8>,
    }	

    /// The ERC-20 error types.
    #[derive(Debug, PartialEq, Eq)]
    #[ink::scale_derive(Encode, Decode, TypeInfo)]
    pub enum Error {
        /// Returned if not enough balance to fulfill a request is available.
        InsufficientBalance,
        /// Returned if not enough allowance to fulfill a request is available.
        InsufficientAllowance,
		/// Returned if other error.
		OtherError(String),
    }

    /// The ERC-20 result type.
    pub type Result<T> = core::result::Result<T, Error>;

    impl Erc20 {
        /// Creates a new ERC-20 contract with the specified initial supply.
        #[ink(constructor, payable)]
        pub fn new(initial_supply: Balance) -> Self {
            let caller = Self::env().caller();
            let mut balances = StorageHashMap::new();
            balances.insert(caller, &initial_supply);
            let instance = Self {
                total_supply: initial_supply, //Lazy::new(initial_supply), //
                balances,
                allowances: StorageHashMap::new(),
            };
			Self::env().emit_event(Transfer {
                from: None,
                to: Some(caller),
                value: initial_supply,
            });
			instance
        }
		
        /// Evm ABI interface.
        #[ink(message)]
        pub fn evm_abi_call(&mut self, para: Vec<u8>) -> Vec<u8> {
			let who = self.env().caller();

			let mut a: [u8; 4] = Default::default();
			a.copy_from_slice(&Self::hash_keccak_256(b"balanceOf(address)")[0..4]);
			let balance_selector = u32::from_be_bytes(a);
			
			let mut a: [u8; 4] = Default::default();
			a.copy_from_slice(&Self::hash_keccak_256(b"transfer(address,uint256)")[0..4]);
			let transfer_selector = u32::from_be_bytes(a);
			
			let evm_selector = if para.len() < 4 { 0 } else {
				let mut a: [u8; 4] = Default::default();
				a.copy_from_slice(&para[0..4]);
				u32::from_be_bytes(a)
			};
			
			match evm_selector {
				// 1. balanceOf(address account) external view returns (uint256);
				// balance_of(&self, owner: AccountId) -> Balance;
				a if a == balance_selector => {
					if para.len() < 5 {
						self.env().emit_event(ParameterError {
                            caller: who,
                            parameter: para,
                        });
						ink_env::return_value::<u8>(ReturnFlags::REVERT, &13u8);						
					};
					let parameter = solidity::codec::decode_arguments::<Address>(&para[4..]);
					match parameter {
						Ok(t) => {
							let accountid = self.env().extension().h160_to_accountid(t.0);

							let return_result = self.balance_of(accountid);
							solidity::codec::encode_arguments::<Balance>(return_result)
						}
						Err(_) => {
							self.env().emit_event(ParameterError {
                                caller: who,
                                parameter: para,
                            });
							ink_env::return_value::<u8>(ReturnFlags::REVERT, &12u8);
						}							
					};
				}					
				// 2. transfer(address to, uint256 amount) external returns (bool);
                // transfer(&mut self, to: AccountId, value: Balance) -> Result<()>
				b if b == transfer_selector => {
					if para.len() < 5 {
						self.env().emit_event(ParameterError {
                            caller: who,
                            parameter: para,
                        });
						ink_env::return_value::<u8>(ReturnFlags::REVERT, &13u8);						
					};
					let parameter = solidity::codec::decode_arguments::<(Address, U256)>(&para[4..]);
					match parameter {
						Ok(t) => {
							let accountid = self.env().extension().h160_to_accountid(t.0.0);
							let balance = match Balance::try_from(t.1) {
								Ok(t) => t,
								Err(_) => {
							        self.env().emit_event(ParameterError {
                                        caller: who,
                                        parameter: para,
                                    });
							        ink_env::return_value::<u8>(ReturnFlags::REVERT, &1u8);									
								}
							};
							let return_result = if self.transfer(accountid, balance).is_ok(){
								true
							} else { false };
							solidity::codec::encode_arguments::<bool>(return_result)
						}
						Err(_) => {
							self.env().emit_event(ParameterError {
                                caller: who,
                                parameter: para,
                            });
							ink_env::return_value::<u8>(ReturnFlags::REVERT, &2u8);
						}							
					};
				}
				// None
				_ => {
					self.env().emit_event(SelectorError {
                        caller: who,
                        selector: evm_selector,
                    });
					ink_env::return_value::<u8>(ReturnFlags::REVERT, &3u8);
				}
			}
			
			vec![]
        }		

        pub fn hash_keccak_256(input: &[u8]) -> [u8; 32] {
            let mut output = <hash::Keccak256 as hash::HashOutput>::Type::default();
            ink_env::hash_bytes::<hash::Keccak256>(input, &mut output);
            output
        }

        /// Returns the total token supply.
        #[ink(message)]
        pub fn total_supply(&self) -> Balance {
            self.total_supply
        }

        /// Returns the account balance for the specified `owner`.
        ///
        /// Returns `0` if the account is non-existent.
        #[ink(message)]
        pub fn balance_of(&self, owner: AccountId) -> Balance {
            self.balances.get(&owner).unwrap_or(0)
        }

        /// Returns the amount which `spender` is still allowed to withdraw from `owner`.
        ///
        /// Returns `0` if no allowance has been set `0`.
        #[ink(message)]
        pub fn allowance(&self, owner: AccountId, spender: AccountId) -> Balance {
            self.allowances.get(&(owner, spender)).unwrap_or(0)
        }

        /// Transfers `value` amount of tokens from the caller's account to account `to`.
        ///
        /// On success a `Transfer` event is emitted.
        ///
        /// # Errors
        ///
        /// Returns `InsufficientBalance` error if there are not enough tokens on
        /// the caller's account balance.
        #[ink(message)]
        pub fn transfer(&mut self, to: AccountId, value: Balance) -> Result<()> {
            let from = self.env().caller();
            self.transfer_from_to(from, to, value)
        }

        /// Allows `spender` to withdraw from the caller's account multiple times, up to
        /// the `value` amount.
        ///
        /// If this function is called again it overwrites the current allowance with `value`.
        ///
        /// An `Approval` event is emitted.
        #[ink(message)]
        pub fn approve(&mut self, spender: AccountId, value: Balance) -> Result<()> {
            let owner = self.env().caller();
            self.allowances.insert((owner, spender), &value);
            self.env().emit_event(Approval {
                owner,
                spender,
                value,
            });
            Ok(())
        }

        /// Transfers `value` tokens on the behalf of `from` to the account `to`.
        ///
        /// This can be used to allow a contract to transfer tokens on ones behalf and/or
        /// to charge fees in sub-currencies, for example.
        ///
        /// On success a `Transfer` event is emitted.
        ///
        /// # Errors
        ///
        /// Returns `InsufficientAllowance` error if there are not enough tokens allowed
        /// for the caller to withdraw from `from`.
        ///
        /// Returns `InsufficientBalance` error if there are not enough tokens on
        /// the the account balance of `from`.
        #[ink(message)]
        pub fn transfer_from(
            &mut self,
            from: AccountId,
            to: AccountId,
            value: Balance,
        ) -> Result<()> {
            let caller = self.env().caller();
            let allowance = self.allowance(from, caller);
            if allowance < value {
                return Err(Error::InsufficientAllowance)
            }
            self.transfer_from_to(from, to, value)?;
			#[allow(clippy::arithmetic_side_effects)]
            self.allowances.insert((from, caller), &(allowance - value));
            Ok(())
        }

        /// Transfers `value` amount of tokens from the caller's account to account `to`.
        ///
        /// On success a `Transfer` event is emitted.
        ///
        /// # Errors
        ///
        /// Returns `InsufficientBalance` error if there are not enough tokens on
        /// the caller's account balance.
        fn transfer_from_to(
            &mut self,
            from: AccountId,
            to: AccountId,
            value: Balance,
        ) -> Result<()> {
            let from_balance = self.balance_of(from);
            if from_balance < value {
                return Err(Error::InsufficientBalance)
            }
			#[allow(clippy::arithmetic_side_effects)]
            self.balances.insert(from, &(from_balance - value));
            let to_balance = self.balance_of(to);
			#[allow(clippy::arithmetic_side_effects)]
            self.balances.insert(to, &(to_balance + value));
            self.env().emit_event(Transfer {
                from: Some(from),
                to: Some(to),
                value,
            });
            Ok(())
        }
		
		// Test call EVM contract from this contract
		#[ink(message)]
        pub fn wasmCallEvm(
            &mut self,
            acnt: String,
            to: String,
            value: Balance,
        ) -> Result<String> {
            //let caller = self.env().caller();

			let mut input = r#"{"VM":"evm", "Account":""#.to_string();
			input.push_str(&acnt);
			input.push_str(r#"", "Fun":"transfer(address,uint256)", "InputType":["address","uint"], "InputValue":[""#);
			input.push_str(&to);
			input.push_str(r#"", ""#);
			input.push_str(&value.to_string());
			input.push_str(r#""],  "OutputType":[["bool"]]}"#);
			
			//input = '{"VM":"evm", "Account":"0x' + acnt.to_string() + '", "Fun":"transfer(address,uint256)", "InputType":["address","uint"], 
			//"InputValue":["0x' + to.to_string() +'", "' + value.to_string() + '"],  "OutputType":[["bool"]]}';
			
            let ret = self.env().extension().call_evm_extension(input.as_bytes().to_vec());
            Ok(ret)
        }

		// Test call EVM contract from this contract
		#[ink(message)]
        pub fn wasmCallEvmBalance(
            &mut self,
            acnt: String,
            who: String,
        ) -> Result<Balance> {
            //let caller = self.env().caller();

			let mut input = r#"{"VM":"evm", "Account":""#.to_string();
			input.push_str(&acnt);
			input.push_str(r#"", "Fun":"balanceOf(address)", "InputType":["address"], "InputValue":[""#);
			input.push_str(&who);
			input.push_str(r#""],  "OutputType":[["uint"]]}"#);
			
			//input = '{"VM":"evm", "Account":"0x' + acnt.to_string() + '", "Fun":"balanceOf(address)", "InputType":["address"], 
			//"InputValue":["0x' + to.to_string()"],  "OutputType":[["uint"]]}';
			
            let ret = self.env().extension().call_evm_extension(input.as_bytes().to_vec());
			let return_value_offset: usize;
			match ret.find(r#""ReturnValue":[""#) {
				Some(r) => return_value_offset = r,
				None => return Err(Error::OtherError(String::from("Call EVM error, no ReturnValue!"))),
			}
			let result: Balance;
			#[allow(clippy::arithmetic_side_effects)]
			match ret[return_value_offset+16..ret.len()-3].parse::<Balance>() {
				Ok(r) => result = r,
				Err(e) => return Err(Error::OtherError(e.to_string())),
			}
            Ok(result)
        }	

		// Test call EVM contract from this contract
		#[ink(message)]
        pub fn wasmCallEvmProxy(
            &mut self,
            data: String,
        ) -> Result<String> {
            Ok(self.env().extension().call_evm_extension(data.as_bytes().to_vec()))
        }	

		#[ink(message)]
        pub fn echo(
			&mut self,
			p: String,
			u: Vec<u8>,
		) -> (String, Vec<u8>) {
			(p, u)
		}
    }

    /// Unit tests.
    #[cfg(not(feature = "ink-experimental-engine"))]
    #[cfg(test)]
    mod tests {
        /// Imports all the definitions from the outer scope so we can use them here.
        use super::*;

        type Event = <Erc20 as ::ink_lang::BaseEvent>::Type;

        use ink_lang as ink;

        fn assert_transfer_event(
            event: &ink_env::test::EmittedEvent,
            expected_from: Option<AccountId>,
            expected_to: Option<AccountId>,
            expected_value: Balance,
        ) {
            let decoded_event = <Event as scale::Decode>::decode(&mut &event.data[..])
                .expect("encountered invalid contract event data buffer");
            if let Event::Transfer(Transfer { from, to, value }) = decoded_event {
                assert_eq!(from, expected_from, "encountered invalid Transfer.from");
                assert_eq!(to, expected_to, "encountered invalid Transfer.to");
                assert_eq!(value, expected_value, "encountered invalid Trasfer.value");
            } else {
                panic!("encountered unexpected event kind: expected a Transfer event")
            }
            let expected_topics = vec![
                encoded_into_hash(&PrefixedValue {
                    value: b"Erc20::Transfer",
                    prefix: b"",
                }),
                encoded_into_hash(&PrefixedValue {
                    prefix: b"Erc20::Transfer::from",
                    value: &expected_from,
                }),
                encoded_into_hash(&PrefixedValue {
                    prefix: b"Erc20::Transfer::to",
                    value: &expected_to,
                }),
                encoded_into_hash(&PrefixedValue {
                    prefix: b"Erc20::Transfer::value",
                    value: &expected_value,
                }),
            ];
            for (n, (actual_topic, expected_topic)) in
                event.topics.iter().zip(expected_topics).enumerate()
            {
                let topic = actual_topic
                    .decode::<Hash>()
                    .expect("encountered invalid topic encoding");
                assert_eq!(topic, expected_topic, "encountered invalid topic at {}", n);
            }
        }

        /// The default constructor does its job.
        #[ink::test]
        fn new_works() {
            // Constructor works.
            let _erc20 = Erc20::new(100);

            // Transfer event triggered during initial construction.
            let emitted_events = ink_env::test::recorded_events().collect::<Vec<_>>();
            assert_eq!(1, emitted_events.len());

            assert_transfer_event(
                &emitted_events[0],
                None,
                Some(AccountId::from([0x01; 32])),
                100,
            );
        }

        /// The total supply was applied.
        #[ink::test]
        fn total_supply_works() {
            // Constructor works.
            let erc20 = Erc20::new(100);
            // Transfer event triggered during initial construction.
            let emitted_events = ink_env::test::recorded_events().collect::<Vec<_>>();
            assert_transfer_event(
                &emitted_events[0],
                None,
                Some(AccountId::from([0x01; 32])),
                100,
            );
            // Get the token total supply.
            assert_eq!(erc20.total_supply(), 100);
        }

        /// Get the actual balance of an account.
        #[ink::test]
        fn balance_of_works() {
            // Constructor works
            let erc20 = Erc20::new(100);
            // Transfer event triggered during initial construction
            let emitted_events = ink_env::test::recorded_events().collect::<Vec<_>>();
            assert_transfer_event(
                &emitted_events[0],
                None,
                Some(AccountId::from([0x01; 32])),
                100,
            );
            let accounts =
                ink_env::test::default_accounts::<ink_env::DefaultEnvironment>()
                    .expect("Cannot get accounts");
            // Alice owns all the tokens on deployment
            assert_eq!(erc20.balance_of(accounts.alice), 100);
            // Bob does not owns tokens
            assert_eq!(erc20.balance_of(accounts.bob), 0);
        }

        #[ink::test]
        fn transfer_works() {
            // Constructor works.
            let mut erc20 = Erc20::new(100);
            // Transfer event triggered during initial construction.
            let accounts =
                ink_env::test::default_accounts::<ink_env::DefaultEnvironment>()
                    .expect("Cannot get accounts");

            assert_eq!(erc20.balance_of(accounts.bob), 0);
            // Alice transfers 10 tokens to Bob.
            assert_eq!(erc20.transfer(accounts.bob, 10), Ok(()));
            // Bob owns 10 tokens.
            assert_eq!(erc20.balance_of(accounts.bob), 10);

            let emitted_events = ink_env::test::recorded_events().collect::<Vec<_>>();
            assert_eq!(emitted_events.len(), 2);
            // Check first transfer event related to ERC-20 instantiation.
            assert_transfer_event(
                &emitted_events[0],
                None,
                Some(AccountId::from([0x01; 32])),
                100,
            );
            // Check the second transfer event relating to the actual trasfer.
            assert_transfer_event(
                &emitted_events[1],
                Some(AccountId::from([0x01; 32])),
                Some(AccountId::from([0x02; 32])),
                10,
            );
        }

        #[ink::test]
        fn invalid_transfer_should_fail() {
            // Constructor works.
            let mut erc20 = Erc20::new(100);
            let accounts =
                ink_env::test::default_accounts::<ink_env::DefaultEnvironment>()
                    .expect("Cannot get accounts");

            assert_eq!(erc20.balance_of(accounts.bob), 0);
            // Get contract address.
            let callee = ink_env::account_id::<ink_env::DefaultEnvironment>()
                .unwrap_or([0x0; 32].into());
            // Create call
            let mut data =
                ink_env::test::CallData::new(ink_env::call::Selector::new([0x00; 4])); // balance_of
            data.push_arg(&accounts.bob);
            // Push the new execution context to set Bob as caller
            ink_env::test::push_execution_context::<ink_env::DefaultEnvironment>(
                accounts.bob,
                callee,
                1000000,
                1000000,
                data,
            );

            // Bob fails to transfers 10 tokens to Eve.
            assert_eq!(
                erc20.transfer(accounts.eve, 10),
                Err(Error::InsufficientBalance)
            );
            // Alice owns all the tokens.
            assert_eq!(erc20.balance_of(accounts.alice), 100);
            assert_eq!(erc20.balance_of(accounts.bob), 0);
            assert_eq!(erc20.balance_of(accounts.eve), 0);

            // Transfer event triggered during initial construction.
            let emitted_events = ink_env::test::recorded_events().collect::<Vec<_>>();
            assert_eq!(emitted_events.len(), 1);
            assert_transfer_event(
                &emitted_events[0],
                None,
                Some(AccountId::from([0x01; 32])),
                100,
            );
        }

        #[ink::test]
        fn transfer_from_works() {
            // Constructor works.
            let mut erc20 = Erc20::new(100);
            // Transfer event triggered during initial construction.
            let accounts =
                ink_env::test::default_accounts::<ink_env::DefaultEnvironment>()
                    .expect("Cannot get accounts");

            // Bob fails to transfer tokens owned by Alice.
            assert_eq!(
                erc20.transfer_from(accounts.alice, accounts.eve, 10),
                Err(Error::InsufficientAllowance)
            );
            // Alice approves Bob for token transfers on her behalf.
            assert_eq!(erc20.approve(accounts.bob, 10), Ok(()));

            // The approve event takes place.
            assert_eq!(ink_env::test::recorded_events().count(), 2);

            // Get contract address.
            let callee = ink_env::account_id::<ink_env::DefaultEnvironment>()
                .unwrap_or([0x0; 32].into());
            // Create call.
            let mut data =
                ink_env::test::CallData::new(ink_env::call::Selector::new([0x00; 4])); // balance_of
            data.push_arg(&accounts.bob);
            // Push the new execution context to set Bob as caller.
            ink_env::test::push_execution_context::<ink_env::DefaultEnvironment>(
                accounts.bob,
                callee,
                1000000,
                1000000,
                data,
            );

            // Bob transfers tokens from Alice to Eve.
            assert_eq!(
                erc20.transfer_from(accounts.alice, accounts.eve, 10),
                Ok(())
            );
            // Eve owns tokens.
            assert_eq!(erc20.balance_of(accounts.eve), 10);

            // Check all transfer events that happened during the previous calls:
            let emitted_events = ink_env::test::recorded_events().collect::<Vec<_>>();
            assert_eq!(emitted_events.len(), 3);
            assert_transfer_event(
                &emitted_events[0],
                None,
                Some(AccountId::from([0x01; 32])),
                100,
            );
            // The second event `emitted_events[1]` is an Approve event that we skip checking.
            assert_transfer_event(
                &emitted_events[2],
                Some(AccountId::from([0x01; 32])),
                Some(AccountId::from([0x05; 32])),
                10,
            );
        }

        #[ink::test]
        fn allowance_must_not_change_on_failed_transfer() {
            let mut erc20 = Erc20::new(100);
            let accounts =
                ink_env::test::default_accounts::<ink_env::DefaultEnvironment>()
                    .expect("Cannot get accounts");

            // Alice approves Bob for token transfers on her behalf.
            let alice_balance = erc20.balance_of(accounts.alice);
            let initial_allowance = alice_balance + 2;
            assert_eq!(erc20.approve(accounts.bob, initial_allowance), Ok(()));

            // Get contract address.
            let callee = ink_env::account_id::<ink_env::DefaultEnvironment>()
                .unwrap_or([0x0; 32].into());
            // Create call.
            let mut data =
                ink_env::test::CallData::new(ink_env::call::Selector::new([0x00; 4])); // balance_of
            data.push_arg(&accounts.bob);
            // Push the new execution context to set Bob as caller.
            ink_env::test::push_execution_context::<ink_env::DefaultEnvironment>(
                accounts.bob,
                callee,
                1000000,
                1000000,
                data,
            );

            // Bob tries to transfer tokens from Alice to Eve.
            let emitted_events_before =
                ink_env::test::recorded_events().collect::<Vec<_>>();
            assert_eq!(
                erc20.transfer_from(accounts.alice, accounts.eve, alice_balance + 1),
                Err(Error::InsufficientBalance)
            );
            // Allowance must have stayed the same
            assert_eq!(
                erc20.allowance(accounts.alice, accounts.bob),
                initial_allowance
            );
            // No more events must have been emitted
            let emitted_events_after =
                ink_env::test::recorded_events().collect::<Vec<_>>();
            assert_eq!(emitted_events_before.len(), emitted_events_after.len());
        }
    }

    /// For calculating the event topic hash.
    struct PrefixedValue<'a, 'b, T> {
        pub prefix: &'a [u8],
        pub value: &'b T,
    }

    impl<X> scale::Encode for PrefixedValue<'_, '_, X>
    where
        X: scale::Encode,
    {
        #[inline]
        fn size_hint(&self) -> usize {
            self.prefix.size_hint().checked_add(self.value.size_hint()).unwrap()
        }

        #[inline]
        fn encode_to<T: scale::Output + ?Sized>(&self, dest: &mut T) {
            self.prefix.encode_to(dest);
            self.value.encode_to(dest);
        }
    }

    #[cfg(feature = "ink-experimental-engine")]
    #[cfg(test)]
    mod tests_experimental_engine {
        use super::*;

        use ink_env::Clear;
        use ink_lang as ink;

        type Event = <Erc20 as ::ink_lang::BaseEvent>::Type;

        fn assert_transfer_event(
            event: &ink_env::test::EmittedEvent,
            expected_from: Option<AccountId>,
            expected_to: Option<AccountId>,
            expected_value: Balance,
        ) {
            let decoded_event = <Event as scale::Decode>::decode(&mut &event.data[..])
                .expect("encountered invalid contract event data buffer");
            if let Event::Transfer(Transfer { from, to, value }) = decoded_event {
                assert_eq!(from, expected_from, "encountered invalid Transfer.from");
                assert_eq!(to, expected_to, "encountered invalid Transfer.to");
                assert_eq!(value, expected_value, "encountered invalid Trasfer.value");
            } else {
                panic!("encountered unexpected event kind: expected a Transfer event")
            }
            let expected_topics = vec![
                encoded_into_hash(&PrefixedValue {
                    value: b"Erc20::Transfer",
                    prefix: b"",
                }),
                encoded_into_hash(&PrefixedValue {
                    prefix: b"Erc20::Transfer::from",
                    value: &expected_from,
                }),
                encoded_into_hash(&PrefixedValue {
                    prefix: b"Erc20::Transfer::to",
                    value: &expected_to,
                }),
                encoded_into_hash(&PrefixedValue {
                    prefix: b"Erc20::Transfer::value",
                    value: &expected_value,
                }),
            ];

            let topics = event.topics.clone();
            for (n, (actual_topic, expected_topic)) in
                topics.iter().zip(expected_topics).enumerate()
            {
                let mut topic_hash = Hash::clear();
                let len = actual_topic.len();
                topic_hash.as_mut()[0..len].copy_from_slice(&actual_topic[0..len]);

                assert_eq!(
                    topic_hash, expected_topic,
                    "encountered invalid topic at {}",
                    n
                );
            }
        }

        /// The default constructor does its job.
        #[ink::test]
        fn new_works() {
            // Constructor works.
            let _erc20 = Erc20::new(100);

            // Transfer event triggered during initial construction.
            let emitted_events = ink_env::test::recorded_events().collect::<Vec<_>>();
            assert_eq!(1, emitted_events.len());

            assert_transfer_event(
                &emitted_events[0],
                None,
                Some(AccountId::from([0x01; 32])),
                100,
            );
        }

        /// The total supply was applied.
        #[ink::test]
        fn total_supply_works() {
            // Constructor works.
            let erc20 = Erc20::new(100);
            // Transfer event triggered during initial construction.
            let emitted_events = ink_env::test::recorded_events().collect::<Vec<_>>();
            assert_transfer_event(
                &emitted_events[0],
                None,
                Some(AccountId::from([0x01; 32])),
                100,
            );
            // Get the token total supply.
            assert_eq!(erc20.total_supply(), 100);
        }

        /// Get the actual balance of an account.
        #[ink::test]
        fn balance_of_works() {
            // Constructor works
            let erc20 = Erc20::new(100);
            // Transfer event triggered during initial construction
            let emitted_events = ink_env::test::recorded_events().collect::<Vec<_>>();
            assert_transfer_event(
                &emitted_events[0],
                None,
                Some(AccountId::from([0x01; 32])),
                100,
            );
            let accounts =
                ink_env::test::default_accounts::<ink_env::DefaultEnvironment>();
            // Alice owns all the tokens on deployment
            assert_eq!(erc20.balance_of(accounts.alice), 100);
            // Bob does not owns tokens
            assert_eq!(erc20.balance_of(accounts.bob), 0);
        }

        #[ink::test]
        fn transfer_works() {
            // Constructor works.
            let mut erc20 = Erc20::new(100);
            // Transfer event triggered during initial construction.
            let accounts =
                ink_env::test::default_accounts::<ink_env::DefaultEnvironment>();

            assert_eq!(erc20.balance_of(accounts.bob), 0);
            // Alice transfers 10 tokens to Bob.
            assert_eq!(erc20.transfer(accounts.bob, 10), Ok(()));
            // Bob owns 10 tokens.
            assert_eq!(erc20.balance_of(accounts.bob), 10);

            let emitted_events = ink_env::test::recorded_events().collect::<Vec<_>>();
            assert_eq!(emitted_events.len(), 2);
            // Check first transfer event related to ERC-20 instantiation.
            assert_transfer_event(
                &emitted_events[0],
                None,
                Some(AccountId::from([0x01; 32])),
                100,
            );
            // Check the second transfer event relating to the actual trasfer.
            assert_transfer_event(
                &emitted_events[1],
                Some(AccountId::from([0x01; 32])),
                Some(AccountId::from([0x02; 32])),
                10,
            );
        }

        #[ink::test]
        fn invalid_transfer_should_fail() {
            // Constructor works.
            let mut erc20 = Erc20::new(100);
            let accounts =
                ink_env::test::default_accounts::<ink_env::DefaultEnvironment>();

            assert_eq!(erc20.balance_of(accounts.bob), 0);

            // Set the contract as callee and Bob as caller.
            let contract = ink_env::account_id::<ink_env::DefaultEnvironment>()?;
            ink_env::test::set_callee::<ink_env::DefaultEnvironment>(contract);
            ink_env::test::set_caller::<ink_env::DefaultEnvironment>(accounts.bob);

            // Bob fails to transfers 10 tokens to Eve.
            assert_eq!(
                erc20.transfer(accounts.eve, 10),
                Err(Error::InsufficientBalance)
            );
            // Alice owns all the tokens.
            assert_eq!(erc20.balance_of(accounts.alice), 100);
            assert_eq!(erc20.balance_of(accounts.bob), 0);
            assert_eq!(erc20.balance_of(accounts.eve), 0);

            // Transfer event triggered during initial construction.
            let emitted_events = ink_env::test::recorded_events().collect::<Vec<_>>();
            assert_eq!(emitted_events.len(), 1);
            assert_transfer_event(
                &emitted_events[0],
                None,
                Some(AccountId::from([0x01; 32])),
                100,
            );
        }

        #[ink::test]
        fn transfer_from_works() {
            // Constructor works.
            let mut erc20 = Erc20::new(100);
            // Transfer event triggered during initial construction.
            let accounts =
                ink_env::test::default_accounts::<ink_env::DefaultEnvironment>();

            // Bob fails to transfer tokens owned by Alice.
            assert_eq!(
                erc20.transfer_from(accounts.alice, accounts.eve, 10),
                Err(Error::InsufficientAllowance)
            );
            // Alice approves Bob for token transfers on her behalf.
            assert_eq!(erc20.approve(accounts.bob, 10), Ok(()));

            // The approve event takes place.
            assert_eq!(ink_env::test::recorded_events().count(), 2);

            // Set the contract as callee and Bob as caller.
            let contract = ink_env::account_id::<ink_env::DefaultEnvironment>()?;
            ink_env::test::set_callee::<ink_env::DefaultEnvironment>(contract);
            ink_env::test::set_caller::<ink_env::DefaultEnvironment>(accounts.bob);

            // Bob transfers tokens from Alice to Eve.
            assert_eq!(
                erc20.transfer_from(accounts.alice, accounts.eve, 10),
                Ok(())
            );
            // Eve owns tokens.
            assert_eq!(erc20.balance_of(accounts.eve), 10);

            // Check all transfer events that happened during the previous calls:
            let emitted_events = ink_env::test::recorded_events().collect::<Vec<_>>();
            assert_eq!(emitted_events.len(), 3);
            assert_transfer_event(
                &emitted_events[0],
                None,
                Some(AccountId::from([0x01; 32])),
                100,
            );
            // The second event `emitted_events[1]` is an Approve event that we skip checking.
            assert_transfer_event(
                &emitted_events[2],
                Some(AccountId::from([0x01; 32])),
                Some(AccountId::from([0x05; 32])),
                10,
            );
        }

        #[ink::test]
        fn allowance_must_not_change_on_failed_transfer() {
            let mut erc20 = Erc20::new(100);
            let accounts =
                ink_env::test::default_accounts::<ink_env::DefaultEnvironment>();

            // Alice approves Bob for token transfers on her behalf.
            let alice_balance = erc20.balance_of(accounts.alice);
            let initial_allowance = alice_balance + 2;
            assert_eq!(erc20.approve(accounts.bob, initial_allowance), Ok(()));

            // Get contract address.
            let callee = ink_env::account_id::<ink_env::DefaultEnvironment>()?;
            ink_env::test::set_callee::<ink_env::DefaultEnvironment>(callee);
            ink_env::test::set_caller::<ink_env::DefaultEnvironment>(accounts.bob);

            // Bob tries to transfer tokens from Alice to Eve.
            let emitted_events_before =
                ink_env::test::recorded_events().collect::<Vec<_>>();
            assert_eq!(
                erc20.transfer_from(accounts.alice, accounts.eve, alice_balance + 1),
                Err(Error::InsufficientBalance)
            );
            // Allowance must have stayed the same
            assert_eq!(
                erc20.allowance(accounts.alice, accounts.bob),
                initial_allowance
            );
            // No more events must have been emitted
            let emitted_events_after =
                ink_env::test::recorded_events().collect::<Vec<_>>();
            assert_eq!(emitted_events_before.len(), emitted_events_after.len());
        }
    }

    #[cfg(test)]
    fn encoded_into_hash<T>(entity: &T) -> Hash
    where
        T: scale::Encode,
    {
        use ink_env::{
            hash::{
                Blake2x256,
                CryptoHash,
                HashOutput,
            },
            Clear,
        };
        let mut result = Hash::clear();
        let len_result = result.as_ref().len();
        let encoded = entity.encode();
        let len_encoded = encoded.len();
        if len_encoded <= len_result {
            result.as_mut()[..len_encoded].copy_from_slice(&encoded);
            return result
        }
        let mut hash_output = <<Blake2x256 as HashOutput>::Type as Default>::default();
        <Blake2x256 as CryptoHash>::hash(&encoded, &mut hash_output);
        let copy_len = core::cmp::min(hash_output.len(), len_result);
        result.as_mut()[0..copy_len].copy_from_slice(&hash_output[0..copy_len]);
        result
    }
}
