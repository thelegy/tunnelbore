use std::io::Read;

use proc_macro::TokenStream;
use proc_macro2::Literal;
use quote::quote;
use tunnelbore::*;

#[proc_macro]
pub fn pubkey(attr: TokenStream) -> TokenStream {
    let key: syn::LitStr = syn::parse_macro_input!(attr);
    let pubkey = Pubkey::try_from(&key.value()[..]).unwrap();
    quote!(#pubkey).into()
}

#[proc_macro]
pub fn b64(attr: TokenStream) -> TokenStream {
    let data_string: syn::LitStr = syn::parse_macro_input!(attr);
    let data_bytes = base64::decode(data_string.value()).unwrap();
    let data_lit = Literal::byte_string(&data_bytes);
    quote!(#data_lit).into()
}
