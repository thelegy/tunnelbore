use base64::Engine;
use proc_macro::TokenStream;
use proc_macro2::Literal;
use quote::quote;
use tunnelbore::*;

const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

#[proc_macro]
pub fn pubkey(attr: TokenStream) -> TokenStream {
    let key: syn::LitStr = syn::parse_macro_input!(attr);
    let pubkey = Pubkey::try_from(&key.value()[..]).unwrap();
    quote!(#pubkey).into()
}

#[proc_macro]
pub fn b64(attr: TokenStream) -> TokenStream {
    let data_string: syn::LitStr = syn::parse_macro_input!(attr);
    let data_bytes = BASE64.decode(data_string.value()).unwrap();
    let data_lit = Literal::byte_string(&data_bytes);
    quote!(#data_lit).into()
}
