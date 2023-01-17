use tunnelbore::*;
use proc_macro::TokenStream;
use quote::quote;

#[proc_macro]
pub fn pubkey(attr: TokenStream) -> TokenStream {
    let key: syn::LitStr = syn::parse_macro_input!(attr);
    let pubkey = Pubkey::try_from(&key.value()[..]).unwrap();
    quote!(#pubkey).into()
}

