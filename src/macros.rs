/// Unwrap a parse result in ingress code, returning early (with the function's
/// default return value) on a malformed packet.
macro_rules! check {
    ($e:expr) => {
        match $e {
            Ok(x) => x,
            Err(_) => {
                trace!("iface: malformed ingress packet");
                return Default::default();
            }
        }
    };
}

macro_rules! open_enum {
    (
        $( #[$enum_attr:meta] )*
        pub enum $name:ident($ty:ty) {
            $(
              $( #[$variant_attr:meta] )*
              $variant:ident = $value:expr
            ),+ $(,)?
        }
    ) => {
        $( #[$enum_attr] )*
        #[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash)]
        pub struct $name(pub $ty);

        #[allow(non_upper_case_globals)]
        impl $name {
            $(
              $( #[$variant_attr] )*
              pub const $variant: Self = Self($value);
            )*
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                match *self {
                    $( Self::$variant => f.write_str(stringify!($variant)), )*
                    Self(other) => write!(f, "0x{:01$x}", other, ::core::mem::size_of::<$ty>() * 2),
                }
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                ::core::fmt::Debug::fmt(self, f)
            }
        }

        #[cfg(feature = "defmt")]
        impl ::defmt::Format for $name {
            fn format(&self, f: ::defmt::Formatter) {
                // The variant names are interned into the ELF (never sent over the
                // wire) by deriving `Format` on a fieldless mirror enum. `intern!`
                // itself can't be used here: it's a proc macro that requires a
                // string literal, and `stringify!($variant)` isn't one yet at the
                // point it would see it.
                #[derive(::defmt::Format)]
                #[allow(non_camel_case_types)]
                enum Names {
                    $( $variant, )*
                }

                let name = match *self {
                    $( Self::$variant => Names::$variant, )*
                    Self(other) => {
                        ::defmt::write!(f, "{:#x}", other);
                        return;
                    }
                };
                ::defmt::write!(f, "{}", name);
            }
        }

        impl ::core::convert::From<$ty> for $name {
            fn from(value: $ty) -> Self {
                Self(value)
            }
        }

        impl ::core::convert::From<$name> for $ty {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    }
}
