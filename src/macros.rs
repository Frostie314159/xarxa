#[cfg(not(test))]
#[collapse_debuginfo(yes)]
macro_rules! net_log {
    (trace, $($arg:expr),*) => { log::trace!($($arg),*) };
    (debug, $($arg:expr),*) => { log::debug!($($arg),*) };
}

#[cfg(test)]
#[collapse_debuginfo(yes)]
macro_rules! net_log {
    (trace, $($arg:expr),*) => { println!($($arg),*) };
    (debug, $($arg:expr),*) => { println!($($arg),*) };
}

#[collapse_debuginfo(yes)]
macro_rules! net_trace {
    ($($arg:expr),*) => (net_log!(trace, $($arg),*));
}

#[collapse_debuginfo(yes)]
macro_rules! net_debug {
    ($($arg:expr),*) => (net_log!(debug, $($arg),*));
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
