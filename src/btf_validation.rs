// SPDX-License-Identifier: GPL-2.0-only

use crate::bpf::BpfError;
use libbpf_rs::btf::HasSize;
use libbpf_rs::Btf;
use std::collections::HashSet;

/// Prefix used for anonymous field names in validation
const ANONYMOUS_FIELD_PREFIX: &str = "anon_";

/// Represents a field to be validated against BTF.
/// Contains all necessary information for validation: name, offset, size, and type.
#[derive(Debug, Clone, Copy)]
pub struct ValidationField {
    /// Field name (uses ANONYMOUS_FIELD_PREFIX for anonymous fields)
    pub name: &'static str,
    /// Byte offset from start of struct (0 for union members)
    pub offset: usize,
    /// Size in bytes
    pub size: usize,
    /// Rust type name as string
    pub type_name: &'static str,
}

impl ValidationField {
    /// Creates a new validation field
    pub const fn new(
        name: &'static str,
        offset: usize,
        size: usize,
        type_name: &'static str,
    ) -> Self {
        Self {
            name,
            offset,
            size,
            type_name,
        }
    }
}

// Type registry for BTF validation
// Validators register themselves using the macros via linkme distributed slices
pub type BtfValidatorFn =
    fn(&Btf, libbpf_rs::btf::BtfType, &mut HashSet<String>) -> Result<(), BpfError>;

#[linkme::distributed_slice]
pub static BTF_VALIDATORS: [(&'static str, BtfValidatorFn)];

/// Resolves a BTF type through typedef, const, volatile, etc. to the actual type.
///
/// # Arguments
/// * `btf_type` - The BTF type to resolve
///
/// # Returns
/// The fully resolved BTF type
fn resolve_btf_type(mut btf_type: libbpf_rs::btf::BtfType) -> libbpf_rs::btf::BtfType {
    while let Some(next) = btf_type.next_type() {
        btf_type = next;
    }
    btf_type
}

/// Trait for struct types that can be validated against BTF.
///
/// This trait is typically implemented via the `btf_validated_struct!` macro,
/// which automatically generates the validation metadata and registers the type.
pub(crate) trait BtfValidatedStruct: Sized {
    /// Returns field validation data for all fields in this struct.
    fn get_validation_fields() -> Vec<ValidationField>;

    /// Validates the BTF layout of this type against the provided BTF type.
    ///
    /// # Arguments
    /// * `btf` - The BTF object containing type information
    /// * `btf_type` - The BTF type to validate against
    /// * `cache` - Cache of already-validated types to avoid infinite recursion
    fn validate_btf_layout_from_type(
        btf: &Btf,
        btf_type: libbpf_rs::btf::BtfType,
        cache: &mut HashSet<String>,
    ) -> Result<(), BpfError> {
        let resolved_type = resolve_btf_type(btf_type);

        // Verify the type is a struct
        let btf_struct = libbpf_rs::btf::types::Struct::try_from(resolved_type).map_err(|_| {
            log::error!(
                target: "libbpf",
                "expected struct type for {}",
                std::any::type_name::<Self>()
            );
            BpfError::LibBPFError {
                error: libbpf_rs::Error::from_raw_os_error(libc::EINVAL),
            }
        })?;

        // Validate this struct - recursive validation handles nested types
        let fields = Self::get_validation_fields();
        btf_struct.validate(
            btf,
            std::any::type_name::<Self>(),
            std::mem::size_of::<Self>(),
            &fields,
            cache,
        )
    }
}

/// Trait for union types that can be validated against BTF.
///
/// This trait is typically implemented via the `btf_validated_union!` macro,
/// which automatically generates the validation metadata and registers the type.
pub(crate) trait BtfValidatedUnion: Sized {
    /// Returns field validation data for all members in this union.
    fn get_validation_fields() -> Vec<ValidationField>;

    /// Validates the BTF layout of this union against the provided BTF type.
    ///
    /// # Arguments
    /// * `btf` - The BTF object containing type information
    /// * `btf_type` - The BTF type to validate against
    /// * `cache` - Cache of already-validated types to avoid infinite recursion
    fn validate_btf_layout_from_type(
        btf: &Btf,
        btf_type: libbpf_rs::btf::BtfType,
        cache: &mut HashSet<String>,
    ) -> Result<(), BpfError> {
        let resolved_type = resolve_btf_type(btf_type);

        // Verify the type is a union
        let btf_union = libbpf_rs::btf::types::Union::try_from(resolved_type).map_err(|_| {
            log::error!(
                target: "libbpf",
                "expected union type for {}",
                std::any::type_name::<Self>()
            );
            BpfError::LibBPFError {
                error: libbpf_rs::Error::from_raw_os_error(libc::EINVAL),
            }
        })?;

        // Validate this union - recursive validation handles nested types
        let fields = Self::get_validation_fields();
        btf_union.validate(
            btf,
            std::any::type_name::<Self>(),
            std::mem::size_of::<Self>(),
            &fields,
            cache,
        )
    }
}

// Macro to define a BTF-validated struct and implement the BtfValidatedStruct trait
// This generates the struct definition and implements get_validation_fields()
#[macro_export]
macro_rules! btf_validated_struct {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident {
            $($(#[$field_meta:meta])* $field_vis:vis $field:ident: $field_type:ty),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        $vis struct $name {
            $($(#[$field_meta])* $field_vis $field: $field_type),+
        }

        impl $crate::btf_validation::BtfValidatedStruct for $name {
            fn get_validation_fields() -> Vec<$crate::btf_validation::ValidationField> {
                use memoffset::span_of;
                vec![
                    $(
                        {
                            let span = span_of!($name, $field);
                            $crate::btf_validation::ValidationField::new(
                                stringify!($field),
                                span.start,
                                span.end - span.start,
                                stringify!($field_type),
                            )
                        }
                    ),+
                ]
            }
        }

        // Register this type's validator in the global registry
        // Use const _: () = {} to create unique scope for each static
        const _: () = {
            #[linkme::distributed_slice($crate::btf_validation::BTF_VALIDATORS)]
            static VALIDATOR: (&'static str, $crate::btf_validation::BtfValidatorFn) = (
                stringify!($name),
                <$name as $crate::btf_validation::BtfValidatedStruct>::validate_btf_layout_from_type,
            );
        };
    };
}

// Macro to define a BTF-validated union and implement the BtfValidatedUnion trait
// This generates the union definition and implements get_validation_fields()
#[macro_export]
macro_rules! btf_validated_union {
    (
        $(#[$meta:meta])*
        $vis:vis union $name:ident {
            $($(#[$field_meta:meta])* $field_vis:vis $field:ident: $field_type:ty),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        $vis union $name {
            $($(#[$field_meta])* $field_vis $field: $field_type),+
        }

        impl $crate::btf_validation::BtfValidatedUnion for $name {
            fn get_validation_fields() -> Vec<$crate::btf_validation::ValidationField> {
                vec![
                    $(
                        $crate::btf_validation::ValidationField::new(
                            stringify!($field),
                            0, // All union fields start at offset 0
                            std::mem::size_of::<$field_type>(),
                            stringify!($field_type),
                        )
                    ),+
                ]
            }
        }

        // Register this type's validator in the global registry
        // Use const _: () = {} to create unique scope for each static
        const _: () = {
            #[linkme::distributed_slice($crate::btf_validation::BTF_VALIDATORS)]
            static VALIDATOR: (&'static str, $crate::btf_validation::BtfValidatorFn) = (
                stringify!($name),
                <$name as $crate::btf_validation::BtfValidatedUnion>::validate_btf_layout_from_type,
            );
        };
    };
}

/// Validates a complex type by name, recursively validating nested types.
///
/// This function looks up validators in the global BTF_VALIDATORS registry
/// and calls them to validate nested struct/union types. It maintains a cache
/// to avoid infinite recursion when types reference each other.
///
/// # Arguments
/// * `btf` - The BTF object containing type information
/// * `btf_type` - The BTF type to validate
/// * `type_name` - The Rust type name (may include array syntax like "[Foo; 32]")
/// * `cache` - Cache of already-validated types to avoid infinite recursion
fn validate_complex_type_by_name(
    btf: &Btf,
    btf_type: libbpf_rs::btf::BtfType,
    type_name: &str,
    cache: &mut HashSet<String>,
) -> Result<(), BpfError> {
    // Check if already validated
    if cache.contains(type_name) {
        return Ok(());
    }

    // Strip array syntax if present (e.g., "[HidRdescCollection; 32]" -> "HidRdescCollection")
    let base_type = type_name
        .trim_start_matches('[')
        .split(';')
        .next()
        .unwrap_or(type_name)
        .trim();

    let resolved_type = resolve_btf_type(btf_type);

    // If the resolved type is an array, extract the element type
    let validation_type = if let Ok(array) = libbpf_rs::btf::types::Array::try_from(resolved_type) {
        btf.type_by_id::<libbpf_rs::btf::BtfType>(array.ty())
            .ok_or_else(|| BpfError::LibBPFError {
                error: libbpf_rs::Error::from_raw_os_error(libc::EINVAL),
            })?
    } else {
        resolved_type
    };

    // Check if it's a primitive type
    match base_type {
        "u8" | "u16" | "u32" | "u64" | "i8" | "i16" | "i32" | "i64" | "usize" | "isize"
        | "bool" | "char" | "f32" | "f64" => {
            // Primitive types don't need validation
        }
        _ => {
            // Look up validator in the registry
            if let Some((_, validator)) = BTF_VALIDATORS.iter().find(|(name, _)| *name == base_type)
            {
                validator(btf, validation_type, cache)?;
            } else {
                // Unknown complex type - skip with debug message
                log::debug!(target: "libbpf", "Skipping validation for unknown type: {}", type_name);
            }
        }
    }

    // Mark as validated
    cache.insert(type_name.to_string());
    Ok(())
}

/// Internal trait abstracting over BTF struct and union types.
///
/// This trait allows unified validation logic for both composite types,
/// with the differences (offset validation, terminology) handled through
/// the trait methods.
trait BtfCompositeType: Sized {
    /// The member type (StructMember or UnionMember)
    type Member<'a>;

    /// Returns the name of this composite type from BTF
    fn get_name_str(&self) -> Option<&str>;

    /// Returns an iterator over the members of this composite type
    fn members(&self) -> impl Iterator<Item = Self::Member<'_>>;

    /// Returns the size of this composite type in bytes
    fn get_size(&self) -> usize;

    /// Extracts the name from a member
    fn member_name<'a>(member: &Self::Member<'a>) -> Option<&'a str>;

    /// Extracts the type ID from a member
    fn member_ty(member: &Self::Member<'_>) -> libbpf_rs::btf::TypeId;

    /// Extracts the byte offset from a member (0 for unions)
    fn member_offset(member: &Self::Member<'_>) -> Option<usize>;

    /// Returns "struct" or "union" for error messages
    fn type_name() -> &'static str;

    /// Returns true for structs (validates offsets), false for unions
    fn validates_offset() -> bool;

    /// Validates this composite type against BTF.
    ///
    /// This is the main validation logic that works for both structs and unions.
    fn validate(
        &self,
        btf: &Btf,
        rust_name: &str,
        expected_size: usize,
        expected_fields: &[ValidationField],
        cache: &mut HashSet<String>,
    ) -> Result<(), BpfError> {
        let btf_name = self.get_name_str().unwrap_or("<unnamed>");
        let btf_size = self.get_size();
        let type_name = Self::type_name();
        let validates_offset = Self::validates_offset();

        if btf_size != expected_size {
            log::error!(target: "libbpf",
                "{} '{}' (Rust: {}) size mismatch: BPF object has {} bytes, expected {} bytes",
                type_name, btf_name, rust_name, btf_size, expected_size);
            return Err(BpfError::LibBPFError {
                error: libbpf_rs::Error::from_raw_os_error(libc::EINVAL),
            });
        }

        // Collect members once to avoid multiple iterations
        let members: Vec<_> = self.members().collect();

        for field in expected_fields {
            let is_anonymous = field.name.starts_with(ANONYMOUS_FIELD_PREFIX);

            let btf_member = if is_anonymous && validates_offset {
                // For anonymous fields in structs, find unnamed field at the expected offset
                members.iter().find(|m| {
                    Self::member_name(m).is_none() && Self::member_offset(m) == Some(field.offset)
                })
            } else if is_anonymous {
                // For anonymous fields in unions, find first unnamed member
                members.iter().find(|m| Self::member_name(m).is_none())
            } else {
                // For named fields, find by name
                members
                    .iter()
                    .find(|m| Self::member_name(m) == Some(field.name))
            };

            let member = match btf_member {
                None => {
                    let msg = if validates_offset {
                        format!(
                            "{} '{}' (Rust: {}) missing {} field '{}' at offset {}",
                            type_name,
                            btf_name,
                            rust_name,
                            if is_anonymous { "anonymous" } else { "named" },
                            field.name,
                            field.offset
                        )
                    } else {
                        format!(
                            "{} '{}' (Rust: {}) missing {} member '{}'",
                            type_name,
                            btf_name,
                            rust_name,
                            if is_anonymous { "anonymous" } else { "named" },
                            field.name
                        )
                    };
                    log::error!(target: "libbpf", "{}", msg);
                    return Err(BpfError::LibBPFError {
                        error: libbpf_rs::Error::from_raw_os_error(libc::EINVAL),
                    });
                }
                Some(m) => m,
            };

            // Validate offset for structs
            if validates_offset {
                if let Some(btf_offset) = Self::member_offset(member) {
                    if btf_offset != field.offset {
                        log::error!(target: "libbpf",
                            "{} '{}' (Rust: {}) field '{}' offset mismatch: BPF object has offset {}, expected {}",
                            type_name, btf_name, rust_name, field.name, btf_offset, field.offset);
                        return Err(BpfError::LibBPFError {
                            error: libbpf_rs::Error::from_raw_os_error(libc::EINVAL),
                        });
                    }
                }
            }

            // Get and resolve member type
            let member_type = btf
                .type_by_id::<libbpf_rs::btf::BtfType>(Self::member_ty(member))
                .ok_or_else(|| BpfError::LibBPFError {
                    error: libbpf_rs::Error::from_raw_os_error(libc::EINVAL),
                })?;

            let resolved_type = resolve_btf_type(member_type);

            // Validate member size
            let context = format!("{} '{}' (Rust: {})", type_name, btf_name, rust_name);
            let btf_field_size = get_btf_type_size(btf, resolved_type, &context, field.name)?;

            if btf_field_size != field.size {
                log::error!(target: "libbpf",
                    "{} '{}' (Rust: {}) {} '{}' size mismatch: BPF object has {} bytes, expected {} bytes",
                    type_name, btf_name, rust_name,
                    if validates_offset { "field" } else { "member" },
                    field.name, btf_field_size, field.size);
                return Err(BpfError::LibBPFError {
                    error: libbpf_rs::Error::from_raw_os_error(libc::EINVAL),
                });
            }

            // Recursively validate complex types
            validate_complex_type_by_name(btf, resolved_type, field.type_name, cache)?;
        }

        log::debug!(target: "libbpf",
            "BTF {} validation passed for '{}' (Rust: {}, size: {} bytes)",
            type_name, btf_name, rust_name, btf_size);

        Ok(())
    }
}

impl<'a> BtfCompositeType for libbpf_rs::btf::types::Struct<'a> {
    type Member<'b> = libbpf_rs::btf::types::StructMember<'b>;

    fn get_name_str(&self) -> Option<&str> {
        self.name().and_then(|n| n.to_str())
    }

    fn members(&self) -> impl Iterator<Item = Self::Member<'_>> {
        self.iter()
    }

    fn get_size(&self) -> usize {
        HasSize::size(self)
    }

    fn member_name<'b>(member: &Self::Member<'b>) -> Option<&'b str> {
        member.name.and_then(|n| n.to_str())
    }

    fn member_ty(member: &Self::Member<'_>) -> libbpf_rs::btf::TypeId {
        member.ty
    }

    fn member_offset(member: &Self::Member<'_>) -> Option<usize> {
        match member.attr {
            libbpf_rs::btf::types::MemberAttr::Normal { offset }
            | libbpf_rs::btf::types::MemberAttr::BitField { offset, .. } => {
                Some((offset / 8) as usize)
            }
        }
    }

    fn type_name() -> &'static str {
        "struct"
    }

    fn validates_offset() -> bool {
        true
    }
}

impl<'a> BtfCompositeType for libbpf_rs::btf::types::Union<'a> {
    type Member<'b> = libbpf_rs::btf::types::UnionMember<'b>;

    fn get_name_str(&self) -> Option<&str> {
        self.name().and_then(|n| n.to_str())
    }

    fn members(&self) -> impl Iterator<Item = Self::Member<'_>> {
        self.iter()
    }

    fn get_size(&self) -> usize {
        HasSize::size(self)
    }

    fn member_name<'b>(member: &Self::Member<'b>) -> Option<&'b str> {
        member.name.and_then(|n| n.to_str())
    }

    fn member_ty(member: &Self::Member<'_>) -> libbpf_rs::btf::TypeId {
        member.ty
    }

    fn member_offset(_member: &Self::Member<'_>) -> Option<usize> {
        Some(0) // All union members are at offset 0
    }

    fn type_name() -> &'static str {
        "union"
    }

    fn validates_offset() -> bool {
        false
    }
}

/// Gets the size in bytes of a BTF type.
///
/// Handles Int, Struct, Union, Enum, and Array types. For arrays, recursively
/// calculates the size by multiplying the element size by the number of elements.
///
/// # Arguments
/// * `btf` - The BTF object containing type information
/// * `resolved_type` - The resolved BTF type (should already have typedefs resolved)
/// * `context_name` - Context string for error messages
/// * `field_name` - Field name for error messages
fn get_btf_type_size(
    btf: &Btf,
    resolved_type: libbpf_rs::btf::BtfType,
    context_name: &str,
    field_name: &str,
) -> Result<usize, BpfError> {
    // Try Int
    if let Ok(int_type) = libbpf_rs::btf::types::Int::try_from(resolved_type) {
        return Ok(int_type.size());
    }

    // Try Struct
    if let Ok(struct_type) = libbpf_rs::btf::types::Struct::try_from(resolved_type) {
        return Ok(struct_type.size());
    }

    // Try Union
    if let Ok(union_type) = libbpf_rs::btf::types::Union::try_from(resolved_type) {
        return Ok(union_type.size());
    }

    // Try Enum
    if let Ok(enum_type) = libbpf_rs::btf::types::Enum::try_from(resolved_type) {
        return Ok(enum_type.size());
    }

    // Try Array - requires recursion to calculate total size
    if let Ok(array_type) = libbpf_rs::btf::types::Array::try_from(resolved_type) {
        let elem_type = btf
            .type_by_id::<libbpf_rs::btf::BtfType>(array_type.ty())
            .ok_or_else(|| BpfError::LibBPFError {
                error: libbpf_rs::Error::from_raw_os_error(libc::EINVAL),
            })?;

        let resolved_elem = resolve_btf_type(elem_type);
        let elem_size = get_btf_type_size(btf, resolved_elem, context_name, field_name)?;

        return Ok(elem_size * array_type.capacity());
    }

    // Unsupported type
    log::error!(target: "libbpf",
        "{} field '{}' has unsupported type", context_name, field_name);
    Err(BpfError::LibBPFError {
        error: libbpf_rs::Error::from_raw_os_error(libc::EINVAL),
    })
}
