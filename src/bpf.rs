// SPDX-License-Identifier: GPL-2.0-only

include!(concat!(env!("OUT_DIR"), "/attach.skel.rs"));

use crate::hidudev;
use anyhow::{bail, Context, Result};
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{AsRawLibbpf, Btf, MapCore, Object, OpenObject, Program};
use std::convert::TryInto;
use std::ffi::OsStr;
use std::fmt::Display;
use std::fs;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd};
use std::os::raw::{c_int, c_uchar, c_uint};
use std::path::Path;
use std::sync::OnceLock;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct hid_bpf_probe_args {
    pub hid: c_uint,
    pub rdesc_size: c_uint,
    pub rdesc: [c_uchar; 4096usize],
    pub retval: c_int,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct AttachProgArgs {
    pub prog_fd: c_int,
    pub hid: c_uint,
    pub retval: c_int,
}

#[derive(Debug)]
pub enum BpfError {
    LibBPFError { error: libbpf_rs::Error },
    OsError { errno: u32 },
    Unsupported,
}

impl std::error::Error for BpfError {}

impl Display for BpfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BpfError::LibBPFError { error } => write!(f, "{error}"),
            BpfError::OsError { errno } => {
                write!(f, "{}", libbpf_rs::Error::from_raw_os_error(*errno as i32))
            }
            BpfError::Unsupported => write!(f, "unsupported on this kernel"),
        }
    }
}

impl From<libbpf_rs::Error> for BpfError {
    fn from(e: libbpf_rs::Error) -> BpfError {
        BpfError::LibBPFError { error: e }
    }
}

// C-compatible structures for passing parsed report descriptor to BPF
// These must match the structs in hid_bpf_helpers.h

const HID_MAX_COLLECTIONS: usize = 32;
const HID_MAX_FIELDS: usize = 64;
const HID_MAX_REPORTS: usize = 16;

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
enum HidRdescFieldType {
    Variable = 0,
    Array = 1,
    Constant = 2,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct HidRdescCollection {
    pub usage_page: u16,
    pub usage_id: u16,
    pub collection_type: u8,
}

impl From<&hidreport::Collection> for HidRdescCollection {
    fn from(collection: &hidreport::Collection) -> Self {
        let usage = collection.usages().first();
        Self {
            usage_page: usage.map(|u| u16::from(&u.usage_page)).unwrap_or(0),
            usage_id: usage.map(|u| u16::from(&u.usage_id)).unwrap_or(0),
            collection_type: u8::from(collection.collection_type()),
        }
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct UsageRange {
    pub usage_minimum: u16,
    pub usage_maximum: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union UsageIdUnion {
    pub usage_id: u16,          // For Variable fields
    pub anon_range: UsageRange, // For Array fields (anonymous struct in C)
}

impl std::fmt::Debug for UsageIdUnion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Safe to read usage_id since all union members start at same offset
        f.debug_struct("UsageIdUnion")
            .field("value", unsafe { &self.usage_id })
            .finish()
    }
}

impl Default for UsageIdUnion {
    fn default() -> Self {
        Self { usage_id: 0 }
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct HidRdescField {
    pub field_type: u8,
    pub num_collections: u8,
    pub bits_start: u16,
    pub bits_end: u16,
    pub usage_page: u16,
    pub anon_usage_id: UsageIdUnion,
    pub logical_minimum: i32,
    pub logical_maximum: i32,
    /// Packed boolean flags matching C bitfield layout (HID Main Item attributes):
    /// bit 0: is_relative - Data is relative to previous value
    /// bit 1: wraps - Value wraps around (e.g., rotary encoder)
    /// bit 2: is_nonlinear - Non-linear relationship between logical/physical
    /// bit 3: has_no_preferred_state - No rest position (e.g., free-floating joystick)
    /// bit 4: has_null_state - Can report null/no-data values
    /// bit 5: is_volatile - Volatile (for Output/Feature items)
    /// bit 6: is_buffered_bytes - Fixed-size byte stream vs bitfield
    /// bit 7: reserved
    pub flags: u8,
    pub collections: [HidRdescCollection; HID_MAX_COLLECTIONS],
}

impl HidRdescField {
    /// Pack HID Main Item attributes into u8 matching C bitfield layout
    fn pack_flags(field: &impl hidreport::FieldAttributes) -> u8 {
        ((field.is_relative() as u8) << 0)
            | ((field.wraps() as u8) << 1)
            | ((field.is_nonlinear() as u8) << 2)
            | ((field.has_no_preferred_state() as u8) << 3)
            | ((field.has_null_state() as u8) << 4)
            | ((field.is_volatile().unwrap_or(false) as u8) << 5)
            | ((field.is_buffered_bytes() as u8) << 6)
    }
}

impl From<&hidreport::Field> for HidRdescField {
    fn from(field: &hidreport::Field) -> Self {
        use hidreport::Field;

        let mut c_field = Self::default();

        match field {
            Field::Variable(vf) => {
                c_field.field_type = HidRdescFieldType::Variable as u8;
                c_field.bits_start = vf.bits.start as u16;
                c_field.bits_end = vf.bits.end as u16;
                c_field.usage_page = u16::from(&vf.usage.usage_page);
                c_field.anon_usage_id = UsageIdUnion {
                    usage_id: u16::from(&vf.usage.usage_id),
                };
                c_field.logical_minimum = i32::from(&vf.logical_minimum);
                c_field.logical_maximum = i32::from(&vf.logical_maximum);
                c_field.flags = Self::pack_flags(vf);

                let num_collections = vf.collections.len().min(HID_MAX_COLLECTIONS);
                c_field.num_collections = num_collections as u8;
                for (i, collection) in vf.collections.iter().take(num_collections).enumerate() {
                    c_field.collections[i] = collection.into();
                }
            }
            Field::Array(af) => {
                c_field.field_type = HidRdescFieldType::Array as u8;
                c_field.bits_start = af.bits.start as u16;
                c_field.bits_end = af.bits.end as u16;
                c_field.usage_page = af
                    .usages()
                    .first()
                    .map(|u| u16::from(&u.usage_page))
                    .unwrap_or(0);
                // For arrays: anon_usage_id holds the usage range (usage_minimum to usage_maximum)
                c_field.anon_usage_id = UsageIdUnion {
                    anon_range: UsageRange {
                        usage_minimum: af
                            .usages()
                            .first()
                            .map(|u| u16::from(&u.usage_id))
                            .unwrap_or(0),
                        usage_maximum: af
                            .usages()
                            .last()
                            .map(|u| u16::from(&u.usage_id))
                            .unwrap_or(0),
                    },
                };
                c_field.logical_minimum = i32::from(&af.logical_minimum);
                c_field.logical_maximum = i32::from(&af.logical_maximum);
                c_field.flags = Self::pack_flags(af);

                let num_collections = af.collections.len().min(HID_MAX_COLLECTIONS);
                c_field.num_collections = num_collections as u8;
                for (i, collection) in af.collections.iter().take(num_collections).enumerate() {
                    c_field.collections[i] = collection.into();
                }
            }
            Field::Constant(cf) => {
                c_field.field_type = HidRdescFieldType::Constant as u8;
                c_field.bits_start = cf.bits.start as u16;
                c_field.bits_end = cf.bits.end as u16;
                c_field.num_collections = 0;
                // Constant fields don't implement FieldAttributes trait, flags remain 0
            }
        }

        c_field
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct HidRdescReport {
    pub report_id: u8,
    pub size_in_bits: u16,
    pub num_fields: u8,
    pub fields: [HidRdescField; HID_MAX_FIELDS],
}

impl Default for HidRdescReport {
    fn default() -> Self {
        Self {
            report_id: 0,
            size_in_bits: 0,
            num_fields: 0,
            fields: [HidRdescField::default(); HID_MAX_FIELDS],
        }
    }
}

impl<T: hidreport::Report> From<&T> for HidRdescReport {
    fn from(report: &T) -> Self {
        let mut c_report = Self::default();

        if let Some(report_id) = report.report_id() {
            c_report.report_id = u8::from(report_id);
        } else {
            c_report.report_id = 0;
        }

        c_report.size_in_bits = report.size_in_bits() as u16;

        let num_fields = report.fields().len().min(HID_MAX_FIELDS);
        c_report.num_fields = num_fields as u8;

        for (i, field) in report.fields().iter().take(num_fields).enumerate() {
            c_report.fields[i] = field.into();
        }

        c_report
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct HidRdescDescriptor {
    pub num_input_reports: u8,
    pub num_output_reports: u8,
    pub num_feature_reports: u8,
    pub input_reports: [HidRdescReport; HID_MAX_REPORTS],
    pub output_reports: [HidRdescReport; HID_MAX_REPORTS],
    pub feature_reports: [HidRdescReport; HID_MAX_REPORTS],
}

impl Default for HidRdescDescriptor {
    fn default() -> Self {
        Self {
            num_input_reports: 0,
            num_output_reports: 0,
            num_feature_reports: 0,
            input_reports: [HidRdescReport::default(); HID_MAX_REPORTS],
            output_reports: [HidRdescReport::default(); HID_MAX_REPORTS],
            feature_reports: [HidRdescReport::default(); HID_MAX_REPORTS],
        }
    }
}

impl From<&hidreport::ReportDescriptor> for HidRdescDescriptor {
    fn from(rdesc: &hidreport::ReportDescriptor) -> Self {
        let mut c_rdesc = Self::default();

        let num_input = rdesc.input_reports().len().min(HID_MAX_REPORTS);
        c_rdesc.num_input_reports = num_input as u8;
        for (i, report) in rdesc.input_reports().iter().take(num_input).enumerate() {
            c_rdesc.input_reports[i] = report.into();
        }

        let num_output = rdesc.output_reports().len().min(HID_MAX_REPORTS);
        c_rdesc.num_output_reports = num_output as u8;
        for (i, report) in rdesc.output_reports().iter().take(num_output).enumerate() {
            c_rdesc.output_reports[i] = report.into();
        }

        let num_feature = rdesc.feature_reports().len().min(HID_MAX_REPORTS);
        c_rdesc.num_feature_reports = num_feature as u8;
        for (i, report) in rdesc.feature_reports().iter().take(num_feature).enumerate() {
            c_rdesc.feature_reports[i] = report.into();
        }

        c_rdesc
    }
}

pub struct HidBPF {}

/// Metadata for a variable extracted from BTF
#[derive(Debug, Clone)]
pub struct VariableMetadata {
    pub name: String,
    pub offset: usize,
    pub size: usize,
}

/// Cached BTF metadata extracted from .bss and .data sections
#[derive(Debug, Default)]
pub struct BpfMetadata {
    /// UDEV properties found in .bss section
    pub udev_properties_bss: Vec<VariableMetadata>,
    /// UDEV properties found in .data section
    pub udev_properties_data: Vec<VariableMetadata>,
    /// HID_REPORT_DESCRIPTOR in .bss section
    pub report_descriptor_bss: Option<VariableMetadata>,
    /// HID_REPORT_DESCRIPTOR in .data section
    pub report_descriptor_data: Option<VariableMetadata>,
}

impl BpfMetadata {
    pub fn from_btf(btf: &Btf) -> Self {
        Self {
            udev_properties_bss: get_udev_properties_metadata(".bss", btf),
            udev_properties_data: get_udev_properties_metadata(".data", btf),
            report_descriptor_bss: get_report_descriptor_metadata(".bss", btf),
            report_descriptor_data: get_report_descriptor_metadata(".data", btf),
        }
    }

    /// Check if the BPF program expects a HID_REPORT_DESCRIPTOR
    pub fn has_report_descriptor(&self) -> bool {
        self.report_descriptor_bss.is_some() || self.report_descriptor_data.is_some()
    }
}

/// Generic helper function to extract variable metadata from a BTF DataSec
/// Returns a vector of VariableMetadata for variables matching the predicate
fn extract_variables_metadata<F>(array_name: &str, btf: &Btf, predicate: F) -> Vec<VariableMetadata>
where
    F: Fn(&str) -> Option<String>,
{
    let Some(btf_map) = btf.type_by_name::<libbpf_rs::btf::types::DataSec>(array_name) else {
        return Vec::new();
    };

    btf_map
        .iter()
        .filter_map(|v| {
            let v_type = btf.type_by_id::<libbpf_rs::btf::BtfType>(v.ty).unwrap();

            v_type
                .name()
                .and_then(|n| n.to_str())
                .and_then(|name| predicate(name))
                .map(|name| {
                    let offset: usize = v.offset.try_into().unwrap();
                    VariableMetadata {
                        name,
                        offset,
                        size: v.size,
                    }
                })
        })
        .collect()
}

/// Helper function to extract UDEV property metadata from a BTF DataSec
/// Returns a vector of VariableMetadata for each UDEV_PROP_* variable found
pub fn get_udev_properties_metadata(array_name: &str, btf: &Btf) -> Vec<VariableMetadata> {
    extract_variables_metadata(array_name, btf, |name| {
        name.strip_prefix("UDEV_PROP_").map(String::from)
    })
}

/// Helper function to find HID_REPORT_DESCRIPTOR in a BTF DataSec
pub fn get_report_descriptor_metadata(array_name: &str, btf: &Btf) -> Option<VariableMetadata> {
    extract_variables_metadata(array_name, btf, |name| {
        if name == "HID_REPORT_DESCRIPTOR" {
            Some(String::from(name))
        } else {
            None
        }
    })
    .into_iter()
    .next()
}

pub trait HidBPFLoader {
    fn load(&self, object: OpenObject, _device: &hidudev::HidUdev) -> Result<Object, BpfError> {
        Ok(object.load()?)
    }

    fn probe(
        &self,
        object: &Object,
        device: &hidudev::HidUdev,
        rdesc_bytes: &[u8],
    ) -> Result<i32, BpfError> {
        match object
            .progs()
            .find(|prog| prog.name().to_str().unwrap() == OsStr::new("probe"))
        {
            None => Ok(0),
            Some(probe) => {
                let args = hid_bpf_probe_args::from(device, rdesc_bytes);
                run_syscall_prog_probe(&probe, args)
            }
        }
    }

    fn inject_udev_properties_in_array(
        &self,
        object: &mut Object,
        array_name: &str,
        properties_metadata: &[VariableMetadata],
        udev_properties: &[hidudev::HidUdevProperty],
    ) -> Result<(), BpfError> {
        if properties_metadata.is_empty() {
            return Ok(());
        }

        object
            .maps_mut()
            .filter(|m| m.name().to_str().unwrap().ends_with(array_name))
            .for_each(|m| {
                for k in m.keys() {
                    let Some(mut data) = m.lookup(&k, libbpf_rs::MapFlags::ANY).unwrap() else {
                        continue;
                    };

                    let mut updated = false;

                    for var in properties_metadata {
                        if let Some(prop) = udev_properties.iter().find(|p| p.name == var.name) {
                            let buf = prop.value.as_bytes();

                            if buf.len() < var.size {
                                let end = var.offset + buf.len();
                                data[var.offset..end].clone_from_slice(buf);

                                log::debug!(target: "libbpf",
                                            "inserting {}={} in map {}", prop.name, prop.value, m.name().to_str().unwrap());
                                updated = true;
                            }
                        }
                    }

                    if updated {
                        let r = m.update(&k, &data, libbpf_rs::MapFlags::ANY);
                        log::debug!(target: "libbpf",
                                    "updated map {}: {:?}", m.name().to_str().unwrap(), r);
                    }
                }
            });
        Ok(())
    }

    fn inject_udev_properties(
        &self,
        object: &mut Object,
        metadata: &BpfMetadata,
        device: &hidudev::HidUdev,
        extra_props: &[hidudev::HidUdevProperty],
    ) -> Result<(), BpfError> {
        let udev_properties: Vec<hidudev::HidUdevProperty> = device
            .udev_properties()
            .into_iter()
            .filter(|prop| !extra_props.iter().any(|ep| ep.name == prop.name))
            .chain(extra_props.iter().map(hidudev::HidUdevProperty::from))
            .collect();

        self.inject_udev_properties_in_array(
            object,
            ".bss",
            &metadata.udev_properties_bss,
            &udev_properties,
        )?;
        self.inject_udev_properties_in_array(
            object,
            ".data",
            &metadata.udev_properties_data,
            &udev_properties,
        )?;
        Ok(())
    }

    fn inject_report_descriptor_in_array(
        &self,
        object: &mut Object,
        array_name: &str,
        rdesc_metadata: Option<&VariableMetadata>,
        rdesc_bytes: &[u8],
    ) -> Result<(), BpfError> {
        let Some(var) = rdesc_metadata else {
            return Ok(());
        };

        if rdesc_bytes.len() > var.size {
            log::warn!(target: "libbpf",
                "HID_REPORT_DESCRIPTOR too small: {} bytes needed, {} bytes available", rdesc_bytes.len(), var.size);
            return Ok(());
        }

        object
            .maps_mut()
            .filter(|m| m.name().to_str().unwrap().ends_with(array_name))
            .for_each(|m| {
                for k in m.keys() {
                    let Some(mut data) = m.lookup(&k, libbpf_rs::MapFlags::ANY).unwrap() else {
                        continue;
                    };
                    let end = var.offset + rdesc_bytes.len();
                    data[var.offset..end].clone_from_slice(rdesc_bytes);

                    log::debug!(target: "libbpf",
                        "inserting HID_REPORT_DESCRIPTOR ({} bytes) in map {}", rdesc_bytes.len(), m.name().to_str().unwrap());

                    let r = m.update(&k, &data, libbpf_rs::MapFlags::ANY);
                    log::debug!(target: "libbpf",
                        "updated map {}: {:?}", m.name().to_str().unwrap(), r);
                }
            });

        Ok(())
    }

    fn inject_report_descriptor(
        &self,
        object: &mut Object,
        metadata: &BpfMetadata,
        rdesc_bytes: &[u8],
    ) -> Result<(), BpfError> {
        // Only parse the report descriptor if the BPF program needs it
        if !metadata.has_report_descriptor() {
            log::debug!(target: "libbpf", "BPF program doesn't use HID_REPORT_DESCRIPTOR, skipping parsing");
            return Ok(());
        }

        let rdesc = hidreport::ReportDescriptor::try_from(rdesc_bytes).unwrap();

        // Convert to C-compatible struct using From trait
        let c_rdesc: HidRdescDescriptor = (&rdesc).into();

        // Convert to byte slice
        let c_rdesc_bytes = unsafe {
            std::slice::from_raw_parts(
                &c_rdesc as *const HidRdescDescriptor as *const u8,
                std::mem::size_of::<HidRdescDescriptor>(),
            )
        };

        self.inject_report_descriptor_in_array(
            object,
            ".bss",
            metadata.report_descriptor_bss.as_ref(),
            c_rdesc_bytes,
        )?;
        self.inject_report_descriptor_in_array(
            object,
            ".data",
            metadata.report_descriptor_data.as_ref(),
            c_rdesc_bytes,
        )?;
        Ok(())
    }

    fn attach_and_pin(
        &self,
        object: &mut Object,
        device: &hidudev::HidUdev,
        bpffs_path: &str,
    ) -> Result<Vec<String>, BpfError>;
}

pub struct HidBPFTrace {
    supported: bool,
}

#[derive(Default)]
pub struct HidBPFStructOps {}

pub fn get_bpffs_path(sysname: &str, object: &str) -> String {
    format!(
        "/sys/fs/bpf/hid/{}/{}",
        sysname.replace([':', '.'], "_"),
        object.replace([':', '.'], "_"),
    )
}

pub fn remove_bpf_objects(sysname: &str) -> std::io::Result<()> {
    let path = get_bpffs_path(sysname, "");

    std::fs::remove_dir_all(path).ok();

    Ok(())
}

fn run_syscall_prog_generic<T>(prog: &libbpf_rs::Program, data: T) -> Result<T, BpfError> {
    let fd = prog.as_fd().as_raw_fd();
    let data_ptr: *const libc::c_void = &data as *const _ as *const libc::c_void;
    let mut run_opts = libbpf_sys::bpf_test_run_opts {
        sz: std::mem::size_of::<libbpf_sys::bpf_test_run_opts>()
            .try_into()
            .unwrap(),
        ctx_in: data_ptr,
        ctx_size_in: std::mem::size_of::<T>() as u32,
        ..Default::default()
    };

    let run_opts_ptr: *mut libbpf_sys::bpf_test_run_opts = &mut run_opts;

    match unsafe { libbpf_sys::bpf_prog_test_run_opts(fd, run_opts_ptr) } {
        0 => Ok(data),
        e => Err(BpfError::OsError { errno: -e as u32 }),
    }
}

fn run_syscall_prog_attach(
    prog: &libbpf_rs::Program,
    attach_args: AttachProgArgs,
) -> Result<i32, BpfError> {
    let args = run_syscall_prog_generic(prog, attach_args)?;
    if args.retval < 0 {
        Err(BpfError::OsError {
            errno: -args.retval as u32,
        })
    } else {
        Ok(args.retval)
    }
}

fn run_syscall_prog_probe(
    prog: &libbpf_rs::Program,
    probe_args: hid_bpf_probe_args,
) -> Result<i32, BpfError> {
    let args = run_syscall_prog_generic(prog, probe_args)?;
    if args.retval != 0 {
        Err(BpfError::OsError {
            errno: -args.retval as u32,
        })
    } else {
        Ok(args.retval)
    }
}

/*
* We have to rewrite our own `pin()` because we must be pinning the link
* provided by HID-BPF, not the Program object nor a normal libbpf_rs::Link
*/
fn pin_hid_bpf_prog(link: i32, path: &str) -> Result<(), BpfError> {
    unsafe {
        let c_str = std::ffi::CString::new(path).unwrap();

        match libbpf_sys::bpf_obj_pin(link, c_str.as_ptr()) {
            0 => Ok(()),
            e => Err(BpfError::OsError { errno: -e as u32 }),
        }
    }
}

impl hid_bpf_probe_args {
    fn from(device: &hidudev::HidUdev, rdesc_bytes: &[u8]) -> Self {
        let mut rdesc = [0u8; 4096];
        let length = rdesc_bytes.len().min(4096);
        rdesc[..length].copy_from_slice(&rdesc_bytes[..length]);

        hid_bpf_probe_args {
            hid: device.id(),
            rdesc_size: length as u32,
            rdesc,
            retval: -1,
        }
    }
}

impl Default for HidBPFTrace {
    fn default() -> Self {
        let skel_builder = AttachSkelBuilder::default();
        let mut open_object = MaybeUninit::uninit();

        // Test if the kernel supports HidBPFTrace by trying to load the skeleton
        let supported = skel_builder
            .open(&mut open_object)
            .map(|skel| skel.load())
            .is_ok();

        Self { supported }
    }
}

impl HidBPFTrace {
    fn load_prog(&self, prog: &Program, hid_id: u32, bpffs_path: &str) -> Result<String> {
        // Create skeleton on demand
        let skel_builder = AttachSkelBuilder::default();
        let mut open_object = MaybeUninit::uninit();

        let attach_obj = skel_builder
            .open(&mut open_object)
            .context("Failed to open skeleton")?
            .load()
            .context("Failed to load skeleton")?;

        let attach_args = AttachProgArgs {
            prog_fd: prog.as_fd().as_raw_fd(),
            hid: hid_id,
            retval: -1,
        };

        let link = run_syscall_prog_attach(&attach_obj.progs.attach_prog, attach_args).context(
            format!("failed the syscall for {}", prog.name().to_str().unwrap()),
        )?;

        log::debug!(
            target: "libbpf",
            "successfully attached {} to device id {}",
            &prog.name().to_str().unwrap(),
            hid_id,
        );

        let path = format!("{}/{}", bpffs_path, prog.name().to_str().unwrap(),);

        fs::create_dir_all(bpffs_path).unwrap_or_else(|why| {
            log::warn!("! {:?}", why.kind());
        });

        pin_hid_bpf_prog(link, &path).context(format!(
            "could not pin {} to device id {}",
            &prog.name().to_str().unwrap(),
            hid_id
        ))?;

        log::debug!(target: "libbpf", "Successfully pinned prog at {}", path);

        Ok(path)
    }

    fn load_progs(
        &self,
        object: &Object,
        hid_id: u32,
        bpffs_path: &str,
    ) -> Result<Vec<String>, BpfError> {
        let attached: Vec<String> = object
            .progs()
            .filter(|p| matches!(p.prog_type(), libbpf_rs::ProgramType::Tracing))
            .map(|p| self.load_prog(&p, hid_id, bpffs_path))
            .inspect(|r| {
                if let Err(e) = r {
                    log::warn!("failed to attach to device id {}: {:#}", hid_id, e,);
                }
            })
            .flatten()
            .collect();

        if attached.is_empty() {
            Err(BpfError::OsError {
                errno: libc::EINVAL as u32,
            })
        } else {
            Ok(attached)
        }
    }
}

impl HidBPFLoader for HidBPFTrace {
    fn load(&self, object: OpenObject, _device: &hidudev::HidUdev) -> Result<Object, BpfError> {
        if self.supported {
            Ok(object.load()?)
        } else {
            Err(BpfError::OsError {
                errno: libc::ENOTSUP as u32,
            })
        }
    }
    fn attach_and_pin(
        &self,
        object: &mut Object,
        device: &hidudev::HidUdev,
        bpffs_path: &str,
    ) -> Result<Vec<String>, BpfError> {
        let hid_id = device.id();

        self.load_progs(object, hid_id, bpffs_path)
    }
}

impl HidBPFLoader for HidBPFStructOps {
    fn load(
        &self,
        mut open_object: OpenObject,
        device: &hidudev::HidUdev,
    ) -> Result<Object, BpfError> {
        let bytes_hid_id: [u8; 4] = device.id().to_le_bytes();

        open_object
            .maps_mut()
            .filter(|m| matches!(m.map_type(), libbpf_rs::MapType::StructOps))
            .for_each(|mut m| {
                if let Some(data) = m.initial_value_mut() {
                    data[0..4].copy_from_slice(&bytes_hid_id);
                }
            });

        open_object.load().map_err(|e| {
            // Unfortunately libbpf gives us ENOENT if the kernel does
            // not support struct ops which makes it impossible to distinguish
            // between "not supported" and "file not found".
            // Since we do our best to only ever load files that exist
            // in the fs, let's assume ENOENT here means "not supported".
            // Which is a much better error than "no such file or directory" for an
            // object that definitely exists...
            if e.kind() == libbpf_rs::ErrorKind::NotFound {
                BpfError::Unsupported
            } else {
                BpfError::LibBPFError { error: e }
            }
        })
    }

    fn attach_and_pin(
        &self,
        object: &mut Object,
        _device: &hidudev::HidUdev,
        bpffs_path: &str,
    ) -> Result<Vec<String>, BpfError> {
        fs::create_dir_all(bpffs_path).unwrap_or_else(|why| {
            log::warn!("! {:?}", why.kind());
        });

        object
            .maps_mut()
            .filter(|m| matches!(m.map_type(), libbpf_rs::MapType::StructOps))
            .map(|mut m| {
                let path = format!("{}/{}", bpffs_path, m.name().to_str().unwrap());

                m.attach_struct_ops()?.pin(&path)?;
                Ok(path)
            })
            .collect()
    }
}

fn get_bpf_loader(open_object: &OpenObject) -> &'static dyn HidBPFLoader {
    static HID_BPF_TRACE: OnceLock<HidBPFTrace> = OnceLock::new();
    static HID_BPF_STRUCT_OPS: OnceLock<HidBPFStructOps> = OnceLock::new();

    let have_tracing: bool = open_object.progs().any(|p| {
        matches!(p.prog_type(), libbpf_rs::ProgramType::Tracing)
            && p.section().to_str().unwrap().starts_with("fmodret/hid_")
    });

    if have_tracing {
        log::debug!("Using HID_BPF_TRACE");
        HID_BPF_TRACE.get_or_init(HidBPFTrace::default)
    } else {
        log::debug!("Using HID_BPF_STRUCT_OPS");
        HID_BPF_STRUCT_OPS.get_or_init(HidBPFStructOps::default)
    }
}

impl HidBPF {
    fn pin_maps(object: &mut Object, bpffs_path: &String) -> Result<()> {
        // compiler internal maps contain the name of the object and a dot
        for mut map in object
            .maps_mut()
            .filter(|map| !map.name().to_str().unwrap().contains('.'))
            .filter(|m| !matches!(m.map_type(), libbpf_rs::MapType::StructOps))
        {
            let path = format!("{}/{}", bpffs_path, map.name().to_str().unwrap(),);

            map.pin(&path)
                .context(format!("Failed to pin map at {}", path))?;
            log::debug!(target: "libbpf", "Successfully pinned map at {}", path);
        }

        Ok(())
    }

    pub fn load_programs(
        path: &Path,
        device: &hidudev::HidUdev,
        properties: &[hidudev::HidUdevProperty],
    ) -> Result<()> {
        log::debug!(target: "libbpf", "loading BPF object at {:?}", path.display());

        let syspath = device.syspath();
        let rdesc_path = syspath + "/report_descriptor";
        let rdesc_bytes = fs::read(rdesc_path).context("couldn't read report descriptor")?;

        let mut obj_builder = libbpf_rs::ObjectBuilder::default();
        let open_object = obj_builder.open_file(path)?;

        let loader = get_bpf_loader(&open_object);

        let mut object = loader.load(open_object, device)?;
        let object_name = path.file_stem().unwrap().to_str().unwrap();

        let btf = Btf::from_bpf_object(unsafe { object.as_libbpf_object().as_ref() })?.unwrap();
        let metadata = BpfMetadata::from_btf(&btf);

        loader
            .inject_udev_properties(&mut object, &metadata, device, properties)
            .context(format!("couldn't set udev properties on {object_name}"))?;

        loader
            .inject_report_descriptor(&mut object, &metadata, &rdesc_bytes)
            .context(format!(
                "couldn't inject report descriptor on {object_name}"
            ))?;

        /*
         * if there is a "probe" syscall, execute it and
         * check for the return value: if not 0, then ignore
         * this bpf.o file
         */
        loader
            .probe(&object, device, &rdesc_bytes)
            .context(format!("probe() of {object_name} failed"))?;

        let bpffs_path = get_bpffs_path(&device.sysname(), object_name);
        loader
            .attach_and_pin(&mut object, device, &bpffs_path)
            .context(format!("attach_and_pin() of {object_name} failed"))?;

        if let Err(e) = HidBPF::pin_maps(&mut object, &bpffs_path) {
            let _ = std::fs::remove_dir_all(bpffs_path);
            bail!(e);
        };

        Ok(())
    }
}
