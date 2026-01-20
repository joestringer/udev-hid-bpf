// SPDX-License-Identifier: GPL-2.0-only

use anyhow::{bail, ensure, Context, Result};
use clap::{Parser, Subcommand};
use regex::Regex;
use serde::Serialize;
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use udev_hid_bpf::{bpf, hidudev, modalias};

static DEFAULT_BPF_DIRS: &str = env!("BPF_LOOKUP_DIRS");
static BINDIR: &str = env!("MESON_BINDIR");

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Folder to look at for bpf objects
    #[arg(short, long)]
    bpf: Option<PathBuf>,
    /// Print debugging information
    #[arg(short, long, default_value_t = false)]
    debug: bool,
    /// Enable verbose output
    #[arg(short, long, default_value_t = false)]
    verbose: bool,
    #[command(subcommand)]
    command: Commands,
}

fn print_to_log(lvl: libbpf_rs::PrintLevel, msg: String) {
    let level = if msg.contains("skipping unrecognized data section")
        && msg.contains(".hid_bpf_config")
        || msg.contains("skipping relo section")
    {
        libbpf_rs::PrintLevel::Debug
    } else {
        lvl
    };
    match level {
        libbpf_rs::PrintLevel::Debug => log::debug!(target: "libbpf", "{}", msg.trim()),
        libbpf_rs::PrintLevel::Info => log::info!(target: "libbpf", "{}", msg.trim()),
        libbpf_rs::PrintLevel::Warn => log::warn!(target: "libbpf", "{}", msg.trim()),
    }
}

// For some reason we can't use PropertyTyple::try_from directly in #[arg(value_parser])
fn tuple_parse(s: &str) -> std::result::Result<hidudev::HidUdevProperty, clap::error::Error> {
    hidudev::HidUdevProperty::try_from(s)
        .map_err(|_| clap::Error::new(clap::error::ErrorKind::ValueValidation))
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Load BPF programs for a device. This command is typically invoked
    /// from a udev rule on the "add" action.
    Add {
        /// The sysfs path to a device, e.g. /sys/bus/hid/devices/0003:045E:07A5.000B
        /// followed by an optional path to a BPF program.
        ///
        /// If one path is provided, that path is the sysfs path to a device.
        ///
        /// If two paths are provided, the first path is the sysfs path to a device followed
        /// by the path to or name of a BPF program.
        ///
        /// If three or more paths are provided, all paths before a literal '-' are
        /// sysfs paths to devices, all paths after the literal '-' are paths to or names of BPF
        /// programs. If the first path is a literal '-' the given BPF programs are
        /// loaded against all devices that match any of the bus:vid:pid combination
        /// as specified in the BPF program.
        ///
        /// BPF programs specified by names only instead of complete paths are looked up
        /// in --bpfdir followed by the built-in BPF directories.
        #[clap(num_args = 1..)]
        paths: Vec<String>,
        /// Additional folder to look at for BPF objects. This folder takes precedence over
        /// the built-in lookup directories.
        #[arg(short, long)]
        bpfdir: Option<PathBuf>,
        /// Remove current BPF programs for the device first.
        /// This is equivalent to running udev-hid-bpf remove with the
        /// same device argument first.
        #[arg(long, default_value_t = false)]
        replace: bool,

        /// Provide an arbitrary NAME=VALUE pair to the BPF program.
        /// This NAME=VALUE pair is treated as if it was a
        /// udev property set on the device, taking precedence over
        /// any udev property of the same name.
        /// This option may be specified multiple times to
        /// supply multiple properties. Empty properties must be
        /// the empty string (NAME="")
        #[arg(short, long, value_parser=tuple_parse)]
        property: Vec<hidudev::HidUdevProperty>,
    },
    /// Remove all BPF programs for a given device. This command is typically
    /// invoked from a udev rule on the "remove" action.
    Remove {
        /// sysfs path to a device, e.g. /sys/bus/hid/devices/0003:045E:07A5.000B
        #[clap(num_args = 1..)]
        devpaths: Vec<PathBuf>,
    },
    /// List currently installed BPF programs
    ListBpfPrograms {
        /// Folder to look at for bpf objects
        #[arg(short, long)]
        bpfdir: Option<PathBuf>,
    },
    /// List available devices
    ListDevices {
        /// Only list devices that currently have BPF programs loaded
        #[arg(long, default_value_t = false)]
        with_bpfs: bool,
    },
    /// Inspect a bpf.o file
    Inspect {
        /// One or more paths to a bpf.o file
        paths: Vec<PathBuf>,
    },
    /// List currently loaded BPF programs from /sys/fs/bpf/hid
    ListLoaded {
        /// Filter by syspath (e.g., /sys/bus/hid/devices/0003:056A:0374.0008 or 0003:056A:0374.0008)
        #[arg(long)]
        syspath: Option<String>,
        /// Output format: json (default) or udev
        #[arg(long, default_value = "json")]
        format: String,
    },
    /// Install one bpf.o file.
    ///
    /// The file is installed into /etc/udev-hid-bpf/ with a corresponding udev rule
    /// in /etc/udev/rules.d/. This command should be used for testing a single bpf.o file
    /// and/or in the case where a proper install of udev-hid-bpf is not otherwise suitable.
    ///
    /// This command looks for an existing udev-hid-bpf executable in the configured prefix,
    /// that executable is referenced in the udev rule. Use the --install-exe argument
    /// to install the current executable in that prefix.
    Install {
        /// Path to a bpf.o file
        path: PathBuf,
        /// The prefix, converted to $prefix/bin. Defaults to the compiled-in prefix.
        #[arg(long)]
        prefix: Option<PathBuf>,
        /// Overwrite an existing file with the same name
        #[arg(long, default_value_t = false)]
        force: bool,
        /// Install the udev-hid-bpf executable at the given prefix (if not already installed)
        #[arg(long, default_value_t = false)]
        install_exe: bool,
        /// Do everything except actually creating/installing target files and directories
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
}

fn default_bpf_dirs() -> Vec<PathBuf> {
    DEFAULT_BPF_DIRS.split(':').map(PathBuf::from).collect()
}

fn cmd_add(
    devices: &[PathBuf],
    objfiles: &[String],
    bpfdir: Option<PathBuf>,
    properties: &[hidudev::HidUdevProperty],
) -> Result<()> {
    for syspath in devices {
        ensure!(syspath.exists(), "Invalid syspath {syspath:?}");
    }

    let target_bpf_dirs: Vec<PathBuf> = bpfdir.into_iter().chain(default_bpf_dirs()).collect();
    if objfiles.is_empty() {
        ensure!(
            target_bpf_dirs.iter().any(|d| d.exists()),
            "bpf directories {:?} don't exist, aborting",
            target_bpf_dirs
        );
    }

    for syspath in devices {
        let dev = hidudev::HidUdev::from_syspath(syspath)?;
        if objfiles.is_empty() {
            if !dev.is_ignored() {
                let objfiles = dev.search_for_matching_objfiles(&target_bpf_dirs);
                dev.load_bpf_files(&objfiles, properties)?;
            } else {
                log::warn!("Device {syspath:?} has HID_BPF_IGNORE_DEVICE set, skipping");
            }
        } else {
            let bpf_files = hidudev::HidUdev::find_named_objfiles(&objfiles, &target_bpf_dirs);
            if bpf_files.is_empty() {
                log::warn!("Unable to find any BPF programs for: {:?}", objfiles);
            } else {
                dev.load_bpf_files(&bpf_files, properties)?;
            }
        }
    }

    Ok(())
}

fn sysname_from_syspath(syspath: &PathBuf) -> std::io::Result<String> {
    let re = Regex::new(r"[A-Z0-9]{4}:[A-Z0-9]{4}:[A-Z0-9]{4}\.[A-Z0-9]{4}").unwrap();
    let abspath = std::fs::read_link(syspath).unwrap_or(syspath.clone());
    abspath
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|d| re.captures(d).is_some())
        .map(String::from)
        .ok_or(std::io::Error::from_raw_os_error(libc::EINVAL))
}

fn cmd_remove(syspaths: &Vec<PathBuf>) -> Result<()> {
    for syspath in syspaths {
        let sysname = match hidudev::HidUdev::from_syspath(syspath) {
            Ok(dev) => dev.sysname(),
            Err(e) => match e.raw_os_error() {
                Some(libc::ENODEV) => sysname_from_syspath(syspath)?,
                _ => return Err(e.into()),
            },
        };
        bpf::remove_bpf_objects(&sysname)?;
    }
    Ok(())
}

fn find_bpfs(dir: &PathBuf) -> Result<Vec<PathBuf>> {
    ensure!(dir.exists(), "File or directory {dir:?} does not exist");

    let metadata = dir.metadata().unwrap();
    let result = if metadata.is_file() {
        if dir.to_str().unwrap().ends_with(".bpf.o") {
            return Ok(vec![dir.into()]);
        }
        bail!("Not a bpf.o file");
    } else {
        std::fs::read_dir(dir)?
            .flatten()
            .flat_map(|f| find_bpfs(&f.path()))
            .flatten()
            .collect()
    };

    Ok(result)
}

fn cmd_list_bpf_programs(bpfdir: Option<PathBuf>) -> Result<()> {
    let dirs: Vec<PathBuf> = bpfdir.into_iter().chain(default_bpf_dirs()).collect();
    let files = dirs
        .iter()
        .map(move |dir| (dir, find_bpfs(dir)))
        .filter(|t| matches!(t, (_, Ok(_))))
        .inspect(|t| {
            let (dir, files) = t;
            if !files.as_ref().unwrap().is_empty() {
                println!(
                    "Showing available BPF files in {}:",
                    dir.as_path().to_str().unwrap()
                );
                files
                    .iter()
                    .flatten()
                    .for_each(|f| println!(" {}", f.to_str().unwrap()));
            }
        })
        .flat_map(move |t| t.1.into_iter())
        .flatten()
        .collect::<Vec<PathBuf>>();

    ensure!(!files.is_empty(), "no BPF object file found in {dirs:?}");

    println!("Use udev-hid-bpf inspect <file> to obtain more information about a BPF object file.");
    Ok(())
}

fn cmd_list_devices(with_bpfs: bool) -> Result<()> {
    let re = Regex::new(r"hid:b([A-Z0-9]{4})g([A-Z0-9]{4})v0000([A-Z0-9]{4})p0000([A-Z0-9]{4})")
        .unwrap();

    println!("devices:");
    // We use this path because it looks nicer than the true device path in /sys/devices/pci...
    for entry in std::fs::read_dir("/sys/bus/hid/devices")? {
        let syspath = entry.unwrap().path();
        let device = udev::Device::from_syspath(&syspath)?;
        let name = device.property_value("HID_NAME").unwrap().to_str().unwrap();
        if let Some(Some(matches)) = device
            .property_value("MODALIAS")
            .map(|modalias| re.captures(modalias.to_str().unwrap()))
        {
            let bus = matches.get(1).unwrap().as_str();
            let group = matches.get(2).unwrap().as_str();
            let vid = matches.get(3).unwrap().as_str();
            let pid = matches.get(4).unwrap().as_str();

            let bus = match bus {
                "0001" => "BUS_PCI",
                "0002" => "BUS_ISAPNP",
                "0003" => "BUS_USB",
                "0004" => "BUS_HIL",
                "0005" => "BUS_BLUETOOTH",
                "0006" => "BUS_VIRTUAL",
                "0010" => "BUS_ISA",
                "0011" => "BUS_I8042",
                "0012" => "BUS_XTKBD",
                "0013" => "BUS_RS232",
                "0014" => "BUS_GAMEPORT",
                "0015" => "BUS_PARPORT",
                "0016" => "BUS_AMIGA",
                "0017" => "BUS_ADB",
                "0018" => "BUS_I2C",
                "0019" => "BUS_HOST",
                "001A" => "BUS_GSC",
                "001B" => "BUS_ATARI",
                "001C" => "BUS_SPI",
                "001D" => "BUS_RMI",
                "001E" => "BUS_CEC",
                "001F" => "BUS_INTEL_ISHTP",
                "0020" => "BUS_AMD_SFH",
                _ => bus,
            };

            let group = match group {
                "0001" => "HID_GROUP_GENERIC",
                "0002" => "HID_GROUP_MULTITOUCH",
                "0003" => "HID_GROUP_SENSOR_HUB",
                "0004" => "HID_GROUP_MULTITOUCH_WIN_8",
                "0100" => "HID_GROUP_RMI",
                "0101" => "HID_GROUP_WACOM",
                "0102" => "HID_GROUP_LOGITECH_DJ_DEVICE",
                "0103" => "HID_GROUP_STEAM",
                "0104" => "HID_GROUP_LOGITECH_27MHZ_DEVICE",
                "0105" => "HID_GROUP_VIVALDI",
                _ => group,
            };

            let path = bpf::get_bpffs_path(&syspath.file_name().unwrap().to_string_lossy(), "");
            let bpfs: Vec<PathBuf> = PathBuf::from(path)
                .read_dir()
                .and_then(|entries| Ok(entries))
                .into_iter()
                .flat_map(|entries| entries)
                .filter_map(|dir| {
                    let dir = dir.ok()?;
                    if dir.file_type().ok()?.is_dir() {
                        Some(dir.path())
                    } else {
                        None
                    }
                })
                .collect();

            if with_bpfs {
                if bpfs.is_empty() {
                    continue;
                }
            }

            println!("  -  syspath:      \"{}\"", syspath.to_str().unwrap());
            println!("     name:         \"{name}\"");
            println!("     device entry: \"HID_DEVICE({bus}, {group}, 0x{vid}, 0x{pid})\"");
            if !bpfs.is_empty() {
                println!("     bpfs:");
                for bpf in bpfs {
                    println!("       - {:?}", bpf.file_name().unwrap());
                }
            }
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct InspectionDevice {
    bus: String,
    group: String,
    vid: String,
    pid: String,
}

#[derive(Serialize)]
struct InspectionProgram {
    name: String,
    section: String,
}

#[derive(Serialize)]
struct InspectionMap {
    name: String,
}

#[derive(Serialize)]
struct InspectionUdevProp {
    name: String,
    size: usize,
    readonly: bool,
}

#[derive(Serialize)]
struct InspectionData {
    filename: String,
    devices: Vec<InspectionDevice>,
    programs: Vec<InspectionProgram>,
    maps: Vec<InspectionMap>,
    udev_properties: Vec<InspectionUdevProp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    report_descriptor_size: Option<usize>,
}

#[derive(Serialize)]
struct LoadedMap {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
}

#[derive(Serialize)]
struct LoadedProgram {
    name: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    callbacks: Vec<ProgramCallback>,
}

#[derive(Serialize, Clone)]
struct ProgramCallback {
    prog_name: String,
}

#[derive(Serialize)]
struct LoadedBpfObject {
    name: String,
    programs: Vec<LoadedProgram>,
    maps: Vec<LoadedMap>,
}

#[derive(Serialize)]
struct LoadedDevice {
    sysname: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    syspath: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    detached: bool,
    bpf_objects: Vec<LoadedBpfObject>,
}

#[derive(Serialize)]
struct LoadedBpfData {
    devices: Vec<LoadedDevice>,
}

fn inspect(path: &PathBuf) -> Result<InspectionData> {
    ensure!(path.exists(), "Invalid bpf.o path {path:?}");

    let btf = libbpf_rs::btf::Btf::from_path(path)
        .context(format!("Failed to read BPF from {:?}", path))?;
    let bpf_metadata = bpf::BpfMetadata::from_btf(&btf);

    let metadata = modalias::Metadata::from_btf(&btf);
    let devices: Vec<InspectionDevice> = metadata
        .and_then(|metadata| {
            Some(
                metadata
                    .modaliases()
                    .map(|modalias| InspectionDevice {
                        bus: format!("0x{:04X}", modalias.bus),
                        group: format!("0x{:04X}", modalias.group),
                        vid: format!("0x{:04X}", modalias.vid),
                        pid: format!("0x{:04X}", modalias.pid),
                    })
                    .collect::<Vec<InspectionDevice>>(),
            )
        })
        .or(Some(Vec::new()))
        .unwrap();

    let mut obj_builder = libbpf_rs::ObjectBuilder::default();
    let object = obj_builder.open_file(path.clone()).unwrap();

    let programs: Vec<InspectionProgram> = object
        .progs()
        .map(|prog| InspectionProgram {
            name: prog.name().to_str().unwrap().to_string(),
            section: prog.section().to_str().unwrap().to_string(),
        })
        .collect();

    let maps: Vec<InspectionMap> = object
        .maps()
        .map(|map| InspectionMap {
            name: map.name().to_str().unwrap().to_string(),
        })
        .collect();

    let udev_properties: Vec<InspectionUdevProp> = bpf_metadata
        .udev_properties_bss
        .iter()
        .chain(bpf_metadata.udev_properties_data.iter())
        .map(|var| InspectionUdevProp {
            name: var.name.clone(),
            size: var.size,
            readonly: true,
        })
        .chain(
            bpf_metadata
                .udev_property_maps
                .iter()
                .map(|map| InspectionUdevProp {
                    name: map.name.clone(),
                    size: map.size,
                    readonly: false,
                }),
        )
        .collect();

    // Check for HID_REPORT_DESCRIPTOR presence and size
    let report_descriptor_size = bpf_metadata
        .report_descriptor_bss
        .as_ref()
        .or(bpf_metadata.report_descriptor_data.as_ref())
        .map(|var| var.size);

    let data = InspectionData {
        filename: String::from(path.file_name().unwrap().to_string_lossy()),
        devices,
        programs,
        maps,
        udev_properties,
        report_descriptor_size,
    };

    Ok(data)
}

fn cmd_inspect(paths: &[PathBuf]) -> Result<()> {
    let objects = paths
        .iter()
        .map(|path| inspect(path))
        .collect::<Result<Vec<InspectionData>>>()?;
    let json = serde_json::to_string_pretty(&objects).context("Failed to parse json")?;
    println!("{}", json);
    Ok(())
}

fn cmd_list_loaded(filter_syspath: Option<String>, format: &str) -> Result<()> {
    use std::fs;
    use std::path::Path;

    if format != "json" && format != "udev" {
        bail!("Unknown format '{}', expected 'json' or 'udev'", format);
    }

    let bpffs_root = Path::new(bpf::BPFFS_ROOT);

    if !bpffs_root.exists() {
        // No BPF programs loaded
        if format == "json" {
            let data = LoadedBpfData {
                devices: Vec::new(),
            };
            let json = serde_json::to_string_pretty(&data)?;
            println!("{}", json);
        }
        return Ok(());
    }

    // Extract sysname from syspath and convert to bpffs format if filter provided
    // Syspath can be either "/sys/bus/hid/devices/0003:056A:0374.0008" or just "0003:056A:0374.0008"
    let filter_bpffs_name = filter_syspath.as_ref().map(|syspath| {
        let path = std::path::Path::new(syspath);

        // Try to use HidUdev::from_syspath which handles parent device lookup
        match hidudev::HidUdev::from_syspath(path) {
            Ok(dev) => {
                let sysname = dev.sysname();
                bpf::sysname_to_bpffs(&sysname)
            }
            Err(_) => {
                // If path doesn't exist in sysfs, assume it's just a sysname
                let sysname = path
                    .file_name()
                    .unwrap_or_else(|| std::ffi::OsStr::new(syspath))
                    .to_string_lossy();
                bpf::sysname_to_bpffs(&sysname)
            }
        }
    });

    // Fast path for udev format - only read UDEV_PROP_* maps
    if format == "udev" {
        let properties = bpf::collect_udev_properties(bpffs_root, filter_bpffs_name.as_ref())?;
        for (key, value) in &properties {
            println!("{}={}", key, value);
        }
        return Ok(());
    }

    // Build a map of prog_id -> prog_name for efficient lookup (only needed for JSON)
    let prog_names = bpf::build_prog_name_map();

    let mut devices = Vec::new();

    // Iterate over device directories
    for device_entry in fs::read_dir(bpffs_root)? {
        let device_entry = device_entry?;
        let device_path = device_entry.path();

        if !device_path.is_dir() {
            continue;
        }

        let bpffs_name = device_entry.file_name().to_string_lossy().to_string();

        // Apply sysname filter if provided
        if let Some(ref filter) = filter_bpffs_name {
            if &bpffs_name != filter {
                continue;
            }
        }

        // Convert bpffs name to actual HID sysname
        let sysname = bpf::bpffs_to_sysname(&bpffs_name);

        // Check if device still exists and get its sysfs path
        let syspath = bpf::get_hid_sysfs_path(&sysname);
        let detached = syspath.is_none();

        let mut bpf_objects = Vec::new();

        // Iterate over BPF object directories within each device
        for object_entry in fs::read_dir(&device_path)? {
            let object_entry = object_entry?;
            let object_path = object_entry.path();

            if !object_path.is_dir() {
                continue;
            }

            let object_name = object_entry.file_name().to_string_lossy().to_string();
            let mut programs = Vec::new();
            let mut maps = Vec::new();

            // Iterate over entries within each BPF object
            // These can be either struct_ops (programs) or regular maps
            for entry in fs::read_dir(&object_path)? {
                let entry = entry?;
                let entry_path = entry.path();

                if entry_path.is_dir() {
                    continue;
                }

                let entry_name = entry.file_name().to_string_lossy().to_string();

                // Check if this is a struct_ops link
                if let Some(map_id) = bpf::get_struct_ops_map_id(&entry_path) {
                    // This is a struct_ops link (program)
                    let callbacks = bpf::get_struct_ops_callbacks(map_id, &prog_names)
                        .into_iter()
                        .map(|(prog_name, _)| ProgramCallback { prog_name })
                        .collect();
                    programs.push(LoadedProgram {
                        name: entry_name,
                        callbacks,
                    });
                } else if let Ok(map_handle) = libbpf_rs::MapHandle::from_pinned_path(&entry_path) {
                    // This is a map
                    let value = if entry_name.starts_with("UDEV_PROP_") {
                        bpf::read_udev_property_map(&map_handle).ok().flatten()
                    } else {
                        None
                    };

                    maps.push(LoadedMap {
                        name: entry_name,
                        value,
                    });
                }
            }

            bpf_objects.push(LoadedBpfObject {
                name: object_name,
                programs,
                maps,
            });
        }

        devices.push(LoadedDevice {
            sysname,
            syspath,
            detached,
            bpf_objects,
        });
    }

    // Output in JSON format
    let data = LoadedBpfData { devices };
    let json = serde_json::to_string_pretty(&data)?;
    println!("{}", json);

    Ok(())
}

fn write_udev_rule(
    rulefile: &mut dyn Write,
    bindir: &std::path::Path,
    target: &std::path::Path,
    devices: &[InspectionDevice],
) -> Result<()> {
    let header = r#"# This udev rule was generated by udev-hid-bpf install
ACTION!="add|remove|bind|unbind", GOTO="hid_bpf_end"
SUBSYSTEM!="hid", GOTO="hid_bpf_end"
"#;
    let footer = r#"LABEL="hid_bpf_end""#;
    let bindir = bindir.to_string_lossy();

    writeln!(rulefile, "{}", header)?;
    devices.iter().for_each(|dev| {
        let bus = u32::from_str_radix(&dev.bus[2..], 16).unwrap();
        let vid = u32::from_str_radix(&dev.vid[2..], 16).unwrap();
        let pid = u32::from_str_radix(&dev.pid[2..], 16).unwrap();
        let grp = u32::from_str_radix(&dev.group[2..], 16).unwrap();
        let vid = if vid == 0 { String::from("*") } else { format!("{vid:08X}") };
        let pid = if pid == 0 { String::from("*") } else { format!("{pid:08X}") };
        let bus = if bus == 0 { String::from("*") } else { format!("{bus:04X}") };
        let grp = if grp == 0 { String::from("*") } else { format!("{grp:04X}") };
        let kernel_match = format!(r#"ENV{{MODALIAS}}=="hid:b{bus}g{grp}v{vid}p{pid}""#);
        writeln!(
            rulefile,
            r###"# {} "###,
            target.file_name().unwrap().to_string_lossy()
        ).unwrap();
        for action in ["add", "remove"] {
            let bpf_o = match action {
                "add" => target.to_string_lossy().into_owned(),
                "remove" => String::from(""),
                &_ => panic!("Unexpected action") // can't happen
            };
            let cmd = match action {
                "add" => String::from("IMPORT"),
                "remove" => String::from("RUN"),
                &_ => panic!("Unexpected action") // can't happen
            };
            writeln!(
                rulefile,
                r#"ACTION=="{action}",{kernel_match}, {cmd}{{program}}+="{bindir}/udev-hid-bpf {action} $sys$devpath {bpf_o}""#
            )
            .unwrap();
        }
        writeln!(
            rulefile,
            r#"
# bind/unbind clears the properties set during the previous add/bind stage, so
# let's import them to keep them alive

ACTION=="bind|unbind",{kernel_match}, IMPORT{{program}}+="{bindir}/udev-hid-bpf list-loaded --format udev --syspath $sys$devpath""#
        )
        .unwrap();
    });
    writeln!(rulefile).unwrap();
    writeln!(rulefile, "{}", footer).unwrap();

    Ok(())
}

fn cmd_install(
    path: &PathBuf,
    prefix: Option<PathBuf>,
    force: bool,
    install_exe: bool,
    dry_run: bool,
) -> Result<()> {
    if dry_run {
        println!("This is a dry run, nothing will be created or installed");
    }

    if !path.to_str().unwrap().ends_with(".bpf.o") {
        bail!("Expected a bpf.o file as argument, not {path:?}");
    }

    let idata = inspect(path)?;
    if idata.devices.is_empty() {
        bail!("{path:?} has no HID_DEVICE entries and must be manually attached");
    }

    // udevdir is hardcoded for now, very few use-cases for the rule to be elsewhere
    let udevdir = "/etc/udev/rules.d";
    // bindir is always $prefix/bin unless we use the fallback, then it's whatever meson said
    let bindir = prefix
        .as_ref()
        .map(|p| p.join("bin"))
        .unwrap_or(PathBuf::from(BINDIR));

    // We install ourselves if requested
    let exe = bindir.join("udev-hid-bpf");
    if !exe.exists() {
        if !install_exe {
            bail!("{exe:?} does not exist. Install this project first or use --install-exe");
        }

        println!("Installing myself as {exe:?}");
        if !dry_run {
            let myself = std::env::current_exe().unwrap();
            std::fs::create_dir_all(exe.parent().unwrap())
                .and_then(|_| std::fs::copy(myself, &exe))
                .context("Failed to install myself as {exe:?}: {e}")?;
        }
    }

    let fwdir = PathBuf::from("/etc/udev-hid-bpf/");

    // We know it's .bpf.o suffixed
    let filename: String = path.file_name().unwrap().to_string_lossy().to_string();
    let stem = &filename.strip_suffix(".bpf.o").unwrap();
    let target = fwdir.join(&filename);
    let udevtarget = PathBuf::from(format!("{udevdir}/99-hid-bpf-{stem}.rules"));

    if !force {
        for t in [&target, &udevtarget] {
            ensure!(
                !t.exists(),
                format!("File {t:?} exists, remove first or use --force to overwrite")
            );
        }
    }

    println!("Installing {filename} as {target:?}");
    if !dry_run {
        std::fs::create_dir_all(target.parent().unwrap())
            .and_then(|_| std::fs::copy(path, &target))
            .context(format!("Failed to copy to {:?}", target))?;
    }

    println!("Installing udev rule as {:?}", udevtarget);
    if !dry_run {
        std::fs::create_dir_all(udevdir)?;
        let mut rulefile = std::fs::File::create(&udevtarget)
            .context(format!("Failed to install udev rule {:?}", udevtarget))?;
        write_udev_rule(&mut rulefile, &bindir, &target, &idata.devices)?;
    } else {
        println!("Printing udev rule instead of installing it:");
        println!("---");
        write_udev_rule(&mut std::io::stdout(), &bindir, &target, &idata.devices)?;
        println!("--");
    }

    if !dry_run {
        if let Err(e) = std::process::Command::new("udevadm")
            .args(["control", "--reload"])
            .status()
        {
            eprintln!("WARNING: Failed to run `udevadm control --reload`: {e:#}");
        }
    }

    println!();
    println!("Installation successful. You can now plug in your device.");
    println!("To uninstall, run");
    println!(" $ rm {target:?}");
    println!(" $ rm {udevtarget:?}");
    println!(" $ sudo udevadm control --reload ");
    Ok(())
}

/// Split a list of paths at the occurance of the first '-'
/// element, i.e. [a, b, c, -, d, e] becomes [a, b, c] and [d, e].
fn split_paths(mut paths: Vec<String>) -> Result<(Vec<String>, Vec<String>)> {
    let divider = String::from("-");
    let (devices, objects) = match &mut paths[..] {
        [] => bail!("At least one device path is required"),
        [d] => (vec![d.clone()], vec![]),
        [d, o] if d != "-" => (vec![d.clone()], vec![o.clone()]),
        _ => {
            let split = paths.iter().position(|p| p == &divider);
            match split {
                // Special case of "-" as first entry
                Some(0) => {
                    paths.remove(0);
                    (Vec::new(), paths)
                }
                Some(idx) => {
                    let mut objfiles = paths.split_off(idx);
                    objfiles.remove(0);
                    (paths, objfiles)
                }
                None => (paths, vec![]),
            }
        }
    };

    if devices.iter().any(|d| d.is_empty() || d == &divider)
        || objects.iter().any(|o| o.is_empty() || o == &divider)
    {
        bail!("Invalid device or object path");
    }

    Ok((devices, objects))
}

// Remove the "0x" prefix from a string, if it exists
fn hex_without_prefix<'a>(s: &'a str) -> &'a str {
    s.strip_prefix("0x").or(Some(&s)).unwrap()
}

fn device_vid_pid_name(device: &InspectionDevice) -> String {
    let bus = hex_without_prefix(&device.bus.as_str());
    let vid = hex_without_prefix(&device.vid.as_str());
    let pid = hex_without_prefix(&device.pid.as_str());
    format!("{bus}:{vid}:{pid}.")
}

/// Find sysfs devices that match the various HID_DEVICE
/// entries the given BPF object files register.
///
/// The returned map is { objfile: [device, device, device ...] }
fn find_sysfs_devices(objfiles: &Vec<String>) -> Result<HashMap<String, Vec<PathBuf>>> {
    let devices = std::fs::read_dir(PathBuf::from("/sys/bus/hid/devices/"))?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .collect::<Vec<PathBuf>>();

    let inspection_data = objfiles
        .iter()
        .map(|objfile| inspect(&PathBuf::from(objfile)))
        .collect::<Result<Vec<InspectionData>>>()?;

    let mut map: HashMap<String, Vec<PathBuf>> = HashMap::new();
    for (objfile, idata) in std::iter::zip(objfiles, inspection_data) {
        // filename is something like 0003:045E:07A5.0002 but we only care
        // about the BUS:VID:PID part of that name
        let prefixes = idata
            .devices
            .iter()
            .map(device_vid_pid_name)
            .collect::<Vec<String>>();

        for d in &devices {
            for prefix in &prefixes {
                let fname = d.file_name().unwrap().to_string_lossy();
                if fname.starts_with(prefix) {
                    log::debug!("{}: found compatible device {d:?}", idata.filename);
                    map.entry(objfile.clone())
                        .or_insert(Vec::new())
                        .push(d.clone());
                }
            }
        }
    }

    Ok(map)
}

fn udev_hid_bpf() -> Result<()> {
    let cli = Cli::parse();

    libbpf_rs::set_print(Some((
        if cli.debug {
            libbpf_rs::PrintLevel::Debug
        } else {
            libbpf_rs::PrintLevel::Info
        },
        print_to_log,
    )));

    let mut modules = vec![module_path!(), "HID-BPF metadata"];
    if cli.verbose {
        modules.push("libbpf");
    }

    let cli_color = match std::env::var("CLICOLOR_FORCE") {
        Err(_) => stderrlog::ColorChoice::Auto,
        _ => stderrlog::ColorChoice::Always,
    };

    stderrlog::new()
        .modules(modules)
        .show_module_names(true)
        .verbosity(if cli.verbose {
            log::LevelFilter::Debug
        } else {
            log::LevelFilter::Warn
        })
        .color(cli_color)
        .init()
        .unwrap();

    match cli.command {
        Commands::Add {
            paths,
            bpfdir,
            replace,
            property,
        } => {
            let (devices, objfiles) = split_paths(paths)?;

            if devices.is_empty() {
                let object_device_map: HashMap<String, Vec<PathBuf>> =
                    find_sysfs_devices(&objfiles)?;

                if object_device_map.is_empty() {
                    bail!("Unable to find any devices that match the given BPF program(s)");
                }

                if replace {
                    let devices: Vec<PathBuf> = object_device_map
                        .iter()
                        .flat_map(|(_, devices)| devices)
                        .map(PathBuf::from)
                        .collect();
                    cmd_remove(&devices)?;
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }

                // HashMap doesn't have a defined order, for better UX
                // better UX we load objects in the order given on the cmdline.
                objfiles
                    .into_iter()
                    .filter(|objfile| object_device_map.contains_key(objfile))
                    .map(|objfile| object_device_map.get_key_value(&objfile).unwrap())
                    .map(|(objfile, devices)| {
                        let objfiles = vec![String::from(objfile)];
                        cmd_add(&devices, objfiles.as_slice(), bpfdir.clone(), &property)
                    })
                    .collect::<Result<(), anyhow::Error>>()
            } else {
                let devices = devices.iter().map(PathBuf::from).collect();
                if replace {
                    cmd_remove(&devices)?;
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
                cmd_add(&devices, &objfiles, bpfdir, &property)
            }
        }
        Commands::Remove { devpaths } => cmd_remove(&devpaths),
        Commands::ListBpfPrograms { bpfdir } => cmd_list_bpf_programs(bpfdir),
        Commands::ListDevices { with_bpfs } => cmd_list_devices(with_bpfs),
        Commands::Inspect { paths } => cmd_inspect(&paths),
        Commands::ListLoaded { syspath, format } => cmd_list_loaded(syspath, &format),
        Commands::Install {
            path,
            prefix,
            force,
            install_exe,
            dry_run,
        } => cmd_install(&path, prefix, force, install_exe, dry_run),
    }
}

fn main() -> ExitCode {
    let rc = udev_hid_bpf();
    match rc {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sysname_resolution() {
        let syspath = "/sys/blah/1234";
        let sysname = sysname_from_syspath(&PathBuf::from(syspath));
        assert!(sysname.is_err());

        let syspath = "/sys/blah/0003:04F3:2D4A.0001";
        let sysname = sysname_from_syspath(&PathBuf::from(syspath));
        assert!(sysname.unwrap() == "0003:04F3:2D4A.0001");

        let syspath = "/sys/blah/0003:04F3:2D4A-0001";
        let sysname = sysname_from_syspath(&PathBuf::from(syspath));
        assert!(sysname.is_err());

        // Only run this test if there's a local hidraw0 device
        let syspath = "/sys/class/hidraw/hidraw0/device";
        if std::path::Path::new(syspath).exists() {
            let sysname = sysname_from_syspath(&PathBuf::from(syspath));
            assert!(sysname.is_ok());
        }
    }

    macro_rules! vec_of_strings {
        ($($x:expr),*) => (vec![$($x.to_string()),*]);
    }

    #[test]
    fn test_split_paths() {
        let paths: Vec<String> = vec_of_strings!["a"];
        let (a, b) = split_paths(paths).unwrap();
        assert_eq!(a, vec!["a"]);
        assert_eq!(b, vec![] as Vec<&str>);

        let paths: Vec<String> = vec_of_strings!["a", "b"];
        let (a, b) = split_paths(paths).unwrap();
        assert_eq!(a, vec!["a"]);
        assert_eq!(b, vec!["b"]);

        let paths: Vec<String> = vec_of_strings!["a", "b", "c"];
        let (a, b) = split_paths(paths).unwrap();
        assert_eq!(a, vec!["a", "b", "c"]);
        assert_eq!(b, vec![] as Vec<&str>);

        let paths: Vec<String> = vec_of_strings!["a", "b", "-", "c"];
        let (a, b) = split_paths(paths).unwrap();
        assert_eq!(a, vec!["a", "b"]);
        assert_eq!(b, vec!["c"]);

        let paths: Vec<String> = vec_of_strings!["a", "-", "b", "c"];
        let (a, b) = split_paths(paths).unwrap();
        assert_eq!(a, vec!["a"]);
        assert_eq!(b, vec!["b", "c"] as Vec<&str>);

        let paths: Vec<String> = vec_of_strings!["a", "b", "c", "-"];
        let (a, b) = split_paths(paths).unwrap();
        assert_eq!(a, vec!["a", "b", "c"]);
        assert_eq!(b, vec![] as Vec<&str>);

        let paths: Vec<String> = vec_of_strings!["-", "b", "c", "d"];
        let (a, b) = split_paths(paths).unwrap();
        assert_eq!(a, vec![] as Vec<&str>);
        assert_eq!(b, vec!["b", "c", "d"]);

        let paths: Vec<String> = vec_of_strings!["-", "a"];
        let (a, b) = split_paths(paths).unwrap();
        assert_eq!(a, vec![] as Vec<&str>);
        assert_eq!(b, vec!["a"]);

        let paths: Vec<String> = vec_of_strings!["a", "-"];
        assert!(split_paths(paths).is_err());

        let paths: Vec<String> = vec_of_strings!["-"];
        assert!(split_paths(paths).is_err());
        let paths: Vec<String> = vec_of_strings![""];
        assert!(split_paths(paths).is_err());
        let paths: Vec<String> = vec_of_strings!["a", "-", ""];
        assert!(split_paths(paths).is_err());
    }

    #[test]
    fn test_tuple_parse() {
        let p = tuple_parse("foo=bar").unwrap();
        assert_eq!(p.name, "foo");
        assert_eq!(p.value, "bar");

        let p = tuple_parse("foo=bar=baz").unwrap();
        assert_eq!(p.name, "foo");
        assert_eq!(p.value, "bar=baz");

        let p = tuple_parse("foo=").unwrap();
        assert_eq!(p.name, "foo");
        assert_eq!(p.value, "");

        assert!(tuple_parse("foo bar=baz").is_err());
        assert!(tuple_parse("foo\tbar=baz").is_err());
        assert!(tuple_parse("foobar =baz").is_err());
        assert!(tuple_parse("foobar").is_err());
    }

    #[test]
    fn test_hex_without_prefix() {
        assert_eq!(hex_without_prefix("0x0"), "0");
        assert_eq!(hex_without_prefix("0"), "0");
        assert_eq!(hex_without_prefix("0x12"), "12");
        assert_eq!(hex_without_prefix("12"), "12");
    }
}
