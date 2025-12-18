// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2025 Red Hat

//! Tool to convert HID report descriptor bytes to C-struct representation
//!
//! This tool reads a HID report descriptor (raw bytes) and outputs the
//! C-struct representation (HidRdescDescriptor) that would be injected
//! into BPF programs. The output is base64-encoded for easy use in tests.
//!
//! Usage:
//!   hid-rdesc-to-c-struct <rdesc-file>
//!   hid-rdesc-to-c-struct
//!   cat rdesc.bin | hid-rdesc-to-c-struct
//!
//! Output formats:
//!   --format=base64  - Base64 encoded binary (default)
//!   --format=hex     - Hex string
//!   --format=python  - Python bytes literal

use base64::{engine::general_purpose::STANDARD as base64_engine, Engine as _};
use clap::Parser;
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "hid-rdesc-to-c-struct")]
#[command(about = "Convert HID report descriptor to C-struct representation")]
struct Args {
    /// Input file containing HID report descriptor bytes
    /// If ommitted, read from stdin
    #[arg(value_name = "FILE")]
    input: Option<PathBuf>,

    /// Output format
    #[arg(long, value_name = "FORMAT", default_value = "base64")]
    format: OutputFormat,

    /// Include size information in output
    #[arg(long)]
    show_size: bool,
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum OutputFormat {
    /// Base64 encoded (for easy copy-paste)
    Base64,
    /// Hex string (0x01020304...)
    Hex,
    /// Python bytes literal (b'\x01\x02\x03')
    Python,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Read input
    let rdesc_bytes = if let Some(path) = args.input {
        fs::read(&path)?
    } else {
        let mut buffer = Vec::new();
        io::stdin().read_to_end(&mut buffer)?;
        buffer
    };

    // Parse the report descriptor using hidreport
    let rdesc = match hidreport::ReportDescriptor::try_from(rdesc_bytes.as_slice()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error parsing HID report descriptor: {}", e);
            std::process::exit(1);
        }
    };

    // Convert to C struct using the From trait
    let c_rdesc = udev_hid_bpf::bpf::HidRdescDescriptor::from(&rdesc);

    // Convert struct to bytes
    let c_rdesc_bytes = unsafe {
        std::slice::from_raw_parts(
            &c_rdesc as *const _ as *const u8,
            std::mem::size_of_val(&c_rdesc),
        )
    };

    // Output in requested format
    match args.format {
        OutputFormat::Base64 => {
            let encoded = base64_engine.encode(c_rdesc_bytes);
            println!("{}", encoded);
        }
        OutputFormat::Hex => {
            let hex = c_rdesc_bytes
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>();
            println!("{}", hex);
        }
        OutputFormat::Python => {
            print!("b'");
            for byte in c_rdesc_bytes {
                print!("\\x{:02x}", byte);
            }
            println!("'");
        }
    }

    if args.show_size {
        eprintln!("Size: {} bytes", c_rdesc_bytes.len());
        eprintln!("Input reports: {}", rdesc.input_reports().len());
        eprintln!("Feature reports: {}", rdesc.feature_reports().len());
        eprintln!("Output reports: {}", rdesc.output_reports().len());
    }

    Ok(())
}
