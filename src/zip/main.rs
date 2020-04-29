/*
 Simple zip compressor.
*/
extern crate zip;

use std::env;
use std::fs::File;
use std::path::Path;
use std::io::{self, BufReader, BufWriter, Write};
use zip::write::FileOptions;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("Usage: <source_file> <zip_file>");
        return;
    }

    let dst_file = File::create(args[2].clone()).expect(&format!("Unable create target zip file {}", args[0]));

    let source_filename = args[1].clone();


    let mut writer = {
        let zip = zip::ZipWriter::new(dst_file);
        BufWriter::new(zip)
    };

    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o600);

    let name= Path::new(&source_filename).file_name().expect("Wrong sources file path").to_os_string();
    let file = File::open(source_filename.clone()).expect("Unable to open source file");

    writer.get_mut().start_file( name.to_str().unwrap(),
                                 options).expect("Unable to start zip archive");
    io::copy(&mut BufReader::new(file), &mut writer).expect("Unable to zip the data");
    // Flush the BufWriter after each file so we start then next one correctly.
    writer.flush().expect("Failed flush zip writer");

    writer.get_mut().finish().expect("Unable to finalize zip archive");
    //dst_file.sync_all().expect("Unable to finalize zip archive");

    println!("DONE");
    process::exit(3);
}