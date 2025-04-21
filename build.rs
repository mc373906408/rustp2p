use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    // 配置输出路径
    let out_dir = PathBuf::from(&crate_dir);
    let out_file = out_dir.join("include").join("rustp2p.h");

    // 确保输出目录存在
    fs::create_dir_all(out_dir.join("include")).expect("无法创建输出目录");

    // 配置cbindgen
    let config =
        cbindgen::Config::from_file("cbindgen.toml").expect("无法加载cbindgen.toml配置文件");

    // 生成头文件
    println!("cargo:warning=正在生成C头文件...");
    cbindgen::Builder::new()
        .with_crate(crate_dir.clone())
        .with_config(config)
        .generate()
        .expect("无法生成头文件")
        .write_to_file(&out_file);

    println!("cargo:warning=头文件已生成至: {}", out_file.display());

    // 不再复制到C示例目录
    // 直接使用include目录中的头文件

    // 让Cargo在ffi.rs改变时重新运行
    println!("cargo:rerun-if-changed=src/ffi.rs");
    println!("cargo:rerun-if-changed=cbindgen.toml");
}
