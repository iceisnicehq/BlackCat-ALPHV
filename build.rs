use std::fs;
use std::path::Path;

fn main() {
    // Этот скрипт запускается при компиляции
    println!("cargo:rerun-if-changed=assets/psexec.exe");
    
    // В реальном коде PsExec был бы здесь встроен через include_bytes!
    // Для лабораторных целей это демонстрирует структуру
    
    // Пример сжатия:
    // let psexec_data = include_bytes!("assets/psexec.exe");
    // let compressed = compress(psexec_data);
    // Сохраняем в переменную окружения для использования в main.rs
    
    println!("cargo:rustc-env=PSEXEC_EMBEDDED=true");
}
