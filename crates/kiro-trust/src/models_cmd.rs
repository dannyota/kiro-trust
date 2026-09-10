//! Offline inspection of the compiled model catalog (spec 4.2.1).

use crate::config::{ModelsArgs, ModelsCommand};
use kiro_trust_protocol::catalog::{self, ModelInfo};

pub fn run(args: ModelsArgs) -> i32 {
    match args.command {
        ModelsCommand::List { json } => {
            let models = catalog::models();
            if json {
                print_json(&serde_json::json!({"object": "model_catalog", "models": models}));
            } else {
                print_list(&models);
            }
            0
        }
        ModelsCommand::Show { model, json } => match catalog::model(&model) {
            Ok(info) => {
                if json {
                    print_json(&info);
                } else {
                    print_model(&info);
                }
                0
            }
            Err(_) => {
                eprintln!(
                    "kiro-trust: unknown model; run 'kiro-trust models list' for supported models"
                );
                1
            }
        },
    }
}

fn print_json<T: serde::Serialize>(value: &T) {
    println!(
        "{}",
        serde_json::to_string(value).expect("catalog metadata serializes")
    );
}

fn print_list(models: &[ModelInfo]) {
    println!("ID\tKIRO MODEL\tCONTEXT\tINPUTS\tEFFORT");
    for model in models {
        println!(
            "{}\t{}\t{}\t{}\t{}",
            model.id,
            model.kiro_model,
            format_context(model.context_window),
            model.proxy_input_types.join(","),
            format_effort(&model.effort_levels),
        );
    }
}

fn print_model(model: &ModelInfo) {
    println!("ID\t{}", model.id);
    println!("DISPLAY NAME\t{}", model.display_name);
    println!("KIRO MODEL\t{}", model.kiro_model);
    println!("ALIASES\t{}", model.aliases.join(","));
    println!("ACCEPTS DATE SUFFIX\t{}", model.accepts_date_suffix);
    println!("CONTEXT\t{}", format_context(model.context_window));
    println!("EFFORT\t{}", format_effort(&model.effort_levels));
    println!("INPUTS\t{}", model.proxy_input_types.join(","));
    println!(
        "HISTORY IMAGES FORWARDED\t{}",
        model.history_images_forwarded
    );
}

fn format_context(context_window: u32) -> String {
    if context_window.is_multiple_of(1_000_000) {
        format!("{}M", context_window / 1_000_000)
    } else {
        format!("{}K", context_window / 1_000)
    }
}

fn format_effort(levels: &[String]) -> String {
    if levels.is_empty() {
        "none".to_string()
    } else {
        levels.join(",")
    }
}
