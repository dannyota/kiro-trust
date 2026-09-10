//! Compiled catalog inspection and explicit bounded discovery (spec 3.7, 4.2).

use crate::config::{ModelsArgs, ModelsCommand, read_extra_ca, resolve_db_path};
use kiro_trust_auth::TokenSource;
use kiro_trust_kiro::{DiscoveryClient, DiscoveryReport};
use kiro_trust_net::{Client, Policy};
use kiro_trust_protocol::catalog::{self, ModelInfo};
use std::sync::Arc;

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
        ModelsCommand::Discover {
            json,
            kiro_db,
            extra_ca,
        } => discover(json, kiro_db, extra_ca),
    }
}

fn discover(
    json: bool,
    kiro_db: Option<std::path::PathBuf>,
    extra_ca: Option<std::path::PathBuf>,
) -> i32 {
    let db_path = match resolve_db_path(kiro_db) {
        Ok(path) => path,
        Err(_) => {
            discovery_config_error();
            return 2;
        }
    };
    let extra_ca = match read_extra_ca(extra_ca.as_ref()) {
        Ok(value) => value,
        Err(_) => {
            discovery_config_error();
            return 2;
        }
    };
    let policy = match extra_ca {
        Some(extra_ca) => Policy::production().with_extra_ca(extra_ca),
        None => Policy::production(),
    };
    let net = match Client::new(policy) {
        Ok(net) => Arc::new(net),
        Err(_) => {
            eprintln!("kiro-trust: discovery transport failed");
            return 1;
        }
    };
    let tokens = Arc::new(TokenSource::new(db_path, net.clone(), None));
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(_) => {
            eprintln!("kiro-trust: cannot start async runtime");
            return 1;
        }
    };
    match runtime.block_on(DiscoveryClient::new(net, tokens).discover()) {
        Ok(report) => {
            if json {
                print_json(&report);
            } else {
                print_discovery(&report);
            }
            0
        }
        Err(error) => {
            eprintln!("kiro-trust: {error}");
            1
        }
    }
}

fn discovery_config_error() {
    eprintln!("kiro-trust: discovery configuration invalid");
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

fn print_discovery(report: &DiscoveryReport) {
    print!("{}", render_discovery(report));
}

pub fn render_discovery(report: &DiscoveryReport) -> String {
    let mut out = String::from(
        "AVAILABLE ID\tCATALOG STATUS\tINPUTS\tINPUT LIMIT\tOUTPUT LIMIT\tPROMPT CACHE\n",
    );
    for model in &report.models {
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            model.id,
            serde_json::to_value(&model.catalog_status)
                .unwrap()
                .as_str()
                .unwrap(),
            model
                .input_types
                .iter()
                .map(|value| serde_json::to_value(value)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_string())
                .collect::<Vec<_>>()
                .join(","),
            model
                .max_input_tokens
                .map_or_else(|| "null".to_string(), |value| value.to_string()),
            model
                .max_output_tokens
                .map_or_else(|| "null".to_string(), |value| value.to_string()),
            model
                .supports_prompt_cache
                .map_or_else(|| "null".to_string(), |value| value.to_string()),
        ));
        out.push('\n');
    }
    out
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
