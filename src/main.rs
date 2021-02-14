
use std::collections::HashMap;
use std::env;
use std::process::Command;
use std::time::Duration;

use clap::{Arg, App};
use job_scheduler::{JobScheduler, Job};
use shiplift::Docker;


static DEFAULT_NOTIFY_TEMPLATE : &str = "Vulnerabilities found in image '{name}'";


struct Image {
    name : String,
    id : String,
}

impl Image {
    fn new(name : &str, id : &str) -> Image {
        Image {
            name: name.to_string(),
            // Remove the "sha256:" from the front of the id
            id: id.split(':').nth(1).unwrap().to_string(),
        }
    }
}


fn run_trivy(image : &Image) -> bool {
    let mut trivy = Command::new("trivy");

    let trivy_env : HashMap<String, String> =
        env::vars().filter(|&(ref key, _)|
            key.starts_with("TRIVY")
        ).collect();

    trivy.env_clear();
    trivy.env("TRIVY_TEMPLATE", "@templates/html.tpl");
    trivy.envs(&trivy_env);

    trivy.arg("image");
    trivy.arg("--format").arg("template");
    trivy.arg("--exit-code").arg("1");
    trivy.arg("--output").arg(format!("/output/{}.html", image.id));
    trivy.arg(&image.name);

    let output = trivy.output().expect("failed to run trivy");
    println!("{}", String::from_utf8_lossy(&output.stdout));

    return output.status.success();
}


async fn check_images(docker : &Docker) -> Vec<Image> {
    let mut vulnerable = Vec::new();

    let result = docker.containers().list(&Default::default()).await;
    match result {
        Ok(container) => {
            for c in container {
                let image = Image::new(&c.image, &c.image_id);

                println!("Checking {}\n", image.name);
                if !run_trivy(&image) {
                    vulnerable.push(image);
                }
            }
        }
        Err(e) => eprintln!("Error: {}", e),
    }

    return vulnerable;
}


fn send_notification(image : &Image, notify_url : &str, notify_template : &str) {
    let message = notify_template.clone()
        .replace("{name}", &image.name)
        .replace("{id}", &image.id);

    let status = Command::new("shoutrrr")
        .arg("send")
        .arg("--url")
        .arg(notify_url)
        .arg("--message")
        .arg(message)
        .status();
        
    if status.is_err() || !status.unwrap().success() {
        eprintln!("Failed to send notification");
    }
}


async fn run_checker(docker : &Docker, notify_url : &str, notify_template : &str) {
    let vulnerable = check_images(&docker).await;

    if vulnerable.len() == 0 {
        println!("No vulnerabilities found");
    }

    for image in vulnerable {
        println!("Found vulnerabilities in {}", image.name);
        send_notification(&image, notify_url, notify_template);
    }
}


fn main() {
    let matches = App::new("trivy-scheduler")
        .version("0.1.0")
        .arg(Arg::with_name("schedule")
            .required(true)
            .short("s")
            .long("schedule")
            .takes_value(true)
            .help("When to run trivy in cron format"))
        .arg(Arg::with_name("url")
            .required(true)
            .short("u")
            .long("notify-url")
            .takes_value(true)
            .help("shoutrrr url to send messages to"))
        .arg(Arg::with_name("template")
            .short("t")
            .long("notify-template")
            .takes_value(true)
            .help("Message to send when vulnerabilities are found. \
                  '{name}' and '{id}' are replaced with details of \
                  the vulnerable image")
            .default_value(DEFAULT_NOTIFY_TEMPLATE))
        .get_matches();

    let schedule = matches.value_of("schedule").unwrap();
    let notify_url = matches.value_of("url").unwrap();
    let notify_template = matches.value_of("template").unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let docker = Docker::new();

    let mut sched = JobScheduler::new();
    sched.add(Job::new(schedule.parse().unwrap(), || {
        rt.block_on(async {
            println!("Running trivy\n");
            run_checker(&docker, notify_url, notify_template).await;
        });
    }));

    loop {
        sched.tick();
        std::thread::sleep(Duration::from_secs(1));
    }
}
