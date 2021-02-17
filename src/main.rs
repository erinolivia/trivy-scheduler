
use std::collections::{HashMap, HashSet};
use std::env;
use std::hash::{Hash, Hasher};
use std::process::Command;
use std::str::FromStr;
use std::time::Duration;

use async_trait::async_trait;
use clap::{Arg, App};
use chrono::Utc;
use job_scheduler::{JobScheduler, Job, Schedule};
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
            // Remove the "sha256:" from the front of the digest
            id: id.split(':').nth(1).unwrap().to_string(),
        }
    }
}

impl PartialEq for Image {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}
impl Eq for Image {}

impl Hash for Image {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

#[async_trait]
trait ImageProvider {
    async fn get_image_list(&self) -> Option<HashSet<Image>>;
}

#[async_trait]
impl ImageProvider for Docker {
    async fn get_image_list(&self) -> Option<HashSet<Image>> {
        let result = self.containers().list(&Default::default()).await;
        match result {
            Ok(container) => {
                let images = container.into_iter().map(|c| {
                        Image::new(&c.image, &c.image_id)
                    }).collect();

                Some(images)
            }

            Err(e) => {
                eprintln!("Error fetching images: {}", e);
                None
            }
        }
    }
}

#[async_trait]
impl ImageProvider for Vec<Docker> {

    async fn get_image_list(&self) -> Option<HashSet<Image>> {
        let mut images = HashSet::new();
        for server in self {
            let newones = server.get_image_list().await;
            if let Some(new_images) = newones {
                images.extend(new_images.into_iter());
            }
        }

        Some(images)
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


async fn check_images(image_provider : &impl ImageProvider) -> Vec<Image> {
    let mut vulnerable = Vec::new();

    let images = image_provider.get_image_list().await.unwrap();
    for image in images {
        println!("Checking {}\n", image.name);
        if !run_trivy(&image) {
            vulnerable.push(image);
        }
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


async fn run_checker(image_provider : &impl ImageProvider, notify_url : &str, notify_template : &str) {
    let vulnerable = check_images(image_provider).await;

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
            .max_values(1)
            .help("When to run trivy in cron format"))
        .arg(Arg::with_name("url")
            .required(true)
            .short("u")
            .long("notify-url")
            .takes_value(true)
            .max_values(1)
            .help("shoutrrr url to send messages to"))
        .arg(Arg::with_name("template")
            .short("t")
            .long("notify-template")
            .takes_value(true)
            .max_values(1)
            .help("Message to send when vulnerabilities are found. \
                  '{name}' and '{id}' are replaced with details of \
                  the vulnerable image")
            .default_value(DEFAULT_NOTIFY_TEMPLATE))
        .arg(Arg::with_name("hosts")
            .short("H")
            .long("hosts")
            .required(true)
            .takes_value(true)
            .min_values(1)
            .help("Docker hosts to connect to"))
        .get_matches();

    let schedule = matches.value_of("schedule").unwrap();
    let notify_url = matches.value_of("url").unwrap();
    let notify_template = matches.value_of("template").unwrap();
    let hosts = matches.values_of("hosts").unwrap();

    let mut servers = Vec::new();
    for host in hosts {
        if let Some(path) = host.strip_prefix("unix://") {
            servers.push(Docker::unix(path));
        } else {
            servers.push(Docker::host(host.parse().expect("Invalid host URL")));
        }
    }

    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut scheduler = JobScheduler::new();

    let schedule = Schedule::from_str(schedule).unwrap();
    println!("Next run scheduled for {}", schedule.upcoming(Utc).next().unwrap());

    scheduler.add(Job::new(schedule.clone(), move || {
        rt.block_on(async {
            println!("Running trivy\n");
            run_checker(&servers, notify_url, notify_template).await;
            println!("Next run scheduled for {}", schedule.upcoming(Utc).next().unwrap());
        });
    }));

    loop {
        scheduler.tick();
        std::thread::sleep(Duration::from_secs(1));
    }
}
