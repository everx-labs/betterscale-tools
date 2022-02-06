use std::net::{Ipv4Addr, SocketAddrV4};

use tl_proto::*;

use crate::ed25519::*;

pub fn generate_dht_config(address: SocketAddrV4, secret: &SecretKey) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .expect("Shouldn't fail")
        .as_secs() as i32;

    let key_pair = KeyPair::from(secret);
    let signature = sign_dht_node(address, &key_pair, now);

    let json = serde_json::json!({
        "@type": "dht.node",
        "id": {
            "@type": "pub.ed25519",
            "key": base64::encode(key_pair.public_key.as_bytes())
        },
        "addr_list": {
            "@type": "adnl.addressList",
            "addrs": [
                {
                    "@type": "adnl.address.udp",
                    "ip": convert_ip(address.ip()),
                    "port": address.port()
                }
            ],
            "version": now,
            "reinit_date": now,
            "priority": 0i32,
            "expire_at": 0i32
        },
        "version": now,
        "signature": base64::encode(signature)
    });

    serde_json::to_string_pretty(&json).expect("Shouldn't fail")
}

fn sign_dht_node(address: SocketAddrV4, key_pair: &'_ KeyPair, now: i32) -> [u8; 64] {
    key_pair.sign(DhtNode {
        id: TlPublicKey(key_pair.public_key.as_bytes()),
        addr_list: AddressList {
            address_len: 1,
            address: TlAddress {
                ip: convert_ip(address.ip()),
                port: address.port() as i32,
            },
            version: now,
            reinit_date: now,
            priority: 0,
            expire_at: 0,
        },
        version: now,
        signature: Vec::new(),
    })
}

#[derive(TlWrite)]
#[tl(boxed, id = 0x84533248)]
struct DhtNode<'a> {
    id: TlPublicKey<'a>,
    addr_list: AddressList,
    version: i32,
    #[tl(signature)]
    signature: Vec<u8>,
}

#[derive(TlWrite)]
#[tl(boxed, id = 0x4813b4c6)]
struct TlPublicKey<'a>(&'a [u8; 32]);

#[derive(TlWrite)]
struct AddressList {
    address_len: u32,
    address: TlAddress,
    version: i32,
    reinit_date: i32,
    priority: i32,
    expire_at: i32,
}

#[derive(TlWrite)]
#[tl(boxed, id = 0x670da6e7)]
struct TlAddress {
    ip: i32,
    port: i32,
}

fn convert_ip(address: &Ipv4Addr) -> i32 {
    let [a, b, c, d] = address.octets();
    ((a as u32) << 24 | (b as u32) << 16 | (c as u32) << 8 | (d as u32)) as i32
}
