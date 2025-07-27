use std::net::Ipv4Addr;
use std::time::Duration;
use clap::{arg, crate_name, crate_version, Command};
use libp2p::{autonat, kad, Multiaddr, StreamProtocol};
use libp2p::futures::StreamExt;
use libp2p::kad::{BootstrapError, QueryId, Quorum, Record};
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use rust_ipns::Record as IPNSRecord;
use chrono::Duration as ChronoDuration;
use cid::Cid;
use cid::multibase::Base::Base36Lower;
use cid::multihash::Multihash;

const LIBP2P_PUBLIC_KEY_CODEC: u64 = 0x72;
// 5 minutes (the recommended default by the IPNS spec)
const TTL_NANOS: u64 = 300_000_000_000;
const BOOTNODES: [&str; 7] = [
    "/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
    "/ip4/104.131.131.82/udp/4001/quic-v1/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
    "/dnsaddr/va1.bootstrap.libp2p.io/p2p/12D3KooWKnDdG3iXw9eTFijk3EWSunZcFi54Zka4wmtqtt6rPxc8"
];

const IPFS_PROTO_NAME: StreamProtocol = StreamProtocol::new("/ipfs/kad/1.0.0");

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let cli_matches = cli().get_matches();
    let cid = cli_matches.get_one::<String>("CID").unwrap();

    let key = libp2p::identity::Keypair::generate_ed25519();

    let value = format!("/ipfs/{}", cid);
    let ipns_record = IPNSRecord::new(&key, value, ChronoDuration::hours(1), 0, TTL_NANOS)?;

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(key.clone())
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_dns()?
        .with_behaviour(|key| {
            // Create a Kademlia behaviour.
            let mut cfg = kad::Config::new(IPFS_PROTO_NAME);
            cfg.set_query_timeout(Duration::from_secs(5 * 60));
            let store = kad::store::MemoryStore::new(key.public().to_peer_id());

            Behaviour {
                kad: kad::Behaviour::with_config(key.public().to_peer_id(), store, cfg),
                autonat: autonat::Behaviour::new(key.public().to_peer_id(), autonat::Config::default())
            }

        })?
        .build();

    for node in BOOTNODES {
        let multiaddr: Multiaddr = node.parse()?;
        let p2p_section = multiaddr.iter()
            .find(|addr_item| matches!(addr_item, Protocol::P2p(_)));
        if let Some(Protocol::P2p(peer_id)) = p2p_section {
            swarm.behaviour_mut().kad.add_address(&peer_id, multiaddr);
        }
    }

    swarm.listen_on(
        Multiaddr::empty()
            .with(Protocol::Ip4(Ipv4Addr::UNSPECIFIED))
            .with(Protocol::Tcp(5500))
    )?;

    let mut one_bootstrap_ok = false;
    let mut bootstrap_finished = false;
    let mut external_address_confirmed = false;
    let mut putrecord_query_id: Option<QueryId> = None;

    loop {
        let event_opt = swarm.next().await;
        if event_opt.is_none() {
            break;
        }

        let event = event_opt.unwrap();
        match event {
            SwarmEvent::ExternalAddrConfirmed { address } => {
                println!("External address confirmed: {}", address);
                external_address_confirmed = true;
            }
            SwarmEvent::Behaviour(BehaviourEvent::Autonat(event)) => {
                println!("AutoNAT event: {:?}", event);
            }
            SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
                result: kad::QueryResult::Bootstrap(result), ..
            })) => {
                println!("Bootstrap event: {:?}", result);
                match result {
                    Ok(details) => {
                        one_bootstrap_ok = true;
                        if details.num_remaining == 0 {
                            bootstrap_finished = true;
                        }
                    },
                    Err(BootstrapError::Timeout { num_remaining, ..}) => {
                        if one_bootstrap_ok && num_remaining.is_some() && num_remaining.unwrap() == 0 {
                            bootstrap_finished = true;
                        }
                    }
                }
            }
            SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
                result: kad::QueryResult::PutRecord(result), id, ..
            })) => {
                if putrecord_query_id.as_ref().filter(|query_id| *query_id == &id).is_some() {
                    if result.is_ok() {
                        println!("IPNS record push succeeded!");
                    } else {
                        eprintln!("IPNS record push failed due to error: {:?}", result.unwrap_err());
                    }

                    break;
                }
            }
            _ => {}
        }

        if bootstrap_finished && external_address_confirmed && putrecord_query_id.is_none() {
            let cid = Cid::new_v1(LIBP2P_PUBLIC_KEY_CODEC, Multihash::from(key.public().to_peer_id()));
            let kad_key = format!("/ipns/{}", cid.to_string_of_base(Base36Lower)?);
            let kad_record = Record::new(kad_key.into_bytes(), ipns_record.encode()?);
            println!("Pushing IPNS record: {:?}", kad_record);

            putrecord_query_id = Some(swarm.behaviour_mut().kad.put_record(kad_record, Quorum::One)?);
        }
    }

    Ok(())
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    kad: kad::Behaviour<kad::store::MemoryStore>,
    autonat: autonat::Behaviour
}


fn cli() -> Command {
    Command::new(crate_name!())
        .version(crate_version!())
        .arg_required_else_help(true)
        .arg(arg!(<CID> "CID of file to push with an autogenerated key").required(true))
}
