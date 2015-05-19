extern crate stunnel;

use std::env;
use std::thread;
use std::io::Write;
use std::io::Error;
use std::vec::Vec;
use std::net::TcpListener;
use std::net::TcpStream;
use std::net::ToSocketAddrs;
use std::str::from_utf8;
use stunnel::tcp::Tcp;
use stunnel::cryptor::Cryptor;
use stunnel::client::{
    Tunnel, TunnelWritePort,
    TunnelReadPort, TunnelPortMsg
};
use stunnel::socks5::{
    ConnectDest, get_connect_dest,
    reply_connect_success, reply_failure
};

fn tunnel_port_write(s: TcpStream, mut write_port: TunnelWritePort,
                     read_port: TunnelReadPort) {
    let mut stream = Tcp::new(s.try_clone().unwrap());

    match get_connect_dest(&mut stream) {
        ConnectDest::Addr(addr) => {
            let mut buf = Vec::new();
            let _ = write!(&mut buf, "{}", addr);
            write_port.connect(buf);
        },

        ConnectDest::DomainName(domain_name, port) => {
            write_port.connect_domain_name(domain_name, port);
        },

        _ => {
            write_port.close();
            return
        }
    }

    thread::spawn(move || {
        let _ = tunnel_port_read(s, read_port);
    });

    loop {
        match stream.read_at_most(10240) {
            Ok(buf) => {
                write_port.write(buf);
            },
            Err(_) => {
                write_port.close();
                break
            }
        }
    }

    stream.shutdown();
}

fn tunnel_port_read(s: TcpStream,
                    read_port: TunnelReadPort) -> Result<(), Error> {
    let addr = match read_port.read() {
        TunnelPortMsg::ConnectOk(buf) => {
            from_utf8(&buf[..]).unwrap().to_socket_addrs().unwrap().nth(0)
        },

        _ => None
    };

    let mut stream = Tcp::new(s);
    match addr {
        Some(addr) => {
            try!(reply_connect_success(&mut stream, addr));
        },
        None => {
            try!(reply_failure(&mut stream));
        }
    }

    loop {
        let buf = match read_port.read() {
            TunnelPortMsg::Data(buf) => buf,
            _ => break
        };

        match stream.write(&buf[..]) {
            Ok(_) => {},
            Err(_) => break,
        }
    }

    stream.shutdown();
    Ok(())
}

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() != 3 {
        println!("usage: {} server-address key", args[0]);
        return
    }

    let server_addr = args[1].clone();
    let key = args[2].clone().into_bytes();
    let (min, max) = Cryptor::key_size_range();

    if key.len() < min || key.len() > max {
        println!("key length must in range [{}, {}]", min, max);
        return
    }

    let mut tunnel = Tunnel::new(server_addr, key);
    let listener = TcpListener::bind("127.0.0.1:1080").unwrap();

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let (write_port, read_port) = tunnel.open_port();
                thread::spawn(move || {
                    tunnel_port_write(stream, write_port, read_port);
                });
            },

            Err(_) => {}
        }
    }
}
