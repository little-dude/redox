use std::collections::{BTreeMap, VecDeque};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::io::AsRawFd;
use std::{cmp, str, u16};
use std;

use netutils::{getcfg, EthernetII};
use syscall;
use syscall::data::{Packet, SocketEndpoint};
use syscall::error::{EACCES, EBADF, EINVAL, EIO, EWOULDBLOCK, Result, Error};
use syscall::flag::O_NONBLOCK;
use syscall::scheme::SchemeMut;

use smoltcp::socket::{SocketSet, Socket, SocketHandle, UdpSocket, UdpPacketBuffer};
use smoltcp::wire::{Ipv4Address, IpEndpoint, IpAddress};
use device::EthernetDevice;
use rand;

pub struct EthernetScheme {
    pub flags: usize,
    pub device: EthernetDevice,
    pub sockets: SocketSet<'static, 'static, 'static>,
    pub udp_ports: BTreeMap<usize, usize>,
    pub tcp_ports: BTreeMap<usize, usize>,
    rng: rand::OsRng,
}

impl EthernetScheme {
    pub fn new(network: File) -> Self {
        EthernetScheme {
            flags: 0,
            device: EthernetDevice::new(network),
            sockets: SocketSet::new(Vec::new()),
            tcp_ports: BTreeMap::new(),
            udp_ports: BTreeMap::new(),
            rng: rand::OsRng::new().expect("Failed to open RNG"),
        }
    }
}

/// Parse a string representing a socket endpoint, e.g. `127.0.0.1:8080`
/// For the moment, it supports only IPv4 endpoints.
fn parse_endpoint(endpoint: String) -> Result<IpEndpoint> {
    let parts = endpoint.split('/');
    let ip = parts.next().ok_or(Err(Error::new(EINVAL)))?;
    let port = parts.next().ok_or(Err(Error::new(EINVAL)))?;
    Ok(
        IpEndpoint::new(
            Ipv4Address::parse(&ip).or(Err(Error::new(EINVAL)))?,
            u16::from_str_radix(port, 16).or(Err(Error::new(EINVAL)))?))
}

impl SchemeMut for EthernetScheme {
    /// Open a new socket. For now, only TCP and UDP sockets are supported, but later, L2 and L3
    /// sockets will be supported.
    ///
    /// Examples of valid urls:
    ///
    ///     - `udp/10.0.0.1:9000`: bind a UDP socket to a local IPv4 endpoint.
    ///     - `udp/[2001:0db8:85a3::8a2e:0370:7334]:1234`: bind a UDP socket to a local IPv6 endpoint.
    ///     - `tcp/10.0.0.1:9000`: open a TCP socket that listens on a local IPv4 endpoint.
    ///     - `tcp/[2001:0db8:85a3::8a2e:0370:7334]:1234`: open a TCP socket that listens on a local IPv6 endpoint.
    fn open(&mut self, url: &[u8], _flags: usize, uid: u32, _gid: u32) -> Result<usize> {
        if uid == 0 {
            let parts = str::from_utf8(url).or(Err(Error::new(EINVAL)))?.split('/');
            let protocol = parts.next().ok_or(Err(Error::new(EINVAL)))?;
            let locality = parts.next().ok_or(Err(Error::new(EINVAL)))?;
            let mut endpoint = parts.next().ok_or(Err(Error::new(EINVAL)))?.parse_endpoint(endpoint)?;
            if endpoint.port == 0 {
                endpoint.port = self.rng.gen_range(32768, 65535);
            }
            match &protocol {
                "tcp" => {
                    unimplemented!()
                },
                "udp" => {
                    let udp_rx_buffer = UdpSocketBuffer::new(vec![UdpPacketBuffer::new(vec![0; 64])]);
                    let udp_tx_buffer = UdpSocketBuffer::new(vec![UdpPacketBuffer::new(vec![0; 64])]);
                    let mut udp_socket = UdpSocket::new(udp_rx_buffer, udp_tx_buffer);
                    udp_socket.bind(endpoint);
                    self.udp_ports.insert(endpoint.port);
                    let socket_handle = self.sockets.add(udp_socket);
                    // FIXME: `index` is actually private in smoltcp.
                    return socket_handle.index
                },
                _ => {
                    return Err(Error::new(EINVAL));
                },
            }
        } else {
            Err(Error::new(EACCES))
        }
    }

    /// `dup` can be called to bind a socket to a different local enpoint.
    ///
    /// The argument must be a valid endpoint, e.g.:
    ///     - `10.0.0.1:9000`: binds the socket to a local IPv4 endpoint.
    ///     - `[2001:0db8:85a3::8a2e:0370:7334]:1234`: binds the socket to a local IPv6 endpoint.
    fn dup(&mut self, id: usize, buf: &[u8]) -> Result<usize> {
        let mut endpoint = str::from_utf8(url).or(Err(Error::new(EINVAL)))?.parse_endpoint(endpoint)?;
        if endpoint.port == 0 {
            endpoint.port = self.rng.gen_range(32768, 65535);
        }

        let socket_handle = SocketHandle { index: id };
        let socket = self.device.sockets.get_mut(&socket_handle).ok_or(Error::new(EBADF))?;
        match socket {
            Socket::Udp(sock) => {
                self.udp_ports.remove(sock.endpoint.port);
                socket.endpoint.port = endpoint.port;
                self.udp_ports.insert(sock.endpoint.port);

            },
            Socket::Tcp(socket) => {
                self.tcp_ports.remove(sock.endpoint.port);
                socket.endpoint.port = endpoint.port;
                self.tcp_ports.insert(sock.endpoint.port);
            },
        }
        Ok(id);
    }

    /// Close a socket.
    fn close(&mut self, id: usize) -> Result<usize> {
        let socket_handle = SocketHandle { index: id };
        let socket = self.device.sockets.remove(socket_handle);
        match socket {
            Socket::Udp(sock) => {
                self.udp_ports.remove(sock.endpoint.port);
            },
            Socket::Tdp(sock) => {
                self.tcp_ports.remove(sock.endpoint.port);
            },
        }
        Ok(id)
    }

    fn sockrecv(&mut self, id: usize, buf: &mut [u8], endpoint: &mut Endpoint) -> Result<usize> {
        let socket_handle = SocketHandle { index: id };
        let socket = self.device.sockets.get_mut(&socket_handle).ok_or(Error::new(EBADF))?;
        match socket {
            Socket::Udp(sock) | Socket::Tcp(sock) => {
                // Copy a datagram into the receive buffer.
                match sock.recv_slice(buf) {
                    Ok(count, from) => {
                        endpoint.port = from.port;
                        match from.address {
                            IpAddress::Ipv4(ipv4) => {
                                endpoint.address_len = 4;
                                for (idx, byte) in ipv4.as_bytes().enumerate() {
                                    endpoint.address[idx] = byte;
                                }
                                return Ok(count);
                            },
                            IpAddress::Unspecified => {
                                // FIXME: find our which error should be returned. It's not really
                                // an IO error.
                                return Err(Error::new(EIO));
                            },
                        }
                    },
                    // FIXME: we assume it's non blocking right now. smoltcp sockets don't store the flags,
                    // so we need to do that ourself.
                    Err(()) => {
                        return Ok(0),
                    },
                }
            }
        }
    }

    fn socksend(&mut self, id: usize, buf: &[u8], endpoint: &Endpoint) -> Result<usize> {
        let socket_handle = SocketHandle { index: id };
        let socket = self.device.sockets.get_mut(&socket_handle).ok_or(Error::new(EBADF))?;
        let endpoint = IpEndpoint::new(
            Ipv4Address::from_bytes(endpoint.address[0..endpoint.address_len]).or(Err(Error::new(EINVAL)))?,
            endpoint.port);

        match socket {
            Socket::Udp(sock) | Socket::Tcp(sock) => {
                Ok(sock.send_slice(buf, endpoint).or(Err(Error::new(EIO)))?)
            },
        }
    }

    /// Read the socket parameters and return them as a string with `/` as separator.
    ///
    /// For instance, for a UDP socket "10/20/1" reads as:
    ///     - the socket read timeout is 10 milliseconds
    ///     - the socket write timeout is 20 milliseconds
    ///     - the socket multicast TTL for IPv4 is 1
    /// 
    /// FIXME: document the output for TCP sockets
    fn read(&mut self, file: usize, buf: &mut [u8]) -> Result<usize> {
        unimplemented!()
    }

    /// Write the socket parameters. The parameters must be provided as a string with `/` as
    /// separator.
    /// 
    /// For instance, for a UDP socket "10/20/1" will:
    ///     - set the socket read timeout is 10 milliseconds
    ///     - set the socket write timeout is 20 milliseconds
    ///     - set the socket multicast TTL for IPv4 is 1
    ///
    /// FIXME: TCP sockets
    fn write(&mut self, file: usize, buf: &[u8]) -> Result<usize> {
        unimplemented!()
    }

    fn fevent(&mut self, id: usize, _flags: usize) -> Result<usize> {
        Ok(id)
    }

    fn fpath(&mut self, id: usize, buf: &mut [u8]) -> Result<usize> {
        let path_string: String;
        match self.socket.get(SocketHandle { index: id }).ok_or(Error::new(EBADF))? {
            Socket::Udp(socket) => {
                path_string = format!("ethernet:udp/{}", socket.endpoint);
            },
            Socket::Tcp(socket) => {
                path_string = format!("ethernet:tcp/{}", socket.endpoint);
            },
        }
        let path = path_string.as_bytes();
        let mut i = 0;
        while i < buf.len() && i < path.len() {
            buf[i] = path[i];
            i += 1;
        }
        Ok(i)
    }

    fn fsync(&mut self, id: usize) -> Result<usize> {
        let _ = self.socket.get(SocketHandle { index: id }).ok_or(Error::new(EBADF))?;
        syscall::fsync(self.network.as_raw_fd())
    }
}
