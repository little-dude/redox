use std::fs::File;
use smoltcp;
use std::io::{self, Read, Write};

// FIXME: we should have one network: resource per physical interface. Currently it's ok because we
// support only one physical interface. However, what happens when a broadcast frame arrived on the
// network scheme, and we have multiple interfaces? We have no way to tell for which interface it
// is.
struct Device {
    network: File,
}

struct TxBuffer {
    buffer: Vec<u8>,
    network: File,
}

impl AsRef<[u8]> for TxBuffer {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

impl AsMut<[u8]> for TxBuffer {
    fn as_mut(&mut self) -> &mut [u8] {
        self.buffer.as_mut()
    }
}

impl Drop for TxBuffer {
    fn drop(&mut self) {
        self.network.write(&mut self.buffer[..]).unwrap();
    }
}

// FIXME: with this implementation
//  - we allocate a new buffer every time we receive or send a frame. We should reuse buffers as
//    much a possible
//  - we perform a copy for each frame we send and receive. This can only be fixed if the driver
//    implemented the Device trait, afaict.
impl smoltcp::phy::Device for Device {
    type RxBuffer = Vec<u8>;
    type TxBuffer = TxBuffer;

    fn mtu(&self) -> usize {
        1536
    }

    fn receive(&mut self) -> Result<Self::RxBuffer, smoltcp::Error> {
        let mut buffer = vec![0; self.mtu()];
        let size = self.network.read(&mut buffer[..]).unwrap();
        buffer.resize(size, 0);
        Ok(buffer)
    }

    fn transmit(&mut self, length: usize) -> Result<Self::TxBuffer, smoltcp::Error> {
        Ok(TxBuffer {
            network:  self.network.try_clone().unwrap(),
            buffer: vec![0; length]
        })
    }
}

pub struct EthernetDevice(smoltcp::iface::EthernetInterface<'static, 'static, 'static, Device>);

impl EthernetDevice {
    pub fn new(network: File) -> Self {
        let device = Box::new(Device { network: network });
        let arp_cache = Box::new(smoltcp::iface::SliceArpCache::new(vec![Default::default(); 8])) as Box<smoltcp::iface::ArpCache>;
        let hardware_addr = smoltcp::wire::EthernetAddress([0x0, 0x0, 0x0, 0x0, 0x0, 0x0]);
        let ip_addresses = [smoltcp::wire::IpAddress::v4(192, 168, 0, 2)];
        EthernetDevice(smoltcp::iface::EthernetInterface::new(device, arp_cache, hardware_addr, ip_addresses))
    }

    pub fn set_mac_address(&mut self, mac_address: &str) -> Result<(), ()> {
        let addr = smoltcp::wire::EthernetAddress::parse(mac_address).or(Err(()))?;
        self.0.set_hardware_addr(addr);
        Ok(())
    }

    pub fn add_ipv4_address(&mut self, addr: [u8; 4]) {
        unimplemented!()
    }

    pub fn del_ipv4_address(&mut self, addr: [u8; 4]) {
        unimplemented!()
    }
}
