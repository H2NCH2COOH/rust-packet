//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//                    Version 2, December 2004
//
// Copyleft (ↄ) meh. <meh@schizofreni.co> | http://meh.schizofreni.co
//
// Everyone is permitted to copy and distribute verbatim or modified
// copies of this license document, and changing it is allowed as long
// as the name is changed.
//
//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
//
//  0. You just DO WHAT THE FUCK YOU WANT TO.

use std::io::Cursor;
use byteorder::{WriteBytesExt, BigEndian};

use crate::error::*;
use crate::buffer::{self, Buffer};
use crate::builder::{Builder as Build, Finalization};
use crate::packet::{AsPacket, AsPacketMut};
use crate::icmp::builder;
use crate::icmp::Kind;
use crate::icmp::code::{DestinationUnreachable, TimeExceeded};
use crate::icmp::previous::Packet;
use crate::ip::v4::Packet as IpV4Packet;

/// Echo Request/Reply packet builder.
#[derive(Debug)]
pub struct Builder<B: Buffer = buffer::Dynamic> {
	buffer:    B,
	finalizer: Finalization,

	kind:    bool,
	prev:    bool,
}

impl<B: Buffer> Build<B> for Builder<B> {
	fn with(mut buffer: B) -> Result<Self> {
		buffer.next(8)?;

		Ok(Builder {
			buffer:    buffer,
			finalizer: Default::default(),

			kind:    false,
			prev:    false,
		})
	}

	fn finalizer(&mut self) -> &mut Finalization {
		&mut self.finalizer
	}

	fn build(mut self) -> Result<B::Inner> {
		if !self.kind || !self.prev {
			Err(Error::InvalidPacket)?
		}

		builder::prepare(&mut self.finalizer, &self.buffer);

		let mut buffer = self.buffer.into_inner();
		self.finalizer.finalize(buffer.as_mut())?;
		Ok(buffer)
	}
}

impl Default for Builder<buffer::Dynamic> {
	fn default() -> Self {
		Builder::with(buffer::Dynamic::default()).unwrap()
	}
}

impl<'a, B: Buffer> AsPacket<'a, Packet<&'a [u8]>> for Builder<B> {
	fn as_packet(&self) -> Result<Packet<&[u8]>> {
		Packet::new(self.buffer.data())
	}
}

impl<'a, B: Buffer> AsPacketMut<'a, Packet<&'a mut [u8]>> for Builder<B> {
	fn as_packet_mut(&mut self) -> Result<Packet<&mut [u8]>> {
		Packet::new(self.buffer.data_mut())
	}
}

impl<B: Buffer> Builder<B> {
	/// Make it a source quench.
	pub fn source_quench(mut self) -> Result<Self> {
		self.kind = true;
		self.buffer.data_mut()[0] = Kind::SourceQuench.into();
		self.buffer.data_mut()[1] = 0;

		Ok(self)
	}

	/// Make it a destination unreachable.
	pub fn destination_unreachable(mut self, code: DestinationUnreachable) -> Result<Self> {
		self.kind = true;
		self.buffer.data_mut()[0] = Kind::DestinationUnreachable.into();
		self.buffer.data_mut()[1] = code.into();

		Ok(self)
	}

	/// Add optional net-hop-mtu.
	pub fn next_hop_mtu(mut self, mtu: u16) -> Result<Self> {
		Cursor::new(&mut self.buffer.data_mut()[6 ..])
			.write_u16::<BigEndian>(mtu)?;

		Ok(self)
	}

	/// Make it a time exceeded
	pub fn time_exceeded(mut self, code: TimeExceeded) -> Result<Self> {
		self.kind = true;
		self.buffer.data_mut()[0] = Kind::TimeExceeded.into();
		self.buffer.data_mut()[1] = code.into();

		Ok(self)
	}

	/// The previous packet that caused this.
	pub fn previous<T: AsRef<[u8]>>(mut self, prev: IpV4Packet<T>) -> Result<Self> {
		if self.prev {
			Err(Error::InvalidPacket)?
		}

		self.prev = true;

		let mut len = (prev.header() as usize) * 4 + 8;
		if len > prev.length() as usize {
			len = prev.length() as usize;
		}
		for byte in &(prev.as_ref())[0 .. len] {
			self.buffer.more(1)?;
			*self.buffer.data_mut().last_mut().unwrap() = *byte;
		}

		Ok(self)
	}
}
