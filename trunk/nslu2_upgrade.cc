/*-
 * nslu2_upgrade.cc
 *  Classes to upgrade an NSLU2.
 */
#include <cstring>

#include "nslu2_protocol.h"
#include "nslu2_upgrade.h"

namespace NSLU2Upgrade {
	/* Hardware ID field, add others as required. */
	static const unsigned char NSLU2ID0[][32] = {
		{4, 112, 49, 149, 88, 16}, /* remainder 0 */
		{0x44, 0x47, 0x38, 0x33, 0x34, 0x56, 0x33},  /* remainder 0 */
		0
	};

	/* Real implementations. */
	class RealGetHardwareInfo : public GetHardwareInfo {
	public:
		RealGetHardwareInfo(Wire *w, int s) :
			wire(w), sequence(s & 0xffff) {
			NSLU2Protocol::HardwareInfoPacket packet(sequence);
			wire->Send(packet.PacketBuffer(), packet.PacketLength());
		}

		virtual ~RealGetHardwareInfo() {
		}

		virtual bool Next(unsigned short &product_id, unsigned short &protocol_id,
			unsigned short &firmware_version) {
			/* Return information from the next received packet,
			 * return false if there is no packet (empty packet
			 * returned or fatal error).  The information is the
			 * current flash product id, protocol id and firmware
			 * version from the hardware info packet - the rest of
			 * the packet has already been validated.
			 */
			do {
				NSLU2Protocol::ReceivePacket receive;
				size_t size = receive.PacketBufferSize();
				/* Wait up to 1/16s for a new packet (this is somewhat
				 * arbitrary).
				 */
				wire->Receive(receive.PacketWriteBuffer(), size, 1<<16);

				/* Non-fatal - no packet received. */
				if (size == 0)
					return false;

				/* NOTE: because we may receive from multiple NSLU2
				 * machines it is important not to change the sequence
				 * number - they will all be the same!
				 */
				if (receive.TypeOf() == NSLU2Protocol::HardwareInfo &&
					receive.Sequence() == sequence &&
					receive.DataLength() == NSLU2Protocol::HardwareInfoLength
					/* Validate the non-variable parts of the hardware
					 * info - this stuff is simply copied from the RedBoot
					 * part of the image, however the data in question is
					 * not actually from the RedBoot source/build - rather
					 * it is inserted when the flash image is built.  This
					 * code checks the 32 byte 'hardware id' for a match.
					 */) {
					/* try all IDs */
					int found = 0, i;
					const unsigned char *d = receive.Data()+4+32+2;
					for(i = 0; NSLU2ID0[i][0]; i++)
						if(memcmp(receive.Data()+4, NSLU2ID0[i], 32) == 0)
							found = 1;
					if(found == 0)
						continue;
						
					/* Copy out the ProductID, ProtocolID and
					 * FirmwareVersion fields.
					 */
					product_id       = (d[0]<<8) + d[1], d += 4;
					protocol_id      = (d[0]<<8) + d[1], d += 4;
					/* skip FunctionId */ d += 4;
					firmware_version = (d[0]<<8) + d[1];
					return true;
				}
			} while (1);
		}

	private:
		Wire*                        wire;
		int                          sequence;
	};


	GetHardwareInfo *GetHardwareInfo::MakeGetHardwareInfo(Wire *wire, int seq) {
		return new RealGetHardwareInfo(wire, seq);
	}

	class RealDoUpgrade : public DoUpgrade {
	public:
		RealDoUpgrade(Wire *w, Progress *p, bool r) :
			wire(w), progress(p), sequenceError(-1), reprogram(r),
			lastType(NSLU2Protocol::InvalidType) {
			if (reprogram) {
				NSLU2Protocol::ReprogramStartPacket packet(seq);
				wire->Send(packet.PacketBuffer(), packet.PacketLength());
			} else {
				NSLU2Protocol::UpgradeStartPacket packet(seq);
				wire->Send(packet.PacketBuffer(), packet.PacketLength());
			}
		}

		virtual ~RealDoUpgrade() {
		}

		virtual void Upgrade(int address, int length, const char *buffer);
			/* Upgrade the given bytes at the given address, throws an
			 * exception on error.
			 */

		virtual void Verify(int address, int length, const char *buffer);
			/* Verify the given bytes at the given address, returns false
			 * if verification fails.  Note that 'Upgrade' must precede
			 * Verify and not be inter-mixed with it, however Verify may
			 * be called without Upgrade (note that the protocol can only
			 * verify a simple upgrade, not a reprogram).
			 */

		virtual void Finish(void);
			/* Finish a verify (or upgrade) - need only be called at the
			 * end.  Throws an exception on error.
			 */

		virtual void Reboot(void);
			/* Reboot the NSLU2. */

	private:
		bool Receive(unsigned long timeout);
			/* Receive one or more packets, if the API returns 'true'
			 * then a sequence error has been detected and the caller
			 * must retransmit the relevant packets.
			 */

		void ReceiveAndRetransmit(NSLU2Protocol::Type type,
				unsigned long timeout);
			/* Call Receive, do a retransmit if required, the type
			 * is the type of the packet being received (upgrade or
			 * verify) but is only used for the progress indicator.
			 */

		void Transmit(NSLU2Protocol::Type type, int sequence, int address,
				int length, const char *buffer);
			/* Transmit a single packet, return the sequence number,
			 * throws an exception on error.
			 */

		void Transmit(int sequence);
			/* Transmit an already prepared packet. */

		void Send(NSLU2Protocol::Type type, int address, int length,
				const char *buffer);
			/* Send a single packet for an upgrade or verify, dealing
			 * with retransmission errors and the possible need for a
			 * blocking receive.
			 */

		void DoBlock(NSLU2Protocol::Type type, int address, int length,
				const char *buffer);
			/* Implement either Upgrade or Verify according to the value
			 * of 'type'
			 */

		inline int AddressOfLastSent(NSLU2Protocol::Type type) const {
			/* Return the base address of the last sent packet,
			 * initially return -1
			 */
			if (lastType == type)
				return packetInfo[seq.LastSent() &
					NSLU2Protocol::PacketArrayMask].address;
			else
				return -1;
		}

	private:
		NSLU2Protocol::SequenceNumber  seq;
		Wire*                          wire;
		Progress*                      progress;
		NSLU2Protocol::Type            lastType;
		int                            sequenceError;
		bool                           reprogram;
		struct Info {
			int sequence;  /* complete sequence number */
			int address;   /* complete address */
			int length;    /* copy of length from packet */

			inline void Init(int s, int a, int l) {
				sequence = s;
				address = a;
				length = l;
			}
		}                              packetInfo[NSLU2Protocol::PacketArraySize];
		/* The packets are stored at the end because they are large
		 * and will flood the data cache if interleaved with the other
		 * data.  Typically a packet is only touched when it is actually
		 * sent.
		 */
		NSLU2Protocol::DataPacket      packetArray[NSLU2Protocol::PacketArraySize];

	};

	DoUpgrade *DoUpgrade::MakeDoUpgrade(Wire *wire, Progress *progress, bool reprogram) {
		return new RealDoUpgrade(wire, progress, reprogram);
	}
};

/* Transmit a single packet, throws an exception on error. */
void NSLU2Upgrade::RealDoUpgrade::Transmit(int sequence) {
	const int i(sequence & NSLU2Protocol::PacketArrayMask);
	wire->Send(packetArray[i].PacketBuffer(), packetArray[i].PacketLength());
}

void NSLU2Upgrade::RealDoUpgrade::Transmit(NSLU2Protocol::Type type, int sequence,
		int address, int length, const char *buffer) {
	const int i(sequence & NSLU2Protocol::PacketArrayMask);
	packetInfo[i].Init(sequence, address, length);
	packetArray[i].Init(type, sequence, address, length, buffer);
	lastType = type;
	Transmit(sequence);
}

/* The logic to handle the upgrade protocol is contained in this function.
 * It receives packets and changes the internal state of RealDoUpgrade to
 * match.  Note that this only handles the upgrade/verify packets, HardwareInfo
 * and Reboot are handled separately (there is no possibility of out of order
 * packets with these.)
 *
 * On 'true' a sequence error requires packet retransmission.  If a Start
 * packet is dropped the state is set to 'error' and the whole process has
 * to be restarted - 'true' is *not* returned - 'true' means that an UpgradeData
 * or VerifyData packet returned a sequence number error.
 */
bool NSLU2Upgrade::RealDoUpgrade::Receive(unsigned long timeout) {
	bool retransmit(false);
	do {
		NSLU2Protocol::ReceivePacket receive;
		size_t size = receive.PacketBufferSize();
		wire->Receive(receive.PacketWriteBuffer(), size, timeout);

		if (size > 0) {
			switch (receive.TypeOf()) {
			case NSLU2Protocol::UpgradeData: case NSLU2Protocol::UpgradeVerify:
				/* packet contains a return code which says whether
				 * the sequence number has been 'consumed'
				 */
				switch (receive.ReturnCode()) {
				case NSLU2Protocol::Ok:
					/* operation completed ok.  At least one upgrade
					 * or verify packet has been handled, therefore
					 * advance the system state.
					 */
					seq.Seen(receive.Sequence());
					if (progress) {
						const int s(seq.LastSeen());
						const int i(s & NSLU2Protocol::PacketArrayMask);
						if (s == packetInfo[i].sequence)
							progress->Received(receive.TypeOf(), s,
								packetInfo[i].address,
								packetInfo[i].length);
						else
							throw std::logic_error("bad sequence");
					}
					break;

				case NSLU2Protocol::SequenceError:
					/* packet out of sequence (and ignored), this
					 * is recoverable with a retransmit.  This
					 * API keeps receiving packets just in case
					 * some were received ok.
					 */
					sequenceError = receive.Sequence(); /* 2 bytes */
					retransmit = true;
					break;

				case NSLU2Protocol::ProtocolError:
					/* operation not expected (UpgradeStart packet
					 * dropped), nothing has been done.
					 */
				case NSLU2Protocol::ProgramError:
					/* flash programming failed (fatal) */
				case NSLU2Protocol::VerifyError:
					/* flash verification failed (fatal) */
					{
						/* This assumes that the packet is one we
						 * transmitted - it doesn't much matter
						 * if it isn't, the information recorded
						 * will just be wrong.  For VerifyError,
						 * where the info is important, it should
						 * always be correct.
						 */
						const int i(receive.Sequence() &
								NSLU2Protocol::PacketArrayMask);
						throw FlashError(receive.ReturnCode(),
								packetInfo[i].address,
								packetInfo[i].length);
					}
				}
				break;
			case NSLU2Protocol::UpgradeStart:
			case NSLU2Protocol::ReprogramStart:
			case NSLU2Protocol::Reboot:
				/* sequence ignored, return code irrelevant */
				seq.Seen(receive.Sequence());
				break;
			default:
				/* not a known (or expected) packet type, ignore it. */
				break;
			}

			timeout = 0;  /* Just consume any remaining packets. */
		} else
			return retransmit; /* no more packets */
	} while (1);
}

void NSLU2Upgrade::RealDoUpgrade::ReceiveAndRetransmit(NSLU2Protocol::Type type,
		unsigned long timeout) {
	/* Call Receive, do a retransmit if required. */
	while (Receive(timeout)) {
		/* retransmit required.  The NSLU2 implementation of this protocol
		 * is somewhat broken, on Verify it flags out-of-sequence if it gets
		 * too old a packet.  On Upgrade it uses a < test, which, since the
		 * 16 bit sequence numbers wrap, is doomed to failure.  In either case
		 * we may get here with nothing to retransmit.
		 */
		int seen(seq.LastSeen());
		int sent(seq.LastSent());
		if (seen < sent) {
			if (progress)
				progress->Retransmit(type, seen+1, sequenceError);
			/* Just transmit the one packet we know to be unseen. */
			Transmit(seen+1);
		}
	}
}

void NSLU2Upgrade::RealDoUpgrade::Send(NSLU2Protocol::Type type, int address,
		int length, const char *buffer) {
	/* Send a single packet for an upgrade or verify, dealing with
	 * retransmission errors and the possible need for a blocking
	 * receive.
	 *
	 * First receive any pending packets then check to see if there is
	 * space for the new packet, if there isn't do a blocking receive
	 * until there is (with possible retransmits).
	 */
	ReceiveAndRetransmit(type, 0); /* no timeout - poll */
	if (seq.LastSent() >= NSLU2Protocol::MaxPendingPackets + seq.LastSeen()) {
		ReceiveAndRetransmit(type, 1<<16); /* block for up to 1/16s */
		/* If no advance has been made - no slot is available - retransmit
		 * the last packet to provoke a retransmit error if packets have
		 * been dropped.
		 */
		while (seq.LastSent() >= NSLU2Protocol::MaxPendingPackets + seq.LastSeen()) {
			if (progress)
				progress->Timeout(type, seq.LastSeen()+1);
			Transmit(seq.LastSent());
			ReceiveAndRetransmit(type, 1<<17); /* block for 0.125s now */
		}
	}

	/* Transmit this packet. */
	const int sequence(seq.Send());
	Transmit(type, sequence, address, length, buffer);
	if (progress)
		progress->Sent(type, sequence, address, length);
}

void NSLU2Upgrade::RealDoUpgrade::DoBlock(NSLU2Protocol::Type type,
		int address, int length, const char *buffer) {
	/* Do an upgrade or verify.  Transmit all the given data, dealing with
	 * the possible need to handle a 1MByte boundary, retransmission and
	 * blocking receives.
	 */
	{
		const int addressBoundary(address & ~0xfffff);
		do {
			/* Note that AddressOfLastSent is -1 initially and the
			 * result of the following expression must compare <0 -
			 * the first possible address.
			 */
			const int lastBoundary(AddressOfLastSent(type) & ~0xfffff);
			if (lastBoundary >= addressBoundary ||
					lastBoundary+0x100000 == address)
				break;
			Send(type, lastBoundary+0x100000, 0, NULL);
		} while (1);
	}

	while (length > 0) {
		/* Break the data into packets and transmit each in turn. */
		int lengthToSend(length);
		if (lengthToSend > NSLU2Protocol::MaxDataLength)
			lengthToSend = NSLU2Protocol::MaxDataLength;
		if (lengthToSend + (address & 0xfffff) > 0x100000)
			lengthToSend = 0x100000 - (address & 0xfffff);
		Send(type, address, lengthToSend, buffer);
		address += lengthToSend;
		buffer += lengthToSend;
		length -= lengthToSend;
	}
}

/* Upgrade the given bytes at the given address, throws an exception on error.
 */
void NSLU2Upgrade::RealDoUpgrade::Upgrade(int address, int length, const char *buffer) {
	/* Verify the address being used here, it should be a multiple of 4, note
	 * that, for this to work, all the code which sends addresses must generate
	 * addresses which are multiples of 4.  (This doesn't matter for the
	 * verify case - that can handle byte addresses.)
	 */
	if ((address & 3) || (length & 3))
		throw AddressError(address, length);

	/* Simple upgrade programs only the addresses beyound BaseAddress,
	 * reprogram overwrites the whole flash.
	 */
	if (!reprogram && address < NSLU2Protocol::BaseAddress) {
		length += address;
		if (length <= NSLU2Protocol::BaseAddress)
			return; /* nothing to do. */
		address = NSLU2Protocol::BaseAddress;
		length -= address;
	}

#if 1
	/* Skip blocks of 255 valued bytes - the erase clears the flash to this
	 * value.  The protocol header is 24 bytes (14 for the ethernet header,
	 * 10 for the NSLU2 protocol header), so if we see that number or more
	 * bytes set to 255 in a row break the transmit at that point.  The
	 * value to check for is 'SkipLength'
	 */
	while (length > 0) {
		int i(0);
		while (buffer[i] == '\xff')
			if (++i >= length)
				return;

		/* buffer[i] first non-255 byte */
		int e1(i);  /* buffer[e1]: 255 byte or length */
		int e2;     /* buffer[e2]: following non-255 byte or length */
		do {
			e2 = length;
			do
				if (++e1 >= length)
					goto break2;
			while (buffer[e1] != '\xff');

			e2 = e1;
			do
				if (++e2 >= length)
					goto break2;
			while (buffer[e2] == '\xff');

			if (e2-e1 >= NSLU2Protocol::SkipLength)
				goto break2;

			e1 = e2; /* index of a non-255 byte again */
		} while (1);
	break2:

		/* Align to a 4 byte boundary. */
		i &= ~3;
		e1 = (e1+3) & ~3;
		e2 &= ~3;
		if (e1 > e2 || e2 > length)
			throw std::logic_error("error in skip calculation");

		/* Process b[i]..b[e1-1] and skip to b[e2] */
		DoBlock(NSLU2Protocol::UpgradeData, address+i, e1-i, buffer+i);

		address += e2;
		buffer += e2;
		length -= e2;
	}
#else
		DoBlock(NSLU2Protocol::UpgradeData, address, length, buffer);
#endif
}

/* Verify the given bytes at the given address, raise an exception if verification
 * fails.  Note that 'Upgrade' must precede Verify and not be inter-mixed with it,
 * however Verify may be called without Upgrade (note that the protocol can only
 * verify a simple upgrade, not a reprogram).
 */
void NSLU2Upgrade::RealDoUpgrade::Verify(int address, int length, const char *buffer) {
	/* If an Upgrade is still in progress make sure it completes first. */
	if (lastType == NSLU2Protocol::UpgradeData)
		Finish();

	/* Verify never verifies anything below BaseAddress. */
	if (address < NSLU2Protocol::BaseAddress) {
		length += address;
		if (length <= NSLU2Protocol::BaseAddress)
			return; /* nothing to do. */
		address = NSLU2Protocol::BaseAddress;
		length -= address;
	}

	/* Verify all the passed in data (including bytes which should be 255!) */
	DoBlock(NSLU2Protocol::UpgradeVerify, address, length, buffer);
}

/* Finish a verify (or upgrade) - need only be called at the end.  Throws an
 * exception on error.
 */
void NSLU2Upgrade::RealDoUpgrade::Finish(void) {
	const int lastSent(seq.LastSent());
	int lastSeen(seq.LastSeen());
	while (lastSent > lastSeen) {
		ReceiveAndRetransmit(lastType, 1<<16); /* 1/16s to block */
		const int seen(seq.LastSeen());
		if (seen == lastSeen) { /* no progress */
			if (progress)
				progress->Timeout(lastType, seen+1);
			Transmit(lastSent); /* provoke retransmit */
		} else
			lastSeen = seen;
	}
}

/* Reboot the NSLU2. */
void NSLU2Upgrade::RealDoUpgrade::Reboot(void) {
	/* Ensure the data operations complete. */
	Finish();

	int sequence(seq.Send());
	do {
		{
			NSLU2Protocol::RebootPacket reboot(sequence);
			wire->Send(reboot.PacketBuffer(), reboot.PacketLength());
		}

		/* Ensure that the packet is received. */
		Receive(1<<18); /* 0.25s timeout. */
	} while (seq.LastSeen() < sequence);
}
