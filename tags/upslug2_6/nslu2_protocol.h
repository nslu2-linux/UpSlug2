/*-
 * nslu2_protocol.h
 *  A definition of the protocol used by the NSLU2 in "upgrade mode".
 *
 *  The protocol consists of a sequence of packets which are sent and
 *  received over the lowest level ethernet protocol (which, it is important
 *  to note, is unreliable - the packet may need to be resent by the
 *  program).  The values in the packet are little endian - least significant
 *  byte first.
 *
 *  Each protocol packet is acknowledged by the NSLU2, sometimes by
 *  simply returning the original packet with the first couple of bytes
 *  modified to an error code, sometimes (in the case of HardwareInfo)
 *  by returning a new packet with the requested information.
 *
 * BYTES 0,1 TYPE
 * The first two bytes in the data packet describe the contents of
 * the rest of the packet and what to do with them.
 *
 * HardwareInfo   Return a description of hardware and firmware
 * UpgradeStart   Start an upgrade
 * UpgradeData    Download a block of new data
 * Reboot         Reboot the NSLU2
 * UpgradeVerify  Verify a block of data ('upgrade' data only)
 * ReprogramStart Start a complete reflash (Reboot too)
 *
 * BYTES 2,3  SEQUENCE
 * The next two bytes give a little endian sequence number, the protocol
 * requires packets of data (UpgradeData and UpgradeVerify) to have
 * sequence numbers incremented by one between each packet.  The initial
 * sequence number is set by the UpgradeStart or ReprogramStart packet.
 * Verification and Upgrade commands may not be intermixed - Verify must
 * follow upgrade - because the first UpgradeData erases the flash and
 * the first Verify resets the 'erase' state to 'erase on next UpgradeData'.
 *
 * BYTES 4,5 and 6,7 ADDRESS
 * Next comes the address.  This is relevant only for UpgradeData and
 * UpgradeVerify.  The address is an offset within a 1MByte block stored
 * as a byte offset within a 16 byte chunk plus a chunk offset.  Both
 * offsets are 16 bit values, therefore the scheme can only address
 * (about) 1MByte.  When the NSLU2 receives a 0 address it increments
 * it's internal 1MByte block counter.  This is set to (-1) by both
 * UpgradeStart and ReprogramStart and on the first UpgradeVerify.
 * Consequently the first UpgradeData or UpgradeVerify must have an
 * address of 0 (to cause the block number to be incremented to 0).
 *
 * BYTES 4,5: byte offset
 * BYTES 6,7: 16 byte chunk
 *
 * BYTES 8,9  LENGTH
 * The data length is stored next - this is the number of bytes of data
 * which follows.  The actual protocol code in the NSLU2 defines 600
 * bytes for this, however the buffer is allocated by the stock RedBoot
 * ethernet code and this seems to be set up to handle a maximum data
 * length of an ethernet packet (1500 bytes) correctly.
 *
 * Nevertheless of safety, and just in case something on the wire limits
 * the packet size further, this code sends 512 bytes of data at a time;
 * so the maximum data size (including the header) is 522 bytes.
 *
 *-----------------------------------------------------------------------------
 * Protocol definitions.
 *-----------------------------------------------------------------------------
 * In practice the RedBoot implementation does not re-allocate the buffer
 * before returning the packet, therefore whatever the value of the LENGTH
 * field in the packet, the packet must be long enough to also accomodate the
 * return data.  Also the sequence number is never changed, so it can be
 * used to check the response to a packet of any type.
 *
 * HardwareInfo
 * SEND:
 *  TYPE:	HarwareInfo
 *  SEQUENCE:	not required
 *  ADDRESS:	not required
 *  LENGTH:	not required
 *  DATA:	not required
 * RECEIVE:
 *  TYPE:	HardwareInfo
 *  SEQUENCE:	not set
 *  ADDRESS:	not set
 *  LENGTH:	56
 *  DATA:
 *  	The data is taken from the last 70 bytes of the RedBoot flash
 *  	segment, with the trailing and leading 7 bytes stripped and then
 *	further overwritten with the first 6 of the last 16 bytes of the
 *	flash.  Consequently the data block returned looks like this:
 *
 *	0..37  RedBoot 0x03FFC1..0x03FFF8
 *	38,39  Flash   0x7FFFF0, 0x7FFFF1	'product id'
 *	40,41  RedBoot 0x03FFE9, 0x03FFEA	'product id mask'
 *	42,43  Flash   0x7FFFF2, 0x7FFFF3	'protocol id'
 *	44,45  RedBoot 0x03FFED, 0x03FFEE	'protocol id mask'
 *	46..49 RedBoot 0x03FFEF, 0x03FFF2
 *	50,51  Flash   0x7FFFF4, 0x7FFFF5	'firmware version'
 *	52..55 RedBoot 0x03FFF5, 0x03FFF8
 *
 *	The values do not seem to be very useful:
 *
 *	product id	1
 *	protocol id	0
 *	FuncID(redboot)	3
 *	firmware	2329
 *
 * UpgradeStart
 * SEND:
 *  TYPE:	UpgradeStart
 *  SEQUENCE:	first sequence number
 *  ADDRESS:	not required
 *  LENGTH:	not required
 *  DATA:	not required
 * RECEIVE:
 *  TYPE:	UpgradeStart
 *  SEQUENCE:	not set
 *  ADDRESS:	not set
 *  LENGTH:	2
 *  DATA:	not set (!)
 *
 * ReprogramStart is identical.
 *
 * Reboot
 * SEND:
 *  TYPE:	Reboot
 *  SEQUENCE:	not required
 *  ADDRESS:	not required
 *  LENGTH:	not required
 *  DATA:	not required
 * RECEIVE:
 *  TYPE:	Reboot
 *  SEQUENCE:	not set
 *  ADDRESS:	not set
 *  LENGTH:	0 (!)
 *  DATA:	2 bytes set to 0
 */
#ifndef NSLU2_PROTOCOL_H
#define NSLU2_PROTOCOL_H 1

#include <cstring>

#define CHECK_ADDRESS 0
#if CHECK_ADDRESS
#include <stdexcept>
#endif

namespace NSLU2Protocol {
	/* CONSTANTS */
	typedef enum {
		HardwareInfo   = 0,
		UpgradeStart   = 1,
		UpgradeData    = 2,
		Reboot         = 3,
		UpgradeVerify  = 4,
		ReprogramStart = 5,
		InvalidType    = 0xffff,
	} Type;

	/* The following define the possible return codes - these are only
	 * set for UpgradeData and UpgradeVerify.  If an error is marked as
	 * fatal it will be necessary to restart (and re-erase).
	 */
	typedef enum {
		Ok            = 0, /* operation completed ok */
		ProtocolError = 5, /* operation not expected (UpgradeStart packet dropped) */
		SequenceError = 6, /* packet out of sequence (and ignored) */
		ProgramError  = 7, /* flash programming failed (fatal) */
		VerifyError   = 9, /* flash verification failed (fatal) */
	} ReturnCodeType;

	typedef enum {
		TypeOffset = 0,
		SequenceOffset = 2,
		AddressOffset = 4,
		LengthOffset = 8,
		DataOffset = 10,
		HeaderLength = DataOffset,
		SkipLength = 14+HeaderLength,/* actual packet header size */
		HardwareInfoLength = 56,
		MinDataLength = 2,           /* For the return code */
		/* By experiment 1504 produces a 'message too long' error from Linux,
		 * even though it should be fine.  1472 is chosen as the next lower
		 * multiple of 32 (and, in this case, 64).
		 */
		MaxDataLength = 1472,        /* 1540-14(eth hdr)-10(this header) - 1516 */
		MaxPacketLength = 1540-14,   /* at least 600 from the RedBoot code */
		BaseAddress = 0x60000,       /* skip RedBoot and SysConf */
		UpgradeProtocol = 0x8888,    /* defined in the RedBoot code */
		Ln2FlashSize = 23,           /* 8MByte Flash memory */
		FlashSize = (1<<Ln2FlashSize),
		/* The MaxPendingPackets figure is the number of packets which will
		 * be transmitted without receiving a response, this value should be
		 * 5, but experiment on a single system shows that even at 4 timeouts
		 * will occur (because of dropped packets).  It would seem that the
		 * RedBoot polling (not interrupt driven) implementation of the ethernet
		 * packet handling is unable to keep up, at least while upgrading
		 * (writing the flash).
		 */
		//MaxPendingPackets = 5,     /* Redboot can buffer 4 while one is in process */
		MaxPendingPackets = 1,       /* Determined by experiment to be the maximum */
		PacketArraySize = 8,         /* Next power of two for the array of data packets */
		PacketArrayMask = 7,         /* Mask a packet array index from an address */
	} Constant;

	/* SEQUENCE NUMBER HANDLING CLASS */
	/* SequenceNumber holds a sequence number and manages the tricky logic
	 * of updating it correctly - the local end needs to know both the
	 * last sequence number *sent* and the last one acknowledged.  In this
	 * implementation the initial sequence number is always "1".
	 */
	class SequenceNumber {
	public:
		SequenceNumber(void) :
			lastSeen(0), lastSent(0)
		{}

		inline unsigned long LastSeen(void) const {
			return lastSeen;
		}

		inline unsigned long LastSent(void) const {
			return lastSent;
		}

		inline int Send(void) {
			return ++lastSent;
		}

		/* Seen returns 'false' if the value is detectably invalid -
		 * if it is numerically greater than the lastSeen value.  Note
		 * that each packet is 512 bytes, so 65536 sequence numbers
		 * only allow for 32MByte, thus the sequence number will wrap
		 * in the verify for a 16MByte image.
		 */
		inline bool Seen(int seen) {
			if (seen > (lastSent & 0xffff))
				seen |= (lastSeen & ~0xffff);
			else
				seen |= (lastSent & ~0xffff);
			if (seen > lastSeen) {
				if (seen <= lastSent)
					lastSeen = seen;
				else
					return false;
			}
			return true;
		}

		/* Resend resets the sequence number to 'lastSeen', so that the
		 * next sent sequence number will be for the packet after the
		 * last seen one.
		 */
		inline void Resend(void) {
			lastSent = lastSeen;
		}

	private:
		unsigned long lastSeen, lastSent;
	};

	/* PACKET CLASSES */
	/* Packets vary in size, so we need a template class. */
	template <int datalength> class Packet {
		/* THE BUFFER */
	private:
		unsigned char buffer[HeaderLength+
			(datalength < MinDataLength ? MinDataLength : datalength)];

		/* APIS */
	private:
		/* Buffer APIs */
		inline void Write16Bits(int where, int value) {
			buffer[where+0] = value;
			buffer[where+1] = value >> 8;
		}

		inline void WriteAddress(int address) {
			/* Write offset then chunk. */
			Write16Bits(AddressOffset, address & 0xf);
			Write16Bits(AddressOffset+2, address >> 4);
		}

		inline int ReadAddress(void) const {
			return Read16Bits(AddressOffset) + (Read16Bits(AddressOffset+2) << 4);
		}

		inline unsigned char *WriteData(void) {
			return buffer + DataOffset;
		}

		inline const unsigned char *ReadData(void) const {
			return buffer + DataOffset;
		}

	protected:
		inline int Read16Bits(int whence) const {
			return buffer[whence+0] + (buffer[whence+1] << 8);
		}


		/* CONSTRUCTOR */
	protected:
		/* This does not initialise the data! */
		void Init(Type type, int sequence, int address, int length) {
#if CHECK_ADDRESS
			/* It would seem that the NSLU2 RedBoot flash write
			 * code relies on the address being correctly aligned for
			 * the base type of the flash.  Since this is 16 bit and
			 * might be 32 bit this code sanity checks the address
			 * here.
			 */
			if (address & 3)
				throw std::logic_error("badly aligned flash address");
#endif
			Write16Bits(TypeOffset, type);
			Write16Bits(SequenceOffset, sequence);
			WriteAddress(address);
			Write16Bits(LengthOffset, length);
		}

		/* This is used where the sequence number is a pre-determined
		 * value (the data packets).
		 */
		inline Packet(Type type, int sequence, int address, int length) {
			Init(type, sequence, address, length);
		}

		/* This is used for packets to be sent where the sequence number is
		 * just the next in line.
		 */
		inline Packet(Type type, SequenceNumber &seq, int address, int length) {
			Init(type, seq.Send(), address, length);
		}

		/* This is used for the array of data packets, which are uninitialised
		 */
		inline Packet() {}

		/* PUBLIC APIs */
	public:
		inline Type TypeOf(void) const {
			return static_cast<Type>(Read16Bits(TypeOffset));
		}
		inline int DataLength(void) const {
			return Read16Bits(LengthOffset);
		}
		inline int PacketLength(void) const {
			int dataLength(DataLength());
			if (dataLength < MinDataLength)
				dataLength = MinDataLength;
			return HeaderLength + dataLength;
		}
		inline int Sequence(void) const {
			return Read16Bits(SequenceOffset);
		}
		inline const unsigned char *PacketBuffer(void) const {
			return buffer;
		}
		inline const unsigned char *Data(void) const {
			return buffer + DataOffset;
		}
		inline unsigned char *Data(void) {
			return buffer + DataOffset;
		}

	protected:
		inline unsigned char *PacketWriteBuffer(void) {
			return buffer;
		}
	};

	/* Constructors for specific packet types. */
	class HardwareInfoPacket : public Packet<HardwareInfoLength> {
	public:
		/* This packet allows an arbitrary sequence number because it will
		 * typically be broadcast - this allows us to more reliably detect
		 * responses to our request.
		 */
		inline HardwareInfoPacket(int sequence) :
			Packet<HardwareInfoLength>(HardwareInfo, sequence, 0,
					HardwareInfoLength) {
		}
	};
	class RebootPacket : public Packet<0> {
	public:
		inline RebootPacket(int sequence) :
			Packet<0>(Reboot, sequence, 0, 0)
		{}
	};

	/* UpgradeStartPacket and ReprogramStartPacket are both instances of
	 * StartPacket and StartPacket contains the sequence number for the
	 * upgrade and verify exchange.
	 */
	class StartPacket : public Packet<0> {
	protected:
		inline StartPacket(Type type, SequenceNumber &seq) :
			Packet<0>(type, seq, 0, 0)
		{}
	};
	class UpgradeStartPacket : public StartPacket {
	public:
		inline UpgradeStartPacket(SequenceNumber &seq) :
			StartPacket(UpgradeStart, seq)
		{}
	};
	class ReprogramStartPacket : public StartPacket {
	public:
		inline ReprogramStartPacket(SequenceNumber &seq) :
			StartPacket(ReprogramStart, seq)
		{}
	};

	/* UpgradeDataPacket and VerifyDataPacket are implemented using a shared
	 * DataPacket.  In practice these are allocated in an uninitialised array.
	 */
	class DataPacket : public Packet<MaxDataLength> {
	public:
		/* The public initialiser. */
		void Init(Type type, int sequence, int address, int length,
				const void *data) {
			Packet<MaxDataLength>::Init(type, sequence, address, length);
			std::memcpy(Data(), data, length);
		}

		inline DataPacket(Type type, int sequence, int address,
				int length, const void *data) {
			Init(type, sequence, address, length, data);
		}

		/* The non-initialising version */
		inline DataPacket() {}
	};

	/* A general packet used to receive data. */
	class ReceivePacket : public Packet<MaxPacketLength> {
	public:
		inline ReceivePacket() :
			Packet<MaxPacketLength>(InvalidType, 0xffff, 0, 0xffff)
		{}

		/* The ReceivePacket has a writeable buffer for Receive! */
		inline unsigned char *PacketWriteBuffer(void) {
			return Packet<MaxPacketLength>::PacketWriteBuffer();
		}

		inline int PacketBufferSize(void) const {
			return MaxPacketLength;
		}

		inline ReturnCodeType ReturnCode(void) const {
			if (TypeOf() == UpgradeData || TypeOf() == UpgradeVerify)
				return static_cast<ReturnCodeType>(Read16Bits(DataOffset));
			return Ok;

		}
	};
};

#endif
