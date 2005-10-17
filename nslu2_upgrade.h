/*-
 * nslu2_upgrade.h
 *  Classes to upgrade an NSLU2.
 */
#ifndef NSLU2_UPGRADE_H
#define NSLU2_UPGRADE_H 1

#include <stdexcept>

#include "nslu2_protocol.h"

namespace NSLU2Upgrade {
	/* Exception classes. */
	class OSError : public std::exception {
	public:
		inline OSError(int err) : errval(err), reason(0) {
		}
		inline OSError(int err, const char *what) :
			errval(err), reason(what) {
		}

		const char *what(void) {
			if (reason)
				return reason;
			return std::exception::what();
		}

		int         errval; /* OS errno value */
		const char *reason; /* Additional error information */
	};

	class SendError : public OSError {
	public:
		inline SendError(int err) : OSError(err) { }
	};

	class ReceiveError : public OSError {
	public:
		inline ReceiveError(int err) : OSError(err) { }
	};

	class WireError : public OSError {
	public:
		inline WireError(int err) : OSError(err) { }
		inline WireError(int err, const char *what) : OSError(err, what) { }
	};

	/* The basic class implemented to transmit and receive packets over the
	 * wire.
	 */
	class Wire {
	public:
		virtual ~Wire() {
		}

		/* Throws SendError(errno) on a fatal error. */
		virtual void Send(const void *packet, size_t length) = 0;

		/* Receive throws ReceiveError on a fatal error, otherwise
		 * it must update size with the received packet size.  0
		 * must be used to indicate failure to receive a packet (and
		 * this must not be fatal).  If timeout is greater than 0 the
		 * implementation should wait that number of microseconds until
		 * a packet is received or the timeout has expired (in which
		 * case a size of 0 must be returned).
		 */
		virtual void Receive(void *buffer, size_t &size, unsigned long timeout) = 0;

		/* Return the address of the last received packet.  This is
		 * an NSLU2 so the address is a 6 byte Ethernet hardware
		 * address.
		 */
		virtual void LastAddress(unsigned char address[6]) = 0;

		/* Make a new wire, which may be deleted with delete.  The
		 * address should be a value (null terminated this time) returned
		 * by LastAddress, if NULL the Wire will broadcast.  'device'
		 * is the hardware device name to use - the value of the
		 * --device parameter on the command line (if given).  If not
		 *  given (NULL) a potentially useless default will be used.  The
		 *  uid, if not (-1), is an effective user id which will be used
		 *  to make the wire if the current effective user id has
		 *  insufficient privelege.
		 *
		 *  The mac parameter should be the 6 byte ethernet address of
		 *  this device, if not given the internal code will attempt to
		 *  extract it from the device name.  In general it should not
		 *  be given, but this is a work round for when porting to a new
		 *  OS.
		 *
		 *  Throws WireError on (OS) error.
		 */
		static Wire *MakeWire(const char *device, const unsigned char *mac,
				const unsigned char address[6], int uid);
	};

	/* The implemented classes. */
	class GetHardwareInfo {
	public:
		virtual ~GetHardwareInfo() {
		}

		virtual bool Next(unsigned short &product_id, unsigned short &protocol_id,
			unsigned short &firmware_version) = 0;
			/* Return information from the next received packet,
			 * return false if there is no packet (empty packet
			 * returned or fatal error).  The information is the
			 * current flash product id, protocol id and firmware
			 * version from the hardware info packet - the rest of
			 * the packet has already been validated.
			 */

		static GetHardwareInfo *MakeGetHardwareInfo(Wire *wire, int id);
			/* Instantiate a GetHardwareInfo - returns NULL if the
			 * object cannot be instantiated.
			 *
			 * The Wire class determines how the packets are sent
			 * out - broadcast to find all the NSLU2's, directed to
			 * a particular NSLU2 to get info for that machine.
			 *
			 * The id value can be any 16 bit value, it is used to
			 * identify the packets returned in response to the info
			 * request.
			 */
	};

	/* A class to allow progress to be signalled back to the caller - implement
	 * a sub-class to deal with progress updates.  See upslug2_progress for a
	 * basic implementation which handles the callbacks but doesn't, itself,
	 * output any progress indication.
	 */
	class Progress {
	public:
		/* This is a dummy implementation which does nothing. */
		virtual inline ~Progress() {
		}

		/* Sent is called whenever a packet is sent with the sequence
		 * number, address (in flash) of the data and length of the
		 * data.  If retransmission is necessary the sequence number will
		 * be re-used, the last sent valid address (and the highest) is
		 * always that in the last 'Sent' callback - i.e. lower sequence
		 * numbers/addresses invalidate earlier sends.
		 */
		virtual inline void Sent(NSLU2Protocol::Type type, int sequence,
				int address, int length) {
		}

		/* Timeout is called when a receive timeout occurs, the sequence
		 * number is that of the earliest un-received (not seen) packet.
		 */
		virtual inline void Timeout(NSLU2Protocol::Type type, int sequence) {
		}

		/* Retransmit is called when a packet must be retransmitted, the
		 * sequence number is that of the first packet to be retransmitted.
		 * The sequenceError value is from the packet which indicated the
		 * sequence number problem.
		 */
		virtual inline void Retransmit(NSLU2Protocol::Type type, int sequence,
				int sequenceError) {
		}

		/* Received is called after a packet is received and it is passed
		 * the highest sequence number received (not necessarily that of
		 * the received packet) - this is a low water mark on the flash upgrade
		 * or verify, this packet and all earlier ones (therefore all earlier
		 * addresses) have been handled on the NSLU2.
		 */
		virtual inline void Received(NSLU2Protocol::Type type,
				int sequence, int address, int length) {
		}
	};

	class FlashError : public std::exception {
	public:
		inline FlashError(NSLU2Protocol::ReturnCodeType code, int a, int l) :
			returnCode(code), address(a), length(l) {
		}

		NSLU2Protocol::ReturnCodeType returnCode; /* The NSLU2 error code. */
		int                           address;    /* Address from problem packet */
		int                           length;     /* Length from problem packet */
	};

	class SequenceError : public std::exception {
	public:
		inline SequenceError(int seen, int sent, int error) :
			lastSeen(seen), lastSent(sent), sequenceError(error) {
		}

		int lastSeen;      /* Sequence number last seen */
		int lastSent;      /* Sequence number last sent */
		int sequenceError; /* Sequence number from packet indicating error */
	};

	class AddressError : public std::exception {
	public:
		inline AddressError(int a, int l) : address(a), length(l) {
		}

		int address; /* problem address */
		int length;  /* length of data */
	};

	class DoUpgrade {
	public:
		virtual ~DoUpgrade() {
		}

		virtual void Upgrade(int address, int length, const char *buffer) = 0;
			/* Upgrade the given bytes at the given address. */

		virtual void Verify(int address, int length, const char *buffer) = 0;
			/* Verify the given bytes at the given address, throws an
			 * exception if verification fails.  Note that 'Upgrade' must
			 * precede Verify and not be inter-mixed with it, however Verify
			 * may be called without Upgrade (note that the protocol can only
			 * verify a simple upgrade, not a reprogram).
			 */

		virtual void Finish(void) = 0;
			/* Finish a verify (or upgrade) - need only be called at the
			 * end.  Throws an exception on error.
			 */

		virtual void Reboot(void) = 0;
			/* Reboot the NSLU2. */

		static DoUpgrade *MakeDoUpgrade(Wire *wire, Progress *progress, bool reprogram);
			/* Instantiate a real DoUpgrade, returns NULL if the object
			 * cannot be instantiated.
			 *
			 * The Wire class must be set up to transmit to a particular
			 * NSLU2 device, that device will be upgraded.
			 */
	};
};

#endif
