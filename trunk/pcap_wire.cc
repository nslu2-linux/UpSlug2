/*-
 * pcap_wire.cc
 *
 * Implementation of Wire for libpcap
 */
#include "config.h"

#if HAVE_LIBPCAP
#include <cstring>
#include <stdexcept>

#if BROKEN_PCAP_TIMEOUT
#	include <sys/socket.h>
#	include <sys/select.h>
#endif
/* These are for the netdevice ioctl to read the hardware MAC, this may
 * be Linux specific, in which case it will be necessary to find another
 * way of getting the MAC (clearly it's possible because ifconfig outputs
 * it!)
 */
#include <sys/ioctl.h>
#include <net/if.h>

#include <unistd.h>
#include <errno.h>

#include <pcap.h>

#include "nslu2_upgrade.h"

namespace NSLU2Upgrade {
	/* The basic class implemented to transmit and receive packets over the
	 * wire.
	 */
	class PCapWire : public Wire {
	public:
		PCapWire(pcap_t *p, const char *device, const unsigned char address[6]) :
			pcap(p), file(pcap_fileno(p)), broadcast(address == 0) {
			/* The 255 gives the ethernet hardware broadcast address,
			 * set this if a host address is provided.  The packet
			 * header is:
			 *
			 * target MAC      [6 bytes] target or broadcast
			 * originating MAC [6 bytes] MAC of this device
			 * protocol        [2 bytes] 0x8888 (big endian)
			 */
			if (address)
				std::memcpy(header, address, 6);
			else
				std::memset(header, 255, 6);
			header[12] = NSLU2Protocol::UpgradeProtocol >> 8;
			header[13] = NSLU2Protocol::UpgradeProtocol;

			/* This is set just in case of a call to LastAddress before
			 * Receive has succeeded - the result will be all 0's
			 */
			std::memset(source, 0, sizeof source);

			/* This should always work. */
			if (file == -1)
				throw WireError(errno);

			/* The MAC of the transmitting device is needed - without
			 * this the return packet won't go to the right place!
			 */
			struct ifreq device_interface;
			strncpy(device_interface.ifr_name, device,
					sizeof device_interface.ifr_name);
			device_interface.ifr_name[(sizeof device_interface.ifr_name)-1] = 0;

			/* Get the hardware information. */
			if (ioctl(file, SIOCGIFHWADDR, &device_interface) == (-1))
				throw WireError(errno);

			/* And copy the MAC address into the header. */
			std::memcpy(header+6, device_interface.ifr_hwaddr.sa_data, 6);
		}

		virtual ~PCapWire() {
			pcap_close(pcap);
		}

		/* Throws SendError on a fatal error. */
		virtual void Send(const void *packet, size_t length) {
			if (length > 1540-14)
				throw std::logic_error("packet too large");

			/* Set no flags (0) - we block on the transmit if
			 * required, the pcap is *not* set O_NONBLOCK.
			 */
			char buffer[1540];
			std::memcpy(buffer, header, 14);
			std::memcpy(buffer+14, packet, length);

			char *data = buffer;
			int   len(length+14);
			do {
				/* This seems to work on BSD as well as Linux, BSD supports
				 * pcap_inject which does the same thing, WinPcap supports
				 * pcap_sendpacket, which also does the same thing.
				 */
				const ssize_t written(write(file, data, len));
				if (written < 0) {
					if (errno != EINTR)
						throw SendError(errno);
				} else {
					/* I suspect this won't work - the write either
					 * consumes all the data or none of it I think.
					 */
					data += written;
					len -= written;
				}
			} while (len > 0);
		}

		/* Receive throws ReceiveError on a fatal error and must update
		 * size with the received packet size.  0 must be used to
		 * indicate failure to receive a packet (and this must not
		 * be fatal).  If timeout is greater than 0 the implementation
		 * should wait that number of microseconds until a packet is
		 * received or the timeout has expired (in which case a size
		 * of 0 must be returned).
		 */
		virtual void Receive(void *buffer, size_t &size, unsigned long timeout) {
			{
				char errbuf[PCAP_ERRBUF_SIZE];

				/* The pcap is set to a 0.25s timeout - 1<<18, so to
				 * implement longer timeouts decrement the count each
				 * time.  If the timeout is zero set the pcap to
				 * non-blocking temporarily, ignore an error in this.
				 *
				 * On linux the timeout is broken, so we do things
				 * a different way and always set the interface non-blocking.
				 */
				(void)pcap_setnonblock(pcap,
#							if BROKEN_PCAP_TIMEOUT
						       		true,
#							else
								timeout == 0,
#							endif
							errbuf);
			}

			/* Now try to read packets until the timeout has been consumed.
			 */
			do {
#				if BROKEN_PCAP_TIMEOUT
					/* This only works on selected operating systems,
					 * the BSDs do not handle select on a socket, but
					 * they do implement the timeout.
					 */
					fd_set readfds;
					FD_ZERO(&readfds);
					FD_SET(file, &readfds);
				
					/* Timeout as requested by the caller. */
					struct timeval tv;
					tv.tv_sec = timeout >> 20;
					tv.tv_usec = timeout & 0xfffff;
					if (tv.tv_usec >= 1000000)
						++tv.tv_sec, tv.tv_usec = 0;

					/* See if there is anything to read... */
					do {
						int fds(select(file+1, &readfds, 0, 0, &tv));
						if (fds == 0) {
							size = 0;
							return;
						}
						if (fds != (-1))
							break;
						if (errno != EINTR)
							throw ReceiveError(errno);
					} while (1);

					/* Now there is something to read, so the
					 * pcap_next will not block.
					 */
#				endif

				const u_char*       packet;
				struct pcap_pkthdr* packet_header;
				switch(pcap_next_ex(pcap, &packet_header, &packet)) {
				case 1:  /* packet read ok */
					/* The following should never happen because
					 * this is an ethernet packet and the buffer
					 * should be big enough.
					 */
					if (packet_header->caplen < packet_header->len)
						throw std::logic_error("truncated packet");

					/* Verify the protocol and originating address of
					 * the packet, then return this packet.
					 */
					if (packet_header->caplen > 14 && (broadcast ||
						std::memcmp(packet+6, header, 6) == 0)) {
						/* Record the address and copy the data */
						std::memcpy(source, packet+6, 6);
						size_t len(packet_header->caplen - 14);
						if (len > size)
							throw std::logic_error("packet too long");
						std::memcpy(buffer, packet+14, len);
						size = len;
						return;
					}
					break;
				case 0:  /* timeout */
					if (timeout > 1<<18)
						timeout -= 1<<18;
					else
						timeout = 0;
					break;
				case -1: /* IO error */
					if (errno != EINTR)
						throw ReceiveError(errno);
					/* else try again */
					break;
				case -2: /* unexpected (savefile) */
				default:
					throw std::logic_error("pcap unexpected result");
				}
			} while (timeout != 0);

			/* Here on timeout. */
			size = 0;
			return;
		}

		/* Return the address of the last received packet.  This is
		 * an NSLU2 so the address is a 6 byte Ethernet hardware
		 * address.
		 */
		virtual void LastAddress(unsigned char address[6]) {
			std::memcpy(address, source, 6);
		}

	private:
		pcap_t* pcap;
		int     file;       /* pcap file descriptor */
		char    header[14]; /* Packet header. */
		char    source[6];  /* Source of last *received* packet. */
		bool    broadcast;
	};

	/* Class to set and reset the user id to the effective uid. */
	class EUID {
	public:
		EUID(int uid) : euid(geteuid()) {
			if (uid != -1 && seteuid(uid) != 0)
				throw WireError(errno);
		}

		~EUID() {
			seteuid(euid);
		}

	private:
		uid_t euid;
	};

};


/* Make a new wire, which may be deleted with delete.  The
 * address should be a value (null terminated this time) returned
 * by LastAddress, if NULL the Wire will broadcast.  'device'
 * is the hardware device name to use - the value of the
 * --device parameter on the command line (if given).  If not
 *  given (NULL) a potentially useless default will be used.
 */
NSLU2Upgrade::Wire *NSLU2Upgrade::Wire::MakeWire(const char *device,
		const unsigned char *address, int uid) {
	/* Check the device name.  If not given use 'eth0'. */
	if (device == NULL)
		device = "eth0";

	pcap_t *pcap = NULL;
	{
		EUID euid(uid);
		char errbuf[PCAP_ERRBUF_SIZE];
		/* Do *NOT* set promiscuous here - all manner of strangeness
		 * will result because the interfaces will capture packets destined
		 * for other ethernet MACs.  (Because the code above does not
		 * check that the destination matches the device in use).
		 */
		pcap = pcap_open_live(device, 1540, false/*promiscuous*/, 250/*ms*/, errbuf);

		if (pcap == NULL)
			throw WireError(errno);
	}

	try {
		/* libpcap has the primary purpose of slurping all the packets then
		 * filtering out interesting ones.  This is a somewhat dumb way of
		 * receiving packets from a known protocol, but this seems to be the
		 * only portable approach.  Consequently it is necessary to 'compile'
		 * a 'program' for libpcap to get the correct packets.
		 */
		{
			struct bpf_program filter_program;

			if (pcap_compile(pcap, &filter_program, "ether proto 0x8888",
					true/*optimise*/, 0/*netmask - not used*/) == -1)
				throw WireError(errno);

			try {
				if (pcap_setfilter(pcap, &filter_program) == -1)
					throw WireError(errno);
			} catch (...) {
				pcap_freecode(&filter_program);
				throw;
			}

			pcap_freecode(&filter_program);
		}

		/* This is enough to make a new wire. */
		return new PCapWire(pcap, device, address);
	} catch (...) {
		/* Error cleanup - the pcap needs to be deleted. */
		pcap_close(pcap);
		throw;
	}
}
#endif
