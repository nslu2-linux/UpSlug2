/*-
 * pcap_wire.cc
 *
 * Implementation of Wire for libpcap
 */
#include "config.h"

#if HAVE_LIBPCAP
#include <cstring>
#include <stdexcept>
#include <cerrno>

#include <sys/types.h>  /* Required for class EUID */

#if HAVE_GETIFADDRS
#	include <sys/socket.h>
#endif

#include <sys/time.h>
#include <sys/select.h>

/* Ways of finding the hardware MAC on this machine... */
/* This is the Linux only fallback. */
#ifdef SIOCGIFHWADDR
#	include <sys/ioctl.h>
#	include <net/if.h>
#endif

#if HAVE_GETIFADDRS
#	include <ifaddrs.h>
#endif

/* Now the struct sockaddr header files for the required protocol
 * families.  Expect either AF_LINK (BSDs) or AF_PACKET(Linux), or
 * maybe both to be returned from getifaddrs.
 */
#ifdef AF_LINK
#	include <net/if_dl.h>
#endif
#ifdef AF_PACKET
#	include <netpacket/packet.h>
#endif

#include <unistd.h>

#include <pcap.h>

#include "nslu2_upgrade.h"

namespace NSLU2Upgrade {
	/* The basic class implemented to transmit and receive packets over the
	 * wire.
	 */
	class PCapWire : public Wire {
	public:
		PCapWire(pcap_t *p, const char *device, const unsigned char *mac,
				const unsigned char address[6]) :
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

			/* And copy the MAC address into the header. */
			std::memcpy(header+6, mac, 6);
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
#				if HAVE_PCAP_INJECT
					const ssize_t written(pcap_inject(pcap, data, len));
#				else
					const ssize_t written(write(file, data, len));
#				endif
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

		/* This is a pcap_handler implementation, the static callback passed
		 * to pcap_dispatch derives the original 'this' pointer and calls the
		 * non-static (real) Handler.
		 */
		void Handler(const struct pcap_pkthdr *packet_header, const u_char *packet) {
			/* This should only be called once... */
			if (captured)
				throw std::logic_error("Handler called twice");

			/* Verify the protocol and originating address of the packet, then
			 * return this packet.
			 */
			if (packet_header->caplen > 14 && (broadcast ||
				std::memcmp(packet+6, header, 6) == 0)) {
				/* Record the address and copy the data */
				std::memcpy(source, packet+6, 6);
				const size_t len(packet_header->caplen - 14);
				if (len > captureSize)
					throw std::logic_error("packet too long");
				std::memcpy(captureBuffer, packet+14, len);
				captureSize = len;
				captured = true;
			}
		}

		static void PCapHandler(u_char *user, const struct pcap_pkthdr *packet_header,
				const u_char *packet) {
			/* The following should never happen because this is an ethernet
			 * packet and the buffer should be big enough.
			 */
			if (packet_header->caplen < packet_header->len)
				throw std::logic_error("truncated packet");

			/*IGNORE EVIL: known evil cast */
			reinterpret_cast<PCapWire*>(user)->Handler(packet_header, packet);
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
			/* Now try to read packets until the timeout has been consumed.
			 */
			struct timeval tvStart;
			if (timeout > 0 && gettimeofday(&tvStart, 0) != 0)
				throw OSError(errno, "gettimeofday(base)");

			captureBuffer = buffer;
			captureSize = size;
			captured = false;
			do {
				/*IGNORE EVIL: known evil cast */
				int count(pcap_dispatch(pcap, 1, PCapHandler,
							reinterpret_cast<u_char*>(this)));

				if (count > 0) {
					/* Were any packets handled? */
					if (captured) {
						size = captureSize;
						return;
					}
					/* else try again. */
				} else if (count == 0) {
					/* Nothing to handle - do the timeout, do this
					 * by waiting a bit then trying again, the trick
					 * to this is to work out how long to wait each
					 * time, for the moment a 10ms delay is used.
					 */
					if (timeout == 0)
						break;

					struct timeval tvNow;
					if (gettimeofday(&tvNow, 0) != 0)
						throw OSError(errno, "gettimeofday(now)");

					unsigned long t(tvNow.tv_sec - tvStart.tv_sec);
					t *= 1000000;
					t += tvNow.tv_usec;
					t -= tvStart.tv_usec;
					if (t > timeout)
						break;

					tvNow.tv_sec = 0;
					tvNow.tv_usec = timeout-t;
					if (tvNow.tv_usec > 10000)
						tvNow.tv_usec = 10000;

					/* Delay, may be interrupted - this should
					 * be portable to the BSDs (since the
					 * technique originates in BSD.)
					 */
					(void)select(0, 0, 0, 0, &tvNow);
				} else {
					/* Error condition. */
					if (count == -1) {
						if (errno != EINTR)
							throw ReceiveError(errno,
									pcap_geterr(pcap));
						/* else try again */
					} else
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
		void*   captureBuffer; /* Buffer to be filled in by Handler */
		size_t  captureSize;   /* Filled in by Handler - bytes in buffer */
		pcap_t* pcap;
		int     file;           /* pcap file descriptor */
		char    header[14];     /* Packet header. */
		char    source[6];      /* Source of last *received* packet. */
		bool    broadcast;
		bool    captured;       /* Whether Handler was called */
	};

	/* Class to set and reset the user id to the effective uid. */
	class EUID {
	public:
		EUID(int uid) : euid(::geteuid()) {
			if (uid != -1 && ::seteuid(uid) != 0)
				throw WireError(errno);
		}

		~EUID() {
			::seteuid(euid);
		}

	private:
		::uid_t euid;
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
		const unsigned char *mac, const unsigned char *address, int uid) {
	/* This is used to store the error passed to throw. */
	static char PCapErrbuf[PCAP_ERRBUF_SIZE];

	/* Check the device name.  If not given use 'DEFAULT_ETHERNET_IF'. */
	if (device == NULL)
		device = DEFAULT_ETHERNET_IF;

	pcap_t *pcap = NULL;
	{
		EUID euid(uid);
		/* Do *NOT* set promiscuous here - all manner of strangeness
		 * will result because the interfaces will capture packets destined
		 * for other ethernet MACs.  (Because the code above does not
		 * check that the destination matches the device in use).
		 */
		pcap = pcap_open_live(device, 1540, false/*promiscuous*/, 1/*ms*/, PCapErrbuf);

		if (pcap == NULL)
			throw WireError(errno, PCapErrbuf);
	}

	/* Always do a non-blocking read, because the 'timeout' above
	 * doesn't work on Linux (return is immediate) and on OSX (and
	 * maybe other BSDs) the interface tends to hang waiting for
	 * the timeout to expire even after receiving a single packet.
	 */
	if (pcap_setnonblock(pcap, true, PCapErrbuf))
		throw WireError(errno, PCapErrbuf);

	try {
		/* The MAC of the transmitting device is needed - without
		 * this the return packet won't go to the right place!
		 */
		unsigned char macBuffer[6];
		std::memset(macBuffer, 0, sizeof macBuffer);

		/* If the MAC is not given (the normal case) use getifaddrs to find
		 * the MAC of the named device.  getifaddrs is the standard BSD
		 * interface, but it seems to exist on Linux too (anyway, this Wire
		 * implementation should probably not be used on Linux!)
		 */
#		if HAVE_GETIFADDRS
			if (mac == NULL) {
				struct ifaddrs *ifap;

				if (getifaddrs(&ifap) != 0)
					throw WireError(errno, "getifaddrs failed");

				try {
					struct ifaddrs *ifa = ifap;
					do {
						if (ifa == NULL)
							break;

#						ifdef AF_LINK
							if (ifa->ifa_addr->sa_family == AF_LINK &&
								strcmp(ifa->ifa_name, device) == 0) {
								const struct sockaddr_dl *sdl =
									reinterpret_cast<struct sockaddr_dl*>(ifa->ifa_addr);
								std::memcpy(macBuffer, LLADDR(sdl), 6);
								mac = macBuffer;
								break;
							}
#						endif
#						ifdef AF_PACKET
							if (ifa->ifa_addr->sa_family == AF_PACKET &&
								strcmp(ifa->ifa_name, device) == 0) {
								const struct sockaddr_ll *sll =
									reinterpret_cast<struct sockaddr_ll*>(ifa->ifa_addr);
								std::memcpy(macBuffer, sll->sll_addr, 6);
								mac = macBuffer;
								break;
							}
#						endif

						ifa = ifa->ifa_next;
					} while (1);
				} catch (...) {
					freeifaddrs(ifap);
					throw;
				}

				freeifaddrs(ifap);
			}
#		endif
#		ifdef SIOCGIFHWADDR
			/* This is a fallback which currently is only know to work
			 * on Linux.
			 */
			if (mac == NULL) {
				struct ifreq device_interface;

				strncpy(device_interface.ifr_name, device,
						sizeof device_interface.ifr_name);
				device_interface.ifr_name[(sizeof device_interface.ifr_name)-1] = 0;

				/* Get the hardware information. */
				if (ioctl(pcap_fileno(pcap), SIOCGIFHWADDR, &device_interface) == (-1))
					throw WireError(errno);

				std::memcpy(macBuffer, device_interface.ifr_hwaddr.sa_data, 6);
				mac = macBuffer;
			}
#		endif

		if (mac == NULL)
			throw WireError(ENOENT, "no link-level interface to provide hardware MAC");

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
		return new PCapWire(pcap, device, mac, address);
	} catch (...) {
		/* Error cleanup - the pcap needs to be deleted. */
		pcap_close(pcap);
		throw;
	}
}
#endif
