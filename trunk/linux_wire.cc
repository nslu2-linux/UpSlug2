/*-
 * linux_wire.cc
 *
 * Implementation of Wire for linux, may work on other UN*X systems
 * too...
 */
#include <cstring>

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <net/ethernet.h>

#if 0
/* Including this is incompatible with including linux/if_arp.h */
#include <net/if.h>
#include <netpacket/packet.h>
#else
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#endif

#include <unistd.h>
#include <errno.h>

#include "nslu2_upgrade.h"

namespace NSLU2Upgrade {
	/* The basic class implemented to transmit and receive packets over the
	 * wire.
	 */
	class EthernetWire : public Wire {
	public:
		EthernetWire(int s, int hw_index, const unsigned char address[6]) :
			socket(s), broadcast(true) {
			/* Most of these fields aren't used in any given request,
			 * but it does no harm to fill them all correctly.
			 */
			nslu2To.sll_family = AF_PACKET;
			nslu2To.sll_protocol = NSLU2Protocol::UpgradeProtocol;
			nslu2To.sll_ifindex = hw_index;
			nslu2To.sll_hatype = ARPHRD_IEEE802;
			nslu2To.sll_pkttype = address ? PACKET_HOST : PACKET_BROADCAST;
			nslu2To.sll_halen = 6;
			/* The 255 gives the ethernet hardware broadcast address,
			 * overwrite this if a host address is provided.
			 */
			std::memset(nslu2To.sll_addr, 255, sizeof nslu2To.sll_addr);
			if (address) {
				broadcast = false;
				std::memcpy(nslu2To.sll_addr, address, 6);
			}

			/* This is set just in case of a call to LastAddress before
			 * Receive has succeeded - the result will be all 0's
			 */
			std::memset(nslu2From.sll_addr, 0, sizeof nslu2From.sll_addr);
		}

		virtual ~EthernetWire() {
			(void)close(socket);
		}

		/* Throws SendError on a fatal error. */
		virtual void Send(const void *packet, size_t length) {
			/* Set no flags (0) - we block on the sendto if
			 * required, the socket is *not* set O_NONBLOCK.
			 */
			while (sendto(socket, packet, length, 0,
					reinterpret_cast<sockaddr*>(&nslu2To),
					sizeof nslu2To) == (-1)) {
				if (errno != EINTR)
					throw SendError(errno);
			} 
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
			/* The socket is blocking (O_NONBLOCK is not set) therefore
			 * handle the 'block' option by polling.  Even if 'block'
			 * is true this call must not actually block - just
			 * time out - because the response packet we are waiting
			 * for may actually have been dropped.
			 */
			do {
				fd_set readfds;
				FD_ZERO(&readfds);
				FD_SET(socket, &readfds);
				
				/* Timeout as requested by the caller. */
				struct timeval tv;
				tv.tv_sec = timeout >> 20;
				tv.tv_usec = timeout & 0xfffff;
				if (tv.tv_usec >= 1000000)
					++tv.tv_sec, tv.tv_usec = 0;

				/* See if there is anything to read... */
				do {
					int fds(select(socket+1, &readfds, 0, 0, &tv));
					if (fds == 0) {
						size = 0;
						return;
					}
					if (fds != (-1))
						break;
					if (errno != EINTR)
						throw ReceiveError(errno);
				} while (1);

				/* There is something to read... */
				socklen_t resultSize(sizeof nslu2From);
				ssize_t result(recvfrom(socket, buffer, size, 0,
						reinterpret_cast<sockaddr*>(&nslu2From),
						&resultSize));
				if (result == (-1)) {
					if (errno != EINTR)
						throw ReceiveError(errno);
				} else if (broadcast || std::memcmp(nslu2To.sll_addr,
							nslu2From.sll_addr, 6) == 0) {
					/* otherwise this is not a packet for this
					 * program and it is just ignored.
					 */
					size = result;
					return;
				}
			} while (1);
		}

		/* Return the address of the last received packet.  This is
		 * an NSLU2 so the address is a 6 byte Ethernet hardware
		 * address.
		 */
		virtual void LastAddress(unsigned char address[6]) {
			std::memcpy(address, nslu2From.sll_addr, 6);
		}

	private:
		struct sockaddr_ll nslu2To;
		struct sockaddr_ll nslu2From;
		int                socket;
		bool               broadcast;
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
	int packet_socket;
	struct ifreq device_interface;

		{
		EUID euid(uid);
		/* Obtain a datagram low level socket using the 'invented' NSLU2
		 * protocol number.  Change to the effective user id to do
		 * this (if given).
		 */
		packet_socket = socket(PF_PACKET, SOCK_DGRAM, NSLU2Protocol::UpgradeProtocol);
		if (packet_socket == (-1))
			throw WireError(errno);

		/* Check the device name.  If not given use 'eth0'. */
		if (device == NULL)
			device = "eth0";

		/* We are using a level which requires a hardware specific address,
		 * that's because the NSLU2 doesn't (for reasons which are far from
		 * obvious) implement a standard protocol for the upgrade, therefore
		 * there is no standard way of addressing the NSLU2.  Instead we must
		 * use the hardware, which on the NSLU2 is Ethernet, and which therefore
		 * has a 6 byte 'name'.
		 *
		 * What this means is that we need to be talking on an ethernet device;
		 * there ain't no way of getting a random ethernet packet onto some
		 * other network, because there is no way of mapping the address (which
		 * is an ethernet hardware id) into an appropriate address on another
		 * network.  (NOTE: 'tunnelling' stuff does this, it wraps the whole
		 * packet up inside another packet and sends it down the tunnel, it gets
		 * unwrapped at the other end, but that is transparent to this code.)
		 * 
		 * At this point we need an ethernet device to talk to.  Notice that this
		 * could, in theory, be a fake device - just so long as the NSLU2 has a
		 * six byte ethernet address to talk back to.  We look the given device
		 * name up on the socket.  (See netdevice(7) - this is linux specific)
		 *
		 * NOTE: if you are looking at this code and trying to port it the device
		 * stuff may be irrelevant, what you need to do is receive all packets
		 * with the protocol 0x8888 (NSLU2Protocol::UpgradeProtocol) from any
		 * *ethernet* MAC to implement the broadcast stuff and from a specific
		 * ethernet MAC to implement upgrade.  The broadcast stuff isn't necessary
		 * to implement a working upslug2 - because the ethernet MAC can be
		 * determined from the label on the bottom of an NSLU2, so the user can
		 * just be obliged to turn the damn box over.  And this is a better GUI.
		 */
		strncpy(device_interface.ifr_name, device, sizeof device_interface.ifr_name);
		device_interface.ifr_name[(sizeof device_interface.ifr_name)-1] = 0;

		if (ioctl(packet_socket, SIOCGIFINDEX, &device_interface) == (-1)) {
			/* This means the device name is bogus, because if we weren't
			 * euid 0 the socket call would have EACCESed above.
			 */
			const int err(errno);
			(void)close(packet_socket);
			throw WireError(err);
		}
	}

	/* This is enough to make a new wire. */
	return new EthernetWire(packet_socket, device_interface.ifr_ifindex, address);
}
