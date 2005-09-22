/*-
 * upslug2_progress.h
 *
 *  A basic progress implementation which accumulates the information but does
 *  not output it to the user, provides virtual callbacks for a real implementation.
 *
 *  This header defines a template class which should be sub-classed to do
 *  something appropriate with the information.  The sub-class will normally
 *  implement Sent and Received by calling this the parent class (this class)
 *  implementation.
 */
#ifndef UPSLUG2_PROGRESS_H
#define UPSLUG2_PROGRESS_H 1

#include <cstring>

#include "nslu2_protocol.h"
#include "nslu2_upgrade.h"

namespace UpSlug2 {
	/* The basis of a progress bar implementation - simply keeps track of
	 * the last seen and sent addresses.
	 */
	class Progress : public NSLU2Upgrade::Progress {
	public:
		inline Progress() :
			lastType(NSLU2Protocol::InvalidType),
			addressOfLastSeen(-1), addressOfLastSent(-1)
			{
			}
		// virtual inline ~Progress() {}

		/* Return a value in the range 0..(scale-1) to indicate the
		 * proportion of packets sent (but not necessarily received
		 * by the NSLU2) or received and acknowledged.  The result
		 * is *rounded* to the given range and must not be scaled
		 * again - to get a value to a different scale just call this
		 * API a second time.
		 */
		inline unsigned int ProportionSent(unsigned int scale) const {
			if (addressOfLastSent > 0) {
				return Scale(addressOfLastSent,
						NSLU2Protocol::Ln2FlashSize, scale);
			} else
				return 0;
		}

		inline int ProportionReceived(int scale) const {
			if (addressOfLastSeen > 0)
				return Scale(addressOfLastSeen,
						NSLU2Protocol::Ln2FlashSize, scale);
			else
				return 0;
		}
				
	protected:
		int AddressOfLastSeen(void) const {
			return addressOfLastSeen;
		}

		inline int AddressOfLastSent(void) const {
			return addressOfLastSent;
		}

		static inline unsigned int Scale(unsigned long val, unsigned int shift,
				unsigned int scale) {
			while (shift > 0 && scale >= (1<<(32-shift)))
				val >>=1, --shift;
			/* This really is correctly rounded, because a result of
			 * scale-1 corresponds to 100% (i.e. 100% is scale-1,
			 * not scale...)  If you don't want to ever see the full
			 * scale result (i.e. the UI doesn't want to output the
			 * 100% setting until after everything has been confirmed
			 * as written) simply pass in range-1 instead of range.
			 */
			return (val * scale) >> shift;
		}

	protected:
		/* Sent is called whenever a packet is sent with the sequence
		 * number, address (in flash) of the data and length of the
		 * data.  If retransmission is necessary the sequence number will
		 * be re-used, the last sent valid address (and the highest) is
		 * always that in the last 'Sent' callback - i.e. lower sequence
		 * numbers/addresses invalidate earlier sends.
		 */
		virtual void Sent(NSLU2Protocol::Type type,
				int sequence, int address, int length) {
			if (type == NSLU2Protocol::UpgradeVerify &&
				lastType == NSLU2Protocol::UpgradeData) {
				/* Reset for the verify step. */
				addressOfLastSeen = -1;
			}

			lastType = type;
			addressOfLastSent = address+length-1;
		}

		/* Timeout is called when a receive timeout occurs.  Nothing is
		 * implemented for this class.
		 */
		// virtual inline void Timeout(NSLU2Protocol::Type type, int sequence);

		/* Retransmit is called when a packet must be retransmitted, the
		 * sequence number is that of the first packet to be retransmitted.
		 */
		//virtual inline void Retransmit(NSLU2Protocol::Type type, int sequence);

		/* Received is called after a packet is received and it is passed
		 * the highest sequence number received (not necessarily that of
		 * the received packet) - this is a low water mark on the flash upgrade
		 * or verify, this packet and all earlier ones (therefore all earlier
		 * addresses) have been handled on the NSLU2.
		 */
		virtual void Received(NSLU2Protocol::Type type, int sequence,
				int address, int length) {
			if (type == lastType) { /* else an old packet */
				addressOfLastSeen = address+length-1;
			}
		}

	private:
		NSLU2Protocol::Type lastType; /* type of last received packet */

		int addressOfLastSent; /* highest address sent */
		int addressOfLastSeen; /* highest address seen */
	};

	/* This is an implementation of Progress which stores enough information to
	 * display a progress bar.  Points on the progress bar indicate the state
	 * of the corresponding address in the flash.
	 *
	 * Every point on the progress bar will be in one of the enumerated states
	 * (see Status below).  What is more each state is assocated with a single
	 * range of addresses, later states may overlap (and override) states which
	 * occur earlier in the enumeration.  Consequently the progress bar can be
	 * built by asking for the low and high water mark of each state and drawing
	 * each in turn.
	 *
	 * The 'Changed' API is called when the status changes in some way - the
	 * sub-class must determine whether anything has changed enough to cause
	 * a redraw to be required.
	 */
	class ProgressBar : public Progress {
	protected:
		/* Basic typedef to return information about the state of a
		 * given address in the flash.
		 */
		typedef enum {
			Init,       /* .: address has original flash contents */
			Erase,      /* !: address is being erased */
			Erased,     /* -: address has been erased */
			Upgrade,    /* u: address is being upgraded (packet sent). */
			Upgraded,   /* U: address has been upgraded (response received). */
			Verify,     /* v: address is being verified. */
			Verified,   /* V: address has been verified (reprogramming complete). */
			Timedout,   /* *: timeout on a sent packet for this address. */
			NumberOfStates
		} Status;
		
		/* reprogram says whether this is a full reprogram (the entire
		 * flash will be erased) or not (the leading, RedBoot, SysConf
		 * partitions are not erased).
		 * resolution should be about 6 for a command line (character)
		 * progress bar and 8 for a GUI (pixel) progress bar.
		 */
		ProgressBar(bool r) :
			reprogram(r), timeout(false), retransmit(false), status(Init) {
		}

		/* lowWaterMark..(highWaterMark-1) bytes are in state 'st',
		 * unless they are also marked in a (numerically) higher state.
		 */
		void AddressByStatus(Status st, int &lowWaterMark, int &highWaterMark) {
			/* These initial settings cover the majority of cases
			 * correctly.
			 */
			lowWaterMark = reprogram ? 0 : NSLU2Protocol::BaseAddress;
			highWaterMark = status >= st ? NSLU2Protocol::FlashSize-1 : 0;
			switch (st) {
			case Init:
				/* Everything has an initial value... */
				lowWaterMark = 0;
				break;
			case Erase:
			case Erased:
				/* Set correctly above. */
				break;
			case Upgrade: case Verify:
				if (status == st)
					highWaterMark = AddressOfLastSent();
				break;
			case Upgraded: case Verified:
				/* The status class member is set to Upgrade or
				 * Verify, never to Upgraded or Verified.
				 */
				if (status == st-1)
					highWaterMark = AddressOfLastSeen();
				break;
			case Timedout:
				/* status is never set to timeout, but if there
				 * is a timeout then the 'uncertain' addresses
				 * are the ones which have been sent but not
				 * received.
				 */
				if (timeout || retransmit) {
					lowWaterMark = AddressOfLastSeen();
					highWaterMark = AddressOfLastSent();
				}
				break;
			}
		}

		/* The following must be implemented in a sub-class to do the actual
		 * display.
		 */
		virtual void Changed(void) = 0;

		virtual void Sent(NSLU2Protocol::Type type,
				int sequence, int address, int length) {
			int old(AddressOfLastSent());

			Progress::Sent(type, sequence, address, length);

			bool changed(old != AddressOfLastSent());
			if (status == Init && type == NSLU2Protocol::UpgradeData)
				changed = true, status = Erase;

			if (changed)
				Changed();
		}

		virtual void Timeout(NSLU2Protocol::Type type, int sequence) {
			if (!timeout) {
				timeout = true;
				Changed();
			}
		}

		virtual void Retransmit(NSLU2Protocol::Type type, int sequence,
				int sequenceError) {
			if (!retransmit) {
				retransmit = true;
				Changed();
			}
		}

		virtual void Received(NSLU2Protocol::Type type, int sequence,
				int address, int length) {
			int old(AddressOfLastSeen());

			Progress::Received(type, sequence, address, length);

			bool changed(old != AddressOfLastSeen());
			if (timeout || retransmit)
				changed = true, timeout = false, retransmit = false;
			if (type == NSLU2Protocol::UpgradeVerify) {
				if (status != Verify)
					changed = true, status = Verify;
			} else if (type == NSLU2Protocol::UpgradeData) {
				if (status != Upgrade)
					changed = true, status = Upgrade;
			} else
				return;

			if (changed)
				Changed();
		}

	private:
		Status status;        /* Overall status */
	protected:
		bool   reprogram;
		bool   timeout;       /* Timeout recorded */
		bool   retransmit;    /* Retransmit recorded */
	};


	/* This is an implementation of ProgressBar for the command line, the
	 * initialiser must be passed the actual of characters in the output
	 * display, the template parameter is the maximum this can be!
	 */
	template <int characters> class CharacterProgressBar : public ProgressBar {
	public:
		CharacterProgressBar(bool reprogram, int n, const char ind[NumberOfStates] = 0) :
			numberOfCharacters(n > characters || n < 1 ? characters : n),
			ProgressBar(reprogram) {
			if (ind)
				std::memcpy(indicators, ind, NumberOfStates);
			else
				std::memcpy(indicators, ".!-uUvV*", NumberOfStates);
			std::memset(display, 0, sizeof display);
		}

		/* Implement this to update the display, the display argument is
		 * the new character array (null terminated), the values are the
		 * indices of the first and last change.
		 */
		virtual void UpdateDisplay(const char *display,
				int firstChanged, int lastChanged) = 0;

	protected:
		/* Return the progress indicator character for a given state. */
		inline char Indicator(Status st) const {
			return indicators[st];
		}

		/* Callback from ancestor class to indicate a state change - this
		 * won't necessarily change the display.
		 */
		virtual void Changed(void) {
			char oldDisplay[characters];
			std::memcpy(oldDisplay, display, characters);
			for (Status st(Init); st < NumberOfStates; st = static_cast<Status>(st+1)) {
				int lowWaterMark, highWaterMark;
				AddressByStatus(st, lowWaterMark, highWaterMark);
				if (highWaterMark > lowWaterMark) {
					lowWaterMark = Scale(lowWaterMark,
						NSLU2Protocol::Ln2FlashSize, numberOfCharacters);
					/* For things like Upgrade and Verify use the basic
					 * scaling which returns 0..(numberOfCharacters-1)
					 * and evenly distributes the values 0..(flashsize-1)
					 * addresses between those values - flashsize/nochar
					 * in each slot.
					 *
					 * For Upgraded and Verified (etc) only fill value
					 * n when all the flashsize/nochar addresses for
					 * that slot have been filled.
					 */
					if (st & 1) /* 'in progress' status */
						highWaterMark = Scale(highWaterMark,
							NSLU2Protocol::Ln2FlashSize,
							numberOfCharacters);
					else        /* 'done' status */
						highWaterMark = Scale(highWaterMark+1,
							NSLU2Protocol::Ln2FlashSize,
							numberOfCharacters)-1;

					while (lowWaterMark <= highWaterMark)
						display[lowWaterMark++] = indicators[st];
				}
			}

			int firstChanged(characters), lastChanged(0);
			for (int i(0); i<numberOfCharacters; ++i)
				if (oldDisplay[i] != display[i]) {
					if (i < firstChanged)
						firstChanged = i;
					lastChanged = i;
				}
			if (firstChanged <= lastChanged || retransmit || timeout)
				UpdateDisplay(display, firstChanged, lastChanged);
		}

	private:
		int  numberOfCharacters;
		char indicators[NumberOfStates];
		char display[characters+1];
	};
};

#endif
