/*-
 * upslug2.cc
 *
 * The upslug2 main program for the command line implementation.
 */
#include <cstdio>
#include <cstring>
#include <cstdlib>

#include <unistd.h>
#include <sys/types.h>   /* For getuid/euid */

#include <getopt.h>      /* For getopt */

#include "nslu2_upgrade.h"
#include "nslu2_image.h"
#include "upslug2_progress.h"

class ProgressBar : public UpSlug2::CharacterProgressBar<80> {
public:
	ProgressBar(bool reprogram, const unsigned char *t) :
		UpSlug2::CharacterProgressBar<80>(reprogram, 64),
		target(t), displayed(false) {
	}

	virtual ~ProgressBar() {
		EndDisplay();
	}

	inline void FirstDisplay(void) {
		std::fprintf(stderr,
			"Upgrading LKG%2.2X%2.2X%2.2X %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x\n"
			"    %c original flash contents  %c packet timed out\n"
			"    %c being erased             %c erased\n"
			"    %c being upgraded           %c upgraded\n"
			"    %c being verified           %c verified \n\n"
			"  Display:\n"
			"    <status> <address completed>+<bytes transmitted but not completed>\n"
			"  Status:\n"
			"    * timeout occured          + sequence error detected\n\n",
			target[3], target[4], target[5],
			target[0], target[1], target[2], target[3], target[4], target[5],
			Indicator(UpSlug2::ProgressBar::Init),
			Indicator(UpSlug2::ProgressBar::Timedout),
			Indicator(UpSlug2::ProgressBar::Erase),
			Indicator(UpSlug2::ProgressBar::Erased),
			Indicator(UpSlug2::ProgressBar::Upgrade),
			Indicator(UpSlug2::ProgressBar::Upgraded),
			Indicator(UpSlug2::ProgressBar::Verify),
			Indicator(UpSlug2::ProgressBar::Verified));
		Changed();
	}

	inline void EndDisplay(void) {
		if (displayed) {
			displayed = false;
			std::fprintf(stderr, "\n");
		}
	}

private:
	void UpdateDisplay(const char *display, int firstChanged, int lastChanged) {
		/* Initially the seen and sent addresses are set to 0xffffffff,
		 * handle this here.
		 */
		int seen(AddressOfLastSeen());
		int sent(AddressOfLastSent());
		if (sent == -1)
			seen = sent = 0;
		else if (seen == -1) {
			/* sent something but not received anything yet, skip the
			 * RedBoot and SysConf stuff unless reprogramming.
			 */
			seen = 0;
			if (!reprogram)
				sent -= NSLU2Protocol::BaseAddress;
		} else
			sent -= seen;
		displayed = true;
		std::fprintf(stderr, "\r%c %6x+%6.6x %s",
			timeout ? '*' : (retransmit ? '+' : ' '), seen, sent, display);
		std::fflush(stderr);
	}

	bool                 displayed;
	const unsigned char *target;
};

/* Yucky template class to get a destructor for all the pointers.
 * This should be in the standard library...
 */
template <class T> class Pointer {
public:
	Pointer(T *ptr) : p(ptr) {
	}
	~Pointer() {
		if (p)
			delete p;
	}
	T* p;
};

const char *FileErrorStr(NSLU2Image::FileErrorType type) {
	switch (type) {
	case NSLU2Image::Required:   /* required file not present */
		return "required file not given";
	case NSLU2Image::OpenError:  /* failed to open the file (str is name) */
		return "failed to open file";
	case NSLU2Image::SizeError:  /* file too large (str is kernel/ramdisk/rootfs/payload) */
		return "file too large or too small";
	case NSLU2Image::ReadError:  /* IO error reading from file */
		return "failed while reading data from file";
	case NSLU2Image::DataError:  /* Error in the data in the file (e.g. bad signature) */
		return "invalid file (e.g. bad signature)";
	default:
		return "unknown error (bug in upslug2)";
	}
}

void Upgrade(NSLU2Upgrade::DoUpgrade *upgrade, NSLU2Image::Image *image,
		bool no_upgrade, bool no_verify) {
	/* Upgrade the flash. */
	if (!no_upgrade) {
		image->Rewind();
		int address, length;
		do {
			char buffer[NSLU2Protocol::MaxDataLength * 8];
			image->GetBytes(buffer, sizeof buffer, address, length);
			if (length > 0)
				upgrade->Upgrade(address, length, buffer);
		} while (length > 0);
	}

	/* Verify the result. */
	if (!no_verify) {
		image->Rewind();
		int address, length;
		do {
			char buffer[NSLU2Protocol::MaxDataLength * 8];
			image->GetBytes(buffer, sizeof buffer, address, length);
			if (length > 0)
				upgrade->Verify(address, length, buffer);
		} while (length > 0);
	}

	/* Ensure that all packets are written successfully. */
	upgrade->Finish();
}

void Reboot(NSLU2Upgrade::DoUpgrade *upgrade, bool no_reboot) {
	if (!no_reboot) {
		/* Reboot the NSLU2 */
		std::fprintf(stderr, "Rebooting...");
		std::fflush(stderr);
		upgrade->Reboot();
		std::fprintf(stderr, " done\n");
	}
}

void help(struct option *options) {
	std::fprintf(stderr, "upslug2: usage: upslug2 {options}\n options:\n");
	while (options->name) {
		std::fprintf(stderr, "  -%c --%s\n", options->val, options->name);
		++options;
	}
	std::fprintf(stderr, "\n"
" Specify --target to upgrade an NSLU2 (or to verify a previous upgrade)\n"
" without --target upslug2 will list the NSLU2 machines which are currently\n"
" in upgrade mode (and do nothing else)."
"\n"
" Specify --image=<file> if a complete NSLU2 flash image is available, if\n"
" --Complete-reprogram is specified the whole flash image will be overwritten\n"
" (the NSLU2 may become permanently unuseable if this is done), otherwise the\n"
" RedBoot boot loader and currently 'SysConf' configuration is not changed.\n"
"\n"
" Alternatively specify --kernel and --rootfs to build the image which will be\n"
" used to upgrade the NSLU2.  In this case --product-id, --protocol-id and\n"
" --firmware-version should be specified to set these fields in the flash image.\n");
	std::exit(1);
}

unsigned char readhex(const char *arg, const char *p) {
	switch (*p) {
	case '0': return 0;
	case '1': return 1;
	case '2': return 2;
	case '3': return 3;
	case '4': return 4;
	case '5': return 5;
	case '6': return 6;
	case '7': return 7;
	case '8': return 8;
	case '9': return 9;
	case 'A': case 'a': return 0xA;
	case 'B': case 'b': return 0xB;
	case 'C': case 'c': return 0xC;
	case 'D': case 'd': return 0xD;
	case 'E': case 'e': return 0xE;
	case 'F': case 'f': return 0xF;
	case 0:
		std::fprintf(stderr, "%s: argument too short (expected hex digit)\n", arg);
		std::exit(1);
	default:
		std::fprintf(stderr, "%s: invalid hex digit %c in number\n", arg, *p);
		std::exit(1);
	}
}

unsigned char readbyte(const char *arg, const char *p) {
	return (readhex(arg, p) << 4) + readhex(arg, p+1);
}

/* Read a complete MAC address, either as an NSLU2 serial number;
 * a : separated 6 byte address.
 */
void parse_mac(unsigned char macBuffer[6], const char *arg) {
	/* The argument must be xx:xx:xx:xx:xx:xx */
	{
		int i(0);
		const char *ap = arg;
		do {
			macBuffer[i] = readbyte(arg, ap);
			ap += 2;
			if (++i == 6)
				break;
			if (*ap++ != ':') {
				std::fprintf(stderr, "%s: invalid MAC address\n", arg);
				std::exit(1);
			}
		} while (1);
		if (*ap) {
			std::fprintf(stderr, "%s: invalid MAC address (too long)\n", arg);
			std::exit(1);
		}
	}
}

/* Read a 2 byte hex number - range check it to ensure that it will
 * fit in 16 bits.
 */
unsigned short parse_number(const char *arg) {
	char *endp;
	unsigned long int n(std::strtoul(arg, &endp, 0));
	if (endp == arg || *endp != 0) {
		std::fprintf(stderr, "%s: not a valid number\n", arg);
		std::exit(1);
	}
	if (n > 0xffff) {
		std::fprintf(stderr, "%s: number too large\n", arg);
		std::exit(1);
	}
	return n;
}

int main(int argc, char **argv) {
	/* The effective uid is stored for later use and reset for the moment
	 * to the real user id.
	 */
	uid_t euid(::geteuid());
	::seteuid(::getuid());

	bool                reprogram(false);     /* Reprogram the whole flash. */
	bool                no_upgrade(false);    /* Do not upgrade, just verify */
	bool                no_verify(false);     /* Do not verify, just upgrade */
	bool                no_reboot(false);     /* Do not reboot after upgrade or verify */
	char                kernel_sex('b');      /* Byte sex of kernel */
	char                data_sex('b');        /* Byte sex of data */
	const char*         device = "eth0";      /* Hardware device to use */
	const char*         target = "broadcast"; /* User specified target name */
	const unsigned char*mac = 0;              /* Ethernet address to upgrade. */
	unsigned char       macBuffer[6];         /* To store the command line address */

	/* The ID fields are defaulted here, these defaults are taken from
	 * the NSLU2 V23R29 flash image.
	 */
	unsigned short product_id(1);
	unsigned short protocol_id(0);
	unsigned short firmware_version(0x2329);
	unsigned short extra_version(0x90f7);

	/* Input files. */
	const char*    full_image = 0;
	const char*    kernel = 0;
	const char*    ram_payload = 0;
	const char*    ram_disk = 0;
	const char*    rootfs = 0;
	const char*    fis_payload = 0;

	/* The list of options, I combine the help text with the option name. */
	struct option options[] = {
{ "help:                     output this help message",         no_argument,       0, 'h' },
{ "device[eth0]:             local ethernet device to use",     required_argument, 0, 'd' },
{ "target:                   NSLU2 to upgrade (MAC address)",   required_argument, 0, 't' },
{ "verify:                   verify only (do not write flash)", no_argument,       0, 'v' },
{ "no-verify:                upgrade only (do not verify)",     no_argument,       0, 'U' },
{ "no-reboot:                do not reboot after upgrade",      no_argument,       0, 'n' },
{ "image:                    complete flash image to use",      required_argument, 0, 'i' },
{ "Complete-reprogram:       overwrite RedBoot",                no_argument,       0, 'C' },
{ "kernel:                   compressed kernel image (zImage)", required_argument, 0, 'k' },
{ "ramdisk:                  compressed ramdisk image (rootfs)",required_argument, 0, 'r' },
{ "ram-payload:              payload (replaces ramdisk)",       required_argument, 0, 'R' },
{ "rootfs:                   jffs2 (flash) rootfs",             required_argument, 0, 'j' },
{ "payload:                  FIS directory payload",            required_argument, 0, 'p' },
{ "little-endian:            little endian kernel and data",    no_argument,       0, 'l' },
{ "pdp-endian:               little endian kernel, PDP data",   no_argument,       0, 'L' },
{ "little-big:               little endian kernel, big data",   no_argument,       0, 'B' },
{ "product-id[1]:            2 byte product id",                required_argument, 0, 'P' },
{ "protocol-id[0]:           2 byte protocol id",               required_argument, 0, 'T' },
{ "firmware-version[0x2329]: 2 byte firmware version",          required_argument, 0, 'F' },
{ "extra-version[0x90f7]:    2 byte extra version info",        required_argument, 0, 'E' },
{ 0,                                                            0,                 0,  0  }
	};

	do switch (getopt_long(argc, argv, "hlLBd:t:vUni:Ck:r:R:j:p:P:T:F:E:", options, 0)) {
	case  -1: if (optind < argc) {
			  std::fprintf(stderr, "%s: unrecognised option\n", argv[optind]);
			  std::exit(1);
		  }
		  goto done;
	case ':':
	case '?': std::exit(1);
	case 'h': help(options); std::exit(1);
	case 'l': kernel_sex = 'l'; data_sex = 'l'; break;
	case 'L': kernel_sex = 'l'; data_sex = 'p'; break;
	case 'B': kernel_sex = 'l'; data_sex = 'b'; break;
	case 'd': device = optarg; break;
	case 't': target = optarg; parse_mac(macBuffer, target); mac = macBuffer; break;
	case 'v': no_verify = false; no_upgrade = true; break;
	case 'U': no_verify = true; no_upgrade = false; break;
	case 'n': no_reboot = true; break;
	case 'i': full_image = optarg; break;
	case 'C': reprogram = true; break;
	case 'k': kernel = optarg; break;
	case 'r': ram_disk = optarg; ram_payload = 0; break;
	case 'R': ram_disk = 0; ram_payload = optarg; break;
	case 'j': rootfs = optarg; break;
	case 'p': fis_payload = optarg;
	case 'P': product_id = parse_number(optarg); break;
	case 'T': protocol_id = parse_number(optarg); break;
	case 'F': firmware_version = parse_number(optarg); break;
	case 'E': extra_version = parse_number(optarg); break;
	} while (1);
done:
	if (reprogram) {
		/* IF you want to test this remove these lines, at your own risk. */
		std::fprintf(stderr, "--Complete-reprogram: this option is disabled\n");
		std::exit(1);
	}

	try {
		if (mac) {
			Pointer<NSLU2Upgrade::Wire> wire(NSLU2Upgrade::Wire::MakeWire(device, mac, euid));
			ProgressBar progress(reprogram, mac);

			if (full_image) { /* complete image. */
				/* The full image case allows a complete reprogram. */
				Pointer<NSLU2Image::Image> image(
						NSLU2Image::Image::MakeImage(
							reprogram, full_image));
				Pointer<NSLU2Upgrade::DoUpgrade> upgrade(
					NSLU2Upgrade::DoUpgrade::MakeDoUpgrade(
						wire.p, &progress, reprogram));
				progress.FirstDisplay();
				Upgrade(upgrade.p, image.p, no_upgrade, no_verify);
				progress.EndDisplay();
				Reboot(upgrade.p, no_reboot);
			} else {          /* synthesise image */
				/* At this time the synthesised image cannot be used
				 * to do a reprogram.
				 */
				Pointer<NSLU2Image::Image> image(
						NSLU2Image::Image::MakeImage(
							kernel_sex, data_sex,
							kernel,
							ram_payload != 0, /* noramdisk */
							ram_payload ? ram_payload : ram_disk,
							rootfs,
							fis_payload,
							product_id, protocol_id,
							firmware_version, extra_version));
				Pointer<NSLU2Upgrade::DoUpgrade> upgrade(
					NSLU2Upgrade::DoUpgrade::MakeDoUpgrade(
						wire.p, &progress, false));
				progress.FirstDisplay();
				Upgrade(upgrade.p, image.p, no_upgrade, no_verify);
				progress.EndDisplay();
				Reboot(upgrade.p, no_reboot);
			}
		} else {
			Pointer<NSLU2Upgrade::Wire> wire(NSLU2Upgrade::Wire::MakeWire(device, 0, euid));
			Pointer<NSLU2Upgrade::GetHardwareInfo> ghi(
					NSLU2Upgrade::GetHardwareInfo::MakeGetHardwareInfo(
						wire.p, 0x1234));
			unsigned short product_id;
			unsigned short protocol_id;
			unsigned short firmware_version;
			bool found_one(false);
			while (ghi.p->Next(product_id, protocol_id, firmware_version)) {
				unsigned char address[6];
				wire.p->LastAddress(address);
				/* I find stdio easier to use that cout, so... */
				if (address[0] == 0x00 && address[1] == 0x0f &&
						address[2] == 0x66) {
					std::printf(
		"LKG%2.2X%2.2X%2.2X %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x Product ID: %d Protocol ID:%d Firmware Version: R%2.2XV%2.2X [0x%4.4X]\n",
		address[3], address[4], address[5],
		address[0], address[1], address[2], address[3], address[4], address[5],
		product_id, protocol_id, firmware_version >> 8, firmware_version & 0xff,
		firmware_version);
					found_one = true;
				} else {
					/* the ethernet doesn't conform to the
					 * expected sequence of numbers.
					 */
					std::printf(
		"not-NSLU2 %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x Product ID: %d Protocol ID: %d Firmware Version: R%2.2XV%2.2X [0x%4.4X]\n",
		address[0], address[1], address[2], address[3], address[4], address[5],
		product_id, protocol_id, firmware_version >> 8, firmware_version & 0xff,
		firmware_version);
				}
			}

			if (!found_one)
				std::printf("[no NSLU2 machines found in upgrade mode]\n");
		}
	} catch (NSLU2Upgrade::FlashError e) {
		switch (e.returnCode) {
		case NSLU2Protocol::ProtocolError:
			std::fprintf(stderr,
				"%s: upgrade protocol error [%s]\n", target, e.what());
			std::fprintf(stderr,
				" Either this is a bug in upslug2 or the upgrade failed because\n"
				" because the start packet was lost, in the latter case it is\n"
				" sufficient to simply restart the upgrade.\n");
			break;
		case NSLU2Protocol::ProgramError:
			std::fprintf(stderr,
				"%s: flash programming error [%s]\n", target, e.what());
			std::fprintf(stderr,
				" The NSLU2 reported an error reprogramming the flash, this is\n"
				" potentially a serious hardware problem, however it is probably\n"
				" worth while retrying the upgrade to see if the problem is\n"
				" temporary.\n");
			break;
		case NSLU2Protocol::VerifyError:
			std::fprintf(stderr,
				"%s: flash verification error (address 0x%X, length %d) [%s]\n",
				target, e.address, e.length, e.what());
			std::fprintf(stderr,
				" The verification step failed, the flash has not been written\n"
				" correctly (or maybe there is a bug in upslug2).  Try repeating\n"
				" the verification step and, if that fails for the same reason,\n"
				" try repeating the whole upgrade.\n");
			break;
		default:
			std::fprintf(stderr,
				"FlashError(%d): internal programming error (bad return code)\n",
				e.returnCode);
			break;
		}
		std::exit(3);
	} catch (NSLU2Upgrade::SequenceError e) {
		std::fprintf(stderr,
			"%s: upgrade packet out of sequence [%8.8x<=xxxx%4.4x<=%8.8x] [%s]\n",
			target, e.lastSeen, e.sequenceError, e.lastSent, e.what());
		std::exit(1);
	} catch (NSLU2Upgrade::AddressError e) {
		std::fprintf(stderr,
			"%s: flash address invalid [0x%6.6x,0x%x] [%s]\n",
			target, e.address, e.length, e.what());
		std::exit(1);
	} catch (NSLU2Image::FileError e) {
		std::fprintf(stderr, "%s: %s: %s [%s]\n", e.str, FileErrorStr(e.type),
				e.errval ? std::strerror(e.errval) : "fatal error", e.what());
		std::exit(1);
	} catch (NSLU2Upgrade::WireError e) {
		std::fprintf(stderr, "%s: %s: error using device [%s]\n",
				device, std::strerror(e.errval), e.what());
		std::exit(1);
	} catch (NSLU2Upgrade::SendError e) {
		std::fprintf(stderr, "%s: %s: transmit error [%s]\n",
				target, std::strerror(e.errval), e.what());
		std::exit(1);
	} catch (NSLU2Upgrade::ReceiveError e) {
		std::fprintf(stderr, "%s: %s: receive error [%s]\n",
				target, std::strerror(e.errval), e.what());
		std::exit(1);
	} catch (NSLU2Upgrade::OSError e) {
		std::fprintf(stderr, "%s,%s: %s: system error [%s]\n",
				device, target, std::strerror(e.errval), e.what());
		std::exit(1);
	} catch (std::logic_error e) {
		std::fprintf(stderr, "internal error (bug) [%s]\n", e.what());
		std::exit(1);
	} catch (std::exception e) {
		std::fprintf(stderr, "internal error [%s]\n", e.what());
		throw e;
	}

	return 0;
}
