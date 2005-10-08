/*-
 * nslu2_image.cc
 *  Return the bytes of an NSLU2 image, constructed on the fly if
 *  necessary.
 */
#include <stdexcept>
#include <cstring>
#include <fstream>
#include <cerrno>

#include "nslu2_image.h"

namespace NSLU2Image {
	/* This code requires a complete read of the given buffer each
	 * time.
	 */
	void SafeRead(std::ifstream *stream, char *buffer, size_t length, const char *name) {
		while (length > 0) {
			if (stream->eof())
				throw NSLU2Image::FileError(SizeError, name, errno);
			stream->read(buffer, length);
			int count(stream->gcount());
			length -= count;
			buffer += count;
			if (stream->fail())
				throw FileError(ReadError, name, errno);
		}
	}

	void SafeSeek(std::ifstream *stream, int offset, const char *name) {
		stream->seekg(offset, std::ios::beg);
		if (!stream->good())
			throw NSLU2Image::FileError(SizeError, name, errno);
	}

	class RealImage : public Image {
	public:
		RealImage(bool r, const char *i) : reprogram(r) {
			image.open(i, std::ios::in | std::ios::binary);
			if (!image.good())
				throw FileError(OpenError, i, errno);
			Validate(i);
			Rewind();
		}

		virtual ~RealImage() {
		}


		/* Get the next block of bytes, returns an address and length.
		 */
		virtual void GetBytes(char *buffer, size_t buffer_length,
				int &address, int &length) {
			address = image.tellg();
			length = buffer_length;
			if (address+length > NSLU2Protocol::FlashSize)
				length = NSLU2Protocol::FlashSize-address;
			if (length > 0)
				SafeRead(&image, buffer, length, "image (read)");
		}

		/* Rewind to the start of the image (or the Kernel if not
		 * doing a complete reprogram).
		 */
		virtual void Rewind(void) {
			SafeSeek(&image, reprogram ? 0 : NSLU2Protocol::BaseAddress,
					"image (seek)");
		}

	private:
		/* Validate that this really is an image file. */
		void Validate(const char *i) {
			char signature[8];

			SafeSeek(&image, NSLU2Protocol::FlashSize-8, i);
			SafeRead(&image, signature, 8, i);
			if (memcmp(signature, "eRcOmM", 6) != 0)
				throw NSLU2Image::FileError(DataError, i, 0);
		}

		bool          reprogram;
		std::ifstream image;
	};

	class SynthesiseImage : public Image {
	public:
		SynthesiseImage(char kernel_sex, char data_sex,
			const char *k, bool noramdisk,
			const char *ram, const char *root, const char *f,
			unsigned short product_id, unsigned short protocol_id,
			unsigned short firmware_version, unsigned short extra_version);
		virtual ~SynthesiseImage() {
		}

		/* Get the next block of bytes, returns an address and length, false if
		 * there is a problem.
		 */
		virtual void GetBytes(char *buffer, size_t buffer_length,
				int &address, int &length);

		/* Rewind to the start of the image data. */
		virtual void Rewind(void) {
			flash_address = 0x60000;
		}

	private:
		/* Return the size of a file. */
		int SizeOf(std::ifstream &file) {
			if (file) {
				file.seekg(0, std::ios::end);
				const int length(file.tellg());
				if (!file.fail())
					return length;
			}
			throw FileError(ReadError, "SizeOf", errno);
		}

		typedef enum {
			RedBoot,
			SysConf,
			Kernel,
			Ramdisk,
			Flashdisk,
			FISDirectory,
		} FlashType;

		/* Write a 32 bit big endian value */
		inline void Write32BE(char *p, unsigned long v) {
			*p++ = v >> 24;
			*p++ = v >> 16;
			*p++ = v >>  8;
			*p++ = v;
		}

		/* Write a 32 bit little endian value */
		inline void Write32LE(char *p, unsigned long v) {
			*p++ = v;
			*p++ = v >>  8;
			*p++ = v >> 16;
			*p++ = v >> 24;
		}

		/* Write a 32 bit image-endian value - the actual test is on
		 * the kernel endianness, not the data endianness, because this
		 * is a value which is written into the data (byte stream) in a
		 * format the kernel is expected to recognise!
		 */
		inline void Write32IE(char *p, unsigned long v) {
			if (little_endian)
				Write32LE(p, v);
			else
				Write32BE(p, v);
		}


		inline unsigned long Read32BE(const char *p) {
			return  ((0xff & p[0]) << 24) +
				((0xff & p[1]) << 16) +
				((0xff & p[2]) <<  8) +
				((0xff & p[3])      );
		}

		inline unsigned long Read32LE(const char *p) {
			return  ((0xff & p[3]) << 24) +
				((0xff & p[2]) << 16) +
				((0xff & p[1]) <<  8) +
				((0xff & p[0])      );
		}

		/* Make a new entry - this must be called in order because it
		 * calculates the base flash address of this entry (on the next
		 * 0x20000 byte boundary) using flash_address and returns a
		 * pointer to the 36 byte data block which is constructed at the
		 * next position in the buffer.
		 *
		 * In: name of entry and actual length of data in the entry.
		 *     size of partition, or 0 to calculate from length
		 * Out: pointer to FIS directory entry (in buffer),
		 *      flash_address set to the base address of the partition
		 *      buffer_pointer advanced over new block of FIS data
		 */
		const char *MakeFISEntry(const char *name, int size, int length) {
			char *b = buffer+buffer_pointer;
			buffer_pointer += 36;

			std::memset(b, 255, 36);
			std::strcpy(b+ 0, name);

			flash_address = (flash_address + 0x1ffff) & ~0x1ffff;
			Write32IE(b+16, 0x50000000 | flash_address);
			/* b+20: Do not set memory address */
			Write32IE(b+24, size != 0 ? size : (length+0x1ffff) & ~0x1ffff);
			/* b+28: Do not set entry point */
			Write32IE(b+32, length);
			return b;
		}

		std::ifstream kernel;         /* The files, where provided */
		std::ifstream ramdisk;
		std::ifstream rootfs;
		std::ifstream payload;
		int      segment_count;  /* Count of Segment entries used */
		int      buffer_pointer; /* Index of next free slot in buffer */
		int      flash_address;  /* Current flash address */
		bool     little_endian;  /* Build a little endian image */
		bool     pdp_endian;     /* half-word, not quad-word, swap the data */
		/* The flash partitions have a data header then data from a file,
		 * represent this as an array of Segment entries, up to 2x5 for
		 * the actual partitions, 6 FIS entries (all data), a payload and
		 * the trailer - 17, allow for checksums in the future by
		 * allocating 32 entries (6 extra for checksums plus 7 spare).
		 */
		struct Segment {
			int            address;
			int            length;
			bool           swap;    /* quad byte swap */
			bool           swab;    /* two byte swap */
			const char*    data;
			std::ifstream* file;
		}         segments[32];

		/* The FIS directory consists of up to 6 entries in this implementation.
		 * Because the checksum is not currently computed each entry is a block
		 * of 36 contiguous bytes.
		 *
		 * A buffer is required for the computed FIS entries (36 bytes x 6),
		 * the trailer (16 bytes) and some bytes per partition - allow 16 (x6).
		 * This is a total of 328 bytes, 512 bytes allows for some extra data
		 * (e.g. the checksums) if required in the future.
		 */
		char buffer[512];
	};
};

/*-
 * r(reprogram) - write the whole image to flash (boot loader too)
 * i(image)     - the image to write
 *
 * Writes exactly the given image to flash (no checking!)
 */
NSLU2Image::Image *NSLU2Image::Image::MakeImage(bool reprogram, const char *image) {
	return new RealImage(reprogram, image);
}

/*-
 * kernel_sex       - byte sex of kernel (determines FIS sex)
 * data_sex         - byte sex of data (l, b or p for PDP!)
 * k(kernel)        - file containing a kernel image
 * nr(noramdisk)    - causes the image to contain a zero length ramdisk
 * ram(ramdisk)     - the ramdisk image (if nr this is just a payload)
 * root(rootfs)     - the jffs2 rootfs image
 * fis(fis_payload) - payload to follow the FIS Directory.
 *
 * Synthesises an image and writes this to flash (never overwrites the
 * boot loader).
 */
NSLU2Image::SynthesiseImage::SynthesiseImage(char kernel_sex, char data_sex,
		const char *k, bool noramdisk, const char *ram,
		const char *root, const char *f, unsigned short product_id,
		unsigned short protocol_id, unsigned short firmware_version,
		unsigned short extra_version) :
	little_endian(kernel_sex == 'l'), segment_count(0), buffer_pointer(0), flash_address(0) {
	const char *fis[8];
	bool swap(data_sex == 'l');
	bool swab(data_sex == 'p');
	/* Use open to open the files, not the constructor, because the arguments
	 * may be null, this also means that the ifstream can be used to determine
	 * whether or not the file exists.
	 *
	 * Build the FIS Directory using the sizes of the above files and knowledge
	 * of the RedBoot and SysConf partition layout.
	 */
	fis[0] = MakeFISEntry("RedBoot", 0x40000, 0x40000);
	flash_address += 0x40000;
	fis[1] = MakeFISEntry("SysConf", 0x20000, 0x20000);
	flash_address += 0x20000;
	int fis_count(2);
	if (k != 0) {
		/* The LinkSys RedBoot modifications hardwire the address of
		 * the ramdisk to 0x160000, it is sufficient for the four
		 * bytes at that address to contain 0 (then nothing will be
		 * copied), but it is difficult to arrange for this to happen
		 * (perhaps by padding the LZ stream in the kernel).  For
		 * the moment this code fixes the kernel size at 0x100000.
		 */
		kernel.open(k, std::ios::in | std::ios::binary);
		if (!kernel.good())
			throw FileError(OpenError, k, errno);
		const int s(SizeOf(kernel));
		if (s+16 > 0x100000)
			throw FileError(SizeError, k, 0);
		fis[fis_count++] = MakeFISEntry("Kernel", 0x100000, 16+s);
		Write32BE(buffer+buffer_pointer, s);
		segments[segment_count].address = flash_address;
		segments[segment_count].length = 4;
		segments[segment_count].swap = false;
		segments[segment_count].swab = false;
		segments[segment_count].data = buffer+buffer_pointer;
		segments[segment_count++].file = 0;
		buffer_pointer += 4;
		if (s > 0) {
			/* An LE kernel is written on the assumption that byte 0
			 * will end in in the LSB, but RedBoot will both write
			 * and subsequently read it as a set of BE values - byte 0
			 * goes into the MSB of the first word, so we need to
			 * quad-byte-swap
			 */
			segments[segment_count].address = flash_address+16;
			segments[segment_count].length = s;
			segments[segment_count].swap = little_endian;
			segments[segment_count].swab = false;
			segments[segment_count].data = 0;
			segments[segment_count++].file = &kernel;
		}
		flash_address += 0x100000;
	} else
		throw FileError(Required, "Kernel", 0);

	/* The Ramdisk entry must always exist, although it need only be one
	 * block in size.
	 */
	{
		int s(0);
		if (ram != 0) {
			ramdisk.open(ram, std::ios::in | std::ios::binary);
			if (!ramdisk.good())
				throw FileError(OpenError, ram, errno);
			s = SizeOf(ramdisk);
			/* The compressed ramdisk has a 16 byte header. */
			if (s+16 > NSLU2Protocol::FlashSize-flash_address-0x20000)
				throw FileError(SizeError, ram, 0);
		}
		fis[fis_count++] = MakeFISEntry("Ramdisk", 0/*calculate*/, s+16);
		Write32BE(buffer+buffer_pointer, noramdisk ? 0 : s);
		segments[segment_count].address = flash_address;
		segments[segment_count].length = 4;
		segments[segment_count].swap = false;
		segments[segment_count].swab = false;
		segments[segment_count].data = buffer+buffer_pointer;
		segments[segment_count++].file = 0;
		buffer_pointer += 4;
		flash_address += 16;
		if (s > 0) {
			/* PDP case:
			 * Data is assumed to be a simple byte stream in the
			 * correct format.  For LE RedBoot will write the first
			 * two bytes into the first 16 bit flash word with the
			 * first byte most significant.  Since the first byte
			 * should be least significant (but still in the first
			 * word) we need to double-byte-swap (swab) the data.
			 *
			 * Note that this differs from the kernel primarily because
			 * RedBoot writes (BE) but the data is then read from an
			 * LE CPU.  Because the Intel architecture treats the
			 * flash as 16 bit and does not word-swap the addresses (in
			 * fact the flash is effectively BE) we have to do 2 byte
			 * swapping.
			 *
			 * Standard case:
			 * Quad byte swap
			 */
			segments[segment_count].address = flash_address;
			segments[segment_count].length = s;
			segments[segment_count].swap = swap;
			segments[segment_count].swab = swab;
			segments[segment_count].data = 0;
			segments[segment_count++].file = &ramdisk;
			flash_address += s;
		}
	}

	/* The ffs2 rootfs is optional */
	if (root != 0) {
		rootfs.open(root, std::ios::in | std::ios::binary);
		if (!rootfs.good())
			throw FileError(OpenError, root, errno);
		const int s(SizeOf(rootfs));
		/* The partition takes all the remaining space - it doesn't have
		 * to do this, but there must be some blank space for the file
		 * system to be useable.
		 */
		flash_address = (flash_address + 0x1ffff) & ~0x1ffff;
		const int size(NSLU2Protocol::FlashSize-0x20000-flash_address);
		/*TODO: check that there is enough space for the ffs2 parition,
		 * at present this just allows 0x20000, is that enough or too much?
		 */
		if (s+0x20000 > size)
			throw FileError(SizeError, root, 0);
		fis[fis_count++] = MakeFISEntry("Flashdisk", size, s);
		/* The jffs2 Flashdisk parition has no header. */
		if (s > 0) {
			segments[segment_count].address = flash_address;
			segments[segment_count].length = s;
			segments[segment_count].swap = swap;
			segments[segment_count].swab = swab;
			segments[segment_count].data = 0;
			segments[segment_count++].file = &rootfs;
			flash_address += s;
		}
	}

	/* The FIS directory is at the end of the image. */
	flash_address = NSLU2Protocol::FlashSize-0x20000;
	fis[fis_count] = MakeFISEntry("FIS directory", 0x20000, (fis_count+1) * 256);
	for (int i(0); i<=fis_count; ++i) {
		segments[segment_count].address = flash_address;
		segments[segment_count].length = 36;
		segments[segment_count].swap = swap;
		segments[segment_count].swab = swab;
		segments[segment_count].data = fis[i];
		segments[segment_count++].file = 0;
		flash_address += 256;
	}
	if (f != 0) {
		/* The payload follows the last valid FIS directory entry, the directory
		 * is terminated by a single 255 byte (in the 'name' field), so to mark
		 * the payload output [255]dat[length] where [length] is the big endian
		 * length of the payload.
		 */
		payload.open(f, std::ios::in | std::ios::binary);
		if (!payload.good())
			throw FileError(OpenError, f, errno);
		const int s(SizeOf(payload));
		/* The payload fits after the last (valid) FIS entry - and must leave
		 * space for the 16 byte 'signature' which the NSLU2 RedBoot recognises
		 * as indicating a valid image and for the 8 byte payload header.
		 */
		if (s > 0x20000 - (fis_count+1)*256 - 16 - 8)
			throw FileError(SizeError, f, 0);

		/* The header is written even for a zero length payload. */
		segments[segment_count].address = flash_address;
		segments[segment_count].length = 8;
		segments[segment_count].swap = false;
		segments[segment_count].swab = false;
		segments[segment_count].data = buffer+buffer_pointer;
		segments[segment_count++].file = 0;
		buffer[buffer_pointer++] = 255;
		buffer[buffer_pointer++] = 'd';
		buffer[buffer_pointer++] = 'a';
		buffer[buffer_pointer++] = 't';
		Write32BE(buffer+buffer_pointer, s);
		buffer_pointer += 4;
		flash_address += 8;

		if (s > 0) {
			segments[segment_count].address = flash_address;
			segments[segment_count].length = s;
			segments[segment_count].swap = swap;
			segments[segment_count].swab = swab;
			segments[segment_count].data = 0;
			segments[segment_count++].file = &payload;
			flash_address += s;
		}
	}

	/* This is a sanity check. */
	if (flash_address > NSLU2Protocol::FlashSize-16)
		throw std::logic_error("flash address too large");
	flash_address = NSLU2Protocol::FlashSize-16;
	segments[segment_count].address = flash_address;
	segments[segment_count].length = 15;
	segments[segment_count].swap = false;
	segments[segment_count].swab = false;
	segments[segment_count].data = buffer+buffer_pointer;
	segments[segment_count++].file = 0;
	buffer[buffer_pointer++] = product_id >> 8;
	buffer[buffer_pointer++] = product_id;
	buffer[buffer_pointer++] = protocol_id >> 8;
	buffer[buffer_pointer++] = protocol_id;
	buffer[buffer_pointer++] = firmware_version >> 8;
	buffer[buffer_pointer++] = firmware_version;
	buffer[buffer_pointer++] = extra_version >> 8;
	buffer[buffer_pointer++] = extra_version;
	/* The following includes a trailing null but leaves the last byte unset. */
	std::memcpy(buffer+buffer_pointer, "eRcOmM", 7);
	buffer_pointer += 7;
	if (buffer_pointer > sizeof buffer)
		throw std::logic_error("data buffer too small");

	/* Set the flash_address local back to after SysConf to start output of the
	 * image.
	 */
	Rewind();
}

void NSLU2Image::SynthesiseImage::GetBytes(char *buffer, size_t buffer_length,
		int &address, int &length) {
	if (buffer_length & 3)
		throw std::logic_error("invalid buffer length");

	/* Just go through the list, segment by segment. */
	int i(0);
	while (i < segment_count &&
			flash_address >= segments[i].address + segments[i].length)
		++i;
	if (i < segment_count) {
		int base(segments[i].address);
		int offset(0);
		if (flash_address < base)
			flash_address = base;
		else
			offset = flash_address-base;
		if (flash_address & 3)
			throw std::logic_error("non-word-aligned flash address");

		int len(segments[i].length - offset);
		if (len > buffer_length)
			len = buffer_length;

		if (segments[i].data != 0)
			std::memcpy(buffer, segments[i].data+offset, len);
		else if (segments[i].file != 0) {
			std::ifstream *pfile = segments[i].file;
			SafeSeek(pfile, offset, "segment");
			SafeRead(pfile, buffer, len, "segment");
		} else
			throw std::logic_error("no data in segment");

		/* At this point the buffer must be padded to a word boundary if
		 * required, this is always safe because the next flash address
		 * will overwrite this data if necessary (and it won't do that
		 * because if it did the flash address itself would not be on
		 * a word boundary).
		 */
		while (len & 3)
			buffer[len++] = '\xff';

		/* At present expect only one of swab or swap. */
		if (segments[i].swab && segments[i].swap)
			throw std::logic_error("swap and swab both specified");

		/* If required quad-byte-swap this data. */
		if (segments[i].swap) for (int j(0); j+4<=len; j+=4) {
			Write32BE(buffer+j, Read32LE(buffer+j));
		}

		/* Likewise for swab */
		if (segments[i].swab) for (int j(0); j+2<=len; j+=2) {
			char tmp(buffer[0]);
			buffer[0] = buffer[1], ++buffer;
			*buffer++ = tmp;
		}

		address = flash_address;
		length = len;
		flash_address += len;
	} else {
		address = NSLU2Protocol::FlashSize;
		length = 0;
	}
}

NSLU2Image::Image *NSLU2Image::Image::MakeImage(char kernel_sex, char data_sex,
		const char *k, bool nr,
		const char *ram, const char *root, const char *fis,
		unsigned short product_id, unsigned short protocol_id,
		unsigned short firmware_version, unsigned short extra_version) {
	return new SynthesiseImage(kernel_sex, data_sex, k, nr, ram, root, fis,
			product_id, protocol_id, firmware_version, extra_version);
}
