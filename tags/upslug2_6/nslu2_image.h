/*-
 * nslu2_image.h
 *  Return the bytes of an NSLU2 image, constructed on the fly if
 *  necessary.
 */
#ifndef NSLU2_IMAGE_H
#define NSLU2_IMAGE_H 1

#include <stdexcept>

#include "nslu2_protocol.h"

namespace NSLU2Image {
	typedef enum {
		Required,   /* required file not present */
		OpenError,  /* failed to open the file (str is name) */
		SizeError,  /* file too large (str is kernel/ramdisk/rootfs/payload) */
		ReadError,  /* IO error reading from file */
		DataError,  /* Error in the data in the file (e.g. bad signature) */
	} FileErrorType;

	class FileError : public std::exception {
	public:
		inline FileError(FileErrorType t, const char *s, int err) :
			type(t), str(s), errval(err) {
		}

		FileErrorType type;
		const char *  str;
		int           errval; /* OS errno value */
	};

	class Image {
	public:
		virtual ~Image() {
		}

		/* Get the next block of bytes, returns an address and length.
		 */
		virtual void GetBytes(char *buffer, size_t buffer_length,
				int &address, int &length) = 0;

		/* Rewind to the start of the image. */
		virtual void Rewind(void) = 0;

		/*-
		 * le               - true to build a little endian image
		 * k(kernel)        - file containing a kernel image
		 * nr(noramdisk)    - causes the image to contain a zero length ramdisk
		 * ram(ramdisk)     - the ramdisk image (if nr this is just a payload)
		 * root(rootfs)     - the jffs2 rootfs image
		 * fis(fis_payload) - payload to follow the FIS Directory.
		 *
		 * Synthesises an image and writes this to flash (never overwrites the
		 * boot loader).
		 */
		static Image *MakeImage(bool le, const char *k, bool nr, const char *ram,
			const char *root, const char *fis,
			unsigned short product_id, unsigned short protocol_id,
			unsigned short firmware_version, unsigned short extra_version);

		/*-
		 * r(reprogram) - write the whole image to flash (boot loader too)
		 * i(image)     - the image to write
		 *
		 * Writes exactly the given image to flash (no checking!)
		 */
		static Image *MakeImage(bool r, const char *i);
	};
};

#endif
