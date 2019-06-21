/*-
 * Copyright (C) 2010, Romain Tartiere.
 * 
 * See AUTHORS file for a more comprehensive list of contributors.
 * Additional contributors of this file:
 * Copyright (C) 2014      Joshua Wright
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 * 
 * $Id$
 */

#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <nfc/nfc.h>

#include <freefare.h>

#define AUTH_DES 0
#define AUTH_3DES 1
#define AUTH_3K3DES 2
#define AUTH_AES 3
#define AUTH_DES_KEYLEN 8
#define AUTH_3DES_KEYLEN 16
#define AUTH_3K3DES_KEYLEN 24
#define AUTH_AES_KEYLEN 16

int bruteforce_key(uint16_t aidval, uint8_t key, uint8_t authtype, MifareTag tag, char *filename)
{
	FILE *f;
	unsigned char *buffer;
	int n, filelen, res;
	size_t readlen;
        uint8_t *key_data = NULL;
        uint8_t key_len = 0;

	MifareDESFireAID aid;
	MifareDESFireKey key_guess;

        switch(authtype) {
		case AUTH_DES:
                        key_len = AUTH_DES_KEYLEN;
			break;
		case AUTH_3DES:
			key_len = AUTH_3DES_KEYLEN;
			break;
		case AUTH_3K3DES:
			key_len = AUTH_3K3DES_KEYLEN;
			break;
		case AUTH_AES:
			key_len = AUTH_AES_KEYLEN;
			break;
                default:
                        fprintf(stderr, "Invalid authentication type: %d\n", authtype);
                        return -1;
        }

	key_data = malloc(key_len);
        if (key_data == NULL) {
		fprintf(stderr, "Unable to allocate memory.\n");
                return -1;
        }

	f = fopen(filename, "rb");
	if (!f) {
		fprintf(stderr, "Unable to open file.\n");
		return -1;
	}

	fseek(f, 0L, SEEK_END);
	filelen = ftell(f);
	fseek(f, 0L, SEEK_SET);

	if (filelen < key_len) {
		fprintf(stderr, "File length too short for key material.\n");
		return -1;
	}
	buffer = malloc(filelen + 1);
	if (buffer == NULL) {
		fprintf(stderr, "Unable to allocate memory, %d bytes.\n",
			filelen + 1);
		return -1;
	}

	readlen = fread(buffer, 1, filelen, f);
	if (readlen != filelen) {
		fprintf(stderr,
			"Read len (%zu) does not match file len (%d).\n",
			readlen, filelen);
		return -1;
	}

	/* Iterate through the file contents, using each key_len byte array as a potential key */
	for (n = 0; n < filelen - (key_len - 1); n++) {
		memcpy(key_data, buffer+n, key_len);

		aid = mifare_desfire_aid_new(aidval);
		res = mifare_desfire_select_application(tag, aid);
		if (res < 0) {
			freefare_perror (tag, "mifare_desfire_select_application");
			break;
		}

		switch(authtype) {
			case AUTH_DES:
				key_guess = mifare_desfire_des_key_new (key_data);
				break;
			case AUTH_3DES:
				key_guess = mifare_desfire_3des_key_new (key_data);
				break;
			case AUTH_3K3DES:
				key_guess = mifare_desfire_3k3des_key_new (key_data);
				break;
			case AUTH_AES:
				key_guess = mifare_desfire_aes_key_new (key_data);
				break;
			default:
				fprintf(stderr, "Invalid authentication type: %d\n", authtype);
				return -1;
		}
		
		res = mifare_desfire_authenticate (tag, key, key_guess);
		if (res >= 0) {
			printf("\nAuthentication AID 0x%x with key %d returned success!\n", aidval, key);
			mifare_desfire_key_free (key_guess);
			for (int i=0; i < key_len-1; i++) {
				printf("%02x:", key_data[i]);
			}
                        printf("%02x\n",key_data[key_len-1]);
			return res;
		}


		/* Status monitor */
		if ((n % 80) == 0) {
			printf("\n");
		}
		printf(".");
		fflush(stdout);
	}

	return -1;
}

void usage(char *progname) {
	printf("usage: %s [AID] [key#] [auth type] [key search data source]\n", progname);
        printf("\nauth type is one of:\n");
        printf("\tAUTH_DES\n");
        printf("\tAUTH_3DES\n");
        printf("\tAUTH_3K3DES\n");
        printf("\tAUTH_AES\n");
	return;
}
		     

int main(int argc, char *argv[])
{
	int error = EXIT_SUCCESS;
	uint16_t aid = 0;
	uint8_t key = 0;
        uint8_t auth_type = -1;
	nfc_device *device = NULL;
	MifareTag *tags = NULL;
	char *p;

	if (argc != 5) {
		usage(argv[0]);
		return 1;
	}

	if (memcmp(argv[1], "0x", 2) == 0) {
		/* User specified AID as hex, convert appropriately */
		aid = (uint16_t) strtoul(argv[1], &p + 2, 16);
	} else {
		aid = (uint16_t) strtoul(argv[1], &p, 10);
	}

	if (errno != 0) {
		errx(EXIT_FAILURE,
		     "ERROR: Incorrect value for AID.  Specify as decimal or hex with leading 0x.");
	}

	if (sscanf(argv[2], SCNd8, &key) == EOF || (key < 0 || key > 13)) {
		errx(EXIT_FAILURE,
		     "ERROR: Incorrect value for key.  Key must be in the range 0-13.");
	}

        if (memcmp(argv[3], "AUTH_DES", 8) == 0) {
		auth_type = AUTH_DES;
	} else if (memcmp(argv[3], "AUTH_3DES", 9) == 0) {
		auth_type = AUTH_3DES;
	} else if (memcmp(argv[3], "AUTH_3K3DES", 9) == 0) {
		auth_type = AUTH_3K3DES;
	} else if (memcmp(argv[3], "AUTH_AES", 9) == 0) {
		auth_type = AUTH_AES;
	} else {
		errx(EXIT_FAILURE, "ERROR: Invalid auth type specified.");
	}

	error = 0;
	nfc_connstring devices[8];
	size_t device_count;

	nfc_context *context;
	nfc_init(&context);
	if (context == NULL)
		errx(EXIT_FAILURE, "Unable to init libnfc (malloc)");

	device_count = nfc_list_devices(context, devices, 8);
	if (device_count <= 0)
		errx(EXIT_FAILURE, "No NFC device found.");

	for (size_t d = 0; d < device_count; d++) {
		device = nfc_open(context, devices[d]);
		if (!device) {
			warnx("nfc_open() failed.");
			error = EXIT_FAILURE;
			continue;
		}

		tags = freefare_get_tags(device);
		if (!tags) {
			nfc_close(device);
			errx(EXIT_FAILURE, "Error listing tags.");
		}

		for (int i = 0; (!error) && tags[i]; i++) {
			MifareTag tag = tags[i];
			if (DESFIRE != freefare_get_tag_type(tags[i])) {
				fprintf(stderr, "Tag is not DESFIRE: %d\n", freefare_get_tag_type(tags[i]));
				continue;
			}

			int res;
			char *tag_uid = freefare_get_tag_uid(tags[i]);

			res = mifare_desfire_connect(tags[i]);
			if (res < 0) {
				warnx
				    ("Can't connect to Mifare DESFire target.");
				error = 1;
				break;
			}

			res = bruteforce_key(aid, key, auth_type, tag, argv[4]);

			free(tag_uid);

			mifare_desfire_disconnect(tags[i]);
		}

		freefare_free_tags(tags);
		nfc_close(device);
	}
	nfc_exit(context);
	exit(error);
}				/* main() */
