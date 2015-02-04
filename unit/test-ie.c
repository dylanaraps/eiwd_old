/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2013-2014  Intel Corporation. All rights reserved.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <ell/ell.h>

#include "src/ie.h"

struct test_data {
	unsigned int num_ie;
	unsigned int len;
	unsigned char *buf;
};

struct ie {
	unsigned char type;
	unsigned char len;
	unsigned char value[];
} __attribute__ ((packed));

static void ie_test_reader(const void *data)
{
	const struct test_data *test = data;
	struct ie_tlv_iter iter;
	struct ie *ie;
	unsigned int count = 0, pos = 0;
	char *str;

	ie_tlv_iter_init(&iter, test->buf, test->len);

	while (ie_tlv_iter_next(&iter)) {
		ie = (struct ie *)&test->buf[pos];
		str = l_util_hexstring(&test->buf[pos + 2], ie->len);
		printf("IE %d [%d/%d/%s]\n", count, ie->type, ie->len, str);
		l_free(str);

		assert(iter.tag == test->buf[pos++]);
		assert(iter.len == test->buf[pos++]);
		assert(!memcmp(iter.data, test->buf + pos, iter.len));
		pos += ie->len;

		count++;
	}

	assert(count == test->num_ie);
}

static unsigned char beacon_frame[] = {
	/* IEEE 802.11 Beacon frame */
	0x80, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xc8, 0xd7, 0x19, 0x39, 0xbe, 0x77,
	0xc8, 0xd7, 0x19, 0x39, 0xbe, 0x77, 0x50, 0xa2,

	/* IEEE 802.11 wireless LAN managment frame
	 * - Fixed parameters (12 bytes)
	 */
	0x87, 0x81, 0x31, 0xe6, 0x29, 0x02, 0x00, 0x00,
	0x64, 0x00, 0x11, 0x00,

	/* - Tagged parameters (TLV format, 252 bytes).
	 *   This starts at byte position 36
	 */
	0x00, 0x0c, 0x57, 0x65, 0x73, 0x31, 0x4f, 0x70,
	0x65, 0x6e, 0x57, 0x4c, 0x41, 0x4e, 0x01, 0x08,
	0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c,
	0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x30, 0x14,
	0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00,
	0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f,
	0xac, 0x02, 0x0c, 0x00, 0x0b, 0x05, 0x02, 0x00,
	0x02, 0x00, 0x00, 0x2d, 0x1a, 0x6f, 0x08, 0x17,
	0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3d,
	0x16, 0x24, 0x0d, 0x16, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
	0x0e, 0x14, 0x00, 0x0a, 0x00, 0x2c, 0x01, 0xc8,
	0x00, 0x14, 0x00, 0x05, 0x00, 0x19, 0x00, 0x7f,
	0x08, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
	0x40, 0xbf, 0x0c, 0x32, 0x58, 0x82, 0x0f, 0xea,
	0xff, 0x00, 0x00, 0xea, 0xff, 0x00, 0x00, 0xc0,
	0x05, 0x01, 0x2a, 0x00, 0x00, 0x00, 0xc3, 0x04,
	0x02, 0x02, 0x02, 0x02, 0xdd, 0x31, 0x00, 0x50,
	0xf2, 0x04, 0x10, 0x4a, 0x00, 0x01, 0x10, 0x10,
	0x44, 0x00, 0x01, 0x02, 0x10, 0x47, 0x00, 0x10,
	0x98, 0x42, 0x13, 0x05, 0x23, 0x6e, 0xde, 0x3a,
	0xfa, 0x13, 0x0a, 0x79, 0x44, 0x0f, 0xab, 0x43,
	0x10, 0x3c, 0x00, 0x01, 0x03, 0x10, 0x49, 0x00,
	0x06, 0x00, 0x37, 0x2a, 0x00, 0x01, 0x20, 0xdd,
	0x09, 0x00, 0x10, 0x18, 0x02, 0x02, 0x00, 0x1c,
	0x00, 0x00, 0xdd, 0x18, 0x00, 0x50, 0xf2, 0x02,
	0x01, 0x01, 0x80, 0x00, 0x03, 0xa4, 0x00, 0x00,
	0x27, 0xa4, 0x00, 0x00, 0x42, 0x43, 0x5e, 0x00,
	0x62, 0x32, 0x2f, 0x00, 0x01, 0x9a, 0xc1, 0xc8,
};

static struct test_data beacon_frame_data = {
	.buf = beacon_frame + 36,
	.num_ie = 15,
	.len = 252,
};

static int create_ie(int ie_count, struct ie_tlv_builder *builder,
		int type, int len, unsigned char *value)
{
	int total_len = 0;
	char *str;

	str = l_util_hexstring(value, len);
	printf("IE %d [%d/%d/%s]\n", ie_count, type, len, str);
	l_free(str);
	assert(ie_tlv_builder_next(builder, type));
	total_len += 1;
	assert(ie_tlv_builder_set_length(builder, len));
	total_len += 1;
	memcpy(ie_tlv_builder_get_data(builder), value, len);
	total_len += len;

	return total_len;
}

#define ie(type, len, value...)						\
	do {								\
		unsigned char buf[] = { value };			\
		final_len += create_ie(ie_count, &builder, type, len, buf); \
		ie_count++;						\
	} while (0)

static void ie_test_writer(const void *data)
{
	struct test_data *test = (struct test_data *)data;
	struct ie_tlv_builder builder;
	unsigned int final_len = 0, builder_len, expected_len = test->len;
	unsigned char *expected_buf = test->buf;
	unsigned int ie_count = 0;
	char *str;

	assert(ie_tlv_builder_init(&builder));

	test->buf = builder.buf;
	test->len = builder.max;

	ie(IE_TYPE_SSID, 0x0c,
		0x57, 0x65, 0x73, 0x31, 0x4f, 0x70, 0x65, 0x6e,
		0x57, 0x4c, 0x41, 0x4e);
	ie(IE_TYPE_SUPPORTED_RATES, 0x08,
		0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c);
	ie(IE_TYPE_TIM, 0x04, 0x00, 0x01, 0x00, 0x00);
	ie(IE_TYPE_RSN, 0x14,
		0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00,
		0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f,
		0xac, 0x02, 0x0c, 0x00);
	ie(IE_TYPE_BSS_LOAD, 0x05, 0x02, 0x00, 0x02, 0x00, 0x00);
	ie(IE_TYPE_HT_CAPABILITIES, 0x1a,
		0x6f, 0x08, 0x17, 0xff, 0xff, 0xff, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00);
	ie(IE_TYPE_HT_OPERATION, 0x16,
		0x24, 0x0d, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
	ie(IE_TYPE_OVERLAPPING_BSS_SCAN_PARAMETERS, 0x0e,
		0x14, 0x00, 0x0a, 0x00, 0x2c, 0x01, 0xc8, 0x00,
		0x14, 0x00, 0x05, 0x00, 0x19, 0x00);
	ie(IE_TYPE_EXTENDED_CAPABILITIES, 0x08,
		0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x40);
	ie(191 /* IEEE 802.11ac/D3.1 VHT Capabilities */, 0x0c,
		0x32, 0x58, 0x82, 0x0f, 0xea, 0xff, 0x00, 0x00,
		0xea, 0xff, 0x00, 0x00);
	ie(192 /* IEEE 802.11ac/D3.1 VHT Operation */, 0x05,
		0x01, 0x2a, 0x00, 0x00, 0x00);
	ie(195 /* unknown */, 0x04, 0x02, 0x02, 0x02, 0x02);
	ie(IE_TYPE_VENDOR_SPECIFIC, 0x31,
		0x00, 0x50, 0xf2,             /* OUI (Microsoft) */
		0x04,                         /* WPS type */
		0x10, 0x4a, 0x00, 0x01, 0x10, /* version */
		0x10, 0x44, 0x00, 0x01, 0x02, /* wps state */
		0x10, 0x47,                   /* UUID E */
		0x00, 0x10,                   /* len */
		0x98, 0x42, 0x13, 0x05, 0x23, 0x6e, 0xde, 0x3a,
		0xfa, 0x13, 0x0a, 0x79, 0x44, 0x0f, 0xab, 0x43, /* enrollee */
		0x10, 0x3c, 0x00, 0x01, 0x03, /* RF bands: 2.5 & 5 GHz */
		0x10, 0x49, 0x00, 0x06, 0x00, 0x37, 0x2a, 0x00,
		0x01, 0x20                    /* vendor extension */ );
	ie(IE_TYPE_VENDOR_SPECIFIC, 0x09,
		0x00, 0x10, 0x18,             /* OUI (Broadcom) */
		0x02,                         /* type */
		0x02, 0x00, 0x1c, 0x00, 0x00  /* data */ );
	ie(IE_TYPE_VENDOR_SPECIFIC, 0x18,
		0x00, 0x50, 0xf2,             /* OUI (Microsoft) */
		0x02,                         /* WMM/WME type */
		0x01, 0x01, 0x80, 0x00, 0x03, 0xa4, 0x00, 0x00,
		0x27, 0xa4, 0x00, 0x00, 0x42, 0x43, 0x5e, 0x00,
		0x62, 0x32, 0x2f, 0x00, 0x01, 0x9a, 0xc1, 0xc8 /* data */ );

	ie_tlv_builder_finalize(&builder, &builder_len);

	assert(final_len == builder_len);
	assert(expected_len = final_len);
	assert(ie_count == test->num_ie);

	str = l_util_hexstring(test->buf, final_len);
	printf("IE buf %s\n", str);
	l_free(str);

	if (memcmp(test->buf, expected_buf, final_len)) {
		unsigned int i;

		str = l_util_hexstring(&beacon_frame[36], final_len);
		printf("Expecting buf %s\n", str);
		l_free(str);

		for (i = 0; i < final_len; i++) {
			if (expected_buf[i] != test->buf[i]) {
				printf("1st difference at pos %d "
					"expecting 0x%02x got 0x%02x\n",
					i, expected_buf[i], test->buf[i]);
				break;
			}
		}

		assert(!memcmp(test->buf, expected_buf, final_len));
	}

	printf("Wrote %d IE total len %d\n", ie_count, expected_len);
}

static void ie_test_writer_invalid_tag(const void *data)
{
	struct ie_tlv_builder builder;

	assert(ie_tlv_builder_init(&builder));
	assert(!ie_tlv_builder_next(&builder, 256));
}

static void ie_test_writer_invalid_len(const void *data)
{
	struct ie_tlv_builder builder;

	assert(ie_tlv_builder_init(&builder));
	assert(ie_tlv_builder_next(&builder, 255));
	assert(!ie_tlv_builder_set_length(&builder, MAX_BUILDER_SIZE));
}

struct ie_rsne_info_test {
	const unsigned char *data;
	size_t data_len;
	enum ie_rsn_cipher_suite group_cipher;
	uint16_t pairwise_ciphers;
	uint16_t akm_suites;
	bool preauthentication:1;
	bool no_pairwise:1;
	uint8_t ptksa_replay_counter:2;
	uint8_t gtksa_replay_counter:2;
	bool mfpr:1;
	bool mfpc:1;
	bool peerkey_enabled:1;
	bool spp_a_msdu_capable:1;
	bool spp_a_msdu_required:1;
	bool pbac:1;
	bool extended_key_id:1;
	uint8_t num_pmkids;
	uint8_t pmkids[232];
	enum ie_rsn_cipher_suite group_management_cipher;
};

static const unsigned char rsne_data_1[] = {
	0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f,
	0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x00, 0x00,
};

static const struct ie_rsne_info_test ie_rsne_info_test_1 = {
	.data = rsne_data_1,
	.data_len = sizeof(rsne_data_1),
	.group_cipher = IE_RSN_CIPHER_SUITE_CCMP,
	.pairwise_ciphers = IE_RSN_CIPHER_SUITE_CCMP,
	.akm_suites = IE_RSN_AKM_SUITE_PSK,
};

/* 802.11, Section 8.4.2.27.1; first example */
static const unsigned char rsne_data_2[] = {
	0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f,
	0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x01, 0x00, 0x00,
};

static const struct ie_rsne_info_test ie_rsne_info_test_2 = {
	.data = rsne_data_2,
	.data_len = sizeof(rsne_data_2),
	.group_cipher = IE_RSN_CIPHER_SUITE_CCMP,
	.pairwise_ciphers = IE_RSN_CIPHER_SUITE_CCMP,
	.akm_suites = IE_RSN_AKM_SUITE_8021X,
};

/* 802.11, Section 8.4.2.27.1; second example */
static const unsigned char rsne_data_3[] = {
	0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f,
	0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x01, 0x01, 0x00,
};

static const struct ie_rsne_info_test ie_rsne_info_test_3 = {
	.data = rsne_data_3,
	.data_len = sizeof(rsne_data_3),
	.group_cipher = IE_RSN_CIPHER_SUITE_CCMP,
	.pairwise_ciphers = IE_RSN_CIPHER_SUITE_CCMP,
	.akm_suites = IE_RSN_AKM_SUITE_8021X,
	.preauthentication = true,
};

/* 802.11, Section 8.4.2.27.1; third example */
static const unsigned char rsne_data_4[] = {
	0x30, 0x12, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x01, 0x01, 0x00, 0x00, 0x0f,
	0xac, 0x00, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x01,
};

static const struct ie_rsne_info_test ie_rsne_info_test_4 = {
	.data = rsne_data_4,
	.data_len = sizeof(rsne_data_4),
	.group_cipher = IE_RSN_CIPHER_SUITE_WEP40,
	.pairwise_ciphers = IE_RSN_CIPHER_SUITE_USE_GROUP_CIPHER,
	.akm_suites = IE_RSN_AKM_SUITE_8021X,
};

/* 802.11, Section 8.4.2.27.1; fourth example */
static const unsigned char rsne_data_5[] = {
	0x30, 0x26, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f,
	0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x01, 0x01, 0x00, 0x01, 0x00,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
	0x0d, 0x0e, 0x0f, 0x10,
};

static const struct ie_rsne_info_test ie_rsne_info_test_5 = {
	.data = rsne_data_5,
	.data_len = sizeof(rsne_data_5),
	.group_cipher = IE_RSN_CIPHER_SUITE_CCMP,
	.pairwise_ciphers = IE_RSN_CIPHER_SUITE_CCMP,
	.akm_suites = IE_RSN_AKM_SUITE_8021X,
	.preauthentication = true,
	.num_pmkids = 1,
	.pmkids = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
			0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, },
};

/* 802.11, Section 8.4.2.27.1; last example */
static const unsigned char rsne_data_6[] = {
	0x30, 0x1a, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f,
	0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x01, 0x80, 0x00, 0x00, 0x00,
	0x00, 0x0f, 0xac, 0x06,
};

static const struct ie_rsne_info_test ie_rsne_info_test_6 = {
	.data = rsne_data_6,
	.data_len = sizeof(rsne_data_6),
	.group_cipher = IE_RSN_CIPHER_SUITE_CCMP,
	.pairwise_ciphers = IE_RSN_CIPHER_SUITE_CCMP,
	.akm_suites = IE_RSN_AKM_SUITE_8021X,
	.mfpc = true, /* Management frame protection is enabled, not required */
	.group_management_cipher = IE_RSN_CIPHER_SUITE_BIP,
};

static void ie_test_rsne_info(const void *data)
{
	const struct ie_rsne_info_test *test = data;
	int r;
	struct ie_rsn_info info;

	r = ie_parse_rsne_from_data(test->data, test->data_len, &info);
	assert(r == 0);

	assert(test->group_cipher == info.group_cipher);
	assert(test->pairwise_ciphers == info.pairwise_ciphers);
	assert(test->akm_suites == info.akm_suites);

	assert(test->preauthentication == info.preauthentication);
	assert(test->no_pairwise == info.no_pairwise);
	assert(test->ptksa_replay_counter == info.ptksa_replay_counter);
	assert(test->gtksa_replay_counter == info.gtksa_replay_counter);
	assert(test->mfpr == info.mfpr);
	assert(test->mfpc == info.mfpc);
	assert(test->peerkey_enabled == info.peerkey_enabled);
	assert(test->spp_a_msdu_capable == info.spp_a_msdu_capable);
	assert(test->spp_a_msdu_required == info.spp_a_msdu_required);
	assert(test->pbac == info.pbac);
	assert(test->extended_key_id == info.extended_key_id);

	assert(test->num_pmkids == info.num_pmkids);
	assert(!memcmp(test->pmkids, info.pmkids, 16 * test->num_pmkids));

	assert(test->group_management_cipher == info.group_management_cipher);
}

static void ie_test_rsne_build_compact_info(const void *data)
{
	const struct ie_rsne_info_test *test = data;
	int r;
	struct ie_rsn_info info;
	uint8_t buf[256];

	r = ie_parse_rsne_from_data(test->data, test->data_len, &info);
	assert(r == 0);

	r = ie_build_rsne(&info, buf);
	assert(r);

	assert(!memcmp(test->data, buf, test->data_len));
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("/ie/reader/static", ie_test_reader, &beacon_frame_data);

	l_test_add("/ie/writer/invalid-tag", ie_test_writer_invalid_tag, NULL);
	l_test_add("/ie/writer/invalid-len", ie_test_writer_invalid_len, NULL);

	l_test_add("/ie/writer/create", ie_test_writer, &beacon_frame_data);

	l_test_add("/ie/RSN Info Parser/Test Case 1",
				ie_test_rsne_info, &ie_rsne_info_test_1);
	l_test_add("/ie/RSN Info Parser/Test Case 2",
				ie_test_rsne_info, &ie_rsne_info_test_2);
	l_test_add("/ie/RSN Info Parser/Test Case 3",
				ie_test_rsne_info, &ie_rsne_info_test_3);
	l_test_add("/ie/RSN Info Parser/Test Case 4",
				ie_test_rsne_info, &ie_rsne_info_test_4);
	l_test_add("/ie/RSN Info Parser/Test Case 5",
				ie_test_rsne_info, &ie_rsne_info_test_5);
	l_test_add("/ie/RSN Info Parser/Test Case 6",
				ie_test_rsne_info, &ie_rsne_info_test_6);

	l_test_add("/ie/RSN Info Builder/Compact Test 1",
				ie_test_rsne_build_compact_info,
				&ie_rsne_info_test_3);
	l_test_add("/ie/RSN Info Builder/Compact Test 2",
				ie_test_rsne_build_compact_info,
				&ie_rsne_info_test_4);
	l_test_add("/ie/RSN Info Builder/Compact Test 3",
				ie_test_rsne_build_compact_info,
				&ie_rsne_info_test_5);

	return l_test_run();
}
