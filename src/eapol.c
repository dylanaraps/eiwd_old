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

#include <string.h>
#include <ell/ell.h>

#include "sha1.h"
#include "crypto.h"
#include "eapol.h"
#include "ie.h"

struct l_hashmap *state_machines;
eapol_tx_packet_func_t tx_packet = NULL;
eapol_get_nonce_func_t get_nonce = NULL;
enum eapol_protocol_version protocol_version = EAPOL_PROTOCOL_VERSION_2004;

#define VERIFY_IS_ZERO(field)					\
	do {							\
		unsigned int i;					\
		for (i = 0; i < sizeof(field); i++)		\
			if ((field)[i] != 0)			\
				return false;			\
	} while (false)						\

/*
 * MIC calculation depends on the selected hash function.  The has function
 * is given in the EAPoL Key Descriptor Version field.
 *
 * The MIC length is always 16 bytes for currently known Key Descriptor
 * Versions.
 *
 * The input struct eapol_key *frame should have a zero-d MIC field
 */
bool eapol_calculate_mic(const uint8_t *kck, const struct eapol_key *frame,
				uint8_t *mic)
{
	size_t frame_len = sizeof(struct eapol_key);

	frame_len += L_BE16_TO_CPU(frame->key_data_len);

	switch (frame->key_descriptor_version) {
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_MD5_ARC4:
		return hmac_md5(kck, 16, frame, frame_len, mic, 16);
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES:
		return hmac_sha1(kck, 16, frame, frame_len, mic, 16);
	case EAPOL_KEY_DESCRIPTOR_VERSION_AES_128_CMAC_AES:
		return cmac_aes(kck, 16, frame, frame_len, mic, 16);
	default:
		return false;
	}
}

bool eapol_verify_mic(const uint8_t *kck, const struct eapol_key *frame)
{
	size_t frame_len = sizeof(struct eapol_key);
	uint8_t mic[16];
	struct iovec iov[3];
	struct l_checksum *checksum = NULL;

	iov[0].iov_base = (void *) frame;
	iov[0].iov_len = offsetof(struct eapol_key, key_mic_data);

	memset(mic, 0, sizeof(mic));
	iov[1].iov_base = mic;
	iov[1].iov_len = sizeof(mic);

	iov[2].iov_base = ((void *) frame) +
				offsetof(struct eapol_key, key_data_len);
	iov[2].iov_len = frame_len - offsetof(struct eapol_key, key_data_len) +
				L_BE16_TO_CPU(frame->key_data_len);

	switch (frame->key_descriptor_version) {
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_MD5_ARC4:
		checksum = l_checksum_new_hmac(L_CHECKSUM_MD5, kck, 16);
		break;
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES:
		checksum = l_checksum_new_hmac(L_CHECKSUM_SHA1, kck, 16);
		break;
	case EAPOL_KEY_DESCRIPTOR_VERSION_AES_128_CMAC_AES:
		checksum = l_checksum_new_cmac_aes(kck, 16);
		break;
	default:
		return false;
	}

	if (checksum == NULL)
		return false;

	l_checksum_updatev(checksum, iov, 3);
	l_checksum_get_digest(checksum, mic, 16);
	l_free(checksum);

	if (!memcmp(frame->key_mic_data, mic, 16))
		return true;

	return false;
}

uint8_t *eapol_decrypt_key_data(const uint8_t *kek,
				const struct eapol_key *frame,
				size_t *decrypted_size)
{
	size_t key_data_len = L_BE16_TO_CPU(frame->key_data_len);
	const uint8_t *key_data = frame->key_data;
	size_t expected_len;
	uint8_t *buf;

	switch (frame->key_descriptor_version) {
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_MD5_ARC4:
		expected_len = key_data_len;
		break;
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES:
	case EAPOL_KEY_DESCRIPTOR_VERSION_AES_128_CMAC_AES:
		expected_len = key_data_len - 8;
		break;
	default:
		return NULL;
	};

	buf = l_new(uint8_t, expected_len);

	switch (frame->key_descriptor_version) {
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_MD5_ARC4:
	{
		uint8_t key[32];
		bool ret;

		memcpy(key, frame->eapol_key_iv, 16);
		memcpy(key + 16, kek, 16);

		ret = arc4_skip(key, 32, 256, key_data, key_data_len, buf);
		memset(key, 0, sizeof(key));

		if (!ret)
			goto error;

		break;
	}
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES:
	case EAPOL_KEY_DESCRIPTOR_VERSION_AES_128_CMAC_AES:
		if (key_data_len < 8 || key_data_len % 8)
			goto error;

		if (!aes_unwrap(kek, key_data, key_data_len, buf))
			goto error;

		break;
	}

	if (decrypted_size)
		*decrypted_size = expected_len;

	return buf;

error:
	l_free(buf);
	return NULL;
}

const struct eapol_key *eapol_key_validate(const uint8_t *frame, size_t len)
{
	const struct eapol_key *ek;
	uint16_t key_data_len;

	if (len < sizeof(struct eapol_key))
		return NULL;

	ek = (const struct eapol_key *) frame;

	if (ek->protocol_version != EAPOL_PROTOCOL_VERSION_2001 &&
			ek->protocol_version != EAPOL_PROTOCOL_VERSION_2004)
		return NULL;

	if (ek->packet_type != 3)
		return NULL;

	switch (ek->descriptor_type) {
	case EAPOL_DESCRIPTOR_TYPE_RC4:
	case EAPOL_DESCRIPTOR_TYPE_80211:
	case EAPOL_DESCRIPTOR_TYPE_WPA:
		break;
	default:
		return NULL;
	}

	switch (ek->key_descriptor_version) {
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_MD5_ARC4:
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES:
	case EAPOL_KEY_DESCRIPTOR_VERSION_AES_128_CMAC_AES:
		break;
	default:
		return NULL;
	}

	key_data_len = L_BE16_TO_CPU(ek->key_data_len);
	if (len < sizeof(struct eapol_key) + key_data_len)
		return NULL;

	return ek;
}

#define VERIFY_PTK_COMMON(ek)	\
	if (!ek->key_type)	\
		return false;	\
	if (ek->smk_message)	\
		return false;	\
	if (ek->request)	\
		return false;	\
	if (ek->error)		\
		return false	\

bool eapol_verify_ptk_1_of_4(const struct eapol_key *ek)
{
	/* Verify according to 802.11, Section 11.6.6.2 */
	VERIFY_PTK_COMMON(ek);

	if (ek->install)
		return false;

	if (!ek->key_ack)
		return false;

	if (ek->key_mic)
		return false;

	if (ek->secure)
		return false;

	if (ek->encrypted_key_data)
		return false;

	VERIFY_IS_ZERO(ek->eapol_key_iv);
	VERIFY_IS_ZERO(ek->key_rsc);
	VERIFY_IS_ZERO(ek->reserved);
	VERIFY_IS_ZERO(ek->key_mic_data);

	return ek;
}

bool eapol_verify_ptk_2_of_4(const struct eapol_key *ek)
{
	uint16_t key_len;

	/* Verify according to 802.11, Section 11.6.6.3 */
	VERIFY_PTK_COMMON(ek);

	if (ek->install)
		return false;

	if (ek->key_ack)
		return false;

	if (!ek->key_mic)
		return false;

	if (ek->secure)
		return false;

	if (ek->encrypted_key_data)
		return false;

	key_len = L_BE16_TO_CPU(ek->key_length);
	if (key_len != 0)
		return false;

	VERIFY_IS_ZERO(ek->eapol_key_iv);
	VERIFY_IS_ZERO(ek->key_rsc);
	VERIFY_IS_ZERO(ek->reserved);

	return true;
}

bool eapol_verify_ptk_3_of_4(const struct eapol_key *ek)
{
	uint16_t key_len;

	/* Verify according to 802.11, Section 11.6.6.4 */
	VERIFY_PTK_COMMON(ek);

	if (!ek->key_ack)
		return false;

	if (!ek->key_mic)
		return false;

	if (!ek->secure)
		return false;

	if (!ek->encrypted_key_data)
		return false;

	key_len = L_BE16_TO_CPU(ek->key_length);
	if (key_len != 16)
		return false;

	VERIFY_IS_ZERO(ek->reserved);

	/* 0 (Version 2) or random (Version 1) */
	if (ek->key_descriptor_version ==
			EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_MD5_ARC4)
		VERIFY_IS_ZERO(ek->eapol_key_iv);

	return true;
}

bool eapol_verify_ptk_4_of_4(const struct eapol_key *ek)
{
	uint16_t key_len;

	/* Verify according to 802.11, Section 11.6.6.5 */
	VERIFY_PTK_COMMON(ek);

	if (ek->key_ack)
		return false;

	if (!ek->key_mic)
		return false;

	if (!ek->secure)
		return false;

	if (ek->encrypted_key_data)
		return false;

	key_len = L_BE16_TO_CPU(ek->key_length);
	if (key_len != 0)
		return false;

	VERIFY_IS_ZERO(ek->key_nonce);
	VERIFY_IS_ZERO(ek->eapol_key_iv);
	VERIFY_IS_ZERO(ek->key_rsc);
	VERIFY_IS_ZERO(ek->reserved);

	return true;
}

static struct eapol_key *eapol_create_common(
				enum eapol_protocol_version protocol,
				enum eapol_key_descriptor_version version,
				bool secure,
				uint64_t key_replay_counter,
				const uint8_t snonce[],
				size_t extra_len,
				const uint8_t *extra_data)
{
	size_t to_alloc = sizeof(struct eapol_key);
	struct eapol_key *out_frame = l_malloc(to_alloc + extra_len);

	memset(out_frame, 0, to_alloc + extra_len);

	out_frame->protocol_version = protocol;
	out_frame->packet_type = 0x3;
	out_frame->packet_len = L_CPU_TO_BE16(to_alloc + extra_len - 4);
	out_frame->descriptor_type = EAPOL_DESCRIPTOR_TYPE_80211;
	out_frame->key_descriptor_version = version;
	out_frame->key_type = true;
	out_frame->install = false;
	out_frame->key_ack = false;
	out_frame->key_mic = true;
	out_frame->secure = secure;
	out_frame->error = false;
	out_frame->request = false;
	out_frame->encrypted_key_data = false;
	out_frame->smk_message = false;
	out_frame->key_length = 0;
	out_frame->key_replay_counter = L_CPU_TO_BE64(key_replay_counter);
	memcpy(out_frame->key_nonce, snonce, sizeof(out_frame->key_nonce));
	out_frame->key_data_len = L_CPU_TO_BE16(extra_len);
	memcpy(out_frame->key_data, extra_data, extra_len);

	return out_frame;
}

struct eapol_key *eapol_create_ptk_2_of_4(
				enum eapol_protocol_version protocol,
				enum eapol_key_descriptor_version version,
				uint64_t key_replay_counter,
				const uint8_t snonce[],
				size_t extra_len,
				const uint8_t *extra_data)
{
	return eapol_create_common(protocol, version, false, key_replay_counter,
					snonce, extra_len, extra_data);
}

struct eapol_key *eapol_create_ptk_4_of_4(
				enum eapol_protocol_version protocol,
				enum eapol_key_descriptor_version version,
				uint64_t key_replay_counter)
{
	uint8_t snonce[32];

	memset(snonce, 0, sizeof(snonce));
	return eapol_create_common(protocol, version, true, key_replay_counter,
					snonce, 0, NULL);
}

struct eapol_sm {
	uint8_t pmk[32];
	uint64_t replay_counter;
	uint8_t sta_addr[6];
	uint8_t snonce[32];
	uint8_t aa_addr[6];
	uint8_t anonce[32];
	uint8_t ptk[64];
	uint8_t *ap_rsn;
	uint8_t *own_rsn;
	bool have_snonce:1;
	bool have_replay:1;
};

static void eapol_sm_destroy(void *value)
{
	struct eapol_sm *sm = value;

	l_free(sm->ap_rsn);
	l_free(sm->own_rsn);
	l_free(sm);
}

struct eapol_sm *eapol_sm_new()
{
	struct eapol_sm *sm;

	sm = l_new(struct eapol_sm, 1);

	return sm;
}

void eapol_sm_free(struct eapol_sm *sm)
{
	eapol_sm_destroy(sm);
}

void eapol_sm_set_sta_address(struct eapol_sm *sm, const uint8_t *sta_addr)
{
	memcpy(sm->sta_addr, sta_addr, sizeof(sm->sta_addr));
}

void eapol_sm_set_aa_address(struct eapol_sm *sm, const uint8_t *aa_addr)
{
	memcpy(sm->aa_addr, aa_addr, sizeof(sm->aa_addr));
}

void eapol_sm_set_pmk(struct eapol_sm *sm, const uint8_t *pmk)
{
	memcpy(sm->pmk, pmk, sizeof(sm->pmk));
}

void eapol_sm_set_ap_rsn(struct eapol_sm *sm, const uint8_t *rsn_ie,
				size_t len)
{
	if (rsn_ie[1] + 2u != len)
		return;

	l_free(sm->ap_rsn);
	sm->ap_rsn = l_memdup(rsn_ie, len);
}

void eapol_sm_set_own_rsn(struct eapol_sm *sm, const uint8_t *rsn_ie,
				size_t len)
{
	if (rsn_ie[1] + 2u != len)
		return;

	l_free(sm->own_rsn);
	sm->own_rsn = l_memdup(rsn_ie, len);
}

void eapol_start(int ifindex, struct eapol_sm *sm)
{
	l_hashmap_insert(state_machines, L_UINT_TO_PTR(ifindex), sm);
}

static void eapol_handle_ptk_1_of_4(int ifindex, struct eapol_sm *sm,
					const struct eapol_key *ek)
{
	struct crypto_ptk *ptk = (struct crypto_ptk *) sm->ptk;
	struct eapol_key *step2;
	uint8_t mic[16];

	if (!eapol_verify_ptk_1_of_4(ek))
		return;

	if (!sm->have_snonce) {
		if (!get_nonce(sm->snonce))
			return;

		sm->have_snonce = true;
	}

	memcpy(sm->anonce, ek->key_nonce, sizeof(ek->key_nonce));

	crypto_derive_pairwise_ptk(sm->pmk, sm->sta_addr, sm->aa_addr,
					sm->anonce, sm->snonce,
					ptk, sizeof(sm->ptk));

	step2 = eapol_create_ptk_2_of_4(protocol_version,
					ek->key_descriptor_version,
					sm->replay_counter,
					sm->snonce,
					sm->own_rsn[1] + 2, sm->own_rsn);

	if (!eapol_calculate_mic(ptk->kck, step2, mic))
		goto fail;

	memcpy(step2->key_mic_data, mic, sizeof(mic));
	tx_packet(ifindex, sm->aa_addr, sm->sta_addr, step2);

fail:
	l_free(step2);
}

static const uint8_t *eapol_find_gtk_kde(const uint8_t *data, size_t data_len,
						size_t *out_gtk_len)
{
	static const unsigned char gtk_oui[] = { 0x00, 0x0f, 0xac, 0x01 };
	struct ie_tlv_iter iter;
	const uint8_t *gtk;
	unsigned int len;

	ie_tlv_iter_init(&iter, data, data_len);

	while (ie_tlv_iter_next(&iter)) {
		if (ie_tlv_iter_get_tag(&iter) != IE_TYPE_VENDOR_SPECIFIC)
			continue;

		len = ie_tlv_iter_get_length(&iter);
		if (len < 4)		/* Take care of padding */
			return NULL;

		/* Check OUI */
		gtk = ie_tlv_iter_get_data(&iter);
		if (memcmp(gtk, gtk_oui, 4))
			continue;

		if (out_gtk_len)
			*out_gtk_len = len - 4;

		return gtk + 4;
	}

	return NULL;
}

static const uint8_t *eapol_find_rsne(const uint8_t *data, size_t data_len)
{
	struct ie_tlv_iter iter;

	ie_tlv_iter_init(&iter, data, data_len);

	while (ie_tlv_iter_next(&iter)) {
		if (ie_tlv_iter_get_tag(&iter) != IE_TYPE_RSN)
			continue;

		return ie_tlv_iter_get_data(&iter) - 2;
	}

	return NULL;
}

/*
 * This function performs a match of the RSN IE obtained from the scan
 * results vs the RSN IE obtained as part of the 4-way handshake.  If they
 * don't match, the EAPoL packet must be silently discarded.
 */
static bool eapol_ap_rsne_matches(const uint8_t *eapol_rsne,
						const uint8_t *scan_rsne)
{
	struct ie_rsn_info eapol_info;
	struct ie_rsn_info scan_info;

	/*
	 * First check that the sizes match, if they do, run a bitwise
	 * comparison.
	 */
	if (eapol_rsne[1] == scan_rsne[1] &&
			!memcmp(eapol_rsne + 2, scan_rsne + 2, eapol_rsne[1]))
		return true;

	/*
	 * Otherwise we have to parse the RSN IEs and compare the individual
	 * fields
	 */
	if (ie_parse_rsne_from_data(eapol_rsne, eapol_rsne[1] + 2,
					&eapol_info) < 0)
		return false;

	if (ie_parse_rsne_from_data(scan_rsne, scan_rsne[1] + 2,
					&scan_info) < 0)
		return false;

	if (eapol_info.group_cipher != scan_info.group_cipher)
		return false;

	if (eapol_info.pairwise_ciphers != scan_info.pairwise_ciphers)
		return false;

	if (eapol_info.akm_suites != scan_info.akm_suites)
		return false;

	if (eapol_info.preauthentication != scan_info.preauthentication)
		return false;

	if (eapol_info.no_pairwise != scan_info.no_pairwise)
		return false;

	if (eapol_info.ptksa_replay_counter != scan_info.ptksa_replay_counter)
		return false;

	if (eapol_info.gtksa_replay_counter != scan_info.gtksa_replay_counter)
		return false;

	if (eapol_info.mfpr != scan_info.mfpr)
		return false;

	if (eapol_info.mfpc != scan_info.mfpc)
		return false;

	if (eapol_info.peerkey_enabled != scan_info.peerkey_enabled)
		return false;

	if (eapol_info.spp_a_msdu_capable != scan_info.spp_a_msdu_capable)
		return false;

	if (eapol_info.spp_a_msdu_required != scan_info.spp_a_msdu_required)
		return false;

	if (eapol_info.pbac != scan_info.pbac)
		return false;

	if (eapol_info.extended_key_id != scan_info.extended_key_id)
		return false;

	/* We don't check the PMKIDs since these might actually be different */

	if (eapol_info.group_management_cipher !=
			scan_info.group_management_cipher)
		return false;

	return true;
}

static void eapol_handle_ptk_3_of_4(int ifindex, struct eapol_sm *sm,
					const struct eapol_key *ek,
					const uint8_t *decrypted_key_data,
					size_t decrypted_key_data_size)
{
	struct crypto_ptk *ptk = (struct crypto_ptk *) sm->ptk;
	struct eapol_key *step4;
	uint8_t mic[16];
	const uint8_t *gtk;
	size_t gtk_len;
	const uint8_t *rsne;

	if (!eapol_verify_ptk_3_of_4(ek))
		return;

	/*
	 * 11.6.6.4: "On reception of Message 3, the Supplicant silently
	 * discards the message if ... or if the ANonce value in Message 3
	 * differs from the ANonce value in Message 1"
	 */
	if (memcmp(sm->anonce, ek->key_nonce, sizeof(ek->key_nonce)))
		return;

	/*
	 * 11.6.6.4: "Verifies the RSNE. If it is part of a Fast BSS Transition
	 * Initial Mobility Domain Association, see 12.4.2. Otherwise, if it is
	 * not identical to that the STA received in the Beacon or Probe
	 * Response frame, the STA shall disassociate.
	 */
	rsne = eapol_find_rsne(decrypted_key_data, decrypted_key_data_size);
	if (!rsne)
		return;

	if (!eapol_ap_rsne_matches(rsne, sm->ap_rsn))
		return;

	/*
	 * TODO: Parse second RSNE
	 * 11.6.6.4: "If a second RSNE is provided in the message, the
	 * Supplicant uses the pairwise cipher suite specified in the second
	 * RSNE or deauthenticates."
	 */

	/*
	 * TODO: If group_cipher was negotiated, find the GTK and install it
	 */
	gtk = eapol_find_gtk_kde(decrypted_key_data, decrypted_key_data_size,
					&gtk_len);
	if (!gtk)
		return;

	step4 = eapol_create_ptk_4_of_4(protocol_version,
					ek->key_descriptor_version,
					sm->replay_counter);

	if (!eapol_calculate_mic(ptk->kck, step4, mic))
		goto fail;

	memcpy(step4->key_mic_data, mic, sizeof(mic));
	tx_packet(ifindex, sm->aa_addr, sm->sta_addr, step4);

fail:
	l_free(step4);

}

void __eapol_rx_packet(int ifindex, const uint8_t *sta_addr,
			const uint8_t *aa_addr,
			const uint8_t *frame, size_t len)
{
	const struct eapol_key *ek;
	struct eapol_sm *sm;
	struct crypto_ptk *ptk;
	uint8_t *decrypted_key_data = NULL;
	size_t decrypted_key_data_len;
	uint64_t replay_counter;

	ek = eapol_key_validate(frame, len);
	if (!ek)
		return;

	sm = l_hashmap_lookup(state_machines, L_UINT_TO_PTR(ifindex));
	if (!sm)
		return;

	if (memcmp(sm->sta_addr, sta_addr, sizeof(sm->sta_addr)))
		return;

	if (memcmp(sm->aa_addr, aa_addr, sizeof(sm->aa_addr)))
		return;

	/* Wrong direction */
	if (!ek->key_ack)
		return;

	replay_counter = L_BE64_TO_CPU(ek->key_replay_counter);

	/*
	 * 11.6.6.2: "If the Key Replay Counter field value is less than or
	 * equal to the current local value, the Supplicant discards the
	 * message.
	 *
	 * 11.6.6.4: "On reception of Message 3, the Supplicant silently
	 * discards the message if the Key Replay Counter field value has
	 * already been used...
	 */
	if (sm->have_replay && sm->replay_counter >= replay_counter)
		return;

	sm->replay_counter = replay_counter;
	sm->have_replay = true;

	ptk = (struct crypto_ptk *) sm->ptk;

	if (ek->key_mic) {
		/* Haven't received step 1 yet, so no ptk */
		if (!sm->have_snonce)
			return;

		if (!eapol_verify_mic(ptk->kck, ek))
			return;
	}

	if (ek->encrypted_key_data) {
		/* Haven't received step 1 yet, so no ptk */
		if (!sm->have_snonce)
			return;

		decrypted_key_data = eapol_decrypt_key_data(ptk->kek, ek,
						&decrypted_key_data_len);
		if (!decrypted_key_data)
			return;
	}

	/* TODO: Handle Group Key Handshake */
	if (ek->key_type == 0)
		goto done;

	/* If no MIC, then assume packet 1, otherwise packet 3 */
	if (!ek->key_mic)
		eapol_handle_ptk_1_of_4(ifindex, sm, ek);
	else
		eapol_handle_ptk_3_of_4(ifindex, sm, ek, decrypted_key_data,
					decrypted_key_data_len);

done:
	l_free(decrypted_key_data);
}

void __eapol_set_tx_packet_func(eapol_tx_packet_func_t func)
{
	tx_packet = func;
}

void __eapol_set_get_nonce_func(eapol_get_nonce_func_t func)
{
	get_nonce = func;
}

void __eapol_set_protocol_version(enum eapol_protocol_version version)
{
	protocol_version = version;
}

bool eapol_init()
{
	state_machines = l_hashmap_new();
	protocol_version = EAPOL_PROTOCOL_VERSION_2004;

	return true;
}

bool eapol_exit()
{
	l_hashmap_destroy(state_machines, eapol_sm_destroy);
	get_nonce = NULL;
	tx_packet = NULL;

	return true;
}
