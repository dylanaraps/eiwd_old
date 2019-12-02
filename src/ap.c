/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2017-2019  Intel Corporation. All rights reserved.
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

#include <errno.h>
#include <linux/if_ether.h>

#include <ell/ell.h>

#include "linux/nl80211.h"

#include "src/iwd.h"
#include "src/module.h"
#include "src/scan.h"
#include "src/netdev.h"
#include "src/wiphy.h"
#include "src/crypto.h"
#include "src/ie.h"
#include "src/mpdu.h"
#include "src/util.h"
#include "src/eapol.h"
#include "src/handshake.h"
#include "src/nl80211util.h"

struct ap_state {
	struct netdev *netdev;
	struct l_genl_family *nl80211;
	char *ssid;
	uint8_t channel;
	unsigned int ciphers;
	enum ie_rsn_cipher_suite group_cipher;
	uint32_t beacon_interval;
	struct l_uintset *rates;
	uint8_t pmk[32];
	struct l_queue *frame_watch_ids;
	uint32_t start_stop_cmd_id;
	uint8_t gtk[CRYPTO_MAX_GTK_LEN];
	uint8_t gtk_index;

	uint16_t last_aid;
	struct l_queue *sta_states;

	bool pending;
	bool started : 1;
	bool gtk_set : 1;
};

struct sta_state {
	uint8_t addr[6];
	bool associated;
	bool rsna;
	uint16_t aid;
	struct mmpdu_field_capability capability;
	uint16_t listen_interval;
	struct l_uintset *rates;
	uint32_t assoc_resp_cmd_id;
	struct ap_state *ap;
	uint8_t *assoc_rsne;
	struct eapol_sm *sm;
	struct handshake_state *hs;
	uint32_t gtk_query_cmd_id;
};

static uint32_t netdev_watch;

static void ap_sta_free(void *data)
{
	struct sta_state *sta = data;
	struct ap_state *ap = sta->ap;

	l_uintset_free(sta->rates);
	l_free(sta->assoc_rsne);

	if (sta->assoc_resp_cmd_id)
		l_genl_family_cancel(ap->nl80211, sta->assoc_resp_cmd_id);

	if (sta->gtk_query_cmd_id)
		l_genl_family_cancel(ap->nl80211, sta->gtk_query_cmd_id);

	if (sta->sm)
		eapol_sm_free(sta->sm);

	if (sta->hs)
		handshake_state_free(sta->hs);

	l_free(sta);
}

static void ap_del_station(struct sta_state *sta, uint16_t reason,
				bool disassociate)
{
	struct ap_state *ap = sta->ap;

	netdev_del_station(ap->netdev, sta->addr, reason, disassociate);
	sta->associated = false;
	sta->rsna = false;

	if (sta->gtk_query_cmd_id) {
		l_genl_family_cancel(ap->nl80211, sta->gtk_query_cmd_id);
		sta->gtk_query_cmd_id = 0;
	}

	if (sta->sm)
		eapol_sm_free(sta->sm);

	if (sta->hs)
		handshake_state_free(sta->hs);

	sta->hs = NULL;
	sta->sm = NULL;
}

static void ap_remove_sta(struct sta_state *sta)
{
	if (!l_queue_remove(sta->ap->sta_states, sta)) {
		l_error("tried to remove station that doesn't exist");
		return;
	}

	ap_sta_free(sta);
}

static void ap_set_sta_cb(struct l_genl_msg *msg, void *user_data)
{
	if (l_genl_msg_get_error(msg) < 0)
		l_error("SET_STATION failed: %i", l_genl_msg_get_error(msg));
}

static void ap_del_key_cb(struct l_genl_msg *msg, void *user_data)
{
	if (l_genl_msg_get_error(msg) < 0)
		l_debug("DEL_KEY failed: %i", l_genl_msg_get_error(msg));
}

static void ap_new_rsna(struct sta_state *sta)
{
	l_debug("STA "MAC" authenticated", MAC_STR(sta->addr));

	sta->rsna = true;
	/*
	 * TODO: Once new AP interface is implemented this is where a
	 * new "ConnectedPeer" property will be added.
	 */
}

static void ap_drop_rsna(struct sta_state *sta)
{
	struct ap_state *ap = sta->ap;
	struct l_genl_msg *msg;
	uint32_t ifindex = netdev_get_ifindex(sta->ap->netdev);
	uint8_t key_id = 0;

	sta->rsna = false;

	msg = nl80211_build_set_station_unauthorized(ifindex, sta->addr);

	l_genl_msg_append_attr(msg, NL80211_ATTR_STA_AID, 2, &sta->aid);

	if (!l_genl_family_send(ap->nl80211, msg, ap_set_sta_cb, NULL, NULL)) {
		l_genl_msg_unref(msg);
		l_error("Issuing SET_STATION failed");
	}

	msg = l_genl_msg_new_sized(NL80211_CMD_DEL_KEY, 64);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);
	l_genl_msg_append_attr(msg, NL80211_ATTR_KEY_IDX, 1, &key_id);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, 6, sta->addr);

	if (!l_genl_family_send(ap->nl80211, msg, ap_del_key_cb, NULL, NULL)) {
		l_genl_msg_unref(msg);
		l_error("Issuing DEL_KEY failed");
	}

	if (sta->sm)
		eapol_sm_free(sta->sm);

	if (sta->hs)
		handshake_state_free(sta->hs);

	sta->hs = NULL;
	sta->sm = NULL;
}

static void ap_set_rsn_info(struct ap_state *ap, struct ie_rsn_info *rsn)
{
	memset(rsn, 0, sizeof(*rsn));
	rsn->akm_suites = IE_RSN_AKM_SUITE_PSK;
	rsn->pairwise_ciphers = ap->ciphers;
	rsn->group_cipher = ap->group_cipher;
}

static uint32_t ap_send_mgmt_frame(struct ap_state *ap,
					const struct mmpdu_header *frame,
					size_t frame_len, bool wait_ack,
					l_genl_msg_func_t callback,
					void *user_data)
{
	struct l_genl_msg *msg;
	uint32_t ifindex = netdev_get_ifindex(ap->netdev);
	uint32_t id;
	uint32_t ch_freq = scan_channel_to_freq(ap->channel, SCAN_BAND_2_4_GHZ);

	msg = l_genl_msg_new_sized(NL80211_CMD_FRAME, 128 + frame_len);

	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WIPHY_FREQ, 4, &ch_freq);
	l_genl_msg_append_attr(msg, NL80211_ATTR_FRAME, frame_len, frame);
	if (!wait_ack)
		l_genl_msg_append_attr(msg, NL80211_ATTR_DONT_WAIT_FOR_ACK,
					0, NULL);

	id = l_genl_family_send(ap->nl80211, msg, callback, user_data, NULL);

	if (!id)
		l_genl_msg_unref(msg);

	return id;
}

static void ap_handshake_event(struct handshake_state *hs,
		enum handshake_event event, void *user_data, ...)
{
	struct sta_state *sta = user_data;
	va_list args;

	va_start(args, user_data);

	switch (event) {
	case HANDSHAKE_EVENT_COMPLETE:
		ap_new_rsna(sta);
		break;
	case HANDSHAKE_EVENT_FAILED:
		netdev_handshake_failed(hs, va_arg(args, int));
		/* fall through */
	case HANDSHAKE_EVENT_SETTING_KEYS_FAILED:
		sta->sm = NULL;
		ap_remove_sta(sta);
	default:
		break;
	}

	va_end(args);
}

static void ap_start_rsna(struct sta_state *sta, const uint8_t *gtk_rsc)
{
	struct ap_state *ap = sta->ap;
	struct netdev *netdev = sta->ap->netdev;
	const uint8_t *own_addr = netdev_get_address(netdev);
	struct scan_bss bss;
	struct ie_rsn_info rsn;
	uint8_t bss_rsne[24];

	memset(&bss, 0, sizeof(bss));

	ap_set_rsn_info(ap, &rsn);
	/*
	 * TODO: This assumes the length that ap_set_rsn_info() requires. If
	 * ap_set_rsn_info() changes then this will need to be updated.
	 */
	ie_build_rsne(&rsn, bss_rsne);

	/* this handshake setup assumes PSK network */
	sta->hs = netdev_handshake_state_new(netdev);

	handshake_state_set_event_func(sta->hs, ap_handshake_event, sta);
	handshake_state_set_ssid(sta->hs, (void *)ap->ssid, strlen(ap->ssid));
	handshake_state_set_authenticator(sta->hs, true);
	handshake_state_set_authenticator_ie(sta->hs, bss_rsne);
	handshake_state_set_supplicant_ie(sta->hs, sta->assoc_rsne);
	handshake_state_set_pmk(sta->hs, ap->pmk, 32);
	handshake_state_set_authenticator_address(sta->hs, own_addr);
	handshake_state_set_supplicant_address(sta->hs, sta->addr);

	if (gtk_rsc)
		handshake_state_set_gtk(sta->hs, ap->gtk, ap->gtk_index,
					gtk_rsc);

	sta->sm = eapol_sm_new(sta->hs);
	if (!sta->sm) {
		handshake_state_free(sta->hs);
		sta->hs = NULL;
		l_error("could not create sm object");
		goto error;
	}

	eapol_sm_set_listen_interval(sta->sm, sta->listen_interval);

	eapol_register(sta->sm);

	return;

error:
	ap_del_station(sta, MMPDU_REASON_CODE_UNSPECIFIED, true);
}

static void ap_gtk_query_cb(struct l_genl_msg *msg, void *user_data)
{
	struct sta_state *sta = user_data;
	const void *gtk_rsc;

	sta->gtk_query_cmd_id = 0;

	gtk_rsc = nl80211_parse_get_key_seq(msg);
	if (!gtk_rsc)
		goto error;

	ap_start_rsna(sta, gtk_rsc);
	return;

error:
	ap_del_station(sta, MMPDU_REASON_CODE_UNSPECIFIED, true);
}

static struct l_genl_msg *ap_build_cmd_new_station(struct sta_state *sta)
{
	struct l_genl_msg *msg;
	uint32_t ifindex = netdev_get_ifindex(sta->ap->netdev);
	/*
	 * This should hopefully work both with and without
	 * NL80211_FEATURE_FULL_AP_CLIENT_STATE.
	 */
	struct nl80211_sta_flag_update flags = {
		.mask = (1 << NL80211_STA_FLAG_AUTHENTICATED) |
			(1 << NL80211_STA_FLAG_ASSOCIATED) |
			(1 << NL80211_STA_FLAG_AUTHORIZED) |
			(1 << NL80211_STA_FLAG_MFP),
		.set = (1 << NL80211_STA_FLAG_AUTHENTICATED) |
			(1 << NL80211_STA_FLAG_ASSOCIATED),
	};

	msg = l_genl_msg_new_sized(NL80211_CMD_NEW_STATION, 300);

	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, 6, sta->addr);
	l_genl_msg_append_attr(msg, NL80211_ATTR_STA_FLAGS2, 8, &flags);

	return msg;
}

static void ap_gtk_op_cb(struct l_genl_msg *msg, void *user_data)
{
	if (l_genl_msg_get_error(msg) < 0) {
		uint8_t cmd = l_genl_msg_get_command(msg);
		const char *cmd_name =
			cmd == NL80211_CMD_NEW_KEY ? "NEW_KEY" :
			cmd == NL80211_CMD_SET_KEY ? "SET_KEY" :
			"DEL_KEY";

		l_error("%s failed for the GTK: %i",
			cmd_name, l_genl_msg_get_error(msg));
	}
}

static void ap_associate_sta_cb(struct l_genl_msg *msg, void *user_data)
{
	struct sta_state *sta = user_data;
	struct ap_state *ap = sta->ap;

	if (l_genl_msg_get_error(msg) < 0) {
		l_error("NEW_STATION/SET_STATION failed: %i",
			l_genl_msg_get_error(msg));
		return;
	}

	/*
	 * Set up the group key.  If this is our first STA then we have
	 * to add the new GTK to the kernel.  In theory we should be
	 * able to supply our own RSC (e.g. generated randomly) and use it
	 * immediately for our 4-Way Handshake without querying the kernel.
	 * However NL80211_CMD_NEW_KEY only lets us set the receive RSC --
	 * the Rx PN for CCMP and the Rx IV for TKIP -- and the
	 * transmit RSC always starts as all zeros.  There's effectively
	 * no way to set the Tx RSC or query the Rx RSC through nl80211.
	 * So we query the Tx RSC in both scenarios just in case some
	 * driver/hardware uses a different initial Tx RSC.
	 *
	 * Optimally we would get called back by the EAPoL state machine
	 * only when building the step 3 of 4 message to query the RSC as
	 * late as possible but that would complicate EAPoL.
	 */
	if (ap->group_cipher != IE_RSN_CIPHER_SUITE_NO_GROUP_TRAFFIC &&
			!ap->gtk_set) {
		enum crypto_cipher group_cipher =
			ie_rsn_cipher_suite_to_cipher(ap->group_cipher);
		int gtk_len = crypto_cipher_key_len(group_cipher);

		/*
		 * Generate our GTK.  Not following the example derivation
		 * method in 802.11-2016 section 12.7.1.4 because a simple
		 * l_getrandom is just as good.
		 */
		l_getrandom(ap->gtk, gtk_len);
		ap->gtk_index = 1;

		msg = nl80211_build_new_key_group(
						netdev_get_ifindex(ap->netdev),
						group_cipher, ap->gtk_index,
						ap->gtk, gtk_len, NULL,
						0, NULL);

		if (!l_genl_family_send(ap->nl80211, msg, ap_gtk_op_cb, NULL,
					NULL)) {
			l_genl_msg_unref(msg);
			l_error("Issuing NEW_KEY failed");
			goto error;
		}

		msg = nl80211_build_set_key(netdev_get_ifindex(ap->netdev),
						ap->gtk_index);
		if (!l_genl_family_send(ap->nl80211, msg, ap_gtk_op_cb, NULL,
					NULL)) {
			l_genl_msg_unref(msg);
			l_error("Issuing SET_KEY failed");
			goto error;
		}

		/*
		 * Set the flag now because any new associating STA will
		 * just use NL80211_CMD_GET_KEY from now.
		 */
		ap->gtk_set = true;
	}

	if (ap->group_cipher == IE_RSN_CIPHER_SUITE_NO_GROUP_TRAFFIC)
		ap_start_rsna(sta, NULL);
	else {
		msg = nl80211_build_get_key(netdev_get_ifindex(ap->netdev),
					ap->gtk_index);
		sta->gtk_query_cmd_id = l_genl_family_send(ap->nl80211, msg,
								ap_gtk_query_cb,
								sta, NULL);
		if (!sta->gtk_query_cmd_id) {
			l_genl_msg_unref(msg);
			l_error("Issuing GET_KEY failed");
			goto error;
		}
	}

	return;

error:
	ap_del_station(sta, MMPDU_REASON_CODE_UNSPECIFIED, true);
}

static void ap_associate_sta(struct ap_state *ap, struct sta_state *sta)
{
	struct l_genl_msg *msg;
	uint32_t ifindex = netdev_get_ifindex(ap->netdev);

	uint8_t rates[256];
	uint32_t r, minr, maxr, count = 0;
	uint16_t capability = l_get_le16(&sta->capability);

	if (sta->associated)
		msg = nl80211_build_set_station_associated(ifindex, sta->addr);
	else
		msg = ap_build_cmd_new_station(sta);

	sta->associated = true;
	sta->rsna = false;

	minr = l_uintset_find_min(sta->rates);
	maxr = l_uintset_find_max(sta->rates);

	for (r = minr; r <= maxr; r++)
		if (l_uintset_contains(sta->rates, r))
			rates[count++] = r;

	l_genl_msg_append_attr(msg, NL80211_ATTR_STA_AID, 2, &sta->aid);
	l_genl_msg_append_attr(msg, NL80211_ATTR_STA_SUPPORTED_RATES,
				count, &rates);
	l_genl_msg_append_attr(msg, NL80211_ATTR_STA_LISTEN_INTERVAL, 2,
				&sta->listen_interval);
	l_genl_msg_append_attr(msg, NL80211_ATTR_STA_CAPABILITY, 2,
				&capability);

	if (!l_genl_family_send(ap->nl80211, msg, ap_associate_sta_cb,
								sta, NULL)) {
		l_genl_msg_unref(msg);
		if (l_genl_msg_get_command(msg) == NL80211_CMD_NEW_STATION)
			l_error("Issuing NEW_STATION failed");
		else
			l_error("Issuing SET_STATION failed");
	}
}

static bool ap_common_rates(struct l_uintset *ap_rates,
				struct l_uintset *sta_rates)
{
	uint32_t minr = l_uintset_find_min(ap_rates);

	/* Our lowest rate is a Basic Rate so must be supported */
	if (l_uintset_contains(sta_rates, minr))
		return true;

	return false;
}

static void ap_success_assoc_resp_cb(struct l_genl_msg *msg, void *user_data)
{
	struct sta_state *sta = user_data;
	struct ap_state *ap = sta->ap;

	sta->assoc_resp_cmd_id = 0;

	if (l_genl_msg_get_error(msg) < 0) {
		l_error("AP (Re)Association Response not sent or not ACKed: %i",
			l_genl_msg_get_error(msg));

		/* If we were in State 3 or 4 go to back to State 2 */
		if (sta->associated)
			ap_del_station(sta, MMPDU_REASON_CODE_UNSPECIFIED,
					true);

		return;
	}

	/* If we were in State 2, 3 or 4 also go to State 3 */
	ap_associate_sta(ap, sta);

	l_info("AP (Re)Association Response ACK received");
}

static void ap_fail_assoc_resp_cb(struct l_genl_msg *msg, void *user_data)
{
	if (l_genl_msg_get_error(msg) < 0)
		l_error("AP (Re)Association Response with an error status not "
			"sent or not ACKed: %i", l_genl_msg_get_error(msg));
	else
		l_info("AP (Re)Association Response with an error status "
			"delivered OK");
}

static uint32_t ap_assoc_resp(struct ap_state *ap, struct sta_state *sta,
				const uint8_t *dest, uint16_t aid,
				enum mmpdu_reason_code status_code,
				bool reassoc, l_genl_msg_func_t callback)
{
	const uint8_t *addr = netdev_get_address(ap->netdev);
	uint8_t mpdu_buf[128];
	struct mmpdu_header *mpdu = (void *) mpdu_buf;
	struct mmpdu_association_response *resp;
	size_t ies_len = 0;
	uint16_t capability = IE_BSS_CAP_ESS | IE_BSS_CAP_PRIVACY;
	uint32_t r, minr, maxr, count;

	memset(mpdu, 0, sizeof(*mpdu));

	/* Header */
	mpdu->fc.protocol_version = 0;
	mpdu->fc.type = MPDU_TYPE_MANAGEMENT;
	mpdu->fc.subtype = reassoc ?
		MPDU_MANAGEMENT_SUBTYPE_REASSOCIATION_RESPONSE :
		MPDU_MANAGEMENT_SUBTYPE_ASSOCIATION_RESPONSE;
	memcpy(mpdu->address_1, dest, 6);	/* DA */
	memcpy(mpdu->address_2, addr, 6);	/* SA */
	memcpy(mpdu->address_3, addr, 6);	/* BSSID */

	/* Association Response body */
	resp = (void *) mmpdu_body(mpdu);
	l_put_le16(capability, &resp->capability);
	resp->status_code = L_CPU_TO_LE16(status_code);
	resp->aid = L_CPU_TO_LE16(aid | 0xc000);

	/* Supported Rates IE */
	resp->ies[ies_len++] = IE_TYPE_SUPPORTED_RATES;

	minr = l_uintset_find_min(ap->rates);
	maxr = l_uintset_find_max(ap->rates);
	count = 0;
	for (r = minr; r <= maxr && count < 8; r++)
		if (l_uintset_contains(ap->rates, r)) {
			uint8_t flag = 0;

			/* Mark only the lowest rate as Basic Rate */
			if (count == 0)
				flag = 0x80;

			resp->ies[ies_len + 1 + count++] = r | flag;
		}

	resp->ies[ies_len++] = count;
	ies_len += count;

	return ap_send_mgmt_frame(ap, mpdu, resp->ies + ies_len - mpdu_buf,
					true, callback, sta);
}

static int ap_parse_supported_rates(struct ie_tlv_iter *iter,
					struct l_uintset **set)
{
	const uint8_t *rates;
	unsigned int len;
	unsigned int i;

	len = ie_tlv_iter_get_length(iter);

	if (ie_tlv_iter_get_tag(iter) == IE_TYPE_SUPPORTED_RATES && len == 0)
		return -EINVAL;

	rates = ie_tlv_iter_get_data(iter);

	if (!*set)
		*set = l_uintset_new(108);

	for (i = 0; i < len; i++) {
		if (rates[i] == 0xff)
			continue;

		l_uintset_put(*set, rates[i] & 0x7f);
	}

	return 0;
}

static void ap_add_interface(struct netdev *netdev)
{
	struct ap_state *ap;

	/*
	 * TODO: Check wiphy supported channels and NL80211_ATTR_TX_FRAME_TYPES
	 */

	/* just allocate/set device, Start method will complete setup */
	ap = l_new(struct ap_state, 1);
	ap->netdev = netdev;
	ap->nl80211 = l_genl_family_new(iwd_get_genl(), NL80211_GENL_NAME);
}

static void ap_remove_interface(struct netdev *netdev)
{
}

static void ap_netdev_watch(struct netdev *netdev,
				enum netdev_watch_event event, void *userdata)
{
	switch (event) {
	case NETDEV_WATCH_EVENT_UP:
	case NETDEV_WATCH_EVENT_NEW:
		if (netdev_get_iftype(netdev) == NETDEV_IFTYPE_AP &&
				netdev_get_is_up(netdev))
			ap_add_interface(netdev);
		break;
	case NETDEV_WATCH_EVENT_DOWN:
	case NETDEV_WATCH_EVENT_DEL:
		ap_remove_interface(netdev);
		break;
	default:
		break;
	}
}

static int ap_init(void)
{
	netdev_watch = netdev_watch_add(ap_netdev_watch, NULL, NULL);

	return 0;
}

static void ap_exit(void)
{
	netdev_watch_remove(netdev_watch);
}

IWD_MODULE(ap, ap_init, ap_exit)
