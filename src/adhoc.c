/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2018-2019  Intel Corporation. All rights reserved.
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

#include <ell/ell.h>

#include "linux/nl80211.h"

#include "src/iwd.h"
#include "src/module.h"
#include "src/netdev.h"
#include "src/wiphy.h"
#include "src/crypto.h"
#include "src/ie.h"
#include "src/util.h"
#include "src/eapol.h"
#include "src/handshake.h"
#include "src/mpdu.h"
#include "src/nl80211util.h"

struct adhoc_state {
	struct netdev *netdev;
	struct l_genl_family *nl80211;
	char *ssid;
	uint8_t pmk[32];
	struct l_queue *sta_states;
	uint32_t sta_watch_id;
	uint32_t netdev_watch_id;
	uint32_t ciphers;
	uint32_t group_cipher;
	uint8_t gtk[CRYPTO_MAX_GTK_LEN];
	uint8_t gtk_index;
	bool started : 1;
	bool open : 1;
	bool gtk_set : 1;
};

struct sta_state {
	uint8_t addr[6];
	struct adhoc_state *adhoc;
	struct eapol_sm *sm;
	struct handshake_state *hs_sta;
	struct eapol_sm *sm_a;
	struct handshake_state *hs_auth;
	uint32_t gtk_query_cmd_id;
	bool hs_sta_done : 1;
	bool hs_auth_done : 1;
	bool authenticated : 1;
};

static uint32_t netdev_watch;

static void adhoc_sta_free(void *data)
{
	struct sta_state *sta = data;

	if (sta->adhoc->open)
		goto end;

	if (sta->gtk_query_cmd_id)
		l_genl_family_cancel(sta->adhoc->nl80211,
						sta->gtk_query_cmd_id);

	if (sta->sm)
		eapol_sm_free(sta->sm);

	if (sta->hs_sta)
		handshake_state_free(sta->hs_sta);

	if (sta->sm_a)
		eapol_sm_free(sta->sm_a);

	if (sta->hs_auth)
		handshake_state_free(sta->hs_auth);

end:
	l_free(sta);
}

static void adhoc_remove_sta(struct sta_state *sta)
{
	if (!l_queue_remove(sta->adhoc->sta_states, sta)) {
		l_error("station %p was not found", sta);
		return;
	}

	if (sta->gtk_query_cmd_id) {
		l_genl_family_cancel(sta->adhoc->nl80211,
						sta->gtk_query_cmd_id);
		sta->gtk_query_cmd_id = 0;
	}

	adhoc_sta_free(sta);
}

static void adhoc_set_rsn_info(struct adhoc_state *adhoc,
						struct ie_rsn_info *rsn)
{
	memset(rsn, 0, sizeof(*rsn));
	rsn->akm_suites = IE_RSN_AKM_SUITE_PSK;
	rsn->pairwise_ciphers = adhoc->ciphers;
	rsn->group_cipher = adhoc->group_cipher;
}

static void adhoc_handshake_event(struct handshake_state *hs,
		enum handshake_event event, void *user_data, ...)
{
	struct sta_state *sta = user_data;

	switch (event) {
	case HANDSHAKE_EVENT_FAILED:
		l_error("handshake failed with STA "MAC, MAC_STR(sta->addr));

		/*
		 * eapol frees the state machines upon handshake failure. Since
		 * this is only a failure on one of the handshakes we need to
		 * set the failing SM to NULL so it will not get double freed
		 * by adhoc_remove_sta.
		 */
		if (sta->hs_auth == hs)
			sta->sm_a = NULL;
		else
			sta->sm = NULL;

		/* fall through */
	case HANDSHAKE_EVENT_SETTING_KEYS_FAILED:
		adhoc_remove_sta(sta);

		return;
	case HANDSHAKE_EVENT_COMPLETE:
		if (sta->hs_auth == hs)
			sta->hs_auth_done = true;

		if (sta->hs_sta == hs)
			sta->hs_sta_done = true;

		if ((sta->hs_auth_done && sta->hs_sta_done) &&
				!sta->authenticated) {
			sta->authenticated = true;
		}
		break;
	default:
		break;
	}
}

static struct eapol_sm *adhoc_new_sm(struct sta_state *sta, bool authenticator,
					const uint8_t *gtk_rsc)
{
	struct adhoc_state *adhoc = sta->adhoc;
	struct netdev *netdev = adhoc->netdev;
	const uint8_t *own_addr = netdev_get_address(netdev);
	struct ie_rsn_info rsn;
	uint8_t bss_rsne[24];
	struct handshake_state *hs;
	struct eapol_sm *sm;

	/* fill in only what handshake setup requires */
	adhoc_set_rsn_info(adhoc, &rsn);
	ie_build_rsne(&rsn, bss_rsne);

	hs = netdev_handshake_state_new(netdev);
	if (!hs) {
		l_error("could not create handshake object");
		return NULL;
	}

	handshake_state_set_event_func(hs, adhoc_handshake_event, sta);
	handshake_state_set_ssid(hs, (void *)adhoc->ssid, strlen(adhoc->ssid));
	/* we dont have the connecting peer rsn info, so just set ap == own */
	handshake_state_set_authenticator_ie(hs, bss_rsne);
	handshake_state_set_supplicant_ie(hs, bss_rsne);
	handshake_state_set_pmk(hs, adhoc->pmk, 32);

	if (authenticator) {
		handshake_state_set_authenticator_address(hs, own_addr);
		handshake_state_set_supplicant_address(hs, sta->addr);
		handshake_state_set_authenticator(hs, true);
	} else {
		handshake_state_set_authenticator_address(hs, sta->addr);
		handshake_state_set_supplicant_address(hs, own_addr);
	}

	if (gtk_rsc)
		handshake_state_set_gtk(hs, adhoc->gtk, adhoc->gtk_index,
					gtk_rsc);

	sm = eapol_sm_new(hs);
	if (!sm) {
		l_error("could not create sm object");
		return NULL;
	}

	eapol_sm_set_listen_interval(sm, 100);

	if (authenticator)
		sta->hs_auth = hs;
	else
		sta->hs_sta = hs;

	return sm;
}

static void adhoc_add_interface(struct netdev *netdev)
{
	struct adhoc_state *adhoc;

	/* just allocate/set device, Start method will complete setup */
	adhoc = l_new(struct adhoc_state, 1);
	adhoc->netdev = netdev;
	adhoc->nl80211 = l_genl_family_new(iwd_get_genl(), NL80211_GENL_NAME);
}

static void adhoc_netdev_watch(struct netdev *netdev,
				enum netdev_watch_event event, void *userdata)
{
	switch (event) {
	case NETDEV_WATCH_EVENT_UP:
	case NETDEV_WATCH_EVENT_NEW:
		if (netdev_get_iftype(netdev) == NETDEV_IFTYPE_ADHOC &&
				netdev_get_is_up(netdev))
			adhoc_add_interface(netdev);
		break;
	case NETDEV_WATCH_EVENT_DOWN:
	case NETDEV_WATCH_EVENT_DEL:
		break;
	default:
		break;
	}
}

static int adhoc_init(void)
{
	netdev_watch = netdev_watch_add(adhoc_netdev_watch, NULL, NULL);

	return 0;
}

static void adhoc_exit(void)
{
	netdev_watch_remove(netdev_watch);
}

IWD_MODULE(adhoc, adhoc_init, adhoc_exit)
