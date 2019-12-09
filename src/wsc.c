/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2015-2019  Intel Corporation. All rights reserved.
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
#include <stdio.h>
#include <ell/ell.h>

#include "src/missing.h"
#include "src/module.h"
#include "src/netdev.h"
#include "src/wiphy.h"
#include "src/station.h"
#include "src/scan.h"
#include "src/ie.h"
#include "src/wscutil.h"
#include "src/util.h"
#include "src/handshake.h"
#include "src/eap-wsc.h"
#include "src/crypto.h"
#include "src/common.h"
#include "src/storage.h"
#include "src/iwd.h"
#include "src/network.h"
#include "src/wsc.h"

#define WALK_TIME 120

static uint32_t netdev_watch = 0;

struct wsc {
	struct netdev *netdev;
	struct station *station;
	uint8_t *wsc_ies;
	size_t wsc_ies_size;
	struct l_timeout *walk_timer;
	uint32_t scan_id;
	struct scan_bss *target;
	uint32_t station_state_watch;
	struct wsc_credentials_info creds[3];
	uint32_t n_creds;
	struct l_settings *eap_settings;

	bool wsc_association : 1;
};

static inline enum wsc_rf_band freq_to_rf_band(uint32_t freq)
{
	enum scan_band band;

	scan_freq_to_channel(freq, &band);

	switch (band) {
	case SCAN_BAND_2_4_GHZ:
		return WSC_RF_BAND_2_4_GHZ;
	case SCAN_BAND_5_GHZ:
		return WSC_RF_BAND_5_0_GHZ;
	}

	return WSC_RF_BAND_2_4_GHZ;
}

static void wsc_add_interface(struct netdev *netdev)
{
	struct wsc *wsc;

	if (!wiphy_get_max_scan_ie_len(netdev_get_wiphy(netdev))) {
		l_debug("Simple Configuration isn't supported by ifindex %u",
						netdev_get_ifindex(netdev));

		return;
	}

	wsc = l_new(struct wsc, 1);
	wsc->netdev = netdev;
}

static void wsc_remove_interface(struct netdev *netdev)
{
}

static void wsc_netdev_watch(struct netdev *netdev,
				enum netdev_watch_event event, void *userdata)
{
	switch (event) {
	case NETDEV_WATCH_EVENT_UP:
	case NETDEV_WATCH_EVENT_NEW:
		if (netdev_get_iftype(netdev) == NETDEV_IFTYPE_STATION &&
				netdev_get_is_up(netdev))
			wsc_add_interface(netdev);
		break;
	case NETDEV_WATCH_EVENT_DOWN:
	case NETDEV_WATCH_EVENT_DEL:
		wsc_remove_interface(netdev);
		break;
	default:
		break;
	}
}

static int wsc_init(void)
{
	l_debug("");
	netdev_watch = netdev_watch_add(wsc_netdev_watch, NULL, NULL);
	return 0;
}

static void wsc_exit(void)
{
	l_debug("");
	netdev_watch_remove(netdev_watch);
}

IWD_MODULE(wsc, wsc_init, wsc_exit)
