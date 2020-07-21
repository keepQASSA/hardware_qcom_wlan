/*
 * Driver interaction with extended Linux CFG8021
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 */

#include "includes.h"
#include <sys/types.h>
#include <fcntl.h>
#include <net/if.h>
#include <netlink/object-api.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <linux/pkt_sched.h>

#include "common.h"
#include "linux_ioctl.h"
#include "driver_nl80211.h"
#include "wpa_supplicant_i.h"
#include "config.h"
#ifdef LINUX_EMBEDDED
#include <sys/ioctl.h>
#endif
#if defined(ANDROID) || defined(LINUX_EMBEDDED)
#include "android_drv.h"
#endif
#include "driver_cmd_nl80211_extn.h"

#define WPA_PS_ENABLED		0
#define WPA_PS_DISABLED		1
#define UNUSED(x)	(void)(x)

#define TWT_SETUP_WAKE_INTVL_MANTISSA_MAX       0xFFFF
#define TWT_SETUP_WAKE_DURATION_MAX             0xFF
#define TWT_SETUP_WAKE_INTVL_EXP_MAX            31

#define TWT_SETUP_STR "TWT_SETUP"
#define TWT_SETUP_STRLEN strlen(TWT_SETUP_STR)
#define TWT_CMD_NOT_EXIST -EINVAL
#define DEFAULT_IFNAME "wlan0"
#define TWT_RESP_BUF_LEN 512

#define SINGLE_SPACE_LEN 1
#define SINGLE_DIGIT_LEN 1

#define DIALOG_ID_STR           "dialog_id"
#define REQ_TYPE_STR            "req_type"
#define TRIG_TYPE_STR           "trig_type"
#define FLOW_TYPE_STR           "flow_type"
#define WAKE_INTR_EXP_STR       "wake_intr_exp"
#define PROTECTION_STR          "protection"
#define WAKE_TIME_STR           "wake_time"
#define WAKE_DUR_STR            "wake_dur"
#define WAKE_INTR_MANTISSA_STR  "wake_intr_mantissa"
#define BROADCAST_STR           "broadcast"

#define DIALOG_ID_STR_LEN                   strlen(DIALOG_ID_STR)
#define REQ_TYPE_STR_LEN                strlen(REQ_TYPE_STR)
#define TRIG_TYPE_STR_LEN               strlen(TRIG_TYPE_STR)
#define FLOW_TYPE_STR_LEN               strlen(FLOW_TYPE_STR)
#define WAKE_INTR_EXP_STR_LEN           strlen(WAKE_INTR_EXP_STR)
#define PROTECTION_STR_LEN              strlen(PROTECTION_STR)
#define WAKE_TIME_STR_LEN               strlen(WAKE_TIME_STR)
#define WAKE_DUR_STR_LEN                strlen(WAKE_DUR_STR)
#define WAKE_INTR_MANTISSA_STR_LEN      strlen(WAKE_INTR_MANTISSA_STR)
#define BROADCAST_STR_LEN               strlen(BROADCAST_STR)

struct twt_setup_parameters {
	u8 dialog_id;
	u8 req_type;
	u8 trig_type;
	u8 flow_type;
	u8 wake_intr_exp;
	u8 protection;
	u32 wake_time;
	u32 wake_dur;
	u32 wake_intr_mantissa;
	u8 bcast;
};

struct twt_resp_info {
	char *reply_buf;
	int reply_buf_len;
	enum qca_wlan_twt_operation twt_oper;
	struct wpa_driver_nl80211_data *drv;
};

/* Return type for setBand*/
enum {
	SEND_CHANNEL_CHANGE_EVENT = 0,
	DO_NOT_SEND_CHANNEL_CHANGE_EVENT,
};

typedef struct android_wifi_priv_cmd {
	char *buf;
	int used_len;
	int total_len;
} android_wifi_priv_cmd;

static int drv_errors = 0;

static void wpa_driver_notify_country_change(void *ctx, char *cmd)
{
	if ((os_strncasecmp(cmd, "COUNTRY", 7) == 0) ||
	    (os_strncasecmp(cmd, "SETBAND", 7) == 0)) {
		union wpa_event_data event;

		os_memset(&event, 0, sizeof(event));
		event.channel_list_changed.initiator = REGDOM_SET_BY_USER;
		if (os_strncasecmp(cmd, "COUNTRY", 7) == 0) {
			event.channel_list_changed.type = REGDOM_TYPE_COUNTRY;
			if (os_strlen(cmd) > 9) {
				event.channel_list_changed.alpha2[0] = cmd[8];
				event.channel_list_changed.alpha2[1] = cmd[9];
			}
		} else {
			event.channel_list_changed.type = REGDOM_TYPE_UNKNOWN;
		}
		wpa_supplicant_event(ctx, EVENT_CHANNEL_LIST_CHANGED, &event);
	}
}

int check_for_twt_cmd(char **cmd)
{
	if (os_strncasecmp(*cmd, TWT_SETUP_STR, TWT_SETUP_STRLEN) == 0) {
		*cmd += (TWT_SETUP_STRLEN + 1);
		return QCA_WLAN_TWT_SET;
	}

	wpa_printf(MSG_DEBUG, "Not a TWT command");
	return TWT_CMD_NOT_EXIST;
}

static int pack_nlmsg_vendor_hdr(struct nl_msg *drv_nl_msg,
				 struct wpa_driver_nl80211_data *drv,
				 char *ifname)
{
	int ret;
	int ifindex;

	genlmsg_put(drv_nl_msg, NL_AUTO_PORT, NL_AUTO_SEQ,
		    drv->global->nl80211_id, 0, 0,
		    NL80211_CMD_VENDOR, 0);

	ret = nla_put_u32(drv_nl_msg, NL80211_ATTR_VENDOR_ID, OUI_QCA);
	if (ret < 0) {
		wpa_printf(MSG_ERROR, "Failed to put vendor id");
		return ret;
	}

	ret = nla_put_u32(drv_nl_msg, NL80211_ATTR_VENDOR_SUBCMD,
			  QCA_NL80211_VENDOR_SUBCMD_CONFIG_TWT);
	if (ret < 0) {
		wpa_printf(MSG_DEBUG, "nl put twt vendor subcmd failed");
		return ret;
	}

	if (ifname && (strlen(ifname) > 0))
		ifindex = if_nametoindex(ifname);
	else
		ifindex = if_nametoindex(DEFAULT_IFNAME);

	ret = nla_put_u32(drv_nl_msg, NL80211_ATTR_IFINDEX, ifindex);
	if (ret < 0) {
		wpa_printf(MSG_DEBUG, "nl put iface: %s failed", ifname);
		return ret;
	}
	return ret;
}

static u32 get_u32_from_string(char *cmd_string, int *ret)
{
	u32 val = 0;
	char *cmd = cmd_string;

	while (*cmd != ' ')
		cmd++;

	*ret = 0;
	errno = 0;
	val = strtol(cmd_string, NULL, 10);
	if (errno == ERANGE || (errno != 0 && val == 0)) {
		wpa_printf(MSG_ERROR, "invalid value");
		*ret = -EINVAL;
        }
	return val;
}

static u8 get_u8_from_string(char *cmd_string, int *ret)
{
	char *cmd = cmd_string;
	u8 val = 0;

	while (*cmd != ' ')
		cmd++;

	*ret = 0;
	errno = 0;
	val = strtol(cmd_string, NULL, 10) & 0xFF;
	if (errno == ERANGE || (errno != 0 && val == 0)) {
		wpa_printf(MSG_ERROR, "invalid value");
		*ret = -EINVAL;
        }
	return val;
}

char *move_to_next_str(char *cmd)
{
	while (*cmd != ' ')
		cmd++;

	while (*cmd == ' ')
		cmd++;

	return cmd;
}

static int is_binary(u8 value) {
	if(value == 0 || value == 1)
		return 0;
	return -1;
}

static
void print_setup_cmd_values(struct twt_setup_parameters *twt_setup_params)
{
	wpa_printf(MSG_DEBUG, "TWT: setup dialog_id: %x",
		   twt_setup_params->dialog_id);
	wpa_printf(MSG_DEBUG, "TWT: setup req type: %d ",
		   twt_setup_params->req_type);
	wpa_printf(MSG_DEBUG, "TWT: setup trig type: %d ",
		   twt_setup_params->trig_type);
	wpa_printf(MSG_DEBUG, "TWT: setup flow type: 0x%x",
		   twt_setup_params->flow_type);
	wpa_printf(MSG_DEBUG, "TWT: setup wake exp: 0x%x",
		   twt_setup_params->wake_intr_exp);
	wpa_printf(MSG_DEBUG, "TWT: setup protection: 0x%x",
		   twt_setup_params->protection);
	wpa_printf(MSG_DEBUG, "TWT: setup wake time: 0x%x",
		   twt_setup_params->wake_time);
	wpa_printf(MSG_DEBUG, "TWT: setup wake dur: 0x%x",
		   twt_setup_params->wake_dur);
	wpa_printf(MSG_DEBUG, "TWT: setup wake intr mantissa: 0x%x",
		   twt_setup_params->wake_intr_mantissa);
	wpa_printf(MSG_DEBUG, "TWT: setup bcast: %d ",
		   twt_setup_params->bcast);
}

static int check_cmd_input(char *cmd_string)
{
	u32 cmd_string_len;

	if (!cmd_string) {
		wpa_printf(MSG_ERROR, "cmd string null");
		return -EINVAL;
	}
	cmd_string_len = strlen(cmd_string);
	wpa_printf(MSG_DEBUG, "cmd string : %s len = %u", cmd_string,
		   cmd_string_len);
	if (cmd_string_len < DIALOG_ID_STR_LEN + SINGLE_SPACE_LEN +
			     SINGLE_DIGIT_LEN) {
		wpa_printf(MSG_ERROR, "Dialog_id parameter missing");
		return -EINVAL;
	}

	return 0;
}

static
int process_twt_setup_cmd_string(char *cmd,
				 struct twt_setup_parameters *twt_setup_params)
{
	int ret = 0;

	if (!twt_setup_params) {
		wpa_printf(MSG_ERROR, "cmd or twt_setup_params null");
		return -EINVAL;
	}

	if (check_cmd_input(cmd))
		return -EINVAL;

	wpa_printf(MSG_DEBUG, "process twt setup command string: %s", cmd);
	while (*cmd == ' ')
		cmd++;

	if (os_strncasecmp(cmd, DIALOG_ID_STR, DIALOG_ID_STR_LEN) == 0) {
		cmd += (DIALOG_ID_STR_LEN + 1);
		twt_setup_params->dialog_id = get_u8_from_string(cmd, &ret);
		if (ret < 0)
			return ret;
		cmd = move_to_next_str(cmd);
	}

	if (os_strncasecmp(cmd, REQ_TYPE_STR, REQ_TYPE_STR_LEN) == 0) {
		cmd += (REQ_TYPE_STR_LEN + 1);
		twt_setup_params->req_type = get_u8_from_string(cmd, &ret);
		if (ret < 0)
			return ret;
		cmd = move_to_next_str(cmd);
	}

	if (os_strncasecmp(cmd, TRIG_TYPE_STR, TRIG_TYPE_STR_LEN) == 0) {
		cmd += (TRIG_TYPE_STR_LEN + 1);
		twt_setup_params->trig_type = get_u8_from_string(cmd, &ret);
		if (ret < 0)
			return ret;

		if (is_binary(twt_setup_params->trig_type)) {
			wpa_printf(MSG_ERROR, "Invalid trigger type");
			return -EINVAL;
		}
		cmd = move_to_next_str(cmd);
	}

	if (strncmp(cmd, FLOW_TYPE_STR, FLOW_TYPE_STR_LEN) == 0) {
		cmd += (FLOW_TYPE_STR_LEN + 1);
		twt_setup_params->flow_type = get_u8_from_string(cmd, &ret);
		if (ret < 0)
			return ret;

		if (is_binary(twt_setup_params->flow_type)) {
			wpa_printf(MSG_ERROR, "Invalid flow type");
			return -EINVAL;
		}
		cmd = move_to_next_str(cmd);
	}

	if (strncmp(cmd, WAKE_INTR_EXP_STR, WAKE_INTR_EXP_STR_LEN) == 0) {
		cmd += (WAKE_INTR_EXP_STR_LEN + 1);
		twt_setup_params->wake_intr_exp = get_u8_from_string(cmd, &ret);
		if (ret < 0)
			return ret;

		if (twt_setup_params->wake_intr_exp >
		    TWT_SETUP_WAKE_INTVL_EXP_MAX) {
			wpa_printf(MSG_DEBUG, "Invalid wake_intr_exp %u",
				   twt_setup_params->wake_intr_exp);
			return -EINVAL;
		}
		cmd = move_to_next_str(cmd);
	}

	if (strncmp(cmd, PROTECTION_STR, PROTECTION_STR_LEN) == 0) {
		cmd += (PROTECTION_STR_LEN + 1);
		twt_setup_params->protection = get_u8_from_string(cmd, &ret);
		if (ret < 0)
			return ret;

		if (is_binary(twt_setup_params->protection)) {
			wpa_printf(MSG_ERROR, "Invalid protection value");
			return -EINVAL;
		}
		cmd = move_to_next_str(cmd);
	}

	if (strncmp(cmd, WAKE_TIME_STR, WAKE_TIME_STR_LEN) == 0) {
		cmd += (WAKE_TIME_STR_LEN + 1);
		twt_setup_params->wake_time = get_u32_from_string(cmd, &ret);
		if (ret < 0)
			return ret;
		cmd = move_to_next_str(cmd);
	}

	if (strncmp(cmd, WAKE_DUR_STR, WAKE_DUR_STR_LEN) == 0) {
		cmd += (WAKE_DUR_STR_LEN + 1);
		twt_setup_params->wake_dur = get_u32_from_string(cmd, &ret);
		if (ret < 0)
			return ret;

		if (twt_setup_params->wake_dur == 0 ||
		    twt_setup_params->wake_dur > TWT_SETUP_WAKE_DURATION_MAX) {
			wpa_printf(MSG_ERROR, "Invalid wake_dura_us %u",
				   twt_setup_params->wake_dur);
			return -EINVAL;
		}

		cmd = move_to_next_str(cmd);
	}

	if (strncmp(cmd, WAKE_INTR_MANTISSA_STR,
		    WAKE_INTR_MANTISSA_STR_LEN) == 0) {
		cmd += (WAKE_INTR_MANTISSA_STR_LEN + 1);
		twt_setup_params->wake_intr_mantissa = get_u32_from_string(cmd, &ret);
		if (ret < 0)
			return ret;
		if (twt_setup_params->wake_intr_mantissa >
		    TWT_SETUP_WAKE_INTVL_MANTISSA_MAX) {
			wpa_printf(MSG_ERROR, "Invalid wake_intr_mantissa %u",
				   twt_setup_params->wake_intr_mantissa);
			return -EINVAL;
		}

		cmd = move_to_next_str(cmd);
	}

	if (strncmp(cmd, BROADCAST_STR, BROADCAST_STR_LEN) == 0) {
		cmd += (BROADCAST_STR_LEN + 1);
		twt_setup_params->bcast = get_u8_from_string(cmd, &ret);
		if (ret < 0)
			return ret;

		if (is_binary(twt_setup_params->bcast)) {
			wpa_printf(MSG_ERROR, "Invalid broadcast value");
			return -EINVAL;
		}
		cmd = move_to_next_str(cmd);
	}

	print_setup_cmd_values(twt_setup_params);

	return 0;
}

static
int prepare_twt_setup_nlmsg(struct nl_msg *nlmsg,
			    struct twt_setup_parameters *twt_setup_params)
{
	struct nlattr *twt_attr;

	if (nla_put_u8(nlmsg, QCA_WLAN_VENDOR_ATTR_CONFIG_TWT_OPERATION,
		       QCA_WLAN_TWT_SET)) {
		wpa_printf(MSG_DEBUG, "TWT: Failed to put QCA_WLAN_TWT_SET");
		goto fail;
	}

	twt_attr = nla_nest_start(nlmsg,
				  QCA_WLAN_VENDOR_ATTR_CONFIG_TWT_PARAMS);
	if (twt_attr == NULL)
		goto fail;

	if (nla_put_u8(nlmsg, QCA_WLAN_VENDOR_ATTR_TWT_SETUP_FLOW_ID,
		       twt_setup_params->dialog_id)) {
		wpa_printf(MSG_DEBUG, "TWT: Failed to put dialog_id");
		goto fail;
	}

	if (nla_put_u8(nlmsg, QCA_WLAN_VENDOR_ATTR_TWT_SETUP_REQ_TYPE,
		       twt_setup_params->req_type)) {
		wpa_printf(MSG_DEBUG, "TWT: Failed to put req type");
		goto fail;
	}

	if (twt_setup_params->trig_type) {
		if (nla_put_flag(nlmsg, QCA_WLAN_VENDOR_ATTR_TWT_SETUP_TRIGGER)
				 ) {
			wpa_printf(MSG_DEBUG, "TWT: Failed to put trig type");
			goto fail;
		}
	}

	/*0 - Announced/ 1 - Unannounced*/
	if (nla_put_u8(nlmsg, QCA_WLAN_VENDOR_ATTR_TWT_SETUP_FLOW_TYPE,
		       twt_setup_params->flow_type)) {
		wpa_printf(MSG_DEBUG, "TWT: Failed to put flow type");
		goto fail;
	}

	if (nla_put_u8(nlmsg,
		       QCA_WLAN_VENDOR_ATTR_TWT_SETUP_WAKE_INTVL_EXP,
		       twt_setup_params->wake_intr_exp)) {
		wpa_printf(MSG_DEBUG, "TWT: Failed to put wake exp");
		goto fail;
	}

	if (twt_setup_params->protection) {
		if (nla_put_flag(nlmsg,
		    QCA_WLAN_VENDOR_ATTR_TWT_SETUP_PROTECTION)) {
			wpa_printf(MSG_DEBUG,
				   "TWT: Failed to add protection");
			goto fail;
		}
	}

	/*offset to add with TBTT after which 1st SP will start*/
	if (nla_put_u32(nlmsg,
			QCA_WLAN_VENDOR_ATTR_TWT_SETUP_WAKE_TIME,
			twt_setup_params->wake_time)) {
		wpa_printf(MSG_DEBUG, "TWT: Failed to put wake time");
		goto fail;
	}

	/*TWT Wake Duration in units of us, must be <= 65280*/
	if (nla_put_u32(nlmsg,
			QCA_WLAN_VENDOR_ATTR_TWT_SETUP_WAKE_DURATION,
			twt_setup_params->wake_dur)) {
		wpa_printf(MSG_DEBUG, "TWT: Failed to put wake dur");
		goto fail;
	}

	if (nla_put_u32(nlmsg,
		QCA_WLAN_VENDOR_ATTR_TWT_SETUP_WAKE_INTVL_MANTISSA,
		twt_setup_params->wake_intr_mantissa)) {
		wpa_printf(MSG_DEBUG, "TWT: Failed to put wake intr mantissa");
		goto fail;
	}

	if (twt_setup_params->bcast) {
		if (nla_put_flag(nlmsg,
			QCA_WLAN_VENDOR_ATTR_TWT_SETUP_BCAST)) {
			wpa_printf(MSG_DEBUG, "TWT: Failed to put bcast");
			goto fail;
		}
	}

	nla_nest_end(nlmsg, twt_attr);
	wpa_printf(MSG_DEBUG, "TWT: setup command nla end");
	return 0;

fail:
	return -EINVAL;
}

static int pack_nlmsg_twt_params(struct nl_msg *twt_nl_msg, char *cmd,
				 enum qca_wlan_twt_operation type)
{
	struct nlattr *attr;
	int ret = 0;
	struct twt_setup_parameters params = {0};

	attr = nla_nest_start(twt_nl_msg, NL80211_ATTR_VENDOR_DATA);
	if (attr == NULL)
		return -EINVAL;

	switch (type) {
	case QCA_WLAN_TWT_SET:
		if (process_twt_setup_cmd_string(cmd, &params))
			return -EINVAL;
		ret = prepare_twt_setup_nlmsg(twt_nl_msg, &params);
		break;
	default:
		wpa_printf(MSG_DEBUG, "Unsupported command: %d", type);
		ret = -EINVAL;
		break;
	}

	if (!ret)
		nla_nest_end(twt_nl_msg, attr);

	return ret;
}

char *result_copy_to_buf(char *src, char *dst_buf, int *dst_len)
{
	int str_len, remaining = 0;

	remaining = *dst_len;
	str_len = strlen(src);
	remaining = remaining - (str_len + 1);

	if (remaining <= 0) {
		wpa_printf(MSG_ERROR, "destination buffer length not enough");
		return NULL;
	}
	os_memcpy(dst_buf, src, str_len);

	*dst_len = remaining;
	*(dst_buf + str_len) = ' ';

	return (dst_buf + str_len + 1);
}

static int wpa_get_twt_setup_resp_val(struct nlattr **tb2, char *buf,
				      int buf_len)
{
	uint32_t wake_intvl_exp = 0, wake_intvl_mantis = 0;
	int cmd_id, val;
	uint32_t value;
	unsigned long wake_tsf;
	char temp[TWT_RESP_BUF_LEN];

	os_memset(temp, 0, TWT_RESP_BUF_LEN);
	cmd_id = QCA_WLAN_VENDOR_ATTR_TWT_SETUP_FLOW_ID;
	if (!tb2[cmd_id]) {
		wpa_printf(MSG_ERROR, "TWT dialog id missing");
		return -EINVAL;
	}
	val = nla_get_u8(tb2[cmd_id]);
	os_snprintf(temp, TWT_RESP_BUF_LEN, "dialog_id %d ", val);
	buf = result_copy_to_buf(temp, buf, &buf_len);
	if (!buf)
		return -EINVAL;

	cmd_id = QCA_WLAN_VENDOR_ATTR_TWT_SETUP_STATUS;
	if (!tb2[cmd_id]) {
		wpa_printf(MSG_ERROR, "TWT resp status missing");
		return -EINVAL;
	}
	val = nla_get_u8(tb2[cmd_id]);
	os_snprintf(temp, TWT_RESP_BUF_LEN, "status %d ", val);
	buf = result_copy_to_buf(temp, buf, &buf_len);
	if (!buf)
		return -EINVAL;

	cmd_id = QCA_WLAN_VENDOR_ATTR_TWT_SETUP_RESP_TYPE;
	if (!tb2[cmd_id]) {
		wpa_printf(MSG_ERROR, "TWT resp type missing");
		return -EINVAL;
	}
	val = nla_get_u8(tb2[cmd_id]);
	os_snprintf(temp, TWT_RESP_BUF_LEN, "resp_reason %d ", val);
	buf = result_copy_to_buf(temp, buf, &buf_len);
	if (!buf)
		return -EINVAL;

	cmd_id = QCA_WLAN_VENDOR_ATTR_TWT_SETUP_WAKE_INTVL_EXP;
	if (!tb2[cmd_id]) {
		wpa_printf(MSG_ERROR, "TWT_SETUP_WAKE_INTVL_EXP is must");
		return -EINVAL;
	}
	wake_intvl_exp = nla_get_u8(tb2[cmd_id]);
	os_snprintf(temp, TWT_RESP_BUF_LEN, "wake_intvl_exp %d ",
		    wake_intvl_exp);
	buf = result_copy_to_buf(temp, buf, &buf_len);
	if (!buf)
		return -EINVAL;

	val = 0;
	cmd_id = QCA_WLAN_VENDOR_ATTR_TWT_SETUP_BCAST;
	if (tb2[cmd_id])
		val = nla_get_flag(tb2[cmd_id]);

	os_snprintf(temp, TWT_RESP_BUF_LEN, "bcast %d", val);
	buf = result_copy_to_buf(temp, buf, &buf_len);
	if (!buf)
		return -EINVAL;

	val = 0;
	cmd_id = QCA_WLAN_VENDOR_ATTR_TWT_SETUP_TRIGGER;
	if (tb2[cmd_id])
		val = nla_get_flag(tb2[cmd_id]);

	os_snprintf(temp, TWT_RESP_BUF_LEN, "trig_type %d", val);
	buf = result_copy_to_buf(temp, buf, &buf_len);
	if (!buf)
		return -EINVAL;

	cmd_id = QCA_WLAN_VENDOR_ATTR_TWT_SETUP_FLOW_TYPE;
	if (!tb2[cmd_id]) {
		wpa_printf(MSG_ERROR, "TWT_SETUP_FLOW_TYPE is must");
		return -EINVAL;
	}
	val = nla_get_u8(tb2[cmd_id]);
	os_snprintf(temp, TWT_RESP_BUF_LEN, "flow_type %d", val);
	buf = result_copy_to_buf(temp, buf, &buf_len);
	if (!buf)
		return -EINVAL;

	val = 0;
	cmd_id = QCA_WLAN_VENDOR_ATTR_TWT_SETUP_PROTECTION;
	if (tb2[cmd_id])
		val = nla_get_flag(tb2[cmd_id]);
	os_snprintf(temp, TWT_RESP_BUF_LEN, "protection %d", val);
	buf = result_copy_to_buf(temp, buf, &buf_len);
	if (!buf)
		return -EINVAL;

	value = 0;
	cmd_id = QCA_WLAN_VENDOR_ATTR_TWT_SETUP_WAKE_TIME;
	if (tb2[cmd_id])
		value = nla_get_u32(tb2[cmd_id]);
	os_snprintf(temp, TWT_RESP_BUF_LEN, "wake_time 0x%x", value);
	buf = result_copy_to_buf(temp, buf, &buf_len);
	if (!buf)
		return -EINVAL;

	cmd_id = QCA_WLAN_VENDOR_ATTR_TWT_SETUP_WAKE_DURATION;
	if (!tb2[cmd_id]) {
		wpa_printf(MSG_ERROR, "TWT_SETUP_WAKE_DURATION is must");
		return -EINVAL;
	}
	value = nla_get_u32(tb2[cmd_id]);
	os_snprintf(temp, TWT_RESP_BUF_LEN, "wake_dur %d", value);
	buf = result_copy_to_buf(temp, buf, &buf_len);
	if (!buf)
		return -EINVAL;

	cmd_id =
	QCA_WLAN_VENDOR_ATTR_TWT_SETUP_WAKE_INTVL_MANTISSA;
	if (!tb2[cmd_id]) {
		wpa_printf(MSG_ERROR, "SETUP_WAKE_INTVL_MANTISSA is must");
		return -EINVAL;
	}
	wake_intvl_mantis = nla_get_u32(tb2[cmd_id]);
	os_snprintf(temp, TWT_RESP_BUF_LEN, "wake_intvl %d", wake_intvl_mantis);
	buf = result_copy_to_buf(temp, buf, &buf_len);
	if (!buf)
		return -EINVAL;

	wake_tsf = 0;
	cmd_id = QCA_WLAN_VENDOR_ATTR_TWT_SETUP_WAKE_TIME_TSF;
	if (tb2[cmd_id])
		wake_tsf = nla_get_u64(tb2[cmd_id]);
	os_snprintf(temp, TWT_RESP_BUF_LEN, "wake_tsf 0x%lx", wake_tsf);
	buf = result_copy_to_buf(temp, buf, &buf_len);
	if (!buf)
		return -EINVAL;

	val = 0;
	cmd_id = QCA_WLAN_VENDOR_ATTR_TWT_SETUP_TWT_INFO_ENABLED;
	if (tb2[cmd_id])
		val = nla_get_flag(tb2[cmd_id]);

	os_snprintf(temp, TWT_RESP_BUF_LEN, "info_enabled %d", val);
	buf = result_copy_to_buf(temp, buf, &buf_len);
	if (!buf)
		return -EINVAL;
	*buf = '\0';

	return 0;
}

int unpack_twt_setup_nlmsg(struct nlattr **tb, char *buf, int buf_len)
{
	int ret = 0;
	struct nlattr *tb2[QCA_WLAN_VENDOR_ATTR_TWT_SETUP_MAX + 1];

	if (nla_parse_nested(tb2, QCA_WLAN_VENDOR_ATTR_TWT_SETUP_MAX,
			     tb[NL80211_ATTR_VENDOR_DATA], NULL)) {
		wpa_printf(MSG_ERROR, "nla_parse failed for vendor_data\n");
		return -EINVAL;
	}

	ret = wpa_get_twt_setup_resp_val(tb2, buf, buf_len);

	return ret;
}

static int unpack_nlmsg_twt_params(struct nl_msg *twt_nl_msg,
				   enum qca_wlan_twt_operation type,
				   char *buf, int buf_len)
{
	int ret = 0;
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(twt_nl_msg));

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	switch (type) {
	case QCA_WLAN_TWT_SET:
		ret = unpack_twt_setup_nlmsg(tb, buf, buf_len);
		break;
	default:
		wpa_printf(MSG_DEBUG, "Unsupported command: %d", type);
		ret = -EINVAL;
		break;
	}

	return ret;
}

static int twt_response_handler(struct nl_msg *msg, void *arg)
{
	struct twt_resp_info *info = (struct twt_resp_info *) arg;
	struct wpa_driver_nl80211_data *drv = NULL;
	int ret;

	drv = info->drv;
	ret = unpack_nlmsg_twt_params(msg, info->twt_oper, info->reply_buf,
				      info->reply_buf_len);
	wpa_printf(MSG_DEBUG, "%s - twt_oper %d", __func__, info->twt_oper);
	if (!ret)
		wpa_msg(drv->ctx, MSG_INFO,
			WPA_EVENT_DRIVER_STATE "TWT: %s : OK", info->reply_buf);
	else
		wpa_msg(drv->ctx, MSG_INFO,
			WPA_EVENT_DRIVER_STATE "TWT: %s : Error = %d",
			info->reply_buf, ret);

	return ret;
}

static int ack_handler(struct nl_msg *msg, void *arg)
{
	int *err = (int *)arg;

	*err = 0;
	return NL_STOP;
}

static int finish_handler(struct nl_msg *msg, void *arg)
{
	int *ret = (int *)arg;

	*ret = 0;
	return NL_SKIP;
}

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
			 void *arg)
{
	int *ret = (int *)arg;

	*ret = err->error;
	wpa_printf(MSG_DEBUG, "%s received : %d - %s", __func__,
		   err->error, strerror(err->error));
	return NL_SKIP;
}

static int no_seq_check(struct nl_msg *msg, void *arg)
{
	return NL_OK;
}

int send_nlmsg_get_resp(struct nl_sock *drv_nl_sock, struct nl_msg *drv_nl_msg,
			int (*valid_handler)(struct nl_msg *, void *),
			void *valid_data)
{
	struct nl_cb *cb;
	int err;

	cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!cb)
		return -ENOMEM;

	err = nl_send_auto_complete(drv_nl_sock, drv_nl_msg);
	if (err < 0) {
		wpa_printf(MSG_ERROR,
			   "nl_send_auto_complete: failed with err=%d", err);
		goto free_mem;
	}

	err = 1;

	nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, NULL);
	nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);
	if (valid_handler)
		nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM,
			  valid_handler, valid_data);

	while (err > 0) {
		int res = nl_recvmsgs(drv_nl_sock, cb);

		if (res < 0) {
			wpa_printf(MSG_ERROR,
				   "%s nl_recvmsgs failed: ret=%d, err=%d",
				    __func__, res, err);
		}
	}

free_mem:
	nl_cb_put(cb);
	return err;
}

static int wpa_driver_twt_cmd_handler(struct wpa_driver_nl80211_data *drv,
				      char *ifname,
				      enum qca_wlan_twt_operation twt_oper,
				      char *param, char *buf,
				      size_t buf_len, int *status)
{
	struct nl_msg *twt_nl_msg;
	struct twt_resp_info reply_info;
	int ret = 0;

	if (!param) {
		wpa_printf(MSG_ERROR, "%s:TWT cmd args missing\n", __func__);
		return -EINVAL;
	}

	if (!buf) {
		wpa_printf(MSG_ERROR, "buf is NULL");
		return -EINVAL;
	}

	wpa_printf(MSG_DEBUG, "TWT DRIVER cmd: %s", param);

	memset(&reply_info, 0, sizeof(struct twt_resp_info));
	os_memset(buf, 0, buf_len);

	reply_info.twt_oper = twt_oper;
	reply_info.reply_buf = buf;
	reply_info.reply_buf_len = buf_len;
	reply_info.drv = drv;

	twt_nl_msg = nlmsg_alloc();
	if (!twt_nl_msg) {
		wpa_printf(MSG_ERROR, "nlmg alloc failure");
		return -ENOMEM;
	}

	ret = pack_nlmsg_vendor_hdr(twt_nl_msg, drv, ifname);
	if (ret)
		goto free_mem;

	ret = pack_nlmsg_twt_params(twt_nl_msg, param, twt_oper);
	if (ret)
		goto free_mem;

	*status = send_nlmsg_get_resp((struct nl_sock *)drv->global->nl,
				      twt_nl_msg, twt_response_handler,
				      &reply_info);
	if (*status != 0) {
		wpa_printf(MSG_ERROR, "Failed to send nlmsg - err %d", *status);
		ret = -EINVAL;
	}

free_mem:
	if (twt_nl_msg)
		nlmsg_free(twt_nl_msg);
	return ret;
}

int wpa_driver_nl80211_driver_cmd(void *priv, char *cmd, char *buf,
				  size_t buf_len )
{
	struct i802_bss *bss = priv;
	struct wpa_driver_nl80211_data *drv = NULL;
	struct wpa_driver_nl80211_data *driver;
	struct ifreq ifr;
	android_wifi_priv_cmd priv_cmd;
	int ret = 0, status = 0, lib_n = 0;
	static wpa_driver_oem_cb_table_t *oem_cb_table = NULL;

	if (bss) {
		drv = bss->drv;
	} else {
		if (os_strncasecmp(cmd, "SET_AP_SUSPEND", 14)) {
			wpa_printf(MSG_ERROR, "%s: bss is NULL for cmd %s\n",
				   __func__, cmd);
			return -EINVAL;
		}
	}

	if (wpa_driver_oem_initialize(&oem_cb_table) != WPA_DRIVER_OEM_STATUS_FAILURE &&
	    oem_cb_table) {

		for (lib_n = 0;
		     oem_cb_table[lib_n].wpa_driver_driver_cmd_oem_cb != NULL;
		     lib_n++)
		{
			ret = oem_cb_table[lib_n].wpa_driver_driver_cmd_oem_cb(
					priv, cmd, buf, buf_len, &status);
			if (ret == WPA_DRIVER_OEM_STATUS_SUCCESS ) {
				return strlen(buf);
			} else if (ret == WPA_DRIVER_OEM_STATUS_ENOSUPP) {
				continue;
			} else if ((ret == WPA_DRIVER_OEM_STATUS_FAILURE) &&
				   (status != 0)) {
				wpa_printf(MSG_DEBUG, "%s: Received error: %d",
						__func__, ret);
				return -1;
			}
		}
		/* else proceed with legacy handling as below */
	}

	if (!drv) {
		wpa_printf(MSG_ERROR, "%s: drv is NULL for cmd %s\n",
			   __func__, cmd);
		return -EINVAL;
	}

	if (os_strcasecmp(cmd, "START") == 0) {
		dl_list_for_each(driver, &drv->global->interfaces, struct wpa_driver_nl80211_data, list) {
			linux_set_iface_flags(drv->global->ioctl_sock, driver->first_bss->ifname, 1);
			wpa_msg(drv->ctx, MSG_INFO, WPA_EVENT_DRIVER_STATE "STARTED");
		}
	} else if (os_strcasecmp(cmd, "MACADDR") == 0) {
		u8 macaddr[ETH_ALEN] = {};

		ret = linux_get_ifhwaddr(drv->global->ioctl_sock, bss->ifname, macaddr);
		if (!ret)
			ret = os_snprintf(buf, buf_len,
					  "Macaddr = " MACSTR "\n", MAC2STR(macaddr));
	} else if ((ret = check_for_twt_cmd(&cmd)) != TWT_CMD_NOT_EXIST) {
		enum qca_wlan_twt_operation twt_oper = ret;

		ret = wpa_driver_twt_cmd_handler(drv, bss->ifname, twt_oper, cmd, buf, buf_len,
						 &status);
		if (ret)
			ret = os_snprintf(buf, buf_len, "TWT failed for operation %d", twt_oper);
	} else { /* Use private command */
		memset(&ifr, 0, sizeof(ifr));
		memset(&priv_cmd, 0, sizeof(priv_cmd));
		os_memcpy(buf, cmd, strlen(cmd) + 1);
		os_strlcpy(ifr.ifr_name, bss->ifname, IFNAMSIZ);

		priv_cmd.buf = buf;
		priv_cmd.used_len = buf_len;
		priv_cmd.total_len = buf_len;
		ifr.ifr_data = &priv_cmd;

		if ((ret = ioctl(drv->global->ioctl_sock, SIOCDEVPRIVATE + 1, &ifr)) < 0) {
			wpa_printf(MSG_ERROR, "%s: failed to issue private commands\n", __func__);
		} else {
			drv_errors = 0;
			if((os_strncasecmp(cmd, "SETBAND", 7) == 0) &&
				ret == DO_NOT_SEND_CHANNEL_CHANGE_EVENT) {
				return 0;
			}

			ret = 0;
			if ((os_strcasecmp(cmd, "LINKSPEED") == 0) ||
			    (os_strcasecmp(cmd, "RSSI") == 0) ||
			    (os_strstr(cmd, "GET") != NULL))
				ret = strlen(buf);
			else if (os_strcasecmp(cmd, "P2P_DEV_ADDR") == 0)
				wpa_printf(MSG_DEBUG, "%s: P2P: Device address ("MACSTR")",
					__func__, MAC2STR(buf));
			else if (os_strcasecmp(cmd, "P2P_SET_PS") == 0)
				wpa_printf(MSG_DEBUG, "%s: P2P: %s ", __func__, buf);
			else if (os_strcasecmp(cmd, "P2P_SET_NOA") == 0)
				wpa_printf(MSG_DEBUG, "%s: P2P: %s ", __func__, buf);
			else if (os_strcasecmp(cmd, "STOP") == 0) {
				wpa_printf(MSG_DEBUG, "%s: %s ", __func__, buf);
				dl_list_for_each(driver, &drv->global->interfaces, struct wpa_driver_nl80211_data, list) {
					linux_set_iface_flags(drv->global->ioctl_sock, driver->first_bss->ifname, 0);
					wpa_msg(drv->ctx, MSG_INFO, WPA_EVENT_DRIVER_STATE "STOPPED");
				}
			}
			else
				wpa_printf(MSG_DEBUG, "%s %s len = %d, %zu", __func__, buf, ret, buf_len);
			wpa_driver_notify_country_change(drv->ctx, cmd);
		}
	}
	return ret;
}

int wpa_driver_set_p2p_noa(void *priv, u8 count, int start, int duration)
{
	char buf[MAX_DRV_CMD_SIZE];

	memset(buf, 0, sizeof(buf));
	wpa_printf(MSG_DEBUG, "%s: Entry", __func__);
	snprintf(buf, sizeof(buf), "P2P_SET_NOA %d %d %d", count, start, duration);
	return wpa_driver_nl80211_driver_cmd(priv, buf, buf, strlen(buf)+1);
}

int wpa_driver_get_p2p_noa(void *priv, u8 *buf, size_t len)
{
	UNUSED(priv), UNUSED(buf), UNUSED(len);
	/* Return 0 till we handle p2p_presence request completely in the driver */
	return 0;
}

int wpa_driver_set_p2p_ps(void *priv, int legacy_ps, int opp_ps, int ctwindow)
{
	char buf[MAX_DRV_CMD_SIZE];

	memset(buf, 0, sizeof(buf));
	wpa_printf(MSG_DEBUG, "%s: Entry", __func__);
	snprintf(buf, sizeof(buf), "P2P_SET_PS %d %d %d", legacy_ps, opp_ps, ctwindow);
	return wpa_driver_nl80211_driver_cmd(priv, buf, buf, strlen(buf) + 1);
}

int wpa_driver_set_ap_wps_p2p_ie(void *priv, const struct wpabuf *beacon,
				 const struct wpabuf *proberesp,
				 const struct wpabuf *assocresp)
{
	UNUSED(priv), UNUSED(beacon), UNUSED(proberesp), UNUSED(assocresp);
	return 0;
}
