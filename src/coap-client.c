/*
 * Copyright (c) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(net_coap_client_sample, LOG_LEVEL_DBG);

#include <errno.h>
#include <zephyr/sys/printk.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/kernel.h>

#include <zephyr/posix/poll.h>
#include <zephyr/posix/sys/socket.h>
#include <zephyr/posix/arpa/inet.h>
#include <zephyr/posix/unistd.h>

#include <zephyr/net/socket.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/net_event.h>
#include <zephyr/net/udp.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/tls_credentials.h>
#include <zephyr/net/conn_mgr_connectivity.h>
#include <zephyr/net/conn_mgr_monitor.h>

#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/drivers/sensor.h>

#include "net_private.h"
#include "credentials.h"

#define MAX_COAP_MSG_LEN 256

#define THINGSBOARD_HOST "coap.eu.thingsboard.cloud"

static const struct device *bmp280 = DEVICE_DT_GET_ANY(bosch_bme280);
static const struct device *ccs811 = DEVICE_DT_GET_ANY(ams_ccs811);
static const struct device *bmm150 = DEVICE_DT_GET_ANY(bosch_bmm150);

static K_SEM_DEFINE(net_ready, 0, 1);
static struct net_mgmt_event_callback net_l4_cb;

/* CoAP socket fd */
static int sock;

struct pollfd fds[1];
static int nfds;

/* CoAP URI path: /api/v1/telemetry (X.509 auth, no token needed) */
static const char * const telemetry_path[] = {
	"api", "v1", "telemetry", NULL
};

static void wait(void)
{
	if (poll(fds, nfds, -1) < 0) {
		LOG_ERR("Error in poll:%d", errno);
	}
}

static void prepare_fds(void)
{
	fds[nfds].fd = sock;
	fds[nfds].events = POLLIN;
	nfds++;
}

static int setup_credentials(void)
{
	int ret;

	ret = tls_credential_add(2,
				 TLS_CREDENTIAL_CA_CERTIFICATE,
				 ca_cert, sizeof(ca_cert));
	if (ret < 0) {
		LOG_ERR("Failed to add CA cert: %d", ret);
		return ret;
	}

	ret = tls_credential_add(CLIENT_CERT_TAG,
				 TLS_CREDENTIAL_PUBLIC_CERTIFICATE,
				 client_cert, sizeof(client_cert));
	if (ret < 0) {
		LOG_ERR("Failed to add client cert: %d", ret);
		return ret;
	}

	ret = tls_credential_add(CLIENT_CERT_TAG,
				 TLS_CREDENTIAL_PRIVATE_KEY,
				 client_key, sizeof(client_key));
	if (ret < 0) {
		LOG_ERR("Failed to add client key: %d", ret);
		return ret;
	}

	return 0;
}

static int start_coap_client(void)
{
	int ret;
	struct zsock_addrinfo hints = {0};
	struct zsock_addrinfo *addr;

	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_DTLS_1_2;

	ret = zsock_getaddrinfo(THINGSBOARD_HOST, "5684",
				&hints, &addr);
	if (ret) {
		LOG_ERR("Failed to resolve %s: %d", THINGSBOARD_HOST, ret);
		return -EINVAL;
	}

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_DTLS_1_2);
	if (sock < 0) {
		LOG_ERR("Failed to create DTLS socket %d", errno);
		zsock_freeaddrinfo(addr);
		return -errno;
	}

	sec_tag_t sec_tag_list[] = { CA_CERT_TAG };

	ret = setsockopt(sock, SOL_TLS, TLS_SEC_TAG_LIST,
			 sec_tag_list, sizeof(sec_tag_list));
	if (ret < 0) {
		LOG_ERR("Failed to set TLS_SEC_TAG_LIST: %d", errno);
		zsock_freeaddrinfo(addr);
		return -errno;
	}

	int verify = TLS_PEER_VERIFY_OPTIONAL;
	ret = setsockopt(sock, SOL_TLS, TLS_PEER_VERIFY,
			 &verify, sizeof(verify));
	if (ret < 0) {
		LOG_ERR("Failed to set TLS_PEER_VERIFY: %d", errno);
		zsock_freeaddrinfo(addr);
		return -errno;
	}

	ret = setsockopt(sock, SOL_TLS, TLS_HOSTNAME,
			 THINGSBOARD_HOST, sizeof(THINGSBOARD_HOST));
	if (ret < 0) {
		LOG_ERR("Failed to set TLS_HOSTNAME: %d", errno);
		zsock_freeaddrinfo(addr);
		return -errno;
	}

	/* Explicitly set cipher suites supported by Californium/Scandium */
	int ciphersuites[] = {
		0xC02B,  /* TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 */
		0xC0AE,  /* TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 */
		0xC0AC,  /* TLS_ECDHE_ECDSA_WITH_AES_128_CCM */
		0xC02F,  /* TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 */
	};

	ret = setsockopt(sock, SOL_TLS, TLS_CIPHERSUITE_LIST,
			 ciphersuites, sizeof(ciphersuites));
	if (ret < 0) {
		LOG_ERR("Failed to set TLS_CIPHERSUITE_LIST: %d", errno);
		zsock_freeaddrinfo(addr);
		return -errno;
	}

	ret = connect(sock, addr->ai_addr, addr->ai_addrlen);
	zsock_freeaddrinfo(addr);
	if (ret < 0) {
		LOG_ERR("Cannot connect to DTLS remote: %d", errno);
		return -errno;
	}

	prepare_fds();

	return 0;
}

static int process_coap_reply(void)
{
	struct coap_packet reply;
	uint8_t *data;
	int rcvd;
	int ret;

	wait();

	data = (uint8_t *)k_malloc(MAX_COAP_MSG_LEN);
	if (!data) {
		return -ENOMEM;
	}

	rcvd = recv(sock, data, MAX_COAP_MSG_LEN, MSG_DONTWAIT);
	if (rcvd == 0) {
		ret = -EIO;
		goto end;
	}

	if (rcvd < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			ret = 0;
		} else {
			ret = -errno;
		}

		goto end;
	}

	net_hexdump("Response", data, rcvd);

	ret = coap_packet_parse(&reply, data, rcvd, NULL, 0);
	if (ret < 0) {
		LOG_ERR("Invalid data received");
	}

end:
	k_free(data);

	return ret;
}

static int send_telemetry(const char *json_payload)
{
	struct coap_packet request;
	const char * const *p;
	uint8_t *data;
	int r;

	data = (uint8_t *)k_malloc(MAX_COAP_MSG_LEN);
	if (!data) {
		return -ENOMEM;
	}

	r = coap_packet_init(&request, data, MAX_COAP_MSG_LEN,
			     COAP_VERSION_1, COAP_TYPE_CON,
			     COAP_TOKEN_MAX_LEN, coap_next_token(),
			     COAP_METHOD_POST, coap_next_id());
	if (r < 0) {
		LOG_ERR("Failed to init CoAP message");
		goto end;
	}

	/* Content-Format: application/json */
	r = coap_append_option_int(&request, COAP_OPTION_CONTENT_FORMAT,
				   COAP_CONTENT_FORMAT_APP_JSON);
	if (r < 0) {
		LOG_ERR("Unable to add content format option");
		goto end;
	}

	for (p = telemetry_path; p && *p; p++) {
		r = coap_packet_append_option(&request, COAP_OPTION_URI_PATH,
					      *p, strlen(*p));
		if (r < 0) {
			LOG_ERR("Unable add option to request");
			goto end;
		}
	}

	r = coap_packet_append_payload_marker(&request);
	if (r < 0) {
		LOG_ERR("Unable to append payload marker");
		goto end;
	}

	r = coap_packet_append_payload(&request, (uint8_t *)json_payload,
				       strlen(json_payload));
	if (r < 0) {
		LOG_ERR("Not able to append payload");
		goto end;
	}

	net_hexdump("Request", request.data, request.offset);

	r = send(sock, request.data, request.offset, 0);

end:
	k_free(data);

	return r;
}

static void net_event_handler(struct net_mgmt_event_callback *cb,
			      uint64_t mgmt_event, struct net_if *iface)
{
	if (mgmt_event == NET_EVENT_IPV4_ADDR_ADD) {
		LOG_INF("Network connected");
		k_sem_give(&net_ready);
	}
}

int main(void)
{
	int r;
	struct sensor_value temp;
	struct sensor_value press;
	struct sensor_value co2;
	struct sensor_value tvoc;
	struct sensor_value magn_x, magn_y, magn_z;
	bool ccs811_ok;
	bool bmm150_ok;
	char json_buf[512];

	LOG_DBG("Start CoAP-client sample");

	if (!device_is_ready(bmp280)) {
		LOG_ERR("BMP280 device not ready");
		return 0;
	}

	ccs811_ok = device_is_ready(ccs811);
	if (!ccs811_ok) {
		LOG_WRN("CCS811 device not ready, continuing without it");
	}

	bmm150_ok = device_is_ready(bmm150);
	if (!bmm150_ok) {
		LOG_WRN("BMM150 device not ready, continuing without it");
	}

	net_mgmt_init_event_callback(&net_l4_cb, net_event_handler,
		NET_EVENT_IPV4_ADDR_ADD);
	net_mgmt_add_event_callback(&net_l4_cb);

	LOG_INF("Waiting for network connection...");
	k_sem_take(&net_ready, K_FOREVER);

	r = setup_credentials();
	if (r < 0) {
		goto quit;
	}

	r = start_coap_client();
	if (r < 0) {
		goto quit;
	}

	while (1) {
		r = sensor_sample_fetch(bmp280);
		if (r < 0) {
			LOG_ERR("Failed to fetch sensor sample: %d", r);
			k_sleep(K_SECONDS(5));
			continue;
		}

		r = sensor_channel_get(bmp280, SENSOR_CHAN_AMBIENT_TEMP, &temp);
		if (r < 0) {
			LOG_ERR("Failed to get temperature: %d", r);
			k_sleep(K_SECONDS(5));
			continue;
		}

		r = sensor_channel_get(bmp280, SENSOR_CHAN_PRESS, &press);
		if (r < 0) {
			LOG_ERR("Failed to get pressure: %d", r);
			k_sleep(K_SECONDS(5));
			continue;
		}

		int off = snprintf(json_buf, sizeof(json_buf),
				   "{\"temperature\": %d.%02d, \"pressure\": %d.%02d",
				   temp.val1, temp.val2 / 10000,
				   press.val1, press.val2 / 10000);

		if (ccs811_ok &&
		    sensor_sample_fetch(ccs811) == 0 &&
		    sensor_channel_get(ccs811, SENSOR_CHAN_CO2, &co2) == 0 &&
		    sensor_channel_get(ccs811, SENSOR_CHAN_VOC, &tvoc) == 0) {
			off += snprintf(json_buf + off, sizeof(json_buf) - off,
					", \"co2\": %d, \"tvoc\": %d",
					co2.val1, tvoc.val1);
		}

		if (bmm150_ok &&
		    sensor_sample_fetch(bmm150) == 0 &&
		    sensor_channel_get(bmm150, SENSOR_CHAN_MAGN_X, &magn_x) == 0 &&
		    sensor_channel_get(bmm150, SENSOR_CHAN_MAGN_Y, &magn_y) == 0 &&
		    sensor_channel_get(bmm150, SENSOR_CHAN_MAGN_Z, &magn_z) == 0) {
			off += snprintf(json_buf + off, sizeof(json_buf) - off,
					", \"magn_x\": %d.%06d, \"magn_y\": %d.%06d, \"magn_z\": %d.%06d",
					magn_x.val1, magn_x.val2,
					magn_y.val1, magn_y.val2,
					magn_z.val1, magn_z.val2);
		}

		snprintf(json_buf + off, sizeof(json_buf) - off, "}");

		printk("\nSending telemetry: %s\n", json_buf);
		r = send_telemetry(json_buf);
		if (r < 0) {
			LOG_ERR("Failed to send telemetry: %d", r);
			goto quit;
		}

		r = process_coap_reply();
		if (r < 0) {
			LOG_ERR("Failed to process reply: %d", r);
			goto quit;
		}

		k_sleep(K_SECONDS(5));
	}

quit:
	(void)close(sock);

	LOG_ERR("quit");
	return 0;
}
