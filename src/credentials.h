#ifndef CREDENTIALS_H
#define CREDENTIALS_H

#define CA_CERT_TAG 1
#define CLIENT_CERT_TAG 1  /* same tag -- cert + key are a pair */

static const unsigned char ca_cert[] = {
#include "../certs/ca-cert.der.inc"
};

static const unsigned char client_cert[] = {
#include "../certs/cert-pem.der.inc"
};

static const unsigned char client_key[] = {
#include "../certs/key-pem.der.inc"
};

#endif
