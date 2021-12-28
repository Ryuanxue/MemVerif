#ifndef HEDER_FUZZ_H
#define HEDER_FUZZ_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>


#include <openssl/ssl.h>
#include <openssl/ssl_locl.h>
#include <openssl/ossl_typ.h>
#include <openssl/err.h>
#include <iostream>
#include <assert.h>
#include <string.h>


extern "C" void s2_pkt610s2_pkt490_1(SSL *_n_do_ssl_write_s_, const unsigned char *_n_do_ssl_write_buf_, unsigned int _n_do_ssl_write_len_, unsigned int _n_do_ssl_write_p_, int _n_do_ssl_write_mac_size_, register unsigned char *_n_do_ssl_write_pp_, unsigned int _n_do_ssl_write_olen_, int n_do_ssl_write_return_, int write_pending_return_);

#endif
