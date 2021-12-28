#include <stdlib.h>
#include <openssl/ebcdic.h>
#include <openssl/bio.h>
#include <openssl/rc2.h>
#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <openssl/pem2.h>
#include <openssl/comp.h>
#include <openssl/ripemd.h>
#include <openssl/camellia.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/ts.h>
#include <openssl/stack.h>
#include <openssl/x509.h>
#include <openssl/lhash.h>
#include <openssl/ui.h>
#include <openssl/opensslv.h>
#include <openssl/dsa.h>
#include <openssl/bn.h>
#include <openssl/dso.h>
#include <openssl/sha.h>
#include <openssl/symhacks.h>
#include <openssl/x509_vfy.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/ui_compat.h>
#include <openssl/des.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ecdsa.h>
#include <openssl/opensslconf.h>
#include <openssl/err.h>
#include <openssl/pqueue.h>
#include <openssl/rc4.h>
#include <openssl/buffer.h>
#include <openssl/md4.h>
#include <openssl/ossl_typ.h>
#include <openssl/ecdh.h>
#include <openssl/x509v3.h>
#include <openssl/seed.h>
#include <openssl/idea.h>
#include <openssl/ocsp.h>
#include <openssl/blowfish.h>
#include <openssl/whrlpool.h>
#include <openssl/modes.h>
#include <openssl/pkcs7.h>
#include <openssl/asn1_mac.h>
#include <openssl/safestack.h>
#include <openssl/pkcs12.h>
#include <openssl/cast.h>
#include <openssl/rand.h>
#include <openssl/conf_api.h>
#include <openssl/cms.h>
#include <openssl/mdc2.h>
#include <openssl/krb5_asn.h>
#include <openssl/cmac.h>
#include <openssl/obj_mac.h>
#include <openssl/asn1t.h>
#include <openssl/txt_db.h>
#include <openssl/des_old.h>
#include <openssl/srp.h>
#include <openssl/engine.h>
void *ebcdic2ascii(void *dest,  void *srce, size_t count){	}
void *ascii2ebcdic(void *dest,  void *srce, size_t count){	}
void BIO_set_flags(BIO *b, int flags){	}
int  BIO_test_flags( BIO *b, int flags){	}
void BIO_clear_flags(BIO *b, int flags){	}
void BIO_set_callback(BIO *b, long (*callback)(struct bio_st *,int, char *,int, long,long)){	}
char *BIO_get_callback_arg( BIO *b){	}
void BIO_set_callback_arg(BIO *b, char *arg){	}
char * BIO_method_name( BIO *b){	}
int BIO_method_type( BIO *b){	}
int BIO_read_filename(BIO *b, char *name){	}
size_t BIO_ctrl_pending(BIO *b){	}
size_t BIO_ctrl_wpending(BIO *b){	}
size_t BIO_ctrl_get_write_guarantee(BIO *b){	}
size_t BIO_ctrl_get_read_request(BIO *b){	}
int BIO_ctrl_reset_read_request(BIO *b){	}
int BIO_set_ex_data(BIO *bio,int idx,void *data){	}
void *BIO_get_ex_data(BIO *bio,int idx){	}
int BIO_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func){	}
unsigned long BIO_number_read(BIO *bio){	}
unsigned long BIO_number_written(BIO *bio){	}
int BIO_asn1_set_prefix(BIO *b, asn1_ps_func *prefix, asn1_ps_func *prefix_free){	}
int BIO_asn1_get_prefix(BIO *b, asn1_ps_func **pprefix, asn1_ps_func **pprefix_free){	}
int BIO_asn1_set_suffix(BIO *b, asn1_ps_func *suffix, asn1_ps_func *suffix_free){	}
int BIO_asn1_get_suffix(BIO *b, asn1_ps_func **psuffix, asn1_ps_func **psuffix_free){	}
BIO_METHOD *BIO_s_file(void ){	}
BIO *BIO_new_file( char *filename,  char *mode){	}
BIO *BIO_new_fp(FILE *stream, int close_flag){	}
BIO *	BIO_new(BIO_METHOD *type){	}
int	BIO_set(BIO *a,BIO_METHOD *type){	}
int	BIO_free(BIO *a){	}
void	BIO_vfree(BIO *a){	}
int	BIO_read(BIO *b, void *data, int len){	}
int	BIO_gets(BIO *bp,char *buf, int size){	}
int	BIO_write(BIO *b,  void *data, int len){	}
int	BIO_puts(BIO *bp, char *buf){	}
int	BIO_indent(BIO *b,int indent,int max){	}
long	BIO_ctrl(BIO *bp,int cmd,long larg,void *parg){	}
long BIO_callback_ctrl(BIO *b, int cmd, void (*fp)(struct bio_st *, int,  char *, int, long, long)){	}
char *	BIO_ptr_ctrl(BIO *bp,int cmd,long larg){	}
long	BIO_int_ctrl(BIO *bp,int cmd,long larg,int iarg){	}
BIO *	BIO_push(BIO *b,BIO *append){	}
BIO *	BIO_pop(BIO *b){	}
void	BIO_free_all(BIO *a){	}
BIO *	BIO_find_type(BIO *b,int bio_type){	}
BIO *	BIO_next(BIO *b){	}
BIO *	BIO_get_retry_BIO(BIO *bio, int *reason){	}
int	BIO_get_retry_reason(BIO *bio){	}
BIO *	BIO_dup_chain(BIO *in){	}
int BIO_nread0(BIO *bio, char **buf){	}
int BIO_nread(BIO *bio, char **buf, int num){	}
int BIO_nwrite0(BIO *bio, char **buf){	}
int BIO_nwrite(BIO *bio, char **buf, int num){	}
long BIO_debug_callback(BIO *bio,int cmd, char *argp,int argi, long argl,long ret){	}
BIO_METHOD *BIO_s_mem(void){	}
BIO *BIO_new_mem_buf(void *buf, int len){	}
BIO_METHOD *BIO_s_socket(void){	}
BIO_METHOD *BIO_s_connect(void){	}
BIO_METHOD *BIO_s_accept(void){	}
BIO_METHOD *BIO_s_fd(void){	}
BIO_METHOD *BIO_s_log(void){	}
BIO_METHOD *BIO_s_bio(void){	}
BIO_METHOD *BIO_s_null(void){	}
BIO_METHOD *BIO_f_null(void){	}
BIO_METHOD *BIO_f_buffer(void){	}
BIO_METHOD *BIO_f_linebuffer(void){	}
BIO_METHOD *BIO_f_nbio_test(void){	}
BIO_METHOD *BIO_s_datagram(void){	}
BIO_METHOD *BIO_s_datagram_sctp(void){	}
int BIO_sock_should_retry(int i){	}
int BIO_sock_non_fatal_error(int error){	}
int BIO_dgram_non_fatal_error(int error){	}
int BIO_fd_should_retry(int i){	}
int BIO_fd_non_fatal_error(int error){	}
int BIO_dump_cb(int (*cb)( void *data, size_t len, void *u), void *u,  char *s, int len){	}
int BIO_dump_indent_cb(int (*cb)( void *data, size_t len, void *u), void *u,  char *s, int len, int indent){	}
int BIO_dump(BIO *b, char *bytes,int len){	}
int BIO_dump_indent(BIO *b, char *bytes,int len,int indent){	}
int BIO_dump_fp(FILE *fp,  char *s, int len){	}
int BIO_dump_indent_fp(FILE *fp,  char *s, int len, int indent){	}
struct hostent *BIO_gethostbyname( char *name){	}
int BIO_sock_error(int sock){	}
int BIO_socket_ioctl(int fd, long type, void *arg){	}
int BIO_socket_nbio(int fd,int mode){	}
int BIO_get_port( char *str, unsigned short *port_ptr){	}
int BIO_get_host_ip( char *str, unsigned char *ip){	}
int BIO_get_accept_socket(char *host_port,int mode){	}
int BIO_accept(int sock,char **ip_port){	}
int BIO_sock_init(void ){	}
void BIO_sock_cleanup(void){	}
int BIO_set_tcp_ndelay(int sock,int turn_on){	}
BIO *BIO_new_socket(int sock, int close_flag){	}
BIO *BIO_new_dgram(int fd, int close_flag){	}
BIO *BIO_new_dgram_sctp(int fd, int close_flag){	}
int BIO_dgram_is_sctp(BIO *bio){	}
int BIO_dgram_sctp_notification_cb(BIO *b, void (*handle_notifications)(BIO *bio, void *context, void *buf), void *context){	}
int BIO_dgram_sctp_wait_for_dry(BIO *b){	}
int BIO_dgram_sctp_msg_waiting(BIO *b){	}
BIO *BIO_new_fd(int fd, int close_flag){	}
BIO *BIO_new_connect(char *host_port){	}
BIO *BIO_new_accept(char *host_port){	}
int BIO_new_bio_pair(BIO **bio1, size_t writebuf1, BIO **bio2, size_t writebuf2){	}
void BIO_copy_next_retry(BIO *b){	}
void ERR_load_BIO_strings(void){	}
void private_RC2_set_key(RC2_KEY *key, int len,  unsigned char *data,int bits){	}
void RC2_set_key(RC2_KEY *key, int len,  unsigned char *data,int bits){	}
void RC2_ecb_encrypt( unsigned char *in,unsigned char *out,RC2_KEY *key, int enc){	}
void RC2_encrypt(unsigned long *data,RC2_KEY *key){	}
void RC2_decrypt(unsigned long *data,RC2_KEY *key){	}
void RC2_cbc_encrypt( unsigned char *in, unsigned char *out, long length, RC2_KEY *ks, unsigned char *iv, int enc){	}
void RC2_cfb64_encrypt( unsigned char *in, unsigned char *out, long length, RC2_KEY *schedule, unsigned char *ivec, int *num, int enc){	}
void RC2_ofb64_encrypt( unsigned char *in, unsigned char *out, long length, RC2_KEY *schedule, unsigned char *ivec, int *num){	}
void ASN1_TYPE_set(ASN1_TYPE *a, int type, void *value){	}
int ASN1_TYPE_set1(ASN1_TYPE *a, int type,  void *value){	}
int            ASN1_TYPE_cmp(ASN1_TYPE *a, ASN1_TYPE *b){	}
ASN1_OBJECT *	ASN1_OBJECT_new(void ){	}
void		ASN1_OBJECT_free(ASN1_OBJECT *a){	}
int		i2d_ASN1_OBJECT(ASN1_OBJECT *a,unsigned char **pp){	}
ASN1_OBJECT *	c2i_ASN1_OBJECT(ASN1_OBJECT **a, unsigned char **pp, long length){	}
ASN1_OBJECT *	d2i_ASN1_OBJECT(ASN1_OBJECT **a, unsigned char **pp, long length){	}
void		ASN1_STRING_free(ASN1_STRING *a){	}
int		ASN1_STRING_copy(ASN1_STRING *dst,  ASN1_STRING *str){	}
ASN1_STRING *	ASN1_STRING_dup( ASN1_STRING *a){	}
ASN1_STRING *	ASN1_STRING_type_new(int type ){	}
int 		ASN1_STRING_cmp( ASN1_STRING *a,  ASN1_STRING *b){	}
int 		ASN1_STRING_set(ASN1_STRING *str,  void *data, int len){	}
void		ASN1_STRING_set0(ASN1_STRING *str, void *data, int len){	}
int ASN1_STRING_length( ASN1_STRING *x){	}
void ASN1_STRING_length_set(ASN1_STRING *x, int n){	}
int ASN1_STRING_type(ASN1_STRING *x){	}
unsigned char * ASN1_STRING_data(ASN1_STRING *x){	}
ASN1_BIT_STRING *c2i_ASN1_BIT_STRING(ASN1_BIT_STRING **a, unsigned char **pp, long length){	}
int		ASN1_BIT_STRING_set(ASN1_BIT_STRING *a, unsigned char *d, int length ){	}
int		ASN1_BIT_STRING_set_bit(ASN1_BIT_STRING *a, int n, int value){	}
int		ASN1_BIT_STRING_get_bit(ASN1_BIT_STRING *a, int n){	}
int            ASN1_BIT_STRING_check(ASN1_BIT_STRING *a, unsigned char *flags, int flags_len){	}
int ASN1_BIT_STRING_name_print(BIO *out, ASN1_BIT_STRING *bs, BIT_STRING_BITNAME *tbl, int indent){	}
int ASN1_BIT_STRING_num_asc(char *name, BIT_STRING_BITNAME *tbl){	}
int ASN1_BIT_STRING_set_asc(ASN1_BIT_STRING *bs, char *name, int value, BIT_STRING_BITNAME *tbl){	}
int		i2d_ASN1_BOOLEAN(int a,unsigned char **pp){	}
int 		d2i_ASN1_BOOLEAN(int *a, unsigned char **pp,long length){	}
ASN1_INTEGER *c2i_ASN1_INTEGER(ASN1_INTEGER **a, unsigned char **pp, long length){	}
ASN1_INTEGER *d2i_ASN1_UINTEGER(ASN1_INTEGER **a, unsigned char **pp, long length){	}
ASN1_INTEGER *	ASN1_INTEGER_dup( ASN1_INTEGER *x){	}
int ASN1_INTEGER_cmp( ASN1_INTEGER *x,  ASN1_INTEGER *y){	}
ASN1_UTCTIME *ASN1_UTCTIME_set(ASN1_UTCTIME *s,time_t t){	}
ASN1_UTCTIME *ASN1_UTCTIME_adj(ASN1_UTCTIME *s, time_t t, int offset_day, long offset_sec){	}
int ASN1_UTCTIME_set_string(ASN1_UTCTIME *s,  char *str){	}
int ASN1_UTCTIME_cmp_time_t( ASN1_UTCTIME *s, time_t t){	}
time_t ASN1_UTCTIME_get( ASN1_UTCTIME *s){	}
int ASN1_GENERALIZEDTIME_check(ASN1_GENERALIZEDTIME *a){	}
ASN1_GENERALIZEDTIME *ASN1_GENERALIZEDTIME_set(ASN1_GENERALIZEDTIME *s,time_t t){	}
ASN1_GENERALIZEDTIME *ASN1_GENERALIZEDTIME_adj(ASN1_GENERALIZEDTIME *s, time_t t, int offset_day, long offset_sec){	}
int ASN1_GENERALIZEDTIME_set_string(ASN1_GENERALIZEDTIME *s,  char *str){	}
int 	ASN1_OCTET_STRING_cmp( ASN1_OCTET_STRING *a,  ASN1_OCTET_STRING *b){	}
int 	ASN1_OCTET_STRING_set(ASN1_OCTET_STRING *str,  unsigned char *data, int len){	}
int UTF8_putc(unsigned char *str, int len, unsigned long value){	}
ASN1_TIME *ASN1_TIME_adj(ASN1_TIME *s,time_t t, int offset_day, long offset_sec){	}
int ASN1_TIME_check(ASN1_TIME *t){	}
ASN1_GENERALIZEDTIME *ASN1_TIME_to_generalizedtime(ASN1_TIME *t, ASN1_GENERALIZEDTIME **out){	}
int ASN1_TIME_set_string(ASN1_TIME *s,  char *str){	}
int i2d_ASN1_SET(STACK_OF(OPENSSL_BLOCK) *a, unsigned char **pp, i2d_of_void *i2d, int ex_tag, int ex_class, int is_set){	}
int i2a_ASN1_INTEGER(BIO *bp, ASN1_INTEGER *a){	}
int a2i_ASN1_INTEGER(BIO *bp,ASN1_INTEGER *bs,char *buf,int size){	}
int i2a_ASN1_ENUMERATED(BIO *bp, ASN1_ENUMERATED *a){	}
int a2i_ASN1_ENUMERATED(BIO *bp,ASN1_ENUMERATED *bs,char *buf,int size){	}
int i2a_ASN1_OBJECT(BIO *bp,ASN1_OBJECT *a){	}
int a2i_ASN1_STRING(BIO *bp,ASN1_STRING *bs,char *buf,int size){	}
int i2a_ASN1_STRING(BIO *bp, ASN1_STRING *a, int type){	}
int i2t_ASN1_OBJECT(char *buf,int buf_len,ASN1_OBJECT *a){	}
int a2d_ASN1_OBJECT(unsigned char *out,int olen,  char *buf, int num){	}
ASN1_OBJECT *ASN1_OBJECT_create(int nid, unsigned char *data,int len, char *sn,  char *ln){	}
int ASN1_INTEGER_set(ASN1_INTEGER *a, long v){	}
long ASN1_INTEGER_get( ASN1_INTEGER *a){	}
ASN1_INTEGER *BN_to_ASN1_INTEGER( BIGNUM *bn, ASN1_INTEGER *ai){	}
BIGNUM *ASN1_INTEGER_to_BN( ASN1_INTEGER *ai,BIGNUM *bn){	}
int ASN1_ENUMERATED_set(ASN1_ENUMERATED *a, long v){	}
long ASN1_ENUMERATED_get(ASN1_ENUMERATED *a){	}
ASN1_ENUMERATED *BN_to_ASN1_ENUMERATED(BIGNUM *bn, ASN1_ENUMERATED *ai){	}
BIGNUM *ASN1_ENUMERATED_to_BN(ASN1_ENUMERATED *ai,BIGNUM *bn){	}
int ASN1_PRINTABLE_type( unsigned char *s, int max){	}
int i2d_ASN1_bytes(ASN1_STRING *a, unsigned char **pp, int tag, int xclass){	}
ASN1_STRING *d2i_ASN1_bytes(ASN1_STRING **a,  unsigned char **pp, long length, int Ptag, int Pclass){	}
unsigned long ASN1_tag2bit(int tag){	}
ASN1_STRING *d2i_ASN1_type_bytes(ASN1_STRING **a, unsigned char **pp, long length,int type){	}
int asn1_Finish(ASN1_CTX *c){	}
int asn1_const_Finish(ASN1_const_CTX *c){	}
int ASN1_get_object( unsigned char **pp, long *plength, int *ptag, int *pclass, long omax){	}
int ASN1_check_infinite_end(unsigned char **p,long len){	}
int ASN1_const_check_infinite_end( unsigned char **p,long len){	}
void ASN1_put_object(unsigned char **pp, int constructed, int length, int tag, int xclass){	}
int ASN1_put_eoc(unsigned char **pp){	}
int ASN1_object_size(int constructed, int length, int tag){	}
void *ASN1_dup(i2d_of_void *i2d, d2i_of_void *d2i, void *x){	}
void *ASN1_item_dup( ASN1_ITEM *it, void *x){	}
void *ASN1_d2i_fp(void *(*xnew)(void), d2i_of_void *d2i, FILE *in, void **x){	}
void *ASN1_item_d2i_fp( ASN1_ITEM *it, FILE *in, void *x){	}
int ASN1_i2d_fp(i2d_of_void *i2d,FILE *out,void *x){	}
int ASN1_item_i2d_fp( ASN1_ITEM *it, FILE *out, void *x){	}
int ASN1_STRING_print_ex_fp(FILE *fp, ASN1_STRING *str, unsigned long flags){	}
int ASN1_STRING_to_UTF8(unsigned char **out, ASN1_STRING *in){	}
void *ASN1_d2i_bio(void *(*xnew)(void), d2i_of_void *d2i, BIO *in, void **x){	}
void *ASN1_item_d2i_bio( ASN1_ITEM *it, BIO *in, void *x){	}
int ASN1_i2d_bio(i2d_of_void *i2d,BIO *out, unsigned char *x){	}
int ASN1_item_i2d_bio( ASN1_ITEM *it, BIO *out, void *x){	}
int ASN1_UTCTIME_print(BIO *fp,  ASN1_UTCTIME *a){	}
int ASN1_GENERALIZEDTIME_print(BIO *fp,  ASN1_GENERALIZEDTIME *a){	}
int ASN1_TIME_print(BIO *fp,  ASN1_TIME *a){	}
int ASN1_STRING_print(BIO *bp,  ASN1_STRING *v){	}
int ASN1_STRING_print_ex(BIO *out, ASN1_STRING *str, unsigned long flags){	}
int ASN1_bn_print(BIO *bp,  char *number,  BIGNUM *num, unsigned char *buf, int off){	}
int ASN1_parse(BIO *bp, unsigned char *pp,long len,int indent){	}
int ASN1_parse_dump(BIO *bp, unsigned char *pp,long len,int indent,int dump){	}
char *ASN1_tag2str(int tag){	}
int ASN1_TYPE_set_octetstring(ASN1_TYPE *a, unsigned char *data, int len){	}
int ASN1_TYPE_get_octetstring(ASN1_TYPE *a, unsigned char *data, int max_len){	}
int ASN1_TYPE_set_int_octetstring(ASN1_TYPE *a, long num, unsigned char *data, int len){	}
int ASN1_TYPE_get_int_octetstring(ASN1_TYPE *a,long *num, unsigned char *data, int max_len){	}
unsigned char *ASN1_seq_pack(STACK_OF(OPENSSL_BLOCK) *safes, i2d_of_void *i2d, unsigned char **buf, int *len ){	}
void *ASN1_unpack_string(ASN1_STRING *oct, d2i_of_void *d2i){	}
void *ASN1_item_unpack(ASN1_STRING *oct,  ASN1_ITEM *it){	}
ASN1_STRING *ASN1_pack_string(void *obj, i2d_of_void *i2d, ASN1_OCTET_STRING **oct){	}
ASN1_STRING *ASN1_item_pack(void *obj,  ASN1_ITEM *it, ASN1_OCTET_STRING **oct){	}
void ASN1_STRING_set_default_mask(unsigned long mask){	}
int ASN1_STRING_set_default_mask_asc( char *p){	}
unsigned long ASN1_STRING_get_default_mask(void){	}
int ASN1_mbstring_copy(ASN1_STRING **out,  unsigned char *in, int len, int inform, unsigned long mask){	}
int ASN1_mbstring_ncopy(ASN1_STRING **out,  unsigned char *in, int len, int inform, unsigned long mask, long minsize, long maxsize){	}
ASN1_STRING *ASN1_STRING_set_by_NID(ASN1_STRING **out, unsigned char *in, int inlen, int inform, int nid){	}
ASN1_STRING_TABLE *ASN1_STRING_TABLE_get(int nid){	}
int ASN1_STRING_TABLE_add(int, long, long, unsigned long, unsigned long){	}
void ASN1_STRING_TABLE_cleanup(void){	}
ASN1_VALUE *ASN1_item_new( ASN1_ITEM *it){	}
void ASN1_item_free(ASN1_VALUE *val,  ASN1_ITEM *it){	}
ASN1_VALUE * ASN1_item_d2i(ASN1_VALUE **val,  unsigned char **in, long len,  ASN1_ITEM *it){	}
int ASN1_item_i2d(ASN1_VALUE *val, unsigned char **out,  ASN1_ITEM *it){	}
int ASN1_item_ndef_i2d(ASN1_VALUE *val, unsigned char **out,  ASN1_ITEM *it){	}
void ASN1_add_oid_module(void){	}
ASN1_TYPE *ASN1_generate_nconf(char *str, CONF *nconf){	}
ASN1_TYPE *ASN1_generate_v3(char *str, X509V3_CTX *cnf){	}
int ASN1_item_print(BIO *out, ASN1_VALUE *ifld, int indent, ASN1_ITEM *it,  ASN1_PCTX *pctx){	}
ASN1_PCTX *ASN1_PCTX_new(void){	}
void ASN1_PCTX_free(ASN1_PCTX *p){	}
unsigned long ASN1_PCTX_get_flags(ASN1_PCTX *p){	}
void ASN1_PCTX_set_flags(ASN1_PCTX *p, unsigned long flags){	}
unsigned long ASN1_PCTX_get_nm_flags(ASN1_PCTX *p){	}
void ASN1_PCTX_set_nm_flags(ASN1_PCTX *p, unsigned long flags){	}
unsigned long ASN1_PCTX_get_cert_flags(ASN1_PCTX *p){	}
void ASN1_PCTX_set_cert_flags(ASN1_PCTX *p, unsigned long flags){	}
unsigned long ASN1_PCTX_get_oid_flags(ASN1_PCTX *p){	}
void ASN1_PCTX_set_oid_flags(ASN1_PCTX *p, unsigned long flags){	}
unsigned long ASN1_PCTX_get_str_flags(ASN1_PCTX *p){	}
void ASN1_PCTX_set_str_flags(ASN1_PCTX *p, unsigned long flags){	}
BIO_METHOD *BIO_f_asn1(void){	}
BIO *BIO_new_NDEF(BIO *out, ASN1_VALUE *val,  ASN1_ITEM *it){	}
int i2d_ASN1_bio_stream(BIO *out, ASN1_VALUE *val, BIO *in, int flags, ASN1_ITEM *it){	}
int PEM_write_bio_ASN1_stream(BIO *out, ASN1_VALUE *val, BIO *in, int flags, char *hdr, ASN1_ITEM *it){	}
int SMIME_write_ASN1(BIO *bio, ASN1_VALUE *val, BIO *data, int flags, int ctype_nid, int econt_nid, STACK_OF(X509_ALGOR) *mdalgs, ASN1_ITEM *it){	}
ASN1_VALUE *SMIME_read_ASN1(BIO *bio, BIO **bcont,  ASN1_ITEM *it){	}
int SMIME_crlf_copy(BIO *in, BIO *out, int flags){	}
int SMIME_text(BIO *in, BIO *out){	}
void ERR_load_ASN1_strings(void){	}
int OBJ_NAME_init(void){	}
int OBJ_NAME_new_index(unsigned long (*hash_func)( char *), int (*cmp_func)( char *,  char *), void (*free_func)( char *, int,  char *)){	}
char *OBJ_NAME_get( char *name,int type){	}
int OBJ_NAME_add( char *name,int type, char *data){	}
int OBJ_NAME_remove( char *name,int type){	}
void OBJ_NAME_cleanup(int type){	}
void OBJ_NAME_do_all(int type,void (*fn)( OBJ_NAME *,void *arg), void *arg){	}
void OBJ_NAME_do_all_sorted(int type,void (*fn)( OBJ_NAME *,void *arg), void *arg){	}
ASN1_OBJECT *	OBJ_dup( ASN1_OBJECT *o){	}
ASN1_OBJECT *	OBJ_nid2obj(int n){	}
char *	OBJ_nid2ln(int n){	}
char *	OBJ_nid2sn(int n){	}
int		OBJ_obj2nid( ASN1_OBJECT *o){	}
ASN1_OBJECT *	OBJ_txt2obj( char *s, int no_name){	}
int	OBJ_obj2txt(char *buf, int buf_len,  ASN1_OBJECT *a, int no_name){	}
int		OBJ_txt2nid( char *s){	}
int		OBJ_ln2nid( char *s){	}
int		OBJ_sn2nid( char *s){	}
int		OBJ_cmp( ASN1_OBJECT *a, ASN1_OBJECT *b){	}
void *	OBJ_bsearch_( void *key, void *base,int num,int size, int (*cmp)( void *,  void *)){	}
void *	OBJ_bsearch_ex_( void *key, void *base,int num, int size, int (*cmp)( void *,  void *), int flags){	}
int		OBJ_new_nid(int num){	}
int		OBJ_add_object( ASN1_OBJECT *obj){	}
int		OBJ_create( char *oid, char *sn, char *ln){	}
void		OBJ_cleanup(void ){	}
int		OBJ_create_objects(BIO *in){	}
int OBJ_find_sigid_algs(int signid, int *pdig_nid, int *ppkey_nid){	}
int OBJ_find_sigid_by_algs(int *psignid, int dig_nid, int pkey_nid){	}
int OBJ_add_sigid(int signid, int dig_id, int pkey_id){	}
void OBJ_sigid_free(void){	}
void check_defer(int nid){	}
void ERR_load_OBJ_strings(void){	}
void ERR_load_PEM_strings(void){	}
COMP_CTX *COMP_CTX_new(COMP_METHOD *meth){	}
void COMP_CTX_free(COMP_CTX *ctx){	}
int COMP_compress_block(COMP_CTX *ctx, unsigned char *out, int olen, unsigned char *in, int ilen){	}
int COMP_expand_block(COMP_CTX *ctx, unsigned char *out, int olen, unsigned char *in, int ilen){	}
COMP_METHOD *COMP_rle(void ){	}
COMP_METHOD *COMP_zlib(void ){	}
void COMP_zlib_cleanup(void){	}
BIO_METHOD *BIO_f_zlib(void){	}
void ERR_load_COMP_strings(void){	}
int private_RIPEMD160_Init(RIPEMD160_CTX *c){	}
int RIPEMD160_Init(RIPEMD160_CTX *c){	}
int RIPEMD160_Update(RIPEMD160_CTX *c,  void *data, size_t len){	}
int RIPEMD160_Final(unsigned char *md, RIPEMD160_CTX *c){	}
unsigned char *RIPEMD160( unsigned char *d, size_t n, unsigned char *md){	}
void RIPEMD160_Transform(RIPEMD160_CTX *c,  unsigned char *b){	}
int private_Camellia_set_key( unsigned char *userKey,  int bits, CAMELLIA_KEY *key){	}
int Camellia_set_key( unsigned char *userKey,  int bits, CAMELLIA_KEY *key){	}
void Camellia_encrypt( unsigned char *in, unsigned char *out, CAMELLIA_KEY *key){	}
void Camellia_decrypt( unsigned char *in, unsigned char *out, CAMELLIA_KEY *key){	}
void Camellia_ecb_encrypt( unsigned char *in, unsigned char *out, CAMELLIA_KEY *key,  int enc){	}
void Camellia_cbc_encrypt( unsigned char *in, unsigned char *out, size_t length,  CAMELLIA_KEY *key, unsigned char *ivec,  int enc){	}
void Camellia_cfb128_encrypt( unsigned char *in, unsigned char *out, size_t length,  CAMELLIA_KEY *key, unsigned char *ivec, int *num,  int enc){	}
void Camellia_cfb1_encrypt( unsigned char *in, unsigned char *out, size_t length,  CAMELLIA_KEY *key, unsigned char *ivec, int *num,  int enc){	}
void Camellia_cfb8_encrypt( unsigned char *in, unsigned char *out, size_t length,  CAMELLIA_KEY *key, unsigned char *ivec, int *num,  int enc){	}
void Camellia_ofb128_encrypt( unsigned char *in, unsigned char *out, size_t length,  CAMELLIA_KEY *key, unsigned char *ivec, int *num){	}
void Camellia_ctr128_encrypt( unsigned char *in, unsigned char *out, size_t length,  CAMELLIA_KEY *key, unsigned char ivec[CAMELLIA_BLOCK_SIZE], unsigned char ecount_buf[CAMELLIA_BLOCK_SIZE], unsigned int *num){	}
RSA *	RSA_new(void){	}
RSA *	RSA_new_method(ENGINE *engine){	}
int	RSA_size( RSA *rsa){	}
RSA *	RSA_generate_key(int bits, unsigned long e,void (*callback)(int,int,void *),void *cb_arg){	}
int	RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb){	}
int	RSA_check_key( RSA *){	}
int	RSA_public_encrypt(int flen,  unsigned char *from, unsigned char *to, RSA *rsa,int padding){	}
int	RSA_private_encrypt(int flen,  unsigned char *from, unsigned char *to, RSA *rsa,int padding){	}
int	RSA_public_decrypt(int flen,  unsigned char *from, unsigned char *to, RSA *rsa,int padding){	}
int	RSA_private_decrypt(int flen,  unsigned char *from, unsigned char *to, RSA *rsa,int padding){	}
void	RSA_free (RSA *r){	}
int	RSA_up_ref(RSA *r){	}
int	RSA_flags( RSA *r){	}
void RSA_set_default_method( RSA_METHOD *meth){	}
RSA_METHOD *RSA_get_default_method(void){	}
RSA_METHOD *RSA_get_method( RSA *rsa){	}
int RSA_set_method(RSA *rsa,  RSA_METHOD *meth){	}
int RSA_memory_lock(RSA *r){	}
RSA_METHOD *RSA_PKCS1_SSLeay(void){	}
RSA_METHOD *RSA_null_method(void){	}
int	RSA_print_fp(FILE *fp,  RSA *r,int offset){	}
int	RSA_print(BIO *bp,  RSA *r,int offset){	}
int i2d_RSA_NET( RSA *a, unsigned char **pp, int (*cb)(char *buf, int len,  char *prompt, int verify), int sgckey){	}
RSA *d2i_RSA_NET(RSA **a,  unsigned char **pp, long length, int (*cb)(char *buf, int len,  char *prompt, int verify), int sgckey){	}
int i2d_Netscape_RSA( RSA *a, unsigned char **pp, int (*cb)(char *buf, int len,  char *prompt, int verify)){	}
RSA *d2i_Netscape_RSA(RSA **a,  unsigned char **pp, long length, int (*cb)(char *buf, int len,  char *prompt, int verify)){	}
int RSA_sign(int type,  unsigned char *m, unsigned int m_length, unsigned char *sigret, unsigned int *siglen, RSA *rsa){	}
int RSA_verify(int type,  unsigned char *m, unsigned int m_length, unsigned char *sigbuf, unsigned int siglen, RSA *rsa){	}
int RSA_sign_ASN1_OCTET_STRING(int type, unsigned char *m, unsigned int m_length, unsigned char *sigret, unsigned int *siglen, RSA *rsa){	}
int RSA_verify_ASN1_OCTET_STRING(int type, unsigned char *m, unsigned int m_length, unsigned char *sigbuf, unsigned int siglen, RSA *rsa){	}
int RSA_blinding_on(RSA *rsa, BN_CTX *ctx){	}
void RSA_blinding_off(RSA *rsa){	}
BN_BLINDING *RSA_setup_blinding(RSA *rsa, BN_CTX *ctx){	}
int RSA_padding_add_PKCS1_type_1(unsigned char *to,int tlen, unsigned char *f,int fl){	}
int RSA_padding_check_PKCS1_type_1(unsigned char *to,int tlen, unsigned char *f,int fl,int rsa_len){	}
int RSA_padding_add_PKCS1_type_2(unsigned char *to,int tlen, unsigned char *f,int fl){	}
int RSA_padding_check_PKCS1_type_2(unsigned char *to,int tlen, unsigned char *f,int fl,int rsa_len){	}
int PKCS1_MGF1(unsigned char *mask, long len, unsigned char *seed, long seedlen,  EVP_MD *dgst){	}
int RSA_padding_add_PKCS1_OAEP(unsigned char *to,int tlen, unsigned char *f,int fl, unsigned char *p,int pl){	}
int RSA_padding_check_PKCS1_OAEP(unsigned char *to,int tlen, unsigned char *f,int fl,int rsa_len, unsigned char *p,int pl){	}
int RSA_padding_add_SSLv23(unsigned char *to,int tlen, unsigned char *f,int fl){	}
int RSA_padding_check_SSLv23(unsigned char *to,int tlen, unsigned char *f,int fl,int rsa_len){	}
int RSA_padding_add_none(unsigned char *to,int tlen, unsigned char *f,int fl){	}
int RSA_padding_check_none(unsigned char *to,int tlen, unsigned char *f,int fl,int rsa_len){	}
int RSA_padding_add_X931(unsigned char *to,int tlen, unsigned char *f,int fl){	}
int RSA_padding_check_X931(unsigned char *to,int tlen, unsigned char *f,int fl,int rsa_len){	}
int RSA_X931_hash_id(int nid){	}
int RSA_verify_PKCS1_PSS(RSA *rsa,  unsigned char *mHash, EVP_MD *Hash,  unsigned char *EM, int sLen){	}
int RSA_padding_add_PKCS1_PSS(RSA *rsa, unsigned char *EM, unsigned char *mHash, EVP_MD *Hash, int sLen){	}
int RSA_verify_PKCS1_PSS_mgf1(RSA *rsa,  unsigned char *mHash, EVP_MD *Hash,  EVP_MD *mgf1Hash, unsigned char *EM, int sLen){	}
int RSA_padding_add_PKCS1_PSS_mgf1(RSA *rsa, unsigned char *EM, unsigned char *mHash, EVP_MD *Hash,  EVP_MD *mgf1Hash, int sLen){	}
int RSA_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func){	}
int RSA_set_ex_data(RSA *r,int idx,void *arg){	}
void *RSA_get_ex_data( RSA *r, int idx){	}
RSA *RSAPublicKey_dup(RSA *rsa){	}
RSA *RSAPrivateKey_dup(RSA *rsa){	}
void ERR_load_RSA_strings(void){	}
EC_METHOD *EC_GFp_simple_method(void){	}
EC_METHOD *EC_GFp_mont_method(void){	}
EC_METHOD *EC_GFp_nist_method(void){	}
EC_METHOD *EC_GFp_nistp224_method(void){	}
EC_METHOD *EC_GFp_nistp256_method(void){	}
EC_METHOD *EC_GFp_nistp521_method(void){	}
EC_METHOD *EC_GF2m_simple_method(void){	}
EC_GROUP *EC_GROUP_new( EC_METHOD *meth){	}
void EC_GROUP_free(EC_GROUP *group){	}
void EC_GROUP_clear_free(EC_GROUP *group){	}
int EC_GROUP_copy(EC_GROUP *dst,  EC_GROUP *src){	}
EC_GROUP *EC_GROUP_dup( EC_GROUP *src){	}
EC_METHOD *EC_GROUP_method_of( EC_GROUP *group){	}
int EC_METHOD_get_field_type( EC_METHOD *meth){	}
int EC_GROUP_set_generator(EC_GROUP *group,  EC_POINT *generator,  BIGNUM *order,  BIGNUM *cofactor){	}
EC_POINT *EC_GROUP_get0_generator( EC_GROUP *group){	}
int EC_GROUP_get_order( EC_GROUP *group, BIGNUM *order, BN_CTX *ctx){	}
int EC_GROUP_get_cofactor( EC_GROUP *group, BIGNUM *cofactor, BN_CTX *ctx){	}
void EC_GROUP_set_curve_name(EC_GROUP *group, int nid){	}
int EC_GROUP_get_curve_name( EC_GROUP *group){	}
void EC_GROUP_set_asn1_flag(EC_GROUP *group, int flag){	}
int EC_GROUP_get_asn1_flag( EC_GROUP *group){	}
void EC_GROUP_set_point_conversion_form(EC_GROUP *group, point_conversion_form_t form){	}
point_conversion_form_t EC_GROUP_get_point_conversion_form( EC_GROUP *){	}
unsigned char *EC_GROUP_get0_seed( EC_GROUP *x){	}
size_t EC_GROUP_get_seed_len( EC_GROUP *){	}
size_t EC_GROUP_set_seed(EC_GROUP *,  unsigned char *, size_t len){	}
int EC_GROUP_set_curve_GFp(EC_GROUP *group,  BIGNUM *p,  BIGNUM *a,  BIGNUM *b, BN_CTX *ctx){	}
int EC_GROUP_get_curve_GFp( EC_GROUP *group, BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *ctx){	}
int EC_GROUP_set_curve_GF2m(EC_GROUP *group,  BIGNUM *p,  BIGNUM *a,  BIGNUM *b, BN_CTX *ctx){	}
int EC_GROUP_get_curve_GF2m( EC_GROUP *group, BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *ctx){	}
int EC_GROUP_get_degree( EC_GROUP *group){	}
int EC_GROUP_check( EC_GROUP *group, BN_CTX *ctx){	}
int EC_GROUP_check_discriminant( EC_GROUP *group, BN_CTX *ctx){	}
int EC_GROUP_cmp( EC_GROUP *a,  EC_GROUP *b, BN_CTX *ctx){	}
EC_GROUP *EC_GROUP_new_curve_GFp( BIGNUM *p,  BIGNUM *a,  BIGNUM *b, BN_CTX *ctx){	}
EC_GROUP *EC_GROUP_new_curve_GF2m( BIGNUM *p,  BIGNUM *a,  BIGNUM *b, BN_CTX *ctx){	}
EC_GROUP *EC_GROUP_new_by_curve_name(int nid){	}
size_t EC_get_builtin_curves(EC_builtin_curve *r, size_t nitems){	}
EC_POINT *EC_POINT_new( EC_GROUP *group){	}
void EC_POINT_free(EC_POINT *point){	}
void EC_POINT_clear_free(EC_POINT *point){	}
int EC_POINT_copy(EC_POINT *dst,  EC_POINT *src){	}
EC_POINT *EC_POINT_dup( EC_POINT *src,  EC_GROUP *group){	}
EC_METHOD *EC_POINT_method_of( EC_POINT *point){	}
int EC_POINT_set_to_infinity( EC_GROUP *group, EC_POINT *point){	}
int EC_POINT_set_Jprojective_coordinates_GFp( EC_GROUP *group, EC_POINT *p, BIGNUM *x,  BIGNUM *y,  BIGNUM *z, BN_CTX *ctx){	}
int EC_POINT_get_Jprojective_coordinates_GFp( EC_GROUP *group, EC_POINT *p, BIGNUM *x, BIGNUM *y, BIGNUM *z, BN_CTX *ctx){	}
int EC_POINT_set_affine_coordinates_GFp( EC_GROUP *group, EC_POINT *p, BIGNUM *x,  BIGNUM *y, BN_CTX *ctx){	}
int EC_POINT_get_affine_coordinates_GFp( EC_GROUP *group, EC_POINT *p, BIGNUM *x, BIGNUM *y, BN_CTX *ctx){	}
int EC_POINT_set_compressed_coordinates_GFp( EC_GROUP *group, EC_POINT *p, BIGNUM *x, int y_bit, BN_CTX *ctx){	}
int EC_POINT_set_affine_coordinates_GF2m( EC_GROUP *group, EC_POINT *p, BIGNUM *x,  BIGNUM *y, BN_CTX *ctx){	}
int EC_POINT_get_affine_coordinates_GF2m( EC_GROUP *group, EC_POINT *p, BIGNUM *x, BIGNUM *y, BN_CTX *ctx){	}
int EC_POINT_set_compressed_coordinates_GF2m( EC_GROUP *group, EC_POINT *p, BIGNUM *x, int y_bit, BN_CTX *ctx){	}
size_t EC_POINT_point2oct( EC_GROUP *group,  EC_POINT *p, point_conversion_form_t form, unsigned char *buf, size_t len, BN_CTX *ctx){	}
int EC_POINT_oct2point( EC_GROUP *group, EC_POINT *p, unsigned char *buf, size_t len, BN_CTX *ctx){	}
BIGNUM *EC_POINT_point2bn( EC_GROUP *,  EC_POINT *, point_conversion_form_t form, BIGNUM *, BN_CTX *){	}
EC_POINT *EC_POINT_bn2point( EC_GROUP *,  BIGNUM *, EC_POINT *, BN_CTX *){	}
char *EC_POINT_point2hex( EC_GROUP *,  EC_POINT *, point_conversion_form_t form, BN_CTX *){	}
EC_POINT *EC_POINT_hex2point( EC_GROUP *,  char *, EC_POINT *, BN_CTX *){	}
int EC_POINT_add( EC_GROUP *group, EC_POINT *r,  EC_POINT *a,  EC_POINT *b, BN_CTX *ctx){	}
int EC_POINT_dbl( EC_GROUP *group, EC_POINT *r,  EC_POINT *a, BN_CTX *ctx){	}
int EC_POINT_invert( EC_GROUP *group, EC_POINT *a, BN_CTX *ctx){	}
int EC_POINT_is_at_infinity( EC_GROUP *group,  EC_POINT *p){	}
int EC_POINT_is_on_curve( EC_GROUP *group,  EC_POINT *point, BN_CTX *ctx){	}
int EC_POINT_cmp( EC_GROUP *group,  EC_POINT *a,  EC_POINT *b, BN_CTX *ctx){	}
int EC_POINT_make_affine( EC_GROUP *group, EC_POINT *point, BN_CTX *ctx){	}
int EC_POINTs_make_affine( EC_GROUP *group, size_t num, EC_POINT *points[], BN_CTX *ctx){	}
int EC_POINTs_mul( EC_GROUP *group, EC_POINT *r,  BIGNUM *n, size_t num,  EC_POINT *p[],  BIGNUM *m[], BN_CTX *ctx){	}
int EC_POINT_mul( EC_GROUP *group, EC_POINT *r,  BIGNUM *n,  EC_POINT *q,  BIGNUM *m, BN_CTX *ctx){	}
int EC_GROUP_precompute_mult(EC_GROUP *group, BN_CTX *ctx){	}
int EC_GROUP_have_precompute_mult( EC_GROUP *group){	}
int EC_GROUP_get_basis_type( EC_GROUP *){	}
int EC_GROUP_get_trinomial_basis( EC_GROUP *, unsigned int *k){	}
int EC_GROUP_get_pentanomial_basis( EC_GROUP *, unsigned int *k1, unsigned int *k2, unsigned int *k3){	}
EC_GROUP *d2i_ECPKParameters(EC_GROUP **,  unsigned char **in, long len){	}
int i2d_ECPKParameters( EC_GROUP *, unsigned char **out){	}
int     ECPKParameters_print(BIO *bp,  EC_GROUP *x, int off){	}
int     ECPKParameters_print_fp(FILE *fp,  EC_GROUP *x, int off){	}
EC_KEY *EC_KEY_new(void){	}
int EC_KEY_get_flags( EC_KEY *key){	}
void EC_KEY_set_flags(EC_KEY *key, int flags){	}
void EC_KEY_clear_flags(EC_KEY *key, int flags){	}
EC_KEY *EC_KEY_new_by_curve_name(int nid){	}
void EC_KEY_free(EC_KEY *key){	}
EC_KEY *EC_KEY_copy(EC_KEY *dst,  EC_KEY *src){	}
EC_KEY *EC_KEY_dup( EC_KEY *src){	}
int EC_KEY_up_ref(EC_KEY *key){	}
EC_GROUP *EC_KEY_get0_group( EC_KEY *key){	}
int EC_KEY_set_group(EC_KEY *key,  EC_GROUP *group){	}
BIGNUM *EC_KEY_get0_private_key( EC_KEY *key){	}
int EC_KEY_set_private_key(EC_KEY *key,  BIGNUM *prv){	}
EC_POINT *EC_KEY_get0_public_key( EC_KEY *key){	}
int EC_KEY_set_public_key(EC_KEY *key,  EC_POINT *pub){	}
unsigned EC_KEY_get_enc_flags( EC_KEY *key){	}
void EC_KEY_set_enc_flags(EC_KEY *eckey, unsigned int flags){	}
point_conversion_form_t EC_KEY_get_conv_form( EC_KEY *key){	}
void EC_KEY_set_conv_form(EC_KEY *eckey, point_conversion_form_t cform){	}
void *EC_KEY_get_key_method_data(EC_KEY *key, void *(*dup_func)(void *), void (*free_func)(void *), void (*clear_free_func)(void *)){	}
void *EC_KEY_insert_key_method_data(EC_KEY *key, void *data, void *(*dup_func)(void *), void (*free_func)(void *), void (*clear_free_func)(void *)){	}
void EC_KEY_set_asn1_flag(EC_KEY *eckey, int asn1_flag){	}
int EC_KEY_precompute_mult(EC_KEY *key, BN_CTX *ctx){	}
int EC_KEY_generate_key(EC_KEY *key){	}
int EC_KEY_check_key( EC_KEY *key){	}
int EC_KEY_set_public_key_affine_coordinates(EC_KEY *key, BIGNUM *x, BIGNUM *y){	}
EC_KEY *d2i_ECPrivateKey(EC_KEY **key,  unsigned char **in, long len){	}
int i2d_ECPrivateKey(EC_KEY *key, unsigned char **out){	}
EC_KEY *d2i_ECParameters(EC_KEY **key,  unsigned char **in, long len){	}
int i2d_ECParameters(EC_KEY *key, unsigned char **out){	}
EC_KEY *o2i_ECPublicKey(EC_KEY **key,  unsigned char **in, long len){	}
int i2o_ECPublicKey(EC_KEY *key, unsigned char **out){	}
int	ECParameters_print(BIO *bp,  EC_KEY *key){	}
int	EC_KEY_print(BIO *bp,  EC_KEY *key, int off){	}
int	ECParameters_print_fp(FILE *fp,  EC_KEY *key){	}
int	EC_KEY_print_fp(FILE *fp,  EC_KEY *key, int off){	}
void ERR_load_EC_strings(void){	}
TS_REQ	*TS_REQ_new(void){	}
void	TS_REQ_free(TS_REQ *a){	}
int	i2d_TS_REQ( TS_REQ *a, unsigned char **pp){	}
TS_REQ	*d2i_TS_REQ(TS_REQ **a,  unsigned char **pp, long length){	}
TS_REQ	*TS_REQ_dup(TS_REQ *a){	}
TS_REQ	*d2i_TS_REQ_fp(FILE *fp, TS_REQ **a){	}
int	i2d_TS_REQ_fp(FILE *fp, TS_REQ *a){	}
TS_REQ	*d2i_TS_REQ_bio(BIO *fp, TS_REQ **a){	}
int	i2d_TS_REQ_bio(BIO *fp, TS_REQ *a){	}
TS_MSG_IMPRINT	*TS_MSG_IMPRINT_new(void){	}
void		TS_MSG_IMPRINT_free(TS_MSG_IMPRINT *a){	}
int		i2d_TS_MSG_IMPRINT( TS_MSG_IMPRINT *a, unsigned char **pp){	}
TS_MSG_IMPRINT	*d2i_TS_MSG_IMPRINT(TS_MSG_IMPRINT **a, unsigned char **pp, long length){	}
TS_MSG_IMPRINT	*TS_MSG_IMPRINT_dup(TS_MSG_IMPRINT *a){	}
TS_MSG_IMPRINT	*d2i_TS_MSG_IMPRINT_fp(FILE *fp, TS_MSG_IMPRINT **a){	}
int		i2d_TS_MSG_IMPRINT_fp(FILE *fp, TS_MSG_IMPRINT *a){	}
TS_MSG_IMPRINT	*d2i_TS_MSG_IMPRINT_bio(BIO *fp, TS_MSG_IMPRINT **a){	}
int		i2d_TS_MSG_IMPRINT_bio(BIO *fp, TS_MSG_IMPRINT *a){	}
TS_RESP	*TS_RESP_new(void){	}
void	TS_RESP_free(TS_RESP *a){	}
int	i2d_TS_RESP( TS_RESP *a, unsigned char **pp){	}
TS_RESP	*d2i_TS_RESP(TS_RESP **a,  unsigned char **pp, long length){	}
TS_TST_INFO *PKCS7_to_TS_TST_INFO(PKCS7 *token){	}
TS_RESP	*TS_RESP_dup(TS_RESP *a){	}
TS_RESP	*d2i_TS_RESP_fp(FILE *fp, TS_RESP **a){	}
int	i2d_TS_RESP_fp(FILE *fp, TS_RESP *a){	}
TS_RESP	*d2i_TS_RESP_bio(BIO *fp, TS_RESP **a){	}
int	i2d_TS_RESP_bio(BIO *fp, TS_RESP *a){	}
TS_STATUS_INFO	*TS_STATUS_INFO_new(void){	}
void		TS_STATUS_INFO_free(TS_STATUS_INFO *a){	}
int		i2d_TS_STATUS_INFO( TS_STATUS_INFO *a, unsigned char **pp){	}
TS_STATUS_INFO	*d2i_TS_STATUS_INFO(TS_STATUS_INFO **a, unsigned char **pp, long length){	}
TS_STATUS_INFO	*TS_STATUS_INFO_dup(TS_STATUS_INFO *a){	}
TS_TST_INFO	*TS_TST_INFO_new(void){	}
void		TS_TST_INFO_free(TS_TST_INFO *a){	}
int		i2d_TS_TST_INFO( TS_TST_INFO *a, unsigned char **pp){	}
TS_TST_INFO	*d2i_TS_TST_INFO(TS_TST_INFO **a,  unsigned char **pp, long length){	}
TS_TST_INFO	*TS_TST_INFO_dup(TS_TST_INFO *a){	}
TS_TST_INFO	*d2i_TS_TST_INFO_fp(FILE *fp, TS_TST_INFO **a){	}
int		i2d_TS_TST_INFO_fp(FILE *fp, TS_TST_INFO *a){	}
TS_TST_INFO	*d2i_TS_TST_INFO_bio(BIO *fp, TS_TST_INFO **a){	}
int		i2d_TS_TST_INFO_bio(BIO *fp, TS_TST_INFO *a){	}
TS_ACCURACY	*TS_ACCURACY_new(void){	}
void		TS_ACCURACY_free(TS_ACCURACY *a){	}
int		i2d_TS_ACCURACY( TS_ACCURACY *a, unsigned char **pp){	}
TS_ACCURACY	*d2i_TS_ACCURACY(TS_ACCURACY **a,  unsigned char **pp, long length){	}
TS_ACCURACY	*TS_ACCURACY_dup(TS_ACCURACY *a){	}
ESS_ISSUER_SERIAL *ESS_ISSUER_SERIAL_new(void){	}
void		  ESS_ISSUER_SERIAL_free(ESS_ISSUER_SERIAL *a){	}
int		  i2d_ESS_ISSUER_SERIAL( ESS_ISSUER_SERIAL *a, unsigned char **pp){	}
ESS_ISSUER_SERIAL *d2i_ESS_ISSUER_SERIAL(ESS_ISSUER_SERIAL **a, unsigned char **pp, long length){	}
ESS_ISSUER_SERIAL *ESS_ISSUER_SERIAL_dup(ESS_ISSUER_SERIAL *a){	}
ESS_CERT_ID	*ESS_CERT_ID_new(void){	}
void		ESS_CERT_ID_free(ESS_CERT_ID *a){	}
int		i2d_ESS_CERT_ID( ESS_CERT_ID *a, unsigned char **pp){	}
ESS_CERT_ID	*d2i_ESS_CERT_ID(ESS_CERT_ID **a,  unsigned char **pp, long length){	}
ESS_CERT_ID	*ESS_CERT_ID_dup(ESS_CERT_ID *a){	}
ESS_SIGNING_CERT *ESS_SIGNING_CERT_new(void){	}
void		 ESS_SIGNING_CERT_free(ESS_SIGNING_CERT *a){	}
int		 i2d_ESS_SIGNING_CERT( ESS_SIGNING_CERT *a, unsigned char **pp){	}
ESS_SIGNING_CERT *d2i_ESS_SIGNING_CERT(ESS_SIGNING_CERT **a, unsigned char **pp, long length){	}
ESS_SIGNING_CERT *ESS_SIGNING_CERT_dup(ESS_SIGNING_CERT *a){	}
void ERR_load_TS_strings(void){	}
int TS_REQ_set_version(TS_REQ *a, long version){	}
long TS_REQ_get_version( TS_REQ *a){	}
int TS_REQ_set_msg_imprint(TS_REQ *a, TS_MSG_IMPRINT *msg_imprint){	}
TS_MSG_IMPRINT *TS_REQ_get_msg_imprint(TS_REQ *a){	}
int TS_MSG_IMPRINT_set_algo(TS_MSG_IMPRINT *a, X509_ALGOR *alg){	}
X509_ALGOR *TS_MSG_IMPRINT_get_algo(TS_MSG_IMPRINT *a){	}
int TS_MSG_IMPRINT_set_msg(TS_MSG_IMPRINT *a, unsigned char *d, int len){	}
ASN1_OCTET_STRING *TS_MSG_IMPRINT_get_msg(TS_MSG_IMPRINT *a){	}
int TS_REQ_set_policy_id(TS_REQ *a, ASN1_OBJECT *policy){	}
ASN1_OBJECT *TS_REQ_get_policy_id(TS_REQ *a){	}
int TS_REQ_set_nonce(TS_REQ *a,  ASN1_INTEGER *nonce){	}
ASN1_INTEGER *TS_REQ_get_nonce( TS_REQ *a){	}
int TS_REQ_set_cert_req(TS_REQ *a, int cert_req){	}
int TS_REQ_get_cert_req( TS_REQ *a){	}
void TS_REQ_ext_free(TS_REQ *a){	}
int TS_REQ_get_ext_count(TS_REQ *a){	}
int TS_REQ_get_ext_by_NID(TS_REQ *a, int nid, int lastpos){	}
int TS_REQ_get_ext_by_OBJ(TS_REQ *a, ASN1_OBJECT *obj, int lastpos){	}
int TS_REQ_get_ext_by_critical(TS_REQ *a, int crit, int lastpos){	}
X509_EXTENSION *TS_REQ_get_ext(TS_REQ *a, int loc){	}
X509_EXTENSION *TS_REQ_delete_ext(TS_REQ *a, int loc){	}
int TS_REQ_add_ext(TS_REQ *a, X509_EXTENSION *ex, int loc){	}
void *TS_REQ_get_ext_d2i(TS_REQ *a, int nid, int *crit, int *idx){	}
int TS_REQ_print_bio(BIO *bio, TS_REQ *a){	}
int TS_RESP_set_status_info(TS_RESP *a, TS_STATUS_INFO *info){	}
TS_STATUS_INFO *TS_RESP_get_status_info(TS_RESP *a){	}
void TS_RESP_set_tst_info(TS_RESP *a, PKCS7 *p7, TS_TST_INFO *tst_info){	}
PKCS7 *TS_RESP_get_token(TS_RESP *a){	}
TS_TST_INFO *TS_RESP_get_tst_info(TS_RESP *a){	}
int TS_TST_INFO_set_version(TS_TST_INFO *a, long version){	}
long TS_TST_INFO_get_version( TS_TST_INFO *a){	}
int TS_TST_INFO_set_policy_id(TS_TST_INFO *a, ASN1_OBJECT *policy_id){	}
ASN1_OBJECT *TS_TST_INFO_get_policy_id(TS_TST_INFO *a){	}
int TS_TST_INFO_set_msg_imprint(TS_TST_INFO *a, TS_MSG_IMPRINT *msg_imprint){	}
TS_MSG_IMPRINT *TS_TST_INFO_get_msg_imprint(TS_TST_INFO *a){	}
int TS_TST_INFO_set_serial(TS_TST_INFO *a,  ASN1_INTEGER *serial){	}
ASN1_INTEGER *TS_TST_INFO_get_serial( TS_TST_INFO *a){	}
int TS_TST_INFO_set_time(TS_TST_INFO *a,  ASN1_GENERALIZEDTIME *gtime){	}
ASN1_GENERALIZEDTIME *TS_TST_INFO_get_time( TS_TST_INFO *a){	}
int TS_TST_INFO_set_accuracy(TS_TST_INFO *a, TS_ACCURACY *accuracy){	}
TS_ACCURACY *TS_TST_INFO_get_accuracy(TS_TST_INFO *a){	}
int TS_ACCURACY_set_seconds(TS_ACCURACY *a,  ASN1_INTEGER *seconds){	}
ASN1_INTEGER *TS_ACCURACY_get_seconds( TS_ACCURACY *a){	}
int TS_ACCURACY_set_millis(TS_ACCURACY *a,  ASN1_INTEGER *millis){	}
ASN1_INTEGER *TS_ACCURACY_get_millis( TS_ACCURACY *a){	}
int TS_ACCURACY_set_micros(TS_ACCURACY *a,  ASN1_INTEGER *micros){	}
ASN1_INTEGER *TS_ACCURACY_get_micros( TS_ACCURACY *a){	}
int TS_TST_INFO_set_ordering(TS_TST_INFO *a, int ordering){	}
int TS_TST_INFO_get_ordering( TS_TST_INFO *a){	}
int TS_TST_INFO_set_nonce(TS_TST_INFO *a,  ASN1_INTEGER *nonce){	}
ASN1_INTEGER *TS_TST_INFO_get_nonce( TS_TST_INFO *a){	}
int TS_TST_INFO_set_tsa(TS_TST_INFO *a, GENERAL_NAME *tsa){	}
GENERAL_NAME *TS_TST_INFO_get_tsa(TS_TST_INFO *a){	}
void TS_TST_INFO_ext_free(TS_TST_INFO *a){	}
int TS_TST_INFO_get_ext_count(TS_TST_INFO *a){	}
int TS_TST_INFO_get_ext_by_NID(TS_TST_INFO *a, int nid, int lastpos){	}
int TS_TST_INFO_get_ext_by_OBJ(TS_TST_INFO *a, ASN1_OBJECT *obj, int lastpos){	}
int TS_TST_INFO_get_ext_by_critical(TS_TST_INFO *a, int crit, int lastpos){	}
X509_EXTENSION *TS_TST_INFO_get_ext(TS_TST_INFO *a, int loc){	}
X509_EXTENSION *TS_TST_INFO_delete_ext(TS_TST_INFO *a, int loc){	}
int TS_TST_INFO_add_ext(TS_TST_INFO *a, X509_EXTENSION *ex, int loc){	}
void *TS_TST_INFO_get_ext_d2i(TS_TST_INFO *a, int nid, int *crit, int *idx){	}
TS_RESP_CTX *TS_RESP_CTX_new(void){	}
void TS_RESP_CTX_free(TS_RESP_CTX *ctx){	}
int TS_RESP_CTX_set_signer_cert(TS_RESP_CTX *ctx, X509 *signer){	}
int TS_RESP_CTX_set_signer_key(TS_RESP_CTX *ctx, EVP_PKEY *key){	}
int TS_RESP_CTX_set_def_policy(TS_RESP_CTX *ctx, ASN1_OBJECT *def_policy){	}
int TS_RESP_CTX_set_certs(TS_RESP_CTX *ctx, STACK_OF(X509) *certs){	}
int TS_RESP_CTX_add_policy(TS_RESP_CTX *ctx, ASN1_OBJECT *policy){	}
int TS_RESP_CTX_add_md(TS_RESP_CTX *ctx,  EVP_MD *md){	}
int TS_RESP_CTX_set_accuracy(TS_RESP_CTX *ctx, int secs, int millis, int micros){	}
int TS_RESP_CTX_set_clock_precision_digits(TS_RESP_CTX *ctx, unsigned clock_precision_digits){	}
void TS_RESP_CTX_add_flags(TS_RESP_CTX *ctx, int flags){	}
void TS_RESP_CTX_set_serial_cb(TS_RESP_CTX *ctx, TS_serial_cb cb, void *data){	}
void TS_RESP_CTX_set_time_cb(TS_RESP_CTX *ctx, TS_time_cb cb, void *data){	}
void TS_RESP_CTX_set_extension_cb(TS_RESP_CTX *ctx, TS_extension_cb cb, void *data){	}
int TS_RESP_CTX_set_status_info(TS_RESP_CTX *ctx, int status,  char *text){	}
int TS_RESP_CTX_set_status_info_cond(TS_RESP_CTX *ctx, int status,  char *text){	}
int TS_RESP_CTX_add_failure_info(TS_RESP_CTX *ctx, int failure){	}
TS_REQ *TS_RESP_CTX_get_request(TS_RESP_CTX *ctx){	}
TS_TST_INFO *TS_RESP_CTX_get_tst_info(TS_RESP_CTX *ctx){	}
TS_RESP *TS_RESP_create_response(TS_RESP_CTX *ctx, BIO *req_bio){	}
int TS_RESP_verify_signature(PKCS7 *token, STACK_OF(X509) *certs, X509_STORE *store, X509 **signer_out){	}
int TS_RESP_verify_response(TS_VERIFY_CTX *ctx, TS_RESP *response){	}
int TS_RESP_verify_token(TS_VERIFY_CTX *ctx, PKCS7 *token){	}
TS_VERIFY_CTX *TS_VERIFY_CTX_new(void){	}
void TS_VERIFY_CTX_init(TS_VERIFY_CTX *ctx){	}
void TS_VERIFY_CTX_free(TS_VERIFY_CTX *ctx){	}
void TS_VERIFY_CTX_cleanup(TS_VERIFY_CTX *ctx){	}
TS_VERIFY_CTX *TS_REQ_to_TS_VERIFY_CTX(TS_REQ *req, TS_VERIFY_CTX *ctx){	}
int TS_RESP_print_bio(BIO *bio, TS_RESP *a){	}
int TS_STATUS_INFO_print_bio(BIO *bio, TS_STATUS_INFO *a){	}
int TS_TST_INFO_print_bio(BIO *bio, TS_TST_INFO *a){	}
int TS_ASN1_INTEGER_print_bio(BIO *bio,  ASN1_INTEGER *num){	}
int TS_OBJ_print_bio(BIO *bio,  ASN1_OBJECT *obj){	}
int TS_ext_print_bio(BIO *bio,  STACK_OF(X509_EXTENSION) *extensions){	}
int TS_X509_ALGOR_print_bio(BIO *bio,  X509_ALGOR *alg){	}
int TS_MSG_IMPRINT_print_bio(BIO *bio, TS_MSG_IMPRINT *msg){	}
X509 *TS_CONF_load_cert( char *file){	}
EVP_PKEY *TS_CONF_load_key( char *file,  char *pass){	}
char *TS_CONF_get_tsa_section(CONF *conf,  char *section){	}
int TS_CONF_set_serial(CONF *conf,  char *section, TS_serial_cb cb, TS_RESP_CTX *ctx){	}
int TS_CONF_set_crypto_device(CONF *conf,  char *section, char *device){	}
int TS_CONF_set_default_engine( char *name){	}
int TS_CONF_set_signer_cert(CONF *conf,  char *section, char *cert, TS_RESP_CTX *ctx){	}
int TS_CONF_set_certs(CONF *conf,  char *section,  char *certs, TS_RESP_CTX *ctx){	}
int TS_CONF_set_signer_key(CONF *conf,  char *section, char *key,  char *pass, TS_RESP_CTX *ctx){	}
int TS_CONF_set_def_policy(CONF *conf,  char *section, char *policy, TS_RESP_CTX *ctx){	}
int TS_CONF_set_policies(CONF *conf,  char *section, TS_RESP_CTX *ctx){	}
int TS_CONF_set_digests(CONF *conf,  char *section, TS_RESP_CTX *ctx){	}
int TS_CONF_set_accuracy(CONF *conf,  char *section, TS_RESP_CTX *ctx){	}
int TS_CONF_set_clock_precision_digits(CONF *conf,  char *section, TS_RESP_CTX *ctx){	}
int TS_CONF_set_ordering(CONF *conf,  char *section, TS_RESP_CTX *ctx){	}
int TS_CONF_set_tsa_name(CONF *conf,  char *section, TS_RESP_CTX *ctx){	}
int TS_CONF_set_ess_cert_id_chain(CONF *conf,  char *section, TS_RESP_CTX *ctx){	}
int sk_num( _STACK *){	}
void *sk_value( _STACK *, int){	}
void *sk_set(_STACK *, int, void *){	}
_STACK *sk_new(int (*cmp)( void *,  void *)){	}
_STACK *sk_new_null(void){	}
void sk_free(_STACK *){	}
void sk_pop_free(_STACK *st, void (*func)(void *)){	}
int sk_insert(_STACK *sk, void *data, int where){	}
void *sk_delete(_STACK *st, int loc){	}
void *sk_delete_ptr(_STACK *st, void *p){	}
int sk_find(_STACK *st, void *data){	}
int sk_find_ex(_STACK *st, void *data){	}
int sk_push(_STACK *st, void *data){	}
int sk_unshift(_STACK *st, void *data){	}
void *sk_shift(_STACK *st){	}
void *sk_pop(_STACK *st){	}
void sk_zero(_STACK *st){	}
_STACK *sk_dup(_STACK *st){	}
void sk_sort(_STACK *st){	}
int sk_is_sorted( _STACK *st){	}
void X509_CRL_set_default_method( X509_CRL_METHOD *meth){	}
X509_CRL_METHOD *X509_CRL_METHOD_new( int (*crl_init)(X509_CRL *crl), int (*crl_free)(X509_CRL *crl), int (*crl_lookup)(X509_CRL *crl, X509_REVOKED **ret, ASN1_INTEGER *ser, X509_NAME *issuer), int (*crl_verify)(X509_CRL *crl, EVP_PKEY *pk)){	}
void X509_CRL_METHOD_free(X509_CRL_METHOD *m){	}
void X509_CRL_set_meth_data(X509_CRL *crl, void *dat){	}
void *X509_CRL_get_meth_data(X509_CRL *crl){	}
char *X509_verify_cert_error_string(long n){	}
int X509_verify(X509 *a, EVP_PKEY *r){	}
int X509_REQ_verify(X509_REQ *a, EVP_PKEY *r){	}
int X509_CRL_verify(X509_CRL *a, EVP_PKEY *r){	}
int NETSCAPE_SPKI_verify(NETSCAPE_SPKI *a, EVP_PKEY *r){	}
NETSCAPE_SPKI * NETSCAPE_SPKI_b64_decode( char *str, int len){	}
char * NETSCAPE_SPKI_b64_encode(NETSCAPE_SPKI *x){	}
EVP_PKEY *NETSCAPE_SPKI_get_pubkey(NETSCAPE_SPKI *x){	}
int NETSCAPE_SPKI_set_pubkey(NETSCAPE_SPKI *x, EVP_PKEY *pkey){	}
int NETSCAPE_SPKI_print(BIO *out, NETSCAPE_SPKI *spki){	}
int X509_signature_dump(BIO *bp, ASN1_STRING *sig, int indent){	}
int X509_signature_print(BIO *bp,X509_ALGOR *alg, ASN1_STRING *sig){	}
int X509_sign(X509 *x, EVP_PKEY *pkey,  EVP_MD *md){	}
int X509_sign_ctx(X509 *x, EVP_MD_CTX *ctx){	}
int X509_REQ_sign(X509_REQ *x, EVP_PKEY *pkey,  EVP_MD *md){	}
int X509_REQ_sign_ctx(X509_REQ *x, EVP_MD_CTX *ctx){	}
int X509_CRL_sign(X509_CRL *x, EVP_PKEY *pkey,  EVP_MD *md){	}
int X509_CRL_sign_ctx(X509_CRL *x, EVP_MD_CTX *ctx){	}
int NETSCAPE_SPKI_sign(NETSCAPE_SPKI *x, EVP_PKEY *pkey,  EVP_MD *md){	}
int X509_pubkey_digest( X509 *data, EVP_MD *type, unsigned char *md, unsigned int *len){	}
int X509_digest( X509 *data, EVP_MD *type, unsigned char *md, unsigned int *len){	}
int X509_CRL_digest( X509_CRL *data, EVP_MD *type, unsigned char *md, unsigned int *len){	}
int X509_REQ_digest( X509_REQ *data, EVP_MD *type, unsigned char *md, unsigned int *len){	}
int X509_NAME_digest( X509_NAME *data, EVP_MD *type, unsigned char *md, unsigned int *len){	}
X509 *d2i_X509_fp(FILE *fp, X509 **x509){	}
int i2d_X509_fp(FILE *fp,X509 *x509){	}
X509_CRL *d2i_X509_CRL_fp(FILE *fp,X509_CRL **crl){	}
int i2d_X509_CRL_fp(FILE *fp,X509_CRL *crl){	}
X509_REQ *d2i_X509_REQ_fp(FILE *fp,X509_REQ **req){	}
int i2d_X509_REQ_fp(FILE *fp,X509_REQ *req){	}
RSA *d2i_RSAPrivateKey_fp(FILE *fp,RSA **rsa){	}
int i2d_RSAPrivateKey_fp(FILE *fp,RSA *rsa){	}
RSA *d2i_RSAPublicKey_fp(FILE *fp,RSA **rsa){	}
int i2d_RSAPublicKey_fp(FILE *fp,RSA *rsa){	}
RSA *d2i_RSA_PUBKEY_fp(FILE *fp,RSA **rsa){	}
int i2d_RSA_PUBKEY_fp(FILE *fp,RSA *rsa){	}
DSA *d2i_DSA_PUBKEY_fp(FILE *fp, DSA **dsa){	}
int i2d_DSA_PUBKEY_fp(FILE *fp, DSA *dsa){	}
DSA *d2i_DSAPrivateKey_fp(FILE *fp, DSA **dsa){	}
int i2d_DSAPrivateKey_fp(FILE *fp, DSA *dsa){	}
EC_KEY *d2i_EC_PUBKEY_fp(FILE *fp, EC_KEY **eckey){	}
int   i2d_EC_PUBKEY_fp(FILE *fp, EC_KEY *eckey){	}
EC_KEY *d2i_ECPrivateKey_fp(FILE *fp, EC_KEY **eckey){	}
int   i2d_ECPrivateKey_fp(FILE *fp, EC_KEY *eckey){	}
X509_SIG *d2i_PKCS8_fp(FILE *fp,X509_SIG **p8){	}
int i2d_PKCS8_fp(FILE *fp,X509_SIG *p8){	}
PKCS8_PRIV_KEY_INFO *d2i_PKCS8_PRIV_KEY_INFO_fp(FILE *fp, PKCS8_PRIV_KEY_INFO **p8inf){	}
int i2d_PKCS8_PRIV_KEY_INFO_fp(FILE *fp,PKCS8_PRIV_KEY_INFO *p8inf){	}
int i2d_PKCS8PrivateKeyInfo_fp(FILE *fp, EVP_PKEY *key){	}
int i2d_PrivateKey_fp(FILE *fp, EVP_PKEY *pkey){	}
EVP_PKEY *d2i_PrivateKey_fp(FILE *fp, EVP_PKEY **a){	}
int i2d_PUBKEY_fp(FILE *fp, EVP_PKEY *pkey){	}
EVP_PKEY *d2i_PUBKEY_fp(FILE *fp, EVP_PKEY **a){	}
X509 *d2i_X509_bio(BIO *bp,X509 **x509){	}
int i2d_X509_bio(BIO *bp,X509 *x509){	}
X509_CRL *d2i_X509_CRL_bio(BIO *bp,X509_CRL **crl){	}
int i2d_X509_CRL_bio(BIO *bp,X509_CRL *crl){	}
X509_REQ *d2i_X509_REQ_bio(BIO *bp,X509_REQ **req){	}
int i2d_X509_REQ_bio(BIO *bp,X509_REQ *req){	}
RSA *d2i_RSAPrivateKey_bio(BIO *bp,RSA **rsa){	}
int i2d_RSAPrivateKey_bio(BIO *bp,RSA *rsa){	}
RSA *d2i_RSAPublicKey_bio(BIO *bp,RSA **rsa){	}
int i2d_RSAPublicKey_bio(BIO *bp,RSA *rsa){	}
RSA *d2i_RSA_PUBKEY_bio(BIO *bp,RSA **rsa){	}
int i2d_RSA_PUBKEY_bio(BIO *bp,RSA *rsa){	}
DSA *d2i_DSA_PUBKEY_bio(BIO *bp, DSA **dsa){	}
int i2d_DSA_PUBKEY_bio(BIO *bp, DSA *dsa){	}
DSA *d2i_DSAPrivateKey_bio(BIO *bp, DSA **dsa){	}
int i2d_DSAPrivateKey_bio(BIO *bp, DSA *dsa){	}
EC_KEY *d2i_EC_PUBKEY_bio(BIO *bp, EC_KEY **eckey){	}
int   i2d_EC_PUBKEY_bio(BIO *bp, EC_KEY *eckey){	}
EC_KEY *d2i_ECPrivateKey_bio(BIO *bp, EC_KEY **eckey){	}
int   i2d_ECPrivateKey_bio(BIO *bp, EC_KEY *eckey){	}
X509_SIG *d2i_PKCS8_bio(BIO *bp,X509_SIG **p8){	}
int i2d_PKCS8_bio(BIO *bp,X509_SIG *p8){	}
PKCS8_PRIV_KEY_INFO *d2i_PKCS8_PRIV_KEY_INFO_bio(BIO *bp, PKCS8_PRIV_KEY_INFO **p8inf){	}
int i2d_PKCS8_PRIV_KEY_INFO_bio(BIO *bp,PKCS8_PRIV_KEY_INFO *p8inf){	}
int i2d_PKCS8PrivateKeyInfo_bio(BIO *bp, EVP_PKEY *key){	}
int i2d_PrivateKey_bio(BIO *bp, EVP_PKEY *pkey){	}
EVP_PKEY *d2i_PrivateKey_bio(BIO *bp, EVP_PKEY **a){	}
int i2d_PUBKEY_bio(BIO *bp, EVP_PKEY *pkey){	}
EVP_PKEY *d2i_PUBKEY_bio(BIO *bp, EVP_PKEY **a){	}
X509 *X509_dup(X509 *x509){	}
X509_ATTRIBUTE *X509_ATTRIBUTE_dup(X509_ATTRIBUTE *xa){	}
X509_EXTENSION *X509_EXTENSION_dup(X509_EXTENSION *ex){	}
X509_CRL *X509_CRL_dup(X509_CRL *crl){	}
X509_REQ *X509_REQ_dup(X509_REQ *req){	}
X509_ALGOR *X509_ALGOR_dup(X509_ALGOR *xn){	}
int X509_ALGOR_set0(X509_ALGOR *alg, ASN1_OBJECT *aobj, int ptype, void *pval){	}
void X509_ALGOR_get0(ASN1_OBJECT **paobj, int *pptype, void **ppval, X509_ALGOR *algor){	}
void X509_ALGOR_set_md(X509_ALGOR *alg,  EVP_MD *md){	}
X509_NAME *X509_NAME_dup(X509_NAME *xn){	}
X509_NAME_ENTRY *X509_NAME_ENTRY_dup(X509_NAME_ENTRY *ne){	}
int		X509_cmp_time( ASN1_TIME *s, time_t *t){	}
int		X509_cmp_current_time( ASN1_TIME *s){	}
ASN1_TIME *	X509_time_adj(ASN1_TIME *s, long adj, time_t *t){	}
ASN1_TIME *	X509_time_adj_ex(ASN1_TIME *s, int offset_day, long offset_sec, time_t *t){	}
ASN1_TIME *	X509_gmtime_adj(ASN1_TIME *s, long adj){	}
char *	X509_get_default_cert_area(void ){	}
char *	X509_get_default_cert_dir(void ){	}
char *	X509_get_default_cert_file(void ){	}
char *	X509_get_default_cert_dir_env(void ){	}
char *	X509_get_default_cert_file_env(void ){	}
char *	X509_get_default_private_dir(void ){	}
X509_REQ *	X509_to_X509_REQ(X509 *x, EVP_PKEY *pkey,  EVP_MD *md){	}
X509 *		X509_REQ_to_X509(X509_REQ *r, int days,EVP_PKEY *pkey){	}
EVP_PKEY *	X509_PUBKEY_get(X509_PUBKEY *key){	}
int		X509_get_pubkey_parameters(EVP_PKEY *pkey, STACK_OF(X509) *chain){	}
int		i2d_PUBKEY(EVP_PKEY *a,unsigned char **pp){	}
EVP_PKEY *	d2i_PUBKEY(EVP_PKEY **a, unsigned char **pp, long length){	}
int		i2d_RSA_PUBKEY(RSA *a,unsigned char **pp){	}
RSA *		d2i_RSA_PUBKEY(RSA **a, unsigned char **pp, long length){	}
int		i2d_DSA_PUBKEY(DSA *a,unsigned char **pp){	}
DSA *		d2i_DSA_PUBKEY(DSA **a, unsigned char **pp, long length){	}
int		i2d_EC_PUBKEY(EC_KEY *a, unsigned char **pp){	}
EC_KEY 		*d2i_EC_PUBKEY(EC_KEY **a,  unsigned char **pp, long length){	}
int X509_set_ex_data(X509 *r, int idx, void *arg){	}
void *X509_get_ex_data(X509 *r, int idx){	}
int		i2d_X509_AUX(X509 *a,unsigned char **pp){	}
X509 *		d2i_X509_AUX(X509 **a, unsigned char **pp,long length){	}
int X509_alias_set1(X509 *x, unsigned char *name, int len){	}
int X509_keyid_set1(X509 *x, unsigned char *id, int len){	}
unsigned char * X509_alias_get0(X509 *x, int *len){	}
unsigned char * X509_keyid_get0(X509 *x, int *len){	}
int X509_TRUST_set(int *t, int trust){	}
int X509_add1_trust_object(X509 *x, ASN1_OBJECT *obj){	}
int X509_add1_reject_object(X509 *x, ASN1_OBJECT *obj){	}
void X509_trust_clear(X509 *x){	}
void X509_reject_clear(X509 *x){	}
int X509_CRL_get0_by_serial(X509_CRL *crl, X509_REVOKED **ret, ASN1_INTEGER *serial){	}
int X509_CRL_get0_by_cert(X509_CRL *crl, X509_REVOKED **ret, X509 *x){	}
X509_PKEY *	X509_PKEY_new(void ){	}
void		X509_PKEY_free(X509_PKEY *a){	}
int		i2d_X509_PKEY(X509_PKEY *a,unsigned char **pp){	}
X509_PKEY *	d2i_X509_PKEY(X509_PKEY **a, unsigned char **pp,long length){	}
X509_INFO *	X509_INFO_new(void){	}
void		X509_INFO_free(X509_INFO *a){	}
char *		X509_NAME_oneline(X509_NAME *a,char *buf,int size){	}
int ASN1_verify(i2d_of_void *i2d, X509_ALGOR *algor1, ASN1_BIT_STRING *signature,char *data,EVP_PKEY *pkey){	}
int ASN1_digest(i2d_of_void *i2d, EVP_MD *type,char *data, unsigned char *md,unsigned int *len){	}
int ASN1_sign(i2d_of_void *i2d, X509_ALGOR *algor1, X509_ALGOR *algor2, ASN1_BIT_STRING *signature, char *data,EVP_PKEY *pkey,  EVP_MD *type){	}
int ASN1_item_digest( ASN1_ITEM *it, EVP_MD *type,void *data, unsigned char *md,unsigned int *len){	}
int ASN1_item_verify( ASN1_ITEM *it, X509_ALGOR *algor1, ASN1_BIT_STRING *signature,void *data,EVP_PKEY *pkey){	}
int ASN1_item_sign( ASN1_ITEM *it, X509_ALGOR *algor1, X509_ALGOR *algor2, ASN1_BIT_STRING *signature, void *data, EVP_PKEY *pkey,  EVP_MD *type){	}
int ASN1_item_sign_ctx( ASN1_ITEM *it, X509_ALGOR *algor1, X509_ALGOR *algor2, ASN1_BIT_STRING *signature, void *asn, EVP_MD_CTX *ctx){	}
int 		X509_set_version(X509 *x,long version){	}
int 		X509_set_serialNumber(X509 *x, ASN1_INTEGER *serial){	}
ASN1_INTEGER *	X509_get_serialNumber(X509 *x){	}
int 		X509_set_issuer_name(X509 *x, X509_NAME *name){	}
X509_NAME *	X509_get_issuer_name(X509 *a){	}
int 		X509_set_subject_name(X509 *x, X509_NAME *name){	}
X509_NAME *	X509_get_subject_name(X509 *a){	}
int 		X509_set_notBefore(X509 *x,  ASN1_TIME *tm){	}
int 		X509_set_notAfter(X509 *x,  ASN1_TIME *tm){	}
int 		X509_set_pubkey(X509 *x, EVP_PKEY *pkey){	}
EVP_PKEY *	X509_get_pubkey(X509 *x){	}
ASN1_BIT_STRING * X509_get0_pubkey_bitstr( X509 *x){	}
int		X509_certificate_type(X509 *x,EVP_PKEY *pubkey /* optional */){	}
int		X509_REQ_set_version(X509_REQ *x,long version){	}
int		X509_REQ_set_subject_name(X509_REQ *req,X509_NAME *name){	}
int		X509_REQ_set_pubkey(X509_REQ *x, EVP_PKEY *pkey){	}
EVP_PKEY *	X509_REQ_get_pubkey(X509_REQ *req){	}
int		X509_REQ_extension_nid(int nid){	}
int *		X509_REQ_get_extension_nids(void){	}
void		X509_REQ_set_extension_nids(int *nids){	}
int X509_REQ_add_extensions_nid(X509_REQ *req, STACK_OF(X509_EXTENSION) *exts, int nid){	}
int X509_REQ_add_extensions(X509_REQ *req, STACK_OF(X509_EXTENSION) *exts){	}
int X509_REQ_get_attr_count( X509_REQ *req){	}
int X509_REQ_get_attr_by_NID( X509_REQ *req, int nid, int lastpos){	}
int X509_REQ_get_attr_by_OBJ( X509_REQ *req, ASN1_OBJECT *obj, int lastpos){	}
X509_ATTRIBUTE *X509_REQ_get_attr( X509_REQ *req, int loc){	}
X509_ATTRIBUTE *X509_REQ_delete_attr(X509_REQ *req, int loc){	}
int X509_REQ_add1_attr(X509_REQ *req, X509_ATTRIBUTE *attr){	}
int X509_REQ_add1_attr_by_OBJ(X509_REQ *req, ASN1_OBJECT *obj, int type, unsigned char *bytes, int len){	}
int X509_REQ_add1_attr_by_NID(X509_REQ *req, int nid, int type, unsigned char *bytes, int len){	}
int X509_REQ_add1_attr_by_txt(X509_REQ *req, char *attrname, int type, unsigned char *bytes, int len){	}
int X509_CRL_set_version(X509_CRL *x, long version){	}
int X509_CRL_set_issuer_name(X509_CRL *x, X509_NAME *name){	}
int X509_CRL_set_lastUpdate(X509_CRL *x,  ASN1_TIME *tm){	}
int X509_CRL_set_nextUpdate(X509_CRL *x,  ASN1_TIME *tm){	}
int X509_CRL_sort(X509_CRL *crl){	}
int X509_REVOKED_set_serialNumber(X509_REVOKED *x, ASN1_INTEGER *serial){	}
int X509_REVOKED_set_revocationDate(X509_REVOKED *r, ASN1_TIME *tm){	}
int		X509_REQ_check_private_key(X509_REQ *x509,EVP_PKEY *pkey){	}
int		X509_check_private_key(X509 *x509,EVP_PKEY *pkey){	}
int		X509_issuer_and_serial_cmp( X509 *a,  X509 *b){	}
unsigned long	X509_issuer_and_serial_hash(X509 *a){	}
int		X509_issuer_name_cmp( X509 *a,  X509 *b){	}
unsigned long	X509_issuer_name_hash(X509 *a){	}
int		X509_subject_name_cmp( X509 *a,  X509 *b){	}
unsigned long	X509_subject_name_hash(X509 *x){	}
unsigned long	X509_issuer_name_hash_old(X509 *a){	}
unsigned long	X509_subject_name_hash_old(X509 *x){	}
int		X509_cmp( X509 *a,  X509 *b){	}
int		X509_NAME_cmp( X509_NAME *a,  X509_NAME *b){	}
unsigned long	X509_NAME_hash(X509_NAME *x){	}
unsigned long	X509_NAME_hash_old(X509_NAME *x){	}
int		X509_CRL_cmp( X509_CRL *a,  X509_CRL *b){	}
int		X509_CRL_match( X509_CRL *a,  X509_CRL *b){	}
int		X509_print_ex_fp(FILE *bp,X509 *x, unsigned long nmflag, unsigned long cflag){	}
int		X509_print_fp(FILE *bp,X509 *x){	}
int		X509_CRL_print_fp(FILE *bp,X509_CRL *x){	}
int		X509_REQ_print_fp(FILE *bp,X509_REQ *req){	}
int X509_NAME_print_ex_fp(FILE *fp, X509_NAME *nm, int indent, unsigned long flags){	}
int		X509_NAME_print(BIO *bp, X509_NAME *name, int obase){	}
int X509_NAME_print_ex(BIO *out, X509_NAME *nm, int indent, unsigned long flags){	}
int		X509_print_ex(BIO *bp,X509 *x, unsigned long nmflag, unsigned long cflag){	}
int		X509_print(BIO *bp,X509 *x){	}
int		X509_ocspid_print(BIO *bp,X509 *x){	}
int		X509_CERT_AUX_print(BIO *bp,X509_CERT_AUX *x, int indent){	}
int		X509_CRL_print(BIO *bp,X509_CRL *x){	}
int		X509_REQ_print_ex(BIO *bp, X509_REQ *x, unsigned long nmflag, unsigned long cflag){	}
int		X509_REQ_print(BIO *bp,X509_REQ *req){	}
int 		X509_NAME_entry_count(X509_NAME *name){	}
int 		X509_NAME_get_text_by_NID(X509_NAME *name, int nid, char *buf,int len){	}
int		X509_NAME_get_text_by_OBJ(X509_NAME *name, ASN1_OBJECT *obj, char *buf,int len){	}
int 		X509_NAME_get_index_by_NID(X509_NAME *name,int nid,int lastpos){	}
int 		X509_NAME_get_index_by_OBJ(X509_NAME *name,ASN1_OBJECT *obj, int lastpos){	}
X509_NAME_ENTRY *X509_NAME_get_entry(X509_NAME *name, int loc){	}
X509_NAME_ENTRY *X509_NAME_delete_entry(X509_NAME *name, int loc){	}
int 		X509_NAME_add_entry(X509_NAME *name,X509_NAME_ENTRY *ne, int loc, int set){	}
int X509_NAME_add_entry_by_OBJ(X509_NAME *name, ASN1_OBJECT *obj, int type, unsigned char *bytes, int len, int loc, int set){	}
int X509_NAME_add_entry_by_NID(X509_NAME *name, int nid, int type, unsigned char *bytes, int len, int loc, int set){	}
X509_NAME_ENTRY *X509_NAME_ENTRY_create_by_txt(X509_NAME_ENTRY **ne, char *field, int type,  unsigned char *bytes, int len){	}
X509_NAME_ENTRY *X509_NAME_ENTRY_create_by_NID(X509_NAME_ENTRY **ne, int nid, int type,unsigned char *bytes, int len){	}
int X509_NAME_add_entry_by_txt(X509_NAME *name,  char *field, int type, unsigned char *bytes, int len, int loc, int set){	}
X509_NAME_ENTRY *X509_NAME_ENTRY_create_by_OBJ(X509_NAME_ENTRY **ne, ASN1_OBJECT *obj, int type, unsigned char *bytes, int len){	}
int 		X509_NAME_ENTRY_set_object(X509_NAME_ENTRY *ne, ASN1_OBJECT *obj){	}
int 		X509_NAME_ENTRY_set_data(X509_NAME_ENTRY *ne, int type, unsigned char *bytes, int len){	}
ASN1_OBJECT *	X509_NAME_ENTRY_get_object(X509_NAME_ENTRY *ne){	}
ASN1_STRING *	X509_NAME_ENTRY_get_data(X509_NAME_ENTRY *ne){	}
int		X509v3_get_ext_count( STACK_OF(X509_EXTENSION) *x){	}
int		X509v3_get_ext_by_NID( STACK_OF(X509_EXTENSION) *x, int nid, int lastpos){	}
int		X509v3_get_ext_by_OBJ( STACK_OF(X509_EXTENSION) *x, ASN1_OBJECT *obj,int lastpos){	}
int		X509v3_get_ext_by_critical( STACK_OF(X509_EXTENSION) *x, int crit, int lastpos){	}
X509_EXTENSION *X509v3_get_ext( STACK_OF(X509_EXTENSION) *x, int loc){	}
X509_EXTENSION *X509v3_delete_ext(STACK_OF(X509_EXTENSION) *x, int loc){	}
int		X509_get_ext_count(X509 *x){	}
int		X509_get_ext_by_NID(X509 *x, int nid, int lastpos){	}
int		X509_get_ext_by_OBJ(X509 *x,ASN1_OBJECT *obj,int lastpos){	}
int		X509_get_ext_by_critical(X509 *x, int crit, int lastpos){	}
X509_EXTENSION *X509_get_ext(X509 *x, int loc){	}
X509_EXTENSION *X509_delete_ext(X509 *x, int loc){	}
int		X509_add_ext(X509 *x, X509_EXTENSION *ex, int loc){	}
void	*	X509_get_ext_d2i(X509 *x, int nid, int *crit, int *idx){	}
int		X509_add1_ext_i2d(X509 *x, int nid, void *value, int crit, unsigned long flags){	}
int		X509_CRL_get_ext_count(X509_CRL *x){	}
int		X509_CRL_get_ext_by_NID(X509_CRL *x, int nid, int lastpos){	}
int		X509_CRL_get_ext_by_OBJ(X509_CRL *x,ASN1_OBJECT *obj,int lastpos){	}
int		X509_CRL_get_ext_by_critical(X509_CRL *x, int crit, int lastpos){	}
X509_EXTENSION *X509_CRL_get_ext(X509_CRL *x, int loc){	}
X509_EXTENSION *X509_CRL_delete_ext(X509_CRL *x, int loc){	}
int		X509_CRL_add_ext(X509_CRL *x, X509_EXTENSION *ex, int loc){	}
void	*	X509_CRL_get_ext_d2i(X509_CRL *x, int nid, int *crit, int *idx){	}
int		X509_CRL_add1_ext_i2d(X509_CRL *x, int nid, void *value, int crit, unsigned long flags){	}
int		X509_REVOKED_get_ext_count(X509_REVOKED *x){	}
int		X509_REVOKED_get_ext_by_NID(X509_REVOKED *x, int nid, int lastpos){	}
int		X509_REVOKED_get_ext_by_OBJ(X509_REVOKED *x,ASN1_OBJECT *obj,int lastpos){	}
int		X509_REVOKED_get_ext_by_critical(X509_REVOKED *x, int crit, int lastpos){	}
X509_EXTENSION *X509_REVOKED_get_ext(X509_REVOKED *x, int loc){	}
X509_EXTENSION *X509_REVOKED_delete_ext(X509_REVOKED *x, int loc){	}
int		X509_REVOKED_add_ext(X509_REVOKED *x, X509_EXTENSION *ex, int loc){	}
void	*	X509_REVOKED_get_ext_d2i(X509_REVOKED *x, int nid, int *crit, int *idx){	}
int		X509_REVOKED_add1_ext_i2d(X509_REVOKED *x, int nid, void *value, int crit, unsigned long flags){	}
X509_EXTENSION *X509_EXTENSION_create_by_NID(X509_EXTENSION **ex, int nid, int crit, ASN1_OCTET_STRING *data){	}
X509_EXTENSION *X509_EXTENSION_create_by_OBJ(X509_EXTENSION **ex, ASN1_OBJECT *obj,int crit,ASN1_OCTET_STRING *data){	}
int		X509_EXTENSION_set_object(X509_EXTENSION *ex,ASN1_OBJECT *obj){	}
int		X509_EXTENSION_set_critical(X509_EXTENSION *ex, int crit){	}
int		X509_EXTENSION_set_data(X509_EXTENSION *ex, ASN1_OCTET_STRING *data){	}
ASN1_OBJECT *	X509_EXTENSION_get_object(X509_EXTENSION *ex){	}
ASN1_OCTET_STRING *X509_EXTENSION_get_data(X509_EXTENSION *ne){	}
int		X509_EXTENSION_get_critical(X509_EXTENSION *ex){	}
int X509at_get_attr_count( STACK_OF(X509_ATTRIBUTE) *x){	}
int X509at_get_attr_by_NID( STACK_OF(X509_ATTRIBUTE) *x, int nid, int lastpos){	}
int X509at_get_attr_by_OBJ( STACK_OF(X509_ATTRIBUTE) *sk, ASN1_OBJECT *obj, int lastpos){	}
X509_ATTRIBUTE *X509at_get_attr( STACK_OF(X509_ATTRIBUTE) *x, int loc){	}
X509_ATTRIBUTE *X509at_delete_attr(STACK_OF(X509_ATTRIBUTE) *x, int loc){	}
void *X509at_get0_data_by_OBJ(STACK_OF(X509_ATTRIBUTE) *x, ASN1_OBJECT *obj, int lastpos, int type){	}
X509_ATTRIBUTE *X509_ATTRIBUTE_create_by_NID(X509_ATTRIBUTE **attr, int nid, int atrtype,  void *data, int len){	}
X509_ATTRIBUTE *X509_ATTRIBUTE_create_by_OBJ(X509_ATTRIBUTE **attr, ASN1_OBJECT *obj, int atrtype,  void *data, int len){	}
X509_ATTRIBUTE *X509_ATTRIBUTE_create_by_txt(X509_ATTRIBUTE **attr, char *atrname, int type,  unsigned char *bytes, int len){	}
int X509_ATTRIBUTE_set1_object(X509_ATTRIBUTE *attr,  ASN1_OBJECT *obj){	}
int X509_ATTRIBUTE_set1_data(X509_ATTRIBUTE *attr, int attrtype,  void *data, int len){	}
void *X509_ATTRIBUTE_get0_data(X509_ATTRIBUTE *attr, int idx, int atrtype, void *data){	}
int X509_ATTRIBUTE_count(X509_ATTRIBUTE *attr){	}
ASN1_OBJECT *X509_ATTRIBUTE_get0_object(X509_ATTRIBUTE *attr){	}
ASN1_TYPE *X509_ATTRIBUTE_get0_type(X509_ATTRIBUTE *attr, int idx){	}
int EVP_PKEY_get_attr_count( EVP_PKEY *key){	}
int EVP_PKEY_get_attr_by_NID( EVP_PKEY *key, int nid, int lastpos){	}
int EVP_PKEY_get_attr_by_OBJ( EVP_PKEY *key, ASN1_OBJECT *obj, int lastpos){	}
X509_ATTRIBUTE *EVP_PKEY_get_attr( EVP_PKEY *key, int loc){	}
X509_ATTRIBUTE *EVP_PKEY_delete_attr(EVP_PKEY *key, int loc){	}
int EVP_PKEY_add1_attr(EVP_PKEY *key, X509_ATTRIBUTE *attr){	}
int EVP_PKEY_add1_attr_by_OBJ(EVP_PKEY *key, ASN1_OBJECT *obj, int type, unsigned char *bytes, int len){	}
int EVP_PKEY_add1_attr_by_NID(EVP_PKEY *key, int nid, int type, unsigned char *bytes, int len){	}
int EVP_PKEY_add1_attr_by_txt(EVP_PKEY *key, char *attrname, int type, unsigned char *bytes, int len){	}
int		X509_verify_cert(X509_STORE_CTX *ctx){	}
X509 *X509_find_by_issuer_and_serial(STACK_OF(X509) *sk,X509_NAME *name, ASN1_INTEGER *serial){	}
X509 *X509_find_by_subject(STACK_OF(X509) *sk,X509_NAME *name){	}
X509_ALGOR *PKCS5_pbe_set(int alg, int iter, unsigned char *salt, int saltlen){	}
X509_ALGOR *PKCS5_pbe2_set( EVP_CIPHER *cipher, int iter, unsigned char *salt, int saltlen){	}
X509_ALGOR *PKCS5_pbe2_set_iv( EVP_CIPHER *cipher, int iter, unsigned char *salt, int saltlen, unsigned char *aiv, int prf_nid){	}
X509_ALGOR *PKCS5_pbkdf2_set(int iter, unsigned char *salt, int saltlen, int prf_nid, int keylen){	}
PKCS8_PRIV_KEY_INFO *EVP_PKEY2PKCS8(EVP_PKEY *pkey){	}
PKCS8_PRIV_KEY_INFO *EVP_PKEY2PKCS8_broken(EVP_PKEY *pkey, int broken){	}
PKCS8_PRIV_KEY_INFO *PKCS8_set_broken(PKCS8_PRIV_KEY_INFO *p8, int broken){	}
int PKCS8_pkey_set0(PKCS8_PRIV_KEY_INFO *priv, ASN1_OBJECT *aobj, int version, int ptype, void *pval, unsigned char *penc, int penclen){	}
int PKCS8_pkey_get0(ASN1_OBJECT **ppkalg, unsigned char **pk, int *ppklen, X509_ALGOR **pa, PKCS8_PRIV_KEY_INFO *p8){	}
int X509_PUBKEY_set0_param(X509_PUBKEY *pub, ASN1_OBJECT *aobj, int ptype, void *pval, unsigned char *penc, int penclen){	}
int X509_PUBKEY_get0_param(ASN1_OBJECT **ppkalg, unsigned char **pk, int *ppklen, X509_ALGOR **pa, X509_PUBKEY *pub){	}
int X509_check_trust(X509 *x, int id, int flags){	}
int X509_TRUST_get_count(void){	}
X509_TRUST * X509_TRUST_get0(int idx){	}
int X509_TRUST_get_by_id(int id){	}
int X509_TRUST_add(int id, int flags, int (*ck)(X509_TRUST *, X509 *, int), char *name, int arg1, void *arg2){	}
void X509_TRUST_cleanup(void){	}
int X509_TRUST_get_flags(X509_TRUST *xp){	}
char *X509_TRUST_get0_name(X509_TRUST *xp){	}
int X509_TRUST_get_trust(X509_TRUST *xp){	}
void ERR_load_X509_strings(void){	}
_LHASH *lh_new(LHASH_HASH_FN_TYPE h, LHASH_COMP_FN_TYPE c){	}
void lh_free(_LHASH *lh){	}
void *lh_insert(_LHASH *lh, void *data){	}
void *lh_delete(_LHASH *lh,  void *data){	}
void *lh_retrieve(_LHASH *lh,  void *data){	}
void lh_doall(_LHASH *lh, LHASH_DOALL_FN_TYPE func){	}
void lh_doall_arg(_LHASH *lh, LHASH_DOALL_ARG_FN_TYPE func, void *arg){	}
unsigned long lh_strhash( char *c){	}
unsigned long lh_num_items( _LHASH *lh){	}
void lh_stats( _LHASH *lh, FILE *out){	}
void lh_node_stats( _LHASH *lh, FILE *out){	}
void lh_node_usage_stats( _LHASH *lh, FILE *out){	}
void lh_stats_bio( _LHASH *lh, BIO *out){	}
void lh_node_stats_bio( _LHASH *lh, BIO *out){	}
void lh_node_usage_stats_bio( _LHASH *lh, BIO *out){	}
UI *UI_new(void){	}
UI *UI_new_method( UI_METHOD *method){	}
void UI_free(UI *ui){	}
int UI_add_input_string(UI *ui,  char *prompt, int flags, char *result_buf, int minsize, int maxsize){	}
int UI_dup_input_string(UI *ui,  char *prompt, int flags, char *result_buf, int minsize, int maxsize){	}
int UI_add_verify_string(UI *ui,  char *prompt, int flags, char *result_buf, int minsize, int maxsize,  char *test_buf){	}
int UI_dup_verify_string(UI *ui,  char *prompt, int flags, char *result_buf, int minsize, int maxsize,  char *test_buf){	}
int UI_add_input_boolean(UI *ui,  char *prompt,  char *action_desc, char *ok_chars,  char *cancel_chars, int flags, char *result_buf){	}
int UI_dup_input_boolean(UI *ui,  char *prompt,  char *action_desc, char *ok_chars,  char *cancel_chars, int flags, char *result_buf){	}
int UI_add_info_string(UI *ui,  char *text){	}
int UI_dup_info_string(UI *ui,  char *text){	}
int UI_add_error_string(UI *ui,  char *text){	}
int UI_dup_error_string(UI *ui,  char *text){	}
char *UI_construct_prompt(UI *ui_method, char *object_desc,  char *object_name){	}
void *UI_add_user_data(UI *ui, void *user_data){	}
void *UI_get0_user_data(UI *ui){	}
char *UI_get0_result(UI *ui, int i){	}
int UI_process(UI *ui){	}
int UI_ctrl(UI *ui, int cmd, long i, void *p, void (*f)(void)){	}
int UI_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func){	}
int UI_set_ex_data(UI *r,int idx,void *arg){	}
void *UI_get_ex_data(UI *r, int idx){	}
void UI_set_default_method( UI_METHOD *meth){	}
UI_METHOD *UI_get_default_method(void){	}
UI_METHOD *UI_get_method(UI *ui){	}
UI_METHOD *UI_set_method(UI *ui,  UI_METHOD *meth){	}
UI_METHOD *UI_OpenSSL(void){	}
UI_METHOD *UI_create_method(char *name){	}
void UI_destroy_method(UI_METHOD *ui_method){	}
int UI_method_set_opener(UI_METHOD *method, int (*opener)(UI *ui)){	}
int UI_method_set_writer(UI_METHOD *method, int (*writer)(UI *ui, UI_STRING *uis)){	}
int UI_method_set_flusher(UI_METHOD *method, int (*flusher)(UI *ui)){	}
int UI_method_set_reader(UI_METHOD *method, int (*reader)(UI *ui, UI_STRING *uis)){	}
int UI_method_set_closer(UI_METHOD *method, int (*closer)(UI *ui)){	}
int UI_method_set_prompt_constructor(UI_METHOD *method, char *(*prompt_constructor)(UI* ui,  char* object_desc,  char* object_name)){	}
char * (*UI_method_get_prompt_constructor(UI_METHOD *method))(UI*,  char*,  char*){	}
enum UI_string_types UI_get_string_type(UI_STRING *uis){	}
int UI_get_input_flags(UI_STRING *uis){	}
char *UI_get0_output_string(UI_STRING *uis){	}
char *UI_get0_action_string(UI_STRING *uis){	}
char *UI_get0_result_string(UI_STRING *uis){	}
char *UI_get0_test_string(UI_STRING *uis){	}
int UI_get_result_minsize(UI_STRING *uis){	}
int UI_get_result_maxsize(UI_STRING *uis){	}
int UI_set_result(UI *ui, UI_STRING *uis,  char *result){	}
int UI_UTIL_read_pw_string(char *buf,int length, char *prompt,int verify){	}
int UI_UTIL_read_pw(char *buf,char *buff,int size, char *prompt,int verify){	}
void ERR_load_UI_strings(void){	}
DSA *DSAparams_dup(DSA *x){	}
DSA_SIG * DSA_SIG_new(void){	}
void	DSA_SIG_free(DSA_SIG *a){	}
int	i2d_DSA_SIG( DSA_SIG *a, unsigned char **pp){	}
DSA_SIG * d2i_DSA_SIG(DSA_SIG **v,  unsigned char **pp, long length){	}
DSA_SIG * DSA_do_sign( unsigned char *dgst,int dlen,DSA *dsa){	}
int	DSA_do_verify( unsigned char *dgst,int dgst_len, DSA_SIG *sig,DSA *dsa){	}
DSA_METHOD *DSA_OpenSSL(void){	}
void	DSA_set_default_method( DSA_METHOD *){	}
DSA_METHOD *DSA_get_default_method(void){	}
int	DSA_set_method(DSA *dsa,  DSA_METHOD *){	}
DSA *	DSA_new(void){	}
DSA *	DSA_new_method(ENGINE *engine){	}
void	DSA_free (DSA *r){	}
int	DSA_up_ref(DSA *r){	}
int	DSA_size( DSA *){	}
int	DSA_sign_setup( DSA *dsa,BN_CTX *ctx_in,BIGNUM **kinvp,BIGNUM **rp){	}
int	DSA_sign(int type, unsigned char *dgst,int dlen, unsigned char *sig, unsigned int *siglen, DSA *dsa){	}
int	DSA_verify(int type, unsigned char *dgst,int dgst_len, unsigned char *sigbuf, int siglen, DSA *dsa){	}
int DSA_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func){	}
int DSA_set_ex_data(DSA *d, int idx, void *arg){	}
void *DSA_get_ex_data(DSA *d, int idx){	}
DSA *	d2i_DSAPublicKey(DSA **a,  unsigned char **pp, long length){	}
DSA *	d2i_DSAPrivateKey(DSA **a,  unsigned char **pp, long length){	}
DSA * 	d2i_DSAparams(DSA **a,  unsigned char **pp, long length){	}
DSA *	DSA_generate_parameters(int bits, unsigned char *seed,int seed_len, int *counter_ret, unsigned long *h_ret,void (*callback)(int, int, void *),void *cb_arg){	}
int	DSA_generate_parameters_ex(DSA *dsa, int bits, unsigned char *seed,int seed_len, int *counter_ret, unsigned long *h_ret, BN_GENCB *cb){	}
int	DSA_generate_key(DSA *a){	}
int	i2d_DSAPublicKey( DSA *a, unsigned char **pp){	}
int 	i2d_DSAPrivateKey( DSA *a, unsigned char **pp){	}
int	i2d_DSAparams( DSA *a,unsigned char **pp){	}
int	DSAparams_print(BIO *bp,  DSA *x){	}
int	DSA_print(BIO *bp,  DSA *x, int off){	}
int	DSAparams_print_fp(FILE *fp,  DSA *x){	}
int	DSA_print_fp(FILE *bp,  DSA *x, int off){	}
DH *DSA_dup_DH( DSA *r){	}
void ERR_load_DSA_strings(void){	}
int BN_GENCB_call(BN_GENCB *cb, int a, int b){	}
BIGNUM *BN_value_one(void){	}
char *	BN_options(void){	}
BN_CTX *BN_CTX_new(void){	}
void	BN_CTX_init(BN_CTX *c){	}
void	BN_CTX_free(BN_CTX *c){	}
void	BN_CTX_start(BN_CTX *ctx){	}
BIGNUM *BN_CTX_get(BN_CTX *ctx){	}
void	BN_CTX_end(BN_CTX *ctx){	}
int     BN_rand(BIGNUM *rnd, int bits, int top,int bottom){	}
int     BN_pseudo_rand(BIGNUM *rnd, int bits, int top,int bottom){	}
int	BN_rand_range(BIGNUM *rnd,  BIGNUM *range){	}
int	BN_pseudo_rand_range(BIGNUM *rnd,  BIGNUM *range){	}
int	BN_num_bits( BIGNUM *a){	}
int	BN_num_bits_word(BN_ULONG){	}
BIGNUM *BN_new(void){	}
void	BN_init(BIGNUM *){	}
void	BN_clear_free(BIGNUM *a){	}
BIGNUM *BN_copy(BIGNUM *a,  BIGNUM *b){	}
void	BN_swap(BIGNUM *a, BIGNUM *b){	}
BIGNUM *BN_bin2bn( unsigned char *s,int len,BIGNUM *ret){	}
int	BN_bn2bin( BIGNUM *a, unsigned char *to){	}
BIGNUM *BN_mpi2bn( unsigned char *s,int len,BIGNUM *ret){	}
int	BN_bn2mpi( BIGNUM *a, unsigned char *to){	}
int	BN_sub(BIGNUM *r,  BIGNUM *a,  BIGNUM *b){	}
int	BN_usub(BIGNUM *r,  BIGNUM *a,  BIGNUM *b){	}
int	BN_uadd(BIGNUM *r,  BIGNUM *a,  BIGNUM *b){	}
int	BN_add(BIGNUM *r,  BIGNUM *a,  BIGNUM *b){	}
int	BN_mul(BIGNUM *r,  BIGNUM *a,  BIGNUM *b, BN_CTX *ctx){	}
int	BN_sqr(BIGNUM *r,  BIGNUM *a,BN_CTX *ctx){	}
void	BN_set_negative(BIGNUM *b, int n){	}
int	BN_div(BIGNUM *dv, BIGNUM *rem,  BIGNUM *m,  BIGNUM *d, BN_CTX *ctx){	}
int	BN_nnmod(BIGNUM *r,  BIGNUM *m,  BIGNUM *d, BN_CTX *ctx){	}
int	BN_mod_add(BIGNUM *r,  BIGNUM *a,  BIGNUM *b,  BIGNUM *m, BN_CTX *ctx){	}
int	BN_mod_add_quick(BIGNUM *r,  BIGNUM *a,  BIGNUM *b,  BIGNUM *m){	}
int	BN_mod_sub(BIGNUM *r,  BIGNUM *a,  BIGNUM *b,  BIGNUM *m, BN_CTX *ctx){	}
int	BN_mod_sub_quick(BIGNUM *r,  BIGNUM *a,  BIGNUM *b,  BIGNUM *m){	}
int	BN_mod_mul(BIGNUM *r,  BIGNUM *a,  BIGNUM *b, BIGNUM *m, BN_CTX *ctx){	}
int	BN_mod_sqr(BIGNUM *r,  BIGNUM *a,  BIGNUM *m, BN_CTX *ctx){	}
int	BN_mod_lshift1(BIGNUM *r,  BIGNUM *a,  BIGNUM *m, BN_CTX *ctx){	}
int	BN_mod_lshift1_quick(BIGNUM *r,  BIGNUM *a,  BIGNUM *m){	}
int	BN_mod_lshift(BIGNUM *r,  BIGNUM *a, int n,  BIGNUM *m, BN_CTX *ctx){	}
int	BN_mod_lshift_quick(BIGNUM *r,  BIGNUM *a, int n,  BIGNUM *m){	}
BN_ULONG BN_mod_word( BIGNUM *a, BN_ULONG w){	}
BN_ULONG BN_div_word(BIGNUM *a, BN_ULONG w){	}
int	BN_mul_word(BIGNUM *a, BN_ULONG w){	}
int	BN_add_word(BIGNUM *a, BN_ULONG w){	}
int	BN_sub_word(BIGNUM *a, BN_ULONG w){	}
int	BN_set_word(BIGNUM *a, BN_ULONG w){	}
BN_ULONG BN_get_word( BIGNUM *a){	}
int	BN_cmp( BIGNUM *a,  BIGNUM *b){	}
void	BN_free(BIGNUM *a){	}
int	BN_is_bit_set( BIGNUM *a, int n){	}
int	BN_lshift(BIGNUM *r,  BIGNUM *a, int n){	}
int	BN_lshift1(BIGNUM *r,  BIGNUM *a){	}
int	BN_exp(BIGNUM *r,  BIGNUM *a,  BIGNUM *p,BN_CTX *ctx){	}
int	BN_mod_exp(BIGNUM *r,  BIGNUM *a,  BIGNUM *p, BIGNUM *m,BN_CTX *ctx){	}
int	BN_mod_exp_mont(BIGNUM *r,  BIGNUM *a,  BIGNUM *p, BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx){	}
int BN_mod_exp_mont_consttime(BIGNUM *rr,  BIGNUM *a,  BIGNUM *p, BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *in_mont){	}
int	BN_mod_exp_mont_word(BIGNUM *r, BN_ULONG a,  BIGNUM *p, BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx){	}
int	BN_mod_exp2_mont(BIGNUM *r,  BIGNUM *a1,  BIGNUM *p1, BIGNUM *a2,  BIGNUM *p2, BIGNUM *m, BN_CTX *ctx,BN_MONT_CTX *m_ctx){	}
int	BN_mod_exp_simple(BIGNUM *r,  BIGNUM *a,  BIGNUM *p, BIGNUM *m,BN_CTX *ctx){	}
int	BN_mask_bits(BIGNUM *a,int n){	}
int	BN_print_fp(FILE *fp,  BIGNUM *a){	}
int	BN_print(BIO *fp,  BIGNUM *a){	}
int	BN_reciprocal(BIGNUM *r,  BIGNUM *m, int len, BN_CTX *ctx){	}
int	BN_rshift(BIGNUM *r,  BIGNUM *a, int n){	}
int	BN_rshift1(BIGNUM *r,  BIGNUM *a){	}
void	BN_clear(BIGNUM *a){	}
BIGNUM *BN_dup( BIGNUM *a){	}
int	BN_ucmp( BIGNUM *a,  BIGNUM *b){	}
int	BN_set_bit(BIGNUM *a, int n){	}
int	BN_clear_bit(BIGNUM *a, int n){	}
char *	BN_bn2hex( BIGNUM *a){	}
char *	BN_bn2dec( BIGNUM *a){	}
int 	BN_hex2bn(BIGNUM **a,  char *str){	}
int 	BN_dec2bn(BIGNUM **a,  char *str){	}
int	BN_asc2bn(BIGNUM **a,  char *str){	}
int	BN_gcd(BIGNUM *r, BIGNUM *a, BIGNUM *b,BN_CTX *ctx){	}
BIGNUM *BN_mod_inverse(BIGNUM *ret, BIGNUM *a,  BIGNUM *n,BN_CTX *ctx){	}
BIGNUM *BN_mod_sqrt(BIGNUM *ret, BIGNUM *a,  BIGNUM *n,BN_CTX *ctx){	}
BIGNUM *BN_generate_prime(BIGNUM *ret,int bits,int safe, BIGNUM *add,  BIGNUM *rem, void (*callback)(int,int,void *),void *cb_arg){	}
int	BN_is_prime( BIGNUM *p,int nchecks, void (*callback)(int,int,void *), BN_CTX *ctx,void *cb_arg){	}
int	BN_is_prime_fasttest( BIGNUM *p,int nchecks, void (*callback)(int,int,void *),BN_CTX *ctx,void *cb_arg, int do_trial_division){	}
int	BN_generate_prime_ex(BIGNUM *ret,int bits,int safe,  BIGNUM *add, BIGNUM *rem, BN_GENCB *cb){	}
int	BN_is_prime_ex( BIGNUM *p,int nchecks, BN_CTX *ctx, BN_GENCB *cb){	}
int	BN_is_prime_fasttest_ex( BIGNUM *p,int nchecks, BN_CTX *ctx, int do_trial_division, BN_GENCB *cb){	}
int BN_X931_generate_Xpq(BIGNUM *Xp, BIGNUM *Xq, int nbits, BN_CTX *ctx){	}
int BN_X931_derive_prime_ex(BIGNUM *p, BIGNUM *p1, BIGNUM *p2, BIGNUM *Xp,  BIGNUM *Xp1,  BIGNUM *Xp2, BIGNUM *e, BN_CTX *ctx, BN_GENCB *cb){	}
int BN_X931_generate_prime_ex(BIGNUM *p, BIGNUM *p1, BIGNUM *p2, BIGNUM *Xp1, BIGNUM *Xp2, BIGNUM *Xp, BIGNUM *e, BN_CTX *ctx, BN_GENCB *cb){	}
BN_MONT_CTX *BN_MONT_CTX_new(void ){	}
void BN_MONT_CTX_init(BN_MONT_CTX *ctx){	}
int BN_mod_mul_montgomery(BIGNUM *r, BIGNUM *a, BIGNUM *b, BN_MONT_CTX *mont, BN_CTX *ctx){	}
int BN_from_montgomery(BIGNUM *r, BIGNUM *a, BN_MONT_CTX *mont, BN_CTX *ctx){	}
void BN_MONT_CTX_free(BN_MONT_CTX *mont){	}
int BN_MONT_CTX_set(BN_MONT_CTX *mont, BIGNUM *mod,BN_CTX *ctx){	}
BN_MONT_CTX *BN_MONT_CTX_copy(BN_MONT_CTX *to,BN_MONT_CTX *from){	}
BN_MONT_CTX *BN_MONT_CTX_set_locked(BN_MONT_CTX **pmont, int lock, BIGNUM *mod, BN_CTX *ctx){	}
BN_BLINDING *BN_BLINDING_new( BIGNUM *A,  BIGNUM *Ai, BIGNUM *mod){	}
void BN_BLINDING_free(BN_BLINDING *b){	}
int BN_BLINDING_update(BN_BLINDING *b,BN_CTX *ctx){	}
int BN_BLINDING_convert(BIGNUM *n, BN_BLINDING *b, BN_CTX *ctx){	}
int BN_BLINDING_invert(BIGNUM *n, BN_BLINDING *b, BN_CTX *ctx){	}
int BN_BLINDING_convert_ex(BIGNUM *n, BIGNUM *r, BN_BLINDING *b, BN_CTX *){	}
int BN_BLINDING_invert_ex(BIGNUM *n,  BIGNUM *r, BN_BLINDING *b, BN_CTX *){	}
unsigned long BN_BLINDING_get_thread_id( BN_BLINDING *){	}
void BN_BLINDING_set_thread_id(BN_BLINDING *, unsigned long){	}
CRYPTO_THREADID *BN_BLINDING_thread_id(BN_BLINDING *){	}
unsigned long BN_BLINDING_get_flags( BN_BLINDING *){	}
void BN_BLINDING_set_flags(BN_BLINDING *, unsigned long){	}
BN_BLINDING *BN_BLINDING_create_param(BN_BLINDING *b, BIGNUM *e, BIGNUM *m, BN_CTX *ctx, int (*bn_mod_exp)(BIGNUM *r,  BIGNUM *a,  BIGNUM *p, BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx), BN_MONT_CTX *m_ctx){	}
void BN_set_params(int mul,int high,int low,int mont){	}
int BN_get_params(int which){	}
void	BN_RECP_CTX_init(BN_RECP_CTX *recp){	}
BN_RECP_CTX *BN_RECP_CTX_new(void){	}
void	BN_RECP_CTX_free(BN_RECP_CTX *recp){	}
int	BN_RECP_CTX_set(BN_RECP_CTX *recp, BIGNUM *rdiv,BN_CTX *ctx){	}
int	BN_mod_mul_reciprocal(BIGNUM *r,  BIGNUM *x,  BIGNUM *y, BN_RECP_CTX *recp,BN_CTX *ctx){	}
int	BN_mod_exp_recp(BIGNUM *r,  BIGNUM *a,  BIGNUM *p, BIGNUM *m, BN_CTX *ctx){	}
int	BN_div_recp(BIGNUM *dv, BIGNUM *rem,  BIGNUM *m, BN_RECP_CTX *recp, BN_CTX *ctx){	}
int	BN_GF2m_add(BIGNUM *r,  BIGNUM *a,  BIGNUM *b){	}
int	BN_GF2m_mod(BIGNUM *r,  BIGNUM *a,  BIGNUM *p){	}
int	BN_GF2m_mod_mul(BIGNUM *r,  BIGNUM *a,  BIGNUM *b, BIGNUM *p, BN_CTX *ctx){	}
int	BN_GF2m_mod_sqr(BIGNUM *r,  BIGNUM *a,  BIGNUM *p, BN_CTX *ctx){	}
int	BN_GF2m_mod_inv(BIGNUM *r,  BIGNUM *b,  BIGNUM *p, BN_CTX *ctx){	}
int	BN_GF2m_mod_div(BIGNUM *r,  BIGNUM *a,  BIGNUM *b, BIGNUM *p, BN_CTX *ctx){	}
int	BN_GF2m_mod_exp(BIGNUM *r,  BIGNUM *a,  BIGNUM *b, BIGNUM *p, BN_CTX *ctx){	}
int	BN_GF2m_mod_sqrt(BIGNUM *r,  BIGNUM *a,  BIGNUM *p, BN_CTX *ctx){	}
int	BN_GF2m_mod_solve_quad(BIGNUM *r,  BIGNUM *a,  BIGNUM *p, BN_CTX *ctx){	}
int	BN_GF2m_mod_arr(BIGNUM *r,  BIGNUM *a,  int p[]){	}
int	BN_GF2m_mod_mul_arr(BIGNUM *r,  BIGNUM *a,  BIGNUM *b, int p[], BN_CTX *ctx){	}
int	BN_GF2m_mod_sqr_arr(BIGNUM *r,  BIGNUM *a,  int p[], BN_CTX *ctx){	}
int	BN_GF2m_mod_inv_arr(BIGNUM *r,  BIGNUM *b,  int p[], BN_CTX *ctx){	}
int	BN_GF2m_mod_div_arr(BIGNUM *r,  BIGNUM *a,  BIGNUM *b, int p[], BN_CTX *ctx){	}
int	BN_GF2m_mod_exp_arr(BIGNUM *r,  BIGNUM *a,  BIGNUM *b, int p[], BN_CTX *ctx){	}
int	BN_GF2m_mod_sqrt_arr(BIGNUM *r,  BIGNUM *a, int p[], BN_CTX *ctx){	}
int	BN_GF2m_mod_solve_quad_arr(BIGNUM *r,  BIGNUM *a, int p[], BN_CTX *ctx){	}
int	BN_GF2m_poly2arr( BIGNUM *a, int p[], int max){	}
int	BN_GF2m_arr2poly( int p[], BIGNUM *a){	}
int BN_nist_mod_192(BIGNUM *r,  BIGNUM *a,  BIGNUM *p, BN_CTX *ctx){	}
int BN_nist_mod_224(BIGNUM *r,  BIGNUM *a,  BIGNUM *p, BN_CTX *ctx){	}
int BN_nist_mod_256(BIGNUM *r,  BIGNUM *a,  BIGNUM *p, BN_CTX *ctx){	}
int BN_nist_mod_384(BIGNUM *r,  BIGNUM *a,  BIGNUM *p, BN_CTX *ctx){	}
int BN_nist_mod_521(BIGNUM *r,  BIGNUM *a,  BIGNUM *p, BN_CTX *ctx){	}
BIGNUM *BN_get0_nist_prime_192(void){	}
BIGNUM *BN_get0_nist_prime_224(void){	}
BIGNUM *BN_get0_nist_prime_256(void){	}
BIGNUM *BN_get0_nist_prime_384(void){	}
BIGNUM *BN_get0_nist_prime_521(void){	}
BIGNUM *bn_expand2(BIGNUM *a, int words){	}
BIGNUM *bn_dup_expand( BIGNUM *a, int words){	}
int RAND_pseudo_bytes(unsigned char *buf,int num){	}
BN_ULONG bn_mul_add_words(BN_ULONG *rp,  BN_ULONG *ap, int num, BN_ULONG w){	}
BN_ULONG bn_mul_words(BN_ULONG *rp,  BN_ULONG *ap, int num, BN_ULONG w){	}
void     bn_sqr_words(BN_ULONG *rp,  BN_ULONG *ap, int num){	}
BN_ULONG bn_div_words(BN_ULONG h, BN_ULONG l, BN_ULONG d){	}
BN_ULONG bn_add_words(BN_ULONG *rp,  BN_ULONG *ap,  BN_ULONG *bp,int num){	}
BN_ULONG bn_sub_words(BN_ULONG *rp,  BN_ULONG *ap,  BN_ULONG *bp,int num){	}
BIGNUM *get_rfc2409_prime_768(BIGNUM *bn){	}
BIGNUM *get_rfc2409_prime_1024(BIGNUM *bn){	}
BIGNUM *get_rfc3526_prime_1536(BIGNUM *bn){	}
BIGNUM *get_rfc3526_prime_2048(BIGNUM *bn){	}
BIGNUM *get_rfc3526_prime_3072(BIGNUM *bn){	}
BIGNUM *get_rfc3526_prime_4096(BIGNUM *bn){	}
BIGNUM *get_rfc3526_prime_6144(BIGNUM *bn){	}
BIGNUM *get_rfc3526_prime_8192(BIGNUM *bn){	}
int BN_bntest_rand(BIGNUM *rnd, int bits, int top,int bottom){	}
void ERR_load_BN_strings(void){	}
DSO *	DSO_new(void){	}
DSO *	DSO_new_method(DSO_METHOD *method){	}
int	DSO_free(DSO *dso){	}
int	DSO_flags(DSO *dso){	}
int	DSO_up_ref(DSO *dso){	}
long	DSO_ctrl(DSO *dso, int cmd, long larg, void *parg){	}
int	DSO_set_name_converter(DSO *dso, DSO_NAME_CONVERTER_FUNC cb, DSO_NAME_CONVERTER_FUNC *oldcb){	}
char *DSO_get_filename(DSO *dso){	}
int	DSO_set_filename(DSO *dso,  char *filename){	}
char	*DSO_convert_filename(DSO *dso,  char *filename){	}
char	*DSO_merge(DSO *dso,  char *filespec1,  char *filespec2){	}
char *DSO_get_loaded_filename(DSO *dso){	}
void	DSO_set_default_method(DSO_METHOD *meth){	}
DSO_METHOD *DSO_get_default_method(void){	}
DSO_METHOD *DSO_get_method(DSO *dso){	}
DSO_METHOD *DSO_set_method(DSO *dso, DSO_METHOD *meth){	}
DSO *DSO_load(DSO *dso,  char *filename, DSO_METHOD *meth, int flags){	}
void *DSO_bind_var(DSO *dso,  char *symname){	}
DSO_FUNC_TYPE DSO_bind_func(DSO *dso,  char *symname){	}
DSO_METHOD *DSO_METHOD_openssl(void){	}
DSO_METHOD *DSO_METHOD_null(void){	}
DSO_METHOD *DSO_METHOD_dlfcn(void){	}
DSO_METHOD *DSO_METHOD_dl(void){	}
DSO_METHOD *DSO_METHOD_win32(void){	}
DSO_METHOD *DSO_METHOD_vms(void){	}
int DSO_pathbyaddr(void *addr,char *path,int sz){	}
void *DSO_global_lookup( char *name){	}
DSO_METHOD *DSO_METHOD_beos(void){	}
void ERR_load_DSO_strings(void){	}
int private_SHA_Init(SHA_CTX *c){	}
int SHA_Init(SHA_CTX *c){	}
int SHA_Update(SHA_CTX *c,  void *data, size_t len){	}
int SHA_Final(unsigned char *md, SHA_CTX *c){	}
unsigned char *SHA( unsigned char *d, size_t n, unsigned char *md){	}
void SHA_Transform(SHA_CTX *c,  unsigned char *data){	}
int private_SHA1_Init(SHA_CTX *c){	}
int SHA1_Init(SHA_CTX *c){	}
int SHA1_Update(SHA_CTX *c,  void *data, size_t len){	}
int SHA1_Final(unsigned char *md, SHA_CTX *c){	}
unsigned char *SHA1( unsigned char *d, size_t n, unsigned char *md){	}
void SHA1_Transform(SHA_CTX *c,  unsigned char *data){	}
int private_SHA224_Init(SHA256_CTX *c){	}
int private_SHA256_Init(SHA256_CTX *c){	}
int SHA224_Init(SHA256_CTX *c){	}
int SHA224_Update(SHA256_CTX *c,  void *data, size_t len){	}
int SHA224_Final(unsigned char *md, SHA256_CTX *c){	}
unsigned char *SHA224( unsigned char *d, size_t n,unsigned char *md){	}
int SHA256_Init(SHA256_CTX *c){	}
int SHA256_Update(SHA256_CTX *c,  void *data, size_t len){	}
int SHA256_Final(unsigned char *md, SHA256_CTX *c){	}
unsigned char *SHA256( unsigned char *d, size_t n,unsigned char *md){	}
void SHA256_Transform(SHA256_CTX *c,  unsigned char *data){	}
int private_SHA384_Init(SHA512_CTX *c){	}
int private_SHA512_Init(SHA512_CTX *c){	}
int SHA384_Init(SHA512_CTX *c){	}
int SHA384_Update(SHA512_CTX *c,  void *data, size_t len){	}
int SHA384_Final(unsigned char *md, SHA512_CTX *c){	}
unsigned char *SHA384( unsigned char *d, size_t n,unsigned char *md){	}
int SHA512_Init(SHA512_CTX *c){	}
int SHA512_Update(SHA512_CTX *c,  void *data, size_t len){	}
int SHA512_Final(unsigned char *md, SHA512_CTX *c){	}
unsigned char *SHA512( unsigned char *d, size_t n,unsigned char *md){	}
void SHA512_Transform(SHA512_CTX *c,  unsigned char *data){	}
int X509_STORE_set_depth(X509_STORE *store, int depth){	}
void X509_STORE_CTX_set_depth(X509_STORE_CTX *ctx, int depth){	}
int X509_OBJECT_idx_by_subject(STACK_OF(X509_OBJECT) *h, int type, X509_NAME *name){	}
X509_OBJECT *X509_OBJECT_retrieve_by_subject(STACK_OF(X509_OBJECT) *h,int type,X509_NAME *name){	}
X509_OBJECT *X509_OBJECT_retrieve_match(STACK_OF(X509_OBJECT) *h, X509_OBJECT *x){	}
void X509_OBJECT_up_ref_count(X509_OBJECT *a){	}
void X509_OBJECT_free_contents(X509_OBJECT *a){	}
X509_STORE *X509_STORE_new(void ){	}
void X509_STORE_free(X509_STORE *v){	}
int X509_STORE_set_flags(X509_STORE *ctx, unsigned long flags){	}
int X509_STORE_set_purpose(X509_STORE *ctx, int purpose){	}
int X509_STORE_set_trust(X509_STORE *ctx, int trust){	}
int X509_STORE_set1_param(X509_STORE *ctx, X509_VERIFY_PARAM *pm){	}
void X509_STORE_set_verify_cb(X509_STORE *ctx, int (*verify_cb)(int, X509_STORE_CTX *)){	}
X509_STORE_CTX *X509_STORE_CTX_new(void){	}
int X509_STORE_CTX_get1_issuer(X509 **issuer, X509_STORE_CTX *ctx, X509 *x){	}
void X509_STORE_CTX_free(X509_STORE_CTX *ctx){	}
int X509_STORE_CTX_init(X509_STORE_CTX *ctx, X509_STORE *store, X509 *x509, STACK_OF(X509) *chain){	}
void X509_STORE_CTX_trusted_stack(X509_STORE_CTX *ctx, STACK_OF(X509) *sk){	}
void X509_STORE_CTX_cleanup(X509_STORE_CTX *ctx){	}
X509_LOOKUP *X509_STORE_add_lookup(X509_STORE *v, X509_LOOKUP_METHOD *m){	}
X509_LOOKUP_METHOD *X509_LOOKUP_hash_dir(void){	}
X509_LOOKUP_METHOD *X509_LOOKUP_file(void){	}
int X509_STORE_add_cert(X509_STORE *ctx, X509 *x){	}
int X509_STORE_add_crl(X509_STORE *ctx, X509_CRL *x){	}
int X509_STORE_get_by_subject(X509_STORE_CTX *vs,int type,X509_NAME *name, X509_OBJECT *ret){	}
int X509_LOOKUP_ctrl(X509_LOOKUP *ctx, int cmd,  char *argc, long argl, char **ret){	}
int X509_load_cert_file(X509_LOOKUP *ctx,  char *file, int type){	}
int X509_load_crl_file(X509_LOOKUP *ctx,  char *file, int type){	}
int X509_load_cert_crl_file(X509_LOOKUP *ctx,  char *file, int type){	}
X509_LOOKUP *X509_LOOKUP_new(X509_LOOKUP_METHOD *method){	}
void X509_LOOKUP_free(X509_LOOKUP *ctx){	}
int X509_LOOKUP_init(X509_LOOKUP *ctx){	}
int X509_LOOKUP_by_subject(X509_LOOKUP *ctx, int type, X509_NAME *name, X509_OBJECT *ret){	}
int X509_LOOKUP_by_issuer_serial(X509_LOOKUP *ctx, int type, X509_NAME *name, ASN1_INTEGER *serial, X509_OBJECT *ret){	}
int X509_LOOKUP_by_fingerprint(X509_LOOKUP *ctx, int type, unsigned char *bytes, int len, X509_OBJECT *ret){	}
int X509_LOOKUP_by_alias(X509_LOOKUP *ctx, int type, char *str, int len, X509_OBJECT *ret){	}
int X509_LOOKUP_shutdown(X509_LOOKUP *ctx){	}
int	X509_STORE_load_locations (X509_STORE *ctx, char *file,  char *dir){	}
int	X509_STORE_set_default_paths(X509_STORE *ctx){	}
int X509_STORE_CTX_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func){	}
int	X509_STORE_CTX_set_ex_data(X509_STORE_CTX *ctx,int idx,void *data){	}
void *	X509_STORE_CTX_get_ex_data(X509_STORE_CTX *ctx,int idx){	}
int	X509_STORE_CTX_get_error(X509_STORE_CTX *ctx){	}
void	X509_STORE_CTX_set_error(X509_STORE_CTX *ctx,int s){	}
int	X509_STORE_CTX_get_error_depth(X509_STORE_CTX *ctx){	}
X509 *	X509_STORE_CTX_get_current_cert(X509_STORE_CTX *ctx){	}
X509 *X509_STORE_CTX_get0_current_issuer(X509_STORE_CTX *ctx){	}
X509_CRL *X509_STORE_CTX_get0_current_crl(X509_STORE_CTX *ctx){	}
X509_STORE_CTX *X509_STORE_CTX_get0_parent_ctx(X509_STORE_CTX *ctx){	}
void	X509_STORE_CTX_set_cert(X509_STORE_CTX *c,X509 *x){	}
void	X509_STORE_CTX_set_chain(X509_STORE_CTX *c,STACK_OF(X509) *sk){	}
void	X509_STORE_CTX_set0_crls(X509_STORE_CTX *c,STACK_OF(X509_CRL) *sk){	}
int X509_STORE_CTX_set_purpose(X509_STORE_CTX *ctx, int purpose){	}
int X509_STORE_CTX_set_trust(X509_STORE_CTX *ctx, int trust){	}
int X509_STORE_CTX_purpose_inherit(X509_STORE_CTX *ctx, int def_purpose, int purpose, int trust){	}
void X509_STORE_CTX_set_flags(X509_STORE_CTX *ctx, unsigned long flags){	}
void X509_STORE_CTX_set_time(X509_STORE_CTX *ctx, unsigned long flags, time_t t){	}
void X509_STORE_CTX_set_verify_cb(X509_STORE_CTX *ctx, int (*verify_cb)(int, X509_STORE_CTX *)){	}
X509_POLICY_TREE *X509_STORE_CTX_get0_policy_tree(X509_STORE_CTX *ctx){	}
int X509_STORE_CTX_get_explicit_policy(X509_STORE_CTX *ctx){	}
X509_VERIFY_PARAM *X509_STORE_CTX_get0_param(X509_STORE_CTX *ctx){	}
void X509_STORE_CTX_set0_param(X509_STORE_CTX *ctx, X509_VERIFY_PARAM *param){	}
int X509_STORE_CTX_set_default(X509_STORE_CTX *ctx,  char *name){	}
X509_VERIFY_PARAM *X509_VERIFY_PARAM_new(void){	}
void X509_VERIFY_PARAM_free(X509_VERIFY_PARAM *param){	}
int X509_VERIFY_PARAM_inherit(X509_VERIFY_PARAM *to, X509_VERIFY_PARAM *from){	}
int X509_VERIFY_PARAM_set1(X509_VERIFY_PARAM *to, X509_VERIFY_PARAM *from){	}
int X509_VERIFY_PARAM_set1_name(X509_VERIFY_PARAM *param,  char *name){	}
int X509_VERIFY_PARAM_set_flags(X509_VERIFY_PARAM *param, unsigned long flags){	}
int X509_VERIFY_PARAM_clear_flags(X509_VERIFY_PARAM *param, unsigned long flags){	}
unsigned long X509_VERIFY_PARAM_get_flags(X509_VERIFY_PARAM *param){	}
int X509_VERIFY_PARAM_set_purpose(X509_VERIFY_PARAM *param, int purpose){	}
int X509_VERIFY_PARAM_set_trust(X509_VERIFY_PARAM *param, int trust){	}
void X509_VERIFY_PARAM_set_depth(X509_VERIFY_PARAM *param, int depth){	}
void X509_VERIFY_PARAM_set_time(X509_VERIFY_PARAM *param, time_t t){	}
int X509_VERIFY_PARAM_add0_policy(X509_VERIFY_PARAM *param, ASN1_OBJECT *policy){	}
int X509_VERIFY_PARAM_set1_policies(X509_VERIFY_PARAM *param, STACK_OF(ASN1_OBJECT) *policies){	}
int X509_VERIFY_PARAM_get_depth( X509_VERIFY_PARAM *param){	}
int X509_VERIFY_PARAM_add0_table(X509_VERIFY_PARAM *param){	}
X509_VERIFY_PARAM *X509_VERIFY_PARAM_lookup( char *name){	}
void X509_VERIFY_PARAM_table_cleanup(void){	}
int X509_policy_check(X509_POLICY_TREE **ptree, int *pexplicit_policy, STACK_OF(X509) *certs, STACK_OF(ASN1_OBJECT) *policy_oids, unsigned int flags){	}
void X509_policy_tree_free(X509_POLICY_TREE *tree){	}
int X509_policy_tree_level_count( X509_POLICY_TREE *tree){	}
X509_POLICY_LEVEL * X509_policy_tree_get0_level( X509_POLICY_TREE *tree, int i){	}
int X509_policy_level_node_count(X509_POLICY_LEVEL *level){	}
X509_POLICY_NODE *X509_policy_level_get0_node(X509_POLICY_LEVEL *level, int i){	}
ASN1_OBJECT *X509_policy_node_get0_policy( X509_POLICY_NODE *node){	}
X509_POLICY_NODE * X509_policy_node_get0_parent( X509_POLICY_NODE *node){	}
void HMAC_CTX_init(HMAC_CTX *ctx){	}
void HMAC_CTX_cleanup(HMAC_CTX *ctx){	}
int HMAC_Init(HMAC_CTX *ctx,  void *key, int len, EVP_MD *md){	}
int HMAC_Init_ex(HMAC_CTX *ctx,  void *key, int len, EVP_MD *md, ENGINE *impl){	}
int HMAC_Update(HMAC_CTX *ctx,  unsigned char *data, size_t len){	}
int HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len){	}
unsigned char *HMAC( EVP_MD *evp_md,  void *key, int key_len, unsigned char *d, size_t n, unsigned char *md, unsigned int *md_len){	}
int HMAC_CTX_copy(HMAC_CTX *dctx, HMAC_CTX *sctx){	}
void HMAC_CTX_set_flags(HMAC_CTX *ctx, unsigned long flags){	}
int private_MD5_Init(MD5_CTX *c){	}
int MD5_Init(MD5_CTX *c){	}
int MD5_Update(MD5_CTX *c,  void *data, size_t len){	}
int MD5_Final(unsigned char *md, MD5_CTX *c){	}
unsigned char *MD5( unsigned char *d, size_t n, unsigned char *md){	}
void MD5_Transform(MD5_CTX *c,  unsigned char *b){	}
int _ossl_old_des_read_pw_string(char *buf,int length, char *prompt,int verify){	}
int _ossl_old_des_read_pw(char *buf,char *buff,int size, char *prompt,int verify){	}
char *DES_options(void){	}
void DES_ecb3_encrypt(const_DES_cblock *input, DES_cblock *output, DES_key_schedule *ks1,DES_key_schedule *ks2, DES_key_schedule *ks3, int enc){	}
DES_LONG DES_cbc_cksum( unsigned char *input,DES_cblock *output, long length,DES_key_schedule *schedule, const_DES_cblock *ivec){	}
void DES_cbc_encrypt( unsigned char *input,unsigned char *output, long length,DES_key_schedule *schedule,DES_cblock *ivec, int enc){	}
void DES_ncbc_encrypt( unsigned char *input,unsigned char *output, long length,DES_key_schedule *schedule,DES_cblock *ivec, int enc){	}
void DES_xcbc_encrypt( unsigned char *input,unsigned char *output, long length,DES_key_schedule *schedule,DES_cblock *ivec, const_DES_cblock *inw,const_DES_cblock *outw,int enc){	}
void DES_cfb_encrypt( unsigned char *in,unsigned char *out,int numbits, long length,DES_key_schedule *schedule,DES_cblock *ivec, int enc){	}
void DES_ecb_encrypt(const_DES_cblock *input,DES_cblock *output, DES_key_schedule *ks,int enc){	}
void DES_encrypt1(DES_LONG *data,DES_key_schedule *ks, int enc){	}
void DES_encrypt2(DES_LONG *data,DES_key_schedule *ks, int enc){	}
void DES_encrypt3(DES_LONG *data, DES_key_schedule *ks1, DES_key_schedule *ks2, DES_key_schedule *ks3){	}
void DES_decrypt3(DES_LONG *data, DES_key_schedule *ks1, DES_key_schedule *ks2, DES_key_schedule *ks3){	}
void DES_ede3_cbc_encrypt( unsigned char *input,unsigned char *output, long length, DES_key_schedule *ks1,DES_key_schedule *ks2, DES_key_schedule *ks3,DES_cblock *ivec,int enc){	}
void DES_ede3_cbcm_encrypt( unsigned char *in,unsigned char *out, long length, DES_key_schedule *ks1,DES_key_schedule *ks2, DES_key_schedule *ks3, DES_cblock *ivec1,DES_cblock *ivec2, int enc){	}
void DES_ede3_cfb64_encrypt( unsigned char *in,unsigned char *out, long length,DES_key_schedule *ks1, DES_key_schedule *ks2,DES_key_schedule *ks3, DES_cblock *ivec,int *num,int enc){	}
void DES_ede3_cfb_encrypt( unsigned char *in,unsigned char *out, int numbits,long length,DES_key_schedule *ks1, DES_key_schedule *ks2,DES_key_schedule *ks3, DES_cblock *ivec,int enc){	}
void DES_ede3_ofb64_encrypt( unsigned char *in,unsigned char *out, long length,DES_key_schedule *ks1, DES_key_schedule *ks2,DES_key_schedule *ks3, DES_cblock *ivec,int *num){	}
void DES_xwhite_in2out(const_DES_cblock *DES_key,const_DES_cblock *in_white, DES_cblock *out_white){	}
int DES_enc_read(int fd,void *buf,int len,DES_key_schedule *sched, DES_cblock *iv){	}
int DES_enc_write(int fd, void *buf,int len,DES_key_schedule *sched, DES_cblock *iv){	}
char *DES_fcrypt( char *buf, char *salt, char *ret){	}
char *DES_crypt( char *buf, char *salt){	}
void DES_ofb_encrypt( unsigned char *in,unsigned char *out,int numbits, long length,DES_key_schedule *schedule,DES_cblock *ivec){	}
void DES_pcbc_encrypt( unsigned char *input,unsigned char *output, long length,DES_key_schedule *schedule,DES_cblock *ivec, int enc){	}
DES_LONG DES_quad_cksum( unsigned char *input,DES_cblock output[], long length,int out_count,DES_cblock *seed){	}
int DES_random_key(DES_cblock *ret){	}
void DES_set_odd_parity(DES_cblock *key){	}
int DES_check_key_parity(const_DES_cblock *key){	}
int DES_is_weak_key(const_DES_cblock *key){	}
int DES_set_key(const_DES_cblock *key,DES_key_schedule *schedule){	}
int DES_key_sched(const_DES_cblock *key,DES_key_schedule *schedule){	}
int DES_set_key_checked(const_DES_cblock *key,DES_key_schedule *schedule){	}
void DES_set_key_unchecked(const_DES_cblock *key,DES_key_schedule *schedule){	}
void private_DES_set_key_unchecked(const_DES_cblock *key,DES_key_schedule *schedule){	}
void DES_string_to_key( char *str,DES_cblock *key){	}
void DES_string_to_2keys( char *str,DES_cblock *key1,DES_cblock *key2){	}
void DES_cfb64_encrypt( unsigned char *in,unsigned char *out,long length, DES_key_schedule *schedule,DES_cblock *ivec,int *num, int enc){	}
void DES_ofb64_encrypt( unsigned char *in,unsigned char *out,long length, DES_key_schedule *schedule,DES_cblock *ivec,int *num){	}
int DES_read_password(DES_cblock *key,  char *prompt, int verify){	}
int DES_read_2passwords(DES_cblock *key1, DES_cblock *key2,  char *prompt, int verify){	}
int CONF_set_default_method(CONF_METHOD *meth){	}
void CONF_set_nconf(CONF *conf,LHASH_OF(CONF_VALUE) *hash){	}
char *CONF_get_string(LHASH_OF(CONF_VALUE) *conf, char *group, char *name){	}
long CONF_get_number(LHASH_OF(CONF_VALUE) *conf, char *group, char *name){	}
void CONF_free(LHASH_OF(CONF_VALUE) *conf){	}
int CONF_dump_fp(LHASH_OF(CONF_VALUE) *conf, FILE *out){	}
int CONF_dump_bio(LHASH_OF(CONF_VALUE) *conf, BIO *out){	}
void OPENSSL_config( char *config_name){	}
void OPENSSL_no_config(void){	}
CONF *NCONF_new(CONF_METHOD *meth){	}
CONF_METHOD *NCONF_default(void){	}
CONF_METHOD *NCONF_WIN32(void){	}
CONF_METHOD *NCONF_XML(void){	}
void NCONF_free(CONF *conf){	}
void NCONF_free_data(CONF *conf){	}
int NCONF_load(CONF *conf, char *file,long *eline){	}
int NCONF_load_fp(CONF *conf, FILE *fp,long *eline){	}
int NCONF_load_bio(CONF *conf, BIO *bp,long *eline){	}
char *NCONF_get_string( CONF *conf, char *group, char *name){	}
int NCONF_get_number_e( CONF *conf, char *group, char *name, long *result){	}
int NCONF_dump_fp( CONF *conf, FILE *out){	}
int NCONF_dump_bio( CONF *conf, BIO *out){	}
int CONF_modules_load( CONF *cnf,  char *appname, unsigned long flags){	}
int CONF_modules_load_file( char *filename,  char *appname, unsigned long flags){	}
void CONF_modules_unload(int all){	}
void CONF_modules_finish(void){	}
void CONF_modules_free(void){	}
int CONF_module_add( char *name, conf_init_func *ifunc, conf_finish_func *ffunc){	}
char *CONF_imodule_get_name( CONF_IMODULE *md){	}
char *CONF_imodule_get_value( CONF_IMODULE *md){	}
void *CONF_imodule_get_usr_data( CONF_IMODULE *md){	}
void CONF_imodule_set_usr_data(CONF_IMODULE *md, void *usr_data){	}
CONF_MODULE *CONF_imodule_get_module( CONF_IMODULE *md){	}
unsigned long CONF_imodule_get_flags( CONF_IMODULE *md){	}
void CONF_imodule_set_flags(CONF_IMODULE *md, unsigned long flags){	}
void *CONF_module_get_usr_data(CONF_MODULE *pmod){	}
void CONF_module_set_usr_data(CONF_MODULE *pmod, void *usr_data){	}
char *CONF_get1_default_config_file(void){	}
int CONF_parse_list( char *list, int sep, int nospc, int (*list_cb)( char *elem, int len, void *usr), void *arg){	}
void OPENSSL_load_builtin_modules(void){	}
void ERR_load_CONF_strings(void){	}
int CRYPTO_mem_ctrl(int mode){	}
int CRYPTO_is_mem_check_on(void){	}
char *SSLeay_version(int type){	}
unsigned long SSLeay(void){	}
int OPENSSL_issetugid(void){	}
CRYPTO_EX_DATA_IMPL *CRYPTO_get_ex_data_implementation(void){	}
int CRYPTO_set_ex_data_implementation( CRYPTO_EX_DATA_IMPL *i){	}
int CRYPTO_ex_data_new_class(void){	}
int CRYPTO_get_ex_new_index(int class_index, long argl, void *argp, CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func){	}
int CRYPTO_new_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad){	}
int CRYPTO_dup_ex_data(int class_index, CRYPTO_EX_DATA *to, CRYPTO_EX_DATA *from){	}
void CRYPTO_free_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad){	}
int CRYPTO_set_ex_data(CRYPTO_EX_DATA *ad, int idx, void *val){	}
void *CRYPTO_get_ex_data( CRYPTO_EX_DATA *ad,int idx){	}
void CRYPTO_cleanup_all_ex_data(void){	}
int CRYPTO_get_new_lockid(char *name){	}
void CRYPTO_lock(int mode, int type, char *file,int line){	}
void CRYPTO_set_locking_callback(void (*func)(int mode,int type, char *file,int line)){	}
void CRYPTO_set_add_lock_callback(int (*func)(int *num,int mount,int type, char *file, int line)){	}
void CRYPTO_THREADID_set_numeric(CRYPTO_THREADID *id, unsigned long val){	}
void CRYPTO_THREADID_set_pointer(CRYPTO_THREADID *id, void *ptr){	}
int CRYPTO_THREADID_set_callback(void (*threadid_func)(CRYPTO_THREADID *)){	}
void CRYPTO_THREADID_current(CRYPTO_THREADID *id){	}
int CRYPTO_THREADID_cmp( CRYPTO_THREADID *a,  CRYPTO_THREADID *b){	}
void CRYPTO_THREADID_cpy(CRYPTO_THREADID *dest,  CRYPTO_THREADID *src){	}
unsigned long CRYPTO_THREADID_hash( CRYPTO_THREADID *id){	}
void CRYPTO_set_id_callback(unsigned long (*func)(void)){	}
unsigned long (*CRYPTO_get_id_callback(void))(void){	}
unsigned long CRYPTO_thread_id(void){	}
char *CRYPTO_get_lock_name(int type){	}
int CRYPTO_add_lock(int *pointer,int amount,int type,  char *file, int line){	}
int CRYPTO_get_new_dynlockid(void){	}
void CRYPTO_destroy_dynlockid(int i){	}
struct CRYPTO_dynlock_value *CRYPTO_get_dynlock_value(int i){	}
void CRYPTO_set_dynlock_create_callback(struct CRYPTO_dynlock_value *(*dyn_create_function)( char *file, int line)){	}
void CRYPTO_set_dynlock_lock_callback(void (*dyn_lock_function)(int mode, struct CRYPTO_dynlock_value *l,  char *file, int line)){	}
void CRYPTO_set_dynlock_destroy_callback(void (*dyn_destroy_function)(struct CRYPTO_dynlock_value *l,  char *file, int line)){	}
struct CRYPTO_dynlock_value *(*CRYPTO_get_dynlock_create_callback(void))( char *file,int line){	}
int CRYPTO_set_mem_functions(void *(*m)(size_t),void *(*r)(void *,size_t), void (*f)(void *)){	}
int CRYPTO_set_locked_mem_functions(void *(*m)(size_t), void (*free_func)(void *)){	}
int CRYPTO_set_mem_ex_functions(void *(*m)(size_t, char *,int), void *(*r)(void *,size_t, char *,int), void (*f)(void *)){	}
int CRYPTO_set_locked_mem_ex_functions(void *(*m)(size_t, char *,int), void (*free_func)(void *)){	}
int CRYPTO_set_mem_debug_functions(void (*m)(void *,int, char *,int,int), void (*r)(void *,void *,int, char *,int,int), void (*f)(void *,int), void (*so)(long), long (*go)(void)){	}
void CRYPTO_get_mem_functions(void *(**m)(size_t),void *(**r)(void *, size_t), void (**f)(void *)){	}
void CRYPTO_get_locked_mem_functions(void *(**m)(size_t), void (**f)(void *)){	}
void CRYPTO_get_mem_ex_functions(void *(**m)(size_t, char *,int), void *(**r)(void *, size_t, char *,int), void (**f)(void *)){	}
void CRYPTO_get_locked_mem_ex_functions(void *(**m)(size_t, char *,int), void (**f)(void *)){	}
void CRYPTO_get_mem_debug_functions(void (**m)(void *,int, char *,int,int), void (**r)(void *,void *,int, char *,int,int), void (**f)(void *,int), void (**so)(long), long (**go)(void)){	}
void *CRYPTO_malloc_locked(int num,  char *file, int line){	}
void CRYPTO_free_locked(void *ptr){	}
void *CRYPTO_malloc(int num,  char *file, int line){	}
char *CRYPTO_strdup( char *str,  char *file, int line){	}
void CRYPTO_free(void *ptr){	}
void *CRYPTO_realloc(void *addr,int num,  char *file, int line){	}
void *CRYPTO_realloc_clean(void *addr,int old_num,int num, char *file, int line){	}
void *CRYPTO_remalloc(void *addr,int num,  char *file, int line){	}
void OPENSSL_cleanse(void *ptr, size_t len){	}
void CRYPTO_set_mem_debug_options(long bits){	}
long CRYPTO_get_mem_debug_options(void){	}
int CRYPTO_push_info_( char *info,  char *file, int line){	}
int CRYPTO_pop_info(void){	}
int CRYPTO_remove_all_info(void){	}
void CRYPTO_dbg_malloc(void *addr,int num, char *file,int line,int before_p){	}
void CRYPTO_dbg_realloc(void *addr1,void *addr2,int num, char *file,int line,int before_p){	}
void CRYPTO_dbg_free(void *addr,int before_p){	}
void CRYPTO_dbg_set_options(long bits){	}
long CRYPTO_dbg_get_options(void){	}
void CRYPTO_mem_leaks_fp(FILE *){	}
void CRYPTO_mem_leaks(struct bio_st *bio){	}
void CRYPTO_mem_leaks_cb(CRYPTO_MEM_LEAK_CB *cb){	}
void OpenSSLDie( char *file,int line, char *assertion){	}
unsigned long *OPENSSL_ia32cap_loc(void){	}
int OPENSSL_isservice(void){	}
int FIPS_mode(void){	}
int FIPS_mode_set(int r){	}
void OPENSSL_init(void){	}
int CRYPTO_memcmp( void *a,  void *b, size_t len){	}
void ERR_load_CRYPTO_strings(void){	}
DH *DHparams_dup(DH *){	}
DH_METHOD *DH_OpenSSL(void){	}
void DH_set_default_method( DH_METHOD *meth){	}
DH_METHOD *DH_get_default_method(void){	}
int DH_set_method(DH *dh,  DH_METHOD *meth){	}
DH *DH_new_method(ENGINE *engine){	}
DH *	DH_new(void){	}
void	DH_free(DH *dh){	}
int	DH_up_ref(DH *dh){	}
int	DH_size( DH *dh){	}
int DH_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func){	}
int DH_set_ex_data(DH *d, int idx, void *arg){	}
void *DH_get_ex_data(DH *d, int idx){	}
DH *	DH_generate_parameters(int prime_len,int generator, void (*callback)(int,int,void *),void *cb_arg){	}
int	DH_generate_parameters_ex(DH *dh, int prime_len,int generator, BN_GENCB *cb){	}
int	DH_check( DH *dh,int *codes){	}
int	DH_check_pub_key( DH *dh, BIGNUM *pub_key, int *codes){	}
int	DH_generate_key(DH *dh){	}
int	DH_compute_key(unsigned char *key, BIGNUM *pub_key,DH *dh){	}
DH *	d2i_DHparams(DH **a, unsigned char **pp, long length){	}
int	i2d_DHparams( DH *a,unsigned char **pp){	}
int	DHparams_print_fp(FILE *fp,  DH *x){	}
int	DHparams_print(BIO *bp,  DH *x){	}
void ERR_load_DH_strings(void){	}
char *AES_options(void){	}
int AES_set_encrypt_key( unsigned char *userKey,  int bits, AES_KEY *key){	}
int AES_set_decrypt_key( unsigned char *userKey,  int bits, AES_KEY *key){	}
int private_AES_set_encrypt_key( unsigned char *userKey,  int bits, AES_KEY *key){	}
int private_AES_set_decrypt_key( unsigned char *userKey,  int bits, AES_KEY *key){	}
void AES_encrypt( unsigned char *in, unsigned char *out, AES_KEY *key){	}
void AES_decrypt( unsigned char *in, unsigned char *out, AES_KEY *key){	}
void AES_ecb_encrypt( unsigned char *in, unsigned char *out, AES_KEY *key,  int enc){	}
void AES_cbc_encrypt( unsigned char *in, unsigned char *out, size_t length,  AES_KEY *key, unsigned char *ivec,  int enc){	}
void AES_cfb128_encrypt( unsigned char *in, unsigned char *out, size_t length,  AES_KEY *key, unsigned char *ivec, int *num,  int enc){	}
void AES_cfb1_encrypt( unsigned char *in, unsigned char *out, size_t length,  AES_KEY *key, unsigned char *ivec, int *num,  int enc){	}
void AES_cfb8_encrypt( unsigned char *in, unsigned char *out, size_t length,  AES_KEY *key, unsigned char *ivec, int *num,  int enc){	}
void AES_ofb128_encrypt( unsigned char *in, unsigned char *out, size_t length,  AES_KEY *key, unsigned char *ivec, int *num){	}
void AES_ctr128_encrypt( unsigned char *in, unsigned char *out, size_t length,  AES_KEY *key, unsigned char ivec[AES_BLOCK_SIZE], unsigned char ecount_buf[AES_BLOCK_SIZE], unsigned int *num){	}
void AES_ige_encrypt( unsigned char *in, unsigned char *out, size_t length,  AES_KEY *key, unsigned char *ivec,  int enc){	}
void AES_bi_ige_encrypt( unsigned char *in, unsigned char *out, size_t length,  AES_KEY *key, AES_KEY *key2,  unsigned char *ivec, int enc){	}
int AES_wrap_key(AES_KEY *key,  unsigned char *iv, unsigned char *out, unsigned char *in, unsigned int inlen){	}
int AES_unwrap_key(AES_KEY *key,  unsigned char *iv, unsigned char *out, unsigned char *in, unsigned int inlen){	}
int EVP_MD_type( EVP_MD *md){	}
int EVP_MD_pkey_type( EVP_MD *md){	}
int EVP_MD_size( EVP_MD *md){	}
int EVP_MD_block_size( EVP_MD *md){	}
unsigned long EVP_MD_flags( EVP_MD *md){	}
EVP_MD *EVP_MD_CTX_md( EVP_MD_CTX *ctx){	}
int EVP_CIPHER_nid( EVP_CIPHER *cipher){	}
int EVP_CIPHER_block_size( EVP_CIPHER *cipher){	}
int EVP_CIPHER_key_length( EVP_CIPHER *cipher){	}
int EVP_CIPHER_iv_length( EVP_CIPHER *cipher){	}
unsigned long EVP_CIPHER_flags( EVP_CIPHER *cipher){	}
EVP_CIPHER * EVP_CIPHER_CTX_cipher( EVP_CIPHER_CTX *ctx){	}
int EVP_CIPHER_CTX_nid( EVP_CIPHER_CTX *ctx){	}
int EVP_CIPHER_CTX_block_size( EVP_CIPHER_CTX *ctx){	}
int EVP_CIPHER_CTX_key_length( EVP_CIPHER_CTX *ctx){	}
int EVP_CIPHER_CTX_iv_length( EVP_CIPHER_CTX *ctx){	}
int EVP_CIPHER_CTX_copy(EVP_CIPHER_CTX *out,  EVP_CIPHER_CTX *in){	}
void * EVP_CIPHER_CTX_get_app_data( EVP_CIPHER_CTX *ctx){	}
void EVP_CIPHER_CTX_set_app_data(EVP_CIPHER_CTX *ctx, void *data){	}
unsigned long EVP_CIPHER_CTX_flags( EVP_CIPHER_CTX *ctx){	}
void BIO_set_md(BIO *, EVP_MD *md){	}
int EVP_Cipher(EVP_CIPHER_CTX *c, unsigned char *out, unsigned char *in, unsigned int inl){	}
void	EVP_MD_CTX_init(EVP_MD_CTX *ctx){	}
int	EVP_MD_CTX_cleanup(EVP_MD_CTX *ctx){	}
EVP_MD_CTX *EVP_MD_CTX_create(void){	}
void	EVP_MD_CTX_destroy(EVP_MD_CTX *ctx){	}
int     EVP_MD_CTX_copy_ex(EVP_MD_CTX *out, EVP_MD_CTX *in){	}
void	EVP_MD_CTX_set_flags(EVP_MD_CTX *ctx, int flags){	}
void	EVP_MD_CTX_clear_flags(EVP_MD_CTX *ctx, int flags){	}
int 	EVP_MD_CTX_test_flags( EVP_MD_CTX *ctx,int flags){	}
int	EVP_DigestInit_ex(EVP_MD_CTX *ctx,  EVP_MD *type, ENGINE *impl){	}
int	EVP_DigestUpdate(EVP_MD_CTX *ctx, void *d, size_t cnt){	}
int	EVP_DigestFinal_ex(EVP_MD_CTX *ctx,unsigned char *md,unsigned int *s){	}
int	EVP_Digest( void *data, size_t count, unsigned char *md, unsigned int *size,  EVP_MD *type, ENGINE *impl){	}
int     EVP_MD_CTX_copy(EVP_MD_CTX *out, EVP_MD_CTX *in){	}
int	EVP_DigestInit(EVP_MD_CTX *ctx,  EVP_MD *type){	}
int	EVP_DigestFinal(EVP_MD_CTX *ctx,unsigned char *md,unsigned int *s){	}
int	EVP_read_pw_string(char *buf,int length, char *prompt,int verify){	}
int	EVP_read_pw_string_min(char *buf,int minlen,int maxlen, char *prompt,int verify){	}
void	EVP_set_pw_prompt( char *prompt){	}
char *	EVP_get_pw_prompt(void){	}
int	EVP_BytesToKey( EVP_CIPHER *type, EVP_MD *md, unsigned char *salt,  unsigned char *data, int datal, int count, unsigned char *key,unsigned char *iv){	}
void	EVP_CIPHER_CTX_set_flags(EVP_CIPHER_CTX *ctx, int flags){	}
void	EVP_CIPHER_CTX_clear_flags(EVP_CIPHER_CTX *ctx, int flags){	}
int 	EVP_CIPHER_CTX_test_flags( EVP_CIPHER_CTX *ctx,int flags){	}
int	EVP_EncryptInit(EVP_CIPHER_CTX *ctx, EVP_CIPHER *cipher, unsigned char *key,  unsigned char *iv){	}
int	EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, EVP_CIPHER *cipher, ENGINE *impl, unsigned char *key,  unsigned char *iv){	}
int	EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,  unsigned char *in, int inl){	}
int	EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl){	}
int	EVP_EncryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl){	}
int	EVP_DecryptInit(EVP_CIPHER_CTX *ctx, EVP_CIPHER *cipher, unsigned char *key,  unsigned char *iv){	}
int	EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, EVP_CIPHER *cipher, ENGINE *impl, unsigned char *key,  unsigned char *iv){	}
int	EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,  unsigned char *in, int inl){	}
int	EVP_DecryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl){	}
int	EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl){	}
int	EVP_CipherInit(EVP_CIPHER_CTX *ctx, EVP_CIPHER *cipher, unsigned char *key, unsigned char *iv, int enc){	}
int	EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, EVP_CIPHER *cipher, ENGINE *impl, unsigned char *key, unsigned char *iv, int enc){	}
int	EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,  unsigned char *in, int inl){	}
int	EVP_CipherFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl){	}
int	EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl){	}
int	EVP_SignFinal(EVP_MD_CTX *ctx,unsigned char *md,unsigned int *s, EVP_PKEY *pkey){	}
int	EVP_VerifyFinal(EVP_MD_CTX *ctx, unsigned char *sigbuf, unsigned int siglen,EVP_PKEY *pkey){	}
int	EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, EVP_MD *type, ENGINE *e, EVP_PKEY *pkey){	}
int	EVP_DigestSignFinal(EVP_MD_CTX *ctx, unsigned char *sigret, size_t *siglen){	}
int	EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, EVP_MD *type, ENGINE *e, EVP_PKEY *pkey){	}
int	EVP_DigestVerifyFinal(EVP_MD_CTX *ctx, unsigned char *sig, size_t siglen){	}
int	EVP_OpenInit(EVP_CIPHER_CTX *ctx, EVP_CIPHER *type, unsigned char *ek, int ekl,  unsigned char *iv, EVP_PKEY *priv){	}
int	EVP_OpenFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl){	}
int	EVP_SealInit(EVP_CIPHER_CTX *ctx,  EVP_CIPHER *type, unsigned char **ek, int *ekl, unsigned char *iv, EVP_PKEY **pubk, int npubk){	}
int	EVP_SealFinal(EVP_CIPHER_CTX *ctx,unsigned char *out,int *outl){	}
void	EVP_EncodeInit(EVP_ENCODE_CTX *ctx){	}
void	EVP_EncodeUpdate(EVP_ENCODE_CTX *ctx,unsigned char *out,int *outl, unsigned char *in,int inl){	}
void	EVP_EncodeFinal(EVP_ENCODE_CTX *ctx,unsigned char *out,int *outl){	}
int	EVP_EncodeBlock(unsigned char *t,  unsigned char *f, int n){	}
void	EVP_DecodeInit(EVP_ENCODE_CTX *ctx){	}
int	EVP_DecodeUpdate(EVP_ENCODE_CTX *ctx,unsigned char *out,int *outl, unsigned char *in, int inl){	}
int	EVP_DecodeFinal(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl){	}
int	EVP_DecodeBlock(unsigned char *t,  unsigned char *f, int n){	}
void EVP_CIPHER_CTX_init(EVP_CIPHER_CTX *a){	}
int EVP_CIPHER_CTX_cleanup(EVP_CIPHER_CTX *a){	}
EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void){	}
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *a){	}
int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *x, int keylen){	}
int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *c, int pad){	}
int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr){	}
int EVP_CIPHER_CTX_rand_key(EVP_CIPHER_CTX *ctx, unsigned char *key){	}
BIO_METHOD *BIO_f_md(void){	}
BIO_METHOD *BIO_f_base64(void){	}
BIO_METHOD *BIO_f_cipher(void){	}
BIO_METHOD *BIO_f_reliable(void){	}
void BIO_set_cipher(BIO *b, EVP_CIPHER *c, unsigned char *k, unsigned char *i, int enc){	}
EVP_MD *EVP_md_null(void){	}
EVP_MD *EVP_md2(void){	}
EVP_MD *EVP_md4(void){	}
EVP_MD *EVP_md5(void){	}
EVP_MD *EVP_sha(void){	}
EVP_MD *EVP_sha1(void){	}
EVP_MD *EVP_dss(void){	}
EVP_MD *EVP_dss1(void){	}
EVP_MD *EVP_ecdsa(void){	}
EVP_MD *EVP_sha224(void){	}
EVP_MD *EVP_sha256(void){	}
EVP_MD *EVP_sha384(void){	}
EVP_MD *EVP_sha512(void){	}
EVP_MD *EVP_mdc2(void){	}
EVP_MD *EVP_ripemd160(void){	}
EVP_MD *EVP_whirlpool(void){	}
EVP_CIPHER *EVP_enc_null(void){	}
EVP_CIPHER *EVP_des_ecb(void){	}
EVP_CIPHER *EVP_des_ede(void){	}
EVP_CIPHER *EVP_des_ede3(void){	}
EVP_CIPHER *EVP_des_ede_ecb(void){	}
EVP_CIPHER *EVP_des_ede3_ecb(void){	}
EVP_CIPHER *EVP_des_cfb64(void){	}
EVP_CIPHER *EVP_des_cfb1(void){	}
EVP_CIPHER *EVP_des_cfb8(void){	}
EVP_CIPHER *EVP_des_ede_cfb64(void){	}
EVP_CIPHER *EVP_des_ede_cfb1(void){	}
EVP_CIPHER *EVP_des_ede_cfb8(void){	}
EVP_CIPHER *EVP_des_ede3_cfb64(void){	}
EVP_CIPHER *EVP_des_ede3_cfb1(void){	}
EVP_CIPHER *EVP_des_ede3_cfb8(void){	}
EVP_CIPHER *EVP_des_ofb(void){	}
EVP_CIPHER *EVP_des_ede_ofb(void){	}
EVP_CIPHER *EVP_des_ede3_ofb(void){	}
EVP_CIPHER *EVP_des_cbc(void){	}
EVP_CIPHER *EVP_des_ede_cbc(void){	}
EVP_CIPHER *EVP_des_ede3_cbc(void){	}
EVP_CIPHER *EVP_desx_cbc(void){	}
EVP_CIPHER *EVP_dev_crypto_des_ede3_cbc(void){	}
EVP_CIPHER *EVP_dev_crypto_rc4(void){	}
EVP_MD *EVP_dev_crypto_md5(void){	}
EVP_CIPHER *EVP_rc4(void){	}
EVP_CIPHER *EVP_rc4_40(void){	}
EVP_CIPHER *EVP_rc4_hmac_md5(void){	}
EVP_CIPHER *EVP_idea_ecb(void){	}
EVP_CIPHER *EVP_idea_cfb64(void){	}
EVP_CIPHER *EVP_idea_ofb(void){	}
EVP_CIPHER *EVP_idea_cbc(void){	}
EVP_CIPHER *EVP_rc2_ecb(void){	}
EVP_CIPHER *EVP_rc2_cbc(void){	}
EVP_CIPHER *EVP_rc2_40_cbc(void){	}
EVP_CIPHER *EVP_rc2_64_cbc(void){	}
EVP_CIPHER *EVP_rc2_cfb64(void){	}
EVP_CIPHER *EVP_rc2_ofb(void){	}
EVP_CIPHER *EVP_bf_ecb(void){	}
EVP_CIPHER *EVP_bf_cbc(void){	}
EVP_CIPHER *EVP_bf_cfb64(void){	}
EVP_CIPHER *EVP_bf_ofb(void){	}
EVP_CIPHER *EVP_cast5_ecb(void){	}
EVP_CIPHER *EVP_cast5_cbc(void){	}
EVP_CIPHER *EVP_cast5_cfb64(void){	}
EVP_CIPHER *EVP_cast5_ofb(void){	}
EVP_CIPHER *EVP_rc5_32_12_16_cbc(void){	}
EVP_CIPHER *EVP_rc5_32_12_16_ecb(void){	}
EVP_CIPHER *EVP_rc5_32_12_16_cfb64(void){	}
EVP_CIPHER *EVP_rc5_32_12_16_ofb(void){	}
EVP_CIPHER *EVP_aes_128_ecb(void){	}
EVP_CIPHER *EVP_aes_128_cbc(void){	}
EVP_CIPHER *EVP_aes_128_cfb1(void){	}
EVP_CIPHER *EVP_aes_128_cfb8(void){	}
EVP_CIPHER *EVP_aes_128_cfb128(void){	}
EVP_CIPHER *EVP_aes_128_ofb(void){	}
EVP_CIPHER *EVP_aes_128_ctr(void){	}
EVP_CIPHER *EVP_aes_128_ccm(void){	}
EVP_CIPHER *EVP_aes_128_gcm(void){	}
EVP_CIPHER *EVP_aes_128_xts(void){	}
EVP_CIPHER *EVP_aes_192_ecb(void){	}
EVP_CIPHER *EVP_aes_192_cbc(void){	}
EVP_CIPHER *EVP_aes_192_cfb1(void){	}
EVP_CIPHER *EVP_aes_192_cfb8(void){	}
EVP_CIPHER *EVP_aes_192_cfb128(void){	}
EVP_CIPHER *EVP_aes_192_ofb(void){	}
EVP_CIPHER *EVP_aes_192_ctr(void){	}
EVP_CIPHER *EVP_aes_192_ccm(void){	}
EVP_CIPHER *EVP_aes_192_gcm(void){	}
EVP_CIPHER *EVP_aes_256_ecb(void){	}
EVP_CIPHER *EVP_aes_256_cbc(void){	}
EVP_CIPHER *EVP_aes_256_cfb1(void){	}
EVP_CIPHER *EVP_aes_256_cfb8(void){	}
EVP_CIPHER *EVP_aes_256_cfb128(void){	}
EVP_CIPHER *EVP_aes_256_ofb(void){	}
EVP_CIPHER *EVP_aes_256_ctr(void){	}
EVP_CIPHER *EVP_aes_256_ccm(void){	}
EVP_CIPHER *EVP_aes_256_gcm(void){	}
EVP_CIPHER *EVP_aes_256_xts(void){	}
EVP_CIPHER *EVP_aes_128_cbc_hmac_sha1(void){	}
EVP_CIPHER *EVP_aes_256_cbc_hmac_sha1(void){	}
EVP_CIPHER *EVP_camellia_128_ecb(void){	}
EVP_CIPHER *EVP_camellia_128_cbc(void){	}
EVP_CIPHER *EVP_camellia_128_cfb1(void){	}
EVP_CIPHER *EVP_camellia_128_cfb8(void){	}
EVP_CIPHER *EVP_camellia_128_cfb128(void){	}
EVP_CIPHER *EVP_camellia_128_ofb(void){	}
EVP_CIPHER *EVP_camellia_192_ecb(void){	}
EVP_CIPHER *EVP_camellia_192_cbc(void){	}
EVP_CIPHER *EVP_camellia_192_cfb1(void){	}
EVP_CIPHER *EVP_camellia_192_cfb8(void){	}
EVP_CIPHER *EVP_camellia_192_cfb128(void){	}
EVP_CIPHER *EVP_camellia_192_ofb(void){	}
EVP_CIPHER *EVP_camellia_256_ecb(void){	}
EVP_CIPHER *EVP_camellia_256_cbc(void){	}
EVP_CIPHER *EVP_camellia_256_cfb1(void){	}
EVP_CIPHER *EVP_camellia_256_cfb8(void){	}
EVP_CIPHER *EVP_camellia_256_cfb128(void){	}
EVP_CIPHER *EVP_camellia_256_ofb(void){	}
EVP_CIPHER *EVP_seed_ecb(void){	}
EVP_CIPHER *EVP_seed_cbc(void){	}
EVP_CIPHER *EVP_seed_cfb128(void){	}
EVP_CIPHER *EVP_seed_ofb(void){	}
void OPENSSL_add_all_algorithms_noconf(void){	}
void OPENSSL_add_all_algorithms_conf(void){	}
void OpenSSL_add_all_ciphers(void){	}
void OpenSSL_add_all_digests(void){	}
int EVP_add_cipher( EVP_CIPHER *cipher){	}
int EVP_add_digest( EVP_MD *digest){	}
EVP_CIPHER *EVP_get_cipherbyname( char *name){	}
EVP_MD *EVP_get_digestbyname( char *name){	}
void EVP_cleanup(void){	}
void EVP_CIPHER_do_all(void (*fn)( EVP_CIPHER *ciph, char *from,  char *to, void *x), void *arg){	}
void EVP_CIPHER_do_all_sorted(void (*fn)( EVP_CIPHER *ciph, char *from,  char *to, void *x), void *arg){	}
void EVP_MD_do_all(void (*fn)( EVP_MD *ciph, char *from,  char *to, void *x), void *arg){	}
void EVP_MD_do_all_sorted(void (*fn)( EVP_MD *ciph, char *from,  char *to, void *x), void *arg){	}
int		EVP_PKEY_decrypt_old(unsigned char *dec_key, unsigned char *enc_key,int enc_key_len, EVP_PKEY *private_key){	}
int		EVP_PKEY_encrypt_old(unsigned char *enc_key, unsigned char *key,int key_len, EVP_PKEY *pub_key){	}
int		EVP_PKEY_type(int type){	}
int		EVP_PKEY_id( EVP_PKEY *pkey){	}
int		EVP_PKEY_base_id( EVP_PKEY *pkey){	}
int		EVP_PKEY_bits(EVP_PKEY *pkey){	}
int		EVP_PKEY_size(EVP_PKEY *pkey){	}
int 		EVP_PKEY_set_type(EVP_PKEY *pkey,int type){	}
int		EVP_PKEY_set_type_str(EVP_PKEY *pkey,  char *str, int len){	}
int 		EVP_PKEY_assign(EVP_PKEY *pkey,int type,void *key){	}
void *		EVP_PKEY_get0(EVP_PKEY *pkey){	}
int EVP_PKEY_set1_RSA(EVP_PKEY *pkey,struct rsa_st *key){	}
struct rsa_st *EVP_PKEY_get1_RSA(EVP_PKEY *pkey){	}
int EVP_PKEY_set1_DSA(EVP_PKEY *pkey,struct dsa_st *key){	}
struct dsa_st *EVP_PKEY_get1_DSA(EVP_PKEY *pkey){	}
int EVP_PKEY_set1_DH(EVP_PKEY *pkey,struct dh_st *key){	}
struct dh_st *EVP_PKEY_get1_DH(EVP_PKEY *pkey){	}
int EVP_PKEY_set1_EC_KEY(EVP_PKEY *pkey,struct ec_key_st *key){	}
struct ec_key_st *EVP_PKEY_get1_EC_KEY(EVP_PKEY *pkey){	}
EVP_PKEY *	EVP_PKEY_new(void){	}
void		EVP_PKEY_free(EVP_PKEY *pkey){	}
EVP_PKEY *	d2i_PublicKey(int type,EVP_PKEY **a,  unsigned char **pp, long length){	}
int		i2d_PublicKey(EVP_PKEY *a, unsigned char **pp){	}
EVP_PKEY *	d2i_PrivateKey(int type,EVP_PKEY **a,  unsigned char **pp, long length){	}
EVP_PKEY *	d2i_AutoPrivateKey(EVP_PKEY **a,  unsigned char **pp, long length){	}
int		i2d_PrivateKey(EVP_PKEY *a, unsigned char **pp){	}
int EVP_PKEY_copy_parameters(EVP_PKEY *to,  EVP_PKEY *from){	}
int EVP_PKEY_missing_parameters( EVP_PKEY *pkey){	}
int EVP_PKEY_save_parameters(EVP_PKEY *pkey,int mode){	}
int EVP_PKEY_cmp_parameters( EVP_PKEY *a,  EVP_PKEY *b){	}
int EVP_PKEY_cmp( EVP_PKEY *a,  EVP_PKEY *b){	}
int EVP_PKEY_print_public(BIO *out,  EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx){	}
int EVP_PKEY_print_private(BIO *out,  EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx){	}
int EVP_PKEY_print_params(BIO *out,  EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx){	}
int EVP_PKEY_get_default_digest_nid(EVP_PKEY *pkey, int *pnid){	}
int EVP_CIPHER_type( EVP_CIPHER *ctx){	}
int EVP_CIPHER_param_to_asn1(EVP_CIPHER_CTX *c, ASN1_TYPE *type){	}
int EVP_CIPHER_asn1_to_param(EVP_CIPHER_CTX *c, ASN1_TYPE *type){	}
int EVP_CIPHER_set_asn1_iv(EVP_CIPHER_CTX *c,ASN1_TYPE *type){	}
int EVP_CIPHER_get_asn1_iv(EVP_CIPHER_CTX *c,ASN1_TYPE *type){	}
int PKCS5_PBE_keyivgen(EVP_CIPHER_CTX *ctx,  char *pass, int passlen, ASN1_TYPE *param,  EVP_CIPHER *cipher,  EVP_MD *md, int en_de){	}
int PKCS5_PBKDF2_HMAC_SHA1( char *pass, int passlen, unsigned char *salt, int saltlen, int iter, int keylen, unsigned char *out){	}
int PKCS5_PBKDF2_HMAC( char *pass, int passlen, unsigned char *salt, int saltlen, int iter, EVP_MD *digest, int keylen, unsigned char *out){	}
int PKCS5_v2_PBE_keyivgen(EVP_CIPHER_CTX *ctx,  char *pass, int passlen, ASN1_TYPE *param,  EVP_CIPHER *cipher,  EVP_MD *md, int en_de){	}
void PKCS5_PBE_add(void){	}
int EVP_PBE_CipherInit (ASN1_OBJECT *pbe_obj,  char *pass, int passlen, ASN1_TYPE *param, EVP_CIPHER_CTX *ctx, int en_de){	}
int EVP_PBE_alg_add_type(int pbe_type, int pbe_nid, int cipher_nid, int md_nid, EVP_PBE_KEYGEN *keygen){	}
int EVP_PBE_alg_add(int nid,  EVP_CIPHER *cipher,  EVP_MD *md, EVP_PBE_KEYGEN *keygen){	}
int EVP_PBE_find(int type, int pbe_nid, int *pcnid, int *pmnid, EVP_PBE_KEYGEN **pkeygen){	}
void EVP_PBE_cleanup(void){	}
int EVP_PKEY_asn1_get_count(void){	}
EVP_PKEY_ASN1_METHOD *EVP_PKEY_asn1_get0(int idx){	}
EVP_PKEY_ASN1_METHOD *EVP_PKEY_asn1_find(ENGINE **pe, int type){	}
EVP_PKEY_ASN1_METHOD *EVP_PKEY_asn1_find_str(ENGINE **pe, char *str, int len){	}
int EVP_PKEY_asn1_add0( EVP_PKEY_ASN1_METHOD *ameth){	}
int EVP_PKEY_asn1_add_alias(int to, int from){	}
int EVP_PKEY_asn1_get0_info(int *ppkey_id, int *pkey_base_id, int *ppkey_flags, char **pinfo,  char **ppem_str, EVP_PKEY_ASN1_METHOD *ameth){	}
EVP_PKEY_ASN1_METHOD* EVP_PKEY_get0_asn1(EVP_PKEY *pkey){	}
EVP_PKEY_ASN1_METHOD* EVP_PKEY_asn1_new(int id, int flags, char *pem_str,  char *info){	}
void EVP_PKEY_asn1_copy(EVP_PKEY_ASN1_METHOD *dst, EVP_PKEY_ASN1_METHOD *src){	}
void EVP_PKEY_asn1_free(EVP_PKEY_ASN1_METHOD *ameth){	}
void EVP_PKEY_asn1_set_public(EVP_PKEY_ASN1_METHOD *ameth, int (*pub_decode)(EVP_PKEY *pk, X509_PUBKEY *pub), int (*pub_encode)(X509_PUBKEY *pub,  EVP_PKEY *pk), int (*pub_cmp)( EVP_PKEY *a,  EVP_PKEY *b), int (*pub_print)(BIO *out,  EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx), int (*pkey_size)( EVP_PKEY *pk), int (*pkey_bits)( EVP_PKEY *pk)){	}
void EVP_PKEY_asn1_set_private(EVP_PKEY_ASN1_METHOD *ameth, int (*priv_decode)(EVP_PKEY *pk, PKCS8_PRIV_KEY_INFO *p8inf), int (*priv_encode)(PKCS8_PRIV_KEY_INFO *p8,  EVP_PKEY *pk), int (*priv_print)(BIO *out,  EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx)){	}
void EVP_PKEY_asn1_set_param(EVP_PKEY_ASN1_METHOD *ameth, int (*param_decode)(EVP_PKEY *pkey, unsigned char **pder, int derlen), int (*param_encode)( EVP_PKEY *pkey, unsigned char **pder), int (*param_missing)( EVP_PKEY *pk), int (*param_copy)(EVP_PKEY *to,  EVP_PKEY *from), int (*param_cmp)( EVP_PKEY *a,  EVP_PKEY *b), int (*param_print)(BIO *out,  EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx)){	}
void EVP_PKEY_asn1_set_free(EVP_PKEY_ASN1_METHOD *ameth, void (*pkey_free)(EVP_PKEY *pkey)){	}
void EVP_PKEY_asn1_set_ctrl(EVP_PKEY_ASN1_METHOD *ameth, int (*pkey_ctrl)(EVP_PKEY *pkey, int op, long arg1, void *arg2)){	}
EVP_PKEY_METHOD *EVP_PKEY_meth_find(int type){	}
EVP_PKEY_METHOD* EVP_PKEY_meth_new(int id, int flags){	}
void EVP_PKEY_meth_get0_info(int *ppkey_id, int *pflags, EVP_PKEY_METHOD *meth){	}
void EVP_PKEY_meth_copy(EVP_PKEY_METHOD *dst,  EVP_PKEY_METHOD *src){	}
void EVP_PKEY_meth_free(EVP_PKEY_METHOD *pmeth){	}
int EVP_PKEY_meth_add0( EVP_PKEY_METHOD *pmeth){	}
EVP_PKEY_CTX *EVP_PKEY_CTX_new(EVP_PKEY *pkey, ENGINE *e){	}
EVP_PKEY_CTX *EVP_PKEY_CTX_new_id(int id, ENGINE *e){	}
EVP_PKEY_CTX *EVP_PKEY_CTX_dup(EVP_PKEY_CTX *ctx){	}
void EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx){	}
int EVP_PKEY_CTX_ctrl(EVP_PKEY_CTX *ctx, int keytype, int optype, int cmd, int p1, void *p2){	}
int EVP_PKEY_CTX_ctrl_str(EVP_PKEY_CTX *ctx,  char *type, char *value){	}
int EVP_PKEY_CTX_get_operation(EVP_PKEY_CTX *ctx){	}
void EVP_PKEY_CTX_set0_keygen_info(EVP_PKEY_CTX *ctx, int *dat, int datlen){	}
EVP_PKEY *EVP_PKEY_new_mac_key(int type, ENGINE *e, unsigned char *key, int keylen){	}
void EVP_PKEY_CTX_set_data(EVP_PKEY_CTX *ctx, void *data){	}
void *EVP_PKEY_CTX_get_data(EVP_PKEY_CTX *ctx){	}
EVP_PKEY *EVP_PKEY_CTX_get0_pkey(EVP_PKEY_CTX *ctx){	}
EVP_PKEY *EVP_PKEY_CTX_get0_peerkey(EVP_PKEY_CTX *ctx){	}
void EVP_PKEY_CTX_set_app_data(EVP_PKEY_CTX *ctx, void *data){	}
void *EVP_PKEY_CTX_get_app_data(EVP_PKEY_CTX *ctx){	}
int EVP_PKEY_sign_init(EVP_PKEY_CTX *ctx){	}
int EVP_PKEY_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, unsigned char *tbs, size_t tbslen){	}
int EVP_PKEY_verify_init(EVP_PKEY_CTX *ctx){	}
int EVP_PKEY_verify(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t siglen, unsigned char *tbs, size_t tbslen){	}
int EVP_PKEY_verify_recover_init(EVP_PKEY_CTX *ctx){	}
int EVP_PKEY_verify_recover(EVP_PKEY_CTX *ctx, unsigned char *rout, size_t *routlen, unsigned char *sig, size_t siglen){	}
int EVP_PKEY_encrypt_init(EVP_PKEY_CTX *ctx){	}
int EVP_PKEY_encrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, unsigned char *in, size_t inlen){	}
int EVP_PKEY_decrypt_init(EVP_PKEY_CTX *ctx){	}
int EVP_PKEY_decrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, unsigned char *in, size_t inlen){	}
int EVP_PKEY_derive_init(EVP_PKEY_CTX *ctx){	}
int EVP_PKEY_derive_set_peer(EVP_PKEY_CTX *ctx, EVP_PKEY *peer){	}
int EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen){	}
int EVP_PKEY_paramgen_init(EVP_PKEY_CTX *ctx){	}
int EVP_PKEY_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey){	}
int EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx){	}
int EVP_PKEY_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey){	}
void EVP_PKEY_CTX_set_cb(EVP_PKEY_CTX *ctx, EVP_PKEY_gen_cb *cb){	}
EVP_PKEY_gen_cb *EVP_PKEY_CTX_get_cb(EVP_PKEY_CTX *ctx){	}
int EVP_PKEY_CTX_get_keygen_info(EVP_PKEY_CTX *ctx, int idx){	}
void EVP_PKEY_meth_set_init(EVP_PKEY_METHOD *pmeth, int (*init)(EVP_PKEY_CTX *ctx)){	}
void EVP_PKEY_meth_set_copy(EVP_PKEY_METHOD *pmeth, int (*copy)(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)){	}
void EVP_PKEY_meth_set_cleanup(EVP_PKEY_METHOD *pmeth, void (*cleanup)(EVP_PKEY_CTX *ctx)){	}
void EVP_PKEY_meth_set_paramgen(EVP_PKEY_METHOD *pmeth, int (*paramgen_init)(EVP_PKEY_CTX *ctx), int (*paramgen)(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)){	}
void EVP_PKEY_meth_set_keygen(EVP_PKEY_METHOD *pmeth, int (*keygen_init)(EVP_PKEY_CTX *ctx), int (*keygen)(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)){	}
void EVP_PKEY_meth_set_sign(EVP_PKEY_METHOD *pmeth, int (*sign_init)(EVP_PKEY_CTX *ctx), int (*sign)(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, unsigned char *tbs, size_t tbslen)){	}
void EVP_PKEY_meth_set_verify(EVP_PKEY_METHOD *pmeth, int (*verify_init)(EVP_PKEY_CTX *ctx), int (*verify)(EVP_PKEY_CTX *ctx,  unsigned char *sig, size_t siglen, unsigned char *tbs, size_t tbslen)){	}
void EVP_PKEY_meth_set_verify_recover(EVP_PKEY_METHOD *pmeth, int (*verify_recover_init)(EVP_PKEY_CTX *ctx), int (*verify_recover)(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, unsigned char *tbs, size_t tbslen)){	}
void EVP_PKEY_meth_set_signctx(EVP_PKEY_METHOD *pmeth, int (*signctx_init)(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx), int (*signctx)(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, EVP_MD_CTX *mctx)){	}
void EVP_PKEY_meth_set_verifyctx(EVP_PKEY_METHOD *pmeth, int (*verifyctx_init)(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx), int (*verifyctx)(EVP_PKEY_CTX *ctx,  unsigned char *sig,int siglen, EVP_MD_CTX *mctx)){	}
void EVP_PKEY_meth_set_encrypt(EVP_PKEY_METHOD *pmeth, int (*encrypt_init)(EVP_PKEY_CTX *ctx), int (*encryptfn)(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, unsigned char *in, size_t inlen)){	}
void EVP_PKEY_meth_set_decrypt(EVP_PKEY_METHOD *pmeth, int (*decrypt_init)(EVP_PKEY_CTX *ctx), int (*decrypt)(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, unsigned char *in, size_t inlen)){	}
void EVP_PKEY_meth_set_derive(EVP_PKEY_METHOD *pmeth, int (*derive_init)(EVP_PKEY_CTX *ctx), int (*derive)(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen)){	}
void EVP_PKEY_meth_set_ctrl(EVP_PKEY_METHOD *pmeth, int (*ctrl)(EVP_PKEY_CTX *ctx, int type, int p1, void *p2), int (*ctrl_str)(EVP_PKEY_CTX *ctx, char *type,  char *value)){	}
void EVP_add_alg_module(void){	}
void ERR_load_EVP_strings(void){	}
int	PEM_get_EVP_CIPHER_INFO(char *header, EVP_CIPHER_INFO *cipher){	}
int	PEM_do_header (EVP_CIPHER_INFO *cipher, unsigned char *data,long *len, pem_password_cb *callback,void *u){	}
int	PEM_read_bio(BIO *bp, char **name, char **header, unsigned char **data,long *len){	}
int	PEM_write_bio(BIO *bp, char *name,char *hdr,unsigned char *data, long len){	}
int PEM_bytes_read_bio(unsigned char **pdata, long *plen, char **pnm,  char *name, BIO *bp, pem_password_cb *cb, void *u){	}
void *	PEM_ASN1_read_bio(d2i_of_void *d2i,  char *name, BIO *bp, void **x, pem_password_cb *cb, void *u){	}
int	PEM_ASN1_write_bio(i2d_of_void *i2d, char *name,BIO *bp, void *x, EVP_CIPHER *enc,unsigned char *kstr,int klen, pem_password_cb *cb, void *u){	}
int	PEM_X509_INFO_write_bio(BIO *bp,X509_INFO *xi, EVP_CIPHER *enc, unsigned char *kstr, int klen, pem_password_cb *cd, void *u){	}
int	PEM_read(FILE *fp, char **name, char **header, unsigned char **data,long *len){	}
int	PEM_write(FILE *fp,char *name,char *hdr,unsigned char *data,long len){	}
void *  PEM_ASN1_read(d2i_of_void *d2i,  char *name, FILE *fp, void **x, pem_password_cb *cb, void *u){	}
int	PEM_ASN1_write(i2d_of_void *i2d, char *name,FILE *fp, void *x, EVP_CIPHER *enc,unsigned char *kstr, int klen,pem_password_cb *callback, void *u){	}
int	PEM_SealInit(PEM_ENCODE_SEAL_CTX *ctx, EVP_CIPHER *type, EVP_MD *md_type, unsigned char **ek, int *ekl, unsigned char *iv, EVP_PKEY **pubk, int npubk){	}
void	PEM_SealUpdate(PEM_ENCODE_SEAL_CTX *ctx, unsigned char *out, int *outl, unsigned char *in, int inl){	}
int	PEM_SealFinal(PEM_ENCODE_SEAL_CTX *ctx, unsigned char *sig,int *sigl, unsigned char *out, int *outl, EVP_PKEY *priv){	}
void    PEM_SignInit(EVP_MD_CTX *ctx, EVP_MD *type){	}
void    PEM_SignUpdate(EVP_MD_CTX *ctx,unsigned char *d,unsigned int cnt){	}
int	PEM_SignFinal(EVP_MD_CTX *ctx, unsigned char *sigret, unsigned int *siglen, EVP_PKEY *pkey){	}
int	PEM_def_callback(char *buf, int num, int w, void *key){	}
void	PEM_proc_type(char *buf, int type){	}
void	PEM_dek_info(char *buf,  char *type, int len, char *str){	}
int PEM_write_bio_PKCS8PrivateKey(BIO *, EVP_PKEY *,  EVP_CIPHER *, char *, int, pem_password_cb *, void *){	}
int i2d_PKCS8PrivateKey_bio(BIO *bp, EVP_PKEY *x,  EVP_CIPHER *enc, char *kstr, int klen, pem_password_cb *cb, void *u){	}
int i2d_PKCS8PrivateKey_nid_bio(BIO *bp, EVP_PKEY *x, int nid, char *kstr, int klen, pem_password_cb *cb, void *u){	}
EVP_PKEY *d2i_PKCS8PrivateKey_bio(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u){	}
int i2d_PKCS8PrivateKey_fp(FILE *fp, EVP_PKEY *x,  EVP_CIPHER *enc, char *kstr, int klen, pem_password_cb *cb, void *u){	}
int i2d_PKCS8PrivateKey_nid_fp(FILE *fp, EVP_PKEY *x, int nid, char *kstr, int klen, pem_password_cb *cb, void *u){	}
int PEM_write_PKCS8PrivateKey_nid(FILE *fp, EVP_PKEY *x, int nid, char *kstr, int klen, pem_password_cb *cb, void *u){	}
EVP_PKEY *d2i_PKCS8PrivateKey_fp(FILE *fp, EVP_PKEY **x, pem_password_cb *cb, void *u){	}
int PEM_write_PKCS8PrivateKey(FILE *fp,EVP_PKEY *x, EVP_CIPHER *enc, char *kstr,int klen, pem_password_cb *cd, void *u){	}
EVP_PKEY *PEM_read_bio_Parameters(BIO *bp, EVP_PKEY **x){	}
int PEM_write_bio_Parameters(BIO *bp, EVP_PKEY *x){	}
EVP_PKEY *b2i_PrivateKey( unsigned char **in, long length){	}
EVP_PKEY *b2i_PublicKey( unsigned char **in, long length){	}
EVP_PKEY *b2i_PrivateKey_bio(BIO *in){	}
EVP_PKEY *b2i_PublicKey_bio(BIO *in){	}
int i2b_PrivateKey_bio(BIO *out, EVP_PKEY *pk){	}
int i2b_PublicKey_bio(BIO *out, EVP_PKEY *pk){	}
EVP_PKEY *b2i_PVK_bio(BIO *in, pem_password_cb *cb, void *u){	}
int i2b_PVK_bio(BIO *out, EVP_PKEY *pk, int enclevel, pem_password_cb *cb, void *u){	}
ECDSA_SIG *ECDSA_SIG_new(void){	}
void	  ECDSA_SIG_free(ECDSA_SIG *sig){	}
int	  i2d_ECDSA_SIG( ECDSA_SIG *sig, unsigned char **pp){	}
ECDSA_SIG *d2i_ECDSA_SIG(ECDSA_SIG **sig,  unsigned char **pp, long len){	}
ECDSA_SIG *ECDSA_do_sign( unsigned char *dgst,int dgst_len,EC_KEY *eckey){	}
ECDSA_SIG *ECDSA_do_sign_ex( unsigned char *dgst, int dgstlen, BIGNUM *kinv,  BIGNUM *rp, EC_KEY *eckey){	}
int	  ECDSA_do_verify( unsigned char *dgst, int dgst_len, ECDSA_SIG *sig, EC_KEY* eckey){	}
ECDSA_METHOD *ECDSA_OpenSSL(void){	}
void	  ECDSA_set_default_method( ECDSA_METHOD *meth){	}
ECDSA_METHOD *ECDSA_get_default_method(void){	}
int 	  ECDSA_set_method(EC_KEY *eckey,  ECDSA_METHOD *meth){	}
int	  ECDSA_size( EC_KEY *eckey){	}
int 	  ECDSA_sign_setup(EC_KEY *eckey, BN_CTX *ctx, BIGNUM **kinv, BIGNUM **rp){	}
int	  ECDSA_sign(int type,  unsigned char *dgst, int dgstlen, unsigned char *sig, unsigned int *siglen, EC_KEY *eckey){	}
int	  ECDSA_sign_ex(int type,  unsigned char *dgst, int dgstlen, unsigned char *sig, unsigned int *siglen,  BIGNUM *kinv, BIGNUM *rp, EC_KEY *eckey){	}
int 	  ECDSA_verify(int type,  unsigned char *dgst, int dgstlen, unsigned char *sig, int siglen, EC_KEY *eckey){	}
int 	  ECDSA_set_ex_data(EC_KEY *d, int idx, void *arg){	}
void 	  *ECDSA_get_ex_data(EC_KEY *d, int idx){	}
void ERR_load_ECDSA_strings(void){	}
void ERR_put_error(int lib, int func,int reason, char *file,int line){	}
void ERR_set_error_data(char *data,int flags){	}
unsigned long ERR_get_error(void){	}
unsigned long ERR_get_error_line( char **file,int *line){	}
unsigned long ERR_get_error_line_data( char **file,int *line, char **data, int *flags){	}
unsigned long ERR_peek_error(void){	}
unsigned long ERR_peek_error_line( char **file,int *line){	}
unsigned long ERR_peek_error_line_data( char **file,int *line, char **data,int *flags){	}
unsigned long ERR_peek_last_error(void){	}
unsigned long ERR_peek_last_error_line( char **file,int *line){	}
unsigned long ERR_peek_last_error_line_data( char **file,int *line, char **data,int *flags){	}
void ERR_clear_error(void ){	}
char *ERR_error_string(unsigned long e,char *buf){	}
void ERR_error_string_n(unsigned long e, char *buf, size_t len){	}
char *ERR_lib_error_string(unsigned long e){	}
char *ERR_func_error_string(unsigned long e){	}
char *ERR_reason_error_string(unsigned long e){	}
void ERR_print_errors_cb(int (*cb)( char *str, size_t len, void *u), void *u){	}
void ERR_print_errors_fp(FILE *fp){	}
void ERR_print_errors(BIO *bp){	}
void ERR_add_error_data(int num, ...){	}
void ERR_add_error_vdata(int num, va_list args){	}
void ERR_load_strings(int lib,ERR_STRING_DATA str[]){	}
void ERR_unload_strings(int lib,ERR_STRING_DATA str[]){	}
void ERR_load_ERR_strings(void){	}
void ERR_load_crypto_strings(void){	}
void ERR_free_strings(void){	}
void ERR_remove_thread_state( CRYPTO_THREADID *tid){	}
void ERR_remove_state(unsigned long pid){	}
ERR_STATE *ERR_get_state(void){	}
void ERR_release_err_state_table(LHASH_OF(ERR_STATE) **hash){	}
int ERR_get_next_error_library(void){	}
int ERR_set_mark(void){	}
int ERR_pop_to_mark(void){	}
ERR_FNS *ERR_get_implementation(void){	}
int ERR_set_implementation( ERR_FNS *fns){	}
pitem *pitem_new(unsigned char *prio64be, void *data){	}
void   pitem_free(pitem *item){	}
pqueue pqueue_new(void){	}
void   pqueue_free(pqueue pq){	}
pitem *pqueue_insert(pqueue pq, pitem *item){	}
pitem *pqueue_peek(pqueue pq){	}
pitem *pqueue_pop(pqueue pq){	}
pitem *pqueue_find(pqueue pq, unsigned char *prio64be){	}
pitem *pqueue_iterator(pqueue pq){	}
pitem *pqueue_next(piterator *iter){	}
void   pqueue_print(pqueue pq){	}
int    pqueue_size(pqueue pq){	}
char *RC4_options(void){	}
void RC4_set_key(RC4_KEY *key, int len,  unsigned char *data){	}
void private_RC4_set_key(RC4_KEY *key, int len,  unsigned char *data){	}
void RC4(RC4_KEY *key, size_t len,  unsigned char *indata, unsigned char *outdata){	}
BUF_MEM *BUF_MEM_new(void){	}
void	BUF_MEM_free(BUF_MEM *a){	}
int	BUF_MEM_grow(BUF_MEM *str, size_t len){	}
int	BUF_MEM_grow_clean(BUF_MEM *str, size_t len){	}
char *	BUF_strdup( char *str){	}
char *	BUF_strndup( char *str, size_t siz){	}
void *	BUF_memdup( void *data, size_t siz){	}
void	BUF_reverse(unsigned char *out,  unsigned char *in, size_t siz){	}
size_t BUF_strlcpy(char *dst, char *src,size_t siz){	}
size_t BUF_strlcat(char *dst, char *src,size_t siz){	}
void ERR_load_BUF_strings(void){	}
int private_MD4_Init(MD4_CTX *c){	}
int MD4_Init(MD4_CTX *c){	}
int MD4_Update(MD4_CTX *c,  void *data, size_t len){	}
int MD4_Final(unsigned char *md, MD4_CTX *c){	}
unsigned char *MD4( unsigned char *d, size_t n, unsigned char *md){	}
void MD4_Transform(MD4_CTX *c,  unsigned char *b){	}
ECDH_METHOD *ECDH_OpenSSL(void){	}
void	  ECDH_set_default_method( ECDH_METHOD *){	}
ECDH_METHOD *ECDH_get_default_method(void){	}
int 	  ECDH_set_method(EC_KEY *,  ECDH_METHOD *){	}
int ECDH_compute_key(void *out, size_t outlen,  EC_POINT *pub_key, EC_KEY *ecdh, void *(*KDF)( void *in, size_t inlen, void *out, size_t *outlen)){	}
int 	  ECDH_set_ex_data(EC_KEY *d, int idx, void *arg){	}
void 	  *ECDH_get_ex_data(EC_KEY *d, int idx){	}
void ERR_load_ECDH_strings(void){	}
int SXNET_add_id_ulong(SXNET **psx, unsigned long lzone, char *user, int userlen){	}
int SXNET_add_id_INTEGER(SXNET **psx, ASN1_INTEGER *izone, char *user, int userlen){	}
ASN1_OCTET_STRING *SXNET_get_id_asc(SXNET *sx, char *zone){	}
ASN1_OCTET_STRING *SXNET_get_id_ulong(SXNET *sx, unsigned long lzone){	}
ASN1_OCTET_STRING *SXNET_get_id_INTEGER(SXNET *sx, ASN1_INTEGER *zone){	}
int GENERAL_NAME_cmp(GENERAL_NAME *a, GENERAL_NAME *b){	}
ASN1_BIT_STRING *v2i_ASN1_BIT_STRING(X509V3_EXT_METHOD *method, X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *nval){	}
int GENERAL_NAME_print(BIO *out, GENERAL_NAME *gen){	}
GENERAL_NAMES *v2i_GENERAL_NAMES( X509V3_EXT_METHOD *method, X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *nval){	}
void GENERAL_NAME_set0_value(GENERAL_NAME *a, int type, void *value){	}
void *GENERAL_NAME_get0_value(GENERAL_NAME *a, int *ptype){	}
int GENERAL_NAME_set0_othername(GENERAL_NAME *gen, ASN1_OBJECT *oid, ASN1_TYPE *value){	}
int GENERAL_NAME_get0_otherName(GENERAL_NAME *gen, ASN1_OBJECT **poid, ASN1_TYPE **pvalue){	}
char *i2s_ASN1_OCTET_STRING(X509V3_EXT_METHOD *method, ASN1_OCTET_STRING *ia5){	}
ASN1_OCTET_STRING *s2i_ASN1_OCTET_STRING(X509V3_EXT_METHOD *method, X509V3_CTX *ctx, char *str){	}
int NAME_CONSTRAINTS_check(X509 *x, NAME_CONSTRAINTS *nc){	}
GENERAL_NAME *v2i_GENERAL_NAME( X509V3_EXT_METHOD *method, X509V3_CTX *ctx, CONF_VALUE *cnf){	}
GENERAL_NAME *v2i_GENERAL_NAME_ex(GENERAL_NAME *out, X509V3_EXT_METHOD *method, X509V3_CTX *ctx, CONF_VALUE *cnf, int is_nc){	}
void X509V3_conf_free(CONF_VALUE *val){	}
X509_EXTENSION *X509V3_EXT_nconf_nid(CONF *conf, X509V3_CTX *ctx, int ext_nid, char *value){	}
X509_EXTENSION *X509V3_EXT_nconf(CONF *conf, X509V3_CTX *ctx, char *name, char *value){	}
int X509V3_EXT_add_nconf_sk(CONF *conf, X509V3_CTX *ctx, char *section, STACK_OF(X509_EXTENSION) **sk){	}
int X509V3_EXT_add_nconf(CONF *conf, X509V3_CTX *ctx, char *section, X509 *cert){	}
int X509V3_EXT_REQ_add_nconf(CONF *conf, X509V3_CTX *ctx, char *section, X509_REQ *req){	}
int X509V3_EXT_CRL_add_nconf(CONF *conf, X509V3_CTX *ctx, char *section, X509_CRL *crl){	}
X509_EXTENSION *X509V3_EXT_conf_nid(LHASH_OF(CONF_VALUE) *conf, X509V3_CTX *ctx, int ext_nid, char *value){	}
X509_EXTENSION *X509V3_EXT_conf(LHASH_OF(CONF_VALUE) *conf, X509V3_CTX *ctx, char *name, char *value){	}
int X509V3_EXT_add_conf(LHASH_OF(CONF_VALUE) *conf, X509V3_CTX *ctx, char *section, X509 *cert){	}
int X509V3_EXT_REQ_add_conf(LHASH_OF(CONF_VALUE) *conf, X509V3_CTX *ctx, char *section, X509_REQ *req){	}
int X509V3_EXT_CRL_add_conf(LHASH_OF(CONF_VALUE) *conf, X509V3_CTX *ctx, char *section, X509_CRL *crl){	}
int X509V3_add_value_bool_nf(char *name, int asn1_bool, STACK_OF(CONF_VALUE) **extlist){	}
int X509V3_get_value_bool(CONF_VALUE *value, int *asn1_bool){	}
int X509V3_get_value_int(CONF_VALUE *value, ASN1_INTEGER **aint){	}
void X509V3_set_nconf(X509V3_CTX *ctx, CONF *conf){	}
void X509V3_set_conf_lhash(X509V3_CTX *ctx, LHASH_OF(CONF_VALUE) *lhash){	}
char * X509V3_get_string(X509V3_CTX *ctx, char *name, char *section){	}
void X509V3_string_free(X509V3_CTX *ctx, char *str){	}
void X509V3_section_free( X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *section){	}
void X509V3_set_ctx(X509V3_CTX *ctx, X509 *issuer, X509 *subject, X509_REQ *req, X509_CRL *crl, int flags){	}
int X509V3_add_value( char *name,  char *value, STACK_OF(CONF_VALUE) **extlist){	}
int X509V3_add_value_uchar( char *name,  unsigned char *value, STACK_OF(CONF_VALUE) **extlist){	}
int X509V3_add_value_bool( char *name, int asn1_bool, STACK_OF(CONF_VALUE) **extlist){	}
int X509V3_add_value_int( char *name, ASN1_INTEGER *aint, STACK_OF(CONF_VALUE) **extlist){	}
char * i2s_ASN1_INTEGER(X509V3_EXT_METHOD *meth, ASN1_INTEGER *aint){	}
ASN1_INTEGER * s2i_ASN1_INTEGER(X509V3_EXT_METHOD *meth, char *value){	}
char * i2s_ASN1_ENUMERATED(X509V3_EXT_METHOD *meth, ASN1_ENUMERATED *aint){	}
char * i2s_ASN1_ENUMERATED_TABLE(X509V3_EXT_METHOD *meth, ASN1_ENUMERATED *aint){	}
int X509V3_EXT_add(X509V3_EXT_METHOD *ext){	}
int X509V3_EXT_add_list(X509V3_EXT_METHOD *extlist){	}
int X509V3_EXT_add_alias(int nid_to, int nid_from){	}
void X509V3_EXT_cleanup(void){	}
X509V3_EXT_METHOD *X509V3_EXT_get(X509_EXTENSION *ext){	}
X509V3_EXT_METHOD *X509V3_EXT_get_nid(int nid){	}
int X509V3_add_standard_extensions(void){	}
void *X509V3_EXT_d2i(X509_EXTENSION *ext){	}
void *X509V3_get_d2i(STACK_OF(X509_EXTENSION) *x, int nid, int *crit, int *idx){	}
X509_EXTENSION *X509V3_EXT_i2d(int ext_nid, int crit, void *ext_struc){	}
int X509V3_add1_i2d(STACK_OF(X509_EXTENSION) **x, int nid, void *value, int crit, unsigned long flags){	}
char *hex_to_string( unsigned char *buffer, long len){	}
unsigned char *string_to_hex( char *str, long *len){	}
int name_cmp( char *name,  char *cmp){	}
void X509V3_EXT_val_prn(BIO *out, STACK_OF(CONF_VALUE) *val, int indent, int ml){	}
int X509V3_EXT_print(BIO *out, X509_EXTENSION *ext, unsigned long flag, int indent){	}
int X509V3_EXT_print_fp(FILE *out, X509_EXTENSION *ext, int flag, int indent){	}
int X509V3_extensions_print(BIO *out, char *title, STACK_OF(X509_EXTENSION) *exts, unsigned long flag, int indent){	}
int X509_check_ca(X509 *x){	}
int X509_check_purpose(X509 *x, int id, int ca){	}
int X509_supported_extension(X509_EXTENSION *ex){	}
int X509_PURPOSE_set(int *p, int purpose){	}
int X509_check_issued(X509 *issuer, X509 *subject){	}
int X509_check_akid(X509 *issuer, AUTHORITY_KEYID *akid){	}
int X509_PURPOSE_get_count(void){	}
X509_PURPOSE * X509_PURPOSE_get0(int idx){	}
int X509_PURPOSE_get_by_sname(char *sname){	}
int X509_PURPOSE_get_by_id(int id){	}
int X509_PURPOSE_add(int id, int trust, int flags, int (*ck)( X509_PURPOSE *,  X509 *, int), char *name, char *sname, void *arg){	}
char *X509_PURPOSE_get0_name(X509_PURPOSE *xp){	}
char *X509_PURPOSE_get0_sname(X509_PURPOSE *xp){	}
int X509_PURPOSE_get_trust(X509_PURPOSE *xp){	}
void X509_PURPOSE_cleanup(void){	}
int X509_PURPOSE_get_id(X509_PURPOSE *){	}
void X509_email_free(STACK_OF(OPENSSL_STRING) *sk){	}
ASN1_OCTET_STRING *a2i_IPADDRESS( char *ipasc){	}
ASN1_OCTET_STRING *a2i_IPADDRESS_NC( char *ipasc){	}
int a2i_ipadd(unsigned char *ipout,  char *ipasc){	}
int X509V3_NAME_from_section(X509_NAME *nm, STACK_OF(CONF_VALUE)*dn_sk, unsigned long chtype){	}
void X509_POLICY_NODE_print(BIO *out, X509_POLICY_NODE *node, int indent){	}
int v3_asid_add_inherit(ASIdentifiers *asid, int which){	}
int v3_asid_add_id_or_range(ASIdentifiers *asid, int which, ASN1_INTEGER *min, ASN1_INTEGER *max){	}
int v3_addr_add_inherit(IPAddrBlocks *addr, unsigned afi,  unsigned *safi){	}
int v3_addr_add_prefix(IPAddrBlocks *addr, unsigned afi,  unsigned *safi, unsigned char *a,  int prefixlen){	}
int v3_addr_add_range(IPAddrBlocks *addr, unsigned afi,  unsigned *safi, unsigned char *min, unsigned char *max){	}
unsigned v3_addr_get_afi( IPAddressFamily *f){	}
int v3_addr_get_range(IPAddressOrRange *aor,  unsigned afi, unsigned char *min, unsigned char *max, int length){	}
int v3_asid_is_canonical(ASIdentifiers *asid){	}
int v3_addr_is_canonical(IPAddrBlocks *addr){	}
int v3_asid_canonize(ASIdentifiers *asid){	}
int v3_addr_canonize(IPAddrBlocks *addr){	}
int v3_asid_inherits(ASIdentifiers *asid){	}
int v3_addr_inherits(IPAddrBlocks *addr){	}
int v3_asid_subset(ASIdentifiers *a, ASIdentifiers *b){	}
int v3_addr_subset(IPAddrBlocks *a, IPAddrBlocks *b){	}
int v3_asid_validate_path(X509_STORE_CTX *){	}
int v3_addr_validate_path(X509_STORE_CTX *){	}
int v3_asid_validate_resource_set(STACK_OF(X509) *chain, ASIdentifiers *ext, int allow_inheritance){	}
int v3_addr_validate_resource_set(STACK_OF(X509) *chain, IPAddrBlocks *ext, int allow_inheritance){	}
void ERR_load_X509V3_strings(void){	}
void private_SEED_set_key( unsigned char rawkey[SEED_KEY_LENGTH], SEED_KEY_SCHEDULE *ks){	}
void SEED_set_key( unsigned char rawkey[SEED_KEY_LENGTH], SEED_KEY_SCHEDULE *ks){	}
void SEED_encrypt( unsigned char s[SEED_BLOCK_SIZE], unsigned char d[SEED_BLOCK_SIZE],  SEED_KEY_SCHEDULE *ks){	}
void SEED_decrypt( unsigned char s[SEED_BLOCK_SIZE], unsigned char d[SEED_BLOCK_SIZE],  SEED_KEY_SCHEDULE *ks){	}
void SEED_ecb_encrypt( unsigned char *in, unsigned char *out,  SEED_KEY_SCHEDULE *ks, int enc){	}
void SEED_cbc_encrypt( unsigned char *in, unsigned char *out, size_t len,  SEED_KEY_SCHEDULE *ks, unsigned char ivec[SEED_BLOCK_SIZE], int enc){	}
void SEED_cfb128_encrypt( unsigned char *in, unsigned char *out, size_t len,  SEED_KEY_SCHEDULE *ks, unsigned char ivec[SEED_BLOCK_SIZE], int *num, int enc){	}
void SEED_ofb128_encrypt( unsigned char *in, unsigned char *out, size_t len,  SEED_KEY_SCHEDULE *ks, unsigned char ivec[SEED_BLOCK_SIZE], int *num){	}
char *idea_options(void){	}
void idea_ecb_encrypt( unsigned char *in, unsigned char *out, IDEA_KEY_SCHEDULE *ks){	}
void private_idea_set_encrypt_key( unsigned char *key, IDEA_KEY_SCHEDULE *ks){	}
void idea_set_encrypt_key( unsigned char *key, IDEA_KEY_SCHEDULE *ks){	}
void idea_set_decrypt_key(IDEA_KEY_SCHEDULE *ek, IDEA_KEY_SCHEDULE *dk){	}
void idea_cbc_encrypt( unsigned char *in, unsigned char *out, long length, IDEA_KEY_SCHEDULE *ks, unsigned char *iv,int enc){	}
void idea_cfb64_encrypt( unsigned char *in, unsigned char *out, long length, IDEA_KEY_SCHEDULE *ks, unsigned char *iv, int *num,int enc){	}
void idea_ofb64_encrypt( unsigned char *in, unsigned char *out, long length, IDEA_KEY_SCHEDULE *ks, unsigned char *iv, int *num){	}
void idea_encrypt(unsigned long *in, IDEA_KEY_SCHEDULE *ks){	}
OCSP_CERTID *OCSP_CERTID_dup(OCSP_CERTID *id){	}
OCSP_RESPONSE *OCSP_sendreq_bio(BIO *b, char *path, OCSP_REQUEST *req){	}
OCSP_REQ_CTX *OCSP_sendreq_new(BIO *io, char *path, OCSP_REQUEST *req, int maxline){	}
int OCSP_sendreq_nbio(OCSP_RESPONSE **presp, OCSP_REQ_CTX *rctx){	}
void OCSP_REQ_CTX_free(OCSP_REQ_CTX *rctx){	}
int OCSP_REQ_CTX_set1_req(OCSP_REQ_CTX *rctx, OCSP_REQUEST *req){	}
int OCSP_REQ_CTX_add1_header(OCSP_REQ_CTX *rctx, char *name,  char *value){	}
OCSP_CERTID *OCSP_cert_to_id( EVP_MD *dgst, X509 *subject, X509 *issuer){	}
OCSP_CERTID *OCSP_cert_id_new( EVP_MD *dgst, X509_NAME *issuerName, ASN1_BIT_STRING* issuerKey, ASN1_INTEGER *serialNumber){	}
OCSP_ONEREQ *OCSP_request_add0_id(OCSP_REQUEST *req, OCSP_CERTID *cid){	}
int OCSP_request_add1_nonce(OCSP_REQUEST *req, unsigned char *val, int len){	}
int OCSP_basic_add1_nonce(OCSP_BASICRESP *resp, unsigned char *val, int len){	}
int OCSP_check_nonce(OCSP_REQUEST *req, OCSP_BASICRESP *bs){	}
int OCSP_copy_nonce(OCSP_BASICRESP *resp, OCSP_REQUEST *req){	}
int OCSP_request_set1_name(OCSP_REQUEST *req, X509_NAME *nm){	}
int OCSP_request_add1_cert(OCSP_REQUEST *req, X509 *cert){	}
int OCSP_request_sign(OCSP_REQUEST   *req, X509           *signer, EVP_PKEY       *key, EVP_MD   *dgst, STACK_OF(X509) *certs, unsigned long flags){	}
int OCSP_response_status(OCSP_RESPONSE *resp){	}
OCSP_BASICRESP *OCSP_response_get1_basic(OCSP_RESPONSE *resp){	}
int OCSP_resp_count(OCSP_BASICRESP *bs){	}
OCSP_SINGLERESP *OCSP_resp_get0(OCSP_BASICRESP *bs, int idx){	}
int OCSP_resp_find(OCSP_BASICRESP *bs, OCSP_CERTID *id, int last){	}
int OCSP_single_get0_status(OCSP_SINGLERESP *single, int *reason, ASN1_GENERALIZEDTIME **revtime, ASN1_GENERALIZEDTIME **thisupd, ASN1_GENERALIZEDTIME **nextupd){	}
int OCSP_resp_find_status(OCSP_BASICRESP *bs, OCSP_CERTID *id, int *status, int *reason, ASN1_GENERALIZEDTIME **revtime, ASN1_GENERALIZEDTIME **thisupd, ASN1_GENERALIZEDTIME **nextupd){	}
int OCSP_check_validity(ASN1_GENERALIZEDTIME *thisupd, ASN1_GENERALIZEDTIME *nextupd, long sec, long maxsec){	}
int OCSP_request_verify(OCSP_REQUEST *req, STACK_OF(X509) *certs, X509_STORE *store, unsigned long flags){	}
int OCSP_parse_url(char *url, char **phost, char **pport, char **ppath, int *pssl){	}
int OCSP_id_issuer_cmp(OCSP_CERTID *a, OCSP_CERTID *b){	}
int OCSP_id_cmp(OCSP_CERTID *a, OCSP_CERTID *b){	}
int OCSP_request_onereq_count(OCSP_REQUEST *req){	}
OCSP_ONEREQ *OCSP_request_onereq_get0(OCSP_REQUEST *req, int i){	}
OCSP_CERTID *OCSP_onereq_get0_id(OCSP_ONEREQ *one){	}
int OCSP_id_get0_info(ASN1_OCTET_STRING **piNameHash, ASN1_OBJECT **pmd, ASN1_OCTET_STRING **pikeyHash, ASN1_INTEGER **pserial, OCSP_CERTID *cid){	}
int OCSP_request_is_signed(OCSP_REQUEST *req){	}
OCSP_RESPONSE *OCSP_response_create(int status, OCSP_BASICRESP *bs){	}
OCSP_SINGLERESP *OCSP_basic_add1_status(OCSP_BASICRESP *rsp, OCSP_CERTID *cid, int status, int reason, ASN1_TIME *revtime, ASN1_TIME *thisupd, ASN1_TIME *nextupd){	}
int OCSP_basic_add1_cert(OCSP_BASICRESP *resp, X509 *cert){	}
int OCSP_basic_sign(OCSP_BASICRESP *brsp, X509 *signer, EVP_PKEY *key,  EVP_MD *dgst, STACK_OF(X509) *certs, unsigned long flags){	}
X509_EXTENSION *OCSP_crlID_new(char *url, long *n, char *tim){	}
X509_EXTENSION *OCSP_accept_responses_new(char **oids){	}
X509_EXTENSION *OCSP_archive_cutoff_new(char* tim){	}
X509_EXTENSION *OCSP_url_svcloc_new(X509_NAME* issuer, char **urls){	}
int OCSP_REQUEST_get_ext_count(OCSP_REQUEST *x){	}
int OCSP_REQUEST_get_ext_by_NID(OCSP_REQUEST *x, int nid, int lastpos){	}
int OCSP_REQUEST_get_ext_by_OBJ(OCSP_REQUEST *x, ASN1_OBJECT *obj, int lastpos){	}
int OCSP_REQUEST_get_ext_by_critical(OCSP_REQUEST *x, int crit, int lastpos){	}
X509_EXTENSION *OCSP_REQUEST_get_ext(OCSP_REQUEST *x, int loc){	}
X509_EXTENSION *OCSP_REQUEST_delete_ext(OCSP_REQUEST *x, int loc){	}
void *OCSP_REQUEST_get1_ext_d2i(OCSP_REQUEST *x, int nid, int *crit, int *idx){	}
int OCSP_REQUEST_add1_ext_i2d(OCSP_REQUEST *x, int nid, void *value, int crit, unsigned long flags){	}
int OCSP_REQUEST_add_ext(OCSP_REQUEST *x, X509_EXTENSION *ex, int loc){	}
int OCSP_ONEREQ_get_ext_count(OCSP_ONEREQ *x){	}
int OCSP_ONEREQ_get_ext_by_NID(OCSP_ONEREQ *x, int nid, int lastpos){	}
int OCSP_ONEREQ_get_ext_by_OBJ(OCSP_ONEREQ *x, ASN1_OBJECT *obj, int lastpos){	}
int OCSP_ONEREQ_get_ext_by_critical(OCSP_ONEREQ *x, int crit, int lastpos){	}
X509_EXTENSION *OCSP_ONEREQ_get_ext(OCSP_ONEREQ *x, int loc){	}
X509_EXTENSION *OCSP_ONEREQ_delete_ext(OCSP_ONEREQ *x, int loc){	}
void *OCSP_ONEREQ_get1_ext_d2i(OCSP_ONEREQ *x, int nid, int *crit, int *idx){	}
int OCSP_ONEREQ_add1_ext_i2d(OCSP_ONEREQ *x, int nid, void *value, int crit, unsigned long flags){	}
int OCSP_ONEREQ_add_ext(OCSP_ONEREQ *x, X509_EXTENSION *ex, int loc){	}
int OCSP_BASICRESP_get_ext_count(OCSP_BASICRESP *x){	}
int OCSP_BASICRESP_get_ext_by_NID(OCSP_BASICRESP *x, int nid, int lastpos){	}
int OCSP_BASICRESP_get_ext_by_OBJ(OCSP_BASICRESP *x, ASN1_OBJECT *obj, int lastpos){	}
int OCSP_BASICRESP_get_ext_by_critical(OCSP_BASICRESP *x, int crit, int lastpos){	}
X509_EXTENSION *OCSP_BASICRESP_get_ext(OCSP_BASICRESP *x, int loc){	}
X509_EXTENSION *OCSP_BASICRESP_delete_ext(OCSP_BASICRESP *x, int loc){	}
void *OCSP_BASICRESP_get1_ext_d2i(OCSP_BASICRESP *x, int nid, int *crit, int *idx){	}
int OCSP_BASICRESP_add1_ext_i2d(OCSP_BASICRESP *x, int nid, void *value, int crit, unsigned long flags){	}
int OCSP_BASICRESP_add_ext(OCSP_BASICRESP *x, X509_EXTENSION *ex, int loc){	}
int OCSP_SINGLERESP_get_ext_count(OCSP_SINGLERESP *x){	}
int OCSP_SINGLERESP_get_ext_by_NID(OCSP_SINGLERESP *x, int nid, int lastpos){	}
int OCSP_SINGLERESP_get_ext_by_OBJ(OCSP_SINGLERESP *x, ASN1_OBJECT *obj, int lastpos){	}
int OCSP_SINGLERESP_get_ext_by_critical(OCSP_SINGLERESP *x, int crit, int lastpos){	}
X509_EXTENSION *OCSP_SINGLERESP_get_ext(OCSP_SINGLERESP *x, int loc){	}
X509_EXTENSION *OCSP_SINGLERESP_delete_ext(OCSP_SINGLERESP *x, int loc){	}
void *OCSP_SINGLERESP_get1_ext_d2i(OCSP_SINGLERESP *x, int nid, int *crit, int *idx){	}
int OCSP_SINGLERESP_add1_ext_i2d(OCSP_SINGLERESP *x, int nid, void *value, int crit, unsigned long flags){	}
int OCSP_SINGLERESP_add_ext(OCSP_SINGLERESP *x, X509_EXTENSION *ex, int loc){	}
char *OCSP_cert_status_str(long s){	}
char *OCSP_crl_reason_str(long s){	}
int OCSP_REQUEST_print(BIO *bp, OCSP_REQUEST* a, unsigned long flags){	}
int OCSP_RESPONSE_print(BIO *bp, OCSP_RESPONSE* o, unsigned long flags){	}
int OCSP_basic_verify(OCSP_BASICRESP *bs, STACK_OF(X509) *certs, X509_STORE *st, unsigned long flags){	}
void ERR_load_OCSP_strings(void){	}
void private_BF_set_key(BF_KEY *key, int len,  unsigned char *data){	}
void BF_set_key(BF_KEY *key, int len,  unsigned char *data){	}
void BF_encrypt(BF_LONG *data, BF_KEY *key){	}
void BF_decrypt(BF_LONG *data, BF_KEY *key){	}
void BF_ecb_encrypt( unsigned char *in, unsigned char *out, BF_KEY *key, int enc){	}
void BF_cbc_encrypt( unsigned char *in, unsigned char *out, long length, BF_KEY *schedule, unsigned char *ivec, int enc){	}
void BF_cfb64_encrypt( unsigned char *in, unsigned char *out, long length, BF_KEY *schedule, unsigned char *ivec, int *num, int enc){	}
void BF_ofb64_encrypt( unsigned char *in, unsigned char *out, long length, BF_KEY *schedule, unsigned char *ivec, int *num){	}
char *BF_options(void){	}
int private_WHIRLPOOL_Init(WHIRLPOOL_CTX *c){	}
int WHIRLPOOL_Init	(WHIRLPOOL_CTX *c){	}
int WHIRLPOOL_Update	(WHIRLPOOL_CTX *c, void *inp,size_t bytes){	}
void WHIRLPOOL_BitUpdate(WHIRLPOOL_CTX *c, void *inp,size_t bits){	}
int WHIRLPOOL_Final	(unsigned char *md,WHIRLPOOL_CTX *c){	}
unsigned char *WHIRLPOOL( void *inp,size_t bytes,unsigned char *md){	}
GCM128_CONTEXT *CRYPTO_gcm128_new(void *key, block128_f block){	}
void CRYPTO_gcm128_init(GCM128_CONTEXT *ctx,void *key,block128_f block){	}
void CRYPTO_gcm128_setiv(GCM128_CONTEXT *ctx,  unsigned char *iv, size_t len){	}
int CRYPTO_gcm128_aad(GCM128_CONTEXT *ctx,  unsigned char *aad, size_t len){	}
int CRYPTO_gcm128_encrypt(GCM128_CONTEXT *ctx, unsigned char *in, unsigned char *out, size_t len){	}
int CRYPTO_gcm128_decrypt(GCM128_CONTEXT *ctx, unsigned char *in, unsigned char *out, size_t len){	}
int CRYPTO_gcm128_encrypt_ctr32(GCM128_CONTEXT *ctx, unsigned char *in, unsigned char *out, size_t len, ctr128_f stream){	}
int CRYPTO_gcm128_decrypt_ctr32(GCM128_CONTEXT *ctx, unsigned char *in, unsigned char *out, size_t len, ctr128_f stream){	}
int CRYPTO_gcm128_finish(GCM128_CONTEXT *ctx, unsigned char *tag, size_t len){	}
void CRYPTO_gcm128_tag(GCM128_CONTEXT *ctx, unsigned char *tag, size_t len){	}
void CRYPTO_gcm128_release(GCM128_CONTEXT *ctx){	}
void CRYPTO_ccm128_init(CCM128_CONTEXT *ctx, unsigned int M, unsigned int L, void *key,block128_f block){	}
int CRYPTO_ccm128_setiv(CCM128_CONTEXT *ctx, unsigned char *nonce, size_t nlen, size_t mlen){	}
void CRYPTO_ccm128_aad(CCM128_CONTEXT *ctx, unsigned char *aad, size_t alen){	}
int CRYPTO_ccm128_encrypt(CCM128_CONTEXT *ctx, unsigned char *inp, unsigned char *out, size_t len){	}
int CRYPTO_ccm128_decrypt(CCM128_CONTEXT *ctx, unsigned char *inp, unsigned char *out, size_t len){	}
int CRYPTO_ccm128_encrypt_ccm64(CCM128_CONTEXT *ctx, unsigned char *inp, unsigned char *out, size_t len, ccm128_f stream){	}
int CRYPTO_ccm128_decrypt_ccm64(CCM128_CONTEXT *ctx, unsigned char *inp, unsigned char *out, size_t len, ccm128_f stream){	}
size_t CRYPTO_ccm128_tag(CCM128_CONTEXT *ctx, unsigned char *tag, size_t len){	}
int CRYPTO_xts128_encrypt( XTS128_CONTEXT *ctx,  unsigned char iv[16], unsigned char *inp, unsigned char *out, size_t len, int enc){	}
PKCS7 *d2i_PKCS7_fp(FILE *fp,PKCS7 **p7){	}
int i2d_PKCS7_fp(FILE *fp,PKCS7 *p7){	}
PKCS7 *PKCS7_dup(PKCS7 *p7){	}
PKCS7 *d2i_PKCS7_bio(BIO *bp,PKCS7 **p7){	}
int i2d_PKCS7_bio(BIO *bp,PKCS7 *p7){	}
int i2d_PKCS7_bio_stream(BIO *out, PKCS7 *p7, BIO *in, int flags){	}
int PEM_write_bio_PKCS7_stream(BIO *out, PKCS7 *p7, BIO *in, int flags){	}
int PKCS7_set_type(PKCS7 *p7, int type){	}
int PKCS7_set0_type_other(PKCS7 *p7, int type, ASN1_TYPE *other){	}
int PKCS7_set_content(PKCS7 *p7, PKCS7 *p7_data){	}
int PKCS7_SIGNER_INFO_set(PKCS7_SIGNER_INFO *p7i, X509 *x509, EVP_PKEY *pkey, EVP_MD *dgst){	}
int PKCS7_SIGNER_INFO_sign(PKCS7_SIGNER_INFO *si){	}
int PKCS7_add_signer(PKCS7 *p7, PKCS7_SIGNER_INFO *p7i){	}
int PKCS7_add_certificate(PKCS7 *p7, X509 *x509){	}
int PKCS7_add_crl(PKCS7 *p7, X509_CRL *x509){	}
int PKCS7_content_new(PKCS7 *p7, int nid){	}
int PKCS7_dataVerify(X509_STORE *cert_store, X509_STORE_CTX *ctx, BIO *bio, PKCS7 *p7, PKCS7_SIGNER_INFO *si){	}
int PKCS7_signatureVerify(BIO *bio, PKCS7 *p7, PKCS7_SIGNER_INFO *si, X509 *x509){	}
BIO *PKCS7_dataInit(PKCS7 *p7, BIO *bio){	}
int PKCS7_dataFinal(PKCS7 *p7, BIO *bio){	}
BIO *PKCS7_dataDecode(PKCS7 *p7, EVP_PKEY *pkey, BIO *in_bio, X509 *pcert){	}
PKCS7_SIGNER_INFO *PKCS7_add_signature(PKCS7 *p7, X509 *x509, EVP_PKEY *pkey,  EVP_MD *dgst){	}
X509 *PKCS7_cert_from_signer_info(PKCS7 *p7, PKCS7_SIGNER_INFO *si){	}
int PKCS7_set_digest(PKCS7 *p7,  EVP_MD *md){	}
PKCS7_RECIP_INFO *PKCS7_add_recipient(PKCS7 *p7, X509 *x509){	}
void PKCS7_SIGNER_INFO_get0_algs(PKCS7_SIGNER_INFO *si, EVP_PKEY **pk, X509_ALGOR **pdig, X509_ALGOR **psig){	}
void PKCS7_RECIP_INFO_get0_alg(PKCS7_RECIP_INFO *ri, X509_ALGOR **penc){	}
int PKCS7_add_recipient_info(PKCS7 *p7, PKCS7_RECIP_INFO *ri){	}
int PKCS7_RECIP_INFO_set(PKCS7_RECIP_INFO *p7i, X509 *x509){	}
int PKCS7_set_cipher(PKCS7 *p7,  EVP_CIPHER *cipher){	}
int PKCS7_stream(unsigned char ***boundary, PKCS7 *p7){	}
PKCS7_ISSUER_AND_SERIAL *PKCS7_get_issuer_and_serial(PKCS7 *p7, int idx){	}
ASN1_OCTET_STRING *PKCS7_digest_from_attributes(STACK_OF(X509_ATTRIBUTE) *sk){	}
int PKCS7_add_signed_attribute(PKCS7_SIGNER_INFO *p7si,int nid,int type, void *data){	}
int PKCS7_add_attribute (PKCS7_SIGNER_INFO *p7si, int nid, int atrtype, void *value){	}
ASN1_TYPE *PKCS7_get_attribute(PKCS7_SIGNER_INFO *si, int nid){	}
ASN1_TYPE *PKCS7_get_signed_attribute(PKCS7_SIGNER_INFO *si, int nid){	}
int PKCS7_set_signed_attributes(PKCS7_SIGNER_INFO *p7si, STACK_OF(X509_ATTRIBUTE) *sk){	}
int PKCS7_set_attributes(PKCS7_SIGNER_INFO *p7si,STACK_OF(X509_ATTRIBUTE) *sk){	}
PKCS7 *PKCS7_sign(X509 *signcert, EVP_PKEY *pkey, STACK_OF(X509) *certs, BIO *data, int flags){	}
PKCS7_SIGNER_INFO *PKCS7_sign_add_signer(PKCS7 *p7, X509 *signcert, EVP_PKEY *pkey,  EVP_MD *md, int flags){	}
int PKCS7_final(PKCS7 *p7, BIO *data, int flags){	}
int PKCS7_verify(PKCS7 *p7, STACK_OF(X509) *certs, X509_STORE *store, BIO *indata, BIO *out, int flags){	}
PKCS7 *PKCS7_encrypt(STACK_OF(X509) *certs, BIO *in,  EVP_CIPHER *cipher, int flags){	}
int PKCS7_decrypt(PKCS7 *p7, EVP_PKEY *pkey, X509 *cert, BIO *data, int flags){	}
int PKCS7_add_attrib_smimecap(PKCS7_SIGNER_INFO *si, STACK_OF(X509_ALGOR) *cap){	}
int PKCS7_simple_smimecap(STACK_OF(X509_ALGOR) *sk, int nid, int arg){	}
int PKCS7_add_attrib_content_type(PKCS7_SIGNER_INFO *si, ASN1_OBJECT *coid){	}
int PKCS7_add0_attrib_signing_time(PKCS7_SIGNER_INFO *si, ASN1_TIME *t){	}
int PKCS7_add1_attrib_digest(PKCS7_SIGNER_INFO *si, unsigned char *md, int mdlen){	}
int SMIME_write_PKCS7(BIO *bio, PKCS7 *p7, BIO *data, int flags){	}
PKCS7 *SMIME_read_PKCS7(BIO *bio, BIO **bcont){	}
BIO *BIO_new_PKCS7(BIO *out, PKCS7 *p7){	}
void ERR_load_PKCS7_strings(void){	}
int asn1_GetSequence(ASN1_const_CTX *c, long *length){	}
void asn1_add_error( unsigned char *address,int offset){	}
PKCS12_SAFEBAG *PKCS12_x5092certbag(X509 *x509){	}
PKCS12_SAFEBAG *PKCS12_x509crl2certbag(X509_CRL *crl){	}
X509 *PKCS12_certbag2x509(PKCS12_SAFEBAG *bag){	}
X509_CRL *PKCS12_certbag2x509crl(PKCS12_SAFEBAG *bag){	}
PKCS12_SAFEBAG *PKCS12_item_pack_safebag(void *obj,  ASN1_ITEM *it, int nid1, int nid2){	}
PKCS12_SAFEBAG *PKCS12_MAKE_KEYBAG(PKCS8_PRIV_KEY_INFO *p8){	}
PKCS8_PRIV_KEY_INFO *PKCS8_decrypt(X509_SIG *p8,  char *pass, int passlen){	}
PKCS8_PRIV_KEY_INFO *PKCS12_decrypt_skey(PKCS12_SAFEBAG *bag,  char *pass, int passlen){	}
X509_SIG *PKCS8_encrypt(int pbe_nid,  EVP_CIPHER *cipher, char *pass, int passlen, unsigned char *salt, int saltlen, int iter, PKCS8_PRIV_KEY_INFO *p8){	}
PKCS12_SAFEBAG *PKCS12_MAKE_SHKEYBAG(int pbe_nid,  char *pass, int passlen, unsigned char *salt, int saltlen, int iter, PKCS8_PRIV_KEY_INFO *p8){	}
PKCS7 *PKCS12_pack_p7data(STACK_OF(PKCS12_SAFEBAG) *sk){	}
PKCS7 *PKCS12_pack_p7encdata(int pbe_nid,  char *pass, int passlen, unsigned char *salt, int saltlen, int iter, STACK_OF(PKCS12_SAFEBAG) *bags){	}
int PKCS12_pack_authsafes(PKCS12 *p12, STACK_OF(PKCS7) *safes){	}
int PKCS12_add_localkeyid(PKCS12_SAFEBAG *bag, unsigned char *name, int namelen){	}
int PKCS12_add_friendlyname_asc(PKCS12_SAFEBAG *bag,  char *name, int namelen){	}
int PKCS12_add_CSPName_asc(PKCS12_SAFEBAG *bag,  char *name, int namelen){	}
int PKCS12_add_friendlyname_uni(PKCS12_SAFEBAG *bag,  unsigned char *name, int namelen){	}
int PKCS8_add_keyusage(PKCS8_PRIV_KEY_INFO *p8, int usage){	}
ASN1_TYPE *PKCS12_get_attr_gen(STACK_OF(X509_ATTRIBUTE) *attrs, int attr_nid){	}
char *PKCS12_get_friendlyname(PKCS12_SAFEBAG *bag){	}
unsigned char *PKCS12_pbe_crypt(X509_ALGOR *algor,  char *pass, int passlen, unsigned char *in, int inlen, unsigned char **data, int *datalen, int en_de){	}
void * PKCS12_item_decrypt_d2i(X509_ALGOR *algor,  ASN1_ITEM *it, char *pass, int passlen, ASN1_OCTET_STRING *oct, int zbuf){	}
ASN1_OCTET_STRING *PKCS12_item_i2d_encrypt(X509_ALGOR *algor,  ASN1_ITEM *it, char *pass, int passlen, void *obj, int zbuf){	}
PKCS12 *PKCS12_init(int mode){	}
int PKCS12_key_gen_asc( char *pass, int passlen, unsigned char *salt, int saltlen, int id, int iter, int n, unsigned char *out,  EVP_MD *md_type){	}
int PKCS12_key_gen_uni(unsigned char *pass, int passlen, unsigned char *salt, int saltlen, int id, int iter, int n, unsigned char *out,  EVP_MD *md_type){	}
int PKCS12_PBE_keyivgen(EVP_CIPHER_CTX *ctx,  char *pass, int passlen, ASN1_TYPE *param,  EVP_CIPHER *cipher,  EVP_MD *md_type, int en_de){	}
int PKCS12_gen_mac(PKCS12 *p12,  char *pass, int passlen, unsigned char *mac, unsigned int *maclen){	}
int PKCS12_verify_mac(PKCS12 *p12,  char *pass, int passlen){	}
int PKCS12_set_mac(PKCS12 *p12,  char *pass, int passlen, unsigned char *salt, int saltlen, int iter, EVP_MD *md_type){	}
int PKCS12_setup_mac(PKCS12 *p12, int iter, unsigned char *salt, int saltlen,  EVP_MD *md_type){	}
unsigned char *OPENSSL_asc2uni( char *asc, int asclen, unsigned char **uni, int *unilen){	}
char *OPENSSL_uni2asc(unsigned char *uni, int unilen){	}
int PKCS12_parse(PKCS12 *p12,  char *pass, EVP_PKEY **pkey, X509 **cert, STACK_OF(X509) **ca){	}
PKCS12 *PKCS12_create(char *pass, char *name, EVP_PKEY *pkey, X509 *cert, STACK_OF(X509) *ca, int nid_key, int nid_cert, int iter, int mac_iter, int keytype){	}
PKCS12_SAFEBAG *PKCS12_add_cert(STACK_OF(PKCS12_SAFEBAG) **pbags, X509 *cert){	}
PKCS12_SAFEBAG *PKCS12_add_key(STACK_OF(PKCS12_SAFEBAG) **pbags, EVP_PKEY *key, int key_usage, int iter, int key_nid, char *pass){	}
int PKCS12_add_safe(STACK_OF(PKCS7) **psafes, STACK_OF(PKCS12_SAFEBAG) *bags, int safe_nid, int iter, char *pass){	}
PKCS12 *PKCS12_add_safes(STACK_OF(PKCS7) *safes, int p7_nid){	}
int i2d_PKCS12_bio(BIO *bp, PKCS12 *p12){	}
int i2d_PKCS12_fp(FILE *fp, PKCS12 *p12){	}
PKCS12 *d2i_PKCS12_bio(BIO *bp, PKCS12 **p12){	}
PKCS12 *d2i_PKCS12_fp(FILE *fp, PKCS12 **p12){	}
int PKCS12_newpass(PKCS12 *p12, char *oldpass, char *newpass){	}
void ERR_load_PKCS12_strings(void){	}
void private_CAST_set_key(CAST_KEY *key, int len,  unsigned char *data){	}
void CAST_set_key(CAST_KEY *key, int len,  unsigned char *data){	}
void CAST_ecb_encrypt( unsigned char *in, unsigned char *out,  CAST_KEY *key, int enc){	}
void CAST_encrypt(CAST_LONG *data,  CAST_KEY *key){	}
void CAST_decrypt(CAST_LONG *data,  CAST_KEY *key){	}
void CAST_cbc_encrypt( unsigned char *in, unsigned char *out, long length, CAST_KEY *ks, unsigned char *iv, int enc){	}
void CAST_cfb64_encrypt( unsigned char *in, unsigned char *out, long length,  CAST_KEY *schedule, unsigned char *ivec, int *num, int enc){	}
void CAST_ofb64_encrypt( unsigned char *in, unsigned char *out, long length,  CAST_KEY *schedule, unsigned char *ivec, int *num){	}
int RAND_set_rand_method( RAND_METHOD *meth){	}
RAND_METHOD *RAND_get_rand_method(void){	}
int RAND_set_rand_engine(ENGINE *engine){	}
RAND_METHOD *RAND_SSLeay(void){	}
void RAND_cleanup(void ){	}
int  RAND_bytes(unsigned char *buf,int num){	}
void RAND_seed( void *buf,int num){	}
void RAND_add( void *buf,int num,double entropy){	}
int  RAND_load_file( char *file,long max_bytes){	}
int  RAND_write_file( char *file){	}
char *RAND_file_name(char *file,size_t num){	}
int RAND_status(void){	}
int RAND_query_egd_bytes( char *path, unsigned char *buf, int bytes){	}
int RAND_egd( char *path){	}
int RAND_egd_bytes( char *path,int bytes){	}
int RAND_poll(void){	}
void RAND_screen(void){	}
int RAND_event(UINT, WPARAM, LPARAM){	}
void RAND_set_fips_drbg_type(int type, int flags){	}
int RAND_init_fips(void){	}
void ERR_load_RAND_strings(void){	}
CONF_VALUE *_CONF_new_section(CONF *conf,  char *section){	}
CONF_VALUE *_CONF_get_section( CONF *conf,  char *section){	}
int _CONF_add_string(CONF *conf, CONF_VALUE *section, CONF_VALUE *value){	}
char *_CONF_get_string( CONF *conf,  char *section, char *name){	}
long _CONF_get_number( CONF *conf,  char *section,  char *name){	}
int _CONF_new_data(CONF *conf){	}
void _CONF_free_data(CONF *conf){	}
ASN1_OBJECT *CMS_get0_type(CMS_ContentInfo *cms){	}
BIO *CMS_dataInit(CMS_ContentInfo *cms, BIO *icont){	}
int CMS_dataFinal(CMS_ContentInfo *cms, BIO *bio){	}
int CMS_is_detached(CMS_ContentInfo *cms){	}
int CMS_set_detached(CMS_ContentInfo *cms, int detached){	}
int CMS_stream(unsigned char ***boundary, CMS_ContentInfo *cms){	}
CMS_ContentInfo *d2i_CMS_bio(BIO *bp, CMS_ContentInfo **cms){	}
int i2d_CMS_bio(BIO *bp, CMS_ContentInfo *cms){	}
BIO *BIO_new_CMS(BIO *out, CMS_ContentInfo *cms){	}
int i2d_CMS_bio_stream(BIO *out, CMS_ContentInfo *cms, BIO *in, int flags){	}
int PEM_write_bio_CMS_stream(BIO *out, CMS_ContentInfo *cms, BIO *in, int flags){	}
CMS_ContentInfo *SMIME_read_CMS(BIO *bio, BIO **bcont){	}
int SMIME_write_CMS(BIO *bio, CMS_ContentInfo *cms, BIO *data, int flags){	}
int CMS_final(CMS_ContentInfo *cms, BIO *data, BIO *dcont, unsigned int flags){	}
CMS_ContentInfo *CMS_sign(X509 *signcert, EVP_PKEY *pkey, STACK_OF(X509) *certs, BIO *data, unsigned int flags){	}
CMS_ContentInfo *CMS_sign_receipt(CMS_SignerInfo *si, X509 *signcert, EVP_PKEY *pkey, STACK_OF(X509) *certs, unsigned int flags){	}
int CMS_data(CMS_ContentInfo *cms, BIO *out, unsigned int flags){	}
CMS_ContentInfo *CMS_data_create(BIO *in, unsigned int flags){	}
int CMS_digest_verify(CMS_ContentInfo *cms, BIO *dcont, BIO *out, unsigned int flags){	}
CMS_ContentInfo *CMS_digest_create(BIO *in,  EVP_MD *md, unsigned int flags){	}
int CMS_EncryptedData_decrypt(CMS_ContentInfo *cms, unsigned char *key, size_t keylen, BIO *dcont, BIO *out, unsigned int flags){	}
CMS_ContentInfo *CMS_EncryptedData_encrypt(BIO *in,  EVP_CIPHER *cipher, unsigned char *key, size_t keylen, unsigned int flags){	}
int CMS_EncryptedData_set1_key(CMS_ContentInfo *cms,  EVP_CIPHER *ciph, unsigned char *key, size_t keylen){	}
int CMS_verify(CMS_ContentInfo *cms, STACK_OF(X509) *certs, X509_STORE *store, BIO *dcont, BIO *out, unsigned int flags){	}
int CMS_verify_receipt(CMS_ContentInfo *rcms, CMS_ContentInfo *ocms, STACK_OF(X509) *certs, X509_STORE *store, unsigned int flags){	}
CMS_ContentInfo *CMS_encrypt(STACK_OF(X509) *certs, BIO *in, EVP_CIPHER *cipher, unsigned int flags){	}
int CMS_decrypt(CMS_ContentInfo *cms, EVP_PKEY *pkey, X509 *cert, BIO *dcont, BIO *out, unsigned int flags){	}
int CMS_decrypt_set1_pkey(CMS_ContentInfo *cms, EVP_PKEY *pk, X509 *cert){	}
int CMS_decrypt_set1_key(CMS_ContentInfo *cms, unsigned char *key, size_t keylen, unsigned char *id, size_t idlen){	}
int CMS_decrypt_set1_password(CMS_ContentInfo *cms, unsigned char *pass, ossl_ssize_t passlen){	}
int CMS_RecipientInfo_type(CMS_RecipientInfo *ri){	}
CMS_ContentInfo *CMS_EnvelopedData_create( EVP_CIPHER *cipher){	}
CMS_RecipientInfo *CMS_add1_recipient_cert(CMS_ContentInfo *cms, X509 *recip, unsigned int flags){	}
int CMS_RecipientInfo_set0_pkey(CMS_RecipientInfo *ri, EVP_PKEY *pkey){	}
int CMS_RecipientInfo_ktri_cert_cmp(CMS_RecipientInfo *ri, X509 *cert){	}
int CMS_RecipientInfo_ktri_get0_algs(CMS_RecipientInfo *ri, EVP_PKEY **pk, X509 **recip, X509_ALGOR **palg){	}
int CMS_RecipientInfo_ktri_get0_signer_id(CMS_RecipientInfo *ri, ASN1_OCTET_STRING **keyid, X509_NAME **issuer, ASN1_INTEGER **sno){	}
CMS_RecipientInfo *CMS_add0_recipient_key(CMS_ContentInfo *cms, int nid, unsigned char *key, size_t keylen, unsigned char *id, size_t idlen, ASN1_GENERALIZEDTIME *date, ASN1_OBJECT *otherTypeId, ASN1_TYPE *otherType){	}
int CMS_RecipientInfo_kekri_get0_id(CMS_RecipientInfo *ri, X509_ALGOR **palg, ASN1_OCTET_STRING **pid, ASN1_GENERALIZEDTIME **pdate, ASN1_OBJECT **potherid, ASN1_TYPE **pothertype){	}
int CMS_RecipientInfo_set0_key(CMS_RecipientInfo *ri, unsigned char *key, size_t keylen){	}
int CMS_RecipientInfo_kekri_id_cmp(CMS_RecipientInfo *ri, unsigned char *id, size_t idlen){	}
int CMS_RecipientInfo_set0_password(CMS_RecipientInfo *ri, unsigned char *pass, ossl_ssize_t passlen){	}
CMS_RecipientInfo *CMS_add0_recipient_password(CMS_ContentInfo *cms, int iter, int wrap_nid, int pbe_nid, unsigned char *pass, ossl_ssize_t passlen, EVP_CIPHER *kekciph){	}
int CMS_RecipientInfo_decrypt(CMS_ContentInfo *cms, CMS_RecipientInfo *ri){	}
int CMS_uncompress(CMS_ContentInfo *cms, BIO *dcont, BIO *out, unsigned int flags){	}
CMS_ContentInfo *CMS_compress(BIO *in, int comp_nid, unsigned int flags){	}
int CMS_set1_eContentType(CMS_ContentInfo *cms,  ASN1_OBJECT *oid){	}
ASN1_OBJECT *CMS_get0_eContentType(CMS_ContentInfo *cms){	}
CMS_CertificateChoices *CMS_add0_CertificateChoices(CMS_ContentInfo *cms){	}
int CMS_add0_cert(CMS_ContentInfo *cms, X509 *cert){	}
int CMS_add1_cert(CMS_ContentInfo *cms, X509 *cert){	}
CMS_RevocationInfoChoice *CMS_add0_RevocationInfoChoice(CMS_ContentInfo *cms){	}
int CMS_add0_crl(CMS_ContentInfo *cms, X509_CRL *crl){	}
int CMS_add1_crl(CMS_ContentInfo *cms, X509_CRL *crl){	}
int CMS_SignedData_init(CMS_ContentInfo *cms){	}
CMS_SignerInfo *CMS_add1_signer(CMS_ContentInfo *cms, X509 *signer, EVP_PKEY *pk,  EVP_MD *md, unsigned int flags){	}
void CMS_SignerInfo_set1_signer_cert(CMS_SignerInfo *si, X509 *signer){	}
int CMS_SignerInfo_get0_signer_id(CMS_SignerInfo *si, ASN1_OCTET_STRING **keyid, X509_NAME **issuer, ASN1_INTEGER **sno){	}
int CMS_SignerInfo_cert_cmp(CMS_SignerInfo *si, X509 *cert){	}
int CMS_set1_signers_certs(CMS_ContentInfo *cms, STACK_OF(X509) *certs, unsigned int flags){	}
void CMS_SignerInfo_get0_algs(CMS_SignerInfo *si, EVP_PKEY **pk, X509 **signer, X509_ALGOR **pdig, X509_ALGOR **psig){	}
int CMS_SignerInfo_sign(CMS_SignerInfo *si){	}
int CMS_SignerInfo_verify(CMS_SignerInfo *si){	}
int CMS_SignerInfo_verify_content(CMS_SignerInfo *si, BIO *chain){	}
int CMS_add_smimecap(CMS_SignerInfo *si, STACK_OF(X509_ALGOR) *algs){	}
int CMS_add_simple_smimecap(STACK_OF(X509_ALGOR) **algs, int algnid, int keysize){	}
int CMS_add_standard_smimecap(STACK_OF(X509_ALGOR) **smcap){	}
int CMS_signed_get_attr_count( CMS_SignerInfo *si){	}
int CMS_signed_get_attr_by_NID( CMS_SignerInfo *si, int nid, int lastpos){	}
int CMS_signed_get_attr_by_OBJ( CMS_SignerInfo *si, ASN1_OBJECT *obj, int lastpos){	}
X509_ATTRIBUTE *CMS_signed_get_attr( CMS_SignerInfo *si, int loc){	}
X509_ATTRIBUTE *CMS_signed_delete_attr(CMS_SignerInfo *si, int loc){	}
int CMS_signed_add1_attr(CMS_SignerInfo *si, X509_ATTRIBUTE *attr){	}
int CMS_signed_add1_attr_by_OBJ(CMS_SignerInfo *si, ASN1_OBJECT *obj, int type, void *bytes, int len){	}
int CMS_signed_add1_attr_by_NID(CMS_SignerInfo *si, int nid, int type, void *bytes, int len){	}
int CMS_signed_add1_attr_by_txt(CMS_SignerInfo *si, char *attrname, int type, void *bytes, int len){	}
void *CMS_signed_get0_data_by_OBJ(CMS_SignerInfo *si, ASN1_OBJECT *oid, int lastpos, int type){	}
int CMS_unsigned_get_attr_count( CMS_SignerInfo *si){	}
int CMS_unsigned_get_attr_by_NID( CMS_SignerInfo *si, int nid, int lastpos){	}
int CMS_unsigned_get_attr_by_OBJ( CMS_SignerInfo *si, ASN1_OBJECT *obj, int lastpos){	}
X509_ATTRIBUTE *CMS_unsigned_get_attr( CMS_SignerInfo *si, int loc){	}
X509_ATTRIBUTE *CMS_unsigned_delete_attr(CMS_SignerInfo *si, int loc){	}
int CMS_unsigned_add1_attr(CMS_SignerInfo *si, X509_ATTRIBUTE *attr){	}
int CMS_unsigned_add1_attr_by_OBJ(CMS_SignerInfo *si, ASN1_OBJECT *obj, int type, void *bytes, int len){	}
int CMS_unsigned_add1_attr_by_NID(CMS_SignerInfo *si, int nid, int type, void *bytes, int len){	}
int CMS_unsigned_add1_attr_by_txt(CMS_SignerInfo *si, char *attrname, int type, void *bytes, int len){	}
void *CMS_unsigned_get0_data_by_OBJ(CMS_SignerInfo *si, ASN1_OBJECT *oid, int lastpos, int type){	}
int CMS_get1_ReceiptRequest(CMS_SignerInfo *si, CMS_ReceiptRequest **prr){	}
CMS_ReceiptRequest *CMS_ReceiptRequest_create0(unsigned char *id, int idlen, int allorfirst, STACK_OF(GENERAL_NAMES) *receiptList, STACK_OF(GENERAL_NAMES) *receiptsTo){	}
int CMS_add1_ReceiptRequest(CMS_SignerInfo *si, CMS_ReceiptRequest *rr){	}
void CMS_ReceiptRequest_get0_values(CMS_ReceiptRequest *rr, ASN1_STRING **pcid, int *pallorfirst, STACK_OF(GENERAL_NAMES) **plist, STACK_OF(GENERAL_NAMES) **prto){	}
void ERR_load_CMS_strings(void){	}
int private_MDC2_Init(MDC2_CTX *c){	}
int MDC2_Init(MDC2_CTX *c){	}
int MDC2_Update(MDC2_CTX *c,  unsigned char *data, size_t len){	}
int MDC2_Final(unsigned char *md, MDC2_CTX *c){	}
unsigned char *MDC2( unsigned char *d, size_t n, unsigned char *md){	}
CMAC_CTX *CMAC_CTX_new(void){	}
void CMAC_CTX_cleanup(CMAC_CTX *ctx){	}
void CMAC_CTX_free(CMAC_CTX *ctx){	}
EVP_CIPHER_CTX *CMAC_CTX_get0_cipher_ctx(CMAC_CTX *ctx){	}
int CMAC_CTX_copy(CMAC_CTX *out,  CMAC_CTX *in){	}
int CMAC_Init(CMAC_CTX *ctx,  void *key, size_t keylen, EVP_CIPHER *cipher, ENGINE *impl){	}
int CMAC_Update(CMAC_CTX *ctx,  void *data, size_t dlen){	}
int CMAC_Final(CMAC_CTX *ctx, unsigned char *out, size_t *poutlen){	}
int CMAC_resume(CMAC_CTX *ctx){	}
int ASN1_item_ex_new(ASN1_VALUE **pval,  ASN1_ITEM *it){	}
void ASN1_item_ex_free(ASN1_VALUE **pval,  ASN1_ITEM *it){	}
int ASN1_template_new(ASN1_VALUE **pval,  ASN1_TEMPLATE *tt){	}
int ASN1_primitive_new(ASN1_VALUE **pval,  ASN1_ITEM *it){	}
void ASN1_template_free(ASN1_VALUE **pval,  ASN1_TEMPLATE *tt){	}
int ASN1_template_d2i(ASN1_VALUE **pval,  unsigned char **in, long len,  ASN1_TEMPLATE *tt){	}
int ASN1_item_ex_d2i(ASN1_VALUE **pval,  unsigned char **in, long len,  ASN1_ITEM *it, int tag, int aclass, char opt, ASN1_TLC *ctx){	}
int ASN1_item_ex_i2d(ASN1_VALUE **pval, unsigned char **out,  ASN1_ITEM *it, int tag, int aclass){	}
int ASN1_template_i2d(ASN1_VALUE **pval, unsigned char **out,  ASN1_TEMPLATE *tt){	}
void ASN1_primitive_free(ASN1_VALUE **pval,  ASN1_ITEM *it){	}
int asn1_ex_i2c(ASN1_VALUE **pval, unsigned char *cont, int *putype,  ASN1_ITEM *it){	}
int asn1_ex_c2i(ASN1_VALUE **pval,  unsigned char *cont, int len, int utype, char *free_cont,  ASN1_ITEM *it){	}
int asn1_get_choice_selector(ASN1_VALUE **pval,  ASN1_ITEM *it){	}
int asn1_set_choice_selector(ASN1_VALUE **pval, int value,  ASN1_ITEM *it){	}
ASN1_TEMPLATE *asn1_do_adb(ASN1_VALUE **pval,  ASN1_TEMPLATE *tt, int nullerr){	}
int asn1_do_lock(ASN1_VALUE **pval, int op,  ASN1_ITEM *it){	}
void asn1_enc_init(ASN1_VALUE **pval,  ASN1_ITEM *it){	}
void asn1_enc_free(ASN1_VALUE **pval,  ASN1_ITEM *it){	}
int asn1_enc_restore(int *len, unsigned char **out, ASN1_VALUE **pval,  ASN1_ITEM *it){	}
int asn1_enc_save(ASN1_VALUE **pval,  unsigned char *in, int inlen,  ASN1_ITEM *it){	}
TXT_DB *TXT_DB_read(BIO *in, int num){	}
long TXT_DB_write(BIO *out, TXT_DB *db){	}
int TXT_DB_create_index(TXT_DB *db,int field,int (*qual)(OPENSSL_STRING *), LHASH_HASH_FN_TYPE hash, LHASH_COMP_FN_TYPE cmp){	}
void TXT_DB_free(TXT_DB *db){	}
OPENSSL_STRING *TXT_DB_get_by_index(TXT_DB *db, int idx, OPENSSL_STRING *value){	}
int TXT_DB_insert(TXT_DB *db, OPENSSL_STRING *value){	}
char *_ossl_old_des_options(void){	}
void _ossl_old_des_ecb3_encrypt(_ossl_old_des_cblock *input,_ossl_old_des_cblock *output, _ossl_old_des_key_schedule ks1,_ossl_old_des_key_schedule ks2, _ossl_old_des_key_schedule ks3, int enc){	}
DES_LONG _ossl_old_des_cbc_cksum(_ossl_old_des_cblock *input,_ossl_old_des_cblock *output, long length,_ossl_old_des_key_schedule schedule,_ossl_old_des_cblock *ivec){	}
void _ossl_old_des_cbc_encrypt(_ossl_old_des_cblock *input,_ossl_old_des_cblock *output,long length, _ossl_old_des_key_schedule schedule,_ossl_old_des_cblock *ivec,int enc){	}
void _ossl_old_des_ncbc_encrypt(_ossl_old_des_cblock *input,_ossl_old_des_cblock *output,long length, _ossl_old_des_key_schedule schedule,_ossl_old_des_cblock *ivec,int enc){	}
void _ossl_old_des_xcbc_encrypt(_ossl_old_des_cblock *input,_ossl_old_des_cblock *output,long length, _ossl_old_des_key_schedule schedule,_ossl_old_des_cblock *ivec, _ossl_old_des_cblock *inw,_ossl_old_des_cblock *outw,int enc){	}
void _ossl_old_des_cfb_encrypt(unsigned char *in,unsigned char *out,int numbits, long length,_ossl_old_des_key_schedule schedule,_ossl_old_des_cblock *ivec,int enc){	}
void _ossl_old_des_ecb_encrypt(_ossl_old_des_cblock *input,_ossl_old_des_cblock *output, _ossl_old_des_key_schedule ks,int enc){	}
void _ossl_old_des_encrypt(DES_LONG *data,_ossl_old_des_key_schedule ks, int enc){	}
void _ossl_old_des_encrypt2(DES_LONG *data,_ossl_old_des_key_schedule ks, int enc){	}
void _ossl_old_des_encrypt3(DES_LONG *data, _ossl_old_des_key_schedule ks1, _ossl_old_des_key_schedule ks2, _ossl_old_des_key_schedule ks3){	}
void _ossl_old_des_decrypt3(DES_LONG *data, _ossl_old_des_key_schedule ks1, _ossl_old_des_key_schedule ks2, _ossl_old_des_key_schedule ks3){	}
void _ossl_old_des_ede3_cbc_encrypt(_ossl_old_des_cblock *input, _ossl_old_des_cblock *output, long length, _ossl_old_des_key_schedule ks1, _ossl_old_des_key_schedule ks2, _ossl_old_des_key_schedule ks3, _ossl_old_des_cblock *ivec, int enc){	}
void _ossl_old_des_ede3_cfb64_encrypt(unsigned char *in, unsigned char *out, long length, _ossl_old_des_key_schedule ks1, _ossl_old_des_key_schedule ks2, _ossl_old_des_key_schedule ks3, _ossl_old_des_cblock *ivec, int *num, int enc){	}
void _ossl_old_des_ede3_ofb64_encrypt(unsigned char *in, unsigned char *out, long length, _ossl_old_des_key_schedule ks1, _ossl_old_des_key_schedule ks2, _ossl_old_des_key_schedule ks3, _ossl_old_des_cblock *ivec, int *num){	}
void _ossl_old_des_xwhite_in2out(_ossl_old_des_cblock (*des_key), _ossl_old_des_cblock (*in_white), _ossl_old_des_cblock (*out_white)){	}
int _ossl_old_des_enc_read(int fd,char *buf,int len,_ossl_old_des_key_schedule sched, _ossl_old_des_cblock *iv){	}
int _ossl_old_des_enc_write(int fd,char *buf,int len,_ossl_old_des_key_schedule sched, _ossl_old_des_cblock *iv){	}
char *_ossl_old_des_fcrypt( char *buf, char *salt, char *ret){	}
char *_ossl_old_des_crypt( char *buf, char *salt){	}
char *_ossl_old_crypt( char *buf, char *salt){	}
void _ossl_old_des_ofb_encrypt(unsigned char *in,unsigned char *out, int numbits,long length,_ossl_old_des_key_schedule schedule,_ossl_old_des_cblock *ivec){	}
void _ossl_old_des_pcbc_encrypt(_ossl_old_des_cblock *input,_ossl_old_des_cblock *output,long length, _ossl_old_des_key_schedule schedule,_ossl_old_des_cblock *ivec,int enc){	}
DES_LONG _ossl_old_des_quad_cksum(_ossl_old_des_cblock *input,_ossl_old_des_cblock *output, long length,int out_count,_ossl_old_des_cblock *seed){	}
void _ossl_old_des_random_seed(_ossl_old_des_cblock key){	}
void _ossl_old_des_random_key(_ossl_old_des_cblock ret){	}
int _ossl_old_des_read_password(_ossl_old_des_cblock *key, char *prompt,int verify){	}
int _ossl_old_des_read_2passwords(_ossl_old_des_cblock *key1,_ossl_old_des_cblock *key2, char *prompt,int verify){	}
void _ossl_old_des_set_odd_parity(_ossl_old_des_cblock *key){	}
int _ossl_old_des_is_weak_key(_ossl_old_des_cblock *key){	}
int _ossl_old_des_set_key(_ossl_old_des_cblock *key,_ossl_old_des_key_schedule schedule){	}
int _ossl_old_des_key_sched(_ossl_old_des_cblock *key,_ossl_old_des_key_schedule schedule){	}
void _ossl_old_des_string_to_key(char *str,_ossl_old_des_cblock *key){	}
void _ossl_old_des_string_to_2keys(char *str,_ossl_old_des_cblock *key1,_ossl_old_des_cblock *key2){	}
void _ossl_old_des_cfb64_encrypt(unsigned char *in, unsigned char *out, long length, _ossl_old_des_key_schedule schedule, _ossl_old_des_cblock *ivec, int *num, int enc){	}
void _ossl_old_des_ofb64_encrypt(unsigned char *in, unsigned char *out, long length, _ossl_old_des_key_schedule schedule, _ossl_old_des_cblock *ivec, int *num){	}
void _ossl_096_des_random_seed(des_cblock *key){	}
int SRP_VBASE_free(SRP_VBASE *vb){	}
int SRP_VBASE_init(SRP_VBASE *vb, char * verifier_file){	}
SRP_user_pwd *SRP_VBASE_get_by_user(SRP_VBASE *vb, char *username){	}
char *SRP_create_verifier( char *user,  char *pass, char **salt, char **verifier,  char *N,  char *g){	}
int SRP_create_verifier_BN( char *user,  char *pass, BIGNUM **salt, BIGNUM **verifier, BIGNUM *N, BIGNUM *g){	}
char * SRP_check_known_gN_param(BIGNUM* g, BIGNUM* N){	}
SRP_gN *SRP_get_default_gN( char * id) {	}
BIGNUM *SRP_Calc_server_key(BIGNUM *A, BIGNUM *v, BIGNUM *u, BIGNUM *b, BIGNUM *N){	}
BIGNUM *SRP_Calc_B(BIGNUM *b, BIGNUM *N, BIGNUM *g, BIGNUM *v){	}
int SRP_Verify_A_mod_N(BIGNUM *A, BIGNUM *N){	}
BIGNUM *SRP_Calc_u(BIGNUM *A, BIGNUM *B, BIGNUM *N) {	}
BIGNUM *SRP_Calc_x(BIGNUM *s,  char *user,  char *pass){	}
BIGNUM *SRP_Calc_A(BIGNUM *a, BIGNUM *N, BIGNUM *g){	}
BIGNUM *SRP_Calc_client_key(BIGNUM *N, BIGNUM *B, BIGNUM *g, BIGNUM *x, BIGNUM *a, BIGNUM *u){	}
int SRP_Verify_B_mod_N(BIGNUM *B, BIGNUM *N){	}
ENGINE *ENGINE_get_first(void){	}
ENGINE *ENGINE_get_last(void){	}
ENGINE *ENGINE_get_next(ENGINE *e){	}
ENGINE *ENGINE_get_prev(ENGINE *e){	}
int ENGINE_add(ENGINE *e){	}
int ENGINE_remove(ENGINE *e){	}
ENGINE *ENGINE_by_id( char *id){	}
void ENGINE_load_openssl(void){	}
void ENGINE_load_dynamic(void){	}
void ENGINE_load_4758cca(void){	}
void ENGINE_load_aep(void){	}
void ENGINE_load_atalla(void){	}
void ENGINE_load_chil(void){	}
void ENGINE_load_cswift(void){	}
void ENGINE_load_nuron(void){	}
void ENGINE_load_sureware(void){	}
void ENGINE_load_ubsec(void){	}
void ENGINE_load_padlock(void){	}
void ENGINE_load_capi(void){	}
void ENGINE_load_gmp(void){	}
void ENGINE_load_gost(void){	}
void ENGINE_load_cryptodev(void){	}
void ENGINE_load_rsax(void){	}
void ENGINE_load_rdrand(void){	}
void ENGINE_load_builtin_engines(void){	}
unsigned int ENGINE_get_table_flags(void){	}
void ENGINE_set_table_flags(unsigned int flags){	}
int ENGINE_register_RSA(ENGINE *e){	}
void ENGINE_unregister_RSA(ENGINE *e){	}
void ENGINE_register_all_RSA(void){	}
int ENGINE_register_DSA(ENGINE *e){	}
void ENGINE_unregister_DSA(ENGINE *e){	}
void ENGINE_register_all_DSA(void){	}
int ENGINE_register_ECDH(ENGINE *e){	}
void ENGINE_unregister_ECDH(ENGINE *e){	}
void ENGINE_register_all_ECDH(void){	}
int ENGINE_register_ECDSA(ENGINE *e){	}
void ENGINE_unregister_ECDSA(ENGINE *e){	}
void ENGINE_register_all_ECDSA(void){	}
int ENGINE_register_DH(ENGINE *e){	}
void ENGINE_unregister_DH(ENGINE *e){	}
void ENGINE_register_all_DH(void){	}
int ENGINE_register_RAND(ENGINE *e){	}
void ENGINE_unregister_RAND(ENGINE *e){	}
void ENGINE_register_all_RAND(void){	}
int ENGINE_register_STORE(ENGINE *e){	}
void ENGINE_unregister_STORE(ENGINE *e){	}
void ENGINE_register_all_STORE(void){	}
int ENGINE_register_ciphers(ENGINE *e){	}
void ENGINE_unregister_ciphers(ENGINE *e){	}
void ENGINE_register_all_ciphers(void){	}
int ENGINE_register_digests(ENGINE *e){	}
void ENGINE_unregister_digests(ENGINE *e){	}
void ENGINE_register_all_digests(void){	}
int ENGINE_register_pkey_meths(ENGINE *e){	}
void ENGINE_unregister_pkey_meths(ENGINE *e){	}
void ENGINE_register_all_pkey_meths(void){	}
int ENGINE_register_pkey_asn1_meths(ENGINE *e){	}
void ENGINE_unregister_pkey_asn1_meths(ENGINE *e){	}
void ENGINE_register_all_pkey_asn1_meths(void){	}
int ENGINE_register_complete(ENGINE *e){	}
int ENGINE_register_all_complete(void){	}
int ENGINE_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)(void)){	}
int ENGINE_cmd_is_executable(ENGINE *e, int cmd){	}
int ENGINE_ctrl_cmd(ENGINE *e,  char *cmd_name, long i, void *p, void (*f)(void), int cmd_optional){	}
int ENGINE_ctrl_cmd_string(ENGINE *e,  char *cmd_name,  char *arg, int cmd_optional){	}
ENGINE *ENGINE_new(void){	}
int ENGINE_free(ENGINE *e){	}
int ENGINE_up_ref(ENGINE *e){	}
int ENGINE_set_id(ENGINE *e,  char *id){	}
int ENGINE_set_name(ENGINE *e,  char *name){	}
int ENGINE_set_RSA(ENGINE *e,  RSA_METHOD *rsa_meth){	}
int ENGINE_set_DSA(ENGINE *e,  DSA_METHOD *dsa_meth){	}
int ENGINE_set_ECDH(ENGINE *e,  ECDH_METHOD *ecdh_meth){	}
int ENGINE_set_ECDSA(ENGINE *e,  ECDSA_METHOD *ecdsa_meth){	}
int ENGINE_set_DH(ENGINE *e,  DH_METHOD *dh_meth){	}
int ENGINE_set_RAND(ENGINE *e,  RAND_METHOD *rand_meth){	}
int ENGINE_set_STORE(ENGINE *e,  STORE_METHOD *store_meth){	}
int ENGINE_set_destroy_function(ENGINE *e, ENGINE_GEN_INT_FUNC_PTR destroy_f){	}
int ENGINE_set_init_function(ENGINE *e, ENGINE_GEN_INT_FUNC_PTR init_f){	}
int ENGINE_set_finish_function(ENGINE *e, ENGINE_GEN_INT_FUNC_PTR finish_f){	}
int ENGINE_set_ctrl_function(ENGINE *e, ENGINE_CTRL_FUNC_PTR ctrl_f){	}
int ENGINE_set_load_privkey_function(ENGINE *e, ENGINE_LOAD_KEY_PTR loadpriv_f){	}
int ENGINE_set_load_pubkey_function(ENGINE *e, ENGINE_LOAD_KEY_PTR loadpub_f){	}
int ENGINE_set_load_ssl_client_cert_function(ENGINE *e, ENGINE_SSL_CLIENT_CERT_PTR loadssl_f){	}
int ENGINE_set_ciphers(ENGINE *e, ENGINE_CIPHERS_PTR f){	}
int ENGINE_set_digests(ENGINE *e, ENGINE_DIGESTS_PTR f){	}
int ENGINE_set_pkey_meths(ENGINE *e, ENGINE_PKEY_METHS_PTR f){	}
int ENGINE_set_pkey_asn1_meths(ENGINE *e, ENGINE_PKEY_ASN1_METHS_PTR f){	}
int ENGINE_set_flags(ENGINE *e, int flags){	}
int ENGINE_set_cmd_defns(ENGINE *e,  ENGINE_CMD_DEFN *defns){	}
int ENGINE_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func){	}
int ENGINE_set_ex_data(ENGINE *e, int idx, void *arg){	}
void *ENGINE_get_ex_data( ENGINE *e, int idx){	}
void ENGINE_cleanup(void){	}
char *ENGINE_get_id( ENGINE *e){	}
char *ENGINE_get_name( ENGINE *e){	}
RSA_METHOD *ENGINE_get_RSA( ENGINE *e){	}
DSA_METHOD *ENGINE_get_DSA( ENGINE *e){	}
ECDH_METHOD *ENGINE_get_ECDH( ENGINE *e){	}
ECDSA_METHOD *ENGINE_get_ECDSA( ENGINE *e){	}
DH_METHOD *ENGINE_get_DH( ENGINE *e){	}
RAND_METHOD *ENGINE_get_RAND( ENGINE *e){	}
STORE_METHOD *ENGINE_get_STORE( ENGINE *e){	}
ENGINE_GEN_INT_FUNC_PTR ENGINE_get_destroy_function( ENGINE *e){	}
ENGINE_GEN_INT_FUNC_PTR ENGINE_get_init_function( ENGINE *e){	}
ENGINE_GEN_INT_FUNC_PTR ENGINE_get_finish_function( ENGINE *e){	}
ENGINE_CTRL_FUNC_PTR ENGINE_get_ctrl_function( ENGINE *e){	}
ENGINE_LOAD_KEY_PTR ENGINE_get_load_privkey_function( ENGINE *e){	}
ENGINE_LOAD_KEY_PTR ENGINE_get_load_pubkey_function( ENGINE *e){	}
ENGINE_SSL_CLIENT_CERT_PTR ENGINE_get_ssl_client_cert_function( ENGINE *e){	}
ENGINE_CIPHERS_PTR ENGINE_get_ciphers( ENGINE *e){	}
ENGINE_DIGESTS_PTR ENGINE_get_digests( ENGINE *e){	}
ENGINE_PKEY_METHS_PTR ENGINE_get_pkey_meths( ENGINE *e){	}
ENGINE_PKEY_ASN1_METHS_PTR ENGINE_get_pkey_asn1_meths( ENGINE *e){	}
EVP_CIPHER *ENGINE_get_cipher(ENGINE *e, int nid){	}
EVP_MD *ENGINE_get_digest(ENGINE *e, int nid){	}
EVP_PKEY_METHOD *ENGINE_get_pkey_meth(ENGINE *e, int nid){	}
EVP_PKEY_ASN1_METHOD *ENGINE_get_pkey_asn1_meth(ENGINE *e, int nid){	}
EVP_PKEY_ASN1_METHOD *ENGINE_get_pkey_asn1_meth_str(ENGINE *e, char *str, int len){	}
EVP_PKEY_ASN1_METHOD *ENGINE_pkey_asn1_find_str(ENGINE **pe, char *str, int len){	}
ENGINE_CMD_DEFN *ENGINE_get_cmd_defns( ENGINE *e){	}
int ENGINE_get_flags( ENGINE *e){	}
int ENGINE_init(ENGINE *e){	}
int ENGINE_finish(ENGINE *e){	}
EVP_PKEY *ENGINE_load_private_key(ENGINE *e,  char *key_id, UI_METHOD *ui_method, void *callback_data){	}
EVP_PKEY *ENGINE_load_public_key(ENGINE *e,  char *key_id, UI_METHOD *ui_method, void *callback_data){	}
int ENGINE_load_ssl_client_cert(ENGINE *e, SSL *s, STACK_OF(X509_NAME) *ca_dn, X509 **pcert, EVP_PKEY **ppkey, STACK_OF(X509) **pother, UI_METHOD *ui_method, void *callback_data){	}
ENGINE *ENGINE_get_default_RSA(void){	}
ENGINE *ENGINE_get_default_DSA(void){	}
ENGINE *ENGINE_get_default_ECDH(void){	}
ENGINE *ENGINE_get_default_ECDSA(void){	}
ENGINE *ENGINE_get_default_DH(void){	}
ENGINE *ENGINE_get_default_RAND(void){	}
ENGINE *ENGINE_get_cipher_engine(int nid){	}
ENGINE *ENGINE_get_digest_engine(int nid){	}
ENGINE *ENGINE_get_pkey_meth_engine(int nid){	}
ENGINE *ENGINE_get_pkey_asn1_meth_engine(int nid){	}
int ENGINE_set_default_RSA(ENGINE *e){	}
int ENGINE_set_default_string(ENGINE *e,  char *def_list){	}
int ENGINE_set_default_DSA(ENGINE *e){	}
int ENGINE_set_default_ECDH(ENGINE *e){	}
int ENGINE_set_default_ECDSA(ENGINE *e){	}
int ENGINE_set_default_DH(ENGINE *e){	}
int ENGINE_set_default_RAND(ENGINE *e){	}
int ENGINE_set_default_ciphers(ENGINE *e){	}
int ENGINE_set_default_digests(ENGINE *e){	}
int ENGINE_set_default_pkey_meths(ENGINE *e){	}
int ENGINE_set_default_pkey_asn1_meths(ENGINE *e){	}
int ENGINE_set_default(ENGINE *e, unsigned int flags){	}
void ENGINE_add_conf_module(void){	}
void *ENGINE_get_static_state(void){	}
void ENGINE_setup_bsd_cryptodev(void){	}
void ERR_load_ENGINE_strings(void){	}
