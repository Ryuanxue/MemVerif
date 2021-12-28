void d1_both1487s3_pkt881_1(unsigned char *_dtls1_process_heartbeat_bp_, unsigned char *_dtls1_process_heartbeat_pl_, unsigned int _dtls1_process_heartbeat_payload_, unsigned int _dtls1_process_heartbeat_padding_, int _dtls1_process_heartbeat_r_, SSL *_dtls1_process_heartbeat_s_, unsigned char *_dtls1_process_heartbeat_buffer_, SSL *_do_dtls1_write_s_, int _do_dtls1_write_type_, const unsigned char *_do_dtls1_write_buf_, unsigned int _do_dtls1_write_len_, int dtls1_process_heartbeat_return_, int dtls1_write_bytes_return_, int do_dtls1_write_return_, int ssl3_write_pending_return_)
{
  memcpy(_dtls1_process_heartbeat_bp_, _dtls1_process_heartbeat_pl_, _dtls1_process_heartbeat_payload_);
  _dtls1_process_heartbeat_bp_ += _dtls1_process_heartbeat_payload_;
  RAND_pseudo_bytes(_dtls1_process_heartbeat_bp_, _dtls1_process_heartbeat_padding_);
  SSL *_dtls1_write_bytes_s_;
  _dtls1_write_bytes_s_ = _dtls1_process_heartbeat_s_;
  int _dtls1_write_bytes_type_;
  _dtls1_write_bytes_type_ = 24;
  const void *_dtls1_write_bytes_buf_;
  _dtls1_write_bytes_buf_ = _dtls1_process_heartbeat_buffer_;
  int _dtls1_write_bytes_len_;
  _dtls1_write_bytes_len_ = (3 + _dtls1_process_heartbeat_payload_) + _dtls1_process_heartbeat_padding_;
  int _dtls1_write_bytes_i_;
  (void) ((_dtls1_write_bytes_len_ <= 16384) ? (0) : ((OpenSSLDie("/home/raoxue/Desktop/openssl-1.0.1f/ssl/d1_pkt.c", 1464, "len <= SSL3_RT_MAX_PLAIN_LENGTH"), 1)));
  _dtls1_write_bytes_s_->rwstate = 1;
  SSL *_do_dtls1_write_s_;
  _do_dtls1_write_s_ = _dtls1_write_bytes_s_;
  int _do_dtls1_write_type_;
  _do_dtls1_write_type_ = _dtls1_write_bytes_type_;
  const unsigned char *_do_dtls1_write_buf_;
  _do_dtls1_write_buf_ = _dtls1_write_bytes_buf_;
  unsigned int _do_dtls1_write_len_;
  _do_dtls1_write_len_ = _dtls1_write_bytes_len_;
  int _do_dtls1_write_create_empty_fragment_;
  _do_dtls1_write_create_empty_fragment_ = 0;
  unsigned char *_do_dtls1_write_p_;
  unsigned char *_do_dtls1_write_pseq_;
  int _do_dtls1_write_i_;
  int _do_dtls1_write_mac_size_;
  int _do_dtls1_write_clear_ = 0;
  int _do_dtls1_write_prefix_len_ = 0;
  SSL3_RECORD *_do_dtls1_write_wr_;
  SSL3_BUFFER *_do_dtls1_write_wb_;
  SSL_SESSION *_do_dtls1_write_sess_;
  int _do_dtls1_write_bs_;
  if (_do_dtls1_write_s_->s3->wbuf.left != 0)
  {
    (void) ((0) ? (0) : ((OpenSSLDie("/home/raoxue/Desktop/openssl-1.0.1f/ssl/d1_pkt.c", 1484, "0"), 1)));
    do_dtls1_write_return_ = ssl3_write_pending(_do_dtls1_write_s_, _do_dtls1_write_type_, _do_dtls1_write_buf_, _do_dtls1_write_len_);
    goto do_dtls1_write_label_;
  }

  if (_do_dtls1_write_s_->s3->alert_dispatch)
  {
    _do_dtls1_write_i_ = _do_dtls1_write_s_->method->ssl_dispatch_alert(_do_dtls1_write_s_);
    if (_do_dtls1_write_i_ <= 0)
    {
      do_dtls1_write_return_ = _do_dtls1_write_i_;
      goto do_dtls1_write_label_;
    }

  }

  if ((_do_dtls1_write_len_ == 0) && (!_do_dtls1_write_create_empty_fragment_))
  {
    do_dtls1_write_return_ = 0;
    goto do_dtls1_write_label_;
  }

  _do_dtls1_write_wr_ = &_do_dtls1_write_s_->s3->wrec;
  _do_dtls1_write_wb_ = &_do_dtls1_write_s_->s3->wbuf;
  _do_dtls1_write_sess_ = _do_dtls1_write_s_->session;
  if (((_do_dtls1_write_sess_ == 0) || (_do_dtls1_write_s_->enc_write_ctx == 0)) || (EVP_MD_CTX_md(_do_dtls1_write_s_->write_hash) == 0))
    _do_dtls1_write_clear_ = 1;

  if (_do_dtls1_write_clear_)
    _do_dtls1_write_mac_size_ = 0;
  else
  {
    _do_dtls1_write_mac_size_ = EVP_MD_size(EVP_MD_CTX_md(_do_dtls1_write_s_->write_hash));
    if (_do_dtls1_write_mac_size_ < 0)
      goto _do_dtls1_write_err_;

  }

  _do_dtls1_write_p_ = _do_dtls1_write_wb_->buf + _do_dtls1_write_prefix_len_;
  *(_do_dtls1_write_p_++) = _do_dtls1_write_type_ & 0xff;
  _do_dtls1_write_wr_->type = _do_dtls1_write_type_;
  *(_do_dtls1_write_p_++) = _do_dtls1_write_s_->version >> 8;
  *(_do_dtls1_write_p_++) = _do_dtls1_write_s_->version & 0xff;
  _do_dtls1_write_pseq_ = _do_dtls1_write_p_;
  _do_dtls1_write_p_ += 10;
  if (_do_dtls1_write_s_->enc_write_ctx && ((EVP_CIPHER_flags(_do_dtls1_write_s_->enc_write_ctx->cipher) & 0xF0007) & 0x2))
    _do_dtls1_write_bs_ = EVP_CIPHER_block_size(_do_dtls1_write_s_->enc_write_ctx->cipher);
  else
    _do_dtls1_write_bs_ = 0;

  _do_dtls1_write_wr_->data = _do_dtls1_write_p_ + _do_dtls1_write_bs_;
  _do_dtls1_write_wr_->length = (int) _do_dtls1_write_len_;
  _do_dtls1_write_wr_->input = (unsigned char *) _do_dtls1_write_buf_;
  if (_do_dtls1_write_s_->compress != 0)
  {
    if (!ssl3_do_compress(_do_dtls1_write_s_))
    {
      ERR_put_error(20, 245, 141, "/home/raoxue/Desktop/openssl-1.0.1f/ssl/d1_pkt.c", 1586);
      goto _do_dtls1_write_err_;
    }

  }
  else
  {
    memcpy(_do_dtls1_write_wr_->data, _do_dtls1_write_wr_->input, _do_dtls1_write_wr_->length);
    _do_dtls1_write_wr_->input = _do_dtls1_write_wr_->data;
  }

  if (_do_dtls1_write_mac_size_ != 0)
  {
    if (_do_dtls1_write_s_->method->ssl3_enc->mac(_do_dtls1_write_s_, &_do_dtls1_write_p_[_do_dtls1_write_wr_->length + _do_dtls1_write_bs_], 1) < 0)
      goto _do_dtls1_write_err_;

    _do_dtls1_write_wr_->length += _do_dtls1_write_mac_size_;
  }

  _do_dtls1_write_wr_->input = _do_dtls1_write_p_;
  _do_dtls1_write_wr_->data = _do_dtls1_write_p_;
  if (_do_dtls1_write_bs_)
  {
    RAND_pseudo_bytes(_do_dtls1_write_p_, _do_dtls1_write_bs_);
    _do_dtls1_write_wr_->length += _do_dtls1_write_bs_;
  }

  _do_dtls1_write_s_->method->ssl3_enc->enc(_do_dtls1_write_s_, 1);
  _do_dtls1_write_pseq_[0] = (unsigned char) ((_do_dtls1_write_s_->d1->w_epoch >> 8) & 0xff), _do_dtls1_write_pseq_[1] = (unsigned char) (_do_dtls1_write_s_->d1->w_epoch & 0xff), _do_dtls1_write_pseq_ += 2;
  memcpy(_do_dtls1_write_pseq_, &_do_dtls1_write_s_->s3->write_sequence[2], 6);
  _do_dtls1_write_pseq_ += 6;
  _do_dtls1_write_pseq_[0] = (unsigned char) ((_do_dtls1_write_wr_->length >> 8) & 0xff), _do_dtls1_write_pseq_[1] = (unsigned char) (_do_dtls1_write_wr_->length & 0xff), _do_dtls1_write_pseq_ += 2;
  _do_dtls1_write_wr_->type = _do_dtls1_write_type_;
  _do_dtls1_write_wr_->length += 13;
  ssl3_record_sequence_update(&_do_dtls1_write_s_->s3->write_sequence[0]);
  if (_do_dtls1_write_create_empty_fragment_)
  {
    do_dtls1_write_return_ = _do_dtls1_write_wr_->length;
    goto do_dtls1_write_label_;
  }

  _do_dtls1_write_wb_->left = _do_dtls1_write_prefix_len_ + _do_dtls1_write_wr_->length;
  _do_dtls1_write_wb_->offset = 0;
  _do_dtls1_write_s_->s3->wpend_tot = _do_dtls1_write_len_;
  _do_dtls1_write_s_->s3->wpend_buf = _do_dtls1_write_buf_;
  _do_dtls1_write_s_->s3->wpend_type = _do_dtls1_write_type_;
  _do_dtls1_write_s_->s3->wpend_ret = _do_dtls1_write_len_;
  SSL *_ssl3_write_pending_s_;
  _ssl3_write_pending_s_ = _do_dtls1_write_s_;
  int _ssl3_write_pending_type_;
  _ssl3_write_pending_type_ = _do_dtls1_write_type_;
  const unsigned char *_ssl3_write_pending_buf_;
  _ssl3_write_pending_buf_ = _do_dtls1_write_buf_;
  unsigned int _ssl3_write_pending_len_;
  _ssl3_write_pending_len_ = _do_dtls1_write_len_;
  int _ssl3_write_pending_i_;
  SSL3_BUFFER *_ssl3_write_pending_wb_ = &_ssl3_write_pending_s_->s3->wbuf;
  if (((_ssl3_write_pending_s_->s3->wpend_tot > ((int) _ssl3_write_pending_len_)) || ((_ssl3_write_pending_s_->s3->wpend_buf != _ssl3_write_pending_buf_) && (!(_ssl3_write_pending_s_->mode & 0x00000002L)))) || (_ssl3_write_pending_s_->s3->wpend_type != _ssl3_write_pending_type_))
  {
    ERR_put_error(20, 159, 127, "/home/raoxue/Desktop/openssl-1.0.1f/ssl/s3_pkt.c", 871);
    ssl3_write_pending_return_ = -1;
    goto ssl3_write_pending_label_;
  }

  for (;;)
  {
    errno = 0;
    if (_ssl3_write_pending_s_->wbio != 0)
    {
      _ssl3_write_pending_s_->rwstate = 2;
      _ssl3_write_pending_i_ = BIO_write(_ssl3_write_pending_s_->wbio, (char *) (&_ssl3_write_pending_wb_->buf[_ssl3_write_pending_wb_->offset]), (unsigned int) _ssl3_write_pending_wb_->left);
    }
    else
    {
      ERR_put_error(20, 159, 128, "/home/raoxue/Desktop/openssl-1.0.1f/ssl/s3_pkt.c", 887);
      _ssl3_write_pending_i_ = -1;
    }

    if (_ssl3_write_pending_i_ == _ssl3_write_pending_wb_->left)
    {
      _ssl3_write_pending_wb_->left = 0;
      _ssl3_write_pending_wb_->offset += _ssl3_write_pending_i_;
      if (((_ssl3_write_pending_s_->mode & 0x00000010L) && (SSL_version(_ssl3_write_pending_s_) != 0xFEFF)) && (SSL_version(_ssl3_write_pending_s_) != 0x0100))
        ssl3_release_write_buffer(_ssl3_write_pending_s_);

      _ssl3_write_pending_s_->rwstate = 1;
      ssl3_write_pending_return_ = _ssl3_write_pending_s_->s3->wpend_ret;
      goto ssl3_write_pending_label_;
    }
    else
      if (_ssl3_write_pending_i_ <= 0)
    {
      if ((_ssl3_write_pending_s_->version == 0xFEFF) || (_ssl3_write_pending_s_->version == 0x0100))
      {
        _ssl3_write_pending_wb_->left = 0;
      }

      ssl3_write_pending_return_ = _ssl3_write_pending_i_;
      goto ssl3_write_pending_label_;
    }


    _ssl3_write_pending_wb_->offset += _ssl3_write_pending_i_;
    _ssl3_write_pending_wb_->left -= _ssl3_write_pending_i_;
  }

  do_dtls1_write_label_:
  printf("##\n");

  _do_dtls1_write_err_:
  printf("##\n");

  ssl3_write_pending_label_:
  printf("##\n");

}

