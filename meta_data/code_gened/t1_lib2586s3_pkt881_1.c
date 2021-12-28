void t1_lib2586s3_pkt881_1(unsigned char *_tls1_process_heartbeat_bp_, unsigned char *_tls1_process_heartbeat_pl_, unsigned int _tls1_process_heartbeat_payload_, unsigned int _tls1_process_heartbeat_padding_, int _tls1_process_heartbeat_r_, SSL *_tls1_process_heartbeat_s_, unsigned char *_tls1_process_heartbeat_buffer_, int tls1_process_heartbeat_return_, int ssl3_write_bytes_return_, int do_ssl3_write_return_, int ssl3_write_pending_return_)
{
  memcpy(_tls1_process_heartbeat_bp_, _tls1_process_heartbeat_pl_, _tls1_process_heartbeat_payload_);
  _tls1_process_heartbeat_bp_ += _tls1_process_heartbeat_payload_;
  RAND_pseudo_bytes(_tls1_process_heartbeat_bp_, _tls1_process_heartbeat_padding_);
  SSL *_ssl3_write_bytes_s_;
  _ssl3_write_bytes_s_ = _tls1_process_heartbeat_s_;
  int _ssl3_write_bytes_type_;
  _ssl3_write_bytes_type_ = 24;
  const void *_ssl3_write_bytes_buf__;
  _ssl3_write_bytes_buf__ = _tls1_process_heartbeat_buffer_;
  int _ssl3_write_bytes_len_;
  _ssl3_write_bytes_len_ = (3 + _tls1_process_heartbeat_payload_) + _tls1_process_heartbeat_padding_;
  const unsigned char *_ssl3_write_bytes_buf_ = _ssl3_write_bytes_buf__;
  unsigned int _ssl3_write_bytes_tot_;
  unsigned int _ssl3_write_bytes_n_;
  unsigned int _ssl3_write_bytes_nw_;
  int _ssl3_write_bytes_i_;
  _ssl3_write_bytes_s_->rwstate = 1;
  _ssl3_write_bytes_tot_ = _ssl3_write_bytes_s_->s3->wnum;
  _ssl3_write_bytes_s_->s3->wnum = 0;
  if ((SSL_state(_ssl3_write_bytes_s_) & (0x1000 | 0x2000)) && (!_ssl3_write_bytes_s_->in_handshake))
  {
    _ssl3_write_bytes_i_ = _ssl3_write_bytes_s_->handshake_func(_ssl3_write_bytes_s_);
    if (_ssl3_write_bytes_i_ < 0)
    {
      ssl3_write_bytes_return_ = _ssl3_write_bytes_i_;
      goto ssl3_write_bytes_label_;
    }

    if (_ssl3_write_bytes_i_ == 0)
    {
      ERR_put_error(20, 158, 229, "/home/raoxue/Desktop/openssl-1.0.1f/ssl/s3_pkt.c", 596);
      ssl3_write_bytes_return_ = -1;
      goto ssl3_write_bytes_label_;
    }

  }

  _ssl3_write_bytes_n_ = _ssl3_write_bytes_len_ - _ssl3_write_bytes_tot_;
  for (;;)
  {
    if (_ssl3_write_bytes_n_ > _ssl3_write_bytes_s_->max_send_fragment)
    {
      _ssl3_write_bytes_nw_ = _ssl3_write_bytes_s_->max_send_fragment;
    }
    else
    {
      _ssl3_write_bytes_nw_ = _ssl3_write_bytes_n_;
    }

    printf("##\n");
    SSL *_do_ssl3_write_s_;
    _do_ssl3_write_s_ = _ssl3_write_bytes_s_;
    int _do_ssl3_write_type_;
    _do_ssl3_write_type_ = _ssl3_write_bytes_type_;
    const unsigned char *_do_ssl3_write_buf_;
    _do_ssl3_write_buf_ = &_ssl3_write_bytes_buf_[_ssl3_write_bytes_tot_];
    unsigned int _do_ssl3_write_len_;
    _do_ssl3_write_len_ = _ssl3_write_bytes_nw_;
    int _do_ssl3_write_create_empty_fragment_;
    _do_ssl3_write_create_empty_fragment_ = 0;
    {
      unsigned char *_do_ssl3_write_p_;
      unsigned char *_do_ssl3_write_plen_;
      int _do_ssl3_write_i_;
      int _do_ssl3_write_mac_size_;
      int _do_ssl3_write_clear_ = 0;
      int _do_ssl3_write_prefix_len_ = 0;
      int _do_ssl3_write_eivlen_;
      long _do_ssl3_write_align_ = 0;
      SSL3_RECORD *_do_ssl3_write_wr_;
      SSL3_BUFFER *_do_ssl3_write_wb_ = &_do_ssl3_write_s_->s3->wbuf;
      SSL_SESSION *_do_ssl3_write_sess_;
      if (_do_ssl3_write_wb_->buf == 0)
      {
        if (!ssl3_setup_write_buffer(_do_ssl3_write_s_))
        {
          do_ssl3_write_return_ = -1;
          goto do_ssl3_write_label_;
        }

      }

      if (_do_ssl3_write_wb_->left != 0)
      {
        printf("##\n");
        SSL *_ssl3_write_pending_s_;
        _ssl3_write_pending_s_ = _do_ssl3_write_s_;
        int _ssl3_write_pending_type_;
        _ssl3_write_pending_type_ = _do_ssl3_write_type_;
        const unsigned char *_ssl3_write_pending_buf_;
        _ssl3_write_pending_buf_ = _do_ssl3_write_buf_;
        unsigned int _ssl3_write_pending_len_;
        _ssl3_write_pending_len_ = _do_ssl3_write_len_;
        {
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

          ssl3_write_pending_label_:
          printf("##\n");

        }
        do_ssl3_write_return_ = ssl3_write_pending_return_;
        goto do_ssl3_write_label_;
      }

      if (_do_ssl3_write_s_->s3->alert_dispatch)
      {
        _do_ssl3_write_i_ = _do_ssl3_write_s_->method->ssl_dispatch_alert(_do_ssl3_write_s_);
        if (_do_ssl3_write_i_ <= 0)
        {
          do_ssl3_write_return_ = _do_ssl3_write_i_;
          goto do_ssl3_write_label_;
        }

      }

      if ((_do_ssl3_write_len_ == 0) && (!_do_ssl3_write_create_empty_fragment_))
      {
        do_ssl3_write_return_ = 0;
        goto do_ssl3_write_label_;
      }

      _do_ssl3_write_wr_ = &_do_ssl3_write_s_->s3->wrec;
      _do_ssl3_write_sess_ = _do_ssl3_write_s_->session;
      if (((_do_ssl3_write_sess_ == 0) || (_do_ssl3_write_s_->enc_write_ctx == 0)) || (EVP_MD_CTX_md(_do_ssl3_write_s_->write_hash) == 0))
      {
        _do_ssl3_write_clear_ = (_do_ssl3_write_s_->enc_write_ctx) ? (0) : (1);
        _do_ssl3_write_mac_size_ = 0;
      }
      else
      {
        _do_ssl3_write_mac_size_ = EVP_MD_size(EVP_MD_CTX_md(_do_ssl3_write_s_->write_hash));
        if (_do_ssl3_write_mac_size_ < 0)
          goto _do_ssl3_write_err_;

      }

      if (((!_do_ssl3_write_clear_) && (!_do_ssl3_write_create_empty_fragment_)) && (!_do_ssl3_write_s_->s3->empty_fragment_done))
      {
        if (_do_ssl3_write_s_->s3->need_empty_fragments && (_do_ssl3_write_type_ == 23))
        {
          _do_ssl3_write_prefix_len_ = do_ssl3_write(_do_ssl3_write_s_, _do_ssl3_write_type_, _do_ssl3_write_buf_, 0, 1);
          if (_do_ssl3_write_prefix_len_ <= 0)
            goto _do_ssl3_write_err_;

          if (_do_ssl3_write_prefix_len_ > (5 + (16 + 64)))
          {
            ERR_put_error(20, 104, 4 | 64, "/home/raoxue/Desktop/openssl-1.0.1f/ssl/s3_pkt.c", 706);
            goto _do_ssl3_write_err_;
          }

        }

        _do_ssl3_write_s_->s3->empty_fragment_done = 1;
      }

      if (_do_ssl3_write_create_empty_fragment_)
      {
        _do_ssl3_write_align_ = ((long) _do_ssl3_write_wb_->buf) + (2 * 5);
        _do_ssl3_write_align_ = (-_do_ssl3_write_align_) & (8 - 1);
        _do_ssl3_write_p_ = _do_ssl3_write_wb_->buf + _do_ssl3_write_align_;
        _do_ssl3_write_wb_->offset = _do_ssl3_write_align_;
      }
      else
        if (_do_ssl3_write_prefix_len_)
      {
        _do_ssl3_write_p_ = (_do_ssl3_write_wb_->buf + _do_ssl3_write_wb_->offset) + _do_ssl3_write_prefix_len_;
      }
      else
      {
        _do_ssl3_write_align_ = ((long) _do_ssl3_write_wb_->buf) + 5;
        _do_ssl3_write_align_ = (-_do_ssl3_write_align_) & (8 - 1);
        _do_ssl3_write_p_ = _do_ssl3_write_wb_->buf + _do_ssl3_write_align_;
        _do_ssl3_write_wb_->offset = _do_ssl3_write_align_;
      }


      *(_do_ssl3_write_p_++) = _do_ssl3_write_type_ & 0xff;
      _do_ssl3_write_wr_->type = _do_ssl3_write_type_;
      *(_do_ssl3_write_p_++) = _do_ssl3_write_s_->version >> 8;
      if (((_do_ssl3_write_s_->state == (0x111 | 0x1000)) && (!_do_ssl3_write_s_->renegotiate)) && ((((_do_ssl3_write_s_->version >> 8) == 0x03) ? (_do_ssl3_write_s_->version) : (0)) > 0x0301))
        *(_do_ssl3_write_p_++) = 0x1;
      else
        *(_do_ssl3_write_p_++) = _do_ssl3_write_s_->version & 0xff;

      _do_ssl3_write_plen_ = _do_ssl3_write_p_;
      _do_ssl3_write_p_ += 2;
      if (_do_ssl3_write_s_->enc_write_ctx && (_do_ssl3_write_s_->version >= 0x0302))
      {
        int _do_ssl3_write_mode_ = EVP_CIPHER_CTX_flags(_do_ssl3_write_s_->enc_write_ctx) & 0xF0007;
        if (_do_ssl3_write_mode_ == 0x2)
        {
          _do_ssl3_write_eivlen_ = EVP_CIPHER_CTX_iv_length(_do_ssl3_write_s_->enc_write_ctx);
          if (_do_ssl3_write_eivlen_ <= 1)
            _do_ssl3_write_eivlen_ = 0;

        }
        else
          if (_do_ssl3_write_mode_ == 0x6)
          _do_ssl3_write_eivlen_ = 8;
        else
          _do_ssl3_write_eivlen_ = 0;


      }
      else
        _do_ssl3_write_eivlen_ = 0;

      _do_ssl3_write_wr_->data = _do_ssl3_write_p_ + _do_ssl3_write_eivlen_;
      _do_ssl3_write_wr_->length = (int) _do_ssl3_write_len_;
      _do_ssl3_write_wr_->input = (unsigned char *) _do_ssl3_write_buf_;
      if (_do_ssl3_write_s_->compress != 0)
      {
        if (!ssl3_do_compress(_do_ssl3_write_s_))
        {
          ERR_put_error(20, 104, 141, "/home/raoxue/Desktop/openssl-1.0.1f/ssl/s3_pkt.c", 792);
          goto _do_ssl3_write_err_;
        }

      }
      else
      {
        memcpy(_do_ssl3_write_wr_->data, _do_ssl3_write_wr_->input, _do_ssl3_write_wr_->length);
        _do_ssl3_write_wr_->input = _do_ssl3_write_wr_->data;
      }

      if (_do_ssl3_write_mac_size_ != 0)
      {
        if (_do_ssl3_write_s_->method->ssl3_enc->mac(_do_ssl3_write_s_, &_do_ssl3_write_p_[_do_ssl3_write_wr_->length + _do_ssl3_write_eivlen_], 1) < 0)
          goto _do_ssl3_write_err_;

        _do_ssl3_write_wr_->length += _do_ssl3_write_mac_size_;
      }

      _do_ssl3_write_wr_->input = _do_ssl3_write_p_;
      _do_ssl3_write_wr_->data = _do_ssl3_write_p_;
      if (_do_ssl3_write_eivlen_)
      {
        _do_ssl3_write_wr_->length += _do_ssl3_write_eivlen_;
      }

      _do_ssl3_write_s_->method->ssl3_enc->enc(_do_ssl3_write_s_, 1);
      _do_ssl3_write_plen_[0] = (unsigned char) ((_do_ssl3_write_wr_->length >> 8) & 0xff), _do_ssl3_write_plen_[1] = (unsigned char) (_do_ssl3_write_wr_->length & 0xff), _do_ssl3_write_plen_ += 2;
      _do_ssl3_write_wr_->type = _do_ssl3_write_type_;
      _do_ssl3_write_wr_->length += 5;
      if (_do_ssl3_write_create_empty_fragment_)
      {
        do_ssl3_write_return_ = _do_ssl3_write_wr_->length;
        goto do_ssl3_write_label_;
      }

      _do_ssl3_write_wb_->left = _do_ssl3_write_prefix_len_ + _do_ssl3_write_wr_->length;
      _do_ssl3_write_s_->s3->wpend_tot = _do_ssl3_write_len_;
      _do_ssl3_write_s_->s3->wpend_buf = _do_ssl3_write_buf_;
      _do_ssl3_write_s_->s3->wpend_type = _do_ssl3_write_type_;
      _do_ssl3_write_s_->s3->wpend_ret = _do_ssl3_write_len_;
      do_ssl3_write_return_ = ssl3_write_pending(_do_ssl3_write_s_, _do_ssl3_write_type_, _do_ssl3_write_buf_, _do_ssl3_write_len_);
      goto do_ssl3_write_label_;
      _do_ssl3_write_err_:
      {
        do_ssl3_write_return_ = -1;
        goto do_ssl3_write_label_;
      }

      do_ssl3_write_label_:
      printf("##\n");

    }
    _ssl3_write_bytes_i_ = do_ssl3_write_return_;
    if (_ssl3_write_bytes_i_ <= 0)
    {
      _ssl3_write_bytes_s_->s3->wnum = _ssl3_write_bytes_tot_;
      ssl3_write_bytes_return_ = _ssl3_write_bytes_i_;
      goto ssl3_write_bytes_label_;
    }

    if ((_ssl3_write_bytes_i_ == ((int) _ssl3_write_bytes_n_)) || ((_ssl3_write_bytes_type_ == 23) && (_ssl3_write_bytes_s_->mode & 0x00000001L)))
    {
      _ssl3_write_bytes_s_->s3->empty_fragment_done = 0;
      ssl3_write_bytes_return_ = _ssl3_write_bytes_tot_ + _ssl3_write_bytes_i_;
      goto ssl3_write_bytes_label_;
    }

    _ssl3_write_bytes_n_ -= _ssl3_write_bytes_i_;
    _ssl3_write_bytes_tot_ += _ssl3_write_bytes_i_;
  }

  ssl3_write_bytes_label_:
  printf("##\n");

}

