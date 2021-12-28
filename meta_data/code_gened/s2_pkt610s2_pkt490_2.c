void s2_pkt610s2_pkt490_2(int _ssl2_write_i_, SSL *_ssl2_write_s_, const unsigned char *_ssl2_write_buf_, unsigned int _ssl2_write_tot_, unsigned int _ssl2_write_n_, int ssl2_write_return_, int n_do_ssl_write_return_, int write_pending_return_)
{
  for (;;)
  {
    printf("##\n");
    SSL *_n_do_ssl_write_s_;
    _n_do_ssl_write_s_ = _ssl2_write_s_;
    const unsigned char *_n_do_ssl_write_buf_;
    _n_do_ssl_write_buf_ = &_ssl2_write_buf_[_ssl2_write_tot_];
    unsigned int _n_do_ssl_write_len_;
    _n_do_ssl_write_len_ = _ssl2_write_n_;
    {
      unsigned int _n_do_ssl_write_j_;
      unsigned int _n_do_ssl_write_k_;
      unsigned int _n_do_ssl_write_olen_;
      unsigned int _n_do_ssl_write_p_;
      unsigned int _n_do_ssl_write_bs_;
      int _n_do_ssl_write_mac_size_;
      register unsigned char *_n_do_ssl_write_pp_;
      _n_do_ssl_write_olen_ = _n_do_ssl_write_len_;
      if (_n_do_ssl_write_s_->s2->wpend_len != 0)
      {
        printf("##\n");
        SSL *_write_pending_s_;
        _write_pending_s_ = _n_do_ssl_write_s_;
        const unsigned char *_write_pending_buf_;
        _write_pending_buf_ = _n_do_ssl_write_buf_;
        unsigned int _write_pending_len_;
        _write_pending_len_ = _n_do_ssl_write_len_;
        {
          int _write_pending_i_;
          if ((_write_pending_s_->s2->wpend_tot > ((int) _write_pending_len_)) || ((_write_pending_s_->s2->wpend_buf != _write_pending_buf_) && (!(_write_pending_s_->mode & 0x00000002L))))
          {
            ERR_put_error(20, 212, 127, "/home/raoxue/Desktop/openssl-1.0.1f/ssl/s2_pkt.c", 480);
            write_pending_return_ = -1;
            goto write_pending_label_;
          }

          for (;;)
          {
            errno = 0;
            if (_write_pending_s_->wbio != 0)
            {
              _write_pending_s_->rwstate = 2;
              _write_pending_i_ = BIO_write(_write_pending_s_->wbio, (char *) (&_write_pending_s_->s2->write_ptr[_write_pending_s_->s2->wpend_off]), (unsigned int) _write_pending_s_->s2->wpend_len);
            }
            else
            {
              ERR_put_error(20, 212, 260, "/home/raoxue/Desktop/openssl-1.0.1f/ssl/s2_pkt.c", 496);
              _write_pending_i_ = -1;
            }

            if (_write_pending_i_ == _write_pending_s_->s2->wpend_len)
            {
              _write_pending_s_->s2->wpend_len = 0;
              _write_pending_s_->rwstate = 1;
              write_pending_return_ = _write_pending_s_->s2->wpend_ret;
              goto write_pending_label_;
            }
            else
              if (_write_pending_i_ <= 0)
            {
              write_pending_return_ = _write_pending_i_;
              goto write_pending_label_;
            }


            _write_pending_s_->s2->wpend_off += _write_pending_i_;
            _write_pending_s_->s2->wpend_len -= _write_pending_i_;
          }

          write_pending_label_:
          printf("##\n");

        }
        n_do_ssl_write_return_ = write_pending_return_;
        goto n_do_ssl_write_label_;
      }

      if (_n_do_ssl_write_s_->s2->clear_text)
      {
        _n_do_ssl_write_mac_size_ = 0;
      }
      else
      {
        _n_do_ssl_write_mac_size_ = EVP_MD_size(EVP_MD_CTX_md(_n_do_ssl_write_s_->write_hash));
        if (_n_do_ssl_write_mac_size_ < 0)
        {
          n_do_ssl_write_return_ = -1;
          goto n_do_ssl_write_label_;
        }

      }

      if (_n_do_ssl_write_s_->s2->clear_text)
      {
        if (_n_do_ssl_write_len_ > 32767u)
        {
          _n_do_ssl_write_len_ = 32767u;
        }

        _n_do_ssl_write_p_ = 0;
        _n_do_ssl_write_s_->s2->three_byte_header = 0;
      }
      else
      {
        _n_do_ssl_write_bs_ = EVP_CIPHER_CTX_block_size(_n_do_ssl_write_s_->enc_read_ctx);
        _n_do_ssl_write_j_ = _n_do_ssl_write_len_ + _n_do_ssl_write_mac_size_;
        if ((_n_do_ssl_write_j_ > 16383) && (!_n_do_ssl_write_s_->s2->escape))
        {
          if (_n_do_ssl_write_j_ > 32767u)
          {
            _n_do_ssl_write_j_ = 32767u;
          }

          _n_do_ssl_write_k_ = _n_do_ssl_write_j_ - (_n_do_ssl_write_j_ % _n_do_ssl_write_bs_);
          _n_do_ssl_write_len_ = _n_do_ssl_write_k_ - _n_do_ssl_write_mac_size_;
          _n_do_ssl_write_s_->s2->three_byte_header = 0;
          _n_do_ssl_write_p_ = 0;
        }
        else
        {
          if ((_n_do_ssl_write_bs_ <= 1) && (!_n_do_ssl_write_s_->s2->escape))
          {
            _n_do_ssl_write_s_->s2->three_byte_header = 0;
            _n_do_ssl_write_p_ = 0;
          }
          else
          {
            _n_do_ssl_write_p_ = _n_do_ssl_write_j_ % _n_do_ssl_write_bs_;
            _n_do_ssl_write_p_ = (_n_do_ssl_write_p_ == 0) ? (0) : (_n_do_ssl_write_bs_ - _n_do_ssl_write_p_);
            if (_n_do_ssl_write_s_->s2->escape)
            {
              _n_do_ssl_write_s_->s2->three_byte_header = 1;
              if (_n_do_ssl_write_j_ > 16383)
              {
                _n_do_ssl_write_j_ = 16383;
              }

            }
            else
            {
              _n_do_ssl_write_s_->s2->three_byte_header = (_n_do_ssl_write_p_ == 0) ? (0) : (1);
            }

          }

        }

      }

      _n_do_ssl_write_s_->s2->wlength = _n_do_ssl_write_len_;
      _n_do_ssl_write_s_->s2->padding = _n_do_ssl_write_p_;
      _n_do_ssl_write_s_->s2->mac_data = &_n_do_ssl_write_s_->s2->wbuf[3];
      _n_do_ssl_write_s_->s2->wact_data = &_n_do_ssl_write_s_->s2->wbuf[3 + _n_do_ssl_write_mac_size_];
      memcpy(_n_do_ssl_write_s_->s2->wact_data, _n_do_ssl_write_buf_, _n_do_ssl_write_len_);
      if (_n_do_ssl_write_p_)
      {
        memset(&_n_do_ssl_write_s_->s2->wact_data[_n_do_ssl_write_len_], 0, _n_do_ssl_write_p_);
      }

      if (!_n_do_ssl_write_s_->s2->clear_text)
      {
        _n_do_ssl_write_s_->s2->wact_data_length = _n_do_ssl_write_len_ + _n_do_ssl_write_p_;
        ssl2_mac(_n_do_ssl_write_s_, _n_do_ssl_write_s_->s2->mac_data, 1);
        _n_do_ssl_write_s_->s2->wlength += _n_do_ssl_write_p_ + _n_do_ssl_write_mac_size_;
        ssl2_enc(_n_do_ssl_write_s_, 1);
      }

      _n_do_ssl_write_s_->s2->wpend_len = _n_do_ssl_write_s_->s2->wlength;
      if (_n_do_ssl_write_s_->s2->three_byte_header)
      {
        _n_do_ssl_write_pp_ = _n_do_ssl_write_s_->s2->mac_data;
        _n_do_ssl_write_pp_ -= 3;
        _n_do_ssl_write_pp_[0] = (_n_do_ssl_write_s_->s2->wlength >> 8) & (0x3fff >> 8);
        if (_n_do_ssl_write_s_->s2->escape)
        {
          _n_do_ssl_write_pp_[0] |= 0x40;
        }

        _n_do_ssl_write_pp_[1] = _n_do_ssl_write_s_->s2->wlength & 0xff;
        _n_do_ssl_write_pp_[2] = _n_do_ssl_write_s_->s2->padding;
        _n_do_ssl_write_s_->s2->wpend_len += 3;
      }
      else
      {
        _n_do_ssl_write_pp_ = _n_do_ssl_write_s_->s2->mac_data;
        _n_do_ssl_write_pp_ -= 2;
        _n_do_ssl_write_pp_[0] = ((_n_do_ssl_write_s_->s2->wlength >> 8) & (0x7fff >> 8)) | 0x80;
        _n_do_ssl_write_pp_[1] = _n_do_ssl_write_s_->s2->wlength & 0xff;
        _n_do_ssl_write_s_->s2->wpend_len += 2;
      }

      _n_do_ssl_write_s_->s2->write_ptr = _n_do_ssl_write_pp_;
      _n_do_ssl_write_s_->s2->write_sequence = (_n_do_ssl_write_s_->s2->write_sequence + 1) & 0xffffffffL;
      _n_do_ssl_write_s_->s2->wpend_tot = _n_do_ssl_write_olen_;
      _n_do_ssl_write_s_->s2->wpend_buf = _n_do_ssl_write_buf_;
      _n_do_ssl_write_s_->s2->wpend_ret = _n_do_ssl_write_len_;
      _n_do_ssl_write_s_->s2->wpend_off = 0;
      n_do_ssl_write_return_ = write_pending(_n_do_ssl_write_s_, _n_do_ssl_write_buf_, _n_do_ssl_write_olen_);
      goto n_do_ssl_write_label_;
      n_do_ssl_write_label_:
      printf("##\n");

    }
    _ssl2_write_i_ = n_do_ssl_write_return_;
    if (_ssl2_write_i_ <= 0)
    {
      _ssl2_write_s_->s2->wnum = _ssl2_write_tot_;
      ssl2_write_return_ = _ssl2_write_i_;
      goto ssl2_write_label_;
    }

    if ((_ssl2_write_i_ == ((int) _ssl2_write_n_)) || (_ssl2_write_s_->mode & 0x00000001L))
    {
      ssl2_write_return_ = _ssl2_write_tot_ + _ssl2_write_i_;
      goto ssl2_write_label_;
    }

    _ssl2_write_n_ -= _ssl2_write_i_;
    _ssl2_write_tot_ += _ssl2_write_i_;
  }

  ssl2_write_label_:
  printf("##\n");

}

