
#include <stdio.h>
#include <stdlib.h>
#include <uv.h>
#include <functional>
#include <thread>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include "net.h"

static SSL_CTX *ssl_ctx;

static void close_callback(uv_handle_t *handle);

static void write_complete(uv_write_t *req, int status) {
  free(req);
}

static int alpn_callback(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                   const unsigned char *in, unsigned int inlen, void *arg) {
  const unsigned char my[] = {2, 'h', '2'};
  unsigned char *out1;

  int r = SSL_select_next_proto(&out1, outlen, my, sizeof(my), in, inlen);
  if (r == OPENSSL_NPN_NO_OVERLAP) return SSL_TLSEXT_ERR_NOACK;

  *out = out1;
  return SSL_TLSEXT_ERR_OK;
}

class connection_ssl_uv_t : public connection_t {
  uv_tcp_t *c = nullptr;
  SSL *ssl = nullptr;
  BIO *rbio = nullptr;
  BIO *wbio = nullptr;

  std::function<void(const unsigned char *data, int size)> read_cb;
  std::function<void()> release_cb;

public:
  connection_ssl_uv_t(uv_tcp_t *_c) {
    c = _c;
    rbio = BIO_new(BIO_s_mem());
    wbio = BIO_new(BIO_s_mem());
    ssl = SSL_new(ssl_ctx);
    SSL_set_accept_state(ssl);
    SSL_set_bio(ssl, rbio, wbio);
    SSL_CTX_set_alpn_select_cb(ssl_ctx, alpn_callback, nullptr);
  }

  virtual ~connection_ssl_uv_t() {
    printf("destruct\n");
    SSL_free(ssl);
  };

  virtual void set_read_cb(std::function<void(const unsigned char *data, int size)> cb) {
    read_cb = cb;
  }
  virtual void set_release_cb(std::function<void()> cb) {
    release_cb = cb;
  }

  virtual void write(const unsigned char *data, int size) override {
    while (size > 0) {
      int n = SSL_write(ssl, data, size);
      if (n > 0) {
        data += n;
        size -= n;
        write_ssl_buffers();
      }
    }
  }

  void _write(const unsigned char *data, int size) {
    uv_buf_t buf;
    buf.len = size;
    buf.base = (char*)data;

    //some examples suggests req can be on stack - but this is not true
    uv_write_t *req = (uv_write_t*)malloc(sizeof(uv_write_t));
    uv_write(req, (uv_stream_t*)c, &buf, 1, write_complete);
  }

  virtual void close() {
    uv_close((uv_handle_t*)c, close_callback);
  }

  void write_ssl_buffers() {
    char buf[1024*5];
    retry:
      int n2 = BIO_read(wbio, buf, sizeof(buf));
      if (n2 > 0) {
        _write((unsigned char*)buf, n2);
        goto retry;
      }
  }

  void handshake() {
    int n = SSL_do_handshake(ssl);
    if (SSL_get_error(ssl, n) == SSL_ERROR_WANT_READ) write_ssl_buffers();
  }

  void data_in(unsigned char *data, int len) {
    while (len > 0) {
      int r = BIO_write(rbio, data, len);
      if (r <= 0) {
        printf("error - handle me?\n");
        close();
        return;
      }
      data += r;
      len -= r;
      if (!SSL_is_init_finished(ssl)) {
        handshake();
        if (!SSL_is_init_finished(ssl)) return; //not good
      }
    }
    printf("handshake done!\n");
    unsigned char buf[1024*32];
    retry:
     int n = SSL_read(ssl, buf, sizeof(buf));
     if (n > 0) {
       printf("%s\n", buf);
       if (read_cb) read_cb(buf, n);
       goto retry;
     }
     if (SSL_get_error(ssl, n) == SSL_ERROR_WANT_READ) write_ssl_buffers();
  }

  void release() {
    if (release_cb) release_cb();
  }


};

static void close_callback(uv_handle_t *handle) {
  connection_ssl_uv_t *c = (connection_ssl_uv_t*)handle->data;
  c->release(); //user release callbacks
  delete c;
  free(handle);
}

static void alloc_callback(uv_handle_t *h, size_t size, uv_buf_t *buf) {
  buf->base = (char*)malloc(size);
  buf->len = size;
}

static void receive_callback(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
  if (nread < 0) {
    uv_close((uv_handle_t*)stream, close_callback);
    if (buf) free(buf->base);
    return;
  }

  connection_ssl_uv_t *c = (connection_ssl_uv_t*)stream->data;
  c->data_in((unsigned char*)buf->base, nread);
  free(buf->base);
}


static uv_loop_t loop;

static void concb(uv_stream_t *server, int status) {
  printf("got con\n");
  uv_tcp_t *c = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
  uv_tcp_init(&loop, c);
  uv_accept(server, (uv_stream_t*)c);

  connection_t *con = new connection_ssl_uv_t(c);
  c->data = con;

  uv_read_start((uv_stream_t*)c, alloc_callback, receive_callback);

  void(*callback)(connection_t *c) = (void(*)(connection_t *c))server->data;
  callback(con);
}



static bool ssl_server(std::string bind_ip, int port, void(*callback)(connection_t *c)) {
  uv_tcp_t server;
  uv_loop_init(&loop);


  struct sockaddr_in addr;
  uv_ip4_addr(bind_ip.c_str(), port, &addr);

  uv_tcp_init(&loop, &server);
  int res = uv_tcp_bind(&server, (sockaddr*)&addr, 0);
  if (res) {
    printf("err %s\n", uv_strerror(res));
    return false;
  }
  server.data = (void*)callback;

  res = uv_listen((uv_stream_t*)&server, 10, concb);
  if (res) {
    printf("err %s\n", uv_strerror(res));
    return false;
  }

  uv_run(&loop, UV_RUN_DEFAULT);  
  return true;
}

static bool ssl_init() {
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();

  ssl_ctx = SSL_CTX_new(SSLv23_method());
  if (!ssl_ctx) {
    printf("can't get ssl ctx\n");
    return false;
  }
  if (SSL_CTX_use_certificate_file(ssl_ctx, "server.crt", SSL_FILETYPE_PEM) != 1 ) {
    ERR_print_errors_fp(stdout);
    return false;
  }
  if (SSL_CTX_use_PrivateKey_file(ssl_ctx, "server.key", SSL_FILETYPE_PEM) != 1 ) {
    ERR_print_errors_fp(stdout);
    return false;
  }
  if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
    ERR_print_errors_fp(stdout);
    return false;
  }
  printf("ok1\n");
  return true;
}

bool ssl_server_init(std::string bind_ip, int port, void(*callback)(connection_t *c)) {
  if (!ssl_init()) return false;
  std::thread([bind_ip, port, callback]{ ssl_server(bind_ip, port, callback);}).detach();
  return true;
}

