
#include "net.h"

#include <memory>
#include <string>
#include <list>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>


struct http2_frame_t {
  int type = 0;
  int flags = 0;
  int si = 0;
  std::string data;

  void dump() {
    printf("  type : %d\n", type);
    printf("  flags: %d\n", flags);
    printf("  si   : %d\n", si);
    printf("  dlen : %ld\n", data.size());
  }

  int parse_frame(const std::string &in) {
    if (in.size() < 9) return 0;
    const unsigned char *uchar = (unsigned char*)in.data();
    int size = uchar[0]<<16 | uchar[1]<<8 | uchar[2];
    if (in.size() < (size_t)(size+9)) return 0;
    type = uchar[3];
    flags = uchar[4];
    si = ntohl(*((unsigned long *)(&uchar[5])));
    if (size > 0) data.assign((char*)&uchar[9], size);
    return size + 9;
  }

  static const std::string encode_frame(int type, int flags, const unsigned char *data, int len, uint32_t si) {
    #pragma pack(1)
    struct {
      unsigned char l1, l2, l3;
      unsigned char type;
      unsigned char flags;
      uint32_t si = 0;
    } h;
    #pragma pack()
    
    h.l1 = (len >> 16)&0xff;
    h.l2 = (len >> 8)&0xff;
    h.l3 = len&0xff;
    h.type = type;
    h.flags = flags;
    h.si = htonl(si);

    std::string out((char *)&h, 9);
    if (len > 0) out.append((char*)data, len);
    return out;
  }
};

const static char *client_magic = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const static int client_magic_len = 24;

struct hcon_t {
  connection_t *c;
  std::string buffer;

  ~hcon_t() {
    printf("hdestruct\n");
  }

  void send_frame(int type, int flags, const unsigned char *data, int len, uint32_t si) {
    const std::string &out = http2_frame_t::encode_frame(type, flags, data, len, si);
    c->write((unsigned char *)out.data(), out.size());
  }


  enum class state_t {WAIT_PREFEACE, ESTABLISHED};
  state_t state = state_t::WAIT_PREFEACE;
  void new_data(const unsigned char *data, int size) {
    printf("new data\n");
    buffer.append((char*)data, size);
    while (buffer.size() >= 9) {
      if (state == state_t::WAIT_PREFEACE) {
        if (buffer.find(client_magic) == 0) {
          printf("received client magic\n");
          send_frame(4, 0, nullptr, 0, 0); //sending "prefeace"
          state = state_t::ESTABLISHED;
          buffer.erase(0, client_magic_len);
        } else {
          printf("unexpected garbage\n");
          c->close();
          break;
        }
        continue;
      }
      if (state == state_t::ESTABLISHED) {
        http2_frame_t frame;
        int ret = frame.parse_frame(buffer);
        if (ret == 0) {
          printf("incomplete frame, wait for further data...\n");
          break;
        }
        if (ret > 0) buffer.erase(0, ret);
        printf("got frame %d %ld\n", ret, buffer.size());
        frame.dump();


        if (frame.type == 4) { //settings
          if (frame.flags == 1) {
            printf("got settings ack\n");
            continue;
          }
          printf("sending settings ack\n");
          send_frame(4, 1, nullptr, 0, frame.si); //ack settings
        }

        if (frame.type == 8) { //window update
        }

        if (frame.type == 1) { //headers
          //const unsigned char resp[] = {0x88};
          const unsigned char resp[] = {0x88, 0x5c, 1, 0x38,    0x5f, 9, 't', 'e', 'x', 't', '/', 'h', 't', 'm', 'l'};
          send_frame(1, 4, resp, sizeof(resp), frame.si);
          send_frame(0, 1, (unsigned char*)"nazdar \n", 8, frame.si);
        }
      }
    }
  }
  void con_lost() {
    printf("lost\n");
    delete this;
  }
};

void new_http2_con(connection_t *con) {
  printf("new con\n");
  hcon_t *hc = new hcon_t();
  hc->c = con;
  con->set_read_cb(std::bind(&hcon_t::new_data, hc, std::placeholders::_1, std::placeholders::_2));
  con->set_release_cb(std::bind(&hcon_t::con_lost, hc));
}

