
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <utility>
#include <vector>

struct dec_buf_t {
  unsigned char *buf;
  int size;
  int ptr = 0;

  dec_buf_t(unsigned char *data, int len) {
    buf = data;
    size = len;
  }
  uint8_t get_byte() {
    if (remain() <= 0) return 0;
    ptr++;
    return buf[ptr-1];
  }
  void skip(int n) {
    ptr += n;
  }
  int remain() {
    return size - ptr;
  }
  std::string get_str_and_skip(int n) {
    std::string out((char*)buf+ptr, n);
    ptr += n;
    return out;
  }
};

static uint32_t mask_bottom(int prefix_size) {
  return (((uint32_t)1 << (8-prefix_size)) - 1);
}
static int decode_prefixed(int pref_size, dec_buf_t &buf) {
  uint32_t n = buf.get_byte();
  n &= mask_bottom(pref_size);
  if (n < mask_bottom(pref_size)) return n;
  return -1;
}

std::pair<std::string, std::string> resolve_indexed(int n) {
  return std::make_pair("", "");
}

std::vector<std::pair<std::string, std::string>> stable = {
 {":authority", ""},
 {":method", "GET"},
 {":method", "POST"},
 {":path", "/"},
 {":path", "/index.html"},
 {":scheme", "http"},
 {":scheme", "https"},
 {":status", "200"},
 {":status", "204"},
 {":status", "206"},
 {":status", "304"},
 {":status", "400"},
 {":status", "404"},
 {":status", "500"},
 {"accept-charset", ""},
 {"accept-encoding", "gzip, deflate"},
 {"accept-language", ""},
 {"accept-ranges", ""},
 {"accept", ""},
 {"access-control-allow-origin", ""},
 {"age", ""},
 {"allow", ""},
 {"authorization", ""},
 {"cache-control", ""},
 {"content-disposition", ""},
 {"content-encoding", ""},
 {"content-language", ""},
 {"content-length", ""},
 {"content-location", ""},
 {"content-range", ""},
 {"content-type", ""},
 {"cookie", ""},
 {"date", ""},
 {"etag", ""},
 {"expect", ""},
 {"expires", ""},
 {"from", ""},
 {"host", ""},
 {"if-match", ""},
 {"if-modified-since", ""},
 {"if-none-match", ""},
 {"if-range", ""},
 {"if-unmodified-since", ""},
 {"if-last-modified", ""},
 {"link", ""},
 {"location", ""},
 {"max-forwards", ""},
 {"proxy-authenticate", ""},
 {"proxy-authorization", ""},
 {"range", ""},
 {"referer", ""},
 {"refresh", ""},
 {"retry-after", ""},
 {"server", ""},
 {"set-cookie", ""},
 {"strict-transport-security", ""},
 {"transfer-encoding", ""},
 {"user-agent", ""},
 {"vary", ""},
 {"via", ""},
 {"www-authenticate", ""},
};
void htpack_decode(unsigned char *data, int len) {

  dec_buf_t buf(data, len);

  while (buf.remain() > 0) {
    uint8_t b1 = buf.get_byte();
    printf(":%x\n", b1);
    if (b1 & 0x80) { //indexed
      buf.skip(-1);
      int idx = decode_prefixed(1, buf);
      printf("idx is %d\n", idx);
      if (idx < stable.size()) printf("%s\n", std::get<0>(stable[idx-1]).c_str());
      continue;
    }
    if ((b1 & 0xc0) == 0x40) { //lit header
      if (b1 == 0x40) { //new name
        printf("new name\n");
        int name_len = buf.get_byte() & 0x7f;
        std::string name = buf.get_str_and_skip(name_len);
        printf(" n: %s\n", name.c_str());

        int val_len = buf.get_byte() & 0x7f;
        std::string value = buf.get_str_and_skip(val_len);
        printf(" v: %s\n", value.c_str());
      } else {
        buf.skip(-1);
        int idx = decode_prefixed(2, buf);
        int val_len = buf.get_byte();
        printf("idx2 %d %d (%d)\n", idx, val_len, val_len & 0x7f);
        if (idx < stable.size()) printf("%s\n", std::get<0>(stable[idx-1]).c_str());
        buf.skip(val_len & 0x7f);
      }
    }
  }


}
