
#include <functional>
#include <string>

class connection_t {

public:
  virtual void set_read_cb(std::function<void(const unsigned char *data, int size)> cb) = 0;
  virtual void set_release_cb(std::function<void()> cb) = 0;
  virtual void write(const unsigned char *data, int size) = 0;
  virtual void close() = 0;
  virtual ~connection_t(){};
};

bool server(std::string bind_ip, int port, void(*new_connection_callback)(connection_t *c));
