#include "net.h"

#include <readline/readline.h>

bool ssl_server_init(std::string bind_ip, int port, void(*callback)(connection_t *c));
void new_http2_con(connection_t *con);


int main() {

  ssl_server_init("0.0.0.0", 443, new_http2_con);
  server("0.0.0.0", 80, new_http2_con);


  readline(">");
}
