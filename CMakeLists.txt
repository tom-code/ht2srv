
cmake_minimum_required(VERSION 3.0)
project(http2_t1)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)


set (CMAKE_CXX_FLAGS "-g -std=c++14 -Wall -pedantic")
add_executable(h2srv src/main.cc src/srv_ssl.cc src/srv.cc src/http_con.cc src/hpack.cc)

target_link_libraries(h2srv uv ${OPENSSL_LIBRARIES} Threads::Threads -lreadline)
