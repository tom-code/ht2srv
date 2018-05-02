
openssl genrsa -des3 -passout pass:abcd -out server.pass.key 2048
openssl rsa -passin pass:abcd -in server.pass.key -out server.key
rm -f server.pass.key

openssl req -new -key server.key -out server.csr

openssl x509 -req -sha256 -days 365 -in server.csr -signkey server.key -out server.crt
rm -f server.csr
