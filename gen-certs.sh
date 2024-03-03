openssl genrsa -out ca-key.pem
openssl req -new -x509 -sha256 -subj "/CN=voip" -days 365 -key ca-key.pem -out ca.pem
openssl genrsa -out cert-key.pem
openssl req -new -sha256 -subj "/CN=voip" -key cert-key.pem -out cert.csr
openssl x509 -req -sha256 -days 365 -in cert.csr \
    -CA ca.pem -CAkey ca-key.pem -out cert.pem -extfile <(printf "subjectAltName=DNS:voip.com")
rm cert.csr
