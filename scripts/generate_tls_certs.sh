#!/bin/bash
# scripts/generate_tls_certs.sh
set -e

CA_CN="CloudShield CA"
VALIDITY_DAYS=365
STORE_PASSWORD="changeit"

# Create certs directory
mkdir -p certs
cd certs

# Generate CA
if [ ! -f ca.key ]; then
    echo "Generating CA certificate..."
    openssl req -new -x509 -days ${VALIDITY_DAYS} \
        -subj "/CN=${CA_CN}" \
        -keyout ca.key -out ca.crt
    echo "CA certificate generated."
else
    echo "CA certificate already exists, skipping."
fi

# Function to generate service certificate files expected by compose overlays
generate_service_cert() {
    local name=$1
    local output_name=$2
    echo "Generating certificate for $name..."
    
    # Generate private key and CSR
    openssl req -new -newkey rsa:4096 -nodes \
        -subj "/CN=${name}" \
        -keyout ${name}.key -out ${name}.csr
    
    # Sign certificate
    openssl x509 -req -days ${VALIDITY_DAYS} \
        -in ${name}.csr -CA ca.crt -CAkey ca.key \
        -set_serial 01 -out ${output_name}.crt
    
    # Create PKCS12 store
    openssl pkcs12 -export -in ${output_name}.crt \
        -inkey ${name}.key \
        -out ${output_name}.p12 -password pass:${STORE_PASSWORD}
    
    cp "${name}.key" "${output_name}.key"

    # Convert to JKS/truststore for Kafka/Zookeeper (if keytool is available)
    if command -v keytool &>/dev/null; then
        keytool -importkeystore -srckeystore ${output_name}.p12 \
            -srcstoretype pkcs12 -destkeystore ${output_name}.keystore.jks \
            -srcstorepass ${STORE_PASSWORD} -deststorepass ${STORE_PASSWORD} -noprompt 2>/dev/null || true
        keytool -import -alias CARoot -file ca.crt \
            -keystore ${output_name}.truststore.jks \
            -storepass ${STORE_PASSWORD} -noprompt 2>/dev/null || true
    fi
    
    # Clean up CSR
    rm -f ${name}.csr
    
    echo "Certificate for $name generated."
}

generate_service_cert "kafka-broker" "kafka"
generate_service_cert "zookeeper" "zookeeper"
generate_service_cert "redis-server" "redis"

cat > ssl_credentials <<EOF
${STORE_PASSWORD}
EOF

echo ""
echo "✅ TLS certificates generated in ./certs/"
echo "⚠️  Store ca.key in a secure HSM or vault"
echo ""
echo "Files generated:"
ls -la
