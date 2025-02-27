import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

# Generate a private key for the root CA
root_ca_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Generate a public key for the root CA
root_ca_public_key = root_ca_private_key.public_key()

# Save the private key to a file
with open("root_ca_private_key.pem", "wb") as f:
    f.write(root_ca_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Save the public key to a file
with open("root_ca_public_key.pem", "wb") as f:
    f.write(root_ca_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

    # Generate a private key for the user
user_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Generate a public key for the user
user_public_key = user_private_key.public_key()

# Save the private key to a file
with open("user_private_key.pem", "wb") as f:
    f.write(user_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Save the public key to a file
with open("user_public_key.pem", "wb") as f:
    f.write(user_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

# Create a CSR builder
csr_builder = x509.CertificateSigningRequestBuilder()

# Set the subject of the CSR
csr_builder = csr_builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"user")]))

# Sign the CSR with the user's private key
csr = csr_builder.sign(user_private_key, hashes.SHA256(), default_backend())

# Save the CSR to a file
with open("user_csr.pem", "wb") as f:
    f.write(csr.public_bytes(
        encoding=serialization.Encoding.PEM
    ))


from cryptography.hazmat.primitives import serialization

# Load the CA's private key
with open("root_ca_private_key.pem", "rb") as f:
    root_ca_private_key = serialization.load_pem_private_key(
        f.read(),
        password=None,
        backend=default_backend()
    )

# Load the CA's public key
with open("root_ca_public_key.pem", "rb") as f:
    root_ca_public_key = serialization.load_pem_public_key(
        f.read(),
        backend=default_backend()
    )

# Load the CSR
with open("user_csr.pem", "rb") as f:
    csr = x509.load_pem_x509_csr(f.read(), default_backend())

# Create a certificate builder
cert_builder = x509.CertificateBuilder()

# Set the subject and issuer of the certificate
cert_builder = cert_builder.subject_name(csr.subject)

# Create an x509.Name object for the issuer
issuer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"root_ca")])

# Set the issuer of the certificate
cert_builder = cert_builder.issuer_name(issuer_name)

# Set the serial number and notBefore/NotAfter dates
cert_builder = cert_builder.serial_number(x509.random_serial_number())
cert_builder = cert_builder.not_valid_before(datetime.datetime.utcnow())
cert_builder = cert_builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))

# Add the public key to the certificate
cert_builder = cert_builder.public_key(user_public_key)

# Sign the certificate with the CA's private key
cert = cert_builder.sign(root_ca_private_key, hashes.SHA256(), default_backend())

# Save the certificate to a file
with open("user_cert.pem", "wb") as f:
    f.write(cert.public_bytes(
        encoding=serialization.Encoding.PEM
    ))