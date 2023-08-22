#!/usr/bin/python3.6
# coding: utf-8
"""
version 1.0 Author: Ledivan B. Marques
            Email:    ledivan_bernardo@yahoo.com.br
"""
from base64 import b64decode, b64encode
from json import dumps
from os import getenv, urandom

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from requests import get


class Encrypt:
    AES_GCM_NONCE_SIZE = int(getenv("AES_GCM_NONCE_SIZE", default=12))
    SESSION_KEY_LENGTH = int(getenv("SESSION_KEY_LENGTH", default=256))
    URL_SEAL_SECRET = getenv("URL_SEAL_SECRET")
    scope = getenv("SCOPE", default="strict")

    def __init__(self):
        self.pub_key = self.pem_to_pub_key(self.certificate_serialization())

    def aes_gcm_encrypt(self, key, text):
        nonce = bytes([0] * self.AES_GCM_NONCE_SIZE)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, text.encode("utf-8"), None)
        return ciphertext

    def hybrid_encrypt(self, text, label):
        session_key = urandom(self.SESSION_KEY_LENGTH // 8)
        rsa_cipher_text = self.pub_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=label.encode(),
            ),
        )

        rsa_cipher_length = len(rsa_cipher_text).to_bytes(2, byteorder="big")
        aes_cipher_text = self.aes_gcm_encrypt(session_key, text)
        result_buffer = rsa_cipher_length + rsa_cipher_text + aes_cipher_text
        return result_buffer

    def get_label(self, scope, namespace, name):
        if scope == "cluster":
            return ""
        if scope == "namespace":
            return namespace
        return f"{namespace}/{name}"

    def pem_to_pub_key(self, pem_content):
        pem_data = (
            pem_content.replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace("\n", "")
        )
        key_bytes = b64decode(pem_data)
        pub_key = serialization.load_der_public_key(key_bytes)
        return pub_key

    def encrypt_value(self, namespace, name, value):
        label = self.get_label(self.scope, namespace, name)
        encrypted_value = self.hybrid_encrypt(value, label)
        return b64encode(encrypted_value).decode("utf-8")

    def encrypt_values(self, scope, namespace, name, values):
        label = self.get_label(scope, namespace, name)
        encrypted_values = {}
        for key, value in values.items():
            encrypted_value = self.hybrid_encrypt(value, label)
            encrypted_values[key] = encrypted_value
        encoded_encrypted_values = {
            key: b64encode(value).decode("utf-8")
            for key, value in encrypted_values.items()
        }
        return encoded_encrypted_values

    def certificate_serialization(self):
        cert_pem = get(f"{self.URL_SEAL_SECRET}/v1/cert.pem").text
        certificate = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
        public_key = certificate.public_key()
        pem_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        return pem_public_key

    def get_sealed_secret(self, namespace, name, values):
        print(self)
        encrypted_values = self.encrypt_values(self.scope, namespace, name, values)
        annotations = {}
        if self.scope == "cluster":
            annotations["sealedsecrets.bitnami.com/cluster-wide"] = "true"
        elif self.scope == "namespace":
            annotations["sealedsecrets.bitnami.com/namespace-wide"] = "true"
        manifest = {
            "apiVersion": "bitnami.com/v1alpha1",
            "kind": "SealedSecret",
            "metadata": {
                "annotations": annotations,
                "name": name,
                "namespace": namespace,
            },
            "spec": {
                "encryptedData": encrypted_values,
                "template": {
                    "metadata": {
                        "annotations": annotations,
                        "name": name,
                    },
                    "type": "Opaque",
                },
            },
        }
        return dumps(manifest, indent=2)
