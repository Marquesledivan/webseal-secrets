#!/usr/bin/python3.6
# coding: utf-8
"""
version 1.0 Author: Ledivan B. Marques
            Email:    l.marques@iib-institut.de
"""
from base64 import b64decode, b64encode
from json import dumps, loads
from os import getenv, urandom
from pathlib import Path  # Import the Path class

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import FastAPI, Form, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from requests import get
from yaml import dump

AES_GCM_NONCE_SIZE = int(getenv("AES_GCM_NONCE_SIZE", default=12))
SESSION_KEY_LENGTH = int(getenv("SESSION_KEY_LENGTH", default=256))
URL_SEAL_SECRET = getenv("URL_SEAL_SECRET")
scope = getenv("SCOPE", default="strict")

app = FastAPI()
templates = Jinja2Templates(directory="templates")


def aes_gcm_encrypt(key, text):
    nonce = bytes([0] * AES_GCM_NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, text.encode("utf-8"), None)
    return ciphertext


def hybrid_encrypt(pub_key, text, label):
    session_key = urandom(SESSION_KEY_LENGTH // 8)
    rsa_cipher_text = pub_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=label.encode(),
        ),
    )

    rsa_cipher_length = len(rsa_cipher_text).to_bytes(2, byteorder="big")
    aes_cipher_text = aes_gcm_encrypt(session_key, text)
    result_buffer = rsa_cipher_length + rsa_cipher_text + aes_cipher_text
    return result_buffer


def get_label(scope, namespace, name):
    if scope == "cluster":
        return ""
    if scope == "namespace":
        return namespace
    return f"{namespace}/{name}"


def pem_to_pub_key(pem_content):
    pem_data = (
        pem_content.replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "")
        .replace("\n", "")
    )
    key_bytes = b64decode(pem_data)
    pub_key = serialization.load_der_public_key(key_bytes)
    return pub_key


def encrypt_value(scope, namespace, name, value):
    pub_key = pem_to_pub_key(certificate_serialization())
    label = get_label(scope, namespace, name)
    encrypted_value = hybrid_encrypt(pub_key, value, label)  # Encode label to bytes
    return b64encode(encrypted_value).decode("utf-8")


def encrypt_values(scope, namespace, name, values):
    pub_key = pem_to_pub_key(certificate_serialization())
    label = get_label(scope, namespace, name)
    encrypted_values = {}
    for key, value in values.items():
        encrypted_value = hybrid_encrypt(pub_key, value, label)
        encrypted_values[key] = encrypted_value
    encoded_encrypted_values = {
        key: b64encode(value).decode("utf-8") for key, value in encrypted_values.items()
    }
    return encoded_encrypted_values


def certificate_serialization():
    cert_pem = get(f"{URL_SEAL_SECRET}/v1/cert.pem").text
    certificate = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    public_key = certificate.public_key()
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return pem_public_key


def get_sealed_secret(scope, namespace, name, values):
    encrypted_values = encrypt_values(scope, namespace, name, values)
    annotations = {}
    if scope == "cluster":
        annotations["sealedsecrets.bitnami.com/cluster-wide"] = "true"
    elif scope == "namespace":
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


@app.get("/", response_class=HTMLResponse)
async def read_form(request: Request):
    return templates.TemplateResponse("form.html", {"request": request})


@app.post("/", response_class=HTMLResponse)
async def seal_secret(
    request: Request,
    value: str = Form(...),
    namespace: str = Form(...),
    name: str = Form(...),
):
    try:
        encrypted_value = encrypt_value(scope, namespace, name, value)
        return templates.TemplateResponse(
            "success.html",
            {"request": request, "json_output": encrypted_value},
        )
    except Exception as e:
        error_message = f"Error executing command: {e}"
        return templates.TemplateResponse(
            "error.html", {"request": request, "error_message": error_message}
        )


@app.get("/yaml", response_class=HTMLResponse)
async def show_form(request: Request, yaml: str = Form(default="")):
    return templates.TemplateResponse("yaml.html", {"request": request, "yaml": yaml})


class InvalidInputFormatError(ValueError):
    pass


@app.post("/yaml", response_class=HTMLResponse)
async def seal_yaml_secret(
    request: Request,
    value: str = Form(...),
    namespace: str = Form(...),
    name: str = Form(...),
):
    data_dict = {}
    lines = value.strip().split("\n")

    for line in lines:
        if "=" not in line:
            raise InvalidInputFormatError(
                "Invalid input format should be in the format key=value."
            )
        key, value = line.split("=")
        data_dict[key] = value

    encrypted_value = get_sealed_secret(scope, namespace, name, data_dict)
    json_dict = loads(encrypted_value)
    yaml_data = dump(json_dict, default_flow_style=False)

    return templates.TemplateResponse(
        "success.html", {"request": request, "json_output": yaml_data}
    )


@app.get("/health")
def health_check():
    return {"status": "ok"}


# Serve the logo.png file from the 'static' directory
@app.get("/logo.png")
async def get_logo():
    logo_path = Path(__file__).parent / "static" / "logo.png"
    return FileResponse(logo_path)
