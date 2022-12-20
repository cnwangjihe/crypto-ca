from fastapi import FastAPI, Body, Request
from fastapi.responses import JSONResponse

from pydantic import BaseModel

from pymongo import MongoClient
from pymongo.collection import Collection

import datetime
import json
import time
import os

from typing import TypedDict, Union

from hashlib import md5
from functools import wraps
from base64 import b64decode, b64encode

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from cryptography.exceptions import InvalidSignature

from starlette.middleware.cors import CORSMiddleware

TOLERATE_TIME = 30

app = FastAPI()

if "DB_URL" in os.environ:
    db_addr = os.environ["DB_URL"]
else:
    db_addr = "mongodb://mongodb:27017/"

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"])

ca_privkey: ec.EllipticCurvePrivateKey = \
    serialization.load_pem_private_key(open("ca.pem", "rb").read(), password=None) # type: ignore

class User(TypedDict):
    uid: str
    pubkey: str
    cert_digest: str
    timestamp: int

class Signature(BaseModel):
    sig: str
    timestamp: int


class AppException(Exception):
    pass


def sign_with_ca(data):
    data["timestamp"] = int(time.time() * 1000)
    raw = json.dumps(data, sort_keys=True).encode()
    return {
        "data": data, 
        "sig": b64encode(ca_privkey.sign(raw, ec.ECDSA(hashes.SHA256()))).decode()
    }

def sign_result_with_ca(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        data = func(*args, **kwargs)
        return sign_with_ca(data)
    return wrapper


@app.exception_handler(AppException)
def app_exception_handler(request: Request, e: AppException):
    return JSONResponse(
        status_code=200,
        content=sign_with_ca({
            "result": 1,
            "msg": e.args[0]
        })
    )


def get_db():
    return MongoClient(db_addr)["crypto"]

def query_user(table: Collection[User], uid: str):
    res = table.find_one({"uid": uid}, {"_id": 0})
    if res is None:
        raise AppException("uid not exists.")
    return res

def load_ECDSA_pubkey(pubkey: str) -> ec.EllipticCurvePublicKey:
    try:
        user_pubkey = serialization.load_pem_public_key(pubkey.encode())
    except ValueError:
        raise AppException("pubkey load failed")

    if not isinstance(user_pubkey, ec.EllipticCurvePublicKey):
        raise AppException("pubkey should be ECDSA.")
    return user_pubkey

def check_expire(sig: Signature):
    if abs(time.time() - sig.timestamp / 1000) > TOLERATE_TIME:
        raise AppException("sig expired.")

def verify(user: User, msg: str, sig: Signature):
    if sig.timestamp <= user["timestamp"]:
        raise AppException("invalid timestamp.")
    full_msg = f"{sig.timestamp}||{user['uid']}||{user['pubkey']}||{msg}"
    verify_sig(user["pubkey"], full_msg, sig.sig)

def verify_sig(pubkey: str, msg: str, sig: str):
    return
    user_pubkey = load_ECDSA_pubkey(pubkey)
    try:
        user_pubkey.verify(b64decode(sig), msg.encode(), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise AppException("invalid signature.")

def update_timestamp(table: Collection[User], uid: str, timestamp: int):
    table.update_one({"uid": uid}, {"$set": {"timestamp": timestamp}})

@app.post("/user")
@sign_result_with_ca
def sign_cert(uid: str, sig: Signature, pubkey: str = Body()):
    table = get_db()["users"]

    try:
        query_user(table, uid)
    except AppException:
        pass
    else:
        raise AppException("uid already in use.")

    check_expire(sig)
    msg = f"{sig.timestamp}||{uid}||{pubkey}||POST:/user"
    verify_sig(pubkey, msg, sig.sig)

    issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"HL"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Harbin"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Cryptography Experiment"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"CA"),
    ])

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"HL"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Harbin"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Cryptography Experiment"),
        x509.NameAttribute(NameOID.COMMON_NAME, uid),
    ])

    user_pubkey = load_ECDSA_pubkey(pubkey)

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        user_pubkey
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).sign(ca_privkey, hashes.SHA256())

    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()

    table.insert_one({
        "uid": uid,
        "pubkey": pubkey,
        "cert_digest": cert.fingerprint(hashes.SHA256()).hex(),
        "pubkey_digest": md5(pubkey.encode()).hexdigest()
    })

    update_timestamp(table, uid, sig.timestamp)

    return {"result": 0, "cert": cert_pem}

@app.get("/user")
@sign_result_with_ca
def get_user(uid: Union[str, None] = None):
    table = get_db()["users"]
    if uid is not None:
        res = [query_user(table, uid)]
    else:
        res = list(table.find({}, {"_id": 0}))
    return {"result": 0, "users": res}

class SingleSignature(BaseModel):
    sig: Signature

@app.delete("/user")
@sign_result_with_ca
def revoke_cert(uid: str, sig: SingleSignature):
    check_expire(sig.sig)
    db = get_db()
    user = query_user(db["users"], uid)
    verify(user, "DELETE:/user", sig.sig)
    db["users"].delete_one({"uid": uid})
    db["revoke"].insert_one({"cert_digest": user["cert_digest"], "timestamp": int(time.time() * 1000)})
    return {"result": 0}

@app.get("/user/pubkey")
@sign_result_with_ca
def get_uid_by_pubkey(pubkey: str):
    table = get_db()["users"]
    res = list(table.find({"pubkey": pubkey}, {"uid": 1, "_id": 0}))
    return {"result": 0, "list": [d["uid"] for d in res]}

@app.get("/revoke")
@sign_result_with_ca
def get_revoke_list():
    table = get_db()["revoke"]
    revoke_list = list(table.find({}, {"_id": 0}))
    return {"result": 0, "revoke": revoke_list}

@app.get("/revoke/check")
@sign_result_with_ca
def check_revoke(digest: str):
    table = get_db()["revoke"]
    if table.find_one({"cert_digest": digest}) is not None:
        return {"result": 0, "msg": "cert revoked."}
    else:
        return {"result": 1, "msg": "cert not in revoke list."}
