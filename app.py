from flask import Flask, request, jsonify
from flask_cors import CORS

import pandas as pd
import numpy as np
import joblib

import socket
import ssl
import re

from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)

model = joblib.load("model.pkl")
feature_names = joblib.load("features.pkl")

# HELPERS

def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url

# FEATURES

def having_ip(url):
    hostname = urlparse(url).hostname or ""

    ip_pattern = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}$"
    )

    return -1 if ip_pattern.match(hostname) else 1


def url_length(url):
    l = len(url)

    if l < 54:
        return 1
    elif l <= 75:
        return 0
    return -1


def shortening(url):
    shorteners = [
        "bit.ly",
        "tinyurl",
        "goo.gl",
        "t.co",
        "rb.gy",
        "ow.ly"
    ]

    return -1 if any(s in url for s in shorteners) else 1


def at_symbol(url):
    return -1 if "@" in url else 1


def double_slash(url):
    pos = url.rfind("//")
    return -1 if pos > 7 else 1


def prefix_suffix(url):
    domain = urlparse(url).hostname or ""
    return -1 if "-" in domain else 1


def subdomain(url):
    domain = urlparse(url).hostname or ""

    parts = domain.split(".")

    if len(parts) <= 2:
        return 1
    elif len(parts) == 3:
        return 0
    return -1


def ssl_state(url):
    try:
        hostname = urlparse(url).hostname

        ctx = ssl.create_default_context()

        with ctx.wrap_socket(
            socket.socket(),
            server_hostname=hostname
        ) as s:

            s.settimeout(3)
            s.connect((hostname, 443))

            cert = s.getpeercert()

            issuer = str(cert.get("issuer"))

            trusted = [
                "DigiCert",
                "GlobalSign",
                "Let's Encrypt",
                "Sectigo",
                "Google Trust"
            ]

            return 1 if any(x in issuer for x in trusted) else 0

    except:
        return -1


def https_token(url):
    domain = urlparse(url).hostname or ""

    if "https" in domain.replace(".", ""):
        return -1

    return 1


def dns_record(url):
    try:
        hostname = urlparse(url).hostname
        socket.gethostbyname(hostname)
        return 1
    except:
        return -1


def request_url(url):
    suspicious_words = [
        "login",
        "verify",
        "update",
        "secure",
        "banking",
        "confirm",
        "password",
        "account"
    ]

    url_lower = url.lower()

    score = 1

    for word in suspicious_words:
        if word in url_lower:
            score -= 1

    if score <= -2:
        return -1

    if score == 0:
        return 0

    return 1


def domain_age(url):
    domain = urlparse(url).hostname or ""

    trusted = [
        "google.com",
        "facebook.com",
        "instagram.com",
        "github.com",
        "microsoft.com"
    ]

    if any(t in domain for t in trusted):
        return 1

    return 0


def abnormal_url(url):
    parsed = urlparse(url)

    domain = parsed.hostname or ""

    return 1 if domain in url else -1

# EXTRACT

def extract_features(url):

    url = normalize_url(url)

    features = {
        "having_ip_address": having_ip(url),
        "url_length": url_length(url),
        "shortining_service": shortening(url),
        "having_at_symbol": at_symbol(url),
        "double_slash_redirecting": double_slash(url),
        "prefix_suffix": prefix_suffix(url),
        "having_sub_domain": subdomain(url),
        "sslfinal_state": ssl_state(url),
        "domain_registration_length": domain_age(url),
        "favicon": 1,
        "port": 1,
        "https_token": https_token(url),
        "request_url": request_url(url),
        "url_of_anchor": 0,
        "links_in_tags": 0,
        "sfh": 0,
        "submitting_to_email": 1,
        "abnormal_url": abnormal_url(url),
        "redirect": 0,
        "on_mouseover": 1,
        "rightclick": 1,
        "popupwindow": 1,
        "iframe": 1,
        "age_of_domain": domain_age(url),
        "dnsrecord": dns_record(url),
        "web_traffic": 0,
        "page_rank": 0,
        "google_index": 0,
        "links_pointing_to_page": 0,
        "statistical_report": 0,
    }

    return features

# RISK OVERRIDE

def hard_rule_check(url, features):

    hostname = urlparse(url).hostname or ""

    red_flags = 0

    if features["having_ip_address"] == -1:
        red_flags += 3

    if features["https_token"] == -1:
        red_flags += 2

    if features["prefix_suffix"] == -1:
        red_flags += 2

    if features["request_url"] == -1:
        red_flags += 2

    if features["sslfinal_state"] == -1:
        red_flags += 2

    if len(hostname.split(".")) > 3:
        red_flags += 2

    if red_flags >= 5:
        return True

    return False

# API

@app.route("/predict", methods=["POST"])
def predict():

    data = request.json

    if not data or "url" not in data:
        return jsonify({
            "error": "url required"
        }), 400

    url = normalize_url(data["url"])

    try:

        features = extract_features(url)

        X = pd.DataFrame([features])

        X = X[feature_names]

        prediction = int(model.predict(X)[0])

        proba = model.predict_proba(X)[0]

        classes = list(model.classes_)

        phishing_index = classes.index(-1)

        phishing_prob = float(proba[phishing_index] * 100)

        hard_rule = hard_rule_check(url, features)

        if hard_rule:
            prediction = -1
            phishing_prob = max(phishing_prob, 92)

        is_phishing = prediction == -1

        suspicious = [
            k for k, v in features.items()
            if v == -1
        ]

        warning = [
            k for k, v in features.items()
            if v == 0
        ]

        return jsonify({

            "url": str(url),

            "prediction":
                "PHISHING"
                if is_phishing
                else "LEGITIMATE",

            "is_phishing": bool(is_phishing),

            "confidence": float(round(phishing_prob, 2)),

            "risk_level":
                "HIGH" if phishing_prob >= 80
                else "MEDIUM" if phishing_prob >= 50
                else "LOW",

            "feature_count": {
                "safe": int(len([v for v in features.values() if v == 1])),
                "warning": int(len(warning)),
                "suspicious": int(len(suspicious))
            },

            "suspicious_features": suspicious,

            "warning_features": warning,

            "features": {
                k: int(v)
                for k, v in features.items()
            }
        })

    except Exception as e:

        return jsonify({
            "error": str(e)
        }), 500


@app.route("/")
def home():
    return jsonify({
        "message": "Advanced Phishing Detector API"
    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
