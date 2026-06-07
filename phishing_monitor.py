import sys
sys.stdout.reconfigure(line_buffering=True)
import json
import time
import re
import requests
import unicodedata
import hashlib
import websocket
from datetime import datetime
from rapidfuzz.distance import Levenshtein

# ───────────────────────── CONFIG ─────────────────────────
N8N_WEBHOOK = "http://localhost:5678/webhook/phishing"
CERTSTREAM_URL = "ws://localhost:8888/"
DEBUG = True
SEND_THRESHOLD = 50

BRANDS = [
    "meliuz", "nubank", "bradesco", "santander", "mercadopago",
    "mercadolivre", "picpay", "bancointer", "pagbank", "c6bank",
    "itau", "ifood", "amazon", "magalu", "americanas", "caixa",
]

OFFICIAL_DOMAINS = {
    "meliuz.com.br", "meliuz.com", "nubank.com.br", "bradesco.com.br",
    "santander.com.br", "mercadopago.com.br", "mercadolivre.com.br",
    "picpay.com", "bancointer.com.br", "pagbank.com.br", "c6bank.com",
    "itau.com.br", "ifood.com.br", "amazon.com.br", "amazon.com",
    "magazineluiza.com.br", "americanas.com.br", "caixa.gov.br",
    "amazonaws.com", "googleapis.com", "microsoftonline.com",
    "cloudfront.net", "windows.net", "akamaized.net", "googleusercontent.com",
    "amazon.dev", "aws.dev", "blip.ai",
}

KEYWORDS_HIGH = {"login", "senha", "conta", "secure", "seguro", "verificar",
                 "verify", "acesso", "autenticar", "validar", "recuperar",
                 "token", "atualizar", "app", "cliente", "central"}
KEYWORDS_MED  = {"pay", "cashback", "promo", "oferta", "desconto", "gratis",
                 "free", "bonus", "premio", "ganhe", "resgate", "cupom"}
KEYWORDS_ALL  = KEYWORDS_HIGH | KEYWORDS_MED

SUSPICIOUS_TLDS = {".xyz", ".top", ".click", ".tk", ".ml", ".ga", ".cf",
                   ".gq", ".pw", ".cc", ".icu", ".cyou", ".shop", ".online"}

HOMO = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '6': 'g',
    '7': 't', '8': 'b', '9': 'g', '@': 'a', '$': 's', '!': 'i', '|': 'l',
    'а': 'a', 'е': 'e', 'о': 'o', 'с': 'c', 'р': 'p', 'х': 'x', 'у': 'y',
    'к': 'k', 'м': 'm', 'т': 't', 'в': 'b', 'н': 'h', 'і': 'i', 'ѕ': 's',
}

def basic_norm(text):
    text = text.lower()
    text = unicodedata.normalize('NFKD', text)
    return ''.join(c for c in text if not unicodedata.combining(c))

def deleet(token):
    return ''.join(HOMO.get(c, c) for c in token)

def allowed_distance(brand):
    n = len(brand)
    if n <= 4:  return 0
    if n <= 6:  return 1
    return 2

def registrable_domain(host):
    parts = host.split('.')
    if len(parts) >= 3 and parts[-2] in {"com", "gov", "org", "net", "edu"}:
        return '.'.join(parts[-3:])
    return '.'.join(parts[-2:])

def sld_label(host):
    reg = registrable_domain(host)
    return reg.split('.')[0]

def tokenize(label):
    return [t for t in re.split(r'[^a-z0-9]+', label) if t]

def match_token(token):
    raw = re.sub(r'[^a-z0-9]', '', token)
    if not raw:
        return None
    dl = deleet(raw)
    homoglyph = (raw != dl)
    for brand in BRANDS:
        tol = allowed_distance(brand)
        if dl == brand:
            return (brand, "exato", 0, homoglyph)
        if tol > 0 and abs(len(dl) - len(brand)) <= tol:
            d = Levenshtein.distance(dl, brand)
            if d <= tol:
                return (brand, "typo", d, homoglyph)
        if len(brand) >= 5:
            if dl.startswith(brand) and dl[len(brand):] in KEYWORDS_ALL:
                return (brand, "combo", 0, homoglyph)
            if dl.endswith(brand) and dl[:-len(brand)] in KEYWORDS_ALL:
                return (brand, "combo", 0, homoglyph)
    return None

def detect(host):
    for tok in tokenize(sld_label(host)):
        m = match_token(tok)
        if m:
            return (*m, "sld")
    labels = basic_norm(host).split('.')
    sld = sld_label(host)
    for lb in labels:
        if lb == sld:
            continue
        for tok in tokenize(lb):
            m = match_token(tok)
            if m:
                return (*m, "subdominio")
    return None

def score_domain(host):
    norm = basic_norm(host)
    match = detect(host)
    if not match:
        return 0, [], None, None
    brand, kind, dist, homoglyph, location = match
    score = 0
    detalhes = []
    if kind == "exato":
        base = 50 if location == "sld" else 35
        detalhes.append(f"marca '{brand}' como token {'no SLD' if location=='sld' else 'em subdominio'} +{base}")
    elif kind == "combo":
        base = 50
        detalhes.append(f"combosquatting com '{brand}' +50")
    else:
        base = 45
        detalhes.append(f"typosquatting de '{brand}' (dist={dist}) +45")
    score += base
    if homoglyph:
        score += 20
        detalhes.append("homoglifo/leet na marca +20")
    if any(k in norm for k in KEYWORDS_HIGH):
        score += 15
        detalhes.append("palavra critica (login/secure/...) +15")
    elif any(k in norm for k in KEYWORDS_MED):
        score += 8
        detalhes.append("palavra suspeita (promo/cashback/...) +8")
    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            score += 15
            detalhes.append(f"TLD suspeito {tld} +15")
            break
    return score, detalhes, brand, match

def tem_costimulacao(host, kind, homoglyph, location):
    norm = basic_norm(host)
    if homoglyph:
        return True, "homoglifo na marca"
    if kind == "combo":
        return True, "combosquatting (marca + keyword)"
    if any(k in norm for k in KEYWORDS_HIGH):
        return True, "palavra critica presente"
    if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
        return True, "TLD suspeito"
    if kind == "exato" and location == "sld":
        return True, "marca exata no SLD (impersonacao direta)"
    if location == "sld" and any(k in norm for k in KEYWORDS_MED):
        return True, "marca no SLD + palavra suspeita"
    return False, "sinal insuficiente (sem corroboracao real)"

seen = set()

def send_with_retry(payload, tries=3):
    for i in range(tries):
        try:
            if requests.post(N8N_WEBHOOK, json=payload, timeout=5).status_code == 200:
                return True
        except Exception as e:
            print(f"  tentativa {i+1} falhou: {e}")
            time.sleep(2)
    return False

def processar(message):
    if message.get("message_type") != "certificate_update":
        return
    for domain in message.get("data", {}).get("leaf_cert", {}).get("all_domains", []):
        host = domain.lower().lstrip('*.').replace("www.", "").strip()
        if registrable_domain(basic_norm(host)) in OFFICIAL_DOMAINS:
            continue
        h = hashlib.md5(host.encode()).hexdigest()
        if h in seen:
            continue
        if len(seen) > 20000:
            seen.clear()
        seen.add(h)
        score, detalhes, brand, match = score_domain(host)
        if score == 0:
            continue
        kind = match[1]
        homoglyph = match[3]
        location = match[4]
        passou, motivo = tem_costimulacao(host, kind, homoglyph, location)
        if DEBUG:
            status = "OK candidato" if passou else "X descartado"
            print(f"[DEBUG {status}] {host} | {brand} | score={score} | {motivo}")
        if passou and score >= SEND_THRESHOLD:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"\n[{ts}] ALERTA {host} | score={score}")
            ok = send_with_retry({
                "dominio": host, "score": score,
                "detalhes": detalhes, "timestamp": ts,
            })
            print(f"    n8n: {'OK' if ok else 'FALHOU'}")

def on_message(wsapp, raw):
    try:
        processar(json.loads(raw))
    except Exception as e:
        print(f"Erro ao processar mensagem: {e}")

def on_error(wsapp, error):
    print(f"Erro WebSocket: {error}")

def on_close(wsapp, code, msg):
    print("Conexao encerrada. Reconectando em 5s...")
    time.sleep(5)
    conectar()

def on_open(wsapp):
    print(f"Conectado ao CertStream: {CERTSTREAM_URL}")

def conectar():
    wsapp = websocket.WebSocketApp(
        CERTSTREAM_URL,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close,
        on_open=on_open,
    )
    wsapp.run_forever()

if __name__ == "__main__":
    print("=" * 55)
    print("  Phishing Monitor v2 — token + costimulacao SLD/subdominio")
    print("=" * 55)
    conectar()
