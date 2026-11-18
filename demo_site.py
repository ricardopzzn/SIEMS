"""Site de demonstração local que envia eventos simulados ao SIEMS."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import URLError
from urllib.request import Request, urlopen
from urllib.parse import urlparse

SIEMS_URL = "http://127.0.0.1:8000/api/logs"
PORT = 8080

CASES = {
    "normal": {"ip": "198.51.100.24", "method": "GET", "path": "/produtos", "status": 200, "user_agent": "SIEMS-Demo/1.0"},
    "login": {"ip": "198.51.100.25", "method": "POST", "path": "/login", "status": 401, "user_agent": "SIEMS-Demo/1.0"},
    "scan": {"ip": "198.51.100.66", "method": "GET", "path": "/.env", "status": 404, "user_agent": "SIEMS-Demo/1.0"},
    "sqli": {"ip": "198.51.100.77", "method": "GET", "path": "/busca?q=%27%20OR%201%3D1--", "status": 400, "user_agent": "SIEMS-Demo/1.0"},
    "xss": {"ip": "198.51.100.88", "method": "GET", "path": "/busca?q=%3Cscript%3Ealert(1)%3C/script%3E", "status": 400, "user_agent": "SIEMS-Demo/1.0"},
    "traversal": {"ip": "198.51.100.99", "method": "GET", "path": "/arquivo?nome=..%2F..%2Fetc%2Fpasswd", "status": 400, "user_agent": "SIEMS-Demo/1.0"},
}

PAGE = r'''<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Loja exemplo | SIEMS Lab</title>
<style>
:root{font-family:Inter,Segoe UI,Arial,sans-serif;color:#e8eef6;background:#0b1220}*{box-sizing:border-box}body{margin:0}.wrap{max-width:1000px;margin:auto;padding:28px 22px}header{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #26354a;padding-bottom:18px}.brand{font-size:20px;font-weight:750}.brand b{color:#42d2ae}.tag{font-size:12px;color:#9eafc2;background:#152236;padding:7px 11px;border-radius:20px}.hero{padding:55px 0 34px}.hero small{color:#42d2ae;font-weight:650;letter-spacing:.12em;text-transform:uppercase}.hero h1{font-size:38px;margin:12px 0}.hero p{color:#a5b4c6;max-width:620px;line-height:1.6}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}.card{background:#121d2e;border:1px solid #24344a;border-radius:12px;padding:19px}.card h2{font-size:16px;margin:0 0 8px}.card p{font-size:13px;line-height:1.5;color:#9aabc0;min-height:40px}button{border:0;background:#27b99a;color:#061710;font-weight:700;padding:10px 13px;border-radius:7px;cursor:pointer}button:hover{background:#43d4b3}.tools{margin-top:26px;background:#121d2e;border:1px solid #24344a;border-radius:12px;padding:20px}.tools h2{font-size:17px;margin:0 0 6px}.tools p{color:#9aabc0;font-size:13px}.buttons{display:flex;flex-wrap:wrap;gap:9px;margin-top:15px}.buttons button{background:#22344a;color:#dce8f3}.buttons button:hover{background:#2e4965}.notice{font-size:13px;color:#9aabc0;margin-top:14px;min-height:18px}.links{margin-top:23px;color:#8fa1b5;font-size:13px}.links a{color:#42d2ae;margin-right:18px}footer{margin-top:28px;font-size:12px;color:#72849a}@media(max-width:720px){.grid{grid-template-columns:1fr}.hero h1{font-size:30px}header{gap:12px;align-items:flex-start;flex-direction:column}}
</style></head><body><main class="wrap"><header><div class="brand">Loja <b>Exemplo</b></div><div class="tag">SIEMS LAB · AMBIENTE LOCAL</div></header>
<section class="hero"><small>Site de demonstração</small><h1>Uma loja para testar monitoramento</h1><p>Esta página gera eventos fictícios para o painel SIEMS. Os cenários são simulados: nenhum ataque é executado e nenhum dado real é enviado.</p></section>
<section class="grid"><article class="card"><h2>Catálogo</h2><p>Simula uma visita normal a uma página de produtos.</p><button onclick="send('normal')">Visitar produtos</button></article><article class="card"><h2>Login</h2><p>Simula uma tentativa de autenticação que retornou erro.</p><button onclick="send('login')">Simular login recusado</button></article><article class="card"><h2>Busca</h2><p>Simula uma URL com um padrão que pode indicar tentativa de SQL injection.</p><button onclick="send('sqli')">Simular SQLi</button></article></section>
<section class="tools"><h2>Cenários de segurança</h2><p>Clique para registrar um evento de teste e conferir o alerta no painel SIEMS.</p><div class="buttons"><button onclick="send('scan')">Sondagem de caminho</button><button onclick="send('xss')">Padrão XSS</button><button onclick="send('traversal')">Path traversal</button></div><div class="notice" id="notice">Aguardando ação.</div></section>
<nav class="links"><a href="http://localhost:8000" target="_blank">Abrir painel SIEMS ↗</a><a href="/health">Verificar site de demonstração</a></nav><footer>Projeto acadêmico · eventos fictícios · serviço local</footer></main>
<script>async function send(name){const n=document.querySelector('#notice');n.textContent='Enviando evento…';try{const r=await fetch('/simulate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({scenario:name})});const d=await r.json();n.textContent=r.ok?`Evento enviado ao SIEMS (ID ${d.event_id}). Confira o painel.`:`Falha: ${d.error||'erro desconhecido'}`}catch(e){n.textContent='Não foi possível conectar ao SIEMS. Verifique se os dois servidores estão ativos.'}}</script></body></html>'''


class Handler(BaseHTTPRequestHandler):
    def respond(self, body, code=200, content_type="application/json; charset=utf-8"):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if urlparse(self.path).path == "/":
            return self.respond(PAGE, content_type="text/html; charset=utf-8")
        if urlparse(self.path).path == "/health":
            return self.respond(json.dumps({"ok": True, "site": "Loja Exemplo"}))
        return self.respond(json.dumps({"error": "rota não encontrada"}), 404)

    def do_POST(self):
        if urlparse(self.path).path != "/simulate":
            return self.respond(json.dumps({"error": "rota não encontrada"}), 404)
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 2000:
                return self.respond(json.dumps({"error": "requisição grande demais"}), 413)
            data = json.loads(self.rfile.read(length))
            event = CASES.get(data.get("scenario"))
            if event is None:
                return self.respond(json.dumps({"error": "cenário inválido"}), 400)
            request = Request(SIEMS_URL, data=json.dumps(event).encode(), headers={"Content-Type": "application/json"}, method="POST")
            with urlopen(request, timeout=3) as response:
                result = json.loads(response.read())
            return self.respond(json.dumps({"ok": True, "event_id": result["event_ids"][0]}))
        except (ValueError, URLError, TimeoutError, KeyError) as exc:
            return self.respond(json.dumps({"error": f"SIEMS indisponível ou resposta inválida: {exc}"}), 502)

    def log_message(self, fmt, *args):
        print(f"[{self.log_date_time_string()}] {self.client_address[0]} {fmt % args}")


if __name__ == "__main__":
    print(f"Site de demonstração em http://localhost:{PORT}")
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
