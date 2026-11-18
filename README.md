# SIEMS — monitoramento de segurança para sites

Protótipo acadêmico de um sistema de monitoramento que recebe eventos de acesso HTTP, armazena-os em SQLite, aplica regras simples de detecção e exibe alertas em um painel web.

## Executar

Requer Python 3.10 ou superior. Não há dependências externas.

```powershell
python app.py
```

Abra `http://localhost:8000`. O banco `siems.db` é criado na primeira execução.

Para abrir o site de teste integrado, inicie um segundo terminal na mesma pasta e rode:

```powershell
python demo_site.py
```

Abra `http://localhost:8080` e use os botões para enviar cenários fictícios ao painel em `http://localhost:8000`.

## Enviar um evento

```powershell
Invoke-RestMethod -Method Post -Uri http://localhost:8000/api/logs `
  -ContentType 'application/json' `
  -Body '{"ip":"203.0.113.10","method":"GET","path":"/login","status":401,"user_agent":"exemplo"}'
```

O endpoint aceita um evento JSON ou uma lista de até 500 eventos. Campos: `ip`, `method`, `path`, `status`, `user_agent` e `raw`.

## Regras iniciais

- Sinais comuns de SQL injection, XSS e path traversal na URL.
- Acesso a caminhos frequentemente sondados, como `/.env` e `/wp-admin`.
- Dez ou mais respostas 404 pelo mesmo IP em cinco minutos.
- Oito ou mais requisições por minuto a rotas de autenticação.

Alertas podem ser triados no painel como `Novo`, `Em análise`, `Positivo`, `Resolvido` ou `Falso positivo`, com uma observação de até 1000 caracteres. As alterações são persistidas no SQLite.

As regras são heurísticas didáticas e podem gerar falsos positivos. O protótipo recebe eventos estruturados; um próximo incremento pode adicionar parser de logs Nginx/Apache, autenticação de agentes, gestão de regras e configuração de retenção. Execute apenas localmente: este protótipo não implementa autenticação, TLS, rate limiting ou controles para exposição pública.
