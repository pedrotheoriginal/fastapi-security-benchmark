# 🛡️ Secure Coding & API Hardening

> Estudo de caso prático: a diferença entre uma API financeira **vulnerável** e uma **blindada** sob as diretrizes da OWASP, com explorações reproduzíveis e correções comprovadas.

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-Framework-009688?logo=fastapi&logoColor=white)
![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-2.0-D71F00)
![SQLite](https://img.shields.io/badge/SQLite-Database-003B57?logo=sqlite&logoColor=white)
![OWASP](https://img.shields.io/badge/OWASP-Top%2010-000000)
![Status](https://img.shields.io/badge/Status-Educacional-blue)

---

## 📖 Sobre o Estudo de Caso

Uma carteira digital com transferências de saldo entre usuários é um dos cenários mais críticos em segurança de aplicações. Pequenas falhas de lógica ou de validação podem gerar **criação ou destruição de dinheiro**.

Este repositório expõe duas versões da mesma API:

- **`vulnerable_api.py`**: contém falhas de *Race Condition* (Check-Then-Act), validação insuficiente de valores e vazamento de erros internos.
- **`secure_api.py`**: aplica validação estrita, transações atômicas com lock de escrita, atualizações condicionais e tratamento seguro de erros.

O objetivo é demonstrar, com testes reproduzíveis, como pequenas decisões de engenharia mudam completamente o nível de risco.

---

## 📁 Estrutura do Repositório

```text
secure-coding-api-hardening/
├── vulnerable_api.py   # Versão vulnerável (porta 8000)
├── secure_api.py       # Versão blindada (porta 8001)
└── README.md
```

---

## ⚖️ Tabela Comparativa: Vulnerável vs. Blindado

| Aspecto | `vulnerable_api.py` ❌ | `secure_api.py` ✅ |
|---|---|---|
| **Concorrência** | Check-Then-Act sem lock. Dois pedidos simultâneos leem o mesmo saldo. | `BEGIN IMMEDIATE` + `UPDATE ... WHERE saldo >= valor`. |
| **Validação de valor** | `float` sem restrição: aceita negativos, `Infinity` e `NaN`. | `Decimal` com `gt=0`, `le`, `max_digits`, `decimal_places`, `allow_inf_nan=False`. |
| **Precisão monetária** | Ponto flutuante binário (imprecisão). | Centavos em inteiro (`balance_cents`). |
| **Integridade no banco** | Nenhuma restrição de saldo. | `CHECK (balance_cents >= 0)`. |
| **Verificação de escrita** | Não verifica se a atualização afetou linhas. | Valida `rowcount` e aborta com rollback. |
| **Tratamento de erros** | Devolve `repr(exc)` e `traceback` ao cliente. | Resposta genérica com `error_id`. Detalhes apenas no log. |
| **Schema de entrada** | Aceita campos extras. | `extra="forbid"` rejeita campos não previstos. |

---

## 🔍 Vulnerabilidades Explicadas

### 1. Race Condition: Check-Then-Act (TOCTOU)

A operação "verificar saldo → debitar" não é atômica. Entre a leitura e a escrita existe uma janela de tempo em que outra requisição pode ler o mesmo saldo.

```text
Saldo inicial de Alice: 100

Requisição A (80)                   Requisição B (80)
─────────────────                   ─────────────────
LÊ saldo = 100  ✔ (100 ≥ 80)
                                    LÊ saldo = 100  ✔ (100 ≥ 80)
GRAVA saldo = 20
                                    GRAVA saldo = 20   ← sobrescreve A
Resultado: 2 transferências aprovadas, saldo reflete apenas 1.
```

- **CWE-362**: Concurrent Execution using Shared Resource with Improper Synchronization
- **CWE-367**: Time-of-check Time-of-use (TOCTOU) Race Condition
- **OWASP Top 10 (2021)**: A04: Insecure Design
- **OWASP API Security Top 10 (2023)**: API6: Unrestricted Access to Sensitive Business Flows

### 2. Validação Insuficiente do Valor Monetário

O endpoint aceita qualquer `float`. Com `amount` negativo, o remetente **recebe** dinheiro. Com `-Infinity`, o saldo se torna infinito.

- **CWE-20**: Improper Input Validation
- **CWE-839**: Numeric Range Comparison Without Minimum Check
- **CWE-1287**: Improper Validation of Specified Type of Input (`NaN` / `Infinity`)
- **OWASP Top 10 (2021)**: A04: Insecure Design

### 3. Imprecisão no Tratamento Monetário

Números de ponto flutuante não representam decimais como `0.1` exatamente. Em valores financeiros, isso gera diferenças acumuladas.

- **CWE-681**: Incorrect Conversion between Numeric Types

### 4. Vazamento de Informações Internas

Stack traces e mensagens de exceção expõem caminhos, bibliotecas e estrutura do banco. Esse conteúdo ajuda o atacante a mapear o sistema.

- **CWE-209**: Generation of Error Message Containing Sensitive Information
- **OWASP Top 10 (2021)**: A05: Security Misconfiguration

---

## 🧱 Controles Aplicados na Versão Blindada

- **Entrada estrita:** `Decimal` com limites, precisão máxima de duas casas e rejeição de `inf`/`nan`. Campos extras são bloqueados.
- **Transação atômica:** `BEGIN IMMEDIATE` adquire o lock de escrita antes de qualquer leitura. Concorrentes aguardam na fila.
- **Atualização condicional:** `UPDATE ... WHERE balance_cents >= :valor` faz a verificação e a escrita em uma única operação. O `rowcount` confirma o resultado.
- **Rollback automático:** qualquer falha dentro do bloco `db.begin()` desfaz o débito.
- **Defesa em profundidade:** `CHECK` no banco impede saldo negativo mesmo se a aplicação falhar.
- **Erros seguros:** o cliente recebe apenas um `error_id`. O detalhe técnico fica no log do servidor.

---

## 🚀 Como Executar

### 1. Clone e instale as dependências

```bash
git clone https://github.com/<seu-usuario>/secure-coding-api-hardening.git
cd secure-coding-api-hardening
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install fastapi uvicorn sqlalchemy
```

### 2. Suba as duas APIs (em terminais separados)

```bash
# Terminal 1: vulnerável (porta 8000)
uvicorn vulnerable_api:app --port 8000

# Terminal 2: blindada (porta 8001)
uvicorn secure_api:app --port 8001
```

A documentação interativa fica disponível em `/docs` em cada porta.

---

## 🧪 Como Testar

> Os bancos são criados automaticamente. Para resetar o estado entre os testes, pare o servidor, apague o arquivo `.db` correspondente e suba novamente.

### Teste 1: Race Condition (10 transferências simultâneas de 80.00 com saldo de 100.00)

Salve como `race_test.py` e execute com a API alvo ativa:

```python
import json
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"


def transfer(_):
    body = json.dumps({"from_id": 1, "to_id": 2, "amount": 80}).encode()
    req = urllib.request.Request(
        f"{BASE}/transfer", data=body,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status
    except urllib.error.HTTPError as err:
        return err.code


with ThreadPoolExecutor(max_workers=10) as pool:
    statuses = list(pool.map(transfer, range(10)))

print("Status das requisições:", statuses)
print("Aprovadas (200):", statuses.count(200))

with urllib.request.urlopen(f"{BASE}/wallets/1") as resp:
    print("Saldo final do remetente:", json.loads(resp.read())["balance"])
```

```bash
python race_test.py http://127.0.0.1:8000   # vulnerável
python race_test.py http://127.0.0.1:8001   # blindado
```

**Resultado esperado:**

| Versão | Aprovadas (200) | Comportamento |
|---|---|---|
| Vulnerável | Várias (potencialmente todas) | Saldo inconsistente com o total debitado. Dinheiro é "criado" no sistema. |
| Blindado | **Exatamente 1** | As demais recebem `409`. Saldo final: `20.00`. |

### Teste 2: Valor negativo (inversão de fluxo)

```bash
curl -X POST http://127.0.0.1:8000/transfer \
  -H "Content-Type: application/json" \
  -d '{"from_id": 1, "to_id": 2, "amount": -50}'
```

- **Vulnerável:** `200 OK`. O saldo de Alice **aumenta** em 50.
- **Blindado:** `422 Unprocessable Entity`.

### Teste 3: Valor infinito

```bash
curl -X POST http://127.0.0.1:8000/transfer \
  -H "Content-Type: application/json" \
  -d '{"from_id": 1, "to_id": 2, "amount": -Infinity}'
```

- **Vulnerável:** `200 OK`. O saldo do remetente se torna infinito.
- **Blindado:** `422` (`allow_inf_nan=False`).

> Observação: `Infinity`, `-Infinity` e `NaN` não fazem parte do JSON padrão, mas o parser do Python os aceita. Esse é justamente o vetor explorado.

### Teste 4: Vazamento de erro

Envie `"amount": NaN` para a versão vulnerável:

- **Vulnerável:** `500` com `traceback` completo no corpo da resposta.
- **Blindado:** `422` pela validação de entrada. Se algum erro interno ocorresse, a resposta seria apenas `{"error": "internal_error", "error_id": "..."}`.

---

## ⚠️ Limitações e Próximos Passos

Este projeto é educacional e tem escopo deliberadamente reduzido:

- **Autenticação e autorização:** não implementadas. A versão blindada ainda aceita `from_id` no corpo, o que representaria um problema de BOLA (OWASP API1) em produção. Próximo passo: autenticação JWT e verificação de que o remetente é o dono da carteira.
- **Idempotência:** adicionar uma `Idempotency-Key` para evitar duplicidade em retentativas.
- **Rate limiting:** limitar requisições por cliente para mitigar abuso do fluxo de negócio (API6).
- **Produção:** desativar `/docs` e `/openapi.json`, aplicar headers de segurança e usar um banco com controle de concorrência nativo (PostgreSQL com `SELECT ... FOR UPDATE`).


---

<p align="center">Feito para fins educacionais e de portfólio em Application Security.</p>
