# Relatorio de Segurança - REPROVADO

| Etapa | Total | ALTA | MEDIA | BAIXA |
|---|---:|---:|---:|
| Segredos | 7 | 5 | 2 | 0 |

## Por que o build foi reprovado

-SEGREDOS: 5 achado(s) de gravidade ALTA — o limite é 0
-SAST: 3 achado(s) de gravidade ALTA — o limite é 0
-SAST: 4 achado(s) de gravidade MEDIA — o limite é 3
-SCA: 48 vulnerabilidade(s) em dependencias - limite é 5

## Segredos no código (7)

### [ALTA] Chave de acesso da AWS

- **local:** '.\exemplo\config.py' linha 7
- **Ferramenta:** scanner-de-segredos
- **Detalhe:** Valor encontrado: AKIA****************
- **Como corrigir:** Revogue a chave no console da AWS e use IAM Roles ou variáveis de ambiente.

### [ALTA] Token de bot do Slack

- **local:** '.\exemplo\config.py' linha 13
- **Ferramenta:** scanner-de-segredos
- **Detalhe:** Valor encontrado: xoxb***********************************************
- **Como corrigir:** Revogue o token no painel do Slack e recrie-o como variável de ambiente.

### [ALTA] Chave de acesso da AWS

- **local:** '.\exemplo\legado\backup.py' linha 3
- **Ferramenta:** scanner-de-segredos
- **Detalhe:** Valor encontrado: AKIA****************
- **Como corrigir:** Revogue a chave no console da AWS e use IAM Roles ou variáveis de ambiente.

### [ALTA] Chave de acesso da AWS

- **local:** '.\exemplo\legado\backup.py' linha 3
- **Ferramenta:** scanner-de-segredos
- **Detalhe:** Valor encontrado: AKIA****************
- **Como corrigir:** Revogue a chave no console da AWS e use IAM Roles ou variáveis de ambiente.

### [ALTA] Chave privada (RSA/SSH/EC)

- **local:** '.\exemplo\legado\deploy.pem' linha 1
- **Ferramenta:** scanner-de-segredos
- **Detalhe:** Valor encontrado: ----***************************
- **Como corrigir:** Gere um novo par de chaves e guarde a privada em um cofre de segredos.

### [MEDIA] Senha ou token escrito no código

- **local:** '.\exemplo\config.py' linha 11
- **Ferramenta:** scanner-de-segredos
- **Detalhe:** Valor encontrado: SENH******************************
- **Como corrigir:** Troque o valor por os.environ['NOME_DA_VARIAVEL'] e cadastre o segredo no CI.

### [MEDIA] Senha ou token escrito no código

- **local:** '.\exemplo\config.py' linha 13
- **Ferramenta:** scanner-de-segredos
- **Detalhe:** Valor encontrado: SLAC***************************************************************
- **Como corrigir:** Troque o valor por os.environ['NOME_DA_VARIAVEL'] e cadastre o segredo no CI.

## SAST(analise estetica) (8)

### [ALTA] B602 — subprocess_popen_with_shell_equals_true

- **local:** 'app\main.py' linha 9
- **Ferramenta:** bandit
- **Detalhe:** subprocess call with shell=True identified, security issue. (confiança: HIGH)
- **Como corrigir:** Detalhes e como corrigir: https://bandit.readthedocs.io/en/1.9.4/plugins/b602_subprocess_popen_with_shell_equals_true.html

### [ALTA] B324 — hashlib

- **local:** 'app\main.py' linha 12
- **Ferramenta:** bandit
- **Detalhe:** Use of weak MD5 hash for security. Consider usedforsecurity=False (confiança: HIGH)
- **Como corrigir:** Detalhes e como corrigir: https://bandit.readthedocs.io/en/1.9.4/plugins/b324_hashlib.html

### [ALTA] B501 — request_with_no_cert_validation

- **local:** 'app\main.py' linha 18
- **Ferramenta:** bandit
- **Detalhe:** Call to requests with verify=False disabling SSL certificate checks, security issue. (confiança: HIGH)
- **Como corrigir:** Detalhes e como corrigir: https://bandit.readthedocs.io/en/1.9.4/plugins/b501_request_with_no_cert_validation.html

### [MEDIA] B307 — blacklist

- **local:** 'app\main.py' linha 15
- **Ferramenta:** bandit
- **Detalhe:** Use of possibly insecure function - consider using safer ast.literal_eval. (confiança: HIGH)
- **Como corrigir:** Detalhes e como corrigir: https://bandit.readthedocs.io/en/1.9.4/blacklists/blacklist_calls.html#b307-eval

### [MEDIA] B113 — request_without_timeout

- **local:** 'app\main.py' linha 18
- **Ferramenta:** bandit
- **Detalhe:** Call to requests without timeout (confiança: LOW)
- **Como corrigir:** Detalhes e como corrigir: https://bandit.readthedocs.io/en/1.9.4/plugins/b113_request_without_timeout.html

### [MEDIA] B506 — yaml_load

- **local:** 'app\main.py' linha 22
- **Ferramenta:** bandit
- **Detalhe:** Use of unsafe yaml load. Allows instantiation of arbitrary objects. Consider yaml.safe_load(). (confiança: HIGH)
- **Como corrigir:** Detalhes e como corrigir: https://bandit.readthedocs.io/en/1.9.4/plugins/b506_yaml_load.html

### [MEDIA] B108 — hardcoded_tmp_directory

- **local:** 'app\main.py' linha 25
- **Ferramenta:** bandit
- **Detalhe:** Probable insecure usage of temp file/directory. (confiança: MEDIUM)
- **Como corrigir:** Detalhes e como corrigir: https://bandit.readthedocs.io/en/1.9.4/plugins/b108_hardcoded_tmp_directory.html

### [BAIXA] B404 — blacklist

- **local:** 'app\main.py' linha 3
- **Ferramenta:** bandit
- **Detalhe:** Consider possible security implications associated with the subprocess module. (confiança: HIGH)
- **Como corrigir:** Detalhes e como corrigir: https://bandit.readthedocs.io/en/1.9.4/blacklists/blacklist_imports.html#b404-import-subprocess

## SCA (dependencias) (48)

### [DESCONHECIDA] requests 2.19.1 — PYSEC-2018-28

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** The Requests package before 2.20.0 for Python sends an HTTP Authorization header to an http URI upon receiving a same-hostname https-to-http redirect, which mak...
- **Como corrigir:** Atualize requests para 2.20.0

### [DESCONHECIDA] requests 2.19.1 — PYSEC-2018-28

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** The Requests package through 2.19.1 before 2018-09-14 for Python sends an HTTP Authorization header to an http URI upon receiving a same-hostname https-to-http ...
- **Como corrigir:** Atualize requests para 2.20.0

### [DESCONHECIDA] requests 2.19.1 — PYSEC-2023-74

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** ### Impact Since Requests v2.3.0, Requests has been vulnerable to potentially leaking `Proxy-Authorization` headers to destination servers, specifically during ...
- **Como corrigir:** Atualize requests para 2.31.0

### [DESCONHECIDA] requests 2.19.1 — PYSEC-2023-74

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** Requests is a HTTP library. Since Requests 2.3.0, Requests has been leaking Proxy-Authorization headers to destination servers when redirected to an HTTPS endpo...
- **Como corrigir:** Atualize requests para 2.31.0

### [DESCONHECIDA] requests 2.19.1 — PYSEC-2026-1873

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** When using a `requests.Session`, if the first request to a given origin is made with `verify=False`, TLS certificate verification may remain disabled for all su...
- **Como corrigir:** Atualize requests para 2.32.0

### [DESCONHECIDA] requests 2.19.1 — PYSEC-2026-1872

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** ### Impact Due to a URL parsing issue, Requests releases prior to 2.32.4 may leak .netrc credentials to third parties for specific maliciously-crafted URLs. ###...
- **Como corrigir:** Atualize requests para 2.32.4

### [DESCONHECIDA] requests 2.19.1 — PYSEC-2026-2275

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** ### Impact The `requests.utils.extract_zipped_paths()` utility function uses a predictable filename when extracting files from zip archives into the system temp...
- **Como corrigir:** Atualize requests para 2.33.0

### [DESCONHECIDA] requests 2.19.1 — PYSEC-2026-1873

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** When using a `requests.Session`, if the first request to a given origin is made with `verify=False`, TLS certificate verification may remain disabled for all su...
- **Como corrigir:** Atualize requests para 2.32.0

### [DESCONHECIDA] requests 2.19.1 — PYSEC-2026-1872

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** ### Impact Due to a URL parsing issue, Requests releases prior to 2.32.4 may leak .netrc credentials to third parties for specific maliciously-crafted URLs. ###...
- **Como corrigir:** Atualize requests para 2.32.4

### [DESCONHECIDA] requests 2.19.1 — PYSEC-2026-2275

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** Requests is a HTTP library. Prior to version 2.33.0, the `requests.utils.extract_zipped_paths()` utility function uses a predictable filename when extracting fi...
- **Como corrigir:** Atualize requests para 2.33.0

### [DESCONHECIDA] pyyaml 5.3.1 — PYSEC-2021-142

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** A vulnerability was discovered in the PyYAML library in versions before 5.4, where it is susceptible to arbitrary code execution when it processes untrusted YAM...
- **Como corrigir:** Atualize pyyaml para 5.4

### [DESCONHECIDA] pyyaml 5.3.1 — PYSEC-2021-142

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** A vulnerability was discovered in the PyYAML library in versions before 5.4, where it is susceptible to arbitrary code execution when it processes untrusted YAM...
- **Como corrigir:** Atualize pyyaml para 5.4

### [DESCONHECIDA] jinja2 2.11.2 — PYSEC-2021-66

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** This affects the package jinja2 from 0.0.0 and before 2.11.3. The ReDoS vulnerability is mainly due to the `_punctuation_re regex` operator and its use of multi...
- **Como corrigir:** Atualize jinja2 para 2.11.3

### [DESCONHECIDA] jinja2 2.11.2 — PYSEC-2021-66

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** This affects the package jinja2 from 0.0.0 and before 2.11.3. The ReDOS vulnerability of the regex is mainly due to the sub-pattern [a-zA-Z0-9._-]+.[a-zA-Z0-9._...
- **Como corrigir:** Atualize jinja2 para 2.11.3

### [DESCONHECIDA] jinja2 2.11.2 — PYSEC-2026-1473

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** The `xmlattr` filter in affected versions of Jinja accepts keys containing spaces. XML/HTML attributes cannot contain spaces, as each would then be interpreted ...
- **Como corrigir:** Atualize jinja2 para 3.1.3

### [DESCONHECIDA] jinja2 2.11.2 — PYSEC-2026-1474

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** The `xmlattr` filter in affected versions of Jinja accepts keys containing non-attribute characters. XML/HTML attributes cannot contain spaces, `/`, `>`, or `=`...
- **Como corrigir:** Atualize jinja2 para 3.1.4

### [DESCONHECIDA] jinja2 2.11.2 — PYSEC-2026-1475

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** An oversight in how the Jinja sandboxed environment detects calls to `str.format` allows an attacker that controls the content of a template to execute arbitrar...
- **Como corrigir:** Atualize jinja2 para 3.1.5

### [DESCONHECIDA] jinja2 2.11.2 — PYSEC-2026-1471

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** An oversight in how the Jinja sandboxed environment interacts with the `|attr` filter allows an attacker that controls the content of a template to execute arbi...
- **Como corrigir:** Atualize jinja2 para 3.1.6

### [DESCONHECIDA] jinja2 2.11.2 — PYSEC-2026-1473

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** The `xmlattr` filter in affected versions of Jinja accepts keys containing spaces. XML/HTML attributes cannot contain spaces, as each would then be interpreted ...
- **Como corrigir:** Atualize jinja2 para 3.1.3

### [DESCONHECIDA] jinja2 2.11.2 — PYSEC-2026-1471

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** An oversight in how the Jinja sandboxed environment interacts with the `|attr` filter allows an attacker that controls the content of a template to execute arbi...
- **Como corrigir:** Atualize jinja2 para 3.1.6

### [DESCONHECIDA] jinja2 2.11.2 — PYSEC-2026-1474

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** The `xmlattr` filter in affected versions of Jinja accepts keys containing non-attribute characters. XML/HTML attributes cannot contain spaces, `/`, `>`, or `=`...
- **Como corrigir:** Atualize jinja2 para 3.1.4

### [DESCONHECIDA] jinja2 2.11.2 — PYSEC-2026-1475

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** An oversight in how the Jinja sandboxed environment detects calls to `str.format` allows an attacker that controls the content of a template to execute arbitrar...
- **Como corrigir:** Atualize jinja2 para 3.1.5

### [DESCONHECIDA] idna 2.7 — PYSEC-2024-60

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** ### Impact A specially crafted argument to the `idna.encode()` function could consume significant resources. This may lead to a denial-of-service. ### Patches T...
- **Como corrigir:** Atualize idna para 3.7

### [DESCONHECIDA] idna 2.7 — PYSEC-2024-60

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** A vulnerability was identified in the kjd/idna library, specifically within the `idna.encode()` function, affecting version 3.6. The issue arises from the funct...
- **Como corrigir:** Atualize idna para 3.7

### [DESCONHECIDA] idna 2.7 — PYSEC-2026-215

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** This is the same issue as CVE-2024-3651, however the original remediation in 2024 was not a complete fix. Payloads such as `"\u0660" * N` or `"\u30fb" * N + "\u...
- **Como corrigir:** Atualize idna para 3.15

### [DESCONHECIDA] idna 2.7 — PYSEC-2026-215

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** Internationalized Domain Names in Applications (IDNA) for Python provides support for Internationalized Domain Names in Applications (IDNA) and Unicode IDNA Com...
- **Como corrigir:** Atualize idna para 3.15

### [DESCONHECIDA] urllib3 1.23 — PYSEC-2019-133

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** The urllib3 library before 1.24.2 for Python mishandles certain cases where the desired set of CA certificates is different from the OS store of CA certificates...
- **Como corrigir:** Atualize urllib3 para 1.24.2

### [DESCONHECIDA] urllib3 1.23 — PYSEC-2019-132

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** In the urllib3 library through 1.24.1 for Python, CRLF injection is possible if the attacker controls the request parameter.
- **Como corrigir:** Atualize urllib3 para 1.24.3

### [DESCONHECIDA] urllib3 1.23 — PYSEC-2020-148

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** urllib3 before 1.25.9 allows CRLF injection if the attacker controls the HTTP request method, as demonstrated by inserting CR and LF control characters in the f...
- **Como corrigir:** Atualize urllib3 para 1.25.9

### [DESCONHECIDA] urllib3 1.23 — PYSEC-2019-133

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** The urllib3 library before 1.24.2 for Python mishandles certain cases where the desired set of CA certificates is different from the OS store of CA certificates...
- **Como corrigir:** Atualize urllib3 para 1.24.2

### [DESCONHECIDA] urllib3 1.23 — PYSEC-2020-148

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** urllib3 before 1.25.9 allows CRLF injection if the attacker controls the HTTP request method, as demonstrated by inserting CR and LF control characters in the f...
- **Como corrigir:** Atualize urllib3 para 1.25.9

### [DESCONHECIDA] urllib3 1.23 — PYSEC-2019-132

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** In the urllib3 library through 1.24.2 for Python, CRLF injection is possible if the attacker controls the request parameter.
- **Como corrigir:** Atualize urllib3 para 1.24.3

### [DESCONHECIDA] urllib3 1.23 — PYSEC-2026-1995

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** When using urllib3's proxy support with `ProxyManager`, the `Proxy-Authorization` header is only sent to the configured proxy, as expected. However, when sendin...
- **Como corrigir:** Atualize urllib3 para 1.26.19 ou 2.2.2

### [DESCONHECIDA] urllib3 1.23 — PYSEC-2023-192

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** urllib3 doesn't treat the `Cookie` HTTP header special or provide any helpers for managing cookies over HTTP, that is the responsibility of the user. However, i...
- **Como corrigir:** Atualize urllib3 para 1.26.17 ou 2.0.6

### [DESCONHECIDA] urllib3 1.23 — PYSEC-2023-192

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** urllib3 is a user-friendly HTTP client library for Python. urllib3 doesn't treat the `Cookie` HTTP header special or provide any helpers for managing cookies ov...
- **Como corrigir:** Atualize urllib3 para 1.26.17 ou 2.0.6

### [DESCONHECIDA] urllib3 1.23 — PYSEC-2023-207

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** urllib3 before 1.24.2 does not remove the authorization HTTP header when following a cross-origin redirect (i.e., a redirect that differs in host, port, or sche...
- **Como corrigir:** Atualize urllib3 para 1.24.2

### [DESCONHECIDA] urllib3 1.23 — PYSEC-2023-212

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** urllib3 previously wouldn't remove the HTTP request body when an HTTP redirect response using status 303 "See Other" after the request had its method changed fr...
- **Como corrigir:** Atualize urllib3 para 1.26.18 ou 2.0.7

### [DESCONHECIDA] urllib3 1.23 — PYSEC-2023-207

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** urllib3 before 1.24.2 does not remove the authorization HTTP header when following a cross-origin redirect (i.e., a redirect that differs in host, port, or sche...
- **Como corrigir:** Atualize urllib3 para 1.24.2

### [DESCONHECIDA] urllib3 1.23 — PYSEC-2023-212

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** urllib3 is a user-friendly HTTP client library for Python. urllib3 previously wouldn't remove the HTTP request body when an HTTP redirect response using status ...
- **Como corrigir:** Atualize urllib3 para 1.26.18 ou 2.0.7

### [DESCONHECIDA] urllib3 1.23 — PYSEC-2026-1999

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** urllib3 handles redirects and retries using the same mechanism, which is controlled by the `Retry` object. The most common way to disable redirects is at the re...
- **Como corrigir:** Atualize urllib3 para 2.5.0

### [DESCONHECIDA] urllib3 1.23 — PYSEC-2026-1994

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** ### Impact urllib3's [streaming API](https://urllib3.readthedocs.io/en/2.5.0/advanced-usage.html#streaming-and-i-o) is designed for the efficient handling of la...
- **Como corrigir:** Atualize urllib3 para 2.6.0

### [DESCONHECIDA] urllib3 1.23 — PYSEC-2026-1996

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** ### Impact urllib3's [streaming API](https://urllib3.readthedocs.io/en/2.6.2/advanced-usage.html#streaming-and-i-o) is designed for the efficient handling of la...
- **Como corrigir:** Atualize urllib3 para 2.6.3

### [DESCONHECIDA] urllib3 1.23 — PYSEC-2026-141

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** ### Impact When following cross-origin redirects for requests made using urllib3’s high-level APIs, such as `urllib3.request()`, `PoolManager.request()`, and `P...
- **Como corrigir:** Atualize urllib3 para 2.7.0

### [DESCONHECIDA] urllib3 1.23 — PYSEC-2026-141

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** urllib3 is an HTTP client library for Python. From 1.23 to before 2.7.0, cross-origin redirects followed from the low-level API via ProxyManager.connection_from...
- **Como corrigir:** Atualize urllib3 para 2.7.0

### [DESCONHECIDA] urllib3 1.23 — PYSEC-2026-1999

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** urllib3 handles redirects and retries using the same mechanism, which is controlled by the `Retry` object. The most common way to disable redirects is at the re...
- **Como corrigir:** Atualize urllib3 para 2.5.0

### [DESCONHECIDA] urllib3 1.23 — PYSEC-2026-1995

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** When using urllib3's proxy support with `ProxyManager`, the `Proxy-Authorization` header is only sent to the configured proxy, as expected. However, when sendin...
- **Como corrigir:** Atualize urllib3 para 1.26.19 ou 2.2.2

### [DESCONHECIDA] urllib3 1.23 — PYSEC-2026-1994

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** ### Impact urllib3's [streaming API](https://urllib3.readthedocs.io/en/2.5.0/advanced-usage.html#streaming-and-i-o) is designed for the efficient handling of la...
- **Como corrigir:** Atualize urllib3 para 2.6.0

### [DESCONHECIDA] urllib3 1.23 — PYSEC-2026-1996

- **local:** 'requirements.txt' linha 0
- **Ferramenta:** pip-audit
- **Detalhe:** ### Impact urllib3's [streaming API](https://urllib3.readthedocs.io/en/2.6.2/advanced-usage.html#streaming-and-i-o) is designed for the efficient handling of la...
- **Como corrigir:** Atualize urllib3 para 2.6.3
