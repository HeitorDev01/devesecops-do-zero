"""
Scanner de segredos — etapa 4.

Agora o scanner tem um catalago de padroes, cada um com sua gravidade, em vez de conhecer um unico tipo de segredo
"""

import os
import re

PADROES = [
    {
        "nome": "Chave de acesso da AWS",
        "regex": r"AKIA[A-Z0-9]{16}",
        "gravidade": "ALTA",
    },
    {
        "nome": "Chave privada (RSA/SSH/EC)",
        "regex": r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
        "gravidade": "ALTA",
    },
    {
        "nome": "Token de bot do Slack",
        "regex": r"xox[baprs]-[0-9A-Za-z-]{10,}",
        "gravidade": "ALTA",
    },
    {
        "nome": "Senha ou token escrito no código",
        "regex": r"(?i)[a-z0-9_.-]*(?:senha|password|token|secret|api[_-]?key)[a-z0-9_.-]*\s*=\s*[\"'][^\"'\s]{6,}[\"']",
        "gravidade": "MEDIA",
    },
]

for _padrao in PADROES:
    _padrao["compilado"] = re.compile(_padrao["regex"])

PASTAS_IGNORADAS = [".git", ".venv", "__pycache__"]


def verificar_linha(linha):
    """ Devolve uma lista de (gravidade, nome_do_padrao, trecho)."""
    achados = []

    for padrao in PADROES:
        for encontrado in padrao["compilado"].finditer(linha):
            achados.append((padrao["gravidade"], padrao["nome"], encontrado.group(0)))
    return achados 

def verificar_arquivo(caminho):
    """Devolve uma lista de pares (numero_da_linha, trecho_encontrado)."""
    achados = []

    with open(caminho, "r", encoding="utf-8", errors="ignore") as arquivo:
        for numero, linha in enumerate(arquivo, start=1):
           for gravidade, nome, trecho in verificar_linha(linha):
               achados.append((numero, gravidade, nome, trecho))
    return achados


def escanear(raiz):
    """Percorre a árvore de pastas e devolve (caminho, numero, trecho)."""
    achados = []

    for pasta_atual, subpastas, arquivos in os.walk(raiz):
        subpastas[:] = [p for p in subpastas if p not in PASTAS_IGNORADAS]

        for nome_do_arquivo in arquivos:
            caminho = os.path.join(pasta_atual, nome_do_arquivo)

            for numero, gravidade, nome, trecho in verificar_arquivo(caminho):
                achados.append((caminho, numero, gravidade, nome, trecho))

    return achados


if __name__ == "__main__":
    resultados = escanear(".")

    print("Segredos encontrados:", len(resultados))
    for caminho, numero, gravidade, nome, trecho in resultados:
        print(" [{}] {}:{}  {}".format(gravidade, caminho, numero, nome))
