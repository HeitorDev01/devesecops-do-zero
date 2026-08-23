"""
Scanner de segredos — etapa 2.

Lê um arquivo de texto, linha por linha, e aponta em qual linha
existe uma chave de acesso da AWS.
"""

import re

PADRAO_AWS = r"AKIA[A-Z0-9]{16}"


def procurar_chave(linha):
    """Devolve o trecho encontrado nesta linha, ou None se não achar nada."""
    resultado = re.search(PADRAO_AWS, linha)

    if resultado is None:
        return None

    return resultado.group(0)


def verificar_arquivo(caminho):
    """Devolve uma lista de pares (numero_da_linha, trecho_encontrado)."""
    achados = []

    with open(caminho, "r", encoding="utf-8") as arquivo:
        for numero, linha in enumerate(arquivo, start=1):
            trecho = procurar_chave(linha)

            if trecho is not None:
                achados.append((numero, trecho))

    return achados


if __name__ == "__main__":
    caminho = "exemplo/config.py"

    for numero, trecho in verificar_arquivo(caminho):
        print("{}:{} -> {}".format(caminho, numero, trecho))