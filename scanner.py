"""
Scanner de segredos — etapa 3.

Varre uma pasta inteira, entrando nas subpastas, e aponta cada
chave de acesso da AWS que encontrar: arquivo, linha e valor.
"""

import os
import re

PADRAO_AWS = r"AKIA[A-Z0-9]{16}"

PASTAS_IGNORADAS = [".git", ".venv", "__pycache__"]


def procurar_chave(linha):
    """Devolve o trecho encontrado nesta linha, ou None se não achar nada."""
    resultado = re.search(PADRAO_AWS, linha)

    if resultado is None:
        return None

    return resultado.group(0)


def verificar_arquivo(caminho):
    """Devolve uma lista de pares (numero_da_linha, trecho_encontrado)."""
    achados = []

    with open(caminho, "r", encoding="utf-8", errors="ignore") as arquivo:
        for numero, linha in enumerate(arquivo, start=1):
            trecho = procurar_chave(linha)

            if trecho is not None:
                achados.append((numero, trecho))

    return achados


def escanear(raiz):
    """Percorre a árvore de pastas e devolve (caminho, numero, trecho)."""
    achados = []

    for pasta_atual, subpastas, arquivos in os.walk(raiz):
        subpastas[:] = [p for p in subpastas if p not in PASTAS_IGNORADAS]

        for nome_do_arquivo in arquivos:
            caminho = os.path.join(pasta_atual, nome_do_arquivo)

            for numero, trecho in verificar_arquivo(caminho):
                achados.append((caminho, numero, trecho))

    return achados


if __name__ == "__main__":
    resultados = escanear(".")

    print("Segredos encontrados:", len(resultados))
    for caminho, numero, trecho in resultados:
        print(" - {}:{} -> {}".format(caminho, numero, trecho))
