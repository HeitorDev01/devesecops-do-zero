"""
Orquestrador do pipeline de segurança.

Este é o arquivo que o CI/CD chama. ELE:
1. lê a politica;
2. roda o scanner;
3. pede o veredito ao motor de política;
4. imprimeo resumo;
5. devolve o código de saída certo  - 0 aprovado, 1 reprovado.

Uso: 
    python pipeline.py
    python pipeline.py -- politica outra-politica.yaml
    python pipeline.py --nao-falhar
"""

import argparse
import sys

import politica
import scanner

def montar_argumentos():
    analisador = argparse.ArgumentParser(
        description="Pipeline de verificaçao de segurança para CI/CD."
    )
    analisador.add_argument(
        "--politica", default="security-policy.yaml",
        help="Caminho do arquivo de politica (padrão: security-policy.yaml)",
    )
    