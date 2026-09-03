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
from operator import le
import sys

import sast
import politica
import scanner

def montar_argumentos():
    analisador = argparse.ArgumentParser(
        description="Pipeline de verificaçao de segurança para CI/CD."
    )
    analisador.add_argument(
        "--politica", default="security-policy.yml",
        help="Caminho do arquivo de politica (padrão: security-policy.yml)",
    )
    analisador.add_argument(
    "--raiz", default=".",
    help= "Pasta a escanear (padrao: a pasta atual)",
    )
    analisador.add_argument(
        "--nao-falhar", action="store_true",
        help="Mostrar o relatorio mas sempre sair com codigo 0"
    )
    return analisador.parse_args()

def imprimir_resumo(resultado):
    contagens = resultado["contagens"]

    print("")
    print("=" * 60)
    print("RESUMO DA VERIFICACAO DE SEGURANÇA")
    print("=" * 60)

    for categoria, rotulo in (("segredos", "Segredos"), ("sast", "SAST")):
        c = contagens[categoria]
        print(" {:.<12} {} (ALTA{}, MEDIA{}, BAIXA{})".format( rotulo, 
            c["total"], c["ALTA"],
            c["MEDIA"], c["BAIXA"]
        ))
    print("-" * 60)

    if resultado ["aprovado"]:
        print("RESULTADO: APROVADO - dentro da politica de segurança")
    else:
        print("RESULTADO: REPROVADO - a politica foi violada")
        for violacao in resultado ["violacoes"]:
            print("     * " + violacao)

    print("=" * 60)
    print("")

    for achado in resultado["achados"]:
        print("[{}] {}:{}  {}".format(
            achado["gravidade"], achado["arquivo"],
            achado["linha"], achado["titulo"]
        ))
        print("     {}".format(achado["correcao"]))
    print("")

def main():
    argumentos = montar_argumentos()

    print("")
    print(">> Pipeline de segurança iniciado")
    print(">> Política: {}".format(argumentos.politica))

    try:
        regras = politica.carregar_politica(argumentos.politica)
    except (FileNotFoundError, ValueError) as erro:
        print("ERRO ao ler a política: {}".format(erro))
        return 2 

    ignorar = regras["escopo"].get("igorar_caminhos", [])
    pasta_do_codigo = regras["escopo"].get("pasta_do_codigo", "app")

    achados = []

    print(">>[1/2] Procurando segredos em '{}'...".format(argumentos.raiz))
    encontrados = scanner.escanear(argumentos.raiz, ignorar)
    achados.extend(encontrados)
    print(">>       {} achado(s).".format(len(encontrados)))

    print(">> [2/2] Rodando SAST (Bandit) em '{}'...".format(pasta_do_codigo))
    try:
        encontrados = sast.rodar(pasta_do_codigo)
        achados.extend(encontrados)
        print(">>       {} achado(s).".format(len(encontrados)))
    except RuntimeError as erro:
        print(">>       Etapa falhou: {}".format(erro))
        return 2

    resultado = politica.avaliar(achados, regras)
    imprimir_resumo(resultado)

    if argumentos.nao_falhar:
        return 0 
    if resultado["aprovado"]:
        return 0
    return 1

if __name__ == "__main__":
    sys.exit(main())