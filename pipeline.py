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
    contagem = resultado["contagens"]["segredos"]

    print("")
    print("=" * 60)
    print("RESUMO DA VERIFICACAO DE SEGURANÇA")
    print("=" * 60)
    print(" Segrados ....{} (ALTA{}, MEDIA{}, BAIXA{})".format(
        contagem["total"], contagem["ALTA"],
        contagem["MEDIA"], contagem["BAIXA"]
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

    print(">> Procurando segredos em '{}' ...".format(argumentos.raiz))
    achados = scanner.escanear(argumentos.raiz,ignorar)
    print(">> {} achados(s).".format(len(achados)))

    resultado = politica.avaliar(achados, regras)
    imprimir_resumo(resultado)

    if argumentos.nao_falhar:
        return 0 
    if resultado["aprovado"]:
        return 0
    return 1

if __name__ == "__main__":
    sys.exit(main())