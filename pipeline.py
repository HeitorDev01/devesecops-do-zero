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
import relatorio
import sast
import sca
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
    arquivo_de_dependencias = regras["escopo"].get(
        "arquivos_de_dependencias", "requirements.txt")

    achados = []

    print(">>[1/3] Procurando segredos em '{}'...".format(argumentos.raiz))
    encontrados = scanner.escanear(argumentos.raiz, ignorar)
    achados.extend(encontrados)
    print(">>       {} achado(s).".format(len(encontrados)))

    print(">> [2/3] Rodando SAST (Bandit) em '{}'...".format(pasta_do_codigo))
    try:
        encontrados = sast.rodar(pasta_do_codigo)
        achados.extend(encontrados)
        print(">>       {} achado(s).".format(len(encontrados)))
    except RuntimeError as erro:
        print(">>       Etapa falhou: {}".format(erro))
        return 2

    print(">> [3/3] Rodando SCA (pip-audit) em '{}'...".format(arquivo_de_dependencias))
    try:
        encontrados = sca.rodar(arquivo_de_dependencias)
        achados.extend(encontrados)
        print(">>       {} achado(s).".format(len(encontrados)))
    except RuntimeError as erro:
        print(">>       [aviso] SCA nao pode ser executado: {}".format(erro))

    resultado = politica.avaliar(achados, regras)

    relatorio.imprimir_no_console(resultado)
    relatorio.gerar_markdown(resultado)
    relatorio.gerar_json(resultado)

    print(">> Relatórios em reports/security-report.md e reports/security-findings.json")
    print("")

    if resultado["aprovado"]:
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())