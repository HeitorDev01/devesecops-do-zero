""" 
Geraçao de relatório

um pipeline que só diz "REPROVADO" é inútil: o desenvolvedor precisa 
saber o que, onde e como corrigir. Aqui produzimos tres saídas, para 
tres púbicos diferentes

"""

import json
import os

ORDEM_DE_GRAVIDADE = {"ALTA": 0, "MÉDIA": 1, "BAIXA": 2, "DESCONHECIDA": 3}

NOME_DA_ETAPA = {
    "segredo": "Segredos no código",
    "codigo": "SAST(analise estetica)",
    "dependencia": "SCA (dependencias)"
}

QUANTOS_NO_CONSOLE = 10

def ordenar(achados):
    """ Mais grave primeiro; depois por arquivo e linha."""
    return sorted(
        achados,
        key=lambda a: (
            ORDEM_DE_GRAVIDADE.get(a.get("gravidade"), 9),
            a.get("arquivo") or "",
            a.get("linha") or 0,
        )
    )

def imprimir_no_console(resultado):
    """Resumo curto e os achados mais graves."""
    contagens = resultado["contagens"]

    print("")
    print("=" * 60)
    print("RESUMO DA VERIFICAÇAO DE SEGURANÇA")
    print("=" * 60)

    for categoria, rotulo in (("segredos", "Segredos"), ("sast", "SAST")):
        c = contagens[categoria]
        print("  {:.<12} {} (ALTA {}, MEDIA {}, BAIXA {})".format(
            rotulo, c["total"], c["ALTA"], c["MÉDIA"], c["BAIXA"]))

    print("  {:.<12} {} (vulnerabilidade(s) em dependências)".format(
        "SCA", contagens["dependencia"]["total"]))

    print("-" * 60)

    if resultado["aprovado"]:
        print("RESULTADO:APROVADO - dentro da políticade segurança.")
    else:
        print("RESULTADO: REPROVADO - a política foi violada.")
        for violacao in resultado ["violacoes"]:
            print("     *" + violacao)

    print("=" * 60)
    print("")

    todos = ordenar(resultado["acahdos"])
    principais = todos[:QUANTOS_NO_CONSOLE]

    if principais:
        print(" Achados mais graves")
        for achado in principais:
            print("     [{:<12}] {}:{}  ".format(
                achado.get("gravidade", "?"),
                achado.get("arquivo"),
                achado.get("linha"),
                achado.get("titulo")
            ))

    restantes = len(todos) - len(principais)
    if restantes > 0:
        print("")
        print("  ... e mais {} achado(s). Veja o relatorio completo em".format(
            restantes
        ))
        print("    reports/security-reports.md")
    print("")

def gerar_markdown (resultado, caminho= "reports/security-reports.md"):
    """Monta o relatorio completo em markdonw e grava em arquivo"""
    contagens = resultado["contagens"]
    linhas = []

    if resultado["reprovado"]:
        linhas.append("# Relatorio de Segurança - APROVADO")
    else:
        linhas.append("# Relatorio de Segurança - REPROVADO")

    linhas.append("")
    linhas.append("| Etapa | Total | ALTA | MEDIA | BAIXA |")
    linhas.append("|---|---:|---:|---:|")

    for chave, rotulo in (("segredos", "Segredos"), ("sast, SAST"), ("sca", "SCA")):
        c = contagens[chave]
        linhas.append("| {} | {} | {} | {} | {} |".format(
            rotulo, c["total"] c["ALTA"], c[MÉDIA], c["BAIXA"]
        ))

        linhas.append("")

        if not resultado["aprovado"]:
            linhas.append("## Por que o build foi reprovado")
            linhas.append("")
            for violacao in resultado["violacoes"]:
                linhas.append("-" + violacao)
            linhas.append("")

        achados_ordenados = ordenar(resultado["achados"])