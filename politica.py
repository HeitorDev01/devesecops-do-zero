"""
Motor de política — decide se o build passa ou reprova.

Este módulo não procura vulnerabilidade nenhuma. Ele recebe a lista de
achados que os scanners produziram, lê o security-policy.yml e responde
uma única pergunta: isso passa?

Separar "encontrar problemas" de "decidir o que fazer com eles" é o
que permite mudar a régua de segurança sem tocar em um scanner.
"""

import os

import yaml


def carregar_politica(caminho="security-policy.yml"):
    """Lê o arquivo YAML e devolve um dicionário Python."""
    if not os.path.exists(caminho):
        raise FileNotFoundError(
            "Arquivo de política não encontrado: {}".format(caminho)
        )

    with open(caminho, "r", encoding="utf-8") as arquivo:
        politica = yaml.safe_load(arquivo)

    if not isinstance(politica, dict):
        raise ValueError("A política precisa ser um mapa YAML válido.")

    politica.setdefault("escopo", {})
    politica.setdefault("limites", {})

    return politica


def contar(achados, tipo):
    """Conta achados de um tipo, agrupados por gravidade."""
    contagem = {"ALTA": 0, "MEDIA": 0, "BAIXA": 0, "total": 0}

    for achado in achados:
        if achado["tipo"] != tipo:
            continue

        gravidade = achado.get("gravidade", "BAIXA")
        contagem[gravidade] = contagem.get(gravidade, 0) + 1
        contagem["total"] += 1

    return contagem


CATEGORIAS = (
    ("segredos", "segredo"),
    ("sast", "codigo"),
)


def avaliar(achados, politica):
    """Aplica a política e devolve o veredito completo."""
    limites = politica.get("limites", {})

    contagens = {}
    violacoes = []

    for categoria, tipo in CATEGORIAS:
        contagens[categoria] = contar(achados, tipo)
        limites_da_categoria = limites.get(categoria) or {}

        for gravidade in ("ALTA", "MEDIA", "BAIXA"):
            if gravidade not in limites_da_categoria:
                continue

            limite = limites_da_categoria[gravidade]
            encontrados = contagens[categoria][gravidade]

            if encontrados > limite:
                violacoes.append(
                    "{}: {} achado(s) de gravidade {} — o limite é {}".format(
                        categoria.upper(), encontrados, gravidade, limite
                    )
                )

    return {
        "aprovado": len(violacoes) == 0,
        "violacoes": violacoes,
        "contagens": contagens,
        "achados": achados,
    }


if __name__ == "__main__":
    import scanner

    politica = carregar_politica()
    ignorar = politica["escopo"].get("ignorar_caminhos", [])

    achados = scanner.escanear(".", ignorar)
    resultado = avaliar(achados, politica)

    contagem = resultado["contagens"]["segredos"]

    print("")
    print("Segredos: {} (ALTA {}, MEDIA {}, BAIXA {})".format(
        contagem["total"], contagem["ALTA"], contagem["MEDIA"], contagem["BAIXA"]))
    print("")

    if resultado["aprovado"]:
        print("RESULTADO: APROVADO — dentro da política de segurança.")
    else:
        print("RESULTADO: REPROVADO — a política foi violada:")
        for violacao in resultado["violacoes"]:
            print("  * " + violacao)
    print("")