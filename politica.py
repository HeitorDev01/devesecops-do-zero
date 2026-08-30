"""
Motor de politica - decide se o bild passa ou reprova.

Este módulo nao procura vulnerabilidade nenhuma. Ele recebe a lista de
achados que o scanner produziu, lê o security-politica.yml e responde
uma única pergunta: isso passa ?
"""
import os

import yaml

def carregar_politica(caminho="security-policy.yml"):
    """Le o arquivo YAML e devolve um dicionario Python."""
    if not os.path.exists(caminho):
        raise FileNotFoundError(
            "Arquivo de politica não encontrado: {}".format(caminho)
        )

    with open(caminho, "r", encoding="utf-8") as arquivo:
        politica = yaml.safe_load(arquivo)

    if not isinstance(politica, dict):
        raise ValueError("A plítica precisa ser um mapa YAML válida.")

    politica.setdefault("escopo", {})
    politica.setdefault("limites", {})

    return politica

def contar(achados, tipo):
    """Contato achados de um tipo, agrupado por gravidade."""
    contagem = {"ALTA": 0, "MEDIA": 0, "BAIXA": 0, "total": 0}

    for achado in achados:
        if achado ["tipo"] != tipo:
            continue

        gravidade = achado.get("gravidade", "BAIXA")
        contagem[gravidade] = contagem.get(gravidade, 0 ) + 1
        contagem["total"] += 1

    return contagem

def avaliar (achados, politica):
    """Aplica a politica e devolve o veredito completo."""
    limites = politica.get("limites", {})
    limites_de_segredos = limites.get("segredos", {})

    contagens = {"segredos": contar(achados, "segredo")}

    violacoes = []

    for gravidade in ("ALTA","MEDIA","BAIXA"):
        if gravidade not in limites_de_segredos:
            continue

        limite = limites_de_segredos[gravidade]
        encontrados = contagens["segredos"][gravidade]

        if encontrados > limite:
            violacoes.append(
                "SEGREDOS: {} achado(s) de gravidade {} - o limite é {}".format(
                    encontrados, gravidade, limite
                )
            )

    return{"aprovado": len(violacoes) ==0,
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
    print("Segredos: {} (ALTA {}, MEDIA {}, BAIXA{})".format(
        contagem["total"], contagem["ALTA"], contagem["MEDIA"], contagem["BAIXA"]))
    print("")

    if resultado ["aprovado"]:
        print("RESULTADO: APROVADO - dentro da politica de segurança.")
    else:
        print("RESULTADO: REPROVADO - a politica foi violada:")
        for violacao in resultado["violacoes"]:
            print(" *" + violacao)
    print("")