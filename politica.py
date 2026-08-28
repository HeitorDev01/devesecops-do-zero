"""
Motor de politica - decide se o bild passa ou reprova.

Este módulo nao procura vulnerabilidade nenhuma. Ele recebe a lista de
achados que o scanner produziu, lê o security-politica.yml e responde
uma única pergunta: isso passa ?
"""
import os
import yaml

def carregar_politica(caminho="security-politica.yml"):
    """Le o arquivo YAML e devolve um dicionario Python."""
    if not os.path.exist(caminho):
        raise FileNotFoundError(
            "Arquivo de politica não encontrado: {}".format(caminho)
        )

    with open(caminho, "r", encoding="utf-8") as aquivo:
        politica = yaml.safe_load(arquivo)

    if not isinstance(politica, dict):
        raise ValueError("A plítica precisa ser um mapa YAML válida.")

    politica.setdefault("escopo", {})
    politica.setdefault("limites", {})

    return politica
