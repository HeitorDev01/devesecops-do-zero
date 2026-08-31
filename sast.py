"""
SAST -Static Application Security Testing

Este módulo nao reimplementa o bandit. Ele faz três coisas:
    1. chama o Bandit por linha de comando;
    2. lê o JASON que o Bandit produziu;
    3. converte esse JSON para o MESMO formato de
    achado que o nosso scanner de segredos eusa

"""

import json
import os
import shutil
import subprocess

TRADUCAO_DE_GRAVIDADE = {
    "HIGH": "ALTA",
    "MEDIUM": "MEDIA",
    "LOW": "BAIXA",
    "UNDEFINED": "BAIXA",
}