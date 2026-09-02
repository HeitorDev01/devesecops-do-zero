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

def bandit_esta_instalado():
    """
    shutil.which() procura o programa no PATH, igual ao 'which' do Linux
    
    """
    return shutil.which("bandit") is not None

def executar_bandit(pasta_alvo, arquivo_de_saida):
    """
    Roda o Bandit e devolve o caminho do JSON gerado.
    
    """
    os.makedirs(os.path.dirname(arquivo_de_saida), exist_ok=True)

    comando=[
        
        "bandit",
        "-r",
        pasta_alvo,
        "-f",
        "json",
        "-o",
        arquivo_de_saida,
        "-q",
    ]

    resultado = subprocess.run(comando, capture_output=True, text=True)
    if resultado.returncode not in (0, 1):
        raise RuntimeError(
            "Bandit falhou(código{}):\n{}".format(
                resultado.returncode, resultado.stderr
            )
        )
    return arquivo_de_saida