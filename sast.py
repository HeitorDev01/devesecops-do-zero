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

def normalizar(arquivo_de_saida):
    """"
    Lê o JSON do Bandit e devolve achados no NOSSO formato
    
    """
    with open(arquivo_de_saida, "r", encoding="utf-8") as arquivo:
        dados = json.load(arquivo)

    achados = []

    for item in dados.get("results", []):
        gravidade_original = item.get("issue_severity", "LOW")

        achados.append({
            "ferramenta": "bandit",
            "tipo": "codigo",
            "gravidade": TRADUCAO_DE_GRAVIDADE.get(gravidade_original, "BAIXA"),
            "titulo": "{} — {}".format(item.get("test_id"), item.get("test_name")),
            "arquivo": item.get("filename"),
            "linha": item.get("line_number"),
            "detalhe": "{} (confiança: {})".format(
                item.get("issue_text"), item.get("issue_confidence")
            ),
            "correcao": "Detalhes e como corrigir: " + item.get("more_info", ""),
        })

    return achados

def rodar(pasta_alvo="app", arquivo_de_saida="reports/bandit.jason"):
    """"Executa e já devolve normalizado"""
    if not bandit_esta_instalado():
        print(" [aviso] Bandit não encontrado. Etapa de SAST pulada.")
        print("         Instale com: pip install bandit")
        return []

    executar_bandit(pasta_alvo, arquivo_de_saida)
    return normalizar(arquivo_de_saida)

if __name__ == "__main__":
    for achado in rodar():
        print("[{}] {}:{}  {}".format(
            achado["gravidade"],
            achado["arquivo"],
            achado["linha"],
            achado["titulo"]
        ))
''