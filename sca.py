"""
SCA - Softwere Composition Analysis

A ferramneta é o pip-audit, que compara as versoes do requirements.txt
com banco de dados público de vulnerabilidade (OSV / PyPI Advisory Database).

Detalhe do mundo real: o pip-audit NAO devolve gravidade. Ele devolve o identificador
da falha e as versoes que corrigem. Por isso a política para SCA conta números,
em vez de gravidade.

"""

import json
import os
import shutil
import subprocess

def pip_audit_esta_instalado():
    return shutil.which("pip-audit") is not None


def executar_pip_audit(arquivo_de_dependencias, arquivo_de_saida, tempo_limites=180):
    """Roda o pip-audit sobre o requirmentos.txt e salva o JSON"""
    os.makedirs(os.path.dirname(arquivo_de_saida), exist_ok=True)

    comando =[
        "pip-audit",
        "-r", arquivo_de_dependencias,
        "-f", "json",
        "-o", arquivo_de_saida,
    ]

    try:
        resultado = subprocess.run(
            comando,
            capture_output=True, 
            text=True, 
            timeout=tempo_limites
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            "pip-audit passou de {}s. Rede indiponível?".format(tempo_limites)
        )

    if resultado.returncode not in (0, 1):
        raise RuntimeError(
            "pip-audit falhou (código {}):\n{}".format(
                resultado.returncode, resultado.stderr
            )
        )

    return arquivo_de_saida

def normalizar(arquivo_de_saida, arquivo_de_dependencias="requirements.txt"):
    """Converte o JSON do pip-audit para o NOSSO formato de achados."""
    with open(arquivo_de_saida, "r", encoding="utf-8") as arquivo:
        dados = json.load(arquivo)

        achados = []

        for dependencia in dados.get("dependencies", []):
            nome = dependencia.get("nome")
            versao = dependencia.get("version")

            for vulnerabilidade in dependencia.get("vulns", []):
                correcoes = vulnerabilidade.get("fix_versions", [])

                if correcoes:
                    texto_da_correcao = "Atualize {} para {}".format(
                        nome, " ou ".join(correcoes)
                        )
                else:
                    texto_da_correcao = (
                        "Ainda nao ha versao corrigida. Avalie trocar a "
                        "bliblioteca ou aplicar mitigaça"
                    )
                descricao = (vulnerabilidade.get("description") or "").strip()
                descricao = " ".join(descricao.split())
                if len(descricao) > 160:
                    descricao = descricao[:160] + "..."

                achados.append({
                    "ferramenta": "pip-audit",
                    "tipo": "dependencia",
                    "gravidade": "DESCONHECIDA",
                    "titulo": "{} {} — {}".format(nome, versao, vulnerabilidade.get("id")),
                    "arquivo": arquivo_de_dependencias,
                    "linha": 0,
                    "detalhe": descricao,
                    "correcao": texto_da_correcao,
                    "tem_correcao": bool(correcoes),
                })

        return achados

def rodar(arquivo_de_dependencias="requirements.txt",
          arquivo_de_saida="reports/pip-audit.json",):
    if not pip_audit_esta_instalado():
        print("     [aviso] pip-audit nao encontrado. Etapa do SCA pulada.")
        return []

    if not os.path.exists(arquivo_de_dependencias):
        print("     [aviso] {} nao existe. Etapa do SCA pulada.".format(
            arquivo_de_dependencias
        ))
        return []

    executar_pip_audit(arquivo_de_dependencias, arquivo_de_saida)
    return normalizar(arquivo_de_saida, arquivo_de_dependencias)

if __name__ == "__main__":
    achados = rodar()
    print("Vulnerabilidades encontradas:", len(achados))
    for achado in achados[:5]:
        print("-", achado["titulo"], "|", achado["correcao"])