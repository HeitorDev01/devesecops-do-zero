"""
Scanner de segredos — etapa 6.

Cada achado agora é um dicionario com compos nomeados, sempre os mesmos. É esse formato que vai permitir, mais adiante,
que o Bandit e o pip-audit conversem com o mesmo motor de politica
"""

import os
import re

PADROES = [
    {
        "nome": "Chave de acesso da AWS",
        "regex": r"AKIA[A-Z0-9]{16}",
        "gravidade": "ALTA",
        "correcao": "Revogue a chave no console da AWS e use IAM Roles ou variáveis de ambiente.",
    },
    {
        "nome": "Chave privada (RSA/SSH/EC)",
        "regex": r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
        "gravidade": "ALTA",
        "correcao": "Gere um novo par de chaves e guarde a privada em um cofre de segredos.",
    },
    {
        "nome": "Token de bot do Slack",
        "regex": r"xox[baprs]-[0-9A-Za-z-]{10,}",
        "gravidade": "ALTA",
        "correcao": "Revogue o token no painel do Slack e recrie-o como variável de ambiente.",
    },
    {
        "nome": "Senha ou token escrito no código",
        "regex": r"(?i)[a-z0-9_.-]*(?:senha|password|token|secret|api[_-]?key)[a-z0-9_.-]*\s*=\s*[\"'][^\"'\s]{6,}[\"']",
        "gravidade": "MEDIA",
        "correcao": "Troque o valor por os.environ['NOME_DA_VARIAVEL'] e cadastre o segredo no CI.",
    },
]

for _padrao in PADROES:
    _padrao["compilado"] = re.compile(_padrao["regex"])

PASTAS_IGNORADAS = [".git", ".venv", "__pycache__"]

PALAVRAS_DE_EXEMPLO = [
    "exemplo", "example", "sua_", "seu_", "your_",
    "changeme", "troque", "placeholder", "dummy", "fake",
    "xxxxx", "<", "{{", "os.environ", "getenv",
]

MARCADOR_DE_EXCECAO = "# segredo-ok"

def mascarar(texto):
    """Mantem ops quatro primeiros caracteres e esconde o resto. """
    if len(texto) <= 4:
        return "*" * len(texto)

    return texto[:4] + "*" * (len(texto) - 4)

def parece_exemplo(trecho):
    """Devolve true se o trecho tem cara de placehoder, nao de segredo"""
    trecho_minusculo = trecho.lower()

    for palavra in PALAVRAS_DE_EXEMPLO:
        if palavra in trecho_minusculo:
            return True

    return False


def verificar_linha(linha, numero_da_linha, caminho):
    """ Devolve uma lista de (gravidade, nome_do_padrao, trecho)."""
    achados = []

    if MARCADOR_DE_EXCECAO in linha:
        return achados 

    for padrao in PADROES:
        for encontrado in padrao ["compilado"].finditer(linha):
            trecho = encontrado.group(0)

            if parece_exemplo(trecho):
                continue

            achados.append({
                "ferramenta": "scanner-de-segredos",
                "tipo": "segredo",
                "gravidade": padrao["gravidade"],
                "titulo": padrao["nome"],
                "arquivo": caminho,
                "linha": numero_da_linha,
                "detalhe": "Valor encontrado: " + mascarar(trecho),
                "correcao": padrao["correcao"],
            })

    return achados 

def verificar_arquivo(caminho):
    """Devolve todos os achados deste arquivo."""
    achados = []

    with open(caminho, "r", encoding="utf-8", errors="ignore") as arquivo:
        for numero, linha in enumerate(arquivo, start=1):
               achados.extend(verificar_linha(linha, numero, caminho))
    return achados


def escanear(raiz, ignorar_caminho=None):
    """Percorre a árvore de pastas e devolve todos os achados."""
    if ignorar_caminho is None:
        ignorar_caminho = PASTAS_IGNORADAS
        
    achados = []

    for pasta_atual, subpastas, arquivos in os.walk(raiz):
        subpastas[:] = [p for p in subpastas if p not in PASTAS_IGNORADAS]

        for nome_do_arquivo in arquivos:
            caminho = os.path.join(pasta_atual, nome_do_arquivo)
            achados.extend(verificar_arquivo(caminho))

    return achados


if __name__ == "__main__":
    resultados = escanear(".")

    print("Segredos encontrados:", len(resultados))
    print("")

    for achado in resultados:
        print("[{}] {}:{}".format(
            achado["gravidade"], achado["arquivo"], achado["linha"]))
        print("    {}".format(achado["titulo"]))
        print("    {}".format(achado["detalhe"]))
        print("    Como corrigir: {}".format(achado["correcao"]))
        print("")