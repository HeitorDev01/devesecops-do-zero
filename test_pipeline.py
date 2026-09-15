"""

Teste automatico

Por que testar um ferramenta de segurança? Porque um scanner
quebrado que devolve zero achados parece exatamente com um projeto
seguro. O tste é o que separa "não encontrou nada" para "não procurou nada"

Rode com : pytest -v
"""

import politica
import relatorio
import sast
import scanner

def test_encontra_chave_da_aws():
    achados = scanner.verfificar_linha(
        'CHAVE = "AKIA4KJH2LKJ3HGF9DSA"', 1, "teste.py")

    assert len(achados) >= 1
    assert achados[0]["gravidade"] == "ALTA"

def test_encontra_chave_privada():
    achados = scanner.verificar_linha(
         "-----BEGIN RSA PRIVATE KEY-----", 1, "chave.pem"
    )

    assert len(achados) == 1
    assert achados[0]["titulo"] == "Chave privada (RSA/SSH/EC)"

def test_acha_duas_chaves_na_mesma_linha():
    achados = scanner.verificar_linha(
        'A = ["AKIAQWERTY0987POIUYX", "AKIAMNBVCXZ123456789"]', 1, "teste.py")

    assert len(achados) == 2

def test_ignora_placeholder():
    achados = scanner.verificar_linha(
        'SENHA = "SUA_SENHA_AQUI"', 1, "teste.py")

    assert achados == []

def test_ignorar_variavel_de_ambiente():
    achados = scanner.verificar_linha(
        'TOKEN = os.environ["APP_TOKEN"]', 1, "teste.py"
    )

    assert achados == []

def test_respeita_o_marcador_de_excecao():
    achados = scanner.verificar_linha(
        'CHAVE = "AKIA4KJH2LKJ3HGF9DSA"  # segredo-ok', 1, "teste.py"
    )

    assert achados == []

def test_mascar_esconde_o_valor ():
    mascarado = scanner.mascarar("AKIA4KJH2LKJ3HGF9DSA")

    assert mascarado.startswith("AIKA")
    assert "4KJH2LKJ3HGF9DSA" not in mascarado
    assert len(mascarado) == 20

def test_mascara_lida_com_texto_curto():
    assert scanner.mascarar("abc") == "***"

def achado_falso(tipo="segredo", gravidade="ALTA"):
    """Monta um achado de mentira, para testar a política isolada."""
    return {
        "ferramenta": "teste",
        "tipo": tipo,
        "gravidade": gravidade,
        "titulo": "achado de teste",
        "arquivo": "teste.py",
        "linha": 1,
        "detalhe": "",
        "correcao": "",
    } 