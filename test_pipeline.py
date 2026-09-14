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
    