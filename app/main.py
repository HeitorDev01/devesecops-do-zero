
import hashlib
import subprocess

import requests
import yaml

def radar_comando(entrada_do_usuario):
    return subprocess.check_output("ls" + entrada_do_usuario, shell=True)

def clacular_hash(senha):
    return hashlib.md5(senha.encode()).hexdigest()

def avaliar_expressao(texto):
    return eval(texto)

def buscar_dados(url):
    return requests.get(url, verify=False)

def ler_configuracao(caminho):
    with open(caminho) as arquivo:
        return yaml.load(arquivo.read())

def salvar_temporario(conteudo):
    with open("/tmp/cache_da_app.txt" , "w") as arquivo:
        arquivo.write(conteudo)