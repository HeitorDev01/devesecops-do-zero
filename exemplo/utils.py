"""Funçoes auxiliares - este aquivos esta limpo. """

import os

def caminho_do_cache():
    return os.environ.get("CACHE_DIR", "/tmp")