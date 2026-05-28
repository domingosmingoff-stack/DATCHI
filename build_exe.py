#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DATCHILD.exe - ARQUIVO EXECUTÁVEL
Duplo clique e abre automaticamente
"""
import os
import sys
import subprocess
import PyInstaller.main

# Caminho do script DATCHILD.py
script_path = os.path.join(os.path.dirname(__file__), 'DATCHILD.py')

# Comando para gerar EXE
pyinstaller_args = [
    '--onefile',  # Um arquivo só
    '--windowed',  # Sem janela console
    '--icon=DATCHILD.ico',  # Ícone (opcional)
    '--name=DATCHILD',  # Nome do arquivo
    script_path
]

if __name__ == '__main__':
    PyInstaller.main.run(pyinstaller_args)
    print("\n✅ DATCHILD.exe criado com sucesso!")
    print("📁 Localizado em: dist/DATCHILD.exe")
