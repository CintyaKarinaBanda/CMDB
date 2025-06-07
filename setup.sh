#!/bin/bash

# Instalar dependencias
pip3 install -r requirements.txt

# Hacer ejecutable el script
chmod +x ec2_script.py

echo "Configuración completada. Ahora puedes ejecutar ./ec2_script.py"