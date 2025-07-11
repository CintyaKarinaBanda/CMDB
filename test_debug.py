#!/usr/bin/env python3
"""
Script de prueba para verificar el debugging del script principal
"""

import subprocess
import sys

def test_script_with_debug():
    """Ejecuta el script principal con debugging para un servicio simple"""
    print("🧪 Ejecutando script con debugging...")
    
    try:
        # Ejecutar solo con EC2 para una prueba rápida
        result = subprocess.run([
            sys.executable, "script.py", 
            "--services", "ec2"
        ], capture_output=True, text=True, timeout=300)
        
        print("📤 STDOUT:")
        print(result.stdout)
        
        if result.stderr:
            print("📥 STDERR:")
            print(result.stderr)
        
        print(f"🔢 Return code: {result.returncode}")
        
        # Analizar la salida para identificar problemas
        if "DEBUG: Error" in result.stdout or "DEBUG: Error" in result.stderr:
            print("❌ Se encontraron errores en el debugging")
        elif "DEBUG: Servicios importados correctamente" in result.stdout:
            print("✅ Importaciones correctas")
        else:
            print("⚠️ No se pudo verificar el estado de las importaciones")
            
    except subprocess.TimeoutExpired:
        print("⏰ El script tardó más de 5 minutos - posible problema de conectividad")
    except Exception as e:
        print(f"💥 Error ejecutando el script: {e}")

if __name__ == "__main__":
    test_script_with_debug()