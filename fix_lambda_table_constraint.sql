-- Script para corregir el constraint de la tabla lambda_functions
-- Cambiar de UNIQUE(functionname) a UNIQUE(functionname, accountid, region)

-- 1. Eliminar el constraint actual
ALTER TABLE lambda_functions DROP CONSTRAINT IF EXISTS lambda_functions_functionname_key;

-- 2. Eliminar duplicados existentes (mantener solo el más reciente por función)
DELETE FROM lambda_functions 
WHERE ctid NOT IN (
    SELECT DISTINCT ON (functionname, accountid, region) ctid
    FROM lambda_functions 
    ORDER BY functionname, accountid, region, last_updated DESC NULLS LAST
);

-- 3. Crear el nuevo constraint compuesto
ALTER TABLE lambda_functions 
ADD CONSTRAINT lambda_functions_unique_key 
UNIQUE (functionname, accountid, region);

-- 4. Verificar el resultado
SELECT 'Constraint actualizado correctamente' as status;

-- 5. Mostrar estadísticas
SELECT 
    'Total de funciones Lambda después de limpieza:' as descripcion,
    COUNT(*) as total 
FROM lambda_functions;