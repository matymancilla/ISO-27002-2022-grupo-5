-- Proyecto Integrador ISO/IEC 27002:2022
-- Control 8.11: Enmascaramiento de datos
-- Maestrando 2

-- 1. Crear la vista enmascarada para ocultar datos PII
CREATE VIEW students_masked AS
SELECT 
    student_id,
    matricula,
    -- Oculta el apellido, mostrando solo el primer nombre
    SPLIT_PART(full_name, ' ', 1) || ' ***' AS full_name_masked,
    -- Muestra solo las primeras 3 letras del correo
    LEFT(email, 3) || '***@alumnos.nubeuni.edu.lat' AS email_masked,
    career,
    semester,
    gpa,
    financial_status
FROM students;

-- 2. Crear un usuario de prueba con bajos privilegios
CREATE USER soporte_ti WITH PASSWORD 'Admin123!';

-- 3. Darle permiso de lectura SOLO a la vista enmascarada
GRANT SELECT ON students_masked TO soporte_ti;

-- 4. Asegurarnos de que NO tenga permisos sobre la tabla original
REVOKE ALL ON students FROM soporte_ti;

-- 5. Prueba de eficacia: Simular que el usuario intenta ver los datos reales (Esto debe fallar)
-- SET ROLE soporte_ti;
-- SELECT * FROM students; 
-- RESET ROLE;
