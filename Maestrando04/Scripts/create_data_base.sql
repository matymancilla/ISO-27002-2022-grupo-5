CREATE DATABASE LaboratorioISO;
GO

USE LaboratorioISO;
GO

CREATE TABLE dbo.Usuarios (
    UsuarioId INT IDENTITY PRIMARY KEY,
    NombreUsuario NVARCHAR(50) NOT NULL UNIQUE,
    PasswordHash NVARCHAR(255) NOT NULL,
    Rol VARCHAR(20) NOT NULL
        CHECK (Rol IN ('administrador', 'consulta')),
    Activo BIT NOT NULL DEFAULT 1
);

CREATE TABLE dbo.Estudiantes (
    EstudianteId INT IDENTITY PRIMARY KEY,
    Nombre NVARCHAR(100) NOT NULL,
    Carrera NVARCHAR(100) NOT NULL
);

INSERT INTO dbo.Estudiantes (Nombre, Carrera)
VALUES
    (N'Estudiante de prueba 1', N'Ingeniería en Sistemas'),
    (N'Estudiante de prueba 2', N'Administración');