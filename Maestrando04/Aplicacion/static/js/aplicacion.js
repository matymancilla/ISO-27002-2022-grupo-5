"use strict";

const formulario = document.querySelector("[data-login]");
const password = document.querySelector("#password");
const alternar = document.querySelector("[data-password]");
const avisoMayusculas = document.querySelector("[data-caps]");

if (password && alternar) {
    alternar.addEventListener("click", () => {
        const mostrar = password.type === "password";

        password.type = mostrar ? "text" : "password";
        alternar.textContent = mostrar ? "Ocultar" : "Mostrar";
        alternar.setAttribute("aria-pressed", String(mostrar));
        alternar.setAttribute(
            "aria-label",
            mostrar ? "Ocultar contraseña" : "Mostrar contraseña"
        );
    });
}

if (password && avisoMayusculas) {
    const actualizarMayusculas = (evento) => {
        if (typeof evento.getModifierState === "function") {
            avisoMayusculas.hidden =
                !evento.getModifierState("CapsLock");
        }
    };

    password.addEventListener("keydown", actualizarMayusculas);
    password.addEventListener("keyup", actualizarMayusculas);

    password.addEventListener("blur", () => {
        avisoMayusculas.hidden = true;
    });
}

if (formulario) {
    const boton = formulario.querySelector("[data-submit]");
    const texto = formulario.querySelector("[data-submit-text]");
    const estado = formulario.querySelector("[data-estado]");

    formulario.addEventListener("submit", (evento) => {
        if (boton.disabled) {
            evento.preventDefault();
            return;
        }

        boton.disabled = true;
        texto.textContent = "Ingresando...";
        estado.textContent = "Validando credenciales.";
        formulario.setAttribute("aria-busy", "true");
    });

    window.addEventListener("pageshow", () => {
        boton.disabled = false;
        texto.textContent = "Iniciar sesión";
        estado.textContent = "";
        formulario.removeAttribute("aria-busy");
    });
}