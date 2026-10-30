const menuButton = document.querySelector(".menu-toggle");
const menu = document.querySelector(".nav-links");
const mobileMenuQuery = window.matchMedia("(max-width: 760px)");
const adminNavItem = document.getElementById("admin-nav-item");

if (adminNavItem) {
    fetch("/api/admin/session", {
        headers: { Accept: "application/json" }
    })
        .then(response => {
            if (response.ok) {
                adminNavItem.hidden = false;
            }
        })
        .catch(error => {
            console.warn("Não foi possível verificar a sessão administrativa.", error);
        });
}

function setMenuOpen(open) {
    if (!menuButton || !menu) return;

    menu.classList.toggle("active", open);
    menuButton.setAttribute("aria-expanded", String(open));
    menuButton.setAttribute(
        "aria-label",
        open ? "Fechar menu" : "Abrir menu"
    );
}

if (menuButton && menu) {
    menuButton.addEventListener("click", () => {
        const isOpen = menuButton.getAttribute("aria-expanded") === "true";
        setMenuOpen(!isOpen);
    });

    menu.querySelectorAll("a").forEach(link => {
        link.addEventListener("click", () => setMenuOpen(false));
    });

    document.addEventListener("click", event => {
        if (
            mobileMenuQuery.matches &&
            menuButton.getAttribute("aria-expanded") === "true" &&
            !menu.contains(event.target) &&
            !menuButton.contains(event.target)
        ) {
            setMenuOpen(false);
        }
    });

    document.addEventListener("keydown", event => {
        if (
            event.key === "Escape" &&
            menuButton.getAttribute("aria-expanded") === "true"
        ) {
            setMenuOpen(false);
            menuButton.focus();
        }
    });

    mobileMenuQuery.addEventListener("change", () => setMenuOpen(false));
}

const saudacao = document.getElementById("saudacao");

if (saudacao) {
    const hora = new Date().getHours();
    const periodo = hora >= 5 && hora < 12
        ? "Bom dia"
        : hora >= 12 && hora < 18
            ? "Boa tarde"
            : "Boa noite";

    saudacao.textContent = `${periodo}! Seja bem-vindo.`;
}

const themeButton = document.getElementById("theme-toggle");

function getSavedTheme() {
    try {
        return localStorage.getItem("tema");
    } catch (error) {
        if (error instanceof DOMException && error.name === "SecurityError") {
            console.warn("Não foi possível acessar o tema salvo.", error);
            return null;
        }

        throw error;
    }
}

function saveTheme(theme) {
    try {
        localStorage.setItem("tema", theme);
    } catch (error) {
        if (error instanceof DOMException && error.name === "SecurityError") {
            console.warn("Não foi possível salvar a preferência de tema.", error);
            return;
        }

        throw error;
    }
}

function updateThemeButton(isLight) {
    if (!themeButton) return;

    themeButton.textContent = isLight ? "🌙" : "☀️";
    themeButton.setAttribute(
        "aria-label",
        isLight ? "Ativar modo escuro" : "Ativar modo claro"
    );
}

if (themeButton) {
    const savedTheme = getSavedTheme();
    const isLight = savedTheme === "claro";

    document.body.classList.toggle("light-theme", isLight);
    updateThemeButton(isLight);

    themeButton.addEventListener("click", () => {
        const nextIsLight = !document.body.classList.contains("light-theme");

        document.body.classList.toggle("light-theme", nextIsLight);
        updateThemeButton(nextIsLight);
        saveTheme(nextIsLight ? "claro" : "escuro");
    });
}

const yearElement = document.getElementById("ano");

if (yearElement) {
    yearElement.textContent = new Date().getFullYear();
}

const backToTopLink = document.querySelector('footer a[href="#topo"]');

if (backToTopLink) {
    backToTopLink.addEventListener("click", event => {
        event.preventDefault();
        window.scrollTo({
            top: 0,
            behavior: "smooth"
        });
    });
}
