const toggle = document.getElementById("toggle-form");
const signupForm = document.getElementById("signup-form");
const loginForm = document.getElementById("login-form");
const title = document.getElementById("form-title");
const subtitle = document.getElementById("form-subtitle");
const switchLabel = document.getElementById("switch-label");

/* ✅ SYNC WITH FLASK */
let isLogin = window.initialLoginState === true || window.initialLoginState === "true";

/* =========================
   NAV ACTIVE ON SCROLL
========================= */
const sections = document.querySelectorAll("section[id]");
const navLinks = document.querySelectorAll("nav a");

window.addEventListener("scroll", () => {
    let current = "";

    sections.forEach(section => {
        const sectionTop = section.offsetTop - 120;

        if (window.scrollY >= sectionTop) {
            current = section.getAttribute("id");
        }
    });

    navLinks.forEach(link => {
        link.classList.remove("active");

        if (link.getAttribute("href") === "#" + current) {
            link.classList.add("active");
        }
    });
});

/* =========================
   INITIAL FORM STATE
========================= */
document.addEventListener("DOMContentLoaded", () => {

    if (isLogin) {
        signupForm.style.display = "none";
        loginForm.style.display = "block";

        title.innerText = "Welcome Back";
        subtitle.innerText = "Log in to continue scanning.";
        switchLabel.innerText = "Don't have an account?";
        toggle.innerText = "Sign up";
    } else {
        signupForm.style.display = "block";
        loginForm.style.display = "none";

        title.innerText = "Create Account";
        subtitle.innerText = "Start scanning your system securely.";
        switchLabel.innerText = "Already have an account?";
        toggle.innerText = "Log in";
    }

    /* ✅ ALERT ANIMATION */
    const alertBox = document.getElementById("alert-box");

    if (alertBox) {
        setTimeout(() => {
            alertBox.classList.add("show");
        }, 100);

        setTimeout(() => {
            alertBox.classList.remove("show");
        }, 3000);
    }
});

/* =========================
   FORM TOGGLE (CLICK)
========================= */
toggle.addEventListener("click", () => {
    isLogin = !isLogin;

    if (isLogin) {
        signupForm.classList.add("fade-out");
        setTimeout(() => {
            signupForm.style.display = "none";
            loginForm.style.display = "block";
            loginForm.classList.remove("fade-out");

            title.innerText = "Welcome Back";
            subtitle.innerText = "Log in to continue scanning.";
            switchLabel.innerText = "Don't have an account?";
            toggle.innerText = "Sign up";
        }, 200);
    } else {
        loginForm.classList.add("fade-out");
        setTimeout(() => {
            loginForm.style.display = "none";
            signupForm.style.display = "block";
            signupForm.classList.remove("fade-out");

            title.innerText = "Create Account";
            subtitle.innerText = "Start scanning your system securely.";
            switchLabel.innerText = "Already have an account?";
            toggle.innerText = "Log in";
        }, 200);
    }
});
