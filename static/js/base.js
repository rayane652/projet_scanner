function toggleProfile() {
    const box = document.getElementById("profileBox");
    box.classList.toggle("show");
}

// close dropdown
window.addEventListener("click", function(e) {
    if (!e.target.closest(".profile-container")) {
        document.getElementById("profileBox")?.classList.remove("show");
    }
});

/* ===== EDIT NAME ===== */

function enableEdit(e) {
    e.stopPropagation();

    const input = document.getElementById("nameInput");
    const text = document.getElementById("nameText");

    input.style.display = "block";
    text.style.display = "none";

    input.focus();
    input.select();
}

function saveName() {
    const input = document.getElementById("nameInput");
    const text = document.getElementById("nameText");
    const topName = document.getElementById("topName");

    if (!input || !text) return;

    let value = input.value.trim();
    if (!value) return;

    // capitalize
    value = value.replace(/\b\w/g, c => c.toUpperCase());

    // update UI
    text.innerText = value;
    if (topName) topName.innerText = value;

    input.style.display = "none";
    text.style.display = "block";

    // 🔥 SEND TO BACKEND
    fetch("/update-name", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ name: value })
    })
    .then(res => res.json())
    .then(data => {
        console.log("Saved:", data);
    })
    .catch(err => {
        console.error("Error:", err);
    });
}

// ENTER = save
document.addEventListener("keydown", function(e) {
    if (e.key === "Enter") saveName();
});

// click outside name = save
document.addEventListener("click", function(e) {
    if (!e.target.closest(".name-row")) {
        const input = document.getElementById("nameInput");
        if (input && input.style.display === "block") {
            saveName();
        }
    }
});