function toggleProfile() {
    const box = document.getElementById("profileBox");
    box.classList.toggle("show");
}

// close when clicking outside
window.addEventListener("click", function(e) {
    if (!e.target.closest(".profile-container")) {
        const box = document.getElementById("profileBox");
        if (box) box.classList.remove("show");
    }
});