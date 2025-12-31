document.addEventListener('DOMContentLoaded', function() {
    
    // 1. Theme Toggle Logic
    const themeBtn = document.getElementById("themeToggle");
    const body = document.body;

    // التحقق من الوضع المحفوظ سابقاً
    const savedTheme = localStorage.getItem("theme");
    
    if (savedTheme === "light") {
        body.classList.add("light-mode");
        if(themeBtn) themeBtn.textContent = "☀️";
    } else {
        body.classList.remove("light-mode");
        if(themeBtn) themeBtn.textContent = "🌙";
    }

    // عند الضغط على الزر
    if (themeBtn) {
        themeBtn.addEventListener("click", () => {
            body.classList.toggle("light-mode");

            if (body.classList.contains("light-mode")) {
                themeBtn.textContent = "☀️";
                localStorage.setItem("theme", "light");
            } else {
                themeBtn.textContent = "🌙";
                localStorage.setItem("theme", "dark");
            }
        });
    }

    // 2. Auto-hide Flash Messages (إخفاء رسائل التنبيه تلقائياً بعد 4 ثواني)
    const flashMessages = document.querySelectorAll('.flash-msg');
    if (flashMessages.length > 0) {
        setTimeout(() => {
            flashMessages.forEach(msg => {
                msg.style.opacity = '0';
                setTimeout(() => msg.remove(), 500);
            });
        }, 4000);
    }
});