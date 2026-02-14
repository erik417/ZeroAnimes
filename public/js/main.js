document.addEventListener('DOMContentLoaded', () => {
  const toggle = document.getElementById('themeToggle');
  if (toggle) {
    const updateToggle = () => {
      const isDark = document.documentElement.classList.contains('dark');
      toggle.textContent = isDark ? '☀️' : '🌙';
      const title = isDark ? 'Светлая тема' : 'Тёмная тема';
      toggle.setAttribute('title', title);
      toggle.setAttribute('aria-label', title);
    };
    updateToggle();
    toggle.addEventListener('click', () => {
      const isDark = document.documentElement.classList.toggle('dark');
      localStorage.setItem('theme', isDark ? 'dark' : 'light');
      updateToggle();
    });
  }
  const slider = document.getElementById('bannerSlider');
  if (slider) {
    const slides = Array.from(slider.querySelectorAll('.slide'));
    let idx = 0;
    if (slides.length) {
      slides.forEach((s, i) => {
        s.style.transform = `translateX(${i * 100}%)`;
      });
      setInterval(() => {
        idx = (idx + 1) % slides.length;
        slides.forEach((s, i) => {
          s.style.transform = `translateX(${(i - idx) * 100}%)`;
        });
      }, 4000);
    }
  }
});
