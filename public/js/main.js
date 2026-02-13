document.addEventListener('DOMContentLoaded', () => {
  const toggle = document.getElementById('themeToggle');
  if (toggle) {
    toggle.addEventListener('click', () => {
      const isDark = document.documentElement.classList.toggle('dark');
      localStorage.setItem('theme', isDark ? 'dark' : 'light');
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

