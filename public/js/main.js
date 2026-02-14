document.addEventListener('DOMContentLoaded', () => {
  const toggle = document.getElementById('themeToggle');
  if (toggle) {
    const updateToggle = () => {
      const isDark = document.documentElement.classList.contains('dark');
      toggle.innerHTML = isDark
        ? '<svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4" fill="none" stroke-width="2" /><path fill="none" stroke-width="2" d="M12 2v3M12 19v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M2 12h3M19 12h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1" /></svg>'
        : '<svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><path stroke="none" d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z" /></svg>';
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
  const topbar = document.querySelector('.topbar');
  if (topbar) {
    let lastY = window.scrollY;
    const threshold = 10;
    const updateTopbar = () => {
      const y = window.scrollY;
      if (y > lastY + threshold && y > 80) {
        topbar.classList.add('topbar-hidden');
      } else if (y < lastY - threshold) {
        topbar.classList.remove('topbar-hidden');
      }
      lastY = y;
    };
    let ticking = false;
    window.addEventListener(
      'scroll',
      () => {
        if (ticking) return;
        ticking = true;
        window.requestAnimationFrame(() => {
          updateTopbar();
          ticking = false;
        });
      },
      { passive: true }
    );
    window.addEventListener('resize', updateTopbar);
    updateTopbar();
  }
});
