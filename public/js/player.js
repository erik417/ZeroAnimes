document.addEventListener('DOMContentLoaded', () => {
  const video = document.getElementById('player');
  const qualitySelect = document.getElementById('quality');
  if (!video || !qualitySelect) return;

  const sources = Array.from(video.querySelectorAll('source'));
  sources.forEach((s, i) => {
    const opt = document.createElement('option');
    opt.value = s.src;
    opt.textContent = s.dataset.quality || `Q${i + 1}`;
    qualitySelect.appendChild(opt);
  });
  if (sources[0]) {
    qualitySelect.value = sources[sources.length - 1].src;
    video.src = qualitySelect.value;
    video.load();
  }

  qualitySelect.addEventListener('change', () => {
    const time = video.currentTime;
    const playing = !video.paused;
    video.src = qualitySelect.value;
    video.load();
    video.addEventListener('loadedmetadata', () => {
      video.currentTime = time;
      if (playing) video.play();
    }, { once: true });
  });

  const key = `progress:${window.__EPISODE_ID__ || 'unknown'}`;
  const saved = localStorage.getItem(key);
  if (saved) {
    video.currentTime = Number(saved);
  }
  const saveProgress = () => {
    if (!window.__EPISODE_ID__) return;
    localStorage.setItem(key, String(video.currentTime));
    if (window.__IS_AUTH__) {
      fetch('/progress', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ episode_id: window.__EPISODE_ID__, last_time: video.currentTime })
      });
    }
  };
  let lastSave = 0;
  video.addEventListener('timeupdate', () => {
    const now = Date.now();
    if (now - lastSave > 8000) {
      saveProgress();
      lastSave = now;
    }
  });
  video.addEventListener('ended', () => {
    saveProgress();
    if (window.__NEXT_URL__) window.location.href = window.__NEXT_URL__;
  });
});
