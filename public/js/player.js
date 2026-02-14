document.addEventListener('DOMContentLoaded', () => {
  const video = document.getElementById('player');
  const qualitySelect = document.getElementById('quality');
  if (!video || !qualitySelect) return;

  const sources = Array.from(video.querySelectorAll('source'));
  const controls = document.querySelector('.controls');
  const qualityLabel = document.querySelector('label[for="quality"]');
  sources.forEach((s, i) => {
    const opt = document.createElement('option');
    opt.value = s.src;
    opt.textContent = s.dataset.quality || `Q${i + 1}`;
    qualitySelect.appendChild(opt);
  });
  if (!sources.length) {
    if (controls) controls.style.display = 'none';
    return;
  }
  if (sources.length === 1) {
    if (qualitySelect) qualitySelect.style.display = 'none';
    if (qualityLabel) qualityLabel.style.display = 'none';
  }
  const setVideoSource = (src, time, playing) => {
    video.src = src;
    video.load();
    video.addEventListener(
      'loadedmetadata',
      () => {
        if (Number.isFinite(time)) {
          const duration = video.duration || 0;
          const safeTime = duration ? Math.min(time, Math.max(0, duration - 0.5)) : time;
          if (safeTime > 0) video.currentTime = safeTime;
        }
        if (playing) video.play();
      },
      { once: true }
    );
  };
  qualitySelect.value = sources[sources.length - 1].src;

  qualitySelect.addEventListener('change', () => {
    const time = video.currentTime;
    const playing = !video.paused;
    setVideoSource(qualitySelect.value, time, playing);
  });

  const key = `progress:${window.__EPISODE_ID__ || 'unknown'}`;
  const seekToast = document.getElementById('seekToast');
  let toastTimer = null;
  const saved = localStorage.getItem(key);
  let savedTime = saved ? Number(saved) : null;
  if (!Number.isFinite(savedTime)) savedTime = null;
  setVideoSource(qualitySelect.value, savedTime, false);
  const saveProgress = () => {
    if (!window.__EPISODE_ID__) return;
    if (!Number.isFinite(video.currentTime)) return;
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
  window.addEventListener('pagehide', saveProgress);

  const showSeekToast = (text) => {
    if (!seekToast) return;
    seekToast.textContent = text;
    seekToast.classList.add('show');
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      seekToast.classList.remove('show');
    }, 700);
  };

  const isEditableTarget = (target) => {
    if (!target) return false;
    if (target.isContentEditable) return true;
    const tag = target.tagName;
    return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || tag === 'BUTTON';
  };

  document.addEventListener('keydown', (e) => {
    if (!video) return;
    if (isEditableTarget(e.target)) return;
    if (e.key === 'ArrowRight') {
      e.preventDefault();
      video.currentTime = Math.min(video.duration || Infinity, video.currentTime + 10);
      showSeekToast('>> 10 секунд');
    } else if (e.key === 'ArrowLeft') {
      e.preventDefault();
      video.currentTime = Math.max(0, video.currentTime - 10);
      showSeekToast('<< 10 секунд');
    } else if (e.code === 'Space' || e.key === ' ') {
      if (e.repeat) return;
      e.preventDefault();
      e.stopPropagation();
      if (video.paused) {
        video.play();
      } else {
        video.pause();
      }
    }
  }, { capture: true });

  document.addEventListener('keyup', (e) => {
    if (!video) return;
    if (isEditableTarget(e.target)) return;
    if (e.code === 'Space' || e.key === ' ') {
      e.preventDefault();
      e.stopPropagation();
    }
  }, { capture: true });
});
