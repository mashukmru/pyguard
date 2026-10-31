const menuButton = document.querySelector('.menu-toggle');
const primaryNav = document.querySelector('.primary-nav');

if (menuButton && primaryNav) {
  menuButton.addEventListener('click', () => {
    const expanded = menuButton.getAttribute('aria-expanded') === 'true';
    menuButton.setAttribute('aria-expanded', String(!expanded));
    menuButton.setAttribute('aria-label', expanded ? 'Open navigation' : 'Close navigation');
    primaryNav.classList.toggle('open', !expanded);
  });
  primaryNav.addEventListener('click', (event) => {
    if (event.target.closest('a') && window.matchMedia('(max-width: 640px)').matches) {
      menuButton.setAttribute('aria-expanded', 'false');
      menuButton.setAttribute('aria-label', 'Open navigation');
      primaryNav.classList.remove('open');
    }
  });
  window.addEventListener('resize', () => {
    if (window.matchMedia('(min-width: 641px)').matches) {
      menuButton.setAttribute('aria-expanded', 'false');
      primaryNav.classList.remove('open');
    }
  });
}
