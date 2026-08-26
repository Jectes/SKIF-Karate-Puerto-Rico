const toggle = document.querySelector('[data-nav-toggle]');
const nav = document.querySelector('[data-nav]');
if (toggle && nav) {
  toggle.addEventListener('click', () => {
    const isOpen = nav.classList.toggle('is-open');
    toggle.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
  });
}

document.querySelectorAll('.site-nav a').forEach(link => {
  link.addEventListener('click', () => {
    if (nav) nav.classList.remove('is-open');
    if (toggle) toggle.setAttribute('aria-expanded', 'false');
  });
});

const observer = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) entry.target.classList.add('is-visible');
  });
}, { threshold: 0.12 });

document.querySelectorAll('.reveal').forEach(el => observer.observe(el));

document.querySelectorAll('[data-portal-tab]').forEach(button => {
  button.addEventListener('click', () => {
    const view = button.dataset.portalTab;
    document.querySelectorAll('[data-portal-tab]').forEach(btn => btn.classList.remove('is-active'));
    document.querySelectorAll('[data-portal-view]').forEach(panel => panel.classList.remove('is-active'));
    button.classList.add('is-active');
    const target = document.querySelector(`[data-portal-view="${view}"]`);
    if (target) target.classList.add('is-active');
  });
});

const form = document.querySelector('[data-contact-form]');
const status = document.querySelector('[data-form-status]');
if (form && status) {
  form.addEventListener('submit', (event) => {
    event.preventDefault();
    status.textContent = 'Demo form only — connect this form to email or a backend before launch.';
    form.reset();
  });
}

document.querySelectorAll('[data-year]').forEach(el => el.textContent = new Date().getFullYear());

if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('service-worker.js').catch(() => {});
  });
}
