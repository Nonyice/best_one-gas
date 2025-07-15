const menuToggle = document.querySelector('.menu-toggle');
const navmenu_2 = document.querySelector('.navmenu_2');

menuToggle.addEventListener('click', () => {
    navmenu_2.classList.toggle('active');
});