const menuToggle = document.querySelector('.menu-toggle');
const navmenu= document.querySelector('.navmenu');

menuToggle.addEventListener('click', () => {
    navmenu.classList.toggle('active');
});
