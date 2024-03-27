document.getElementById('login-link').addEventListener('click', function(event) {
    event.preventDefault();

    var username = sessionStorage.getItem('username');

    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/check_admin_status');
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.onload = function() {
        if (xhr.status === 200) {
            var response = JSON.parse(xhr.responseText);
            if (response.is_admin) {
                window.location.href = '/login';
            } else {
                alert('Only admins can login through this link.');
            }
        } else {
            alert('Error checking admin status.');
        }
    };
    xhr.send(JSON.stringify({ username: username }));
});
