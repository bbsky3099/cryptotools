document.addEventListener('DOMContentLoaded', function() {
    const toolLinks = document.querySelectorAll('.tool-icons a');
    toolLinks.forEach(link => {
        link.addEventListener('click', function(event) {
            event.preventDefault();
            const tool = this.getAttribute('data-tool');
            loadTool(tool);
        });
    });

    // Load default tool (e.g., RSA)
    loadTool('rsa');
});

function loadTool(tool) {
    fetch(`tools/${tool}.html`)
        .then(response => response.text())
        .then(data => {
            document.getElementById('tool-content').innerHTML = data;
        })
        .catch(error => console.error('Error loading tool:', error));
}