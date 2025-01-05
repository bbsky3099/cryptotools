document.addEventListener('DOMContentLoaded', () => {
    const links = document.querySelectorAll('nav a');
    const contentContainer = document.getElementById('content-container');

    // 处理初始页面加载
    loadContent(window.location.hash);

    window.addEventListener('popstate', () => {
        loadContent(window.location.hash);
    });

    links.forEach(link => {
        link.addEventListener('click', (event) => {
            event.preventDefault();
            const hash = link.getAttribute('href').substring(1); // Remove the '#' character
            history.pushState({}, '', `#${hash}`);
            loadContent(`#${hash}`);
        });
    });

    function loadContent(hash) {
        if (!hash || hash === '#') {
            contentContainer.innerHTML = '<p>请选择一个工具。</p>';
            return;
        }

        const pageName = hash.substring(1) + '.html';
        fetch(pageName)
            .then(response => {
                if (!response.ok) {
                    throw new Error(`Network response was not ok for ${pageName}: ${response.statusText}`);
                }
                return response.text();
            })
            .then(data => {
                contentContainer.innerHTML = data;
                // Reattach event listeners to new form elements
                attachEventListeners();
            })
            .catch(error => {
                contentContainer.innerHTML = `<p>无法加载页面: ${error.message}</p>`;
            });
    }

    function attachEventListeners() {
        const forms = contentContainer.querySelectorAll('form');
        forms.forEach(form => {
            form.addEventListener('submit', handleFormSubmit);
        });
    }

    function handleFormSubmit(event) {
        event.preventDefault();
        const formData = new FormData(event.target);
        const resultDiv = event.target.querySelector('#result');
        
        try {
            const formId = event.target.id;
            switch (formId) {
                case 'aesForm':
                    const mode = formData.get('mode');
                    const data = formData.get('data');
                    const key = formData.get('key');
                    
                    if (mode === 'encrypt') {
                        const encryptedData = CryptoJS.AES.encrypt(data, key).toString();
                        resultDiv.textContent = `加密后的数据: ${encryptedData}`;
                        resultDiv.style.color = 'green';
                    } else if (mode === 'decrypt') {
                        const decryptedBytes = CryptoJS.AES.decrypt(data, key);
                        const decryptedData = decryptedBytes.toString(CryptoJS.enc.Utf8);
                        resultDiv.textContent = `解密后的数据: ${decryptedData}`;
                        resultDiv.style.color = 'green';
                    }
                    break;
                
                case 'rsaForm':
                    // Add RSA encryption/decryption logic here
                    break;
                
                case 'shaForm':
                    // Add SHA encryption logic here
                    break;
                
                // Add more cases for other forms as needed
                default:
                    resultDiv.textContent = `未知的表单类型: ${formId}`;
                    resultDiv.style.color = 'red';
            }
        } catch (error) {
            resultDiv.textContent = `错误: ${error.message}`;
            resultDiv.style.color = 'red';
        }
    }
});