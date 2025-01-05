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
            switch (event.target.id) {
                case 'aesForm':
                    handleAes(formData, resultDiv);
                    break;
                case 'shaForm':
                    handleSha(formData, resultDiv);
                    break;
                case 'md5Form':
                    handleMd5(formData, resultDiv);
                    break;
                case 'base64HexConverterForm':
                    handleBase64HexConversion(formData, resultDiv);
                    break;
                default:
                    resultDiv.textContent = "未实现的功能";
                    resultDiv.style.color = 'red';
            }
        } catch (error) {
            resultDiv.textContent = `错误: ${error.message}`;
            resultDiv.style.color = 'red';
        }
    }

    function handleAes(formData, resultDiv) {
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
    }

    function handleSha(formData, resultDiv) {
        const algorithm = formData.get('algorithm');
        const data = formData.get('data');
        let hash;

        switch (algorithm) {
            case 'sha256':
                hash = CryptoJS.SHA256(data).toString();
                break;
            case 'sha512':
                hash = CryptoJS.SHA512(data).toString();
                break;
            default:
                throw new Error("不支持的 SHA 算法");
        }

        resultDiv.textContent = `哈希值: ${hash}`;
        resultDiv.style.color = 'green';
    }

    function handleMd5(formData, resultDiv) {
        const data = formData.get('data');
        const hash = CryptoJS.MD5(data).toString();
        resultDiv.textContent = `MD5 哈希值: ${hash}`;
        resultDiv.style.color = 'green';
    }

    function handleBase64HexConversion(formData, resultDiv) {
        const value = formData.get('value');
        const direction = formData.get('direction');

        if (direction === 'toBase64') {
            resultDiv.textContent = `Base64 编码: ${btoa(value)}`;
        } else if (direction === 'toHex') {
            resultDiv.textContent = `Hex 编码: ${Array.from(value).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('')}`;
        } else {
            throw new Error("无效的方向");
        }

        resultDiv.style.color = 'green';
    }

    // Placeholder functions for other features
    function handleRsa(formData, resultDiv) {
        resultDiv.textContent = "RSA 加密/解密功能待实现";
        resultDiv.style.color = 'orange';
    }

    function handleKeccak(formData, resultDiv) {
        resultDiv.textContent = "Keccak 加密功能待实现";
        resultDiv.style.color = 'orange';
    }

    function handleHmac(formData, resultDiv) {
        resultDiv.textContent = "HMAC 加密功能待实现";
        resultDiv.style.color = 'orange';
    }

    function handleCrc32(formData, resultDiv) {
        resultDiv.textContent = "CRC32 校验和功能待实现";
        resultDiv.style.color = 'orange';
    }

    function handleRabbit(formData, resultDiv) {
        resultDiv.textContent = "Rabbit 加密/解密功能待实现";
        resultDiv.style.color = 'orange';
    }

    function handleRc4(formData, resultDiv) {
        resultDiv.textContent = "RC4 加密/解密功能待实现";
        resultDiv.style.color = 'orange';
    }

    function handleDes(formData, resultDiv) {
        resultDiv.textContent = "DES 加密/解密功能待实现";
        resultDiv.style.color = 'orange';
    }

    function handleTripleDes(formData, resultDiv) {
        resultDiv.textContent = "TripleDES 加密/解密功能待实现";
        resultDiv.style.color = 'orange';
    }

    function handleTwentyFourCharEncryption(formData, resultDiv) {
        resultDiv.textContent = "24字加密功能待实现";
        resultDiv.style.color = 'orange';
    }

    function handleJwtDecoding(formData, resultDiv) {
        const token = formData.get('token');
        try {
            const decoded = JSON.parse(atob(token.split('.')[1]));
            resultDiv.textContent = `JWT 解码: ${JSON.stringify(decoded)}`;
            resultDiv.style.color = 'green';
        } catch (error) {
            resultDiv.textContent = "无效的 JWT 令牌";
            resultDiv.style.color = 'red';
        }
    }

    function handleEmailEncoding(formData, resultDiv) {
        const email = formData.get('email');
        resultDiv.textContent = `编码后的邮箱: ${btoa(email)}`;
        resultDiv.style.color = 'green';
    }

    function handleCalculator(formData, resultDiv) {
        const expression = formData.get('expression');
        try {
            resultDiv.textContent = `结果: ${eval(expression)}`; // Note: Using eval can be dangerous and should be avoided in production
            resultDiv.style.color = 'green';
        } catch (error) {
            resultDiv.textContent = "无效的表达式";
            resultDiv.style.color = 'red';
        }
    }

    function handleSm2(formData, resultDiv) {
        resultDiv.textContent = "SM2 加密/解密功能待实现";
        resultDiv.style.color = 'orange';
    }

    function handleSm4(formData, resultDiv) {
        resultDiv.textContent = "SM4 加密/解密功能待实现";
        resultDiv.style.color = 'orange';
    }
});



