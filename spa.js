document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', function(event) {
            event.preventDefault();
            const formData = new FormData(this);
            const action = this.getAttribute('data-action');
            
            let result;
            switch (action) {
                case 'aes':
                    result = aesEncryption(formData.get('input'), formData.get('key'));
                    break;
                case 'rsa':
                    result = rsaEncryption(formData.get('input'), formData.get('publicKey'));
                    // Add RSA decryption logic if needed
                    break;
                case 'sha':
                    result = shaHashing(formData.get('input'));
                    break;
                case 'md5':
                    result = md5Hashing(formData.get('input'));
                    break;
                case 'keccak':
                    result = keccakHashing(formData.get('input'));
                    break;
                case 'hmac':
                    result = hmacHashing(formData.get('input'), formData.get('secret'));
                    break;
                case 'crc32':
                    result = crc32Checksum(formData.get('input'));
                    break;
                case 'rabbit':
                    result = rabbitEncryption(formData.get('input'), formData.get('key'));
                    // Add Rabbit decryption logic if needed
                    break;
                case 'rc4':
                    result = rc4Encryption(formData.get('input'), formData.get('key'));
                    // Add RC4 decryption logic if needed
                    break;
                case 'des':
                    result = desEncryption(formData.get('input'), formData.get('key'));
                    // Add DES decryption logic if needed
                    break;
                case 'tripledes':
                    result = tripleDesEncryption(formData.get('input'), formData.get('key'));
                    // Add TripleDES decryption logic if needed
                    break;
                case '24char_encryption':
                    result = twentyFourCharEncryption(formData.get('input'));
                    break;
                case 'jwt':
                    result = jwtDecoding(formData.get('token'));
                    break;
                case 'email_encoder':
                    result = emailEncoding(formData.get('email'));
                    break;
                case 'calculator':
                    result = calculatorEvaluate(formData.get('expression'));
                    break;
                case 'sm2':
                    result = sm2Encryption(formData.get('input'), formData.get('publicKey'));
                    // Add SM2 decryption logic if needed
                    break;
                case 'sm4':
                    result = sm4Encryption(formData.get('input'), formData.get('key'));
                    // Add SM4 decryption logic if needed
                    break;
                case 'base64_hex_converter':
                    result = base64HexConversion(formData.get('value'), formData.get('direction'));
                    break;
                default:
                    result = "未知操作";
            }
            
            document.getElementById('result').textContent = result;
        });
    });

    // Example implementations of the functions
    function aesEncryption(input, key) {
        // AES encryption implementation here
        return `AES 加密: ${input} 使用密钥 ${key}`;
    }

    function rsaEncryption(input, publicKey) {
        // RSA encryption implementation here
        return `RSA 加密: ${input} 使用公钥 ${publicKey}`;
    }

    function shaHashing(input) {
        // SHA hashing implementation here
        return `SHA 哈希: ${input}`;
    }

    function md5Hashing(input) {
        // MD5 hashing implementation here
        return `MD5 哈希: ${input}`;
    }

    function keccakHashing(input) {
        // Keccak hashing implementation here
        return `Keccak 哈希: ${input}`;
    }

    function hmacHashing(input, secret) {
        // HMAC hashing implementation here
        return `HMAC 哈希: ${input} 使用密钥 ${secret}`;
    }

    function crc32Checksum(input) {
        // CRC32 checksum implementation here
        return `CRC32 校验和: ${input}`;
    }

    function rabbitEncryption(input, key) {
        // Rabbit encryption implementation here
        return `Rabbit 加密: ${input} 使用密钥 ${key}`;
    }

    function rc4Encryption(input, key) {
        // RC4 encryption implementation here
        return `RC4 加密: ${input} 使用密钥 ${key}`;
    }

    function desEncryption(input, key) {
        // DES encryption implementation here
        return `DES 加密: ${input} 使用密钥 ${key}`;
    }

    function tripleDesEncryption(input, key) {
        // TripleDES encryption implementation here
        return `TripleDES 加密: ${input} 使用密钥 ${key}`;
    }

    function twentyFourCharEncryption(input) {
        // 24-character encryption implementation here
        return `24字加密: ${input}`;
    }

    function jwtDecoding(token) {
        // JWT decoding implementation here
        try {
            const decoded = JSON.parse(atob(token.split('.')[1]));
            return `JWT 解码: ${JSON.stringify(decoded)}`;
        } catch (error) {
            return "无效的 JWT 令牌";
        }
    }

    function emailEncoding(email) {
        // Email encoding implementation here
        return `编码后的邮箱: ${btoa(email)}`;
    }

    function calculatorEvaluate(expression) {
        // Calculator evaluation implementation here
        try {
            return eval(expression); // Note: Using eval can be dangerous and should be avoided in production
        } catch (error) {
            return "无效的表达式";
        }
    }

    function sm2Encryption(input, publicKey) {
        // SM2 encryption implementation here
        return `SM2 加密: ${input} 使用公钥 ${publicKey}`;
    }

    function sm4Encryption(input, key) {
        // SM4 encryption implementation here
        return `SM4 加密: ${input} 使用密钥 ${key}`;
    }

    function base64HexConversion(value, direction) {
        // Base64/Hex conversion implementation here
        if (direction === 'toBase64') {
            return btoa(value);
        } else if (direction === 'toHex') {
            return Array.from(value).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
        }
        return "无效的方向";
    }

    // Function to dynamically load forms based on navigation
    function loadForm(action) {
        const contentContainer = document.getElementById('content-container');
        let formHtml;
        switch (action) {
            case 'aes':
                formHtml = `
                    <form data-action="aes">
                        <label for="input">输入:</label>
                        <input type="text" id="input" name="input" required>
                        <label for="key">密钥:</label>
                        <input type="text" id="key" name="key" required>
                        <button type="submit">加密</button>
                    </form>`;
                break;
            case 'rsa':
                formHtml = `
                    <form data-action="rsa">
                        <label for="input">输入:</label>
                        <input type="text" id="input" name="input" required>
                        <label for="publicKey">公钥:</label>
                        <textarea id="publicKey" name="publicKey" required></textarea>
                        <button type="submit">加密</button>
                    </form>`;
                break;
            case 'sha':
                formHtml = `
                    <form data-action="sha">
                        <label for="input">输入:</label>
                        <input type="text" id="input" name="input" required>
                        <button type="submit">哈希</button>
                    </form>`;
                break;
            case 'md5':
                formHtml = `
                    <form data-action="md5">
                        <label for="input">输入:</label>
                        <input type="text" id="input" name="input" required>
                        <button type="submit">哈希</button>
                    </form>`;
                break;
            case 'keccak':
                formHtml = `
                    <form data-action="keccak">
                        <label for="input">输入:</label>
                        <input type="text" id="input" name="input" required>
                        <button type="submit">哈希</button>
                    </form>`;
                break;
            case 'hmac':
                formHtml = `
                    <form data-action="hmac">
                        <label for="input">输入:</label>
                        <input type="text" id="input" name="input" required>
                        <label for="secret">密钥:</label>
                        <input type="text" id="secret" name="secret" required>
                        <button type="submit">哈希</button>
                    </form>`;
                break;
            case 'crc32':
                formHtml = `
                    <form data-action="crc32">
                        <label for="input">输入:</label>
                        <input type="text" id="input" name="input" required>
                        <button type="submit">校验和</button>
                    </form>`;
                break;
            case 'rabbit':
                formHtml = `
                    <form data-action="rabbit">
                        <label for="input">输入:</label>
                        <input type="text" id="input" name="input" required>
                        <label for="key">密钥:</label>
                        <input type="text" id="key" name="key" required>
                        <button type="submit">加密</button>
                    </form>`;
                break;
            case 'rc4':
                formHtml = `
                    <form data-action="rc4">
                        <label for="input">输入:</label>
                        <input type="text" id="input" name="input" required>
                        <label for="key">密钥:</label>
                        <input type="text" id="key" name="key" required>
                        <button type="submit">加密</button>
                    </form>`;
                break;
            case 'des':
                formHtml = `
                    <form data-action="des">
                        <label for="input">输入:</label>
                        <input type="text" id="input" name="input" required>
                        <label for="key">密钥:</label>
                        <input type="text" id="key" name="key" required>
                        <button type="submit">加密</button>
                    </form>`;
                break;
            case 'tripledes':
                formHtml = `
                    <form data-action="tripledes">
                        <label for="input">输入:</label>
                        <input type="text" id="input" name="input" required>
                        <label for="key">密钥:</label>
                        <input type="text" id="key" name="key" required>
                        <button type="submit">加密</button>
                    </form>`;
                break;
            case '24char_encryption':
                formHtml = `
                    <form data-action="24char_encryption">
                        <label for="input">输入:</label>
                        <input type="text" id="input" name="input" required>
                        <button type="submit">加密</button>
                    </form>`;
                break;
            case 'jwt':
                formHtml = `
                    <form data-action="jwt">
                        <label for="token">JWT 令牌:</label>
                        <input type="text" id="token" name="token" required>
                        <button type="submit">解码</button>
                    </form>`;
                break;
            case 'email_encoder':
                formHtml = `
                    <form data-action="email_encoder">
                        <label for="email">邮箱地址:</label>
                        <input type="email" id="email" name="email" required>
                        <button type="submit">编码</button>
                    </form>`;
                break;
            case 'calculator':
                formHtml = `
                    <form data-action="calculator">
                        <label for="expression">表达式:</label>
                        <input type="text" id="expression" name="expression" required>
                        <button type="submit">计算</button>
                    </form>`;
                break;
            case 'sm2':
                formHtml = `
                    <form data-action="sm2">
                        <label for="input">输入:</label>
                        <input type="text" id="input" name="input" required>
                        <label for="publicKey">公钥:</label>
                        <textarea id="publicKey" name="publicKey" required></textarea>
                        <button type="submit">加密</button>
                    </form>`;
                break;
            case 'sm4':
                formHtml = `
                    <form data-action="sm4">
                        <label for="input">输入:</label>
                        <input type="text" id="input" name="input" required>
                        <label for="key">密钥:</label>
                        <input type="text" id="key" name="key" required>
                        <button type="submit">加密</button>
                    </form>`;
                break;
            case 'base64_hex_converter':
                formHtml = `
                    <form data-action="base64_hex_converter">
                        <label for="value">值:</label>
                        <input type="text" id="value" name="value" required>
                        <label for="direction">方向:</label>
                        <select id="direction" name="direction">
                            <option value="toBase64">转换为 Base64</option>
                            <option value="toHex">转换为 Hex</option>
                        </select>
                        <button type="submit">转换</button>
                    </form>`;
                break;
            default:
                formHtml = '<p>请选择一个工具。</p>';
        }
        contentContainer.innerHTML = formHtml;
    }

    // Event listener for navigation links
    document.querySelectorAll('nav a').forEach(link => {
        link.addEventListener('click', function(event) {
            event.preventDefault();
            const targetId = this.getAttribute('href').substring(1);
            loadForm(targetId);
        });
    });

    // Initial load of the first form
    loadForm('aes');

    // Result display element
    const resultElement = document.createElement('div');
    resultElement.id = 'result';
    document.body.appendChild(resultElement);
});



