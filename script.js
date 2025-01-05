document.addEventListener('DOMContentLoaded', function() {
    // 显示初始活动选项卡
    showTab('aes');
	
    document.getElementById('aesForm').addEventListener('submit', function(event) {
        event.preventDefault();
        const mode = document.getElementById('aesMode').value;
        const data = document.getElementById('aesData').value;
        const key = document.getElementById('aesKey').value;
        let result;
        if (mode === 'encrypt') {
            result = CryptoJS.AES.encrypt(data, key).toString();
        } else {
            const bytes = CryptoJS.AES.decrypt(data, key);
            result = bytes.toString(CryptoJS.enc.Utf8);
        }

        document.getElementById('resultText').textContent = ` ${result}`;
    });

    document.getElementById('desForm').addEventListener('submit', function(event) {
        event.preventDefault();
        const mode = document.getElementById('desMode').value;
        const data = document.getElementById('desData').value;
        const key = document.getElementById('desKey').value;
        let result;
        if (mode === 'encrypt') {
            result = CryptoJS.DES.encrypt(data, key).toString();
        } else {
            const bytes = CryptoJS.DES.decrypt(data, key);
            result = bytes.toString(CryptoJS.enc.Utf8);
        }
        
        document.getElementById('resultText').textContent = ` ${result}`;
    });

    document.getElementById('rsaForm').addEventListener('submit', function(event) {
        event.preventDefault();
        const mode = document.getElementById('rsaMode').value;
        const data = document.getElementById('rsaData').value;
        const key = document.getElementById('rsaKey').value;
        let result;
        if (mode === 'encrypt') {
            const rsaKey = KEYUTIL.getKey(key, null, "pem");
            result = rsaKey.encrypt(data, "RSAES-PKCS1-v1_5").toString("base64");
        } else {
            const rsaKey = KEYUTIL.getKey(key, null, "pem");
            result = rsaKey.decrypt(data, "RSAES-PKCS1-v1_5", "utf8");
        }

        document.getElementById('resultText').textContent = ` ${result}`;
    });

    document.getElementById('crc32Form').addEventListener('submit', function(event) {
        event.preventDefault();
        const data = document.getElementById('crc32Data').value;
        const crc32 = new CRC32().str(data).toString(16);

        document.getElementById('resultText').textContent = ` ${crc32}`;
    });

    document.getElementById('rc4Form').addEventListener('submit', function(event) {
        event.preventDefault();
        const mode = document.getElementById('rc4Mode').value;
        const data = document.getElementById('rc4Data').value;
        const key = document.getElementById('rc4Key').value;
        let result;
        if (mode === 'encrypt') {
            result = CryptoJS.RC4.encrypt(data, key).toString();
        } else {
            const bytes = CryptoJS.RC4.decrypt(data, key);
            result = bytes.toString(CryptoJS.enc.Utf8);
        }
        
        document.getElementById('resultText').textContent = ` ${result}`;
    });

    document.getElementById('tripledesForm').addEventListener('submit', function(event) {
        event.preventDefault();
        const mode = document.getElementById('tripledesMode').value;
        const data = document.getElementById('tripledesData').value;
        const key = document.getElementById('tripledesKey').value;
        let result;
        if (mode === 'encrypt') {
            result = CryptoJS.TripleDES.encrypt(data, key).toString();
        } else {
            const bytes = CryptoJS.TripleDES.decrypt(data, key);
            result = bytes.toString(CryptoJS.enc.Utf8);
        }
        
        document.getElementById('resultText').textContent = ` ${result}`;
    });

    document.getElementById('jwtForm').addEventListener('submit', function(event) {
        event.preventDefault();
        const token = document.getElementById('jwtToken').value;
        const secret = document.getElementById('jwtSecret').value;
        try {
            const isValid = KJUR.jws.JWS.verifyJWT(token, secret, { alg: ['HS256'] });
            const decoded = KJUR.jws.JWS.parse(token);
            const payload = JSON.stringify(decoded.payloadObj, null, 2);
            
            document.getElementById('resultText').textContent = `JWT Payload:\n${payload}\n\n有效: ${isValid}`;
        } catch (error) {
            document.getElementById('resultText').textContent = `错误: ${error.message}`;
        }
    });

    document.getElementById('base64hexForm').addEventListener('submit', function(event) {
        event.preventDefault();
        const input = document.getElementById('base64hexInput').value;
        const type = document.getElementById('base64hexType').value;
        let result;
        if (type === 'toBase64') {
            result = btoa(input);
        } else {
            result = atob(input);
        }
        
        document.getElementById('resultText').textContent = ` ${result}`;
    });

    document.getElementById('rabbitForm').addEventListener('submit', function(event) {
        event.preventDefault();
        const mode = document.getElementById('rabbitMode').value;
        const data = document.getElementById('rabbitData').value;
        const key = document.getElementById('rabbitKey').value;
        let result;
        if (mode === 'encrypt') {
            result = CryptoJS.Rabbit.encrypt(data, key).toString();
        } else {
            const bytes = CryptoJS.Rabbit.decrypt(data, key);
            result = bytes.toString(CryptoJS.enc.Utf8);
        }
        
        document.getElementById('resultText').textContent = ` ${result}`;
    });

    document.getElementById('shaForm').addEventListener('submit', function(event) {
        event.preventDefault();
        const algorithm = document.getElementById('shaAlgorithm').value;
        const data = document.getElementById('shaData').value;
        let result;
        switch (algorithm) {
            case 'SHA-1':
                result = CryptoJS.SHA1(data).toString();
                break;
            case 'SHA-256':
                result = CryptoJS.SHA256(data).toString();
                break;
            case 'SHA-512':
                result = CryptoJS.SHA512(data).toString();
                break;
            default:
                result = '未知算法';
        }
        
        document.getElementById('resultText').textContent = ` ${result}`;
    });

    document.getElementById('keccakForm').addEventListener('submit', function(event) {
        event.preventDefault();
        const algorithm = document.getElementById('keccakAlgorithm').value;
        const data = document.getElementById('keccakData').value;
        let result;
        switch (algorithm) {
            case 'KECCAK-224':
                result = CryptoJS.KCDSA.keccak224(data).toString();
                break;
            case 'KECCAK-256':
                result = CryptoJS.KCDSA.keccak256(data).toString();
                break;
            case 'KECCAK-384':
                result = CryptoJS.KCDSA.keccak384(data).toString();
                break;
            case 'KECCAK-512':
                result = CryptoJS.KCDSA.keccak512(data).toString();
                break;
            default:
                result = '未知算法';
        }
        
        document.getElementById('resultText').textContent = ` ${result}`;
    });

    document.getElementById('hmacForm').addEventListener('submit', function(event) {
        event.preventDefault();
        const algorithm = document.getElementById('hmacAlgorithm').value;
        const data = document.getElementById('hmacData').value;
        const key = document.getElementById('hmacKey').value;
        let result;
        switch (algorithm) {
            case 'SHA-1':
                result = CryptoJS.HmacSHA1(data, key).toString();
                break;
            case 'SHA-256':
                result = CryptoJS.HmacSHA256(data, key).toString();
                break;
            case 'SHA-512':
                result = CryptoJS.HmacSHA512(data, key).toString();
                break;
            default:
                result = '未知算法';
        }
        
        document.getElementById('resultText').textContent = `${result}`;
    });

    document.getElementById('24charForm').addEventListener('submit', function(event) {
        event.preventDefault();
        const data = document.getElementById('24charData').value;
        const key = '24byteencryptionkey!';
        const encrypted = CryptoJS.AES.encrypt(data, key).toString();
        
        document.getElementById('resultText').textContent = ` ${encrypted}`;
    });

    document.getElementById('sm2Form').addEventListener('submit', function(event) {
        event.preventDefault();
        const mode = document.getElementById('sm2Mode').value;
        const data = document.getElementById('sm2Data').value;
        const publicKey = document.getElementById('sm2PublicKey').value;
        const privateKey = document.getElementById('sm2PrivateKey').value;
        let result;
        if (mode === 'encrypt') {
            const sm2 = new KJUR.crypto.SM2({ curve: "sm2p256v1" });
            sm2.setPublicKeyHex(publicKey);
            result = sm2.doEncrypt(data, "hex");
        } else {
            const sm2 = new KJUR.crypto.SM2({ curve: "sm2p256v1" });
            sm2.setPrivateKeyHex(privateKey);
            result = sm2.doDecrypt(data, "hex");
        }
        
        document.getElementById('resultText').textContent = ` ${result}`;
    });

    document.getElementById('sm4Form').addEventListener('submit', function(event) {
        event.preventDefault();
        const mode = document.getElementById('sm4Mode').value;
        const data = document.getElementById('sm4Data').value;
        const key = document.getElementById('sm4Key').value;
        let result;
        if (mode === 'encrypt') {
            result = CryptoJS.SM4.encrypt(data, key).toString();
        } else {
            const bytes = CryptoJS.SM4.decrypt(data, key);
            result = bytes.toString(CryptoJS.enc.Utf8);
        }
        
        document.getElementById('resultText').textContent = ` ${result}`;
    });

    document.getElementById('emailEncryptForm').addEventListener('submit', function(event) {
        event.preventDefault();
        const email = document.getElementById('emailAddress').value;
        const key = document.getElementById('emailKey').value;
        const encrypted = CryptoJS.AES.encrypt(email, key).toString();
        
        document.getElementById('resultText').textContent = ` ${encrypted}`;
    });

    document.getElementById('md5Form').addEventListener('submit', function(event) {
        event.preventDefault();
        const data = document.getElementById('md5Data').value;
        const md5Hash = CryptoJS.MD5(data).toString();
        
        document.getElementById('resultText').textContent = `${md5Hash}`;
    });

    document.getElementById('calculatorForm').addEventListener('submit', function(event) {
        event.preventDefault();
        const expression = document.getElementById('calcExpression').value;
        try {
            const result = eval(expression);
            
            document.getElementById('resultText').textContent = `${result}`;
        } catch (error) {
            document.getElementById('resultText').textContent = `错误: ${error.message}`;
        }
    });
});

function showTab(tabName) {
    const tabContent = document.getElementsByClassName('tab-content');
    for (let i = 0; i < tabContent.length; i++) {
        tabContent[i].style.display = 'none';
    }

    const tabButtons = document.getElementsByClassName('tab-button');
    for (let i = 0; i < tabButtons.length; i++) {
        tabButtons[i].classList.remove('active');
    }

    document.getElementById(tabName).style.display = 'block';
    document.querySelector(`[onclick="showTab('${tabName}')"]`).classList.add('active');
    document.getElementById('currentFunction').textContent = document.querySelector(`[onclick="showTab('${tabName}')"]`).textContent;

    switch (document.querySelector(`[onclick="showTab('${tabName}')"]`).textContent) {
                case 'AES加/解密':
                    document.getElementById('labelText1').innerHTML = ` AES加/解密结果:`;
                    break;
                case 'DES加/解密':
                    document.getElementById('labelText1').innerHTML = ` DES加/解密结果:`;
                    break;
                case 'RSA加/解密':
                    document.getElementById('labelText1').innerHTML = ` RSA加/解密结果:`;
                    break;
                case 'CRC32计算':
                    document.getElementById('labelText1').innerHTML = ` CRC32计算结果:`;        
                    break;
                case 'RC4加/解密':
                    document.getElementById('labelText1').innerHTML = ` RC4加/解密结果:`;
                    break;
                case 'TripleDES加/解密':
                    document.getElementById('labelText1').innerHTML = ` TripleDES加/解密结果:`;
                    break;
                case 'JWT解密':
                    document.getElementById('labelText1').innerHTML = ` JWT解密结果:`;
                    break;
                case 'Base64/Hex转换':
                    document.getElementById('labelText1').innerHTML = ` Base64/Hex转换结果:`;
                    break;
                case 'Rabbit加/解密':
                    document.getElementById('labelText1').innerHTML = ` Rabbit加/解密结果:`;
                    break;
                case 'SHA哈希计算':
                    document.getElementById('labelText1').innerHTML = `SHA哈希计算结果:`;
                    break;
                case 'Keccak哈希计算':
                    document.getElementById('labelText1').innerHTML = ` Keccak哈希计算结果:`;
                    break;
                case 'HMAC计算':
                    document.getElementById('labelText1').innerHTML = ` HMAC计算结果: `;
                    break;
                case '24字加密':
                    document.getElementById('labelText1').innerHTML = ` 24字加密结果: `;
                    break;
                case 'SM2加/解密':
                    document.getElementById('labelText1').innerHTML = `SM2加/解密结果:`;
                    break;
                case 'SM4加/解密':
                    document.getElementById('labelText1').innerHTML = `SM4加/解密结果:`;
                    break;
                case 'Email地址加密':
                    document.getElementById('labelText1').innerHTML = `加密后的 Email:`;
                    break;
                case 'MD5加密':
                    document.getElementById('labelText1').innerHTML = `MD5加密 结果: `;
                    break;
                case '在线计算器':
                    document.getElementById('labelText1').innerHTML = `计算结果:  `;
                    break;
                default:
                    document.getElementById('labelText1').innerHTML = ` 结果:`;
    }
}

function copyResult() {
    const resultText = document.getElementById('resultText');
    const range = document.createRange();
    range.selectNodeContents(resultText);
    const selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);

    try {
        document.execCommand('copy');
        alert('结果已复制到剪贴板');
    } catch (err) {
        console.error('无法复制文本: ', err);
    }
}