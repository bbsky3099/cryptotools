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

    document.getElementById('result').innerText = `结果: ${result}`;
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

    document.getElementById('result').innerText = `结果: ${result}`;
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

    document.getElementById('result').innerText = `结果: ${result}`;
});

document.getElementById('crc32Form').addEventListener('submit', function(event) {
    event.preventDefault();
    const data = document.getElementById('crc32Data').value;
    const crc32 = new CRC32().str(data).toString(16);

    document.getElementById('result').innerText = `CRC32 结果: ${crc32}`;
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

    document.getElementById('result').innerText = `结果: ${result}`;
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

    document.getElementById('result').innerText = `结果: ${result}`;
});

document.getElementById('jwtForm').addEventListener('submit', function(event) {
    event.preventDefault();
    const token = document.getElementById('jwtToken').value;
    const secret = document.getElementById('jwtSecret').value;
    try {
        const isValid = KJUR.jws.JWS.verifyJWT(token, secret, {alg: ['HS256']});
        const decoded = KJUR.jws.JWS.parse(token);
        const payload = JSON.stringify(decoded.payloadObj, null, 2);
        document.getElementById('result').innerText = `JWT Payload:\n${payload}\n\n有效: ${isValid}`;
    } catch (error) {
        document.getElementById('result').innerText = `错误: ${error.message}`;
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

    document.getElementById('result').innerText = `结果: ${result}`;
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

    document.getElementById('result').innerText = `结果: ${result}`;
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

    document.getElementById('result').innerText = `${algorithm} 结果: ${result}`;
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

    document.getElementById('result').innerText = `${algorithm} 结果: ${result}`;
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

    document.getElementById('result').innerText = `HMAC-${algorithm} 结果: ${result}`;
});

document.getElementById('24charForm').addEventListener('submit', function(event) {
    event.preventDefault();
    const data = document.getElementById('24charData').value;
    // 这里假设 24 字加密是一个简单的示例，实际应用中可能需要更复杂的逻辑
    const key = '24byteencryptionkey!';
    const encrypted = CryptoJS.AES.encrypt(data, key).toString();

    document.getElementById('result').innerText = `24 字加密结果: ${encrypted}`;
});

document.getElementById('sm2Form').addEventListener('submit', function(event) {
    event.preventDefault();
    const mode = document.getElementById('sm2Mode').value;
    const data = document.getElementById('sm2Data').value;
    const publicKey = document.getElementById('sm2PublicKey').value;
    const privateKey = document.getElementById('sm2PrivateKey').value;

    let result;
    if (mode === 'encrypt') {
        const sm2 = new KJUR.crypto.SM2({curve: "sm2p256v1"});
        sm2.setPublicKeyHex(publicKey);
        result = sm2.doEncrypt(data, "hex");
    } else {
        const sm2 = new KJUR.crypto.SM2({curve: "sm2p256v1"});
        sm2.setPrivateKeyHex(privateKey);
        result = sm2.doDecrypt(data, "hex");
    }

    document.getElementById('result').innerText = `SM2 结果: ${result}`;
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

    document.getElementById('result').innerText = `SM4 结果: ${result}`;
});

document.getElementById('emailEncryptForm').addEventListener('submit', function(event) {
    event.preventDefault();
    const email = document.getElementById('emailAddress').value;
    const key = document.getElementById('emailKey').value;

    const encrypted = CryptoJS.AES.encrypt(email, key).toString();
    document.getElementById('result').innerText = `加密后的 Email: ${encrypted}`;
});

document.getElementById('md5Form').addEventListener('submit', function(event) {
    event.preventDefault();
    const data = document.getElementById('md5Data').value;
    const md5Hash = CryptoJS.MD5(data).toString();

    document.getElementById('result').innerText = `MD5 结果: ${md5Hash}`;
});

document.getElementById('calculatorForm').addEventListener('submit', function(event) {
    event.preventDefault();
    const expression = document.getElementById('calculatorExpression').value;
    try {
        const result = eval(expression);
        document.getElementById('result').innerText = `计算结果: ${result}`;
    } catch (error) {
        document.getElementById('result').innerText = `错误: ${error.message}`;
    }
});

function showTab(tabId) {
    const tabs = document.querySelectorAll('.tab-content');
    tabs.forEach(tab => tab.classList.remove('active'));

    const buttons = document.querySelectorAll('.tab-button');
    buttons.forEach(button => button.classList.remove('active'));

    document.getElementById(tabId).classList.add('active');
    document.querySelector(`.tab-button[onclick*='${tabId}']`).classList.add('active');

    // 更新当前功能显示
    const functionNameMap = {
        aes: 'AES加/解密',
        des: 'DES加/解密',
        rsa: 'RSA加/解密',
        crc32: 'CRC32计算',
        rc4: 'RC4加/解密',
        tripledes: 'TripleDES加/解密',
        jwt: 'JWT解密',
        base64hex: 'Base64/Hex转换',
        rabbit: 'Rabbit加/解密',
        sha: 'SHA哈希计算',
        keccak: 'Keccak哈希计算',
        hmac: 'HMAC计算',
        '24char': '24字加密',
        sm2: 'SM2加/解密',
        sm4: 'SM4加/解密',
        emailEncrypt: 'Email地址加密',
        md5: 'MD5加密',
        calculator: '在线计算器'
    };

    document.getElementById('currentFunction').innerText = functionNameMap[tabId];
}

// CRC32 实现
class CRC32 {
    constructor() {
        this.table = this.createTable();
    }

    createTable() {
        const table = [];
        for (let i = 0; i < 256; i++) {
            let c = i;
            for (let j = 0; j < 8; j++) {
                if (c & 1) {
                    c = 0xEDB88320 ^ (c >>> 1);
                } else {
                    c = c >>> 1;
                }
            }
            table[i] = c;
        }
        return table;
    }

    str(str) {
        let crc = ~0;
        for (let i = 0; i < str.length; i++) {
            crc = (crc >>> 8) ^ this.table[(crc ^ str.charCodeAt(i)) & 0xFF];
        }
        return ~crc;
    }
}