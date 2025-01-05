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

function showTab(tabId) {
    const tabs = document.querySelectorAll('.tab-content');
    tabs.forEach(tab => tab.classList.remove('active'));

    const buttons = document.querySelectorAll('.tab-button');
    buttons.forEach(button => button.classList.remove('active'));

    document.getElementById(tabId).classList.add('active');
    document.querySelector(`.tab-button[onclick*='${tabId}']`).classList.add('active');
}