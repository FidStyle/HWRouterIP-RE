const axios = require('axios');
const crypto = require('crypto-js'); // 使用 CryptoJS
const fs = require('fs'); // 文件操作
const pwd = '123'
const BASE_URL = 'http://192.168.3.1/api/system';
const SESSION_FILE = './session.txt'; // 保存 session 的文件
const debug = true; // 调试开关

const instance = axios.create({
    withCredentials: true,
    headers: { 'Content-Type': 'application/json' }
});

let sessionCookie = ''; // 初始会话 Cookie

async function scramLogin(username, password) {
    try {
        const csrf = await initializeCsrf();
        if (debug) console.log('CSRF Initialized:', csrf);

        const firstNonce = generateNonce();
        if (debug) console.log('First Nonce:', firstNonce);

        const nonceResponse = await sendNonceRequest(username, firstNonce, csrf);
        if (debug) console.log('Nonce Response:', nonceResponse);

        const { servernonce, salt, iterations } = nonceResponse;

        await sendProofRequest(username, password, firstNonce, servernonce, salt, iterations, csrf);
    } catch (error) {
        handleError(error);
    }
}

async function initializeCsrf() {
    const response = await instance.post(`${BASE_URL}/user_login_nonce`, {
        csrf: { csrf_param: '1', csrf_token: '2' }
    });

    const setCookieHeader = response.headers['set-cookie'];
    if (setCookieHeader) {
        sessionCookie = setCookieHeader.find(cookie => cookie.startsWith('SessionID_R3'));
        if (debug) console.log('Session Cookie:', sessionCookie);
    }

    if (response.data.errcode === 1) {
        return {
            csrf_param: response.data.csrf_param,
            csrf_token: response.data.csrf_token
        };
    } else {
        throw new Error('Failed to initialize CSRF');
    }
}

async function sendNonceRequest(username, firstNonce, csrf) {
    const requestData = {
        data: { username, firstnonce: firstNonce },
        csrf
    };

    if (debug) console.log('Request Body:', JSON.stringify(requestData, null, 2));

    const response = await instance.post(`${BASE_URL}/user_login_nonce`, requestData, {
        headers: { 'Cookie': sessionCookie }
    });

    if (response.data.csrf_param && response.data.csrf_token) {
        csrf.csrf_param = response.data.csrf_param;
        csrf.csrf_token = response.data.csrf_token;
        if (debug) console.log('CSRF Updated:', csrf);
    }

    if (response.data.err !== 0) {
        console.log('Nonce Request Failed:', response.data);
        throw new Error('Nonce request failed');
    }

    return response.data;
}

async function sendProofRequest(username, password, firstNonce, serverNonce, salt, iterations, csrf) {
    const saltBuffer = crypto.enc.Hex.parse(salt);
    const authMessage = `${firstNonce},${serverNonce},${serverNonce}`;

    const clientProof = SCRAM.clientProof(password, saltBuffer, iterations, authMessage);
    if (debug) console.log('Client Proof:', clientProof);

    const proofRequestData = {
        name: 'user_login_proof',
        data: {
            clientproof: clientProof,
            finalnonce: serverNonce
        },
        csrf
    };

    if (debug) console.log('Proof Request Body:', JSON.stringify(proofRequestData, null, 2));

    try {
        const response = await instance.post(`${BASE_URL}/user_login_proof`, proofRequestData, {
            headers: { 'Cookie': sessionCookie }
        });

        const setCookieHeader = response.headers['set-cookie'];
        if (setCookieHeader) {
            const newSessionCookie = setCookieHeader
                .find(cookie => cookie.startsWith('SessionID_R3'))
                .split(';')
                .slice(0, -1)
                .join(';') + ';';
            sessionCookie = newSessionCookie;
            if (debug) console.log('New Session Cookie:', sessionCookie);
            saveSessionCookie(); // 保存到文件
        }
        if (response.data.err === 0) {
            console.log('Login successful!');
            console.log('Response:', response.data);
        } else {
            console.log('Login failed:', response.data);
        }
    } catch (error) {
        handleError(error);
    }
}

// 保存 Session Cookie 到文件
function saveSessionCookie() {
    fs.writeFileSync(SESSION_FILE, sessionCookie, 'utf8');
    if (debug) console.log('Session Cookie saved to file.');
}

// 从文件读取 Session Cookie
function loadSessionCookie() {
    if (fs.existsSync(SESSION_FILE)) {
        sessionCookie = fs.readFileSync(SESSION_FILE, 'utf8');
        if (debug) console.log('Session Cookie loaded from file:', sessionCookie);
    }
}

// 请求 WAN Diagnose 并解析 External IP
async function getExternalIP() {
    try {
        const response = await instance.get('http://192.168.3.1/api/ntwk/wandiagnose', {
            headers: { 'Cookie': sessionCookie }
        });

        const data = response.data;
        if (debug) console.log('WAN Diagnose Response:', data);

        const externalIP = data.ExternalIPAddress;
        if (externalIP) {
            console.log('External IP Address:', externalIP);
        } else {
            console.log('External IP not found. Re-authenticating...');
            await scramLogin('admin', pwd);
            await getExternalIP(); // 重新请求
        }
    } catch (error) {
        console.error('Error fetching WAN Diagnose:', error.message);
        console.log('Re-authenticating...');
        await scramLogin('admin', pwd);
        await getExternalIP(); // 重新请求
    }
}

// 处理错误
function handleError(error) {
    console.error('Error:', error.response ? error.response.data : error.message);
}

// 生成随机 Nonce
function generateNonce() {
    return crypto.lib.WordArray.random(32).toString(crypto.enc.Hex);
}

// SCRAM 实现
const SCRAM = {
    keySize: 8,
    hasher: crypto.algo.SHA256,
    hmac: crypto.HmacSHA256,

    saltedPassword: function (password, salt, iterations) {
        return crypto.PBKDF2(password, salt, {
            keySize: this.keySize,
            iterations: iterations,
            hasher: this.hasher,
        });
    },

    clientKey: function (saltedPwd) {
        return this.hmac(saltedPwd, 'Client Key');
    },

    storedKey: function (clientKey) {
        return this.hasher.create().update(clientKey).finalize();
    },

    signature: function (key, message) {
        return this.hmac(key, message);
    },

    clientProof: function (password, salt, iterations, authMessage) {
        const saltedPwd = this.saltedPassword(password, salt, iterations);
        const clientKey = this.clientKey(saltedPwd);
        const storedKey = this.storedKey(clientKey);
        const clientSignature = this.signature(storedKey, authMessage);

        for (let i = 0; i < clientKey.sigBytes / 4; i++) {
            clientKey.words[i] ^= clientSignature.words[i];
        }

        return clientKey.toString(crypto.enc.Hex);
    },
};

// 初始化并请求 External IP
loadSessionCookie();
getExternalIP();
