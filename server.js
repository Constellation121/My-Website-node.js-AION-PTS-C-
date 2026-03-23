const express = require("express");
const sql = require("mssql");
const bodyParser = require("body-parser");
const path = require("path");
const fs = require("fs");
const session = require("express-session");
const rateLimit = require("express-rate-limit");
const axios = require("axios");

const app = express();
const port = 3035;


const dbConfig = {
    user: "sa",
    password: "xxxxxx",
    server: "xxxxxx",
    database: "AionAccounts",
    options: {
        encrypt: false,
        enableArithAbort: true
    }
};


app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.set("view engine", "ejs");


app.use(session({
    secret: "Key_secret",
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 3600000 }
}));


const criarContaLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 3,
    message: "⚠️ Account creation limit reached."
});
app.use("/criar", criarContaLimiter);


async function verificarCaptcha(token) {
    if (!token) return { success: false };

    try {
        const response = await axios.post(
            "https://www.google.com/recaptcha/api/siteverify",
            null,
            {
                params: {
                    secret: "SECRET_KEY",
                    response: token
                }
            }
        );

        return response.data;

    } catch (err) {
        console.error("CAPTCHA Error:", err.message);
        return { success: false };
    }
}


function gerarSenha() {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@#$%¨&*!";
    let senha = "";
    for (let i = 0; i < 10; i++) {
        senha += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return senha;
}

// ====================== AION HASH ======================
function getAionPasswordHash(input) {
    const U32 = BigInt(4294967296);
    const numArray1 = new Array(17).fill(0);
    const numArray2 = new Array(17).fill(0);
    const bytes = Buffer.from(input, "ascii");

    for (let i = 0; i < input.length; i++) {
        numArray1[i + 1] = bytes[i];
        numArray2[i + 1] = bytes[i];
    }

    const low32 = (n) => { let r = n % U32; if (r < 0) r += U32; return r; };

    const n2 = Number(low32((BigInt(numArray1[1]) + BigInt(numArray1[2]) * 256n + BigInt(numArray1[3]) * 65536n + BigInt(numArray1[4]) * 16777216n) * 213119n + 2529077n));
    numArray1[1] = n2 & 0xFF; numArray1[2] = (n2 >>> 8) & 0xFF; numArray1[3] = (n2 >>> 16) & 0xFF; numArray1[4] = (n2 >>> 24) & 0xFF;

    const n4 = Number(low32((BigInt(numArray1[5]) + BigInt(numArray1[6]) * 256n + BigInt(numArray1[7]) * 65536n + BigInt(numArray1[8]) * 16777216n) * 213247n + 2529089n));
    numArray1[5] = n4 & 0xFF; numArray1[6] = (n4 >>> 8) & 0xFF; numArray1[7] = (n4 >>> 16) & 0xFF; numArray1[8] = (n4 >>> 24) & 0xFF;

    const n6 = Number(low32((BigInt(numArray1[9]) + BigInt(numArray1[10]) * 256n + BigInt(numArray1[11]) * 65536n + BigInt(numArray1[12]) * 16777216n) * 213203n + 2529589n));
    numArray1[9] = n6 & 0xFF; numArray1[10] = (n6 >>> 8) & 0xFF; numArray1[11] = (n6 >>> 16) & 0xFF; numArray1[12] = (n6 >>> 24) & 0xFF;

    const n8 = Number(low32((BigInt(numArray1[13]) + BigInt(numArray1[14]) * 256n + BigInt(numArray1[15]) * 65536n + BigInt(numArray1[16]) * 16777216n) * 213821n + 2529997n));
    numArray1[13] = n8 & 0xFF; numArray1[14] = (n8 >>> 8) & 0xFF; numArray1[15] = (n8 >>> 16) & 0xFF; numArray1[16] = (n8 >>> 24) & 0xFF;

    numArray2[1] ^= numArray1[1];
    for (let i = 2; i <= 16; i++) numArray2[i] = (numArray2[i] ^ numArray2[i - 1] ^ numArray1[i]) & 0xFF;
    for (let i = 1; i <= 16; i++) if (numArray2[i] === 0) numArray2[i] = 102;

    const out = Buffer.alloc(16);
    for (let i = 0; i < 16; i++) out[i] = numArray2[i + 1];
    return out;
}


app.get("/", (req, res) => res.render("index"));

app.post("/criar", async (req, res) => {
    const { username, password: userPassword, "g-recaptcha-response": token } = req.body;

    const captcha = await verificarCaptcha(token);
    if (!captcha.success) {
        return res.send("<h1>❌ Invalid CAPTCHA</h1>");
    }

    const password = userPassword || gerarSenha();

    try {
        const hash = getAionPasswordHash(password);
        const pool = await sql.connect(dbConfig);

        const result = await pool.request()
            .input("nickname", sql.VarChar(15), username)
            .input("account", sql.VarChar(14), username)
            .input("password", sql.VarBinary(16), hash)
            .input("email", sql.VarChar(50), `${username}@mail.com`)
            .execute("web_CreateAccount");

        const accountId = result.returnValue;
        if (!accountId) return res.send("❌ User already exists");

        res.send(`✅ Account created<br>User: ${username}<br>Pass: ${password}`);

    } catch (err) {
        console.error(err);
        res.send("Error creating account");
    }
});

app.listen(port, () => {
    console.log(`🚀 http://localhost:${port}`);
});