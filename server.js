const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
app.set('trust proxy', 1); // Confia no primeiro proxy (essencial para o Render obter o IP real)
app.use(cors());
app.use(express.json());

const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: "*", // Em produção, restrinja para o seu domínio
        methods: ["GET", "POST"]
    }
});

const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-for-dev-only-change-in-production';
const PORT = process.env.PORT || 3000;

// Alerta de Segurança para o Ambiente de Produção
if (process.env.NODE_ENV === 'production' && JWT_SECRET === 'fallback-secret-for-dev-only-change-in-production') {
    console.error('\n\n\x1b[31m%s\x1b[0m\n\n', '**************************************************************************************');
    console.error('\x1b[31m%s\x1b[0m', 'ATENÇÃO: A APLICAÇÃO ESTÁ USANDO UMA JWT_SECRET PADRÃO E INSEGURA EM PRODUÇÃO!');
    console.error('\x1b[33m%s\x1b[0m', 'Configure a variável de ambiente "JWT_SECRET" no seu serviço do Render com um valor seguro.');
    console.error('\x1b[31m%s\x1b[0m\n', '**************************************************************************************');
}

// Mapa para guardar a relação entre username e socketId
// Map<username, { socketId: string, ip: string }>
const connectedUsers = new Map();

// --- Gerenciamento de IPs Banidos ---
const bannedIPs = new Set();

// --- Filtro de Censura ---
const badWords = ['palavrão', 'inapropriado', 'ofensa']; // Adicione as palavras que deseja censurar

function censorMessage(message) {
    let censoredText = message;
    badWords.forEach(word => {
        const regex = new RegExp(`\\b${word}\\b`, 'gi'); // 'gi' para global e case-insensitive
        censoredText = censoredText.replace(regex, '*'.repeat(word.length));
    });
    return censoredText;
}

// --- Banco de Dados Simulado ---
// ATENÇÃO: Este banco de dados em memória será RESETADO toda vez que o servidor
// no Render for reiniciado (o que acontece automaticamente após inatividade).
// Isso significa que todos os usuários registrados serão PERDIDOS.
// Para uma aplicação real, você DEVE usar um serviço de banco de dados persistente,
// como o PostgreSQL gratuito oferecido pelo próprio Render.
let users = [
    {
        username: 'Admin',
        email: 'dollya@1',
        passwordHash: bcrypt.hashSync('9092', 10),
        isAdmin: true,
        isTester: false,
        ip: '127.0.0.1',
        status: 'active',
        avatarUrl: 'https://i.imgur.com/DCp3Qe0.png',
        banDetails: {
            bannedBy: null,
            reason: null,
            expiresAt: null
        }
    },
    {
        username: 'Tester',
        email: 'testdolly@1',
        passwordHash: bcrypt.hashSync('test', 10),
        isAdmin: false,
        isTester: true,
        ip: '127.0.0.1',
        status: 'active',
        avatarUrl: 'https://i.imgur.com/R32sf5C.png', // Avatar de Tester
        banDetails: {
            bannedBy: null,
            reason: null,
            expiresAt: null
        }
    }
];

// --- Middleware de Autenticação ---
const authMiddleware = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    // Log para depuração: O que o servidor está recebendo?
    console.log('Recebido authHeader:', authHeader);
    console.log('Token extraído:', token);

    if (!token) {
        console.log('Nenhum token fornecido ou token malformado no header.');
        return res.sendStatus(401);
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.error('Erro na verificação do JWT:', err.message); // Este é o log que você já viu
            return res.sendStatus(403);
        }
        req.user = users.find(u => u.username === user.username);
        if (!req.user) {
            // Adicionando log para o caso do usuário não ser encontrado após um reset
            console.error(`Usuário do token (${user.username}) não encontrado no banco de dados em memória. O servidor pode ter sido reiniciado.`);
            return res.sendStatus(404);
        }
        next();
    });
};

const adminMiddleware = (req, res, next) => {
    if (!req.user || !req.user.isAdmin) {
        return res.status(403).send('Acesso negado. Requer privilégios de administrador.');
    }
    next();
};

// --- Rotas de Autenticação ---
app.post('/api/register', (req, res) => {
    const { username, email, password } = req.body;
    // Validação de entrada no servidor - Prática Essencial
    if (!username || !email || !password) {
        return res.status(400).send('Todos os campos (username, email, password) são obrigatórios.');
    }

    if (users.find(u => u.username === username || u.email === email)) {
        return res.status(400).send('Usuário ou email já existe.');
    }
    const newUser = {
        username,
        email,
        passwordHash: bcrypt.hashSync(password, 10),
        isAdmin: false,
        isTester: false,
        ip: req.ip,
        status: 'active',
        avatarUrl: `https://via.placeholder.com/150/000000/FFFFFF/?text=${username.charAt(0)}`,
        banDetails: {
            bannedBy: null,
            reason: null,
            expiresAt: null
        }
    };
    users.push(newUser);
    res.status(201).send('Usuário criado com sucesso.');
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    // Validação de entrada no servidor
    if (!email || !password) {
        return res.status(400).send('Email e senha são obrigatórios.');
    }

    const user = users.find(u => u.email === email);

    if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
        return res.status(401).send('Email ou senha inválidos.');
    }

    user.ip = req.ip; // Atualiza o IP do usuário no login para garantir que esteja sempre correto

    // Check if ban has expired
    if (user.status === 'banned' && user.banDetails.expiresAt && new Date(user.banDetails.expiresAt) < new Date()) {
        user.status = 'unbanned'; // Mark for reactivation
    }

    if (user.status === 'banned') { // Still banned
        return res.status(403).json({ message: 'Esta conta foi banida.', banDetails: user.banDetails });
    }

    if (user.status === 'unbanned') {
        return res.status(403).json({ message: 'Sua conta foi desbanida.', needsReactivation: true });
    }

    const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token });
});

// --- Rotas de Usuário (Protegidas) ---
app.get('/api/users/me', authMiddleware, (req, res) => {
    // Retorna os dados do usuário logado, exceto a senha
    const { passwordHash, ...userWithoutPassword } = req.user;
    res.json(userWithoutPassword);
});

app.put('/api/users/me/roblox', authMiddleware, async (req, res) => {
    const { robloxUsername } = req.body;
    if (!robloxUsername) {
        return res.status(400).send('Nome de usuário do Roblox não fornecido.');
    }

    try {
        // Etapa 1: Obter o ID do usuário a partir do nome de usuário (usando o novo endpoint da API)
        const usersApiUrl = 'https://users.roblox.com/v1/usernames/users';
        const usersResponse = await fetch(usersApiUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
            body: JSON.stringify({ usernames: [robloxUsername], excludeBannedUsers: true })
        });

        if (!usersResponse.ok) {
            return res.status(404).send('Usuário do Roblox não encontrado ou erro na API de usuários.');
        }
        
        const usersData = await usersResponse.json();
        if (!usersData.data || usersData.data.length === 0) {
            return res.status(404).send('Nome de usuário do Roblox não encontrado.');
        }
        
        const userId = usersData.data[0].id;
        const canonicalUsername = usersData.data[0].name; // É uma boa prática usar o nome retornado pela API

        // Etapa 2: Obter o avatar a partir do ID do usuário
        const thumbResponse = await fetch(`https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=${userId}&size=150x150&format=Png&isCircular=false`);
        if (!thumbResponse.ok) {
            return res.status(500).send('Não foi possível carregar o avatar do Roblox.');
        }

        const thumbData = await thumbResponse.json();
        const avatarUrl = thumbData.data[0].imageUrl;

        // Etapa 3: Atualizar o usuário no nosso "banco de dados" simulado
        req.user.robloxUsername = canonicalUsername;
        req.user.avatarUrl = avatarUrl;

        res.json({ message: 'Perfil do Roblox atualizado com sucesso.', avatarUrl: avatarUrl });
    } catch (error) {
        console.error('Erro ao buscar dados do Roblox:', error);
        res.status(500).send('Erro interno do servidor ao processar a solicitação do Roblox.');
    }
});

app.put('/api/users/me/avatar', authMiddleware, (req, res) => {
    const { avatarData } = req.body; // Espera uma string Base64 (Data URL)

    if (!avatarData || !avatarData.startsWith('data:image/')) {
        return res.status(400).send('Dados de avatar inválidos. Esperado um Data URL (Base64).');
    }

    // Atualiza o avatar do usuário no "banco de dados" em memória
    req.user.avatarUrl = avatarData;

    // Opcional: Enviar um evento de socket para atualizar o avatar em outras sessões abertas do mesmo usuário
    // (fora do escopo desta alteração, mas uma boa prática)

    res.json({ message: 'Avatar atualizado com sucesso.', avatarUrl: req.user.avatarUrl });
});

app.put('/api/users/me/password', authMiddleware, (req, res) => {
    const { currentPassword, newPassword } = req.body;

    // 1. Valida a entrada
    if (!currentPassword || !newPassword) {
        return res.status(400).send('Senha atual e nova senha são obrigatórias.');
    }

    // 2. Verifica a senha atual
    const user = req.user; // Obtido do authMiddleware
    if (!bcrypt.compareSync(currentPassword, user.passwordHash)) {
        return res.status(403).send('Senha atual incorreta.');
    }

    // 3. Atualiza para a nova senha
    user.passwordHash = bcrypt.hashSync(newPassword, 10);

    res.send('Senha alterada com sucesso.');
});

// --- Rotas de Admin (Protegidas) ---
app.get('/api/admin/users', authMiddleware, adminMiddleware, (req, res) => {
    // Retorna todos os usuários, exceto senhas
    const userList = users
        .filter(u => u.username !== req.user.username) // Não mostra o admin logado na lista
        .map(u => {
            const { passwordHash, ...user } = u;
            return user;
        });
    res.json(userList);
});

app.put('/api/admin/users/:username/promote', authMiddleware, adminMiddleware, (req, res) => {
    const { username } = req.params;
    const user = users.find(u => u.username === username);

    if (!user) return res.status(404).send('Usuário não encontrado.');
    if (user.isAdmin) return res.status(400).send('Usuário já é um administrador.');

    user.isAdmin = true;
    res.send(`Usuário ${username} foi promovido a administrador.`);
});

app.put('/api/admin/users/:username/ban', authMiddleware, adminMiddleware, (req, res) => {
    const { username } = req.params;
    const { reason, durationDays } = req.body;
    const user = users.find(u => u.username === username);
    if (!user) return res.status(404).send('Usuário não encontrado.');
    if (user.isAdmin) return res.status(403).send('Não é possível banir um administrador.');

    if (user.status === 'banned') {
        // Unban logic
        user.status = 'unbanned'; // Altera o status para 'unbanned' para que o usuário possa reativar a conta.
        user.banDetails = { bannedBy: null, reason: null, expiresAt: null };

        // --- LÓGICA DE DESBANIMENTO EM TEMPO REAL ---
        const socketId = connectedUsers.get(username)?.socketId;
        if (socketId) {
            const targetSocket = io.sockets.sockets.get(socketId);
            if (targetSocket) {
                // Envia o evento 'unbanned' para o cliente específico
                targetSocket.emit('unbanned');
                console.log(`Notificação de desbanimento enviada em tempo real para ${username}.`);
            }
        }
        // --- FIM DA LÓGICA ---

        res.send(`Usuário ${username} foi desbanido.`);
    } else {
        // Ban logic
        user.status = 'banned';
        const expiresAt = durationDays ? new Date(Date.now() + durationDays * 24 * 60 * 60 * 1000) : null;
        user.banDetails = {
            bannedBy: req.user.username,
            reason: reason || 'Nenhum motivo fornecido.',
            expiresAt: expiresAt
        };

        // --- LÓGICA DE BANIMENTO EM TEMPO REAL ---
        const socketId = connectedUsers.get(username)?.socketId;
        if (socketId) {
            const targetSocket = io.sockets.sockets.get(socketId);
            if (targetSocket) {
                // Envia o evento 'banned' para o cliente específico
                targetSocket.emit('banned', { reason: user.banDetails.reason, bannedBy: user.banDetails.bannedBy, expiresAt: user.banDetails.expiresAt });
                // Não desconectamos o socket para que o usuário possa receber um futuro evento de 'unbanned'
                console.log(`Notificação de banimento enviada em tempo real para ${username}.`);
            }
        }
        // --- FIM DA LÓGICA ---

        res.send(`Usuário ${username} foi banido.`);
    }
});

app.post('/api/admin/impersonate/tester', authMiddleware, adminMiddleware, (req, res) => {
    const testerUser = users.find(u => u.isTester === true);
    if (!testerUser) {
        return res.status(404).send('Conta de Tester não encontrada.');
    }
    // Gera um token para a conta Tester
    const token = jwt.sign({ username: testerUser.username }, JWT_SECRET, { expiresIn: '1h' }); // Duração menor para impersonação
    res.json({ token });
});

app.put('/api/admin/users/:username/password', authMiddleware, adminMiddleware, (req, res) => {
    const { username } = req.params;
    const { newPassword } = req.body;
    const user = users.find(u => u.username === username);

    if (!user) return res.status(404).send('Usuário não encontrado.');
    if (!newPassword) return res.status(400).send('Nova senha não fornecida.');

    user.passwordHash = bcrypt.hashSync(newPassword, 10);
    res.send(`Senha do usuário ${username} alterada com sucesso.`);
});

app.get('/api/admin/banned-ips', authMiddleware, adminMiddleware, (req, res) => {
    res.json(Array.from(bannedIPs));
});

app.put('/api/admin/ip/:ip/toggle-ban', authMiddleware, adminMiddleware, (req, res) => {
    const { ip } = req.params;
    // Express já decodifica o parâmetro, mas vamos garantir que é um IP válido
    const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^::1$|^::ffff:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/;
    if (!ipRegex.test(ip)) {
        return res.status(400).send('Formato de IP inválido.');
    }

    if (bannedIPs.has(ip)) {
        // Unban IP
        bannedIPs.delete(ip);
        res.send(`IP ${ip} foi desbanido.`);
    } else {
        // Ban IP
        bannedIPs.add(ip);

        // Real-time kick
        for (const [username, connectionData] of connectedUsers.entries()) {
            if (connectionData.ip === ip) {
                const targetSocket = io.sockets.sockets.get(connectionData.socketId);
                if (targetSocket) {
                    targetSocket.emit('kicked', { reason: 'Seu endereço de IP foi banido por um administrador.' });
                    targetSocket.disconnect(true);
                    console.log(`Usuário "${username}" no IP ${ip} foi kickado devido a banimento de IP.`);
                }
            }
        }
        res.send(`IP ${ip} foi banido e todos os usuários conectados com este IP foram desconectados.`);
    }
});

// --- Lógica do Chat com Socket.IO ---
io.on('connection', (socket) => {
    // Autenticação e registro do socket
    const token = socket.handshake.auth.token;
    const ip = socket.handshake.address;
    console.log(`Um usuário se conectou: ${socket.id} do IP: ${ip}`);

    if (bannedIPs.has(ip)) {
        console.log(`Conexão bloqueada do IP banido: ${ip}`);
        socket.emit('kicked', { reason: 'Seu endereço de IP está banido.' });
        return socket.disconnect(true);
    }

    let user = null;
    if (token) {
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            user = users.find(u => u.username === decoded.username);
            if (user) {
                user.ip = ip; // ATUALIZA o IP do usuário no "banco de dados" com o IP mais recente da conexão
                console.log(`Usuário "${user.username}" (IP: ${ip}) registrado com o socket ID ${socket.id}`);
                connectedUsers.set(user.username, { socketId: socket.id, ip: ip });
            }
        } catch (err) {
            console.log('Token de socket inválido, conexão anônima.');
        }
    } else {
        console.log('Nenhum token fornecido para o socket, conexão anônima.');
    }
    
    socket.on('sendMessage', (message) => {
        if (!user) {
            return; // Não permite enviar mensagem sem estar logado
        }

        const censoredMessage = censorMessage(message);

        // Cria o objeto da mensagem para transmitir
        const messageData = {
            type: 'text',
            username: user.username,
            avatarUrl: user.avatarUrl,
            text: censoredMessage,
            timestamp: new Date()
        };

        // Envia a mensagem para todos os clientes conectados
        io.emit('newMessage', messageData);
    });

    socket.on('sendImageMessage', (imageUrl) => {
        if (!user || !user.isTester) {
            return; // Apenas testers podem enviar imagens
        }

        const messageData = {
            type: 'image',
            username: user.username,
            avatarUrl: user.avatarUrl,
            imageUrl: imageUrl,
            timestamp: new Date()
        };

        io.emit('newMessage', messageData);
    });

    socket.on('adminWarnUser', ({ username, reason }) => {
        // 1. Verifica se o usuário que está enviando o evento é um admin
        if (!user || !user.isAdmin) {
            console.log(`Ação de aviso não autorizada por: ${user ? user.username : 'usuário desconhecido'}`);
            return;
        }

        // 2. Encontra o socket do usuário alvo
        const targetConnection = connectedUsers.get(username);
        if (targetConnection) {
            const targetSocket = io.sockets.sockets.get(targetConnection.socketId);
            if (targetSocket) {
                // 3. Envia o evento de aviso para o usuário
                targetSocket.emit('banWarning', {
                    reason: reason || 'Você recebeu um aviso de um administrador por comportamento inadequado.',
                    admin: user.username
                });
                console.log(`Aviso de banimento enviado para "${username}" pelo admin "${user.username}".`);
            }
        }
    });

    socket.on('kickUserByIp', (ipToKick) => {
        if (!user || !user.isTester) {
            return; // Apenas testers podem kickar
        }
        if (!ipToKick) {
            return;
        }

        console.log(`Tester "${user.username}" está tentando kickar o IP: ${ipToKick}`);

        // Itera sobre os usuários conectados para encontrar o IP
        for (const [username, connectionData] of connectedUsers.entries()) {
            if (connectionData.ip === ipToKick) {
                const targetSocket = io.sockets.sockets.get(connectionData.socketId);
                const targetUser = users.find(u => u.username === username);

                // Não permite que testers kickem admins ou outros testers
                if (targetSocket && targetUser && !targetUser.isAdmin && !targetUser.isTester) {
                    targetSocket.emit('kicked', { reason: 'Você foi desconectado por um Tester.' });
                    targetSocket.disconnect(true);
                    console.log(`Usuário "${username}" no IP ${ipToKick} foi kickado pelo Tester "${user.username}".`);
                }
            }
        }
    });

    socket.on('disconnect', () => {
        console.log(`Usuário desconectado: ${socket.id}`);
        // Se o usuário estava registrado, removemos ele do mapa
        if (user && user.username) {
            if (connectedUsers.get(user.username)?.socketId === socket.id) {
                connectedUsers.delete(user.username);
                console.log(`Usuário "${user.username}" removido do mapa de conexões.`);
            }
        }
    });
});


// --- Servir os arquivos estáticos (Front-end) ---
// Esta linha diz ao Express para servir os arquivos estáticos (HTML, CSS, JS)
// da pasta raiz do projeto. `__dirname` garante que o caminho esteja sempre correto.
app.use(express.static(path.join(__dirname)));

app.get('*', (req, res) => {
    // Para qualquer outra rota que não seja uma API, sirva o index.html.
    // Isso é crucial para que o roteamento do lado do cliente funcione.
    res.sendFile(path.join(__dirname, 'index.html'));
});


server.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});