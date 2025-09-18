// --- Gerenciamento Global de Erros ---
window.addEventListener('error', (event) => {
    console.error('Algo deu errado... (Uncaught Exception)', event.error);
});

window.addEventListener('unhandledrejection', (event) => {
    console.error('Algo deu errado... (Unhandled Promise Rejection)', event.reason);
});

// --- Configuração Global ---
const API_URL = ''; // Deixe em branco, o servidor servirá a API na mesma URL
const socket = io(window.location.origin, { autoConnect: false, auth: {} });

const startButton = document.getElementById('startButton');
const initialView = document.getElementById('initial-view');
const progressContainer = document.getElementById('progressContainer');
const sidebar = document.getElementById('sidebar');
const hamburgerMenu = document.getElementById('hamburgerMenu');
const connectionStatus = document.getElementById('connection-status');
const statusText = connectionStatus.querySelector('.status-text');

const sidebarOverlay = document.getElementById('sidebar-overlay');

// Elementos do Modal
const modalOverlay = document.getElementById('modal-overlay');
const modalTitle = document.getElementById('modal-title');
const modalContent = document.getElementById('modal-content');
const modalCancelBtn = document.getElementById('modal-cancel-btn');
const modalConfirmBtn = document.getElementById('modal-confirm-btn');
// Painéis de Conteúdo
const allPanels = document.querySelectorAll('.content-panel');

// Formulários de Autenticação
const loginForm = document.getElementById('loginForm');
const signupForm = document.getElementById('signupForm');
const showSignup = document.getElementById('showSignup');
const showLogin = document.getElementById('showLogin');
const showRecover = document.getElementById('showRecover');
const backToLogin = document.getElementById('backToLogin');
const recoverForm = document.getElementById('recoverForm');
const userTableBody = document.getElementById('user-table-body');
const robloxUsernameForm = document.getElementById('robloxUsernameForm');
const robloxUsernameInput = document.getElementById('robloxUsernameInput');
const robloxLoginView = document.getElementById('roblox-login-view');
const chatView = document.getElementById('chat-view');
const chatForm = document.getElementById('chat-form');
const chatInput = document.getElementById('chat-input');
const loginEmail = document.getElementById('loginEmail');
const loginPassword = document.getElementById('loginPassword');

// Elementos de Configurações
const profilePic = document.getElementById('profilePic');
const profilePicInput = document.getElementById('profilePicInput');
const changePicBtn = document.querySelector('.change-pic-btn');
const signupUsername = document.getElementById('signupUsername');
const signupEmail = document.getElementById('signupEmail');
const welcomeUsername = document.getElementById('welcomeUsername');
const usernameChangeInput = document.getElementById('username-change');
const saveUsernameBtn = document.getElementById('saveUsernameBtn');
const newPassword = document.getElementById('newPassword');
const confirmNewPassword = document.getElementById('confirmNewPassword');
const savePasswordBtn = document.getElementById('savePasswordBtn');
const reactivateAccountBtn = document.getElementById('reactivateAccountBtn');

// Itens de Navegação da Sidebar
const navLogin = document.getElementById('nav-login');
const navStory = document.getElementById('nav-story');
const navSettings = document.getElementById('nav-settings');
const navLogout = document.getElementById('nav-logout');
const navAdmin = document.getElementById('nav-admin');
const impersonateTesterBtn = document.getElementById('impersonateTesterBtn');
const navTester = document.getElementById('nav-tester');

// --- Gerenciamento de Estado ---
let isLoggedIn = false;
let currentUsername = '';
let isAdmin = false;
let currentUser = null; // Armazena o objeto completo do usuário logado
let isTester = false;

// --- Sistema de Modal e Notificações ---
let modalConfirmCallback = null;

function hideModal() {
    modalOverlay.classList.add('hidden');
}

// Função genérica para exibir o modal
function showModal({ title, contentHTML, confirmText = 'Confirmar', cancelText = 'Cancelar', onConfirm, hideCancel = false }) {
    modalTitle.textContent = title;
    modalContent.innerHTML = contentHTML;
    modalConfirmBtn.textContent = confirmText;
    modalCancelBtn.textContent = cancelText;
    
    modalCancelBtn.classList.toggle('hidden', hideCancel);

    modalConfirmCallback = onConfirm;
    modalOverlay.classList.remove('hidden');
}

modalCancelBtn.addEventListener('click', hideModal);

modalConfirmBtn.addEventListener('click', () => {
    if (typeof modalConfirmCallback === 'function') {
        const inputs = modalContent.querySelectorAll('input');
        if (inputs.length > 0) {
            const values = {};
            inputs.forEach(input => { values[input.id] = input.value; });
            modalConfirmCallback(values);
        } else {
            modalConfirmCallback(); // Para confirmações simples
        }
    }
    hideModal();
});

// Wrapper para alertas simples
function showCustomAlert(message, title = 'Aviso') {
    showModal({ title, contentHTML: `<p>${message}</p>`, confirmText: 'OK', hideCancel: true, onConfirm: () => {} });
}

// Wrapper para confirmações simples
function showCustomConfirm(message, title = 'Confirmação', onConfirm) {
    showModal({ title, contentHTML: `<p>${message}</p>`, onConfirm });
}


// --- Internacionalização (i18n) e Temas ---

const translations = {
    en: {
        navLogin: 'Login',
        navStory: 'Story',
        navSettings: 'Settings',
        navAdmin: 'Admin Panel',
        navLogout: 'Logout',
        settingsAppearanceTitle: 'Appearance',
        settingsTheme: 'Dark Mode',
        settingsLanguage: 'Language',
        settingsProfileChange: 'Change',
        // Adicione mais chaves de tradução para o inglês aqui
    },
    pt: {
        navLogin: 'Login',
        navStory: 'História',
        navSettings: 'Configurações',
        navAdmin: 'Painel Admin',
        navLogout: 'Sair',
        settingsAppearanceTitle: 'Aparência',
        settingsTheme: 'Modo Escuro',
        settingsLanguage: 'Idioma',
        settingsProfileChange: 'Alterar',
        // Adicione mais chaves de tradução para o português aqui
    }
};

function applyTranslations(lang = 'pt') {
    document.querySelectorAll('[data-translate-key]').forEach(el => {
        const key = el.dataset.translateKey;
        const translation = translations[lang][key];
        if (translation) {
            // Handle title attribute for elements like buttons
            if (el.title !== undefined && el.tagName === 'BUTTON') {
                el.title = translation;
            }
            // Handle placeholders
            else if (el.placeholder !== undefined && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA')) {
                el.placeholder = translation;
            } else {
                // Default case for simple text elements (like the spans in the sidebar)
                el.textContent = translation;
            }
        }
    });
}

function setLanguage(lang) {
    localStorage.setItem('chatyni_language', lang);
    document.documentElement.lang = lang;
    applyTranslations(lang);
    const languageSelector = document.getElementById('languageSelector');
    if (languageSelector) languageSelector.value = lang;
}

function setTheme(theme) {
    localStorage.setItem('chatyni_theme', theme);
    document.documentElement.setAttribute('data-theme', theme);
    const themeToggle = document.getElementById('themeToggle');
    if (themeToggle) themeToggle.checked = theme === 'dark';
}

function updateUIForLoginState() {
    navLogin.classList.toggle('hidden', isLoggedIn);
    navSettings.classList.toggle('hidden', !isLoggedIn);
    navLogout.classList.toggle('hidden', !isLoggedIn);
    navAdmin.classList.toggle('hidden', !isAdmin);
    navTester.classList.toggle('hidden', !isTester);

    if (isLoggedIn) {
        welcomeUsername.textContent = currentUsername || 'Usuário';
        setActivePanel('welcomeContent');
    } else {
        setActivePanel('loginContent');
    }
}

function setActivePanel(panelId) {
    // Desativa todos os painéis e links da sidebar
    allPanels.forEach(panel => panel.classList.remove('active'));
    document.querySelectorAll('.sidebar a[data-target]').forEach(link => link.classList.remove('active'));

    // Ativa o painel de conteúdo alvo
    const targetPanel = document.getElementById(panelId);
    if (targetPanel) {
        targetPanel.classList.add('active');
    }

    // Ativa o link correspondente na sidebar
    const targetLink = document.querySelector(`.sidebar a[data-target="${panelId}"]`);
    if (targetLink) {
        targetLink.classList.add('active');
    }

    // Aplica traduções sempre que um painel é ativado
    applyTranslations(localStorage.getItem('chatyni_language') || 'pt');

    // Preenche o campo de nome nas configurações quando o painel é aberto
    if (panelId === 'settingsContent') {
        usernameChangeInput.value = currentUsername;
    }
    if (panelId === 'adminContent') {
        buildAdminUserTable();
        buildBannedIpList();
    }
    // Lógica para mostrar a view correta dentro do painel de chat
    if (panelId === 'chatContent') {
        if (currentUser && currentUser.robloxUsername) {
            robloxLoginView.classList.add('hidden');
            chatView.classList.remove('hidden');
        } else {
            robloxLoginView.classList.remove('hidden');
            chatView.classList.add('hidden');
        }
    }

    // Fecha a sidebar ao selecionar um painel
    sidebar.classList.remove('show');
    hamburgerMenu.classList.remove('active');
    sidebarOverlay.classList.remove('show');
}

async function refreshCurrentUser(token) {
    try {
        const res = await fetch(`${API_URL}/api/users/me`, { headers: { 'Authorization': `Bearer ${token}` } });
        if (!res.ok) throw new Error('Não foi possível atualizar os dados do usuário.');
        const user = await res.json();
        currentUser = user; // Update the global state object
        profilePic.src = user.avatarUrl; // Also update the profile pic in settings
        return user;
    } catch (error) {
        console.error(error);
        alert(error.message);
        return null;
    }
}

// --- Fluxo Inicial e Persistência ---
function checkInitialState() {
    // Carrega tema e idioma salvos
    const savedLang = localStorage.getItem('chatyni_language') || 'pt';
    const savedTheme = localStorage.getItem('chatyni_theme') || 'dark';
    setLanguage(savedLang);
    setTheme(savedTheme);

    const token = localStorage.getItem('chatyni_token');
    if (token) {
        fetchAndSetUser(token);
    }
}

async function fetchAndSetUser(token) {
    try {
        const res = await fetch(`${API_URL}/api/users/me`, { headers: { 'Authorization': `Bearer ${token}` } });
        if (!res.ok) throw new Error('Sessão inválida');
        const user = await res.json();

        currentUser = user; // Armazena o objeto do usuário
        isLoggedIn = true;
        currentUsername = user.username;
        isAdmin = user.isAdmin;
        isTester = user.isTester;
        profilePic.src = user.avatarUrl;

        // Conecta ao chat
        socket.auth.token = token;
        socket.connect();

        initialView.classList.add('hidden'); // Pula a tela de "Iniciar" se já estiver logado
        hamburgerMenu.classList.add('show');
        updateUIForLoginState();
    } catch (error) {
        console.error(error);
        logout(); // Limpa o token inválido
    }
}

startButton.addEventListener('click', () => {
    initialView.style.opacity = '0'; // Inicia o fade-out da tela inicial

    setTimeout(() => {
        initialView.classList.add('hidden'); // Esconde a tela inicial após o fade-out
        progressContainer.classList.add('show');
    }, 400);

    setTimeout(() => {
        progressContainer.classList.remove('show');

        setTimeout(() => {
            hamburgerMenu.classList.add('show');
            connectionStatus.classList.add('show');
            updateUIForLoginState(); // Mostra o painel de login por padrão
        }, 400);

    }, 3400);
});

// --- Menu Hamburger ---
hamburgerMenu.addEventListener('click', () => {
    hamburgerMenu.classList.toggle('active');
    sidebar.classList.toggle('show');
    sidebarOverlay.classList.toggle('show');
});

// Fecha o menu ao clicar fora (no overlay)
sidebarOverlay.addEventListener('click', () => {
    hamburgerMenu.classList.remove('active');
    sidebar.classList.remove('show');
    sidebarOverlay.classList.remove('show');
});

// --- Troca de Formulário de Autenticação ---
showSignup.addEventListener('click', (e) => {
    e.preventDefault();
    loginForm.classList.remove('show');
    signupForm.classList.add('show');
});

showLogin.addEventListener('click', (e) => {
    e.preventDefault();
    signupForm.classList.remove('show');
    loginForm.classList.add('show');
});

showRecover.addEventListener('click', (e) => {
    e.preventDefault();
    setActivePanel('recoverContent');
});

backToLogin.addEventListener('click', (e) => {
    e.preventDefault();
    setActivePanel('loginContent');
});

recoverForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const email = e.target.querySelector('input[type="email"]').value;
    showCustomAlert(`Se um usuário com o email ${email} existir, um link de recuperação foi enviado.`);
    setActivePanel('loginContent');
});


// --- Simulação de Login/Logout ---
async function handleAuth(e) {
    e.preventDefault(); // Previne o envio real do formulário
    const form = e.target;
    const isRegister = form.id === 'signupForm';
    const endpoint = isRegister ? '/api/register' : '/api/login';
    const body = {};

    if (isRegister) {
        body.username = form.querySelector('#signupUsername').value;
        body.email = form.querySelector('#signupEmail').value;
        body.password = form.querySelector('#signupPassword').value;
    } else {
        body.email = form.querySelector('#loginEmail').value;
        body.password = form.querySelector('#loginPassword').value;
    }

    try {
        const res = await fetch(API_URL + endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });

        if (!res.ok) {
            const errorData = await res.json().catch(() => ({ message: res.statusText }));
            if (res.status === 403) {
                if (errorData.banDetails) {
                    // User is banned, show ban screen
                    document.getElementById('bannedBy').textContent = errorData.banDetails.bannedBy || 'Sistema';
                    document.getElementById('banReason').textContent = errorData.banDetails.reason || 'N/A';
                    document.getElementById('banExpires').textContent = errorData.banDetails.expiresAt ? new Date(errorData.banDetails.expiresAt).toLocaleString('pt-BR') : 'Permanente';
                    setActivePanel('bannedContent');
                    return; // Stop the login process
                }
                if (errorData.needsReactivation) {
                    // User was unbanned, show reactivation screen
                    setActivePanel('unbannedContent');
                    return; // Stop the login process
                }
            }
            throw new Error(errorData.message || 'Ocorreu um erro.');
        }

        if (isRegister) {
            showCustomAlert('Cadastro realizado com sucesso! Por favor, faça o login.');
            setActivePanel('loginContent');
            form.reset();
        } else {
            const { token } = await res.json();
            localStorage.setItem('chatyni_token', token);
            await fetchAndSetUser(token);
        }
    } catch (error) {
        showCustomAlert(error.message, 'Erro');
    }
}

function logout() {
    currentUsername = '';
    isLoggedIn = false;
    currentUser = null;
    isAdmin = false;
    isTester = false;
    localStorage.removeItem('chatyni_token');
    socket.disconnect();
    updateUIForLoginState();
}

loginForm.addEventListener('submit', handleAuth);
signupForm.addEventListener('submit', handleAuth);
changePicBtn.addEventListener('click', () => {
    profilePicInput.click();
});

// Desabilita o botão de salvar nome de usuário, pois não está implementado
saveUsernameBtn.disabled = true;
saveUsernameBtn.title = 'Funcionalidade a ser implementada no futuro.';

savePasswordBtn.addEventListener('click', async () => {
    const currentPass = document.getElementById('currentPassword').value;
    const newPass = newPassword.value;
    const confirmPass = confirmNewPassword.value;

    if (!currentPass || !newPass || !confirmPass) {
        showCustomAlert('Por favor, preencha todos os campos de senha.');
        return;
    }
    if (newPass !== confirmPass) {
        showCustomAlert('As novas senhas não coincidem.');
        return;
    }
    
    try {
        const token = localStorage.getItem('chatyni_token');
        const res = await fetch(`${API_URL}/api/users/me/password`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
            body: JSON.stringify({ currentPassword: currentPass, newPassword: newPass })
        });

        const responseText = await res.text();
        if (!res.ok) throw new Error(responseText);

        showCustomAlert(responseText, 'Sucesso');
        document.getElementById('currentPassword').value = '';
        newPassword.value = '';
        confirmNewPassword.value = '';
    } catch (error) {
        showCustomAlert(error.message, 'Erro ao Alterar Senha');
    }
});

impersonateTesterBtn.addEventListener('click', async () => {
    showCustomConfirm(
        'Isso irá deslogar você da sua conta de Admin e logar como Tester. Deseja continuar?',
        'Entrar como Tester',
        async () => {
            try {
                const token = localStorage.getItem('chatyni_token');
                const res = await fetch(`${API_URL}/api/admin/impersonate/tester`, {
                    method: 'POST',
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                if (!res.ok) throw new Error(await res.text());

                const { token: testerToken } = await res.json();
                localStorage.setItem('chatyni_token', testerToken);
                showCustomAlert('Logado como Tester com sucesso! A página será recarregada.');
                window.location.reload();
            } catch (error) {
                showCustomAlert(`Erro ao entrar na conta Tester: ${error.message}`);
            }
        }
    );
});

// --- Navegação da Sidebar ---
sidebar.addEventListener('click', (e) => {
    const link = e.target.closest('a');
    if (!link) return;

    const targetPanel = link.dataset.target;
    const action = link.dataset.action;

    if (targetPanel) {
        e.preventDefault();
        setActivePanel(targetPanel);
    } else if (action === 'logout') {
        e.preventDefault();
        logout();
    }
});

const settingsContainer = document.querySelector('.settings-container');
if (settingsContainer) {
    const tabButtons = settingsContainer.querySelectorAll('.settings-tab-btn');
    const tabContents = settingsContainer.querySelectorAll('.settings-tab-content');

    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            // Remove a classe 'active' de todos os botões e conteúdos
            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabContents.forEach(content => content.classList.remove('active'));

            // Adiciona a classe 'active' ao botão clicado e ao conteúdo correspondente
            button.classList.add('active');
            const tabId = button.dataset.tab;
            document.getElementById(`tab-${tabId}`).classList.add('active');
        });
    });
}

profilePicInput.addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (file) {
        const reader = new FileReader();
        reader.onload = async (event) => {
            const base64String = event.target.result;

            try {
                const token = localStorage.getItem('chatyni_token');
                const res = await fetch(`${API_URL}/api/users/me/avatar`, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}`
                    },
                    body: JSON.stringify({ avatarData: base64String })
                });

                if (!res.ok) {
                    throw new Error(await res.text());
                }

                const data = await res.json();
                profilePic.src = data.avatarUrl; // Atualiza a foto no painel
                await refreshCurrentUser(token); // Sincroniza o usuário para atualizar o avatar em outros lugares
                showCustomAlert('Foto de perfil atualizada com sucesso!');

            } catch (error) {
                console.error('Erro ao atualizar avatar:', error);
                showCustomAlert(`Erro ao atualizar foto: ${error.message}`);
            }
        };
        reader.readAsDataURL(file);
    }
});

async function buildBannedIpList() {
    try {
        const token = localStorage.getItem('chatyni_token');
        const res = await fetch(`${API_URL}/api/admin/banned-ips`, { headers: { 'Authorization': `Bearer ${token}` } });
        if (!res.ok) throw new Error('Não foi possível carregar a lista de IPs banidos.');
        const bannedIPs = await res.json();

        const bannedIpListEl = document.getElementById('bannedIpList');
        bannedIpListEl.innerHTML = ''; // Limpa a lista

        if (bannedIPs.length === 0) {
            bannedIpListEl.innerHTML = '<li>Nenhum IP banido.</li>';
        } else {
            bannedIPs.forEach(ip => {
                const li = document.createElement('li');
                li.textContent = ip;
                bannedIpListEl.appendChild(li);
            });
        }
    } catch (error) {
        showCustomAlert(error.message, 'Erro no Admin Panel');
    }
}

document.getElementById('ipBanForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const ipInput = document.getElementById('ipBanInput');
    const ip = ipInput.value.trim();
    if (!ip) return;

    try {
        const token = localStorage.getItem('chatyni_token');
        const res = await fetch(`${API_URL}/api/admin/ip/${encodeURIComponent(ip)}/toggle-ban`, { method: 'PUT', headers: { 'Authorization': `Bearer ${token}` } });
        if (!res.ok) throw new Error(await res.text());
        showCustomAlert(await res.text(), 'Gerenciamento de IP');
        ipInput.value = '';
        buildAdminUserTable(); // Refresh user list to show updated status
        buildBannedIpList(); // Refresh banned IP list
    } catch (error) {
        showCustomAlert(`Erro ao gerenciar IP: ${error.message}`);
    }
});

async function buildAdminUserTable() {
    try {
        const token = localStorage.getItem('chatyni_token');
        const res = await fetch(`${API_URL}/api/admin/users`, { headers: { 'Authorization': `Bearer ${token}` } });
        if (!res.ok) throw new Error('Não foi possível carregar os usuários.');
        const users = await res.json();

        userTableBody.innerHTML = ''; // Limpa a tabela
        users.forEach(user => {
            const row = document.createElement('tr');
            row.dataset.username = user.username;
            const isBanned = user.status === 'banned';
            if (isBanned) row.style.cssText = 'opacity: 0.5; text-decoration: line-through;';

            let actionButtonsHTML = '';
            if (user.isAdmin) {
                actionButtonsHTML = '<span>Admin</span>';
            } else {
                actionButtonsHTML = `
                    <button class="admin-btn warn">Avisar</button>
                    <button class="admin-btn ban">${isBanned ? 'Desbanir' : 'Banir'}</button>
                    <button class="admin-btn change-pass">Alterar Senha</button>
                    <button class="admin-btn promote">Promover</button>
                `;
            }

            row.innerHTML = `
                <td>${user.username}</td>
                <td>${user.ip}</td>
                <td class="action-buttons">
                    ${actionButtonsHTML}
                </td>
            `;
            userTableBody.appendChild(row);
        });
    } catch (error) {
        showCustomAlert(error.message, 'Erro no Admin Panel');
    }
}

userTableBody.addEventListener('click', async (e) => {
    const target = e.target;
    if (target.classList.contains('admin-btn')) {
        try {
            const userRow = target.closest('tr');
            const username = userRow.dataset.username;
            const token = localStorage.getItem('chatyni_token');

            if (target.classList.contains('warn')) {
                showModal({
                    title: `Avisar Usuário: ${username}`,
                    contentHTML: `
                        <label for="warnReasonInput">Motivo do Aviso</label>
                        <input type="text" id="warnReasonInput" placeholder="Ex: Linguagem imprópria no chat" required>
                    `,
                    confirmText: 'Enviar Aviso',
                    onConfirm: (values) => {
                        const reason = values.warnReasonInput;
                        if (!reason) {
                            showCustomAlert('O motivo é obrigatório para enviar um aviso.');
                            return;
                        }
                        // Emite o evento de aviso para o servidor
                        socket.emit('adminWarnUser', { username, reason });
                        showCustomAlert(`Aviso enviado para ${username}.`);
                    }
                });
            } else if (target.classList.contains('ban')) {
                const isBanning = !target.textContent.includes('Desbanir');
                if (isBanning) {
                    showModal({
                        title: `Banir Usuário: ${username}`,
                        contentHTML: `
                            <label for="banReasonInput">Motivo do Banimento</label>
                            <input type="text" id="banReasonInput" placeholder="Ex: Comportamento inadequado" required>
                            <label for="banDurationInput">Duração (em dias)</label>
                            <input type="number" id="banDurationInput" placeholder="Deixe em branco para permanente">
                        `,
                        onConfirm: async (values) => {
                            const reason = values.banReasonInput;
                            if (!reason) {
                                showCustomAlert('O motivo é obrigatório para banir um usuário.');
                                return;
                            }
                            const res = await fetch(`${API_URL}/api/admin/users/${username}/ban`, {
                                method: 'PUT',
                                headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
                                body: JSON.stringify({ reason, durationDays: values.banDurationInput || null })
                            });
                            if (!res.ok) throw new Error(await res.text());
                            showCustomAlert(await res.text());
                            buildAdminUserTable();
                        }
                    });
                } else { // Unbanning
                    showCustomConfirm(`Tem certeza que deseja desbanir ${username}?`, 'Confirmar Desbanimento', async () => {
                        const res = await fetch(`${API_URL}/api/admin/users/${username}/ban`, { 
                            method: 'PUT', headers: { 'Authorization': `Bearer ${token}` } 
                        });
                        if (!res.ok) throw new Error(await res.text());
                        showCustomAlert(await res.text());
                        buildAdminUserTable();
                    });
                }
            } else if (target.classList.contains('change-pass')) {
                showModal({
                    title: `Alterar Senha de: ${username}`,
                    contentHTML: `
                        <label for="newPasswordAdminInput">Nova Senha</label>
                        <input type="password" id="newPasswordAdminInput" placeholder="Digite a nova senha" required>
                    `,
                    onConfirm: async (values) => {
                        const newPassword = values.newPasswordAdminInput;
                        if (!newPassword) {
                            showCustomAlert('A nova senha não pode estar em branco.');
                            return;
                        }
                        const res = await fetch(`${API_URL}/api/admin/users/${username}/password`, {
                            method: 'PUT',
                            headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
                            body: JSON.stringify({ newPassword })
                        });
                        if (!res.ok) throw new Error(await res.text());
                        showCustomAlert(await res.text());
                    }
                });
            } else if (target.classList.contains('promote')) {
                showCustomConfirm(`Tem certeza que deseja promover ${username} a administrador? Esta ação não pode ser desfeita.`, 'Promover a Admin', async () => {
                    const res = await fetch(`${API_URL}/api/admin/users/${username}/promote`, { method: 'PUT', headers: { 'Authorization': `Bearer ${token}` } });
                    if (!res.ok) throw new Error(await res.text());
                    showCustomAlert(await res.text());
                    buildAdminUserTable();
                });
            }
        } catch (error) {
            showCustomAlert(`Erro na ação de admin: ${error.message}`);
        }
    }
});

socket.on('banWarning', (data) => {
    const reason = data.reason || 'Comportamento inadequado.';
    const admin = data.admin || 'um administrador';
    showCustomAlert(`Você recebeu um aviso de ${admin}.\n\nMotivo: ${reason}\n\nEste é um aviso de banimento. A reincidência pode levar à suspensão da sua conta.`, 'AVISO');
});

reactivateAccountBtn.addEventListener('click', () => {
    // Limpa o estado e leva o usuário de volta à tela de login
    logout();
});

// --- Lógica do Chat Global e Roblox API ---
// A lógica do Roblox foi movida para o back-end para ser associada ao perfil do usuário.
robloxUsernameForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = robloxUsernameInput.value.trim();
    if (!username) return;

    const submitButton = e.target.querySelector('button');
    const originalButtonText = submitButton.textContent;
    submitButton.textContent = 'Buscando...';
    submitButton.disabled = true;

    try {
        const token = localStorage.getItem('chatyni_token');
        const res = await fetch(`${API_URL}/api/users/me/roblox`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ robloxUsername: username })
        });

        if (!res.ok) {
            const errorText = await res.text();
            throw new Error(errorText);
        }

        // Re-sincroniza o estado do cliente com o servidor após a atualização
        await refreshCurrentUser(token);

        // Agora que o usuário está atualizado, podemos mudar a visualização
        robloxLoginView.classList.add('hidden');
        chatView.classList.remove('hidden');

    } catch (error) {
        showCustomAlert(`Erro: ${error.message}`);
    } finally {
        submitButton.textContent = originalButtonText;
        submitButton.disabled = false;
    }
});

chatForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const messageText = chatInput.value.trim();
    if (!messageText) return;
    socket.emit('sendMessage', messageText);
    chatInput.value = '';
});

socket.on('newMessage', (data) => {
    addMessageToChat(data);
});

socket.on('connect', () => {
    console.log('Conectado ao servidor!');
    connectionStatus.classList.add('connected');
    statusText.textContent = 'Conectado';
});

socket.on('disconnect', () => {
    console.log('Desconectado do servidor.');
    connectionStatus.classList.remove('connected');
    statusText.textContent = 'Desconectado';
});

socket.on('banned', (data) => {
    console.log('Você foi banido em tempo real!', data.reason);

    // 1. Mostra uma mensagem para o usuário
    showCustomAlert(`Você foi banido! Motivo: ${data.reason}`, 'Conta Suspensa');

    // 2. Atualiza os detalhes na página de banimento
    document.getElementById('bannedBy').textContent = data.bannedBy || 'Sistema';
    document.getElementById('banReason').textContent = data.reason || 'N/A';
    document.getElementById('banExpires').textContent = data.expiresAt ? new Date(data.expiresAt).toLocaleString('pt-BR') : 'Permanente';

    // 3. Mostra a tela de banimento, mantendo o socket conectado para ouvir o evento de desbanimento
    setActivePanel('bannedContent');
});

socket.on('unbanned', () => {
    console.log('Você foi desbanido em tempo real!');

    // 1. Mostra uma mensagem para o usuário
    showCustomAlert('Sua conta foi desbanida e está pronta para ser reativada.', 'Você foi Desbanido!');

    // 2. Mostra a tela de reativação. O usuário precisará fazer login novamente.
    setActivePanel('unbannedContent');
});

socket.on('kicked', (data) => {
    const reason = data.reason || 'Você foi desconectado por um moderador.';
    showCustomAlert(reason, 'Desconectado');
    logout();
});


function addMessageToChat(data) {
    const chatMessages = document.getElementById('chat-messages');
    const messageEl = document.createElement('div');
    const isSelf = data.username === currentUsername;
    let messageContentHTML = '';

    if (data.type === 'image' && data.imageUrl) {
        messageContentHTML = `<img src="${data.imageUrl}" alt="Imagem enviada por ${data.username}" class="chat-image">`;
    } else {
        messageContentHTML = `<div class="chat-text">${data.text}</div>`;
    }

    messageEl.classList.add('chat-message', isSelf ? 'self' : 'other');
    messageEl.innerHTML = `
        <img src="${data.avatarUrl}" alt="${data.username}" class="chat-avatar">
        <div class="chat-bubble">
            <div class="chat-username">${data.username}</div>
            ${messageContentHTML}
        </div>
    `;
    chatMessages.appendChild(messageEl);
    chatMessages.scrollTop = chatMessages.scrollHeight; // Rola para a mensagem mais recente
}

document.getElementById('kickUserForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const kickIpInput = document.getElementById('kickIpInput');
    const ipToKick = kickIpInput.value.trim();
    if (ipToKick) {
        socket.emit('kickUserByIp', ipToKick);
        showCustomAlert(`Sinal para kickar o IP ${ipToKick} foi enviado.`);
        kickIpInput.value = '';
    }
});

document.getElementById('sendImageForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const imageUrlInput = document.getElementById('imageUrlInput');
    const imageUrl = imageUrlInput.value.trim();
    if (imageUrl) {
        socket.emit('sendImageMessage', imageUrl);
        imageUrlInput.value = '';
        // Opcional: fechar o painel ou dar feedback
        showCustomAlert('Imagem enviada!');
    }
});

function initializeAppearanceSettings() {
    // A lógica de criação de elementos foi movida para o HTML.
    // Agora, apenas adicionamos os event listeners aos elementos que já existem.
    const themeToggle = document.getElementById('themeToggle');
    const languageSelector = document.getElementById('languageSelector');

    if (!themeToggle || !languageSelector) {
        console.error("Elementos de tema ou idioma não encontrados na aba de aparência!");
        return;
    }

    themeToggle.addEventListener('change', (e) => {
        setTheme(e.target.checked ? 'dark' : 'light');
    });

    languageSelector.addEventListener('change', (e) => {
        setLanguage(e.target.value);
    });
}

function injectThemeStyles() {
    const style = document.createElement('style');
    style.id = 'theme-styles';
    style.textContent = `
        /* Mova estas variáveis para o topo do seu arquivo style.css */
        :root {
            --bg-color: #1a1a1d; --panel-bg: #25282c; --text-color: #f0f0f0;
            --primary-color: #6f2dbd; --border-color: #404040; --input-bg: #33363b;
        }
        [data-theme="light"] {
            --bg-color: #f0f2f5; --panel-bg: #ffffff; --text-color: #1c1e21;
            --primary-color: #1877f2; --border-color: #ced0d4; --input-bg: #e4e6eb;
        }
        /* Aplique as variáveis nos seus elementos. Exemplo: */
        body { background-color: var(--bg-color); color: var(--text-color); }
        .content-panel, .sidebar { background-color: var(--panel-bg); border-color: var(--border-color); }
        input, select, textarea { background-color: var(--input-bg); color: var(--text-color); border-color: var(--border-color); }
        #startButton, #chat-form button { background-color: var(--primary-color); color: white; border: none; }
    `;
    document.head.appendChild(style);
}

// Inicializa as novas funcionalidades
injectThemeStyles();
initializeAppearanceSettings();

// Verifica o estado de login assim que a página carrega
checkInitialState();