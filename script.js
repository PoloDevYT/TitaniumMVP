document.addEventListener('DOMContentLoaded', () => {
    const navbar = document.getElementById('navbar');

    window.addEventListener('scroll', () => {
        if (window.scrollY > 50) {
            navbar.classList.add('scrolled');
        } else {
            navbar.classList.remove('scrolled');
        }
    });
    const revealElements = document.querySelectorAll('.reveal');

    const revealObserver = new IntersectionObserver((entries, observer) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('active');
                observer.unobserve(entry.target);
            }
        });
    }, {
        root: null,
        threshold: 0.15,
        rootMargin: "0px"
    });

    revealElements.forEach(el => revealObserver.observe(el));
    const parallaxBg = document.querySelector('.parallax-bg');
    const parallaxSection = document.querySelector('.parallax-section');

    window.addEventListener('scroll', () => {
        if (!parallaxSection) return;

        const rect = parallaxSection.getBoundingClientRect();
        const scrollSpeed = 0.5;
        if (rect.top < window.innerHeight && rect.bottom > 0) {
            const yPos = (window.scrollY - parallaxSection.offsetTop) * scrollSpeed;
            const limit = 100;
            parallaxBg.style.transform = `translateY(${yPos * 0.2}px)`;
        }
    });
    const accordions = document.querySelectorAll('.accordion-header');

    accordions.forEach(acc => {
        acc.addEventListener('click', () => {
            const content = acc.nextElementSibling;
            if (content.style.maxHeight) {
                content.style.maxHeight = null;
                acc.querySelector('i').style.transform = 'rotate(0deg)';
                acc.style.color = '#fff';
            } else {
                document.querySelectorAll('.accordion-content').forEach(c => c.style.maxHeight = null);
                document.querySelectorAll('.accordion-header i').forEach(i => i.style.transform = 'rotate(0deg)');
                document.querySelectorAll('.accordion-header').forEach(h => h.style.color = '#fff');

                content.style.maxHeight = content.scrollHeight + "px";
                acc.querySelector('i').style.transform = 'rotate(180deg)';
                acc.style.color = 'var(--accent-color)';
            }
        });
    });
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const targetId = this.getAttribute('href');
            if (targetId === '#') return;

            const targetElement = document.querySelector(targetId);
            if (targetElement) {
                const headerOffset = 80;
                const elementPosition = targetElement.getBoundingClientRect().top;
                const offsetPosition = elementPosition + window.pageYOffset - headerOffset;

                window.scrollTo({
                    top: offsetPosition,
                    behavior: "smooth"
                });
            }
        });
    });
    const loginForm = document.getElementById('login-form');
    const registerForm = document.getElementById('register-form');
    const showRegisterBtn = document.getElementById('show-register');
    const showLoginBtn = document.getElementById('show-login');

    if (loginForm && registerForm) {
        showRegisterBtn.addEventListener('click', (e) => {
            e.preventDefault();
            loginForm.classList.add('hidden');
            registerForm.classList.remove('hidden');
        });

        showLoginBtn.addEventListener('click', (e) => {
            e.preventDefault();
            registerForm.classList.add('hidden');
            loginForm.classList.remove('hidden');
        });
        const showToast = (message, type = 'success') => {
            const container = document.getElementById('toast-container') || createToastContainer();
            const toast = document.createElement('div');
            toast.className = `toast-notification ${type}`;

            const icon = type === 'success' ? 'check-circle' : 'alert-circle';
            const title = type === 'success' ? 'SUCESSO' : 'ERRO';

            toast.innerHTML = `
                <div class="toast-icon"><i data-lucide="${icon}"></i></div>
                <div class="toast-content">
                    <div class="toast-title">${title}</div>
                    <div class="toast-msg">${message}</div>
                </div>
                <div class="toast-progress">
                    <div class="toast-progress-bar" style="animation: progressShrink 3s linear forwards;"></div>
                </div>
            `;

            container.appendChild(toast);
            lucide.createIcons();
            requestAnimationFrame(() => {
                toast.classList.add('active');
            });
            setTimeout(() => {
                toast.classList.remove('active');
                setTimeout(() => toast.remove(), 400);
            }, 3000);
        };

        const createToastContainer = () => {
            const el = document.createElement('div');
            el.id = 'toast-container';
            document.body.appendChild(el);
            return el;
        };
        const notify = (msg, isError = false) => {
            showToast(msg, isError ? 'error' : 'success');
        };
        const registerFormEl = registerForm.querySelector('form');
        registerFormEl.addEventListener('submit', async (e) => {
            e.preventDefault();
            const submitBtn = registerFormEl.querySelector('button');
            const originalText = submitBtn.innerText;
            submitBtn.innerText = 'Processando...';
            submitBtn.disabled = true;

            const inputs = registerFormEl.querySelectorAll('input');
            const payload = {
                name: inputs[0].value,
                email: inputs[1].value,
                password: inputs[2].value,
                whatsapp: inputs[3].value
            };

            try {
                const res = await fetch('/api/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();

                if (res.ok) {
                    notify(`Bem-vindo à Elite, ${data.user.name}.`);
                    localStorage.setItem('titanium_token', data.token);
                    setTimeout(() => window.location.href = '/', 1000);
                } else {
                    notify(data.error || 'Falha no registro', true);
                }
            } catch (err) {
                notify('Erro de conexão com o servidor.', true);
            } finally {
                submitBtn.innerText = originalText;
                submitBtn.disabled = false;
            }
        });
        const loginFormEl = loginForm.querySelector('form');
        loginFormEl.addEventListener('submit', async (e) => {
            e.preventDefault();
            const submitBtn = loginFormEl.querySelector('button');
            const originalText = submitBtn.innerText;
            submitBtn.innerText = 'Autenticando...';
            submitBtn.disabled = true;

            const inputs = loginFormEl.querySelectorAll('input');
            const payload = {
                email: inputs[0].value,
                password: inputs[1].value
            };

            try {
                const res = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();

                if (res.ok) {
                    notify(`Login aprovado. Bem-vindo de volta.`);
                    localStorage.setItem('titanium_token', data.token);
                    localStorage.setItem('titanium_user_name', data.user.name);
                    localStorage.setItem('titanium_user_role', data.user.role);
                    setTimeout(() => window.location.href = '/', 1000);
                } else {
                    notify(data.error || 'Credenciais inválidas', true);
                }
            } catch (err) {
                notify('Erro de conexão.', true);
            } finally {
                submitBtn.innerText = originalText;
                submitBtn.disabled = false;
            }
        });
    }
    const token = localStorage.getItem('titanium_token');
    const userName = localStorage.getItem('titanium_user_name');
    const navCta = document.querySelector('.nav-cta');
    if (token && navCta) {
        const userFirstName = userName ? userName.split(' ')[0] : 'Membro';
        const userRole = localStorage.getItem('titanium_user_role');

        let adminLink = '';
        if (userRole === 'admin') {
            adminLink = `<a href="/admin" style="color: #FFD700;"><i data-lucide="shield-alert"></i> Painel Admin</a>`;
        }

        const profileHtml = `
            <div class="user-menu-container" id="nav-user-menu">
                <div class="user-profile-trigger">
                    <span class="user-name">${userFirstName}</span>
                    <div class="avatar-circle"><i data-lucide="user"></i></div>
                    <i data-lucide="chevron-down"></i>
                </div>
                <div class="dropdown-menu">
                    ${adminLink}
                    <a href="/dashboard"><i data-lucide="layout-dashboard"></i> Dashboard</a>
                    <a href="#"><i data-lucide="settings"></i> Configurações</a>
                    <div class="separator"></div>
                    <a href="#" id="logout-btn-nav" class="text-red"><i data-lucide="log-out"></i> Logout</a>
                </div>
            </div>
        `;
        const parent = navCta.parentNode;
        const wrapper = document.createElement('div');
        wrapper.innerHTML = profileHtml;
        navCta.replaceWith(wrapper.firstElementChild);
        if (window.lucide) lucide.createIcons();
    }
    document.addEventListener('click', (e) => {
        const trigger = e.target.closest('.user-profile-trigger');
        const menu = document.querySelector('.dropdown-menu');

        if (trigger) {
            const siblingMenu = trigger.nextElementSibling;
            if (siblingMenu) siblingMenu.classList.toggle('active');
        } else {
            document.querySelectorAll('.dropdown-menu').forEach(m => m.classList.remove('active'));
        }
    });
    const handleLogout = (e) => {
        if (e.target.closest('#logout-btn-nav') || e.target.closest('#logout-btn-dash')) {
            e.preventDefault();
            localStorage.removeItem('titanium_token');
            localStorage.removeItem('titanium_user_name');
            window.location.href = '/';
        }
    };
    document.addEventListener('click', handleLogout);
    if (window.location.pathname.includes('/dashboard')) {
        if (!token) {
            window.location.href = '/login';
            return;
        }

        const loadDashboard = async () => {
            try {
                const res = await fetch('/api/dashboard', {
                    headers: { 'x-access-token': token }
                });

                if (res.status === 401 || res.status === 403) {
                    localStorage.removeItem('titanium_token');
                    window.location.href = '/login';
                    return;
                }

                if (!res.ok) {
                    throw new Error(`Erro do servidor: ${res.status}`);
                }

                const data = await res.json();

                if (!data || !data.name) {
                    throw new Error('Dados do usuário incompletos ou inválidos.');
                }
                document.getElementById('loading-state').classList.add('hidden');
                document.getElementById('user-name').innerText = data.name.split(' ')[0].toUpperCase();

                const statusPill = document.getElementById('status-indicator');
                const badge = document.getElementById('user-plan-badge');

                if (data.plan === 'black' || data.plan === 'iron') {
                    document.getElementById('premium-dashboard').classList.remove('hidden');
                    document.getElementById('free-dashboard').classList.add('hidden');

                    statusPill.innerText = "TITANIUM BLACK";
                    statusPill.classList.remove('status-free');
                    statusPill.classList.add('status-black');
                    badge.innerText = "BLACK MEMBER";
                    badge.style.background = "var(--accent-color)";
                    badge.style.color = "#000";
                    document.getElementById('stat-streak').innerText = data.streak_days || 0;
                    document.getElementById('stat-load').innerText = data.total_load_kg || 0;
                    document.getElementById('stat-checkins').innerText = data.monthly_checkins || 0;

                } else {
                    document.getElementById('free-dashboard').classList.remove('hidden');
                    document.getElementById('premium-dashboard').classList.add('hidden');

                    statusPill.innerText = "CONTA GRATUITA";
                    statusPill.classList.remove('status-black');
                    statusPill.classList.add('status-free');
                    badge.innerText = "VISITANTE";
                    badge.style.background = "var(--bg-card)";
                    badge.style.color = "#fff";
                }

            } catch (err) {
                console.error("Dashboard Error:", err);
                localStorage.removeItem('titanium_token');
                window.location.href = '/login';
            }
        };

        loadDashboard();
        document.getElementById('logout-btn').addEventListener('click', () => {
            localStorage.removeItem('titanium_token');
            window.location.href = '/';
        });
        const contentSections = {
            'dashboard': document.querySelector('.dashboard-sections'),
            'workouts': document.getElementById('workouts-view')
        };
        const statsRow = document.querySelector('.stats-grid');
        const dbHeader = document.querySelector('.db-header');

        document.querySelectorAll('.nav-item').forEach(nav => {
            nav.addEventListener('click', (e) => {
                const targetText = nav.innerText.trim();
                if (targetText === 'Encerrar Sessão') return;

                e.preventDefault();
                document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
                nav.classList.add('active');
                const allViews = ['dashboard', 'workouts', 'evolution-view', 'community-view'];
                allViews.forEach(v => {
                    const el = document.getElementById(v === 'dashboard' ? 'dashboard-sections' : v === 'workouts' ? 'workouts-view' : v);
                    if (el) el.classList.add('hidden');
                });
                statsRow.classList.add('hidden');
                if (targetText === 'Meus Treinos') {
                    document.getElementById('workouts-view').classList.remove('hidden');
                    loadMyWorkouts();
                } else if (targetText === 'Visão Geral') {
                    document.querySelector('.dashboard-sections').classList.remove('hidden');
                    statsRow.classList.remove('hidden');
                } else if (targetText === 'Evolução') {
                    document.getElementById('evolution-view').classList.remove('hidden');
                    loadEvolution();
                } else if (targetText === 'Comunidade Elite') {
                    document.getElementById('community-view').classList.remove('hidden');
                    loadCommunity();
                }
            });
        });
        let tempExercises = [];
        const loadMyWorkouts = async () => {
            const list = document.getElementById('my-workouts-list');
            const emptyMsg = document.getElementById('no-workouts-msg');

            try {
                const res = await fetch('/api/my-workouts', {
                    headers: { 'x-access-token': token }
                });
                const workouts = await res.json();

                if (workouts.length === 0) {
                    list.innerHTML = '';
                    emptyMsg.classList.remove('hidden');
                    return;
                }

                emptyMsg.classList.add('hidden');
                list.innerHTML = '';

                workouts.forEach(w => {
                    const exercisesList = w.exercises.map(e => {
                        if (typeof e === 'object') {
                            return `<li>${e.name} <span style="color:#666;">(${e.sets}x${e.reps} @ ${e.weight}kg)</span></li>`;
                        }
                        return `<li>${e}</li>`;
                    }).join('');
                    const card = `
                        <div class="user-workout-card">
                            <h3><i data-lucide="dumbbell" style="width:20px; height:20px; color: var(--accent-color);"></i> ${w.name}</h3>
                            <ul class="exercises-preview">${exercisesList}</ul>
                            <div style="display: flex; gap: 10px;">
                                <button class="btn btn-outline" style="flex:1; padding:10px;" onclick="deleteMyWorkout(${w.id})">
                                    <i data-lucide="trash-2" style="width:14px; height:14px;"></i> Excluir
                                </button>
                            </div>
                        </div>
                    `;
                    list.insertAdjacentHTML('beforeend', card);
                });

                lucide.createIcons();

            } catch (err) {
                console.error(err);
            }
        };
        window.deleteMyWorkout = async (id) => {
            if (!confirm('Excluir este treino?')) return;
            await fetch(`/api/my-workouts/${id}`, {
                method: 'DELETE',
                headers: { 'x-access-token': token }
            });
            loadMyWorkouts();
        };
        const openBuilderBtn = document.getElementById('open-builder-btn');
        const builderModal = document.getElementById('workout-builder-modal');
        const closeBuilderBtn = document.getElementById('close-builder');

        if (openBuilderBtn) {
            openBuilderBtn.addEventListener('click', () => {
                builderModal.classList.remove('hidden');
                tempExercises = [];
                document.getElementById('workout-name').value = '';
                document.getElementById('exercises-list').innerHTML = '';
                lucide.createIcons();
            });
        }

        if (closeBuilderBtn) {
            closeBuilderBtn.addEventListener('click', () => {
                builderModal.classList.add('hidden');
            });
        }
        const addExerciseBtn = document.getElementById('add-exercise-btn');
        const exerciseInput = document.getElementById('exercise-input');
        const exercisesList = document.getElementById('exercises-list');

        if (addExerciseBtn) {
            addExerciseBtn.addEventListener('click', () => {
                const name = exerciseInput.value.trim();
                const sets = document.getElementById('exercise-sets').value || 3;
                const reps = document.getElementById('exercise-reps').value || 12;
                const weight = document.getElementById('exercise-weight').value || 0;

                if (!name) return;

                const exercise = { name, sets: parseInt(sets), reps: parseInt(reps), weight: parseFloat(weight) };
                tempExercises.push(exercise);
                exerciseInput.value = '';
                document.getElementById('exercise-sets').value = '';
                document.getElementById('exercise-reps').value = '';
                document.getElementById('exercise-weight').value = '';

                const item = document.createElement('div');
                item.className = 'exercise-item';
                item.innerHTML = `
                    <span style="flex:1;">${name}</span>
                    <span style="color:#888; font-size:0.85rem;">${sets}x${reps} @ ${weight}kg</span>
                    <button onclick="this.parentElement.remove(); tempExercises = tempExercises.filter(e => e.name !== '${name}');">&times;</button>
                `;
                exercisesList.appendChild(item);
            });

            exerciseInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') addExerciseBtn.click();
            });
        }
        const saveWorkoutBtn = document.getElementById('save-workout-btn');
        if (saveWorkoutBtn) {
            saveWorkoutBtn.addEventListener('click', async () => {
                const name = document.getElementById('workout-name').value.trim();

                if (!name || tempExercises.length === 0) {
                    notify('Preencha o nome e adicione pelo menos um exercício.', true);
                    return;
                }

                const res = await fetch('/api/my-workouts', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'x-access-token': token },
                    body: JSON.stringify({ name, exercises: tempExercises })
                });

                if (res.ok) {
                    builderModal.classList.add('hidden');
                    loadMyWorkouts();
                } else {
                    notify('Erro ao salvar.', true);
                }
            });
        };
        const upgradeBtn2 = document.getElementById('upgrade-btn-2');
        if (upgradeBtn2) {
            upgradeBtn2.addEventListener('click', async () => {
                const confirmUpgrade = confirm("Simular upgrade para BLACK agora?");
                if (confirmUpgrade) {
                    const res = await fetch('/api/upgrade', { method: 'POST', headers: { 'x-access-token': token } });
                    if (res.ok) {
                        notify("Upgrade Realizado! Acesso Liberado.");
                        setTimeout(() => window.location.reload(), 1500);
                    }
                }
            });
        }
        let progressChart = null;

        const loadEvolution = async () => {
            try {
                const res = await fetch('/api/progress', { headers: { 'x-access-token': token } });
                const data = await res.json();

                const ctx = document.getElementById('progress-chart');
                if (!ctx) return;

                const labels = data.map(d => new Date(d.created_at).toLocaleDateString('pt-BR')).reverse();
                const weights = data.map(d => d.weight_kg).reverse();
                const fats = data.map(d => d.body_fat).reverse();

                if (progressChart) progressChart.destroy();

                progressChart = new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels,
                        datasets: [
                            { label: 'Peso (kg)', data: weights, borderColor: '#ff1f1f', tension: 0.3, fill: false },
                            { label: '% Gordura', data: fats, borderColor: '#FFD700', tension: 0.3, fill: false }
                        ]
                    },
                    options: {
                        responsive: true,
                        plugins: { legend: { labels: { color: '#fff' } } },
                        scales: {
                            x: { ticks: { color: '#888' }, grid: { color: '#333' } },
                            y: { ticks: { color: '#888' }, grid: { color: '#333' } }
                        }
                    }
                });
            } catch (e) { console.error(e); }
        };

        const saveProgressBtn = document.getElementById('save-progress-btn');
        if (saveProgressBtn) {
            saveProgressBtn.addEventListener('click', async () => {
                const weight = document.getElementById('progress-weight').value;
                const fat = document.getElementById('progress-fat').value;
                const notes = document.getElementById('progress-notes').value;

                if (!weight && !fat) { notify('Preencha pelo menos peso ou gordura.', true); return; }

                await fetch('/api/progress', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'x-access-token': token },
                    body: JSON.stringify({ weight_kg: weight, body_fat: fat, notes })
                });

                document.getElementById('progress-weight').value = '';
                document.getElementById('progress-fat').value = '';
                document.getElementById('progress-notes').value = '';
                loadEvolution();
            });
        }
        const loadCommunity = async () => {
            const feed = document.getElementById('community-feed');
            try {
                const res = await fetch('/api/community', { headers: { 'x-access-token': token } });
                const posts = await res.json();

                feed.innerHTML = '';
                posts.forEach(p => {
                    const planColor = p.author_plan === 'black' ? 'var(--accent-color)' : '#888';
                    const card = `
                        <div style="background: #111; border: 1px solid #333; border-radius: 12px; padding: 20px;">
                            <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">
                                <div style="width: 40px; height: 40px; background: ${planColor}; border-radius: 50%; display: flex; align-items: center; justify-content: center; color: #fff; font-weight: bold;">${p.author_name.charAt(0).toUpperCase()}</div>
                                <div>
                                    <h4 style="color: #fff; margin: 0;">${p.author_name}</h4>
                                    <span style="color: #666; font-size: 0.8rem;">${new Date(p.created_at).toLocaleString('pt-BR')}</span>
                                </div>
                            </div>
                            <p style="color: #ddd; line-height: 1.6;">${p.content}</p>
                        </div>
                    `;
                    feed.insertAdjacentHTML('beforeend', card);
                });

                if (posts.length === 0) {
                    feed.innerHTML = '<p style="color: #555; text-align: center;">Nenhuma publicação ainda. Seja o primeiro!</p>';
                }
            } catch (e) { console.error(e); }
        };

        const postCommunityBtn = document.getElementById('post-community-btn');
        if (postCommunityBtn) {
            postCommunityBtn.addEventListener('click', async () => {
                const input = document.getElementById('community-input');
                const content = input.value.trim();
                if (!content) return;

                await fetch('/api/community', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'x-access-token': token },
                    body: JSON.stringify({ content })
                });

                input.value = '';
                loadCommunity();
            });
        }
        const userMiniAvatar = document.querySelector('.mini-avatar');
        const profileModal = document.getElementById('profile-modal');
        const closeProfileBtn = document.getElementById('close-profile');

        if (userMiniAvatar && profileModal) {
            userMiniAvatar.addEventListener('click', async () => {
                profileModal.classList.remove('hidden');

                const res = await fetch('/api/profile', { headers: { 'x-access-token': token } });
                const profile = await res.json();

                document.getElementById('profile-name').value = profile.name || '';
                document.getElementById('profile-email').value = profile.email || '';
                document.getElementById('profile-whatsapp').value = profile.whatsapp || '';

                const badge = document.getElementById('profile-plan-badge');
                badge.innerText = profile.plan?.toUpperCase() || 'FREE';
                if (profile.plan === 'black') badge.style.background = 'var(--accent-color)';

                lucide.createIcons();
            });
        }

        if (closeProfileBtn) {
            closeProfileBtn.addEventListener('click', () => profileModal.classList.add('hidden'));
        }

        const saveProfileBtn = document.getElementById('save-profile-btn');
        if (saveProfileBtn) {
            saveProfileBtn.addEventListener('click', async () => {
                const name = document.getElementById('profile-name').value;
                const whatsapp = document.getElementById('profile-whatsapp').value;

                const res = await fetch('/api/profile', {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json', 'x-access-token': token },
                    body: JSON.stringify({ name, whatsapp })
                });

                if (res.ok) {
                    notify('Perfil atualizado!');
                    profileModal.classList.add('hidden');
                    document.getElementById('user-name').innerText = name.split(' ')[0].toUpperCase();
                }
            });
        }

    }
    const mobileToggle = document.querySelector('.mobile-toggle');
    const navLinks = document.querySelector('.nav-links');

    if (mobileToggle && navLinks) {
        mobileToggle.addEventListener('click', () => {
            navLinks.classList.toggle('active');
        });
        navLinks.querySelectorAll('a').forEach(link => {
            link.addEventListener('click', () => {
                navLinks.classList.remove('active');
            });
        });
    }

});
