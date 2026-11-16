import os
import re
import uuid
import sqlite3
from datetime import datetime

from flask import (Flask, render_template_string, request, jsonify, session, redirect,
                   url_for, flash, send_from_directory, abort)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix

# ==========================================
# 0. CONFIGURATION PRODUCTION & ENVIRONNEMENT
# ==========================================
app = Flask(__name__)

# Support derrière Nginx / Reverse Proxy HTTPS
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

IS_PROD = os.environ.get("FLASK_ENV", "production").lower() == "production"
HTTPS_ENABLED = os.environ.get("HTTPS_ENABLED", "0") == "1"

# Clé secrète obligatoire en production
secret_key = os.environ.get("SECRET_KEY")
if not secret_key:
    if IS_PROD:
        raise RuntimeError("ERREUR CRITIQUE : La variable d'environnement SECRET_KEY doit être définie en production.")
    secret_key = "dev_only_key_change_me"

app.secret_key = secret_key
app.config.update(
    MAX_CONTENT_LENGTH=6 * 1024 * 1024,  # 6 Mo max par upload
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=HTTPS_ENABLED,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME = os.environ.get("DB_PATH", os.path.join(BASE_DIR, "proxipro_portal_v3.db"))
UPLOAD_ROOT = os.environ.get("UPLOAD_DIR", os.path.join(BASE_DIR, "uploads"))

PHOTO_DIR = os.path.join(UPLOAD_ROOT, "photos")
CV_DIR = os.path.join(UPLOAD_ROOT, "cv")
os.makedirs(PHOTO_DIR, exist_ok=True)
os.makedirs(CV_DIR, exist_ok=True)

ALLOWED_PHOTO = {"jpg", "jpeg", "png", "webp"}
ALLOWED_CV = {"pdf", "doc", "docx"}

SIGNATURES = {
    "jpg": [b"\xff\xd8\xff"],
    "jpeg": [b"\xff\xd8\xff"],
    "png": [b"\x89PNG\r\n\x1a\n"],
    "webp": [b"RIFF"],
    "pdf": [b"%PDF"],
    "docx": [b"PK\x03\x04"],
    "doc": [b"\xd0\xcf\x11\xe0"],
}


@app.after_request
def apply_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


def save_upload(file, folder, allowed):
    """Enregistre le fichier sous un nom aléatoire après contrôle de sa signature."""
    ext = os.path.splitext(secure_filename(file.filename))[1].lower().lstrip(".")
    if ext not in allowed:
        return None
    head = file.stream.read(8)
    file.stream.seek(0)
    if not any(head.startswith(sig) for sig in SIGNATURES[ext]):
        return None
    name = f"{uuid.uuid4().hex}.{ext}"
    file.save(os.path.join(folder, name))
    return name


def remove_file(folder, name):
    if name:
        safe_name = os.path.basename(name)
        try:
            os.remove(os.path.join(folder, safe_name))
        except OSError:
            pass


def calculer_commission(tarif_texte, taux=0.10):
    """Extrait le montant numérique d'un tarif (ex: '25 000 FCFA') et calcule 10 %."""
    chiffres = re.sub(r"[^\d]", "", tarif_texte or "")
    if chiffres:
        montant = int(chiffres)
        return f"{int(montant * taux):,} FCFA".replace(",", " ")
    return "À définir"


# ==========================================
# 1. BASE DE DONNÉES SQLITE3 & MIGRATIONS
# ==========================================
def get_db():
    conn = sqlite3.connect(DB_NAME, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def init_db():
    with get_db() as conn:
        c = conn.cursor()

        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nom TEXT NOT NULL,
                commune TEXT,
                telephone TEXT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'client',
                specialite TEXT DEFAULT '',
                tarif_base TEXT DEFAULT '',
                experience TEXT DEFAULT '',
                date_inscription TEXT
            )
        """)

        cols_users = [r[1] for r in c.execute("PRAGMA table_info(users)").fetchall()]
        if "photo" not in cols_users:
            c.execute("ALTER TABLE users ADD COLUMN photo TEXT DEFAULT ''")
        if "cv" not in cols_users:
            c.execute("ALTER TABLE users ADD COLUMN cv TEXT DEFAULT ''")
        if "verifie" not in cols_users:
            c.execute("ALTER TABLE users ADD COLUMN verifie INTEGER DEFAULT 0")

        c.execute("""
            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                titre TEXT NOT NULL,
                metier TEXT NOT NULL,
                categorie TEXT NOT NULL,
                zone TEXT NOT NULL,
                delai TEXT NOT NULL,
                urgent INTEGER DEFAULT 0,
                description TEXT,
                garantie TEXT
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS demandes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                prestataire_id INTEGER DEFAULT NULL,
                metier TEXT NOT NULL,
                commune TEXT NOT NULL,
                adresse_precise TEXT NOT NULL,
                details TEXT,
                etape INTEGER DEFAULT 1,
                statut TEXT DEFAULT '1. Recherche de prestataire disponible',
                prestataire_assigne TEXT DEFAULT 'En attente d’un artisan',
                tarif_propose TEXT DEFAULT 'En attente de chiffrage',
                note_admin TEXT DEFAULT 'Votre demande est visible par nos artisans qualifiés.',
                date_creation TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id),
                FOREIGN KEY(prestataire_id) REFERENCES users(id)
            )
        """)

        cols_demandes = [r[1] for r in c.execute("PRAGMA table_info(demandes)").fetchall()]
        if "commission" not in cols_demandes:
            c.execute("ALTER TABLE demandes ADD COLUMN commission TEXT DEFAULT '0 FCFA'")
        if "note_client" not in cols_demandes:
            c.execute("ALTER TABLE demandes ADD COLUMN note_client INTEGER DEFAULT NULL")
        if "avis_client" not in cols_demandes:
            c.execute("ALTER TABLE demandes ADD COLUMN avis_client TEXT DEFAULT ''")
        if "date_avis" not in cols_demandes:
            c.execute("ALTER TABLE demandes ADD COLUMN date_avis TEXT DEFAULT ''")

        # 1. Compte Admin initial configurable par variables d'environnement
        admin_email = os.environ.get("ADMIN_EMAIL", "admin@proxipro.ci")
        admin_password = os.environ.get("ADMIN_PASSWORD", "admin123")
        if c.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'").fetchone()[0] == 0:
            c.execute("""
                INSERT INTO users (nom, commune, telephone, email, password_hash, role, date_inscription)
                VALUES (?, ?, ?, ?, ?, 'admin', ?)
            """, (
                "Coordinateur ProxiPro CI", "Abidjan - Cocody", "+225 07 00 00 00 00",
                admin_email, generate_password_hash(admin_password),
                datetime.now().strftime("%d/%m/%Y")
            ))

        # 2. Comptes de démonstration (uniquement si SEED_DEMO=1)
        if os.environ.get("SEED_DEMO", "0") == "1":
            if c.execute("SELECT COUNT(*) FROM users WHERE email = 'pro@exemple.ci'").fetchone()[0] == 0:
                c.execute("""
                    INSERT INTO users (nom, commune, telephone, email, password_hash, role, specialite, tarif_base, experience, verifie, date_inscription)
                    VALUES (?, ?, ?, ?, ?, 'prestataire', ?, ?, ?, 1, ?)
                """, (
                    "Bamba Moussa (Plomberie Express)", "Cocody & Riviera", "+225 07 77 66 55 44",
                    "pro@exemple.ci", generate_password_hash("pro123"),
                    "Plombier", "À partir de 15 000 FCFA", "8 ans d'expérience",
                    datetime.now().strftime("%d/%m/%Y")
                ))

            if c.execute("SELECT COUNT(*) FROM users WHERE email = 'client@exemple.ci'").fetchone()[0] == 0:
                c.execute("""
                    INSERT INTO users (nom, commune, telephone, email, password_hash, role, date_inscription)
                    VALUES (?, ?, ?, ?, ?, 'client', ?)
                """, (
                    "Konan Yao Serge", "Cocody Angré", "+225 05 55 44 33 22",
                    "client@exemple.ci", generate_password_hash("client123"),
                    datetime.now().strftime("%d/%m/%Y")
                ))
                demo_user_id = c.lastrowid
                c.execute("""
                    INSERT INTO demandes (user_id, metier, commune, adresse_precise, details, etape, statut, date_creation)
                    VALUES (?, ?, ?, ?, ?, 1, '1. Recherche de prestataire disponible', ?)
                """, (
                    demo_user_id, "Plombier", "Cocody", "Angré 9ème Tranche, près de la pharmacie",
                    "Fuite importante sous l'évier de la cuisine et remplacement d'un mitigeur.",
                    datetime.now().strftime("%d/%m/%Y %H:%M")
                ))

        # Catalogue initial
        if c.execute("SELECT COUNT(*) FROM services").fetchone()[0] == 0:
            items = [
                ("DÉPANNAGE MÉCANIQUE & DIAGNOSTIC AUTO", "Mécanicien", "Automobile & Engins", "Tout Abidjan & Intérieur", "Intervention sous 2h", 1,
                 "Diagnostic électronique, vidange complète, freinage, embrayage et dépannage sur place ou en garage agréé.",
                 "Pièces certifiées & Garantie 3 mois"),
                ("DESIGN D'INTÉRIEUR & AMÉNAGEMENT 3D", "Designer intérieur", "Architecture & Déco", "Abidjan & Yamoussoukro", "3 à 7 jours", 0,
                 "Conception de plans 3D, choix du mobilier, optimisation d'espaces résidentiels, bureaux et commerces.",
                 "Rendu 3D réaliste + Suivi de chantier"),
                ("NETTOYAGE & ENTRETIEN APRÈS CONSTRUCTION", "Entretien après construction", "Fin de Chantier", "Toutes Communes", "24h à 48h", 1,
                 "Remise en état complète après travaux : évacuation gravats fins, décapage sols, nettoyage vitres et sanitaires.",
                 "Produits professionnels sans trace"),
                ("PLOMBERIE SANITAIRE & DÉTECTION DE FUITE", "Plombier", "Bâtiment & Dépannage", "Toutes Communes", "Urgence 1h", 1,
                 "Réparation de fuites, installation chauffe-eau, débouchage canalisation, pose de sanitaires et tuyauterie PPR.",
                 "Intervention rapide 7j/7"),
                ("POSE DE CARRELAGE, MARBRE & FAÏENCE", "Carreleur", "Revêtement Sol & Mur", "Abidjan & Grand-Bassam", "Sur devis (48h)", 0,
                 "Pose de carreaux grès cérame, marbre, faïence salle de bain et terrasse avec finition joints haute précision.",
                 "Alignement laser garanti"),
                ("VITRERIE, BAIES VITRÉES & MIROITERIE", "Vitrier", "Menuiserie Alu & Verre", "Toutes Communes", "24h à 72h", 1,
                 "Remplacement de vitres cassées, pose de baies vitrées coulissantes, cabines de douche en verre trempé.",
                 "Verre sécurit sur mesure"),
                ("PEINTURE BÂTIMENT INTÉRIEURE & EXTÉRIEURE", "Peintre", "Finition & Rénovation", "Toutes Communes", "Sous 48h", 0,
                 "Application d'enduit lisse, peinture acrylique, satinée, effets décoratifs et ravalement de façade.",
                 "Finition propre & protection mobilier")
            ]
            c.executemany("""
                INSERT INTO services (titre, metier, categorie, zone, delai, urgent, description, garantie)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, items)


init_db()

# ==========================================
# 2. PAGE D'ACCUEIL (PORTAIL FLUIDE)
# ==========================================
PORTAL_HTML = """
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ProxiPro CI | Plateforme de Mise en Relation Artisans & Clients</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; background-color: #f8fafc; }
        .hero-bg {
            background: linear-gradient(rgba(15, 23, 42, 0.80), rgba(15, 23, 42, 0.88)),
                        url('https://images.unsplash.com/photo-1581578731548-c64695cc6952?auto=format&fit=crop&w=1600&q=80') center/cover no-repeat;
        }
        .card-hover { transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1); }
        .card-hover:hover { transform: translateY(-4px); box-shadow: 0 12px 24px -8px rgba(0, 0, 0, 0.12); }
    </style>
</head>
<body class="text-slate-800">

    <!-- BARRE DE NAVIGATION -->
    <header class="bg-white shadow-sm sticky top-0 z-40">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
            <a href="/" class="flex items-center space-x-3">
                <div class="w-10 h-10 bg-orange-500 rounded-lg flex items-center justify-center text-white font-extrabold text-xl">P</div>
                <div>
                    <span class="font-extrabold text-lg text-slate-900 tracking-tight">PROXI</span><span class="font-extrabold text-lg text-orange-500">PRO</span>
                    <span class="text-xs font-bold bg-emerald-100 text-emerald-800 px-1.5 py-0.5 rounded ml-1">CI</span>
                    <p class="text-[10px] text-slate-400 -mt-1">Le Guichet Unique des Artisans & Services à Domicile</p>
                </div>
            </a>

            <div class="flex items-center space-x-3">
                {% if session.get('user_id') %}
                    {% if session.get('role') == 'admin' %}
                        <a href="/admin" class="text-sm font-bold text-white bg-slate-900 hover:bg-slate-800 px-4 py-2 rounded-lg transition">
                            ⚙️ Console Admin
                        </a>
                    {% elif session.get('role') == 'prestataire' %}
                        <a href="/espace-prestataire" class="text-sm font-bold text-white bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg transition">
                            🛠️ Espace Artisan ({{ session.get('user_nom').split(' ')[0] }})
                        </a>
                    {% else %}
                        <a href="/mon-espace" class="text-sm font-bold text-white bg-emerald-600 hover:bg-emerald-700 px-4 py-2 rounded-lg transition">
                            👤 Mon Espace ({{ session.get('user_nom').split(' ')[0] }})
                        </a>
                    {% endif %}
                    <a href="/logout" class="text-xs font-semibold text-red-600 hover:underline px-2">Déconnexion</a>
                {% else %}
                    <button onclick="openAuthModal('login')" class="text-sm font-semibold text-slate-700 bg-slate-100 hover:bg-slate-200 px-4 py-2 rounded-lg transition">
                        🔑 Connexion
                    </button>
                    <button onclick="openAuthModal('register_client')" class="text-sm font-semibold text-white bg-orange-500 hover:bg-orange-600 px-4 py-2 rounded-lg shadow-sm transition">
                        Inscription
                    </button>
                {% endif %}
            </div>
        </div>

        <!-- FLASH INFOS -->
        <div class="bg-slate-50 border-t border-b border-slate-200 flex items-center">
            <div class="bg-red-600 text-white text-xs font-bold px-4 py-2 uppercase tracking-wider shrink-0">Flash Infos</div>
            <div class="px-4 py-1.5 text-xs text-slate-600 truncate">
                <span class="font-bold text-slate-800">Recrutement Artisans 2026 :</span> Mécaniciens, plombiers, peintres, vitriers et carreleurs : inscrivez-vous gratuitement, ajoutez votre photo et votre CV pour décrocher des chantiers !
            </div>
        </div>
    </header>

    <!-- HERO SECTION -->
    <section class="hero-bg text-white py-14 px-4">
        <div class="max-w-5xl mx-auto text-center">
            <h1 class="text-3xl sm:text-5xl font-extrabold leading-tight mb-4">
                Trouvez le bon artisan <br>
                <span class="text-orange-500">ou décrochez des chantiers</span>
            </h1>
            <p class="text-slate-200 text-base sm:text-lg max-w-2xl mx-auto mb-10">
                Mécanicien • Designer d'intérieur • Entretien après construction • Plombier • Carreleur • Vitrier • Peintre
            </p>

            <!-- DOUBLE ENTRÉE -->
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4 max-w-3xl mx-auto mb-8 text-left">
                <div onclick="handleClientAction('Plombier')" class="bg-white text-slate-800 p-5 rounded-xl shadow-lg cursor-pointer card-hover flex items-center justify-between">
                    <div class="flex items-center space-x-4">
                        <div class="w-12 h-12 rounded-lg bg-orange-100 text-orange-600 flex items-center justify-center text-2xl">🏠</div>
                        <div>
                            <h3 class="font-bold text-base">Vous cherchez un Prestataire ?</h3>
                            <p class="text-xs text-slate-500">Publiez votre besoin, recevez un tarif et suivez l'intervention</p>
                        </div>
                    </div>
                    <span class="text-orange-500 font-bold text-xl">→</span>
                </div>

                <div onclick="handleProAction()" class="bg-white text-slate-800 p-5 rounded-xl shadow-lg cursor-pointer card-hover flex items-center justify-between border-2 border-blue-500/30">
                    <div class="flex items-center space-x-4">
                        <div class="w-12 h-12 rounded-lg bg-blue-100 text-blue-600 flex items-center justify-center text-2xl">👷</div>
                        <div>
                            <h3 class="font-bold text-base">Vous êtes un Artisan / Pro ?</h3>
                            <p class="text-xs text-slate-500">Inscrivez-vous, ajoutez photo & CV, proposez vos tarifs</p>
                        </div>
                    </div>
                    <span class="text-blue-600 font-bold text-xl">→</span>
                </div>
            </div>

            <!-- GRILLE DES 7 MÉTIERS -->
            <div class="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2.5 max-w-5xl mx-auto">
                <div onclick="filterByMetier('Mécanicien')" class="bg-white/95 text-slate-800 p-3.5 rounded-xl cursor-pointer card-hover text-center">
                    <div class="text-2xl mb-1">🔧</div>
                    <div class="font-bold text-xs">Mécanicien</div>
                </div>
                <div onclick="filterByMetier('Designer intérieur')" class="bg-white/95 text-slate-800 p-3.5 rounded-xl cursor-pointer card-hover text-center">
                    <div class="text-2xl mb-1">🛋️</div>
                    <div class="font-bold text-xs">Designer Int.</div>
                </div>
                <div onclick="filterByMetier('Entretien après construction')" class="bg-white/95 text-slate-800 p-3.5 rounded-xl cursor-pointer card-hover relative text-center">
                    <span class="absolute -top-1.5 right-1 bg-emerald-600 text-white text-[9px] font-bold px-1.5 py-0.5 rounded-full">Chantier</span>
                    <div class="text-2xl mb-1">🧹</div>
                    <div class="font-bold text-xs">Nettoyage</div>
                </div>
                <div onclick="filterByMetier('Plombier')" class="bg-white/95 text-slate-800 p-3.5 rounded-xl cursor-pointer card-hover relative text-center">
                    <span class="absolute -top-1.5 right-1 bg-orange-500 text-white text-[9px] font-bold px-1.5 py-0.5 rounded-full">Express</span>
                    <div class="text-2xl mb-1">🚰</div>
                    <div class="font-bold text-xs">Plombier</div>
                </div>
                <div onclick="filterByMetier('Carreleur')" class="bg-white/95 text-slate-800 p-3.5 rounded-xl cursor-pointer card-hover text-center">
                    <div class="text-2xl mb-1">🧱</div>
                    <div class="font-bold text-xs">Carreleur</div>
                </div>
                <div onclick="filterByMetier('Vitrier')" class="bg-white/95 text-slate-800 p-3.5 rounded-xl cursor-pointer card-hover text-center">
                    <div class="text-2xl mb-1">🪟</div>
                    <div class="font-bold text-xs">Vitrier</div>
                </div>
                <div onclick="filterByMetier('Peintre')" class="bg-white/95 text-slate-800 p-3.5 rounded-xl cursor-pointer card-hover col-span-2 sm:col-span-1 text-center">
                    <div class="text-2xl mb-1">🎨</div>
                    <div class="font-bold text-xs">Peintre</div>
                </div>
            </div>
        </div>
    </section>

    <!-- CATALOGUE DE SERVICES & ARTISANS INSCRITS -->
    <section id="catalogue" class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div class="text-center mb-8">
            <span class="text-xs font-bold uppercase tracking-wider text-orange-600">Catalogue des Prestations</span>
            <h2 class="text-2xl sm:text-3xl font-extrabold text-slate-900 mt-1">Services disponibles & Artisans agréés</h2>
        </div>

        <div class="bg-white p-4 rounded-2xl shadow-md border border-slate-100 mb-6">
            <div class="grid grid-cols-1 md:grid-cols-4 gap-3">
                <input type="text" id="searchInput" onkeyup="applyFilters()" placeholder="🔍 Mot-clé (ex: Fuite, Vidange, Salon, Vitre, Façade)..."
                       class="md:col-span-2 border border-slate-200 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-orange-500">
                <select id="metierSelect" onchange="applyFilters()" class="border border-slate-200 rounded-xl px-4 py-2.5 text-sm bg-white focus:outline-none focus:border-orange-500">
                    <option value="ALL">Tous les corps de métier</option>
                    <option value="Mécanicien">Mécanicien</option>
                    <option value="Designer intérieur">Designer d'intérieur</option>
                    <option value="Entretien après construction">Entretien après construction</option>
                    <option value="Plombier">Plombier</option>
                    <option value="Carreleur">Carreleur</option>
                    <option value="Vitrier">Vitrier</option>
                    <option value="Peintre">Peintre</option>
                </select>
                <button onclick="resetFilters()" class="bg-slate-900 hover:bg-slate-800 text-white font-semibold rounded-xl px-4 py-2.5 text-sm transition">
                    Tout afficher
                </button>
            </div>
        </div>

        <div id="servicesGrid" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5 mb-12">
            {% for s in services %}
            <div class="service-card bg-white rounded-xl border border-slate-200 p-5 card-hover flex flex-col justify-between"
                 data-metier="{{ s.metier }}" data-search="{{ s.titre|lower }} {{ s.description|lower }} {{ s.metier|lower }} {{ s.zone|lower }}">
                <div>
                    <div class="flex items-center justify-between mb-3">
                        <span class="text-xs font-bold text-orange-700 bg-orange-50 px-2.5 py-1 rounded-md">{{ s.metier }}</span>
                        {% if s.urgent %}
                        <span class="text-[11px] font-bold text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded-full">● Dispo immédiate</span>
                        {% endif %}
                    </div>
                    <h3 class="font-extrabold text-base text-slate-900 mb-1">{{ s.titre }}</h3>
                    <p class="text-xs text-slate-500 font-medium mb-3">📍 {{ s.zone }} • ⏱️ {{ s.delai }}</p>
                    <p class="text-sm text-slate-600 leading-relaxed mb-4">{{ s.description }}</p>
                </div>
                <div class="pt-3 border-t border-slate-100 flex items-center justify-between">
                    <span class="text-xs font-semibold text-emerald-700">✓ {{ s.garantie }}</span>
                    <button onclick="handleClientAction('{{ s.metier }}')"
                            class="text-xs font-bold text-orange-600 hover:text-orange-700 flex items-center">
                        Commander →
                    </button>
                </div>
            </div>
            {% endfor %}
        </div>

        <!-- RÉPERTOIRE DES PRESTATAIRES INSCRITS -->
        {% if artisans %}
        <div class="border-t pt-10">
            <h3 class="font-extrabold text-xl text-slate-900 mb-4">👷 Artisans & Prestataires inscrits sur ProxiPro CI</h3>
            <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                {% for a in artisans %}
                <div class="bg-white p-4 rounded-xl border {{ 'border-emerald-300 ring-1 ring-emerald-100' if a.verifie else 'border-slate-200' }} shadow-sm flex items-center justify-between gap-3">
                    <div class="flex items-center min-w-0">
                        {% if a.photo %}
                            <img src="/uploads/photos/{{ a.photo }}" alt="{{ a.nom }}" class="w-14 h-14 rounded-full object-cover mr-3 shrink-0 border border-slate-200">
                        {% else %}
                            <div class="w-14 h-14 rounded-full bg-blue-100 text-blue-700 flex items-center justify-center font-extrabold text-xl mr-3 shrink-0">{{ a.nom[0] }}</div>
                        {% endif %}
                        <div class="min-w-0">
                            <div class="flex flex-wrap items-center gap-1">
                                <span class="text-[11px] font-bold bg-blue-50 text-blue-700 px-2 py-0.5 rounded">{{ a.specialite }}</span>
                                {% if a.verifie %}
                                    <span class="text-[10px] font-extrabold bg-emerald-100 text-emerald-800 px-2 py-0.5 rounded-full">✓ Vérifié</span>
                                {% endif %}
                            </div>
                            <h4 class="font-bold text-sm text-slate-900 mt-1 truncate">{{ a.nom }}</h4>

                            {% if a.nb_avis > 0 %}
                                <div class="text-xs font-bold text-amber-500 mt-0.5">
                                    ★ {{ "%.1f"|format(a.note_moyenne) }}/5 <span class="text-slate-400 font-normal">({{ a.nb_avis }} avis)</span>
                                </div>
                            {% else %}
                                <div class="text-[11px] text-slate-400 mt-0.5">Nouveau sur ProxiPro</div>
                            {% endif %}

                            <p class="text-xs text-slate-500 mt-0.5">📍 {{ a.commune }} • {{ a.experience }}</p>
                            <p class="text-xs font-bold text-emerald-700 mt-0.5">💰 Tarif : {{ a.tarif_base }}</p>
                            {% if a.cv %}
                                {% if session.get('user_id') %}
                                    <a href="/uploads/cv/{{ a.cv }}" target="_blank" class="text-xs font-bold text-blue-600 hover:underline">📄 Voir le CV</a>
                                {% else %}
                                    <span class="text-[11px] text-slate-400">📄 CV disponible (connectez-vous)</span>
                                {% endif %}
                            {% endif %}
                        </div>
                    </div>
                    <button onclick="handleClientAction('{{ a.specialite }}')" class="text-xs font-bold bg-slate-100 hover:bg-orange-500 hover:text-white px-3 py-2 rounded-lg transition shrink-0">
                        Solliciter
                    </button>
                </div>
                {% endfor %}
            </div>
        </div>
        {% endif %}
    </section>

    <!-- MODALE AUTHENTIFICATION -->
    <div id="authModal" class="fixed inset-0 bg-slate-900/60 hidden items-center justify-center z-50 p-4">
        <div class="bg-white rounded-2xl max-w-md w-full p-6 shadow-2xl max-h-[90vh] overflow-y-auto">
            <div class="flex justify-between items-center border-b pb-3 mb-4">
                <div class="flex space-x-3 text-xs sm:text-sm">
                    <button id="tabLogin" onclick="switchAuthTab('login')" class="font-extrabold text-slate-900 border-b-2 border-slate-900 pb-1">Connexion</button>
                    <button id="tabRegClient" onclick="switchAuthTab('register_client')" class="font-bold text-slate-400 pb-1">Compte Client</button>
                    <button id="tabRegPro" onclick="switchAuthTab('register_pro')" class="font-bold text-slate-400 pb-1">Compte Artisan</button>
                </div>
                <button onclick="closeAuthModal()" class="text-slate-400 hover:text-slate-600 text-xl font-bold">&times;</button>
            </div>

            <!-- 1. CONNEXION -->
            <form id="loginForm" onsubmit="submitLogin(event)" class="space-y-3">
                <div>
                    <label class="block text-xs font-bold text-slate-700 mb-1">Adresse Email</label>
                    <input type="email" id="loginEmail" required class="w-full border rounded-lg px-3 py-2 text-sm" placeholder="Votre email">
                </div>
                <div>
                    <label class="block text-xs font-bold text-slate-700 mb-1">Mot de passe</label>
                    <input type="password" id="loginPassword" required class="w-full border rounded-lg px-3 py-2 text-sm" placeholder="••••••••">
                </div>
                <p id="loginError" class="text-xs text-red-600 font-semibold hidden"></p>
                <button type="submit" class="w-full bg-slate-900 hover:bg-slate-800 text-white font-bold py-2.5 rounded-xl transition">
                    Se connecter
                </button>
                {% if show_demo_hint %}
                <div class="bg-slate-50 p-2.5 rounded-lg text-[11px] text-slate-600 mt-2 space-y-1">
                    <div class="font-bold text-slate-800">Comptes de test actifs :</div>
                    <div>• <b>Client :</b> <code>client@exemple.ci</code> / <code>client123</code></div>
                    <div>• <b>Artisan :</b> <code>pro@exemple.ci</code> / <code>pro123</code></div>
                </div>
                {% endif %}
            </form>

            <!-- 2. INSCRIPTION CLIENT -->
            <form id="registerClientForm" onsubmit="submitRegister(event, 'client')" class="space-y-3 hidden">
                <p class="text-xs text-slate-500">Créez votre compte pour publier vos besoins et suivre les interventions.</p>
                <div>
                    <label class="block text-xs font-bold text-slate-700 mb-1">Nom complet *</label>
                    <input type="text" id="cliNom" required class="w-full border rounded-lg px-3 py-2 text-sm" placeholder="Ex: Koffi Kouassi Sylvain">
                </div>
                <div class="grid grid-cols-2 gap-2">
                    <div>
                        <label class="block text-xs font-bold text-slate-700 mb-1">Commune / Ville *</label>
                        <input type="text" id="cliCommune" required class="w-full border rounded-lg px-3 py-2 text-sm" placeholder="Ex: Cocody">
                    </div>
                    <div>
                        <label class="block text-xs font-bold text-slate-700 mb-1">Téléphone *</label>
                        <input type="text" id="cliTel" required class="w-full border rounded-lg px-3 py-2 text-sm" placeholder="+225 07...">
                    </div>
                </div>
                <div>
                    <label class="block text-xs font-bold text-slate-700 mb-1">Email *</label>
                    <input type="email" id="cliEmail" required class="w-full border rounded-lg px-3 py-2 text-sm">
                </div>
                <div>
                    <label class="block text-xs font-bold text-slate-700 mb-1">Mot de passe (6 caractères min.) *</label>
                    <input type="password" id="cliPass" minlength="6" required class="w-full border rounded-lg px-3 py-2 text-sm">
                </div>
                <p id="cliError" class="text-xs text-red-600 font-semibold hidden"></p>
                <button type="submit" class="w-full bg-orange-500 hover:bg-orange-600 text-white font-bold py-2.5 rounded-xl transition">
                    Créer mon compte Client
                </button>
            </form>

            <!-- 3. INSCRIPTION PRESTATAIRE / ARTISAN -->
            <form id="registerProForm" onsubmit="submitRegister(event, 'prestataire')" class="space-y-3 hidden">
                <p class="text-xs text-blue-700 bg-blue-50 p-2 rounded-lg font-medium">Rejoignez ProxiPro CI : vous pourrez ajouter votre photo et votre CV dès l'ouverture de votre espace artisan.</p>
                <div>
                    <label class="block text-xs font-bold text-slate-700 mb-1">Nom complet ou Nom d'atelier *</label>
                    <input type="text" id="proNom" required class="w-full border rounded-lg px-3 py-2 text-sm" placeholder="Ex: Atelier Kouamé Vitrerie">
                </div>
                <div class="grid grid-cols-2 gap-2">
                    <div>
                        <label class="block text-xs font-bold text-slate-700 mb-1">Votre Spécialité *</label>
                        <select id="proSpecialite" class="w-full border rounded-lg px-2 py-2 text-sm bg-white">
                            <option value="Mécanicien">Mécanicien</option>
                            <option value="Designer intérieur">Designer d'intérieur</option>
                            <option value="Entretien après construction">Entretien après construction</option>
                            <option value="Plombier">Plombier</option>
                            <option value="Carreleur">Carreleur</option>
                            <option value="Vitrier">Vitrier</option>
                            <option value="Peintre">Peintre</option>
                        </select>
                    </div>
                    <div>
                        <label class="block text-xs font-bold text-slate-700 mb-1">Zone d'intervention *</label>
                        <input type="text" id="proCommune" required class="w-full border rounded-lg px-3 py-2 text-sm" placeholder="Ex: Yopougon, Tout Abidjan">
                    </div>
                </div>
                <div class="grid grid-cols-2 gap-2">
                    <div>
                        <label class="block text-xs font-bold text-slate-700 mb-1">Tarif de base indicatif *</label>
                        <input type="text" id="proTarif" required class="w-full border rounded-lg px-3 py-2 text-sm" placeholder="Ex: Dès 10 000 FCFA">
                    </div>
                    <div>
                        <label class="block text-xs font-bold text-slate-700 mb-1">Expérience *</label>
                        <input type="text" id="proExp" required class="w-full border rounded-lg px-3 py-2 text-sm" placeholder="Ex: 5 ans">
                    </div>
                </div>
                <div class="grid grid-cols-2 gap-2">
                    <div>
                        <label class="block text-xs font-bold text-slate-700 mb-1">Téléphone / WhatsApp *</label>
                        <input type="text" id="proTel" required class="w-full border rounded-lg px-3 py-2 text-sm" placeholder="+225 07...">
                    </div>
                    <div>
                        <label class="block text-xs font-bold text-slate-700 mb-1">Email *</label>
                        <input type="email" id="proEmail" required class="w-full border rounded-lg px-3 py-2 text-sm">
                    </div>
                </div>
                <div>
                    <label class="block text-xs font-bold text-slate-700 mb-1">Mot de passe (6 caractères min.) *</label>
                    <input type="password" id="proPass" minlength="6" required class="w-full border rounded-lg px-3 py-2 text-sm">
                </div>
                <p id="proError" class="text-xs text-red-600 font-semibold hidden"></p>
                <button type="submit" class="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-2.5 rounded-xl transition">
                    Valider mon inscription Artisan
                </button>
            </form>
        </div>
    </div>

    <script>
        const isLoggedIn = {{ 'true' if session.get('user_id') else 'false' }};
        const userRole = "{{ session.get('role', '') }}";

        function handleClientAction(metier) {
            if (!isLoggedIn) {
                openAuthModal('register_client');
            } else if (userRole === 'client') {
                window.location.href = '/mon-espace?metier=' + encodeURIComponent(metier);
            } else if (userRole === 'prestataire') {
                window.location.href = '/espace-prestataire';
            } else {
                window.location.href = '/admin';
            }
        }

        function handleProAction() {
            if (!isLoggedIn) {
                openAuthModal('register_pro');
            } else if (userRole === 'prestataire') {
                window.location.href = '/espace-prestataire';
            } else {
                alert("Vous êtes connecté avec un compte non-artisan. Déconnectez-vous pour créer un compte Artisan.");
            }
        }

        function filterByMetier(metier) {
            document.getElementById('metierSelect').value = metier;
            applyFilters();
            document.getElementById('catalogue').scrollIntoView({ behavior: 'smooth' });
        }

        function resetFilters() {
            document.getElementById('searchInput').value = '';
            document.getElementById('metierSelect').value = 'ALL';
            applyFilters();
        }

        function applyFilters() {
            const kw = document.getElementById('searchInput').value.toLowerCase();
            const metier = document.getElementById('metierSelect').value;
            document.querySelectorAll('.service-card').forEach(card => {
                const matchMetier = (metier === 'ALL' || card.getAttribute('data-metier') === metier);
                const matchKw = card.getAttribute('data-search').includes(kw);
                card.style.display = (matchMetier && matchKw) ? 'flex' : 'none';
            });
        }

        function openAuthModal(tab) {
            switchAuthTab(tab);
            document.getElementById('authModal').classList.remove('hidden');
            document.getElementById('authModal').classList.add('flex');
        }

        function closeAuthModal() {
            document.getElementById('authModal').classList.add('hidden');
            document.getElementById('authModal').classList.remove('flex');
        }

        function switchAuthTab(tab) {
            document.getElementById('loginForm').classList.add('hidden');
            document.getElementById('registerClientForm').classList.add('hidden');
            document.getElementById('registerProForm').classList.add('hidden');

            document.getElementById('tabLogin').className = "font-bold text-slate-400 pb-1";
            document.getElementById('tabRegClient').className = "font-bold text-slate-400 pb-1";
            document.getElementById('tabRegPro').className = "font-bold text-slate-400 pb-1";

            if (tab === 'login') {
                document.getElementById('loginForm').classList.remove('hidden');
                document.getElementById('tabLogin').className = "font-extrabold text-slate-900 border-b-2 border-slate-900 pb-1";
            } else if (tab === 'register_client') {
                document.getElementById('registerClientForm').classList.remove('hidden');
                document.getElementById('tabRegClient').className = "font-extrabold text-orange-600 border-b-2 border-orange-500 pb-1";
            } else {
                document.getElementById('registerProForm').classList.remove('hidden');
                document.getElementById('tabRegPro').className = "font-extrabold text-blue-600 border-b-2 border-blue-600 pb-1";
            }
        }

        async function submitLogin(e) {
            e.preventDefault();
            const res = await fetch('/api/login', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    email: document.getElementById('loginEmail').value,
                    password: document.getElementById('loginPassword').value
                })
            });
            const data = await res.json();
            if (data.status === 'success') {
                window.location.href = data.redirect;
            } else {
                const err = document.getElementById('loginError');
                err.textContent = data.message;
                err.classList.remove('hidden');
            }
        }

        async function submitRegister(e, role) {
            e.preventDefault();
            let payload = { role: role };
            if (role === 'client') {
                payload.nom = document.getElementById('cliNom').value;
                payload.commune = document.getElementById('cliCommune').value;
                payload.telephone = document.getElementById('cliTel').value;
                payload.email = document.getElementById('cliEmail').value;
                payload.password = document.getElementById('cliPass').value;
            } else {
                payload.nom = document.getElementById('proNom').value;
                payload.specialite = document.getElementById('proSpecialite').value;
                payload.commune = document.getElementById('proCommune').value;
                payload.tarif_base = document.getElementById('proTarif').value;
                payload.experience = document.getElementById('proExp').value;
                payload.telephone = document.getElementById('proTel').value;
                payload.email = document.getElementById('proEmail').value;
                payload.password = document.getElementById('proPass').value;
            }

            const res = await fetch('/api/register', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(payload)
            });
            const data = await res.json();
            if (data.status === 'success') {
                window.location.href = data.redirect;
            } else {
                const errId = role === 'client' ? 'cliError' : 'proError';
                const err = document.getElementById(errId);
                err.textContent = data.message;
                err.classList.remove('hidden');
            }
        }
    </script>
</body>
</html>
"""

# ==========================================
# 3. ESPACE PRESTATAIRE / ARTISAN
# ==========================================
PRO_DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Espace Artisan | ProxiPro CI</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap" rel="stylesheet">
    <style>body { font-family: 'Inter', sans-serif; background-color: #f1f5f9; }</style>
</head>
<body class="text-slate-800">
    <header class="bg-blue-900 text-white shadow-md">
        <div class="max-w-6xl mx-auto px-4 h-16 flex items-center justify-between">
            <div class="flex items-center space-x-3">
                <span class="font-extrabold text-lg">🛠️ ESPACE PRESTATAIRE</span>
                <span class="text-xs bg-blue-700 px-2.5 py-1 rounded-full font-bold">{{ user.specialite }}</span>
                {% if user.verifie %}
                    <span class="text-xs bg-emerald-500 text-white px-2.5 py-1 rounded-full font-bold">✓ Profil Vérifié</span>
                {% endif %}
            </div>
            <div class="flex items-center space-x-4">
                <a href="/" class="text-xs bg-blue-800 hover:bg-blue-700 px-3 py-1.5 rounded-lg">Accueil</a>
                <a href="/logout" class="text-xs font-bold bg-red-600 hover:bg-red-700 px-3 py-1.5 rounded-lg">Déconnexion</a>
            </div>
        </div>
    </header>

    <main class="max-w-6xl mx-auto px-4 py-8 space-y-8">

        {% with messages = get_flashed_messages(with_categories=true) %}
            {% for cat, msg in messages %}
                <div class="p-3 rounded-lg text-sm font-semibold {{ 'bg-emerald-100 text-emerald-800' if cat == 'success' else 'bg-red-100 text-red-700' }}">{{ msg }}</div>
            {% endfor %}
        {% endwith %}

        <!-- PROFIL, PHOTO, CV & NOTE GLOBALE -->
        <div class="bg-white p-6 rounded-2xl shadow-sm border border-slate-200">
            <div class="flex flex-wrap items-center justify-between gap-4 mb-5">
                <div class="flex items-center gap-4">
                    {% if user.photo %}
                        <img src="/uploads/photos/{{ user.photo }}" alt="Photo de profil" class="w-20 h-20 rounded-full object-cover border-2 border-blue-200">
                    {% else %}
                        <div class="w-20 h-20 rounded-full bg-blue-100 text-blue-700 flex items-center justify-center text-3xl font-extrabold">{{ user.nom[0] }}</div>
                    {% endif %}
                    <div>
                        <div class="flex flex-wrap items-center gap-2">
                            <h1 class="font-extrabold text-xl text-slate-900">{{ user.nom }}</h1>
                            {% if user.verifie %}
                                <span class="text-xs font-bold bg-emerald-100 text-emerald-800 px-2 py-0.5 rounded-full">✓ Vérifié par ProxiPro</span>
                            {% else %}
                                <span class="text-xs font-semibold bg-amber-50 text-amber-700 px-2 py-0.5 rounded-full">⏳ En attente de vérification (ajoutez photo + CV)</span>
                            {% endif %}
                        </div>
                        <p class="text-xs text-slate-500 mt-0.5">📍 Zone : <b>{{ user.commune }}</b> • 📞 {{ user.telephone }} • {{ user.experience }}</p>
                        <div class="flex items-center gap-3 mt-1">
                            {% if user.cv %}
                                <a href="/uploads/cv/{{ user.cv }}" target="_blank" class="text-xs font-bold text-blue-600 hover:underline">📄 Voir mon CV actuel</a>
                            {% else %}
                                <span class="text-xs text-slate-400">Aucun CV ajouté</span>
                            {% endif %}
                        </div>
                    </div>
                </div>

                <!-- SCORE DE SATISFACTION -->
                <div class="bg-amber-50 border border-amber-200 px-4 py-3 rounded-xl text-center">
                    <div class="text-[11px] font-bold uppercase text-amber-800">Note Clients</div>
                    {% if stats_avis.nb_avis > 0 %}
                        <div class="text-2xl font-extrabold text-amber-500">★ {{ "%.1f"|format(stats_avis.moyenne) }}/5</div>
                        <div class="text-[11px] text-slate-600">Basé sur {{ stats_avis.nb_avis }} avis</div>
                    {% else %}
                        <div class="text-sm font-bold text-slate-500 mt-1">Aucun avis reçu</div>
                    {% endif %}
                </div>
            </div>

            <form action="/espace-prestataire/profil" method="POST" enctype="multipart/form-data"
                  class="grid grid-cols-1 md:grid-cols-3 gap-4 bg-slate-50 p-4 rounded-xl">
                <div>
                    <label class="block text-xs font-bold text-slate-600 mb-1">Photo de profil (JPG, PNG, WEBP)</label>
                    <input type="file" name="photo" accept=".jpg,.jpeg,.png,.webp" class="w-full text-xs">
                </div>
                <div>
                    <label class="block text-xs font-bold text-slate-600 mb-1">CV (PDF, DOC, DOCX)</label>
                    <input type="file" name="cv" accept=".pdf,.doc,.docx" class="w-full text-xs">
                </div>
                <div>
                    <label class="block text-xs font-bold text-slate-600 mb-1">Mon tarif indicatif</label>
                    <input type="text" name="tarif_base" value="{{ user.tarif_base }}" class="w-full border rounded-lg px-3 py-1.5 text-xs font-semibold bg-white">
                </div>
                <div class="md:col-span-3 flex items-center justify-between flex-wrap gap-2 pt-2 border-t border-slate-200/60">
                    <p class="text-[11px] text-slate-400">Taille max : 6 Mo. Un profil avec photo et CV obtient la certification ProxiPro CI.</p>
                    <button type="submit" class="bg-slate-900 hover:bg-slate-800 text-white text-xs font-bold px-4 py-2 rounded-lg">Enregistrer mon profil</button>
                </div>
            </form>
        </div>

        <!-- SECTION 1 : MISSIONS DISPONIBLES -->
        <div>
            <h2 class="font-extrabold text-lg text-slate-900 mb-3">📢 Missions disponibles en "{{ user.specialite }}" ({{ missions_ouvertes|length }})</h2>
            {% if not missions_ouvertes %}
                <div class="bg-white p-6 rounded-xl border border-slate-200 text-sm text-slate-500">
                    Aucune nouvelle demande en attente dans votre spécialité pour le moment.
                </div>
            {% endif %}

            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                {% for m in missions_ouvertes %}
                <div class="bg-white p-5 rounded-2xl shadow-sm border-l-4 border-orange-500">
                    <div class="flex justify-between items-start mb-2">
                        <span class="text-xs font-extrabold bg-orange-50 text-orange-700 px-2.5 py-0.5 rounded">Demande #{{ m.id }}</span>
                        <span class="text-xs text-slate-400">{{ m.date_creation }}</span>
                    </div>
                    <h3 class="font-bold text-base text-slate-900">📍 {{ m.commune }} — {{ m.adresse_precise }}</h3>
                    <p class="text-xs text-slate-600 my-2 bg-slate-50 p-2.5 rounded-lg">"{{ m.details }}"</p>
                    <p class="text-xs text-slate-500 mb-3">Client : <b>{{ m.client_nom }}</b></p>

                    <form action="/espace-prestataire/accepter/{{ m.id }}" method="POST" class="flex space-x-2 pt-2 border-t">
                        <input type="text" name="tarif_propose" required placeholder="Votre devis (ex: 25 000 FCFA)" class="flex-1 border rounded-lg px-3 py-2 text-xs">
                        <button type="submit" class="bg-blue-600 hover:bg-blue-700 text-white font-bold px-4 py-2 rounded-lg text-xs shrink-0">
                            Accepter la mission ✓
                        </button>
                    </form>
                </div>
                {% endfor %}
            </div>
        </div>

        <!-- SECTION 2 : MES CHANTIERS ACCEPTÉS & AVIS REÇUS -->
        <div>
            <h2 class="font-extrabold text-lg text-slate-900 mb-3">🚧 Mes missions acceptées & en cours ({{ mes_chantiers|length }})</h2>
            <div class="space-y-4">
                {% for c in mes_chantiers %}
                <div class="bg-white p-5 rounded-2xl shadow-sm border border-slate-200 space-y-3">
                    <div class="flex flex-col lg:flex-row justify-between gap-4">
                        <div>
                            <span class="text-xs font-bold bg-emerald-100 text-emerald-800 px-2.5 py-0.5 rounded-full">{{ c.statut }}</span>
                            <h3 class="font-extrabold text-base text-slate-900 mt-1">Mission #{{ c.id }} — {{ c.commune }} ({{ c.adresse_precise }})</h3>
                            <p class="text-xs text-slate-600 mt-1">Client : <b>{{ c.client_nom }}</b> (📞 {{ c.telephone }})</p>
                            <p class="text-xs font-bold text-blue-700 mt-1">💰 Tarif convenu : {{ c.tarif_propose }} <span class="text-slate-400 font-normal">(Commission plateforme 10% : {{ c.commission }})</span></p>
                        </div>

                        <form action="/espace-prestataire/avancement/{{ c.id }}" method="POST" class="flex flex-col sm:flex-row items-center gap-2 bg-slate-50 p-3 rounded-xl h-fit">
                            <select name="etape" class="border rounded-lg px-3 py-2 text-xs bg-white font-semibold">
                                <option value="2" {{ 'selected' if c.etape == 2 else '' }}>2. Devis validé / RDV fixé</option>
                                <option value="3" {{ 'selected' if c.etape == 3 else '' }}>3. Intervention en cours sur site</option>
                                <option value="4" {{ 'selected' if c.etape == 4 else '' }}>4. Travaux terminés ✓</option>
                            </select>
                            <input type="text" name="note_admin" value="{{ c.note_admin }}" placeholder="Message pour le client..." class="border rounded-lg px-3 py-2 text-xs">
                            <button type="submit" class="bg-emerald-600 hover:bg-emerald-700 text-white font-bold px-4 py-2 rounded-lg text-xs">
                                Actualiser
                            </button>
                        </form>
                    </div>

                    {% if c.note_client %}
                    <div class="bg-amber-50 border border-amber-200 p-3 rounded-xl text-xs">
                        <div class="flex items-center justify-between">
                            <span class="font-extrabold text-amber-600">{{ '★' * c.note_client }}{{ '☆' * (5 - c.note_client) }} ({{ c.note_client }}/5)</span>
                            <span class="text-slate-400">Avis laissé par {{ c.client_nom }} le {{ c.date_avis }}</span>
                        </div>
                        {% if c.avis_client %}
                            <p class="text-slate-700 italic mt-1">"{{ c.avis_client }}"</p>
                        {% endif %}
                    </div>
                    {% endif %}
                </div>
                {% endfor %}
            </div>
        </div>
    </main>
</body>
</html>
"""

# ==========================================
# 4. ESPACE DEMANDEUR (CLIENT)
# ==========================================
CLIENT_DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mon Espace Client | ProxiPro CI</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap" rel="stylesheet">
    <style>body { font-family: 'Inter', sans-serif; background-color: #f1f5f9; }</style>
</head>
<body class="text-slate-800">
    <header class="bg-white shadow-sm">
        <div class="max-w-6xl mx-auto px-4 h-16 flex items-center justify-between">
            <a href="/" class="font-extrabold text-slate-900 text-base">← Retour à l'accueil <span class="text-orange-500">ProxiPro CI</span></a>
            <div class="flex items-center space-x-4">
                <span class="text-sm font-semibold text-slate-600">👤 {{ user.nom }} ({{ user.commune }})</span>
                <a href="/logout" class="text-xs font-bold text-red-600 bg-red-50 px-3 py-1.5 rounded-lg">Déconnexion</a>
            </div>
        </div>
    </header>

    <main class="max-w-6xl mx-auto px-4 py-8 grid grid-cols-1 lg:grid-cols-3 gap-8">
        <!-- NOUVELLE DEMANDE -->
        <div class="bg-white p-6 rounded-2xl shadow-sm border border-slate-200 h-fit">
            <h2 class="font-extrabold text-lg text-slate-900 mb-1">🛠️ Demander un prestataire</h2>
            <p class="text-xs text-slate-500 mb-4">Votre demande sera transmise aux artisans qualifiés de votre zone.</p>

            <form action="/mon-espace/nouveau" method="POST" class="space-y-3">
                <div>
                    <label class="block text-xs font-bold text-slate-700 mb-1">Corps de métier souhaité *</label>
                    <select name="metier" class="w-full border rounded-lg px-3 py-2 text-sm bg-white font-semibold">
                        <option value="Mécanicien" {{ 'selected' if default_metier == 'Mécanicien' else '' }}>🔧 Mécanicien</option>
                        <option value="Designer intérieur" {{ 'selected' if default_metier == 'Designer intérieur' else '' }}>🛋️ Designer d'intérieur</option>
                        <option value="Entretien après construction" {{ 'selected' if default_metier == 'Entretien après construction' else '' }}>🧹 Entretien maison après construction</option>
                        <option value="Plombier" {{ 'selected' if default_metier == 'Plombier' else '' }}>🚰 Plombier</option>
                        <option value="Carreleur" {{ 'selected' if default_metier == 'Carreleur' else '' }}>🧱 Carreleur</option>
                        <option value="Vitrier" {{ 'selected' if default_metier == 'Vitrier' else '' }}>🪟 Vitrier</option>
                        <option value="Peintre" {{ 'selected' if default_metier == 'Peintre' else '' }}>🎨 Peintre</option>
                    </select>
                </div>
                <div>
                    <label class="block text-xs font-bold text-slate-700 mb-1">Commune / Ville *</label>
                    <input type="text" name="commune" value="{{ user.commune }}" required class="w-full border rounded-lg px-3 py-2 text-sm">
                </div>
                <div>
                    <label class="block text-xs font-bold text-slate-700 mb-1">Quartier & Repère précis *</label>
                    <input type="text" name="adresse_precise" required class="w-full border rounded-lg px-3 py-2 text-sm" placeholder="Ex: Riviera Palmeraie, près de...">
                </div>
                <div>
                    <label class="block text-xs font-bold text-slate-700 mb-1">Description détaillée du besoin *</label>
                    <textarea name="details" rows="3" required class="w-full border rounded-lg px-3 py-2 text-sm" placeholder="Décrivez le travail à réaliser..."></textarea>
                </div>
                <button type="submit" class="w-full bg-orange-500 hover:bg-orange-600 text-white font-bold py-2.5 rounded-xl transition">
                    Publier ma demande
                </button>
            </form>
        </div>

        <!-- SUIVI DES INTERVENTIONS -->
        <div class="lg:col-span-2 space-y-4">
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% for cat, msg in messages %}
                    <div class="p-3 rounded-lg text-sm font-semibold {{ 'bg-emerald-100 text-emerald-800' if cat == 'success' else 'bg-red-100 text-red-700' }}">{{ msg }}</div>
                {% endfor %}
            {% endwith %}

            <h2 class="font-extrabold text-xl text-slate-900">📋 Suivi en temps réel de mes demandes ({{ demandes|length }})</h2>

            {% for d in demandes %}
            <div class="bg-white p-6 rounded-2xl shadow-sm border border-slate-200">
                <div class="flex flex-wrap justify-between items-start gap-2 mb-3">
                    <div>
                        <span class="text-xs font-bold text-orange-700 bg-orange-50 px-2.5 py-1 rounded-md">Ticket #{{ d.id }}</span>
                        <h3 class="font-extrabold text-base text-slate-900 mt-1">{{ d.metier }}</h3>
                        <p class="text-xs text-slate-500">📍 {{ d.commune }} ({{ d.adresse_precise }}) • Demandé le {{ d.date_creation }}</p>
                    </div>
                    <span class="text-xs font-bold px-3 py-1.5 rounded-full {{ 'bg-emerald-100 text-emerald-800' if d.etape == 4 else 'bg-blue-100 text-blue-800' }}">
                        {{ d.statut }}
                    </span>
                </div>

                <!-- BARRE DE PROGRESSION EN 4 ÉTAPES -->
                <div class="my-4">
                    <div class="grid grid-cols-4 gap-2 text-[11px] font-bold text-center mb-1.5">
                        <div class="{{ 'text-emerald-700' if d.etape >= 1 else 'text-slate-400' }}">1. Recherche Pro</div>
                        <div class="{{ 'text-emerald-700' if d.etape >= 2 else 'text-slate-400' }}">2. Tarif & RDV</div>
                        <div class="{{ 'text-emerald-700' if d.etape >= 3 else 'text-slate-400' }}">3. Sur Chantier</div>
                        <div class="{{ 'text-emerald-700' if d.etape >= 4 else 'text-slate-400' }}">4. Terminé</div>
                    </div>
                    <div class="w-full bg-slate-100 h-2.5 rounded-full overflow-hidden flex">
                        <div class="bg-emerald-600 h-full transition-all" style="width: {{ d.etape * 25 }}%"></div>
                    </div>
                </div>

                <div class="bg-slate-50 p-3.5 rounded-xl text-xs text-slate-700 border border-slate-100 space-y-1.5">
                    <div class="flex items-center gap-3">
                        {% if d.pro_photo %}
                            <img src="/uploads/photos/{{ d.pro_photo }}" alt="Photo du prestataire" class="w-12 h-12 rounded-full object-cover border border-slate-200 shrink-0">
                        {% endif %}
                        <div>
                            <p class="flex items-center gap-1.5">
                                <b>👷 Prestataire assigné :</b> <span class="text-slate-900 font-semibold">{{ d.prestataire_assigne }}</span>
                                {% if d.pro_verifie %}
                                    <span class="text-[10px] font-bold bg-emerald-100 text-emerald-800 px-1.5 py-0.5 rounded-full">✓ Vérifié</span>
                                {% endif %}
                            </p>
                            {% if d.pro_cv %}
                                <a href="/uploads/cv/{{ d.pro_cv }}" target="_blank" class="font-bold text-blue-600 hover:underline">📄 Consulter son CV</a>
                            {% endif %}
                        </div>
                    </div>
                    <p><b>💰 Tarif proposé :</b> <span class="text-emerald-700 font-bold">{{ d.tarif_propose }}</span></p>
                    <p><b>💬 Note de suivi :</b> {{ d.note_admin }}</p>
                </div>

                <!-- SYSTÈME DE NOTATION & AVIS (UNIQUEMENT À L'ÉTAPE 4) -->
                {% if d.etape == 4 %}
                    {% if d.note_client %}
                        <div class="mt-4 bg-amber-50 border border-amber-200 p-3.5 rounded-xl text-xs">
                            <div class="flex items-center justify-between">
                                <span class="font-extrabold text-amber-600 text-sm">{{ '★' * d.note_client }}{{ '☆' * (5 - d.note_client) }} ({{ d.note_client }}/5)</span>
                                <span class="text-slate-400">Avis publié le {{ d.date_avis }}</span>
                            </div>
                            {% if d.avis_client %}
                                <p class="text-slate-700 italic mt-1">"{{ d.avis_client }}"</p>
                            {% endif %}
                        </div>
                    {% else %}
                        <form action="/mon-espace/noter/{{ d.id }}" method="POST" class="mt-4 bg-orange-50/70 border border-orange-200 p-4 rounded-xl space-y-2.5">
                            <div class="font-extrabold text-xs text-slate-900">⭐ Évaluez la prestation de l'artisan :</div>
                            <div class="grid grid-cols-1 sm:grid-cols-3 gap-2">
                                <select name="note_client" required class="border border-slate-300 rounded-lg px-3 py-2 text-xs bg-white font-bold text-amber-600">
                                    <option value="5">★★★★★ (5/5 - Excellent)</option>
                                    <option value="4">★★★★☆ (4/5 - Très bien)</option>
                                    <option value="3">★★★☆☆ (3/5 - Correct)</option>
                                    <option value="2">★★☆☆☆ (2/5 - Moyen)</option>
                                    <option value="1">★☆☆☆☆ (1/5 - Insatisfait)</option>
                                </select>
                                <input type="text" name="avis_client" placeholder="Votre commentaire sur le travail réalisé..." class="sm:col-span-2 border border-slate-300 rounded-lg px-3 py-2 text-xs bg-white">
                            </div>
                            <button type="submit" class="bg-slate-900 hover:bg-slate-800 text-white font-bold px-4 py-2 rounded-lg text-xs">
                                Envoyer mon évaluation
                            </button>
                        </form>
                    {% endif %}
                {% endif %}
            </div>
            {% endfor %}
        </div>
    </main>
</body>
</html>
"""

# ==========================================
# 5. CONSOLE ADMINISTRATEUR
# ==========================================
ADMIN_DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Console Admin | ProxiPro CI</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap" rel="stylesheet">
    <style>body { font-family: 'Inter', sans-serif; background-color: #f1f5f9; }</style>
</head>
<body class="text-slate-800">
    <header class="bg-slate-900 text-white shadow-md">
        <div class="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
            <div class="flex items-center space-x-3">
                <span class="font-extrabold text-lg text-orange-500">⚙️ CONSOLE ADMIN PROXIPRO CI</span>
                <a href="/" class="text-xs bg-slate-800 hover:bg-slate-700 px-3 py-1.5 rounded-lg">Portail Public</a>
            </div>
            <a href="/logout" class="text-xs font-bold bg-red-600 hover:bg-red-700 px-3 py-1.5 rounded-lg">Déconnexion</a>
        </div>
    </header>

    <main class="max-w-7xl mx-auto px-4 py-8 space-y-8">
        <!-- INDICATEURS -->
        <div class="grid grid-cols-1 sm:grid-cols-4 gap-4">
            <div class="bg-white p-4 rounded-xl shadow-sm border-l-4 border-slate-900">
                <div class="text-xs text-slate-500 font-bold uppercase">Total Demandes</div>
                <div class="text-2xl font-extrabold mt-1">{{ demandes|length }}</div>
            </div>
            <div class="bg-white p-4 rounded-xl shadow-sm border-l-4 border-blue-600">
                <div class="text-xs text-slate-500 font-bold uppercase">Artisans Inscrits</div>
                <div class="text-2xl font-extrabold mt-1 text-blue-600">{{ artisans|length }}</div>
            </div>
            <div class="bg-white p-4 rounded-xl shadow-sm border-l-4 border-orange-500">
                <div class="text-xs text-slate-500 font-bold uppercase">Clients Inscrits</div>
                <div class="text-2xl font-extrabold mt-1 text-orange-600">{{ nb_clients }}</div>
            </div>
            <div class="bg-white p-4 rounded-xl shadow-sm border-l-4 border-emerald-600">
                <div class="text-xs text-slate-500 font-bold uppercase">Chantiers Terminés</div>
                <div class="text-2xl font-extrabold mt-1 text-emerald-600">{{ demandes|selectattr('etape', 'equalto', 4)|list|length }}</div>
            </div>
        </div>

        <!-- VALIDATION DES ARTISANS -->
        <div>
            <h2 class="font-extrabold text-xl text-slate-900 mb-3">👷 Vérification des Artisans & Dossiers (Photo / CV / Note)</h2>
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {% for a in artisans %}
                <div class="bg-white p-4 rounded-xl shadow-sm border border-slate-200 flex items-center justify-between gap-3">
                    <div class="flex items-center gap-3 min-w-0">
                        {% if a.photo %}
                            <img src="/uploads/photos/{{ a.photo }}" class="w-12 h-12 rounded-full object-cover border">
                        {% else %}
                            <div class="w-12 h-12 rounded-full bg-slate-100 flex items-center justify-center font-bold text-slate-500">{{ a.nom[0] }}</div>
                        {% endif %}
                        <div class="min-w-0">
                            <h3 class="font-bold text-sm text-slate-900 truncate">{{ a.nom }}</h3>
                            <p class="text-xs text-slate-500">{{ a.specialite }} • {{ a.commune }}</p>
                            <div class="flex items-center gap-2 mt-1 text-xs">
                                {% if a.nb_avis > 0 %}
                                    <span class="font-bold text-amber-500">★ {{ "%.1f"|format(a.note_moyenne) }}/5 ({{ a.nb_avis }})</span>
                                {% endif %}
                                {% if a.cv %}
                                    <a href="/uploads/cv/{{ a.cv }}" target="_blank" class="text-blue-600 font-bold hover:underline">📄 Voir CV</a>
                                {% else %}
                                    <span class="text-slate-400">Sans CV</span>
                                {% endif %}
                            </div>
                        </div>
                    </div>
                    <form action="/admin/certifier/{{ a.id }}" method="POST">
                        <button type="submit" class="text-xs font-bold px-3 py-1.5 rounded-lg {{ 'bg-emerald-100 text-emerald-800' if a.verifie else 'bg-slate-900 text-white hover:bg-slate-800' }}">
                            {{ '✓ Vérifié' if a.verifie else 'Certifier' }}
                        </button>
                    </form>
                </div>
                {% endfor %}
            </div>
        </div>

        <!-- SUPERVISION DES DEMANDES & COMMISSIONS -->
        <div>
            <h2 class="font-extrabold text-xl text-slate-900 mb-4">📋 Supervision globale des demandes & commissions (10 %)</h2>
            <div class="space-y-4">
                {% for d in demandes %}
                <div class="bg-white p-5 rounded-2xl shadow-sm border border-slate-200 grid grid-cols-1 lg:grid-cols-12 gap-4 items-center">
                    <div class="lg:col-span-5">
                        <span class="text-xs font-extrabold bg-slate-900 text-white px-2 py-0.5 rounded">#{{ d.id }}</span>
                        <span class="text-xs font-bold text-orange-700 bg-orange-50 px-2 py-0.5 rounded">{{ d.metier }}</span>
                        <h3 class="font-bold text-sm text-slate-900 mt-1">Client : {{ d.client_nom }} ({{ d.telephone }})</h3>
                        <p class="text-xs text-slate-600">📍 {{ d.commune }} — {{ d.adresse_precise }}</p>
                        <p class="text-xs font-bold text-blue-700 mt-1">
                            👷 Artisan : {{ d.prestataire_assigne }} | 💰 Devis : {{ d.tarif_propose }}
                            <span class="text-emerald-700">(Comm. : {{ d.commission }})</span>
                        </p>
                        {% if d.note_client %}
                            <p class="text-xs text-amber-600 font-bold mt-1">
                                {{ '★' * d.note_client }}{{ '☆' * (5 - d.note_client) }} ({{ d.note_client }}/5)
                                {% if d.avis_client %}— <span class="font-normal italic text-slate-600">"{{ d.avis_client }}"</span>{% endif %}
                            </p>
                        {% endif %}
                    </div>

                    <form action="/admin/update/{{ d.id }}" method="POST" class="lg:col-span-7 grid grid-cols-1 sm:grid-cols-3 gap-3 bg-slate-50 p-3 rounded-xl">
                        <div>
                            <label class="block text-[11px] font-bold text-slate-600 mb-1">Étape</label>
                            <select name="etape" class="w-full border rounded-lg px-2 py-1.5 text-xs bg-white">
                                <option value="1" {{ 'selected' if d.etape == 1 else '' }}>1. Recherche Pro</option>
                                <option value="2" {{ 'selected' if d.etape == 2 else '' }}>2. Tarif & RDV</option>
                                <option value="3" {{ 'selected' if d.etape == 3 else '' }}>3. Sur Chantier</option>
                                <option value="4" {{ 'selected' if d.etape == 4 else '' }}>4. Terminé</option>
                            </select>
                        </div>
                        <div>
                            <label class="block text-[11px] font-bold text-slate-600 mb-1">Prestataire</label>
                            <input type="text" name="prestataire_assigne" value="{{ d.prestataire_assigne }}" class="w-full border rounded-lg px-2 py-1.5 text-xs">
                        </div>
                        <div>
                            <label class="block text-[11px] font-bold text-slate-600 mb-1">Note</label>
                            <div class="flex space-x-1">
                                <input type="text" name="note_admin" value="{{ d.note_admin }}" class="w-full border rounded-lg px-2 py-1.5 text-xs">
                                <button type="submit" class="bg-emerald-600 text-white font-bold px-3 py-1.5 rounded-lg text-xs">OK</button>
                            </div>
                        </div>
                    </form>
                </div>
                {% endfor %}
            </div>
        </div>
    </main>
</body>
</html>
"""

# ==========================================
# 6. ROUTES FLASK
# ==========================================
@app.route("/health")
def health_check():
    """Endpoint de surveillance pour Gunicorn / Load Balancer / Hébergeur."""
    return jsonify({"status": "ok", "service": "ProxiPro CI"}), 200


@app.route("/")
def home():
    with get_db() as conn:
        services = conn.execute("SELECT * FROM services").fetchall()
        artisans = conn.execute("""
            SELECT u.*,
                   COALESCE(AVG(d.note_client), 0) AS note_moyenne,
                   COUNT(d.note_client) AS nb_avis
            FROM users u
            LEFT JOIN demandes d ON u.id = d.prestataire_id AND d.note_client IS NOT NULL
            WHERE u.role = 'prestataire'
            GROUP BY u.id
            ORDER BY u.verifie DESC, note_moyenne DESC, u.id DESC
        """).fetchall()
    show_demo_hint = os.environ.get("SEED_DEMO", "0") == "1"
    return render_template_string(PORTAL_HTML, services=services, artisans=artisans, show_demo_hint=show_demo_hint)


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip()
    password = data.get("password", "")
    if not email or not password:
        return jsonify({"status": "error", "message": "Veuillez renseigner tous les champs."}), 400

    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

    if user and check_password_hash(user["password_hash"], password):
        session.clear()
        session["user_id"] = user["id"]
        session["user_nom"] = user["nom"]
        session["role"] = user["role"]
        target = {"admin": "/admin", "prestataire": "/espace-prestataire"}.get(user["role"], "/mon-espace")
        return jsonify({"status": "success", "redirect": target})

    return jsonify({"status": "error", "message": "Email ou mot de passe incorrect."}), 401


@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    role = data.get("role", "client")
    if role not in ("client", "prestataire"):
        role = "client"

    nom = data.get("nom", "").strip()
    commune = data.get("commune", "").strip()
    telephone = data.get("telephone", "").strip()
    email = data.get("email", "").strip()
    password = data.get("password", "")

    if not all([nom, commune, telephone, email]) or len(password) < 6:
        return jsonify({"status": "error", "message": "Champs invalides (mot de passe de 6 caractères minimum requis)."}), 400

    with get_db() as conn:
        c = conn.cursor()
        try:
            c.execute("""
                INSERT INTO users (nom, commune, telephone, email, password_hash, role, specialite, tarif_base, experience, date_inscription)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                nom, commune, telephone, email, generate_password_hash(password), role,
                data.get("specialite", "").strip(), data.get("tarif_base", "").strip(),
                data.get("experience", "").strip(), datetime.now().strftime("%d/%m/%Y")
            ))
            user_id = c.lastrowid
            conn.commit()
            session.clear()
            session["user_id"] = user_id
            session["user_nom"] = nom
            session["role"] = role
            target = "/espace-prestataire" if role == "prestataire" else "/mon-espace"
            return jsonify({"status": "success", "redirect": target})
        except sqlite3.IntegrityError:
            return jsonify({"status": "error", "message": "Cette adresse email est déjà enregistrée."}), 409


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# --- FICHIERS TÉLÉVERSÉS ---
@app.route("/uploads/photos/<filename>")
def uploaded_photo(filename):
    safe_name = os.path.basename(filename)
    if safe_name != filename:
        abort(400)
    return send_from_directory(PHOTO_DIR, safe_name)


@app.route("/uploads/cv/<filename>")
def uploaded_cv(filename):
    if "user_id" not in session:
        abort(403)
    safe_name = os.path.basename(filename)
    if safe_name != filename:
        abort(400)
    return send_from_directory(CV_DIR, safe_name, as_attachment=True)


@app.errorhandler(413)
def fichier_trop_gros(e):
    flash("Fichier trop volumineux (6 Mo maximum).", "error")
    if session.get("role") == "prestataire":
        return redirect(url_for("pro_dashboard"))
    return redirect(url_for("home"))


# --- ROUTES CLIENT ---
@app.route("/mon-espace")
def client_dashboard():
    if "user_id" not in session or session.get("role") != "client":
        return redirect(url_for("home"))
    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        demandes = conn.execute("""
            SELECT d.*, p.photo AS pro_photo, p.cv AS pro_cv, p.verifie AS pro_verifie
            FROM demandes d LEFT JOIN users p ON d.prestataire_id = p.id
            WHERE d.user_id = ?
            ORDER BY d.id DESC
        """, (session["user_id"],)).fetchall()
    return render_template_string(CLIENT_DASHBOARD_HTML, user=user, demandes=demandes, default_metier=request.args.get("metier", ""))


@app.route("/mon-espace/nouveau", methods=["POST"])
def nouvelle_demande():
    if "user_id" not in session or session.get("role") != "client":
        return redirect(url_for("home"))
    with get_db() as conn:
        conn.execute("""
            INSERT INTO demandes (user_id, metier, commune, adresse_precise, details, date_creation)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            session["user_id"], request.form["metier"], request.form["commune"].strip(),
            request.form["adresse_precise"].strip(), request.form["details"].strip(),
            datetime.now().strftime("%d/%m/%Y %H:%M")
        ))
        conn.commit()
    return redirect(url_for("client_dashboard"))


@app.route("/mon-espace/noter/<int:demande_id>", methods=["POST"])
def client_noter_prestation(demande_id):
    if "user_id" not in session or session.get("role") != "client":
        return redirect(url_for("home"))
    try:
        note = max(1, min(5, int(request.form.get("note_client", 5))))
    except ValueError:
        note = 5

    avis = request.form.get("avis_client", "").strip()
    with get_db() as conn:
        conn.execute("""
            UPDATE demandes
            SET note_client = ?, avis_client = ?, date_avis = ?
            WHERE id = ? AND user_id = ? AND etape = 4 AND note_client IS NULL
        """, (note, avis, datetime.now().strftime("%d/%m/%Y"), demande_id, session["user_id"]))
        conn.commit()
    flash("Merci ! Votre note et votre avis ont bien été enregistrés.", "success")
    return redirect(url_for("client_dashboard"))


# --- ROUTES PRESTATAIRE ---
@app.route("/espace-prestataire")
def pro_dashboard():
    if "user_id" not in session or session.get("role") != "prestataire":
        return redirect(url_for("home"))
    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        stats_avis = conn.execute("""
            SELECT COALESCE(AVG(note_client), 0) AS moyenne, COUNT(note_client) AS nb_avis
            FROM demandes WHERE prestataire_id = ? AND note_client IS NOT NULL
        """, (session["user_id"],)).fetchone()
        missions_ouvertes = conn.execute("""
            SELECT d.*, u.nom as client_nom
            FROM demandes d JOIN users u ON d.user_id = u.id
            WHERE d.metier = ? AND d.prestataire_id IS NULL
            ORDER BY d.id DESC
        """, (user["specialite"],)).fetchall()
        mes_chantiers = conn.execute("""
            SELECT d.*, u.nom as client_nom, u.telephone
            FROM demandes d JOIN users u ON d.user_id = u.id
            WHERE d.prestataire_id = ?
            ORDER BY d.id DESC
        """, (session["user_id"],)).fetchall()
    return render_template_string(
        PRO_DASHBOARD_HTML,
        user=user,
        stats_avis=stats_avis,
        missions_ouvertes=missions_ouvertes,
        mes_chantiers=mes_chantiers
    )


@app.route("/espace-prestataire/profil", methods=["POST"])
def pro_update_profil():
    if "user_id" not in session or session.get("role") != "prestataire":
        return redirect(url_for("home"))

    with get_db() as conn:
        user = conn.execute("SELECT photo, cv FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        photo_name = user["photo"] or ""
        cv_name = user["cv"] or ""

        photo_file = request.files.get("photo")
        if photo_file and photo_file.filename:
            new = save_upload(photo_file, PHOTO_DIR, ALLOWED_PHOTO)
            if new:
                remove_file(PHOTO_DIR, photo_name)
                photo_name = new
            else:
                flash("Photo refusée : utilisez un fichier JPG, PNG ou WEBP valide.", "error")

        cv_file = request.files.get("cv")
        if cv_file and cv_file.filename:
            new = save_upload(cv_file, CV_DIR, ALLOWED_CV)
            if new:
                remove_file(CV_DIR, cv_name)
                cv_name = new
            else:
                flash("CV refusé : utilisez un fichier PDF, DOC ou DOCX valide.", "error")

        conn.execute(
            "UPDATE users SET tarif_base = ?, photo = ?, cv = ? WHERE id = ?",
            (request.form.get("tarif_base", "").strip(), photo_name, cv_name, session["user_id"])
        )
        conn.commit()
    flash("Profil mis à jour avec succès.", "success")
    return redirect(url_for("pro_dashboard"))


@app.route("/espace-prestataire/accepter/<int:demande_id>", methods=["POST"])
def pro_accepter_mission(demande_id):
    if "user_id" not in session or session.get("role") != "prestataire":
        return redirect(url_for("home"))
    tarif = request.form.get("tarif_propose", "").strip()
    if not tarif:
        flash("Veuillez indiquer un tarif avant d'accepter.", "error")
        return redirect(url_for("pro_dashboard"))

    commission = calculer_commission(tarif)
    with get_db() as conn:
        pro = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        info_pro = f"{pro['nom']} (📞 {pro['telephone']})"
        conn.execute("""
            UPDATE demandes
            SET prestataire_id = ?, prestataire_assigne = ?, tarif_propose = ?, commission = ?,
                etape = 2, statut = '2. Prestataire affecté - Tarif proposé',
                note_admin = 'Un artisan a accepté votre demande et proposé son tarif. Il vous contactera sous peu.'
            WHERE id = ? AND prestataire_id IS NULL
        """, (session["user_id"], info_pro, tarif, commission, demande_id))
        conn.commit()
    flash("Mission acceptée ! Retrouvez-la dans vos chantiers en cours.", "success")
    return redirect(url_for("pro_dashboard"))


@app.route("/espace-prestataire/avancement/<int:demande_id>", methods=["POST"])
def pro_update_avancement(demande_id):
    if "user_id" not in session or session.get("role") != "prestataire":
        return redirect(url_for("home"))
    etape = int(request.form["etape"])
    statuts = {
        2: "2. Prestataire affecté - Tarif proposé",
        3: "3. Intervention en cours sur site",
        4: "4. Travaux terminés & Validés"
    }
    with get_db() as conn:
        conn.execute("""
            UPDATE demandes SET etape = ?, statut = ?, note_admin = ?
            WHERE id = ? AND prestataire_id = ?
        """, (etape, statuts.get(etape, "En cours"), request.form["note_admin"].strip(), demande_id, session["user_id"]))
        conn.commit()
    return redirect(url_for("pro_dashboard"))


# --- ROUTES ADMIN ---
@app.route("/admin")
def admin_dashboard():
    if "user_id" not in session or session.get("role") != "admin":
        return redirect(url_for("home"))
    with get_db() as conn:
        demandes = conn.execute("""
            SELECT d.*, u.nom as client_nom, u.telephone
            FROM demandes d JOIN users u ON d.user_id = u.id
            ORDER BY d.id DESC
        """).fetchall()
        nb_clients = conn.execute("SELECT COUNT(*) FROM users WHERE role = 'client'").fetchone()[0]
        artisans = conn.execute("""
            SELECT u.*,
                   COALESCE(AVG(d.note_client), 0) AS note_moyenne,
                   COUNT(d.note_client) AS nb_avis
            FROM users u
            LEFT JOIN demandes d ON u.id = d.prestataire_id AND d.note_client IS NOT NULL
            WHERE u.role = 'prestataire'
            GROUP BY u.id
            ORDER BY u.id DESC
        """).fetchall()
    return render_template_string(ADMIN_DASHBOARD_HTML, demandes=demandes, nb_clients=nb_clients, artisans=artisans)


@app.route("/admin/certifier/<int:user_id>", methods=["POST"])
def admin_certifier_artisan(user_id):
    if "user_id" not in session or session.get("role") != "admin":
        return redirect(url_for("home"))
    with get_db() as conn:
        conn.execute("UPDATE users SET verifie = CASE WHEN verifie = 1 THEN 0 ELSE 1 END WHERE id = ? AND role = 'prestataire'", (user_id,))
        conn.commit()
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/update/<int:demande_id>", methods=["POST"])
def admin_update_demande(demande_id):
    if "user_id" not in session or session.get("role") != "admin":
        return redirect(url_for("home"))
    etape = int(request.form["etape"])
    statuts = {
        1: "1. Recherche de prestataire disponible",
        2: "2. Prestataire affecté - Tarif proposé",
        3: "3. Intervention en cours sur site",
        4: "4. Travaux terminés & Validés"
    }
    with get_db() as conn:
        conn.execute("""
            UPDATE demandes SET etape = ?, statut = ?, prestataire_assigne = ?, note_admin = ?
            WHERE id = ?
        """, (etape, statuts.get(etape, "En cours"), request.form["prestataire_assigne"].strip(), request.form["note_admin"].strip(), demande_id))
        conn.commit()
    return redirect(url_for("admin_dashboard"))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)