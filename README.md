# 🛠️ ProxiPro CI — Plateforme de Mise en Relation Artisans & Clients

**ProxiPro CI** est une application web développée avec **Flask** et **SQLite3** permettant aux particuliers et entreprises en Côte d'Ivoire de trouver rapidement des prestataires qualifiés, et aux artisans de décrocher des chantiers.

## ✨ Fonctionnalités principales

* **Catalogue des 7 corps de métier :** Mécanicien, Designer d'intérieur, Entretien après construction, Plombier, Carreleur, Vitrier et Peintre.
* **Espace Client (`/mon-espace`) :**
  * Publication de demandes d'intervention avec localisation précise.
  * Suivi en temps réel sur **4 étapes** (*Recherche Pro → Tarif & RDV → Sur Chantier → Terminé*).
  * Consultation de la photo, du badge de vérification et du CV de l'artisan assigné.
  * **Système de notation (1 à 5 ★) et d'avis** une fois la mission terminée.
* **Espace Prestataire / Artisan (`/espace-prestataire`) :**
  * Consultation des missions disponibles selon sa spécialité et envoi de devis.
  * Gestion du profil public (téléversement sécurisé de photo et de CV).
  * Mise à jour de l'avancement des chantiers et suivi de sa note moyenne.
* **Console Administrateur (`/admin`) :**
  * Certification des artisans (`✓ Profil Vérifié`) après contrôle de leur photo et CV.
  * Supervision globale des demandes, des avis clients et du calcul automatique des commissions (10 %).

---

## 📂 Structure du projet

```text
proxipro-ci/
├── mainA3.py              # Application principale Flask (routes, SQLite, interfaces)
├── requirements.txt       # Dépendances Python (Flask, Werkzeug, Gunicorn)
├── proxipro_portal_v3.db  # Base de données SQLite (générée automatiquement au démarrage)
├── uploads/               # Dossier créé automatiquement pour les fichiers téléversés
│   ├── photos/            # Photos de profil des artisans
│   └── cv/                # CV des artisans (PDF, DOC, DOCX)
└── README.md              # Documentation du projet
