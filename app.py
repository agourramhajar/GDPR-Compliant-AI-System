"""
Système IA Responsable — ENSA Béni Mellal v3
Corrections complètes + rôles distincts + upload fichiers + base élargie
"""
from flask import Flask, render_template, request, session, redirect, url_for, flash, jsonify
import sqlite3, hashlib, logging, os, re
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.urandom(32)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
ALLOWED_EXT = {'pdf','txt','docx','doc','md','csv'}
os.makedirs('uploads', exist_ok=True)

logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | %(message)s',
    handlers=[logging.FileHandler('audit.log'), logging.StreamHandler()])
logger = logging.getLogger(__name__)
DB_PATH = 'ensa_ia.db'

SENSITIVE_PATTERNS = [
    (r'\b[A-Z]{2}\d{6}\b', "numéro d'identité"),
    (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', "adresse email"),
    (r'\b(?:\+212|0)([ \-]?\d){9}\b', "numéro de téléphone"),
    (r'\b\d{16}\b', "numéro de carte bancaire"),
]
def detect_sensitive(text):
    for p, l in SENSITIVE_PATTERNS:
        if re.search(p, text, re.IGNORECASE): return True, l
    return False, None

def allowed_file(fn): return '.' in fn and fn.rsplit('.',1)[1].lower() in ALLOWED_EXT

ROLES = {
    'etudiant':    {'label':'Étudiant(e)',             'color':'#5B9FD4','icon':'🎓'},
    'prof':        {'label':'Enseignant(e)',            'color':'#F59E0B','icon':'👨‍🏫'},
    'admin_ecole': {'label':'Personnel administratif', 'color':'#A78BFA','icon':'🏛️'},
    'admin':       {'label':'Administrateur système',  'color':'#EF4444','icon':'🛡️'},
}
STAFF = {'prof','admin_ecole','admin'}

DROITS = {
    'etudiant':['Obtenir des explications sur des concepts académiques, scientifiques ou techniques',
        'Générer des ébauches de textes, plans ou résumés à des fins pédagogiques',
        "Formuler des questions dans le cadre de ses études à l'ENSA",
        'Résumer des documents non sensibles soumis dans l\'interface',
        'Améliorer la qualité rédactionnelle de travaux académiques',
        'Poser des questions sur des fichiers ou cours joints'],
    'prof':['Toutes les fonctionnalités étudiants',
        'Générer des plans de cours, sujets d\'examens, fiches pédagogiques',
        'Assistance à la préparation de supports pédagogiques',
        'Analyse et commentaire de travaux (sans données personnelles)',
        'Aide à la recherche et rédaction académique',
        'Accès aux suggestions pédagogiques (Régime 2 — validation humaine)',
        'Questions sur fichiers de cours joints'],
    'admin_ecole':['Toutes les fonctionnalités étudiants',
        'Rédaction de documents administratifs institutionnels',
        'Génération de comptes rendus, rapports, procès-verbaux',
        'Synthèse de documents institutionnels non confidentiels',
        'Questions sur documents joints'],
    'admin':['Accès complet au système','Validation décisions Régime 2',
        'Consultation journaux d\'audit','Gestion utilisateurs et contestations'],
}

KB = {
    "mathématiques":{"k":["math","algèbre","calcul","probabilité","statistique","matrice","vecteur","dérivée","intégrale","limite","équation","géométrie","trigonométrie","logarithme","suite","combinatoire"],"v":"Mathématiques : algèbre (équations, polynômes, matrices, espaces vectoriels), analyse (limites, dérivées, intégrales, séries de Taylor), probabilités (espérance, variance, loi normale, Bayes), statistiques (régression, test d'hypothèse), géométrie et trigonométrie. Applications : cryptographie, traitement du signal, machine learning, simulation."},
    "physique":{"k":["physique","mécanique","thermodynamique","électricité","optique","onde","quantique","énergie","force","champ","circuit électrique","électromagnétisme"],"v":"Physique : mécanique newtonienne (F=ma, lois de conservation, travail-énergie), thermodynamique (1er et 2e principes, entropie, cycles), électromagnétisme (loi de Coulomb, Maxwell, induction), optique (réflexion, réfraction, diffraction, interférence), mécanique quantique (dualité onde-corpuscule, principe d'incertitude d'Heisenberg, modèle de Bohr), relativité restreinte (dilatation du temps, E=mc²)."},
    "chimie":{"k":["chimie","molécule","atome","réaction","acide","base","oxydation","liaison chimique","tableau périodique","stœchiométrie","thermochimie"],"v":"Chimie : tableau périodique et propriétés des éléments, liaisons (covalente, ionique, hydrogène, Van der Waals), réactions (acido-basiques, oxydo-réduction, précipitation), stœchiométrie, thermochimie (enthalpie, énergie de Gibbs, équilibre chimique), cinétique chimique, chimie organique (hydrocarbures, fonctions, substitution/addition/élimination), spectroscopie (IR, NMR, UV-Vis)."},
    "informatique":{"k":["informatique","ordinateur","système d'exploitation","processeur","mémoire","compilation","interprétation","virtualisation","cloud","architecture","assembleur","binaire"],"v":"Informatique fondamentale : architecture von Neumann (CPU, RAM, bus, E/S), systèmes d'exploitation (gestion processus, mémoire, fichiers, threads), représentation de l'information (binaire, hexadécimal, virgule flottante IEEE754), compilation vs interprétation, complexité algorithmique (P, NP, NP-complet), virtualisation, cloud computing (IaaS, PaaS, SaaS), conteneurs Docker."},
    "programmation":{"k":["python","java","c++","javascript","code","variable","boucle","fonction","classe","objet","héritage","récursion","flask","django","api","rest","git","test","debug"],"v":"Programmation : paradigmes (impératif, OOP, fonctionnel, déclaratif). Python : indentation, listes/dicts/sets, compréhensions, générateurs, décorateurs, gestion exceptions, bibliothèques (numpy, pandas, matplotlib, flask). OOP : encapsulation, héritage, polymorphisme, abstraction, SOLID. REST API : verbes HTTP, JSON, status codes. Git : commit, branch, merge, rebase. Tests : unittest, pytest, TDD."},
    "algorithmes":{"k":["algorithme","tri","recherche","complexité","pile","file","arbre","graphe","récursivité","hash","dp","greedy","backtracking","bfs","dfs","dijkstra"],"v":"Algorithmique : tris (bulles O(n²), insertion, sélection, fusion O(n log n), rapide O(n log n) moyen, tas), recherche (linéaire O(n), binaire O(log n)), structures (tableau, liste chaînée, pile LIFO, file FIFO, arbre BST, AVL, tas, graphe), paradigmes (diviser-pour-régner, programmation dynamique, glouton, backtracking), graphes (BFS, DFS, Dijkstra, Bellman-Ford, Floyd-Warshall, Prim, Kruskal), hachage."},
    "ia":{"k":["ia","intelligence artificielle","machine learning","deep learning","réseau de neurones","apprentissage","classification","régression","clustering","nlp","vision","transformer","gpt","cnn","rnn","lstm","reinforcement"],"v":"IA et ML : apprentissage supervisé (régression linéaire/logistique, SVM, arbres de décision, forêts aléatoires, KNN, Naive Bayes), non supervisé (K-means, ACP, autoencoders), par renforcement (Q-learning, DQN). Deep learning : perceptron multicouche, rétropropagation, CNN (images), RNN/LSTM (séquences), Transformers (attention, BERT, GPT). IA générative : VAE, GAN, diffusion models. Métriques : accuracy, précision, rappel, F1, AUC-ROC, RMSE. Bibliothèques : TensorFlow, PyTorch, scikit-learn, Hugging Face."},
    "cybersécurité":{"k":["cybersécurité","sécurité","hacker","attaque","chiffrement","cryptographie","vulnérabilité","pare-feu","intrusion","malware","phishing","authentification","pentest","forensique","owasp"],"v":"Cybersécurité : triade CIA (Confidentialité, Intégrité, Disponibilité). Attaques : phishing, ransomware, injection SQL, XSS, CSRF, DDoS, MITM, buffer overflow. Défenses : chiffrement symétrique (AES-256), asymétrique (RSA, ECC), TLS/HTTPS, hachage (SHA-256, bcrypt), authentification forte (MFA, FIDO2), pare-feu, IDS/IPS, RBAC, zero trust. OWASP Top 10. Tests de pénétration (pentest) : reconnaissance, exploitation, post-exploitation. Analyse forensique, SIEM, SOC. Standards : ISO 27001, NIST CSF."},
    "réseaux":{"k":["réseau","tcp","ip","udp","http","dns","dhcp","ssh","ftp","smtp","routeur","switch","sous-réseau","osi","wan","lan","wifi","fibre","vlan","vpn","qos"],"v":"Réseaux : modèle OSI (7 couches) et TCP/IP (4 couches). Protocoles : TCP (connexion, fiable), UDP (sans connexion, rapide), HTTP/HTTPS, DNS, DHCP, SSH, FTP, SMTP/IMAP. Adressage IPv4 (classes, CIDR, masques, NAT, DHCP), IPv6 (128 bits, link-local, global). Équipements : hub (couche 1), switch (couche 2), routeur (couche 3). Routage : OSPF, BGP, RIP. VLAN, VPN, QoS, WiFi (802.11a/b/g/n/ac/ax), sécurité réseau (ACL, pare-feu, DMZ)."},
    "bdd":{"k":["base de données","sql","mysql","postgresql","sqlite","nosql","mongodb","table","requête","jointure","index","transaction","normalisation","orm","redis","cassandra"],"v":"Bases de données : modèle relationnel (tables, clés primaires/étrangères, contraintes), SQL (SELECT, INSERT, UPDATE, DELETE, JOIN inner/left/right/full, GROUP BY, HAVING, sous-requêtes, vues, index, procédures stockées, triggers), normalisation (1NF, 2NF, 3NF, BCNF, 4NF), transactions ACID, optimisation des requêtes. NoSQL : MongoDB (documents BSON), Redis (clé-valeur, cache), Cassandra (large scale), Neo4j (graphes). ORM : SQLAlchemy, Hibernate, Django ORM."},
    "rgpd":{"k":["rgpd","gdpr","données personnelles","protection des données","vie privée","consentement","dpo","aipd","pia","cnil","cndp","responsable de traitement","sous-traitant","violation"],"v":"RGPD (Règlement UE 2016/679) : principes Art.5 (licéité, minimisation, limitation finalités, exactitude, conservation limitée, intégrité, accountability). Bases légales Art.6 : consentement, contrat, obligation légale, intérêt vital, mission publique, intérêt légitime. Droits Art.15-22 : accès, rectification, effacement, opposition, limitation, portabilité, non-décision automatisée. AIPD obligatoire (Art.35) si ≥2 critères WP248. DPO (Art.37-39). Violation de données (Art.33 : CNDP sous 72h). Sanctions Art.83 : jusqu'à 4% CA mondial."},
    "droit":{"k":["droit","juridique","loi","réglementation","contrat","responsabilité","propriété intellectuelle","brevet","marque","copyright","licence","cgu","cybercriminalité"],"v":"Droit du numérique : propriété intellectuelle (droits d'auteur durée 70 ans post-mortem, brevets 20 ans, marques, licences open source GPL/MIT/Apache), contrats numériques (CGU, SLA, signature électronique eIDAS), responsabilité des hébergeurs (safe harbor), e-commerce, cybercriminalité (Convention de Budapest, loi n°09-08 Maroc, CNDP). Transferts de données hors UE : clauses contractuelles types, binding corporate rules. Loi 09-08 Maroc : protection des données personnelles, rôle CNDP."},
    "éthique":{"k":["éthique","biais algorithmique","fairness","explicabilité","transparence","gouvernance ia","ai act","discrimination algorithmique","xai","lime","shap","responsabilité"],"v":"Éthique de l'IA : principes UE 2019 pour une IA digne de confiance (supervision humaine, robustesse, vie privée, transparence, équité, bien-être sociétal, responsabilité). Biais algorithmiques : types (biais de sélection, confirmation, représentation), sources (données, algorithme, interaction), détection et mitigation. Explicabilité (XAI) : LIME, SHAP, attention maps. AI Act européen : classification par risque (inacceptable, élevé, limité, minimal). Gouvernance IA : accountability, audit, comité d'éthique, DPO."},
    "gestion":{"k":["gestion","management","stratégie","marketing","finance","comptabilité","rh","ressources humaines","entrepreneuriat","projet","agile","scrum","swot","pestel","bsc"],"v":"Management : planification stratégique (SWOT, PESTEL, Porter 5 forces, BSC), gestion de projet (PMI/PMBOK, Agile/Scrum/Kanban, Gantt, PERT), comptabilité (bilan, compte de résultat, tableaux de flux), finance (VAN, TRI, WACC, levier financier, options), marketing (mix 4P/7P, segmentation, ciblage, positionnement, digital marketing, CRM), ressources humaines (recrutement, formation, GPEC, motivation, évaluation 360°), entrepreneuriat (business model canvas, lean startup, business plan, levée de fonds)."},
    "économie":{"k":["économie","microéconomie","macroéconomie","marché","offre","demande","pib","inflation","chômage","banque centrale","monnaie","commerce international","mondialisation"],"v":"Économie : microéconomie (offre/demande, élasticité, surplus, concurrence parfaite/imparfaite/monopole, oligopole, externalités, biens publics, défaillances de marché), macroéconomie (PIB, croissance, chômage NAIRU, inflation, politique monétaire BCE/BAM, politique budgétaire, courbe de Phillips), commerce international (avantages absolus/comparatifs, balance des paiements, taux de change, accords OMC), économie numérique (effets de réseau, plateformes, données comme bien économique)."},
    "biologie":{"k":["biologie","cellule","adn","génétique","protéine","évolution","écosystème","microbiologie","physiologie","enzyme","mitose","méiose","darwin"],"v":"Biologie : cellule (procaryote vs eucaryote, organites : noyau, mitochondrie, réticulum, Golgi, ribosome), génétique moléculaire (ADN double hélice, réplication, transcription ARNm, traduction ribosomale, mutations, épigénétique), génétique mendélienne (hérédité, lois de Mendel, liaison génétique), biochimie (protéines, enzymes cinétique Michaelis-Menten, glucides, lipides, ATP), physiologie (systèmes nerveux, cardiovasculaire, immunitaire, endocrinien), écologie (biomes, chaînes alimentaires, cycles biogéochimiques), microbiologie (bactéries, virus, champignons, antibiotiques, résistance)."},
    "méthodologie":{"k":["méthodologie","recherche","rapport","mémoire","thèse","citation","bibliographie","plan","introduction","conclusion","exposé","présentation","plagiat","apa","ieee"],"v":"Méthodologie universitaire : structure rapport/mémoire (page de garde, résumé/abstract, introduction avec problématique, revue de littérature, méthodologie, résultats, discussion, conclusion, bibliographie, annexes). Normes de citation : APA 7e éd., IEEE, Vancouver, Harvard. Recherche documentaire : Google Scholar, ResearchGate, IEEE Xplore, Scopus, Web of Science. Rédaction scientifique : objectivité, précision, concision, éviter plagiat (Turnitin, iThenticate). Présentation orale : structure 3 actes, gestion du temps, support visuel (règle 10-20-30), gestion du trac."},
    "pédagogie":{"k":["cours","pédagogie","enseignement","examen","évaluation","programme","syllabus","bloom","moodle","travaux dirigés","classe inversée","apprentissage par problèmes"],"v":"Pédagogie et ingénierie de formation : taxonomie de Bloom révisée (mémoriser, comprendre, appliquer, analyser, évaluer, créer), objectifs SMART, conception de séquences pédagogiques (situation d'entrée, développement, évaluation), méthodes actives (classe inversée, apprentissage par problèmes ABP, jeux sérieux, BYOD), évaluation formative vs sommative (QCM, portfolios, projets, soutenances, évaluation par les pairs), outils numériques (Moodle LMS, Wooclap, Kahoot, Padlet, Notion, GitHub Classroom), différenciation pédagogique, gestion de classe."},
}

def find_domain(text):
    r = text.lower()
    scores = {d: sum(1 for k in data["k"] if k in r) for d, data in KB.items()}
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else None

def get_file_ctx(conv_id, uid):
    if not conv_id: return ""
    with get_db() as db:
        files = db.execute("SELECT original_name, content_preview, file_type FROM uploaded_files WHERE conversation_id=? AND user_id=? ORDER BY created_at DESC LIMIT 3",(conv_id, uid)).fetchall()
    if not files: return ""
    ctx = "\n\n📎 **Fichiers joints à cette conversation :**\n"
    for f in files:
        ctx += f"\n**{f['original_name']}** ({f['file_type']}) :\n{f['content_preview'][:800]}\n"
    return ctx

def detect_fonc(req, role):
    r = req.lower()
    if any(w in r for w in ["résume","résumé","synthèse","synthétise","récapitule","résumer","synthétiser"]): return "resume","regime1"
    if any(w in r for w in ["corrige","améliore","reformule","révise","amélioration","correction","corriger","améliorer"]): return "redaction","regime1"
    if any(w in r for w in ["génère","génère","rédige","crée","élabore","liste","propose","écris un","écris une"]): return "generation","regime1"
    if any(w in r for w in ["dois-je","devrais-je","oriente","choisir entre","quel master","quelle filière","quel module","recommande-moi","me conseiller"]): return ("decision_prof" if role in STAFF else "decision"),"regime2"
    if role in STAFF:
        if any(w in r for w in ["plan de cours","sujet d'examen","fiche pédagogique","séquence","objectif bloom"]): return "pedagogique","regime1"
        if any(w in r for w in ["compte rendu","procès-verbal","note de service","rapport administratif"]): return "administratif","regime1"
    return "question","regime1"

def gen_response(req, fonc, role, conv_id=None, uid=None):
    file_ctx = get_file_ctx(conv_id, uid) if conv_id else ""
    has_file = bool(file_ctx)
    domain = find_domain(req)
    base = KB[domain]["v"] if domain else ""
    is_staff = role in STAFF
    rl = ROLES.get(role,{}).get('label','Utilisateur')

    if fonc == "resume":
        if has_file: return f"📄 **Résumé basé sur le fichier joint**\n{file_ctx}\n\n**Synthèse :**\nSur la base du contenu extrait, voici les points essentiels :\n• Identifiez les concepts principaux du document\n• Relevez les arguments, données ou résultats clés\n• Notez les conclusions et recommandations\n\n💡 *Posez une question précise sur le document pour une analyse ciblée.*"
        if base: return f"📄 **Résumé — {domain.replace('_',' ').title()}**\n\n{base[:350]}...\n\n**Points clés à retenir :**\n• Concepts fondamentaux et définitions\n• Applications pratiques dans votre domaine\n• Liens avec d'autres disciplines\n\n💡 *Joignez un fichier via 📎 pour un résumé personnalisé.*"
        return "📄 **Résumé**\n\nPrécisez le sujet à résumer, ou joignez un fichier via le bouton 📎."

    if fonc == "redaction":
        if is_staff: return f"✏️ **Aide à la rédaction — {rl}**\n\n**Documents professionnels et académiques :**\n• **Structure** : Objet / Contexte / Corps articulé / Conclusion / Références\n• **Ton** : neutre, précis, objectif, adapté à l'audience\n• **Mise en forme** : titres numérotés, paragraphes courts, listes pour les étapes\n\n**Pour rapports de recherche :**\n• Introduction : contexte, problématique, plan\n• Revue de littérature : sources académiques référencées (APA/IEEE)\n• Méthodologie : démarche reproductible\n• Résultats et discussion : rigueur, nuance\n• Conclusion : réponse à la problématique + perspectives\n\n💡 *Partagez votre texte pour une correction personnalisée.*"
        return "✏️ **Aide à la rédaction**\n\n**Structure pour travaux académiques :**\n• **Introduction** : contexte + problématique + annonce du plan\n• **Développement** : 2–3 parties avec exemples et transitions\n• **Conclusion** : synthèse + réponse + ouverture\n\n**Conseils :**\n• Connecteurs logiques : ainsi, en effet, par conséquent, cependant, néanmoins\n• Variez la longueur des phrases — évitez les répétitions\n• Vérifiez orthographe, ponctuation et cohérence\n• Citez vos sources (APA ou IEEE selon la discipline)\n\n💡 *Soumettez votre texte pour une correction personnalisée.*"

    if fonc == "generation":
        if is_staff and domain == "pédagogie": return f"📝 **Génération pédagogique — {rl}**\n\n**Plan de cours suggéré (taxonomie de Bloom) :**\n\n🎯 **Objectifs :** À la fin de la séance, l'étudiant sera capable de :\n• Mémoriser : définir les concepts clés\n• Comprendre : expliquer les mécanismes\n• Appliquer : résoudre des exercices\n• Analyser : identifier des problèmes concrets\n\n📅 **Déroulement (2h) :**\n• 10 min : mise en situation / rappel prérequis\n• 60 min : cours structuré avec exemples\n• 30 min : exercices guidés puis autonomes\n• 20 min : correction collective et synthèse\n\n📊 **Évaluation :** QCM (30%) + exercice pratique (70%)\n\n💡 *Précisez le module et le niveau pour un plan personnalisé.*"
        if base: return f"📝 **Contenu généré — {domain.replace('_',' ').title() if domain else 'Général'}**\n\n{base}\n\n**Points complémentaires :**\n• Ce domaine est fondamental dans votre cursus à l'ENSA\n• Des connexions interdisciplinaires enrichissent la maîtrise du sujet\n• La pratique régulière (exercices, projets) consolide les apprentissages\n\n💡 *Contenu à des fins pédagogiques — croisez avec vos supports de cours officiels.*"
        return "📝 **Génération de contenu**\n\nPrécisez ce que vous souhaitez générer.\n*Exemples : \"Génère une explication sur les arbres AVL\", \"Crée un plan de cours sur la thermodynamique\", \"Liste les types d'attaques réseau\".*"

    if fonc in ("decision","decision_prof"):
        r2 = "🔴 **Assistance à la décision — RÉGIME 2 (Art. 22 RGPD)**\n\n⚠️ Cette fonctionnalité relève du Régime 2. Toute suggestion sera soumise à **validation humaine obligatoire** avant communication.\n\n"
        if is_staff: r2 += "**Éléments d'orientation (personnel) :**\n• Consultez les textes réglementaires et le règlement intérieur en vigueur\n• Échangez avec la Direction et les collègues référents\n• Vérifiez les circulaires ministérielles applicables\n• Sollicitez l'avis du service juridique ou RH si nécessaire\n\n"
        else: r2 += "**Éléments d'orientation (étudiant) :**\n• Analysez vos aptitudes, centres d'intérêt et projet professionnel\n• Consultez le programme officiel des formations disponibles à l'ENSA\n• Échangez avec un conseiller pédagogique ou un enseignant référent\n• Explorez les débouchés professionnels actuels dans votre secteur cible\n\n"
        r2 += "⏳ *Votre demande a été enregistrée et sera examinée par un responsable habilité sous 5 jours ouvrés.*"
        return r2

    if fonc == "pedagogique": return f"📚 **Support pédagogique — {rl}**\n\n**Recommandations pour la conception de votre cours :**\n• Définissez des objectifs mesurables (taxonomie de Bloom)\n• Alternez apports théoriques et activités pratiques (ratio conseillé 60/40)\n• Prévoyez des évaluations formatives (quiz, questions, mini-exercices en cours)\n• Différenciez selon les niveaux de vos étudiants\n\n**Outils numériques recommandés :**\n• **Moodle** : dépôt de cours, devoirs, quiz en ligne\n• **Wooclap / Kahoot** : interaction en classe en temps réel\n• **GitHub Classroom** : pour les projets informatiques\n• **Padlet** : brainstorming et travail collaboratif\n\n💡 *Précisez le module, le niveau et l'objectif pour une aide plus ciblée.*"

    if fonc == "administratif": return "🏛️ **Assistance administrative**\n\n**Structure document institutionnel :**\n• **En-tête** : logo ENSA, service émetteur, date, référence, destinataire\n• **Objet** : formulé clairement en 1 ligne\n• **Corps** : contexte → faits → décisions → actions → délais\n• **Conclusion** : récapitulatif et prochaines étapes\n• **Signature** : fonction, nom, visa hiérarchique\n\n**Points d'attention :**\n• Ton neutre, formel et précis — évitez l'ambiguïté\n• Pas de données personnelles nominatives sans base légale\n• Archivez selon la politique de conservation de l'ENSA\n\n💡 *Partagez votre ébauche pour une relecture personnalisée.*"

    # Réponse question générale
    if has_file: return f"💬 **Réponse basée sur le fichier joint**\n{file_ctx}\n\n{'**Analyse :** ' + base if base else '**Analyse :** Sur la base du contenu extrait, posez une question précise sur le document pour obtenir une analyse ciblée.'}\n\n---\n💡 *Basé sur le document joint. Pour d'autres questions, utilisez une nouvelle conversation.*"

    if base:
        extra = "\n\n**Pour aller plus loin :**\n• Littérature académique : Google Scholar, IEEE Xplore, ResearchGate\n• Documentation officielle et normes\n• Conférences spécialisées" if is_staff else "\n\n**Pour approfondir :**\n• Vos supports de cours officiels\n• Exercices pratiques de consolidation\n• Discussion avec votre enseignant référent"
        return f"💬 **Réponse — {domain.replace('_',' ').title()}**\n\n{base}{extra}\n\n---\n💡 *Réponse générée automatiquement{'.' if not is_staff else '. Croisez avec des sources primaires pour tout usage professionnel.'} Vérifiez les informations importantes auprès de sources officielles.*"

    if is_staff: return f"💬 **{rl}** — Je peux vous assister sur :\n\n• 📚 **Pédagogie** : plans de cours, objectifs, évaluation\n• 🔬 **Recherche** : synthèse, rédaction académique, méthodologie\n• 🏛️ **Administration** : rédaction de documents institutionnels\n• 💻 **Toutes les disciplines scientifiques et techniques**\n• 📎 **Fichiers joints** : posez vos questions sur vos documents\n\nPosez votre question ou choisissez une fonctionnalité."
    return "💬 Je suis le système IA de l'ENSA Béni Mellal. Je peux vous aider sur :\n\n📐 **Sciences fondamentales** : Mathématiques, Physique, Chimie, Biologie\n💻 **Informatique & IA** : Programmation, Algorithmes, IA, Cybersécurité, Réseaux, BDD\n⚖️ **Droit & Éthique** : RGPD, Droit du numérique, Éthique IA\n📊 **Gestion & Économie** : Management, Finance, Marketing\n✍️ **Méthodes** : Rédaction académique, Méthodologie de recherche\n📎 **Fichiers** : Joignez un document pour poser des questions dessus\n\nPosez votre question ou utilisez les fonctionnalités ci-dessus !"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL, role TEXT DEFAULT 'etudiant',
            filiere TEXT DEFAULT '', niveau TEXT DEFAULT '',
            consent_given INTEGER DEFAULT 0, consent_date TEXT,
            created_at TEXT DEFAULT (datetime('now')))""")
        db.execute("""CREATE TABLE IF NOT EXISTS conversations (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
            title TEXT NOT NULL, fonctionnalite TEXT DEFAULT 'question',
            created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(user_id) REFERENCES users(id))""")
        db.execute("""CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT, conversation_id INTEGER NOT NULL,
            role TEXT NOT NULL, content TEXT NOT NULL, regime TEXT DEFAULT 'regime1',
            validation_required INTEGER DEFAULT 0, validated_by TEXT, validated_at TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(conversation_id) REFERENCES conversations(id))""")
        db.execute("""CREATE TABLE IF NOT EXISTS uploaded_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
            conversation_id INTEGER, filename TEXT NOT NULL, original_name TEXT NOT NULL,
            file_type TEXT NOT NULL, content_preview TEXT, created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(user_id) REFERENCES users(id))""")
        db.execute("""CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
            action TEXT NOT NULL, detail TEXT, ip_address TEXT,
            timestamp TEXT DEFAULT (datetime('now')))""")
        db.execute("""CREATE TABLE IF NOT EXISTS contestations (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
            message_id INTEGER, motif TEXT NOT NULL, statut TEXT DEFAULT 'en_cours',
            created_at TEXT DEFAULT (datetime('now')))""")
        db.execute("DELETE FROM audit_logs WHERE timestamp < datetime('now', '-12 months')")
        db.execute("DELETE FROM messages WHERE conversation_id IN (SELECT id FROM conversations WHERE updated_at < datetime('now', '-24 months'))")
        db.execute("DELETE FROM conversations WHERE updated_at < datetime('now', '-24 months')")
        admin_h = hashlib.sha256("Admin@ENSA2025!".encode()).hexdigest()
        db.execute("INSERT OR IGNORE INTO users (username, password_hash, role, consent_given, consent_date) VALUES (?,?,'admin',1,datetime('now'))", ("admin", admin_h))
        db.commit()
    logger.info("DB init OK — purge auto exécutée")

def log_action(uid, action, detail="", ip=""):
    with get_db() as db:
        db.execute("INSERT INTO audit_logs (user_id,action,detail,ip_address) VALUES (?,?,?,?)", (uid,action,detail,ip))
        db.commit()

def login_required(f):
    @wraps(f)
    def d(*a,**k):
        if 'user_id' not in session: return redirect(url_for('login'))
        return f(*a,**k)
    return d

def consent_required(f):
    @wraps(f)
    def d(*a,**k):
        if not session.get('consent_given'): return redirect(url_for('consent'))
        return f(*a,**k)
    return d

@app.route('/')
def index(): return redirect(url_for('chat') if 'user_id' in session else url_for('login'))

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        un = request.form.get('username','').strip()
        ph = hashlib.sha256(request.form.get('password','').encode()).hexdigest()
        with get_db() as db:
            user = db.execute("SELECT * FROM users WHERE username=? AND password_hash=?",(un,ph)).fetchone()
        if user:
            session.permanent = True
            session.update({'user_id':user['id'],'username':user['username'],'role':user['role'],'consent_given':bool(user['consent_given'])})
            log_action(user['id'],"CONNEXION",user['role'],request.remote_addr)
            return redirect(url_for('consent') if not user['consent_given'] else url_for('chat'))
        log_action(None,"ECHEC_CONNEXION",un,request.remote_addr)
        return render_template('login.html', error="Identifiants incorrects.")
    return render_template('login.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        un = request.form.get('username','').strip()
        pw = request.form.get('password','')
        pc = request.form.get('password_confirm','')
        role = request.form.get('role','etudiant')
        filiere = request.form.get('filiere','')
        niveau = request.form.get('niveau','')
        if role not in ('etudiant','prof','admin_ecole'): return render_template('register.html',error="Rôle invalide.",roles=ROLES)
        if len(un)<3: return render_template('register.html',error="Identifiant trop court (min. 3).",roles=ROLES)
        if pw!=pc: return render_template('register.html',error="Mots de passe différents.",roles=ROLES)
        if len(pw)<8: return render_template('register.html',error="Mot de passe trop court (min. 8).",roles=ROLES)
        try:
            with get_db() as db:
                db.execute("INSERT INTO users (username,password_hash,role,filiere,niveau) VALUES (?,?,?,?,?)",(un,hashlib.sha256(pw.encode()).hexdigest(),role,filiere,niveau))
                db.commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return render_template('register.html',error="Identifiant déjà utilisé.",roles=ROLES)
    return render_template('register.html',roles=ROLES)

@app.route('/consent', methods=['GET','POST'])
@login_required
def consent():
    if request.method=='POST' and request.form.get('consent')=='yes':
        with get_db() as db:
            db.execute("UPDATE users SET consent_given=1, consent_date=? WHERE id=?",(datetime.now().isoformat(),session['user_id']))
            db.commit()
        session['consent_given'] = True
        log_action(session['user_id'],"CONSENTEMENT",session.get('role'),request.remote_addr)
        return redirect(url_for('chat'))
    role = session.get('role','etudiant')
    return render_template('consent.html', droits=DROITS.get(role,DROITS['etudiant']), role=role, role_info=ROLES.get(role,{}))

@app.route('/chat')
@app.route('/chat/<int:conv_id>')
@login_required
@consent_required
def chat(conv_id=None):
    role = session.get('role','etudiant')
    with get_db() as db:
        convs = db.execute("SELECT * FROM conversations WHERE user_id=? ORDER BY updated_at DESC",(session['user_id'],)).fetchall()
        msgs, cur, files = [], None, []
        if conv_id:
            cur = db.execute("SELECT * FROM conversations WHERE id=? AND user_id=?",(conv_id,session['user_id'])).fetchone()
            if cur:
                msgs = db.execute("SELECT * FROM messages WHERE conversation_id=? ORDER BY created_at ASC",(conv_id,)).fetchall()
                files = db.execute("SELECT * FROM uploaded_files WHERE conversation_id=? AND user_id=?",(conv_id,session['user_id'])).fetchall()
    return render_template('chat.html', conversations=convs, messages=msgs, current_conv=cur,
        conv_id=conv_id, conv_files=files, is_staff=(role in STAFF),
        role=role, role_info=ROLES.get(role,{}), droits_role=DROITS.get(role,[]))

@app.route('/api/send', methods=['POST'])
@login_required
@consent_required
def api_send():
    data = request.get_json()
    req = (data.get('message','') or '').strip()
    conv_id = data.get('conv_id')
    fonc = data.get('fonctionnalite','question')
    role = session.get('role','etudiant')
    if not req: return jsonify({'error':'Message vide'}),400
    if len(req)>2000: return jsonify({'error':'Message trop long (max 2000 car.)'}),400
    det, tp = detect_sensitive(req)
    if det:
        log_action(session['user_id'],"DONNEE_SENSIBLE",tp,request.remote_addr)
        return jsonify({'error':f"⚠️ Votre message semble contenir un(e) {tp}. La saisie de données personnelles est interdite (Art. 5.1.c RGPD). Reformulez sans données personnelles."}),400
    df, regime = detect_fonc(req, role)
    if fonc == 'question': fonc, regime_f = df, regime
    else: regime_f = 'regime2' if fonc in ('decision','decision_prof') else 'regime1'
    with get_db() as db:
        if not conv_id:
            db.execute("INSERT INTO conversations (user_id,title,fonctionnalite) VALUES (?,?,?)",(session['user_id'],req[:50]+('…' if len(req)>50 else ''),fonc))
            db.commit()
            conv_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        else:
            if not db.execute("SELECT id FROM conversations WHERE id=? AND user_id=?",(conv_id,session['user_id'])).fetchone():
                return jsonify({'error':'Conversation introuvable'}),404
            db.execute("UPDATE conversations SET updated_at=datetime('now') WHERE id=?",(conv_id,))
        db.execute("INSERT INTO messages (conversation_id,role,content,regime) VALUES (?,'user',?,?)",(conv_id,req,regime_f))
        rep = gen_response(req, fonc, role, conv_id, session['user_id'])
        vr = 1 if regime_f=='regime2' else 0
        db.execute("INSERT INTO messages (conversation_id,role,content,regime,validation_required) VALUES (?,'assistant',?,?,?)",(conv_id,rep,regime_f,vr))
        mid = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        db.commit()
    log_action(session['user_id'],"MSG",f"conv:{conv_id} fonc:{fonc} r:{regime_f} role:{role}",request.remote_addr)
    return jsonify({'response':rep,'conv_id':conv_id,'regime':regime_f,'fonctionnalite':fonc,'validation_required':bool(vr),'msg_id':mid})

@app.route('/api/upload', methods=['POST'])
@login_required
@consent_required
def api_upload():
    if 'file' not in request.files: return jsonify({'error':'Aucun fichier'}),400
    f = request.files['file']
    conv_id = request.form.get('conv_id', type=int)
    if not f or f.filename=='': return jsonify({'error':'Fichier invalide'}),400
    if not allowed_file(f.filename): return jsonify({'error':f"Format non autorisé. Formats acceptés : {', '.join(ALLOWED_EXT)}"}),400
    fn = secure_filename(f.filename)
    ext = fn.rsplit('.',1)[1].lower()
    uname = f"{session['user_id']}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{fn}"
    fp = os.path.join(app.config['UPLOAD_FOLDER'], uname)
    f.save(fp)
    preview = ""
    try:
        if ext in ('txt','md','csv'):
            with open(fp,'r',encoding='utf-8',errors='ignore') as fh: preview = fh.read(3000)
        elif ext == 'pdf':
            try:
                import subprocess
                r = subprocess.run(['pdftotext',fp,'-'],capture_output=True,text=True,timeout=10)
                preview = r.stdout[:3000] if r.returncode==0 else "[PDF joint — décrivez son contenu pour poser des questions dessus.]"
            except: preview = "[PDF joint — posez vos questions en décrivant le sujet du document.]"
        elif ext in ('docx','doc'): preview = "[Document Word joint — posez vos questions sur son contenu.]"
    except Exception as e: preview = f"[Fichier joint : {str(e)[:80]}]"
    with get_db() as db:
        if not conv_id:
            db.execute("INSERT INTO conversations (user_id,title,fonctionnalite) VALUES (?,?,?)",(session['user_id'],f"📎 {fn[:40]}","resume"))
            db.commit()
            conv_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        db.execute("INSERT INTO uploaded_files (user_id,conversation_id,filename,original_name,file_type,content_preview) VALUES (?,?,?,?,?,?)",(session['user_id'],conv_id,uname,f.filename,ext,preview))
        db.commit()
    log_action(session['user_id'],"UPLOAD",f"{fn} conv:{conv_id}")
    return jsonify({'ok':True,'conv_id':conv_id,'filename':f.filename,'preview':preview[:200]+'…' if len(preview)>200 else preview})

@app.route('/api/conversations')
@login_required
def api_conversations():
    with get_db() as db:
        convs = db.execute("SELECT id,title,fonctionnalite,updated_at FROM conversations WHERE user_id=? ORDER BY updated_at DESC",(session['user_id'],)).fetchall()
    return jsonify([dict(c) for c in convs])

@app.route('/api/conversation/<int:cid>', methods=['DELETE'])
@login_required
def api_del_conv(cid):
    with get_db() as db:
        db.execute("DELETE FROM messages WHERE conversation_id=?",(cid,))
        db.execute("DELETE FROM uploaded_files WHERE conversation_id=?",(cid,))
        db.execute("DELETE FROM conversations WHERE id=? AND user_id=?",(cid,session['user_id']))
        db.commit()
    log_action(session['user_id'],"CONV_DEL",f"conv:{cid} Art.17")
    return jsonify({'ok':True})

@app.route('/droits', methods=['GET','POST'])
@login_required
def droits():
    role = session.get('role','etudiant')
    if request.method=='POST':
        d = request.form.get('droit')
        if d=='effacement':
            with get_db() as db:
                db.execute("DELETE FROM messages WHERE conversation_id IN (SELECT id FROM conversations WHERE user_id=?)",(session['user_id'],))
                db.execute("DELETE FROM uploaded_files WHERE user_id=?",(session['user_id'],))
                db.execute("DELETE FROM conversations WHERE user_id=?",(session['user_id'],))
                db.commit()
            log_action(session['user_id'],"EFFACEMENT","Art.17")
            flash("✅ Toutes vos données ont été supprimées (Art. 17 RGPD).","success")
        elif d=='contestation':
            m = request.form.get('motif','')
            with get_db() as db:
                db.execute("INSERT INTO contestations (user_id,motif) VALUES (?,?)",(session['user_id'],m))
                db.commit()
            flash("✅ Contestation enregistrée. Réponse sous 5 jours ouvrés (Art. 22 RGPD).","success")
    with get_db() as db:
        nc = db.execute("SELECT COUNT(*) as n FROM conversations WHERE user_id=?",(session['user_id'],)).fetchone()['n']
        nm = db.execute("SELECT COUNT(*) as n FROM messages WHERE conversation_id IN (SELECT id FROM conversations WHERE user_id=?)",(session['user_id'],)).fetchone()['n']
        nf = db.execute("SELECT COUNT(*) as n FROM uploaded_files WHERE user_id=?",(session['user_id'],)).fetchone()['n']
    return render_template('droits.html', nb_convs=nc, nb_msgs=nm, nb_files=nf, droits_role=DROITS.get(role,[]), role=role, role_info=ROLES.get(role,{}))

@app.route('/admin')
@login_required
def admin():
    if session.get('role')!='admin': return redirect(url_for('chat'))
    with get_db() as db:
        users = db.execute("SELECT id,username,role,consent_given,filiere,niveau,created_at FROM users").fetchall()
        logs = db.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 100").fetchall()
        pending = db.execute("SELECT c.*,u.username FROM contestations c JOIN users u ON c.user_id=u.id WHERE c.statut='en_cours'").fetchall()
        r2 = db.execute("SELECT m.*,conv.title,u.username,u.role as user_role FROM messages m JOIN conversations conv ON m.conversation_id=conv.id JOIN users u ON conv.user_id=u.id WHERE m.validation_required=1 AND m.validated_by IS NULL ORDER BY m.created_at DESC LIMIT 20").fetchall()
        stats = {
            'users': db.execute("SELECT COUNT(*) as n FROM users").fetchone()['n'],
            'etudiants': db.execute("SELECT COUNT(*) as n FROM users WHERE role='etudiant'").fetchone()['n'],
            'personnel': db.execute("SELECT COUNT(*) as n FROM users WHERE role IN ('prof','admin_ecole')").fetchone()['n'],
            'messages': db.execute("SELECT COUNT(*) as n FROM messages").fetchone()['n'],
            'contestations': db.execute("SELECT COUNT(*) as n FROM contestations WHERE statut='en_cours'").fetchone()['n'],
            'regime2_pending': db.execute("SELECT COUNT(*) as n FROM messages WHERE validation_required=1 AND validated_by IS NULL").fetchone()['n'],
            'fichiers': db.execute("SELECT COUNT(*) as n FROM uploaded_files").fetchone()['n'],
        }
    return render_template('admin.html', users=users, logs=logs, pending=pending, regime2=r2, stats=stats, roles=ROLES)

@app.route('/admin/validate/<int:mid>', methods=['POST'])
@login_required
def validate_msg(mid):
    if session.get('role')!='admin': return jsonify({'error':'Accès refusé'}),403
    with get_db() as db:
        db.execute("UPDATE messages SET validated_by=?,validated_at=datetime('now') WHERE id=?",(session['username'],mid))
        db.commit()
        msg = db.execute("SELECT content FROM messages WHERE id=?",(mid,)).fetchone()
    log_action(session['user_id'],"VALID_R2",f"msg:{mid}")
    return jsonify({'ok':True,'content':msg['content'] if msg else ''})

@app.route('/logout')
def logout():
    uid = session.get('user_id')
    if uid: log_action(uid,"DECONNEXION","")
    session.clear()
    return redirect(url_for('login'))

if __name__=='__main__':
    init_db()
    logger.info("=== Système IA ENSA Béni Mellal v3 ===")
    app.run(debug=True, host='0.0.0.0', port=5000)
