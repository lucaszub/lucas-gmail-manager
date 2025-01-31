# Gestionnaire de Mails avec Gmail, Azure Function et OpenAI

## Description
Ce projet est une Azure Function permettant d'automatiser la gestion des emails Gmail en utilisant l'API Gmail et l'intelligence artificielle d'OpenAI. L'objectif est d'extraire les informations clés des emails reçus et d'effectuer des actions spécifiques en fonction du contenu.

## Fonctionnalités
- Connexion à l'API Gmail pour récupérer les emails.
- Analyse du contenu des emails avec OpenAI (GPT).
- Traitement et catégorisation automatique des emails.
- Envoi de réponses automatisées basées sur l'analyse.
- Intégration avec Azure Functions pour exécuter le script de manière planifiée.

## Prérequis
Avant d'exécuter ce projet, assurez-vous d'avoir :
- Un compte Google avec accès à l'API Gmail (OAuth 2.0 configuré).
- Une instance Azure Function configurée.
- Une clé API OpenAI.
- Python installé (version compatible avec Azure Functions).

## Installation
1. **Cloner le projet**
```bash
git clone https://github.com/votre-repo.git
cd votre-repo
```

2. **Installer les dépendances**
```bash
pip install -r requirements.txt
```

3. **Configurer les variables d'environnement**
Créer un fichier `.env` et ajouter :
```env
GMAIL_CLIENT_ID="votre_client_id"
GMAIL_CLIENT_SECRET="votre_client_secret"
GMAIL_REFRESH_TOKEN="votre_refresh_token"
OPENAI_API_KEY="votre_openai_api_key"
AZURE_FUNCTION_URL="votre_url_azure_function"
```

## Déploiement sur Azure Functions
1. **Se connecter à Azure**
```bash
az login
```
2. **Créer une Function App**
```bash
az functionapp create --resource-group MonGroupe --consumption-plan-location westeurope --runtime python --functions-version 4 --name NomDeLaFunction --storage-account MonStorage
```
3. **Déployer le code**
```bash
func azure functionapp publish NomDeLaFunction
```

## Utilisation
- La fonction s'exécute périodiquement pour analyser les emails.
- OpenAI est utilisé pour générer des résumés et des réponses.
- Les actions peuvent être configurées selon les besoins.

## Améliorations futures
- Amélioration du filtrage et du tri des emails.
- Ajout d'une interface web pour la gestion des emails traités.
- Intégration avec d'autres services cloud.

## Auteur
Lucas Zubiarrain


