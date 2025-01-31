import logging
import json
import openai
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import base64
from bs4 import BeautifulSoup
import azure.functions as func

# Configuration du logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constantes
KEY_VAULT_URL = "https://openai-api-key.vault.azure.net/"
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/gmail.modify']
OUTPUT_JSON_FILE = "emails_summary.json"

CATEGORIES = [
    "Urgent et administration et travail",
    "Facture et finance",
    "Newsletter et promotions",
    "Réseaux sociaux"
]

def get_secrets_from_key_vault():
    """Récupère les secrets depuis Azure Key Vault."""
    try:
        logger.info("Récupération des secrets depuis Azure Key Vault.")
        credential = DefaultAzureCredential()
        client = SecretClient(vault_url=KEY_VAULT_URL, credential=credential)
        
        credentials_secret = client.get_secret("GMAIL-CREDENTIALS")
        token_secret = client.get_secret("token")
        openai_key_secret = client.get_secret("OPENAI-API-KEY")
        
        credentials = json.loads(credentials_secret.value)
        token = json.loads(token_secret.value)
        openai_api_key = openai_key_secret.value
        
        logger.info("Secrets récupérés avec succès.")
        return credentials, token, openai_api_key
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des secrets: {str(e)}")
        raise

def initialize_gmail_credentials(token):
    """Initialise et actualise les credentials Gmail."""
    logger.info("Initialisation des credentials Gmail.")
    creds = Credentials(
        token=token["token"],
        refresh_token=token["refresh_token"],
        client_id=token["client_id"],
        client_secret=token["client_secret"],
        token_uri=token["token_uri"]
    )
    
    if creds.expired and creds.refresh_token:
        logger.info("Les credentials ont expiré. Rafraîchissement du token.")
        creds.refresh(Request())
    
    logger.info("Credentials Gmail initialisés.")
    return creds

def get_unread_emails(service, max_results=10):
    """Récupère les e-mails de la boîte de réception."""
    try:
        logger.info("Récupération des e-mails non lus.")
        results = service.users().messages().list(userId='me', labelIds=['INBOX'], maxResults=max_results).execute()
        messages = results.get('messages', [])
        logger.info(f"{len(messages)} e-mail(s) non lu(s) récupéré(s).")
        return messages
    except HttpError as error:
        logger.error(f"Erreur lors de la récupération des e-mails: {str(error)}")
        return []

def extract_email_body(payload):
    """Extrait le corps du message (texte brut ou HTML)."""
    logger.debug("Extraction du corps de l'e-mail.")
    if 'parts' in payload:
        for part in payload['parts']:
            if part['mimeType'] == 'text/plain':
                data = part['body']['data']
                return base64.urlsafe_b64decode(data).decode('utf-8')
            elif part['mimeType'] == 'text/html':
                data = part['body']['data']
                html_content = base64.urlsafe_b64decode(data).decode('utf-8')
                soup = BeautifulSoup(html_content, "html.parser")
                return soup.get_text()
    else:
        if payload['mimeType'] == 'text/plain':
            data = payload['body']['data']
            return base64.urlsafe_b64decode(data).decode('utf-8')
        elif payload['mimeType'] == 'text/html':
            data = payload['body']['data']
            html_content = base64.urlsafe_b64decode(data).decode('utf-8')
            soup = BeautifulSoup(html_content, "html.parser")
            return soup.get_text()
    return ""

def extract_email_details(service, message_id):
    """Extrait les détails d'un e-mail (expéditeur, objet, corps)."""
    try:
        logger.info(f"Extraction des détails de l'e-mail {message_id}.")
        msg = service.users().messages().get(userId='me', id=message_id, format='full').execute()
        
        # Vérification si le payload existe
        payload = msg.get('payload', {})
        if not payload:
            logger.error(f"Aucune donnée payload trouvée pour l'e-mail {message_id}.")
            return None, None, None
        
        headers = payload.get('headers', [])
        if not headers:
            logger.error(f"Aucun en-tête trouvé pour l'e-mail {message_id}.")
            return None, None, None
        
        # Extraction de l'expéditeur et du sujet avec une gestion des erreurs
        sender = next((header['value'] for header in headers if header['name'] == 'From'), None)
        subject = next((header['value'] for header in headers if header['name'] == 'Subject'), None)
        
        if not sender or not subject:
            logger.error(f"Expéditeur ou objet manquant pour l'e-mail {message_id}.")
            return None, None, None
        
        # Extraction du corps de l'e-mail, avec une gestion des erreurs pour les e-mails sans corps
        body = extract_email_body(payload) if payload.get('body') else None
        if not body:
            logger.warning(f"Corps manquant ou vide pour l'e-mail {message_id}.")
            body = ""  # On assigne une chaîne vide si le corps est vide ou manquant
        
        logger.info(f"Expéditeur: {sender}, Objet: {subject}, Corps: {body[:50]}...")  # Affiche les premiers 50 caractères du corps
        return sender, subject, body
    
    except Exception as e:
        logger.error(f"Erreur lors de l'extraction des détails de l'e-mail {message_id}: {str(e)}")
        return None, None, None


def generate_email_summary(text):
    """Génère un résumé du texte avec GPT-3.5."""    
    prompt = f"Résumez ce texte en une phrase :\n{text}"
    try:
        logger.info("Génération du résumé de l'e-mail.")
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3
        )
        summary = response['choices'][0]['message']['content']
        logger.info("Résumé généré avec succès.")
        return summary
    except Exception as e:
        logger.error(f"Erreur lors de la génération du résumé: {str(e)}")
        return None

def detect_email_category(sender, subject, body):
    """Détecte la catégorie de l'e-mail en utilisant GPT-3.5."""
    
    # Vérification si le corps ou l'objet de l'e-mail est manquant
    if not body or not subject:
        logger.error(f"Corps ou objet manquant pour l'e-mail de {sender}. Classification comme 'Urgent et administration et travail'.")
        return "Urgent et administration et travail"  # Retourne la catégorie par défaut en cas de manque de données

    prompt = (
        "Vous êtes un assistant intelligent capable d'analyser les e-mails et de générer une catégorie pertinente basée sur leur contenu. "
        "Voici les informations d'un e-mail :\n"
        f"- Expéditeur : {sender}\n"
        f"- Objet : {subject}\n"
        f"- Contenu : {body}\n\n"
        "Veuillez déterminer la catégorie de cet e-mail parmi les suivantes :\n"
        "- Urgent et administration et travail\n"
        "- Facture et finance\n"
        "- Newsletter et promotions\n"
        "- Réseaux sociaux\n\n"
        "Retournez uniquement la catégorie correspondante "
        "Le résultat doit juste être le nom de la catégorie sans phrase.\n"
        "Si un email possele aliabdaal ou quelque chose comme ça email = newsletter\n"
        "Si une adresse e-mail finit par @gmail.com alors c'est un email Urgent et administration et travail.\n"
        "Si un email contient des phrases ou du texte sur l'argentine viza canada alors c'est Urgent et administration et travail.\n"
        "Si un réseau social est mentionné dans le contenu alors c'est un email Réseaux sociaux. exemple : Facebook, Twitter, Instagram, LinkedIn, etc. strava garmin\n"
    )
    
    try:
        logger.info(f"Détection de la catégorie pour l'e-mail de {sender}.")
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3
        )
        category = response['choices'][0]['message']['content']
        
        # Si aucune catégorie n'est trouvée ou que la catégorie est vide, on attribue "Urgent et administration et travail" par défaut
        if not category:
            logger.warning(f"Aucune catégorie détectée pour l'e-mail de {sender}. Attribution de 'Urgent et administration et travail'.")
            return "Urgent et administration et travail"

        logger.info(f"Catégorie détectée : {category}")
        return category
    
    except Exception as e:
        logger.error(f"Erreur lors de la détection de la catégorie: {str(e)}")
        return "Urgent et administration et travail"  # Retour par défaut en cas d'erreur


def create_label_if_not_exists(service, label_name):
    """Crée un label Gmail si celui-ci n'existe pas."""
    try:
        logger.info(f"Vérification de l'existence du label '{label_name}'.")
        labels = service.users().labels().list(userId='me').execute()
        label_names = [label['name'] for label in labels['labels']]
        
        if label_name in CATEGORIES and label_name not in label_names:
            label_object = {
                "name": label_name,
                "labelListVisibility": "labelShow",
                "messageListVisibility": "show"
            }
            service.users().labels().create(userId='me', body=label_object).execute()
            logger.info(f"Label '{label_name}' créé.")
        elif label_name not in CATEGORIES:
            logger.info(f"Le label '{label_name}' n'est pas dans les catégories autorisées.")
        else:
            logger.info(f"Le label '{label_name}' existe déjà.")
    except Exception as e:
        logger.error(f"Erreur lors de la création du label: {str(e)}")

def move_email_to_label(service, message_id, label_name):
    """Déplace l'e-mail vers un label spécifié."""  
    try:
        logger.info(f"Déplacement de l'e-mail {message_id} vers le label '{label_name}'.")
        label_info = service.users().labels().list(userId='me').execute()
        label_id = next((label['id'] for label in label_info['labels'] if label['name'] == label_name), None)
        
        if label_id:
            msg = service.users().messages().modify(
                userId='me',
                id=message_id,
                body={'addLabelIds': [label_id], 'removeLabelIds': ['INBOX']},
            ).execute()
            logger.info(f"E-mail {message_id} déplacé avec succès.")
        else:
            logger.warning(f"Label '{label_name}' non trouvé.")
    except Exception as e:
        logger.error(f"Erreur lors du déplacement de l'e-mail {message_id}: {str(e)}")

def save_to_json(data, filename):
    """Enregistre les données dans un fichier JSON."""  
    try:
        logger.info(f"Enregistrement des données dans le fichier {filename}.")
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=4)
        logger.info(f"Données enregistrées avec succès dans {filename}.")
    except Exception as e:
        logger.error(f"Erreur lors de l'enregistrement des données dans {filename}: {str(e)}")

def main(mytimer: func.TimerRequest) -> None:
    try:
        # Récupérer les secrets depuis Azure Key Vault
        credentials, token, openai_api_key = get_secrets_from_key_vault()
        
        # Configurer la clé API OpenAI
        openai.api_key = openai_api_key
        
        # Initialiser les credentials Gmail
        creds = initialize_gmail_credentials(token)
        
        if creds and creds.valid:
            # Créer un service Gmail
            service = build('gmail', 'v1', credentials=creds)
            
            # Récupérer les 1 derniers e-mails
            messages = get_unread_emails(service, max_results=10)
            
            if not messages:
                logger.info("Aucun e-mail non lu trouvé.")
            else:
                emails_data = []  # Liste pour stocker les données des e-mails
                
                for message in messages:
                    sender, subject, body = extract_email_details(service, message['id'])
                    category = detect_email_category(sender, subject, body)
                    
                    # Créer le label si nécessaire
                    create_label_if_not_exists(service, category)
                    
                    # Déplacer le message vers le label correspondant
                    move_email_to_label(service, message['id'], category)
                    
                    email_info = {
                        "email": sender,
                        "objet": subject,
                        "corps": body,
                        "categorie": category
                    }
                    emails_data.append(email_info)
                
                # Enregistrer les données dans un fichier JSON
                save_to_json(emails_data, OUTPUT_JSON_FILE)
    except Exception as e:
        logger.error(f"Erreur générale dans le processus: {str(e)}")
