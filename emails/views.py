from django.http import JsonResponse
from datetime import datetime, timedelta
import os
import base64
import re
import requests
from urllib.parse import urlparse
from django.conf import settings
from django.shortcuts import render
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from supabase import create_client, Client


# Supabase Client
url = settings.URL
key = settings.KEY
supabase: Client = create_client(url, key)

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Google Safe Browsing API
SAFE_BROWSING_API_KEY = settings.SAFE_BROWSING_API_KEY
SAFE_BROWSING_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"


def authenticate_gmail():
    """Authenticate Gmail API and return service instance."""
    creds = None
    token_path = "token.json"

    # Load existing token if available
    if os.path.exists(token_path):
        creds = Credentials.from_authorized_user_file(token_path, SCOPES)

    # If token is invalid or doesn't exist, get a new one
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(
                port=8080, access_type='offline', prompt='consent')

        # Save credentials for future use
        with open(token_path, 'w') as token:
            token.write(creds.to_json())

    # Create Gmail API service
    return build('gmail', 'v1', credentials=creds)


def extract_urls(text):
    """Extract URLs from a given text using regex."""
    url_pattern = r"https?://[^\s]+"
    return re.findall(url_pattern, text)


def check_url_safety(url):
    payload = {
        "client": {
            "clientId": "PhishingEmailDetector",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "UNWANTED_SOFTWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    headers = {"Content-Type": "application/json"}
    response = requests.post(SAFE_BROWSING_URL, json=payload, headers=headers)

    if response.status_code == 200:
        result = response.json()
        return result.get("matches", [])  # If empty, no threats detected
    else:
        print(f"Error checking URL ({url}): {response.status_code}")
        return None


def store_email_in_supabase(sender, subject, body, is_phishing):
    """Store unique email details in Supabase."""
    try:
        # Check if an email with the same sender, subject, and body already exists
        response = supabase.table("email_details").select("id") \
            .eq("sender", sender).eq("subject", subject).eq("body", body).execute()

        if response.data:  # If an email with the same details exists, skip insertion
            print("Duplicate email detected. Skipping insertion.")
            return

        # Insert only if it's unique
        supabase.table("email_details").insert({
            "sender": sender,
            "subject": subject,
            "body": body,
            "is_phishing": is_phishing
        }).execute()

    except Exception as e:
        print(f"Error storing email in Supabase: {e}")


def get_all_emails(service):
    """Fetch emails and store phishing details in Supabase."""
    try:
        results = service.users().messages().list(userId="me", maxResults=10).execute()
        messages = results.get("messages", [])

        if not messages:
            print("No messages found.")
            return

        for msg in messages:
            msg_id = msg["id"]
            message = service.users().messages().get(userId="me", id=msg_id).execute()
            headers = message.get("payload", {}).get("headers", [])

            subject = next(
                (h["value"] for h in headers if h["name"] == "Subject"), "No Subject")
            sender = next(
                (h["value"] for h in headers if h["name"] == "From"), "Unknown Sender")

            # Decode email body
            body = ""
            try:
                if "parts" in message["payload"]:
                    for part in message["payload"]["parts"]:
                        if part["mimeType"] == "text/plain" and "body" in part:
                            body = base64.urlsafe_b64decode(
                                part["body"]["data"]).decode(errors="ignore")
            except Exception as decode_error:
                print(f"Error decoding email body: {decode_error}")

            # Extract URLs
            urls = extract_urls(body)
            phishing_detected = any(check_url_safety(url) for url in urls)

            # Rules for phishing detection
            # Rule 1: Check for phishing keywords in the email body
            phishing_keywords = [
                "prize", "click here", "urgent", "update your account",
                "verify your identity", "password reset", "suspicious activity",
                "account suspended", "immediate action required", "winning",
                "congratulations", "limited time offer", "security alert"
            ]
            keyword_detected = any(word in body.lower()
                                   for word in phishing_keywords)

            # Rule 2: Check for suspicious sender domains
            suspicious_domains = [
                "freegiftcards.com", "secure-login.net", "account-update.com",
                "verify-account.com", "password-reset.net"
            ]
            sender_domain = sender.split("@")[-1]
            suspicious_sender = sender_domain in suspicious_domains

            # Rule 3: Check for mismatched URLs (e.g., text says one thing, link goes elsewhere)
            mismatched_links = False
            for link in urls:
                parsed_link = urlparse(link)
                if parsed_link.netloc not in body:
                    mismatched_links = True
                    break

            # Rule 4: Check for urgency or fear-inducing language in the subject
            urgency_keywords = ["urgent", "immediate",
                                "action required", "last chance"]
            urgency_detected = any(word in subject.lower()
                                   for word in urgency_keywords)

            # Rule 5: Check for generic greetings (e.g., "Dear Customer")
            generic_greetings = ["dear customer",
                                 "dear user", "dear valued member"]
            generic_greeting_detected = any(
                greeting in body.lower() for greeting in generic_greetings)

            # Rule 6: Check for suspicious link domains
            suspicious_link_detected = False
            for link in urls:
                parsed_link = urlparse(link)
                if any(suspicious_domain in parsed_link.netloc for suspicious_domain in suspicious_domains):
                    suspicious_link_detected = True
                    break

            # Final phishing status
            is_phishing = (
                phishing_detected or
                keyword_detected or
                suspicious_sender or
                mismatched_links or
                urgency_detected or
                generic_greeting_detected or
                suspicious_link_detected
            )

            # Store email details in Supabase
            store_email_in_supabase(sender, subject, body, is_phishing)

    except Exception as e:
        print(f"Error fetching emails: {e}")


def home_view(request):
    gmail_service = authenticate_gmail()
    get_all_emails(gmail_service)
    response = supabase.table("email_details").select(
        "*").eq("is_phishing", True).execute()

    if response.data:
        # Use a set to store unique (sender, subject, content) tuples
        unique_emails = {}
        for email in response.data:
            key = (email["sender"], email["subject"],
                   email["body"])  # Unique key

            # Extract only the name from "Name <email@example.com>"
            sender_name = email["sender"].split(
                " <")[0] if " <" in email["sender"] else email["sender"]

            # Store cleaned sender name in the email dictionary
            email["sender_name"] = sender_name

            if key not in unique_emails:
                unique_emails[key] = email  # Store only unique emails

        emails = unique_emails.values()
    else:
        emails = []

    return render(request, "dashboard.html", {"emails": emails})


def check_new_alerts(request):
    """Check for new phishing emails in the last 10 minutes."""
    ten_minutes_ago = datetime.utcnow() - timedelta(minutes=10)

    # Get count of new phishing emails detected in the last 10 minutes
    response = supabase.table("email_details").select(
        "*").eq("is_phishing", True).gte("created_at", ten_minutes_ago.isoformat()).execute()

    new_phishing_count = len(response.data) if response.data else 0
    return JsonResponse({"new_phishing_count": new_phishing_count})
