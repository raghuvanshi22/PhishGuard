import email
from email.policy import default
import re
from phishguard.core.constants import SUSPICIOUS_KEYWORDS

class EmailExtractor:
    def __init__(self, raw_email: str):
        self.raw_email = raw_email
        self.msg = email.message_from_string(self.raw_email, policy=default)
        
    def _get_body(self) -> str:
        body = ""
        if self.msg.is_multipart():
            for part in self.msg.walk():
                ctype = part.get_content_type()
                cdispo = str(part.get('Content-Disposition'))
                if ctype == 'text/plain' and 'attachment' not in cdispo:
                    body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                elif ctype == 'text/html' and 'attachment' not in cdispo:
                    # Ideally strip HTML tags here, but simple append works for feature counting
                    body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
        else:
            body = self.msg.get_payload(decode=True).decode('utf-8', errors='ignore')
        return body

    def extract_features(self) -> dict:
        features = {}
        
        # Header Analysis
        subject = self.msg.get('Subject', '') or ''
        features['subject_length'] = len(subject)
        features['has_urgent_subject'] = int(any(kw in subject.lower() for kw in SUSPICIOUS_KEYWORDS))
        features['num_caps_subject'] = sum(1 for c in subject if c.isupper())
        
        # Authentication Results (Basic check)
        auth_header = self.msg.get('Authentication-Results', '').lower()
        features['dmarc_fail'] = int('dmarc=fail' in auth_header)
        features['spf_fail'] = int('spf=fail' in auth_header)
        features['dkim_fail'] = int('dkim=fail' in auth_header)
        
        # Body Analysis
        body = self._get_body()
        features['body_length'] = len(body)
        features['num_urls'] = len(re.findall(r'https?://\S+', body))
        features['has_suspicious_keyword_body'] = int(any(kw in body.lower() for kw in SUSPICIOUS_KEYWORDS))
        features['has_html_content'] = int('text/html' in self.raw_email)
        
        # Attachments
        num_attachments = 0
        if self.msg.is_multipart():
            for part in self.msg.walk():
                if part.get_content_maintype() == 'multipart': continue
                if part.get('Content-Disposition') is None: continue
                num_attachments += 1
        features['num_attachments'] = num_attachments
        
        return features
