from bs4 import BeautifulSoup
from phishguard.core.constants import SUSPICIOUS_KEYWORDS

class HTMLExtractor:
    def __init__(self, html_content: str):
        self.soup = BeautifulSoup(html_content, 'html.parser')
        self.text_content = self.soup.get_text().lower()
        
    def extract_features(self) -> dict:
        features = {}
        
        # Form Analysis
        forms = self.soup.find_all('form')
        features['num_forms'] = len(forms)
        features['num_password_inputs'] = len(self.soup.find_all('input', type='password'))
        features['num_hidden_inputs'] = len(self.soup.find_all('input', type='hidden'))
        
        # Check if forms post to external domains (simple heuristic)
        # Note: Ideally needs full URL context to check 'external', assuming relative for now is internal
        external_actions = 0
        for form in forms:
            action = form.get('action', '').lower()
            if action.startswith('http') and len(action) > 4:
                external_actions += 1
        features['has_external_form_action'] = int(external_actions > 0)

        # Link Analysis
        all_links = self.soup.find_all('a', href=True)
        features['total_links'] = len(all_links)
        features['num_null_links'] = sum(1 for a in all_links if a['href'] in ['#', 'javascript:void(0)', ''])
        
        # Urgency/Content
        title = self.soup.title.string if self.soup.title else ""
        features['has_urgent_title'] = int(any(kw in title.lower() for kw in SUSPICIOUS_KEYWORDS))
        
        # Scripting
        features['num_scripts'] = len(self.soup.find_all('script'))
        features['num_iframes'] = len(self.soup.find_all('iframe'))
        
        return features
