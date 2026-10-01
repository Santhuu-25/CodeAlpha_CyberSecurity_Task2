import re
from urllib.parse import urlparse

class PhishingDetector:
    """
    Transparent, rule-based phishing detection engine for URLs and Messages/Emails.
    Does not use unexplainable AI/ML models; relies on deterministic heuristic security checks.
    """

    # URL Shorteners list
    URL_SHORTENERS = {
        'bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'buff.ly', 'ow.ly',
        'goo.gl', 'rebrand.ly', 'cutt.ly', 'tiny.cc', 'bc.vc', 'v.gd'
    }

    # Suspicious Top Level Domains
    SUSPICIOUS_TLDS = {
        'xyz', 'top', 'work', 'click', 'loan', 'zip', 'mov', 'tk',
        'ml', 'ga', 'cf', 'gq', 'site', 'online', 'club', 'buzz', 'download'
    }

    # Suspicious keywords commonly found in phishing URLs
    SUSPICIOUS_URL_KEYWORDS = [
        'login', 'signin', 'verify', 'verification', 'account', 'update',
        'banking', 'secure', 'security', 'paypal', 'appleid', 'microsoft',
        'google', 'netflix', 'amazon', 'ebay', 'support', 'service',
        'recover', 'billing', 'confirm', 'credential', 'auth', 'pass'
    ]

    @staticmethod
    def classify_risk(score):
        """Converts numerical score (0-100) to risk level."""
        if score <= 24:
            return "Low Risk"
        elif score <= 49:
            return "Suspicious"
        elif score <= 74:
            return "High Risk"
        else:
            return "Critical"

    def scan_url(self, raw_url):
        """
        Analyzes a URL using transparent heuristic rules.
        Returns risk score, risk level, detected indicators, explanation, and recommendations.
        """
        if not raw_url or not isinstance(raw_url, str):
            return {
                'error': 'Invalid URL input provided.'
            }

        url = raw_url.strip()

        # Add default scheme if missing for proper parsing
        if not re.match(r'^[a-zA-Z]+://', url):
            url_to_parse = 'http://' + url
        else:
            url_to_parse = url

        try:
            parsed = urlparse(url_to_parse)
        except Exception:
            return {
                'error': 'Malformed URL format.'
            }

        domain = parsed.netloc.split(':')[0].lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
        full_path = path + ('?' + query if query else '')

        indicators = []
        score = 0

        # Rule 1: HTTP instead of HTTPS
        if parsed.scheme == 'http':
            score += 15
            indicators.append({
                'rule': 'Unencrypted Protocol (HTTP)',
                'severity': 'Medium',
                'points': 15,
                'description': 'URL uses unsecure HTTP scheme instead of encrypted HTTPS.'
            })

        # Rule 2: IP Address used instead of Domain Name
        ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
        if re.match(ip_pattern, domain):
            score += 30
            indicators.append({
                'rule': 'IP Address in Hostname',
                'severity': 'High',
                'points': 30,
                'description': 'Host uses a raw numerical IP address rather than a registered domain name.'
            })

        # Rule 3: Suspicious URL Length
        if len(url) > 100:
            score += 15
            indicators.append({
                'rule': 'Excessive URL Length',
                'severity': 'Medium',
                'points': 15,
                'description': f'URL is unusually long ({len(url)} characters), often used to hide target destinations.'
            })
        elif len(url) > 75:
            score += 10
            indicators.append({
                'rule': 'Long URL Length',
                'severity': 'Low',
                'points': 10,
                'description': f'URL is moderately long ({len(url)} characters).'
            })

        # Rule 4: Excessive Subdomains
        domain_parts = domain.split('.')
        # Exclude www prefix count
        effective_parts = [p for p in domain_parts if p != 'www']
        if len(effective_parts) >= 4:
            score += 20
            indicators.append({
                'rule': 'Excessive Subdomains',
                'severity': 'High',
                'points': 20,
                'description': f'Domain contains {len(effective_parts)-2} subdomains, which may indicate domain spoofing.'
            })
        elif len(effective_parts) == 3:
            score += 10
            indicators.append({
                'rule': 'Multiple Subdomains',
                'severity': 'Medium',
                'points': 10,
                'description': 'Domain contains subdomains that warrant close inspection.'
            })

        # Rule 5: Suspicious Characters (@ or multiple //)
        if '@' in url:
            score += 25
            indicators.append({
                'rule': '@ Symbol in URL',
                'severity': 'High',
                'points': 25,
                'description': 'Contains "@" symbol, which causes browsers to ignore preceding credentials and redirect.'
            })
        
        if full_path.count('//') > 0 or url_to_parse.count('//') > 1:
            score += 15
            indicators.append({
                'rule': 'Double Slash Redirect Path',
                'severity': 'Medium',
                'points': 15,
                'description': 'Contains extra "//" slashes which can be used to perform sneaky open redirects.'
            })

        # Rule 6: URL Shortener Usage
        if domain in self.URL_SHORTENERS:
            score += 20
            indicators.append({
                'rule': 'URL Shortening Service',
                'severity': 'Medium',
                'points': 20,
                'description': f'Uses known URL shortener service ({domain}) which masks the actual destination.'
            })

        # Rule 7: Suspicious Keywords in Path or Subdomain
        found_keywords = [kw for kw in self.SUSPICIOUS_URL_KEYWORDS if kw in full_path or kw in domain]
        if found_keywords:
            points = min(25, len(found_keywords) * 10)
            score += points
            indicators.append({
                'rule': 'Sensitive Brand/Security Keywords',
                'severity': 'Medium',
                'points': points,
                'description': f'URL contains high-risk keywords: {", ".join(found_keywords)}'
            })

        # Rule 8: Punycode or Hyphen Spoofing
        if 'xn--' in domain:
            score += 30
            indicators.append({
                'rule': 'Punycode Homograph Attempt',
                'severity': 'High',
                'points': 30,
                'description': 'Domain uses Punycode ("xn--") encoding, frequently used to mimic legitimate brand characters.'
            })
        elif domain.count('-') >= 2:
            score += 15
            indicators.append({
                'rule': 'Excessive Hyphens in Domain',
                'severity': 'Medium',
                'points': 15,
                'description': f'Domain contains multiple hyphens ({domain.count("-")}), common in fake lookalike domains.'
            })

        # Rule 9: Suspicious TLD
        tld = domain_parts[-1] if len(domain_parts) > 1 else ''
        if tld in self.SUSPICIOUS_TLDS:
            score += 20
            indicators.append({
                'rule': 'High-Risk Top Level Domain (TLD)',
                'severity': 'Medium',
                'points': 20,
                'description': f'Domain uses TLD ".{tld}" frequently associated with low-cost disposable spam/phishing.'
            })

        # Cap score at 100
        score = min(100, score)
        risk_level = self.classify_risk(score)

        # Generate summary explanation
        if score == 0:
            explanation = "No standard rule-based phishing indicators were detected in this URL structure."
        elif score < 25:
            explanation = "URL exhibits minor non-standard characteristics, but risk appears low based on rule-based heuristics."
        elif score < 50:
            explanation = "URL exhibits several suspicious elements (e.g. unencrypted connection, keywords, or structure). Exercise caution."
        elif score < 75:
            explanation = "URL exhibits multiple strong phishing indicators. It is potentially suspicious and likely untrustworthy."
        else:
            explanation = "URL exhibits critical phishing indicators (e.g. IP host, homograph attempts, @ redirect). Highly likely to be malicious."

        # Recommendations
        recommendations = []
        if parsed.scheme == 'http':
            recommendations.append("Never enter sensitive information or credentials on HTTP pages.")
        if domain in self.URL_SHORTENERS:
            recommendations.append("Expand shortened links using an unshortening tool before visiting.")
        if found_keywords:
            recommendations.append("Verify if the domain matches the official website of the referenced brand.")
        recommendations.append("Do not click links directly from unknown email senders or unsolicited messages.")

        return {
            'input': raw_url,
            'risk_score': score,
            'risk_level': risk_level,
            'detected_indicators': indicators,
            'explanation': explanation,
            'safety_recommendation': recommendations,
            'disclaimer': 'Rule-based analysis checks URL syntax patterns only. It cannot guarantee 100% safety or definitive detection.'
        }

    def analyze_message(self, raw_message):
        """
        Analyzes message/email body text for common social engineering red flags.
        Returns risk score, risk level, detected red flags, explanation, and recommendations.
        """
        if not raw_message or not isinstance(raw_message, str):
            return {
                'error': 'Invalid message content provided.'
            }

        msg = raw_message.strip()
        msg_lower = msg.lower()

        indicators = []
        score = 0

        # Rule 1: Urgent Language / Sense of Urgency
        urgent_keywords = ['immediately', 'urgent', 'within 24 hours', 'within 12 hours', 'act now', 'suspended soon', 'expires today', 'action required', 'immediate attention']
        found_urgency = [w for w in urgent_keywords if w in msg_lower]
        if found_urgency:
            score += 20
            indicators.append({
                'rule': 'Urgent Language / Artificial Time Pressure',
                'severity': 'High',
                'points': 20,
                'description': f'Uses high-pressure time limits to force hurried decisions: "{", ".join(found_urgency[:3])}"'
            })

        # Rule 2: Threats or Intimidation
        threat_keywords = ['legal action', 'lawsuit', 'police', 'arrest', 'terminate your account', 'account block', 'unauthorized activity', 'suspended permanently', 'prosecution']
        found_threats = [w for w in threat_keywords if w in msg_lower]
        if found_threats:
            score += 25
            indicators.append({
                'rule': 'Threats or Psychological Pressure',
                'severity': 'High',
                'points': 25,
                'description': f'Employs intimidating consequences or legal threats: "{", ".join(found_threats[:3])}"'
            })

        # Rule 3: Password / Credential Requests
        pwd_keywords = ['password', 'passcode', 'credentials', 'login details', 'secret code', 'security key']
        if any(w in msg_lower for w in pwd_keywords) and any(verb in msg_lower for verb in ['enter', 'provide', 'send', 'confirm', 'verify', 'update', 'reply']):
            score += 30
            indicators.append({
                'rule': 'Password or Credential Request',
                'severity': 'Critical',
                'points': 30,
                'description': 'Directly or indirectly solicits user password or login credentials.'
            })

        # Rule 4: OTP / 2FA Verification Code Request
        otp_keywords = ['otp', 'one-time password', 'verification code', '2fa code', 'authenticator code', '6-digit code', 'pin number']
        if any(w in msg_lower for w in otp_keywords):
            score += 35
            indicators.append({
                'rule': 'OTP / 2FA Code Harvesting Attempt',
                'severity': 'Critical',
                'points': 35,
                'description': 'Asks for One-Time Password or 2FA verification codes, a primary technique for account takeover.'
            })

        # Rule 5: Financial / Card Information Requests
        financial_keywords = ['credit card', 'debit card', 'cvv', 'cvc', 'social security', 'ssn', 'bank account number', 'routing number', 'card number', 'billing info']
        if any(w in msg_lower for w in financial_keywords):
            score += 30
            indicators.append({
                'rule': 'Sensitive Financial / Payment Data Request',
                'severity': 'Critical',
                'points': 30,
                'description': 'Requests sensitive payment details, card CVVs, or banking identifiers.'
            })

        # Rule 6: Suspicious Links Embedded
        urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', msg)
        if urls:
            score += 15
            link_desc = f'Message contains {len(urls)} embedded URL link(s).'
            # check if any link is non-https or suspicious
            has_http = any(u.startswith('http://') for u in urls)
            if has_http:
                score += 10
                link_desc += ' Includes unencrypted HTTP link(s).'
            indicators.append({
                'rule': 'Embedded Web Link(s)',
                'severity': 'Medium',
                'points': 15 + (10 if has_http else 0),
                'description': link_desc
            })

        # Rule 7: Prize / Reward / Lottery Scams
        prize_keywords = ['you won', 'congratulations', 'lottery', 'gift card', 'free reward', '$1,000', '$10,000', 'prize winner', 'claimed your payout']
        found_prizes = [w for w in prize_keywords if w in msg_lower]
        if found_prizes:
            score += 25
            indicators.append({
                'rule': 'Reward / Prize Scam Wording',
                'severity': 'High',
                'points': 25,
                'description': f'Contains lures regarding unexpected winnings or monetary rewards: "{", ".join(found_prizes[:2])}"'
            })

        # Rule 8: Generic Impersonation / Salutations
        impersonation_greetings = ['dear customer', 'dear user', 'dear account holder', 'valued client', 'dear member', 'attention customer']
        found_greetings = [w for w in impersonation_greetings if w in msg_lower]
        if found_greetings:
            score += 10
            indicators.append({
                'rule': 'Generic Salutation / Impersonation Style',
                'severity': 'Low',
                'points': 10,
                'description': 'Uses impersonal generic salutation rather than addressing you by your actual name.'
            })

        # Rule 9: Account Verification Language
        verify_phrases = ['verify your account', 're-activate account', 'confirm your identity', 'update billing information', 'security check required']
        found_verify = [w for w in verify_phrases if w in msg_lower]
        if found_verify:
            score += 15
            indicators.append({
                'rule': 'Account Verification Trigger',
                'severity': 'Medium',
                'points': 15,
                'description': f'Prompts user to perform account verification: "{", ".join(found_verify[:2])}"'
            })

        # Rule 10: Attachment References (.exe, .zip, invoice attachment)
        attachment_phrases = ['attached invoice', 'see attachment', 'attachment.exe', 'attachment.zip', 'download document', 'pdf invoice attached']
        if any(w in msg_lower for w in attachment_phrases):
            score += 20
            indicators.append({
                'rule': 'Suspicious Attachment Reference',
                'severity': 'Medium',
                'points': 20,
                'description': 'Urges opening attached files or external documents that may contain malware.'
            })

        # Cap score at 100
        score = min(100, score)
        risk_level = self.classify_risk(score)

        # Generate summary explanation
        if score == 0:
            explanation = "No prominent social engineering keywords or phishing indicators were identified in this message."
        elif score < 25:
            explanation = "Message contains mild informational keywords, but risk remains relatively low."
        elif score < 50:
            explanation = "Message presents moderate red flags (such as urgency or link inclusion). Verify the sender independently."
        elif score < 75:
            explanation = "Message contains strong social engineering tactics (threats, prize claims, or account verification). Likely phishing."
        else:
            explanation = "Message exhibits critical phishing red flags soliciting sensitive credentials, OTPs, or financial data. High threat!"

        recommendations = [
            "Never share One-Time Passwords (OTPs), PINs, or passwords with anyone.",
            "Legitimate organizations will never demand immediate password verification via unverified text or email.",
            "Do not click links inside unsolicited messages. Navigate directly to official web addresses.",
            "If suspicious, contact the official organization through verified customer service phone numbers."
        ]

        # Sanitized version for safe preview/storage (privacy protection)
        sanitized_summary = self.sanitize_secrets(msg[:150])

        return {
            'input_summary': sanitized_summary,
            'risk_score': score,
            'risk_level': risk_level,
            'detected_indicators': indicators,
            'explanation': explanation,
            'safety_recommendation': recommendations,
            'disclaimer': 'Rule-based message analysis relies on keyword heuristics and cannot replace organizational security validation.'
        }

    @staticmethod
    def sanitize_secrets(text):
        """
        Scubs potential sensitive secrets (passwords, 6-digit OTPs, 16-digit credit cards)
        from message strings before saving to database history for privacy protection.
        """
        if not text:
            return ""
        # Mask credit card numbers (13-19 digits)
        text = re.sub(r'\b(?:\d[ -]*?){13,19}\b', '[REDACTED CARD NUMBER]', text)
        # Mask OTP codes (4-8 digit isolated numbers following keywords)
        text = re.sub(r'(?i)(code|otp|pin|verification)[\s:]*([0-9]{4,8})', r'\1: [REDACTED CODE]', text)
        # Mask password patterns
        text = re.sub(r'(?i)(password|passcode)[\s:=]+([^\s]+)', r'\1: [REDACTED PASSWORD]', text)
        return text
