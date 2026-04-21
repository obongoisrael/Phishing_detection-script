

"""
Phishing Website Detection System
Project Title: Detection of Phishing Websites Using URL Feature Analysis

Description:
This program analyzes a given URL and determines whether it is likely
legitimate or phishing based on common URL-based indicators.

Ethical Notice:
This tool is for educational and defensive purposes only.
It does NOT attack or interact with websites.
"""

# Import Required Modules


import re                 # For pattern matching (IP address detection)
import tldextract         # For extracting domain and subdomain information


# Feature Extraction

def extract_features(url):
    """
    Extracts security-related features from a URL.

    Parameters:
        url (str): The URL provided by the user

    Returns:
        dict: A dictionary containing extracted features
    """

    features = {}

    # Feature 1: Check if HTTPS is used
    features["https"] = url.startswith("https")

    # Feature 2: URL length
    features["url_length"] = len(url)

    # Feature 3: Check if URL uses an IP address instead of a domain name
    features["has_ip"] = bool(re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", url))

    # Feature 4: Check for '@' symbol in URL
    features["has_at"] = "@" in url

    # Feature 5: Count number of subdomains
    extracted = tldextract.extract(url)
    if extracted.subdomain:
        features["subdomain_count"] = len(extracted.subdomain.split("."))
    else:
        features["subdomain_count"] = 0

    return features


# Phishing Detection Logic


def is_phishing(features):
    """
    Determines whether a URL is phishing based on extracted features.

    Parameters:
        features (dict): Extracted URL features

    Returns:
        bool: True if phishing, False if legitimate
    """

    score = 0

    # Rule-based scoring system
    if not features["https"]:
        score += 1

    if features["url_length"] > 75:
        score += 1

    if features["has_ip"]:
        score += 1

    if features["has_at"]:
        score += 1

    if features["subdomain_count"] > 2:
        score += 1

    # Threshold: if score >= 2, classify as phishing
    return score >= 2

# Display Results

def display_result(url, features, result):
    """
    Displays the analysis result to the user.

    Parameters:
        url (str): Analyzed URL
        features (dict): Extracted features
        result (bool): Detection result
    """

    print("\nURL Analysis Report")
    print("-------------------")
    print(f"URL: {url}")
    print(f"Uses HTTPS: {features['https']}")
    print(f"URL Length: {features['url_length']}")
    print(f"Contains IP Address: {features['has_ip']}")
    print(f"Contains '@' Symbol: {features['has_at']}")
    print(f"Number of Subdomains: {features['subdomain_count']}")

    print("\nFinal Verdict:")
    if result:
        print("WARNING: This URL is likely a PHISHING website.")
    else:
        print("SAFE: This URL appears to be LEGITIMATE.")

# Main Program Execution


if __name__ == "__main__":
    print("Phishing Website Detection System")
    print("--------------------------------")

    user_url = input("Enter a URL to analyze: ").strip()

    extracted_features = extract_features(user_url)
    phishing_result = is_phishing(extracted_features)

    display_result(user_url, extracted_features, phishing_result)
