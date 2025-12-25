import pandas as pd
import os

TARGET_CSV = r"d:\Project\PhishGuard\datasets\raw\phishing_20k_augmented.csv"

# Curated List of 100+ Legitimate Domains (Indian + Global Daily Use)
DOMAINS = [
    # --- Indian Banks ---
    "hdfcbank.com", "onlinesbi.com", "icicibank.com", "axisbank.com", "kotak.com", 
    "indusind.com", "yesbank.in", "punjabnationalbank.in", "canarabank.com", "bankofbaroda.in",
    "unionbankofindia.co.in", "idfcfirstbank.com", "rblbank.com", "federalbank.co.in",
    
    # --- E-Commerce (India) ---
    "flipkart.com", "amazon.in", "myntra.com", "ajio.com", "meesho.com", 
    "tatacliq.com", "nykaa.com", "bigbasket.com", "blinkit.com", "zepto.co.in",
    "jiomart.com", "snapdeal.com", "lenskart.com", "firstcry.com",
    
    # --- Government / Services ---
    "irctc.co.in", "uidai.gov.in", "incometax.gov.in", "passportindia.gov.in", 
    "epfindia.gov.in", "parivahan.gov.in", "gst.gov.in", "india.gov.in",
    "cowin.gov.in", "pmkisan.gov.in", "digilocker.gov.in",
    
    # --- Payments / Fintech ---
    "paytm.com", "phonepe.com", "razorpay.com", "billdesk.com", "ccavenue.com",
    "policybazaar.com", "zerodha.com", "groww.in", "upstox.com", "cred.club",
    
    # --- Travel / Transport ---
    "makemytrip.com", "goibibo.com", "redbus.in", "ixigo.com", "cleartrip.com", 
    "indigo.in", "airindia.com", "vistara.com", "irctc.co.in", "uber.com", "olacabs.com",
    
    # --- Food / Delivery ---
    "zomato.com", "swiggy.com", "dominos.co.in", "pizzahut.co.in", "mcdonaldsindia.com",
    
    # --- Telecom / ISP ---
    "jio.com", "airtel.in", "vodafoneidea.com", "bsnl.co.in", "actcorp.in",
    
    # --- News / Media (India) ---
    "timesofindia.indiatimes.com", "ndtv.com", "indianexpress.com", "thehindu.com", 
    "hindustantimes.com", "moneycontrol.com", "economictimes.indiatimes.com",
    "hotstar.com", "sonyliv.com", "zee5.com", "bookmyshow.com", "jiocinema.com",
    
    # --- Education / Jobs ---
    "naukri.com", "linkedin.com", "indeed.co.in", "byjus.com", "unacademy.com", 
    "udemy.com", "coursera.org", "shiksha.com",
    
    # --- Global / Tech Daily ---
    "google.co.in", "google.com", "youtube.com", "facebook.com", "instagram.com",
    "twitter.com", "whatsapp.com", "yahoo.co.in", "microsoft.com", "apple.com",
    "netflix.com", "spotify.com", "zoom.us", "gmail.com", "outlook.com",
    "dropbox.com", "drive.google.com", "maps.google.com", "translate.google.com",
    "github.com", "stackoverflow.com", "w3schools.com", "geeksforgeeks.org",
    "medium.com", "quora.com", "reddit.com", "wikipedia.org"
]

def append_domains():
    print(f"Loading {TARGET_CSV}...")
    try:
        df = pd.read_csv(TARGET_CSV)
        print(f"Current rows: {len(df)}")
        
        new_entries = []
        for domain in DOMAINS:
            # Add http/https variants to ensure coverage
            new_entries.append({"url": f"http://{domain}", "label": 0})
            new_entries.append({"url": f"https://{domain}", "label": 0})
            # Also add www variant
            new_entries.append({"url": f"https://www.{domain}", "label": 0})
            
        new_df = pd.DataFrame(new_entries)
        
        # Append
        augmented_df = pd.concat([df, new_df], ignore_index=True)
        
        # Drop duplicates just in case
        augmented_df.drop_duplicates(subset='url', inplace=True)
        
        augmented_df.to_csv(TARGET_CSV, index=False)
        
        print(f"Success! Added {len(new_entries)} Indian/Daily URLs.")
        print(f"New total rows: {len(augmented_df)}")
        
    except FileNotFoundError:
        print(f"Error: {TARGET_CSV} not found. Please ensure the dataset exists first.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    append_domains()
