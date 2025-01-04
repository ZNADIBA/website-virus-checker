import streamlit as st
import requests
import hashlib

# Your VirusTotal API key
API_KEY = '6c35618b25287880e25144165a3c14263ff1069a9cd308c46ce45edcda3eac1e'

# Function to check website safety
def check_website_safety(url):
    # Hash the URL to get the unique identifier for VirusTotal
    url_id = hashlib.sha256(url.encode()).hexdigest()

    headers = {
        'x-apikey': API_KEY
    }

    # Construct the VirusTotal API URL
    api_url = f'https://www.virustotal.com/api/v3/urls/{url_id}'

    response = requests.get(api_url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        # Check the safety report from VirusTotal
        safety_status = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        if safety_status.get('malicious', 0) > 0:
            return f"⚠️ **Warning!** This website is flagged as **malicious**. Proceed with caution!"
        else:
            return f"✅ **Safe!** This website is **clean**. You're good to go!"
    else:
        return f"❌ **Error** checking website. Status code: {response.status_code}"

# Fun chatbot-like responses and educational content
def show_safety_tips():
    st.subheader("👨‍💻 How to Stay Safe Online:")
    
    # Using expanders for tabs
    with st.expander("🔍 Check the URL carefully"):
        st.write("""
        Always look for **"https://"** (not just "http://"). The 's' stands for 'secure'. This means the website uses encryption to protect your data.
        """)

    with st.expander("🔒 Padlock Icon - What Does it Mean?"):
        st.write("""
        A **padlock icon** next to the URL means the website is using **SSL (Secure Socket Layer)** encryption, which secures your connection and protects your information from being intercepted.
        """)

    with st.expander("⚠️ Avoid Suspicious Links"):
        st.write("""
        Be cautious with pop-ups, unsolicited emails, or unknown sources. Always verify before clicking.
        """)

    with st.expander("🚫 Don't Click on Fake Login Pages"):
        st.write("""
        Ensure that the website you’re logging into is legitimate. Look for proper spelling, and check the URL.
        """)

    with st.expander("🛡️ Use Trusted Antivirus Software"):
        st.write("""
        Keep your device protected with a reliable antivirus to block potential threats.
        """)

    with st.expander("💰 Be Cautious of Too Good Offers"):
        st.write("""
        If something seems too good to be true, it might be a trap or phishing attempt!
        """)

    with st.expander("🔑 Regularly Update Your Passwords"):
        st.write("""
        Make sure to change your passwords frequently and use unique ones for each account.
        """)

    st.write("👀 Stay smart, stay safe! It’s better to be cautious than to regret later.")

# Streamlit UI
def main():
    st.title("💻 Website Safety Checker & Digital Guardian 🛡️")
    st.write("""
    Welcome to your **personal web safety assistant**! Here, we’ll help you check if a website is safe or potentially malicious.
    
    Just enter a URL below, and we’ll run it through a safety check to make sure you’re browsing smart. 💡
    """)
    
    # Chatbot-style welcome message
    st.write("So, what website do you want to check today? Let’s make sure you’re safe online.")

    url = st.text_input("Enter URL to check:")

    if url:
        result = check_website_safety(url)
        st.write(result)
        
        # Add some cool chatbot-style responses after checking
        if "malicious" in result:
            st.write("**🚨 Caution! 🚨** It seems like you're heading into dangerous waters. Better stay away!")
        else:
            st.write("You're good to go! Keep browsing safely.")

        # Show additional safety tips and explanations in tabs
        show_safety_tips()

if __name__ == "__main__":
    main()
