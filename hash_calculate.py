import streamlit as st
import hashlib
import requests
import os

API_KEY = "34040e4ea1e24ff58a333fc0416d79b77320c011c54539e2f9f5914bc3c5dcb7"

def calculate_hash(file_path):
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()

    with open(file_path, "rb") as file:
        while chunk := file.read(8192):
            md5_hash.update(chunk)
            sha1_hash.update(chunk)
            sha256_hash.update(chunk)

    return md5_hash.hexdigest(), sha1_hash.hexdigest(), sha256_hash.hexdigest()

def check_hash(file_path):
    md5_hash, sha1_hash, sha256_hash = calculate_hash(file_path)
    url = f"https://www.virustotal.com/vtapi/v2/file/report"

    params = {
        "apikey": API_KEY,
        "resource": md5_hash  # You can use MD5 or SHA1 hash as the resource
    }

    response = requests.get(url, params=params)
    result = response.json()

    if result["response_code"] == 0:
        st.write("File not found")
    else:
        st.write("VirusTotal Report:")
        st.write(f"MD5: {md5_hash}")
        st.write(f"SHA1: {sha1_hash}")
        st.write(f"SHA256: {sha256_hash}")
        st.write(f"Total Scans: {result['total']}")
        st.write(f"Positives: {result['positives']}")

# Create a Streamlit app
st.title('File Hash Checker')
st.write('Upload a file to check its hash and VirusTotal report.')

# Create a file uploader
uploaded_file = st.file_uploader('Upload a file')

# Check the file's hash and VirusTotal report when the user clicks a button
if uploaded_file:
    file_path = "uploaded_file.tmp"
    with open(file_path, "wb") as f:
        f.write(uploaded_file.read())

    check_hash(file_path)

    # Clean up the temporary file
    os.remove(file_path)
