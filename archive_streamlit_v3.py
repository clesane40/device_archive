import os
import streamlit as st
import requests
import re
import difflib
import sqlite3
import zipfile
import datetime
from io import BytesIO
from requests.auth import HTTPBasicAuth
from whoosh.index import create_in, open_dir
from whoosh.fields import Schema, TEXT, ID
from whoosh.qparser import QueryParser, WildcardPlugin
from ncclient import manager

# File to save the connection settings
SETTINGS_FILE = "connection_settings.txt"

# Define the schema for Whoosh
schema = Schema(filename=ID(stored=True), content=TEXT, line_number=ID(stored=True))

# Create an index in a directory called "indexdir"
if not os.path.exists("indexdir"):
    os.mkdir("indexdir")
    ix = create_in("indexdir", schema)
else:
    ix = open_dir("indexdir")

# Global variable to store the bearer token
bearer_token = None

def load_files_from_database():
    conn = sqlite3.connect("files.db")
    cursor = conn.cursor()
    
    st.session_state.downloaded_files = st.session_state.get('downloaded_files', {})
    
    cursor.execute("SELECT filename, content FROM files")
    files = cursor.fetchall()
    for filename, content in files:
        file_type = filename.split('.')[-2]  # Assuming file_type is the second last part of the filename
        if file_type not in st.session_state.downloaded_files:
            st.session_state.downloaded_files[file_type] = {}
        st.session_state.downloaded_files[file_type][filename] = content.encode('utf-8')
    
    conn.close()


def save_settings(ip, username, password, connect_on_startup):
    """Save connection settings to a file."""
    with open(SETTINGS_FILE, 'w') as f:
        f.write(f"{ip}\n{username}\n{password}\n{connect_on_startup}")

def load_settings():
    """Load connection settings from a file."""
    with open(SETTINGS_FILE, 'r') as f:
        ip = f.readline().strip()
        username = f.readline().strip()
        password = f.readline().strip()
        connect_on_startup = f.readline().strip().lower() == 'true'
    return ip, username, password, connect_on_startup

def initialize_settings_file():
    """Initialize the settings file with default values."""
    default_ip = "10.46.249.236"
    default_username = "admin"
    default_password = "admin"
    default_connect_on_startup = True
    save_settings(default_ip, default_username, default_password, default_connect_on_startup)

def test_api_connection(ip_address, auth):
    endpoint_url = f"https://{ip_address}:8543/api/netim/v1/devices"
    try:
        response = requests.get(endpoint_url, auth=auth, verify=False)
        print(response.status_code, response.content)  # Print the status and content for debugging
        return response.status_code == 200
    except Exception as e:
        print(e)  # Print any exceptions that occur
        return False

def fetch_api_test_data(ip_address, auth):
    endpoint_url = f"https://{ip_address}:8543/api/test"
    response = requests.get(endpoint_url, auth=auth, verify=False)
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": "Failed to fetch data"}

def filter_devices_by_expression(devices, expression):
    filtered_devices = []
    for device in devices:
        try:
            if eval(expression, {"__builtins__": None}, device):
                filtered_devices.append(device)
        except:
            pass
    return filtered_devices

def get_devices_from_endpoint(endpoint_url, auth):
    global bearer_token
    headers = {}
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"
    response = requests.get(endpoint_url, auth=auth, headers=headers, verify=False)
    if 'Authorization' in response.headers:
        bearer_token = response.headers['Authorization'].split(" ")[1]
    return response.json()["items"]

def get_latest_archive_id(ip_address, device_id, auth, file_type):
    endpoint_url = f"https://{ip_address}:8543/api/netim/v1/devices/{device_id}/archives?fileType={file_type}&limit=5000&offset=0"
    headers = {"Authorization": f"Bearer {bearer_token}"}
    response = requests.get(endpoint_url, auth=auth, headers=headers, verify=False)
    for item in response.json()["items"]:
        if item["latest"]:
            return item["id"]
    return None

def add_to_whoosh_index(filename, content):
    writer = ix.writer()
    for idx, line in enumerate(content.split("\n"), 1):
        writer.add_document(filename=filename, content=line, line_number=str(idx))
    writer.commit()

def search_content(query, use_regex=False):
    matches = []

    # Check if the query is multiline
    is_multiline = len(query.splitlines()) > 1

    if is_multiline:
        with ix.searcher() as searcher:
            all_results = []
            for line in query.splitlines():
                line_query = QueryParser("content", ix.schema, plugins=[WildcardPlugin()]).parse(line)
                results = searcher.search(line_query, limit=None)
                all_results.append(set([hit["filename"] for hit in results]))

            # Find common filenames where all lines matched
            common_files = set.intersection(*all_results)

            for common_file in common_files:
                matching_lines = []
                for line in query.splitlines():
                    line_query = QueryParser("content", ix.schema, plugins=[WildcardPlugin()]).parse(line)
                    results = searcher.search(line_query, limit=None)
                    for hit in results:
                        if hit["filename"] == common_file:
                            matching_lines.append({"line": hit["content"], "line_number": hit["line_number"]})

                # Combine all matching lines for a device into a single entry
                combined_lines = "\n".join([f"Line {line['line_number']}: {line['line']}" for line in matching_lines])
                matches.append({"filename": common_file, "combined_matching_lines": combined_lines})

    if use_regex:
        for file_type, files in st.session_state.downloaded_files.items():
            for filename, content in files.items():
                content_str = content.decode("utf-8", errors="replace")
                if re.search(query, content_str):
                    matches.append({"filename": filename, "combined_matching_lines": query})

    else:  # Single string search
        for file_type, files in st.session_state.downloaded_files.items():
            for filename, content in files.items():
                content_str = content.decode("utf-8", errors="replace")
                if query in content_str:
                    matches.append({"filename": filename, "combined_matching_lines": query})



    return matches

def get_file_for_archive(ip_address, archive_id, file_type, auth, device_name, downloaded_files):
    endpoint_url = f"https://{ip_address}:8543/api/netim/v1/archives/{archive_id}/file?type={file_type}"
    headers = {"Authorization": f"Bearer {bearer_token}"}
    response = requests.get(endpoint_url, auth=auth, headers=headers, verify=False)
    if response.status_code == 200:
        if file_type not in downloaded_files:
            downloaded_files[file_type] = {}
        
        # Handle versioning based on date and time
        current_datetime = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{device_name}.{file_type}.{current_datetime}"
        
        downloaded_files[file_type][filename] = response.content
    return downloaded_files

def display_side_by_side_diff(file1_content, file2_content):
    d = difflib.Differ()
    diff = list(d.compare(file1_content.splitlines(), file2_content.splitlines()))

    left_content = []
    right_content = []
    diff_count = 0

    for line in diff:
        if line.startswith("  "):
            left_content.append(line[2:])
            right_content.append(line[2:])
        elif line.startswith("- "):
            left_content.append(f'<span style="background-color: #FFDDDD">{line[2:]}</span>')
            right_content.append("")
            diff_count += 1
        elif line.startswith("+ "):
            left_content.append("")
            right_content.append(f'<span style="background-color: #DDFFDD">{line[2:]}</span>')
            diff_count += 1

    left_display = "\n".join(left_content)
    right_display = "\n".join(right_content)

    col1, col2 = st.columns(2)
    with col1:
        st.markdown(f'<pre style="white-space: pre;">{left_display}</pre>', unsafe_allow_html=True)
    with col2:
        st.markdown(f'<pre style="white-space: pre;">{right_display}</pre>', unsafe_allow_html=True)

    st.write(f"Total differences: {diff_count}")

def create_zip_from_files(files_dict):
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, 'a', zipfile.ZIP_DEFLATED, False) as zip_file:
        for file_type, files in files_dict.items():
            for filename, content in files.items():
                zip_file.writestr(filename, content)
    return zip_buffer.getvalue()

def ensure_database_setup():
    conn = sqlite3.connect("files.db")
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY,
        filename TEXT NOT NULL,
        content TEXT NOT NULL
    )
    """)
    conn.commit()
    conn.close()

ensure_database_setup()

def push_config_to_device(ip_address, username, password, enable_password, ssh_key, port, timeout,
                          hostkey_verify, allow_agent, look_for_keys, device_params_name, edited_content):
    with manager.connect(host=ip_address, port=port, username=username, password=password,
                         hostkey_verify=hostkey_verify, allow_agent=allow_agent, look_for_keys=look_for_keys,
                         device_params={'name': device_params_name}, timeout=timeout) as m:
        if ssh_key:
            m.add_private_key(ssh_key)
        m.execute("enable", secret=enable_password)
        m.edit_config(target='running', config=edited_content)

def main():
    st.title("External Device Search and File Viewer")
    st.sidebar.write("App Version: 1.0.0")
    st.session_state.downloaded_files = st.session_state.get('downloaded_files', {})

    # Check if the settings file exists at app startup, if not, initialize it
    if not os.path.exists(SETTINGS_FILE):
        initialize_settings_file()

    # If the file exists, load the settings
    else:
        ip_address, username, password, connect_on_startup = load_settings()

    # Define variables at the beginning of main()
    ip_address = st.session_state.get("ip_address", "10.46.249.236")
    username = st.session_state.get("username", "admin")
    password = st.session_state.get("password", "admin")
    connect_on_startup = st.session_state.get("connect_on_startup", False)
    auth = HTTPBasicAuth(username, password)

    # If the checkbox is selected and connection settings are available, attempt to connect
    if connect_on_startup and ip_address and username and password:
        if test_api_connection(ip_address, auth):
            st.sidebar.success("Connected to API successfully!")
        else:
            st.sidebar.error("Failed to connect to API. Check your connection settings.")

    # Initialize SQLite connection and cursor at the beginning of main()
    conn = sqlite3.connect("files.db")
    cursor = conn.cursor()

    # Load files from the database into session state
    load_files_from_database()

    # Create the device_search_history table if it doesn't exist
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS device_search_history (
        id INTEGER PRIMARY KEY,
        expression TEXT NOT NULL
    )
    """)

    # Create the content_search_history table if it doesn't exist
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS content_search_history (
        id INTEGER PRIMARY KEY,
        expression TEXT NOT NULL
    )
    """)

    devices = []  # Initialize devices to an empty list at the beginning of main()

    


    st.sidebar.title("Navigation")
    sections = [
        "Connection Settings",
        "Search Devices",
        "File Management",
        "Content Search",
        "Compare Files"
    ]
    selected_section = st.sidebar.radio("Go to", sections)

    # Define variables at the beginning of main()
    ip_address = st.session_state.get("ip_address", "10.46.249.236")
    username = st.session_state.get("username", "admin")
    password = st.session_state.get("password", "admin")
    auth = HTTPBasicAuth(username, password)

    # Define all_files at the beginning of main()
    all_files = sorted([file for files in st.session_state.downloaded_files.values() for file in files.keys()])

    if selected_section == "Connection Settings":
        with st.expander("Connection Settings", expanded=True):
            ip_address = st.text_input("Enter the IP address", ip_address)
            username = st.text_input("Enter the username", username)
            password = st.text_input("Enter the password", type="password", value=password)
            connect_on_startup = st.checkbox("Connect at app startup", value=st.session_state.get("connect_on_startup", True))
            auth = HTTPBasicAuth(username, password)
            num_workers = st.number_input("Number of thread workers", min_value=1, max_value=20, value=5)
            

            # Store the values in session_state for persistence
            st.session_state.ip_address = ip_address
            st.session_state.username = username
            st.session_state.password = password
            st.session_state.num_workers = num_workers
            st.session_state.connect_on_startup = connect_on_startup

            # Save the settings when the "Save Settings" button is clicked
            if st.button("Save Settings"):
                save_settings(ip_address, username, password, connect_on_startup)
                st.success("Settings saved successfully!")

    elif selected_section == "Search Devices":
        with st.expander("Search Devices", expanded=True):
            # Retrieve previous device search expressions from SQLite
            cursor.execute("SELECT expression FROM device_search_history ORDER BY id DESC")
            previous_device_searches = [row[0] for row in cursor.fetchall()]
            previous_device_search = st.selectbox("Previous Device Searches", [""] + previous_device_searches)
            expression = st.text_input("Enter your search expression (leave empty to fetch all devices)", value=previous_device_search)
            st.text("""
            Examples of valid search expressions:
            1. name == 'BETH-PA-FWL02'
            2. vendor == 'Palo Alto Networks'
            """)

            predefined_file_types = [
                "cfg",
                "alarms",
                "allContexts",
                "aps",
                "arp",
                "asymRoute",
                "bgpRib",
                "cam",
                "cdp",
                "rules.C",
                "objects.C",                
                "fex",
                "frMap",
                "standby",
                "http",
                "ifIndex",
                "igmpGroup",
                "interface",
                "ipRoute",
                "ipv6Interface",
                "ipv6Route",
                "lacp",
                "lldp",
                "module",
                "mplstetunnels",
                "multicastRoute",
                "nextHop",
                "objects.C",
                "ospf",
                "ospfV3",
                "pim",
                "pimV6",
                "portChannel",
                "portSecurity",
                "qos",
                "rules.C",
                "running",
                "saved",
                "security",
                "spanningTree",
                "startup",
                "stp",
                "system",
                "vlan",
                "vrf",
                "vrrp",
                "vtp",
                "wlan",
            ]
            custom_file_type = st.text_input("Enter custom file type (if not in the list above)")
            selected_file_types = st.multiselect("Select file types to fetch", predefined_file_types)
            # Store the values in session_state for persistence
            st.session_state.expression = expression
            st.session_state.selected_file_types = selected_file_types

            if custom_file_type:
                selected_file_types.append(custom_file_type)

            if expression:
                devices = filter_devices_by_expression(devices, expression)

            if st.button("Fetch Devices"):
                with st.spinner('Fetching devices and downloading files...'):
                    # Fetch all devices from the API
                    endpoint_url = f"https://{ip_address}:8543/api/netim/v1/devices"
                    response = requests.get(endpoint_url, auth=auth, verify=False)
                    st.session_state.api_test_data = fetch_api_test_data(ip_address, auth)
                    if response.status_code == 200:
                        devices = response.json()["items"]

            # Filter devices based on the provided expression
            filtered_devices = filter_devices_by_expression(devices, expression) if expression else devices

            # Download files for the filtered devices
            for device in filtered_devices:
                for file_type in selected_file_types:
                    archive_id = get_latest_archive_id(ip_address, device["id"], auth, file_type)
                    if archive_id:
                        st.session_state.downloaded_files = get_file_for_archive(ip_address, archive_id, file_type, auth, device["name"], st.session_state.downloaded_files)
                        all_files = sorted([file for files in st.session_state.downloaded_files.values() for file in files.keys()])

            # Save the downloaded files to the SQLite database
            conn = sqlite3.connect("files.db")
            cursor = conn.cursor()
            for file_type, files in st.session_state.downloaded_files.items():
                for filename, content in files.items():
                    cursor.execute("INSERT INTO files (filename, content) VALUES (?, ?)", (filename, content.decode("utf-8", errors="replace")))
            conn.commit()
            conn.close()

    elif selected_section == "File Management":
        with st.expander("View Files", expanded=True):
            all_files = sorted([file for files in st.session_state.downloaded_files.values() for file in files.keys()])
            
            selected_file_index = st.session_state.get("selected_file_index", 0)
            if selected_file_index is None or selected_file_index >= len(all_files):
                selected_file_index = 0

            selected_file = st.selectbox("Select a file to view", all_files, index=selected_file_index)
            if selected_file in all_files:
                st.session_state.selected_file_index = all_files.index(selected_file)
            else:
                st.session_state.selected_file_index = 0
                selected_file = all_files[0] if all_files else None

            for file_type, files in st.session_state.downloaded_files.items():
                if selected_file in files:
                    st.code(files[selected_file].decode("utf-8", errors="replace"))
        
        with st.expander("Database Operations", expanded=True):
            conn = sqlite3.connect("files.db")
            cursor = conn.cursor()
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY,
                filename TEXT NOT NULL,
                content TEXT NOT NULL
            )
            """)
            conn.commit()
        # File Upload Widget
            uploaded_zip_file = st.file_uploader("Upload ZIP File", type=["zip"])

            if uploaded_zip_file is not None:
                with zipfile.ZipFile(uploaded_zip_file) as zip_ref:
                    extracted_files = []
                    for file_info in zip_ref.infolist():
                        content = zip_ref.read(file_info.filename).decode("utf-8", errors="replace")
                        extracted_files.append((file_info.filename, content))

                    # Add Extracted Files to Database
                    conn = sqlite3.connect("files.db")
                    cursor = conn.cursor()
                    for filename, content in extracted_files:
                        cursor.execute("INSERT INTO files (filename, content) VALUES (?, ?)", (filename, content))
                    conn.commit()
                    conn.close()

            if st.button("Delete All Files from Database"):
                cursor.execute("DELETE FROM files")
                conn.commit()
                st.success("All files deleted from database!")

            if st.button("Delete Specific Files from Database"):
                to_delete = st.multiselect("Select files to delete", all_files)
                for file in to_delete:
                    cursor.execute("DELETE FROM files WHERE filename=?", (file,))
                conn.commit()
                st.success(f"Deleted {len(to_delete)} files from database!")

            conn.close()

        with st.expander("Download Files", expanded=True):
            if st.button("Download as ZIP"):
                zip_content = create_zip_from_files(st.session_state.downloaded_files)
                st.download_button(
                    label="Download ZIP",
                    data=zip_content,
                    file_name="downloaded_files.zip",
                    mime="application/zip"
                )
        with st.expander("Configuration Push", expanded=True):
            selected_config_file = st.selectbox("Select a configuration file", all_files, index=st.session_state.get("selected_config_file_index", 0))
            if st.button("View/Edit Configuration"):
                config_content = st.session_state.downloaded_files["cfg"][selected_config_file].decode("utf-8", errors="replace")
                edited_content = st.text_area("Edit Configuration", value=config_content)

                # Get input values from the user
                device_ip = st.text_input("Device IP", value="")
                username = st.text_input("Username", value="")
                password = st.text_input("Password", value="", type="password")
                enable_password = st.text_input("Enable Password", value="", type="password")
                ssh_key = st.text_area("SSH Private Key", value="")
                port = st.number_input("Port", min_value=1, max_value=65535, value=830)
                timeout = st.number_input("Timeout", min_value=1, value=10)
                hostkey_verify = st.checkbox("Hostkey Verify", value=False)
                allow_agent = st.checkbox("Allow Agent", value=False)
                look_for_keys = st.checkbox("Look for Keys", value=False)
                device_params_name = st.text_input("Device Params Name", value="csr")

                # Push the configuration only when the "Push Configuration" button is clicked
                if st.button("Push Configuration"):
                    push_config_to_device(device_ip, username, password, enable_password, ssh_key, port, timeout,
                                          hostkey_verify, allow_agent, look_for_keys, device_params_name, edited_content)
                    st.success("Configuration pushed successfully!")
                    
    elif selected_section == "Content Search":
        with st.expander("Content Search", expanded=True):
            # Retrieve previous content search expressions from SQLite
            cursor.execute("SELECT expression FROM content_search_history ORDER BY id DESC")
            previous_content_searches = [row[0] for row in cursor.fetchall()]
            previous_content_search = st.selectbox("Previous Content Searches", [""] + previous_content_searches)
            search_query = st.text_area("Enter search query", value=st.session_state.get("search_query", previous_content_search))
            st.session_state.search_query = search_query
            use_regex = st.checkbox("Use Regular Expressions")
                      

            if st.button("Search"):
                matches = search_content(search_query, use_regex)
                for match in matches:
                    st.write(f"Device: {match['filename']}")
                    st.code(match['combined_matching_lines'])
                # Save the search expression to SQLite
                cursor.execute("INSERT INTO content_search_history (expression) VALUES (?)", (search_query,))
                conn.commit()

    elif selected_section == "Compare Files":
        with st.expander("Compare Files", expanded=True):
            file_options = all_files
            file1 = st.selectbox("Select first file", file_options, index=st.session_state.get("file1_index", 0))
            file2 = st.selectbox("Select second file", file_options, index=st.session_state.get("file2_index", 1 if len(file_options) > 1 else 0))
            
            # Ensure file1 and file2 are in file_options before getting their indices
            if file1 in file_options:
                st.session_state.file1_index = file_options.index(file1)
            else:
                st.session_state.file1_index = 0  # Reset to 0 if not found
            
            if file2 in file_options:
                st.session_state.file2_index = file_options.index(file2)
            else:
                st.session_state.file2_index = 1 if len(file_options) > 1 else 0  # Reset to 1 or 0 if not found
            
            if st.button("Compare"):
                file1_content = None
                file2_content = None
                for file_type, files in st.session_state.downloaded_files.items():
                    if file1 in files:
                        file1_content = files[file1].decode("utf-8", errors="replace")
                    if file2 in files:
                        file2_content = files[file2].decode("utf-8", errors="replace")
                if file1_content and file2_content:
                    display_side_by_side_diff(file1_content, file2_content)


    # Close the SQLite connection
    conn.close()

if __name__ == "__main__":
    main()
