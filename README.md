# zeek_dashboard
This is a python project by: Macam, Marvin John; Sebastian, Joshua; Sison, Sweet Lana; Tirao Albert
A dashboard that visualizes logs uploaded in Google Drive coming from Zeek server connected to a network.

To run the project:
1. Clone repository from GitHub: https://github.com/AlbertTirao/zeek_dashboard.git
2. Open terminal, cd to projct directory, create venv, activate venv and type this to download required packages: 
pip install -r requirements.txt
3. Run the project: streamlit run app.py
(On every run/rerun, it will require you to authenticate google drive account you are using in your browser. You have to add your google drive account first as collaborator to Google Drive folder being used to store the Zeek logs.)