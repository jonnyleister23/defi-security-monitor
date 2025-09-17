## 🚀 Installation & Setup

Follow these steps to get the **DeFi Security Monitor** running locally or on Streamlit Cloud.

### 1. Clone the Repository
Clone the repository from GitHub and navigate into the project directory.

### 2. Install Dependencies
Install the required Python packages using the `requirements.txt` file by running:  
`pip install -r requirements.txt`

### 3. Set Up Environment Variables
1. Create a file named `.env` in the root directory of the project.
2. Add your Infura API key in the file like this:  
   `INFURA_KEY=your_infura_project_id`
3. If you are deploying on Streamlit Cloud, add the key through **Settings → Secrets Manager → New Secret** instead of using a `.env` file.

### 4. Run the Dashboard Locally
1. In the project directory, run the dashboard with: `streamlit run dashboard.py`

### 5. Deploy on Streamlit Cloud (Optional)
1. Push your repository to GitHub.
2. Log in to [Streamlit Cloud](https://streamlit.io/cloud) and link your GitHub repository.
3. Add your **INFURA_KEY** in **Secrets Manager**.
4. Deploy the app — it will now be live and shareable.
