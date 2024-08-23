# Orizon Security Dashboard

## Overview
Orizon Security Dashboard is a comprehensive cybersecurity analysis tool powered by advanced AI. It provides in-depth analysis and visualization of vulnerability data, offering actionable insights for improving an organization's security posture.

## Features
- **Data Upload**: Supports JSON file upload for vulnerability data.
- **Interactive Dashboard**: Visualizes key security metrics and vulnerabilities.
- **AI-Powered Analysis**: Utilizes the Orizon Engine (based on Meta-Llama-3.1-8B-Instruct) for in-depth security analysis.
- **Customizable Filters**: Allows filtering by date range and severity.
- **Multiple Visualizations**: Includes risk score gauge, severity distribution pie chart, vulnerability timeline, network topology graph, and more.
- **Detailed Insights**: Provides analysis on severity distribution, top vulnerabilities, network topology, CVSS scores, vulnerability age, and types.
- **Trend Forecasting**: Offers vulnerability trend analysis and 30-day forecasting.
- **Export Options**: Supports exporting reports in PDF, Word, CSV, and JSON formats.
- **Interactive Vulnerability Explorer**: Allows searching and exploring individual vulnerabilities.

## Technologies Used
- **Frontend**: Streamlit
- **Data Processing**: Pandas, NumPy
- **Visualization**: Plotly, Matplotlib, Seaborn
- **Network Analysis**: NetworkX
- **AI Model**: Meta-Llama-3.1-8B-Instruct (via Hugging Face Transformers)
- **Report Generation**: ReportLab (PDF), python-docx (Word)

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/your-repo/orizon-security-dashboard.git
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Set up environment variables:
   - Create a `.env` file in the root directory
   - Add your Hugging Face API token:
     ```
     HF_API_TOKEN=your_token_here
     ```

## Usage

1. Run the Streamlit app:
   ```
   streamlit run cybersecurity_dashboard_vers2-0.py
   ```

2. Upload a JSON file containing vulnerability data through the sidebar.

3. Use the dashboard to explore and analyze the security data.

4. Generate and download reports as needed.

## Data Format
The application expects a JSON file with vulnerability data. The JSON should contain an array of objects, each representing a vulnerability with the following key fields:
- `severity`: The severity level of the vulnerability
- `description`: A description of the vulnerability
- `created_at`: The date the vulnerability was discovered
- `host`: The affected host
- `template_name`: The type or name of the vulnerability
- `cvss_score` (optional): The CVSS score of the vulnerability

## Contributing
Contributions to the Orizon Security Dashboard are welcome. Please follow these steps:

1. Fork the repository
2. Create a new branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License
...

## Contact
Luca Lorenzi luca.lorenzi@orizon.one

Project Link: [https://github.com/your-repo/orizon-security-dashboard](https://github.com/your-repo/orizon-security-dashboard)

## Acknowledgements
- [Streamlit](https://streamlit.io/)
- [Plotly](https://plotly.com/)
- [Hugging Face Transformers](https://huggingface.co/transformers/)
- [NetworkX](https://networkx.org/)
- [ReportLab](https://www.reportlab.com/)
- [python-docx](https://python-docx.readthedocs.io/)
