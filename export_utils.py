import os
import io
import re
import pandas as pd
import shutil
from zipfile import ZipFile
import subprocess
import yaml
import xml.etree.ElementTree as ET

# XML and YAML file paths
xml_file = "CWEs_folders/cwec_v4.15.xml"
yaml_path = 'CWEs_folders/nuclei-templates'

def escape_latex(text):
    """Escape special LaTeX characters while preserving LaTeX commands."""
    if not isinstance(text, str):
        text = str(text)
    
    def replace(match):
        if match.group(1):  # This is a LaTeX command
            return match.group(0)
        char = match.group(0)
        return {
            '&': r'\&',
            '%': r'\%',
            '$': r'\$',
            '#': r'\#',
            '_': r'\_',
            '~': r'\textasciitilde{}',
            '^': r'\textasciicircum{}',
            '\\': r'\textbackslash{}',
            '{': r'\{',
            '}': r'\}'
        }.get(char, char)

    pattern = r'(\\[a-zA-Z]+(?:\[.*?\])?{.*?}|\\[a-zA-Z]+)|([&%$#_~^\\{}])'
    escaped_text = re.sub(pattern, replace, text)
    escaped_text = re.sub(r'\b(\w+(?:\s+\w+){0,3})\b', lambda m: m.group(0).replace(' ', '~'), escaped_text)
    return escaped_text

def load_xml(file_path):
    tree = ET.parse(file_path)
    return tree.getroot()

def load_and_process_dataframe(dfs_dir):
    df_path = os.path.join(dfs_dir, '0.pkl')
    df = pd.read_pickle(df_path)
    severity_order = ['critical', 'high', 'medium', 'low', 'info']
    df['severity'] = pd.Categorical(df['severity'], categories=severity_order, ordered=True)
    df_sorted = df.sort_values('severity')
    top_10 = df_sorted.head(10)
    return top_10

def format_code_snippet(code):
    """Format code snippets using LaTeX verbatim environment."""
    return f"\\begin{{verbatim}}\n{code}\n\\end{{verbatim}}\n"

def safe_get(element, attr):
    return element.get(attr) if element is not None else None

def extract_text(element, xpath, namespaces):
    found = element.find(xpath, namespaces) if element is not None else None
    return found.text if found is not None else None

def extract_list(element, xpath, namespaces):
    items = element.findall(xpath, namespaces) if element is not None else []
    return [item.text for item in items if item is not None and item.text]

def extract_code_example(example, namespace):
    intro = extract_text(example, 'cwe:Intro_Text', namespace) or ''
    body = extract_text(example, 'cwe:Body_Text', namespace) or ''
    
    code_elements = example.findall('.//cwe:Example_Code', namespace)
    code_snippets = []
    for code in code_elements:
        nature = safe_get(code, 'Nature') or ''
        language = safe_get(code, 'Language') or ''
        snippet = ''.join(code.itertext()).strip()
        code_snippets.append(f"Nature: {nature}\nLanguage: {language}\n```{language.lower()}\n{snippet}\n```")
    
    return f"{intro}\n\n{body}\n\n" + "\n\n".join(code_snippets)

def extract_references(weakness, namespace):
    references = []
    for ref in weakness.findall('cwe:References/cwe:Reference', namespace):
        ref_id = safe_get(ref, 'External_Reference_ID')
        section = safe_get(ref, 'Section')
        link_element = ref.find('cwe:URL', namespace)
        link = link_element.text if link_element is not None else None
        if ref_id:
            ref_string = f"{ref_id}"
            if link:
                ref_string += f": {link}"
            if section:
                ref_string += f" (Section: {section})"
            references.append(ref_string)
    return references

def extract_attack_patterns(weakness, namespace):
    patterns = []
    related_patterns = weakness.find('cwe:Related_Attack_Patterns', namespace)
    if related_patterns is not None:
        for rap in related_patterns.findall('cwe:Related_Attack_Pattern', namespace):
            capec_id = safe_get(rap, 'CAPEC_ID')
            capec_name = extract_text(rap, 'cwe:CAPEC_Name', namespace)
            if capec_id:
                pattern = f"CAPEC-{capec_id}"
                if capec_name:
                    pattern += f": {capec_name}"
                patterns.append(pattern)
    return patterns

def extract_mitigations(weakness, namespace):
    mitigations = []
    for mit in weakness.findall('cwe:Potential_Mitigations/cwe:Mitigation', namespace):
        phase = extract_text(mit, 'cwe:Phase', namespace)
        description = extract_text(mit, 'cwe:Description', namespace)
        effectiveness = extract_text(mit, 'cwe:Effectiveness', namespace)
        notes = extract_text(mit, 'cwe:Effectiveness_Notes', namespace)
        
        mitigation = f"Phase: {phase}\nDescription: {description}"
        if effectiveness:
            mitigation += f"\nEffectiveness: {effectiveness}"
        if notes:
            mitigation += f"\nNotes: {notes}"
        
        mitigations.append(mitigation)
    return mitigations

def fetch_and_parse_yaml(target_path, template_id):
    for root, dirs, files in os.walk(target_path):
        for file in files:
            if file.endswith(".yaml"):
                file_path = os.path.join(root, file)
                with open(file_path, 'r') as f:
                    try:
                        yaml_data = yaml.safe_load(f)
                        if yaml_data.get('id') == template_id:
                            return yaml_data
                    except yaml.YAMLError as e:
                        print(f"Error parsing file {file}: {e}")
    return None

def search_cwe(cwe_id, xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    namespace = {'cwe': 'http://cwe.mitre.org/cwe-7'}
    cwe = root.find(f".//cwe:Weakness[@ID='{cwe_id}']", namespace)
    
    if cwe is not None:
        cwe_info = {
            'ID': cwe.get('ID'),
            'Name': cwe.get('Name'),
            'Abstraction': cwe.get('Abstraction'),
            'Structure': cwe.get('Structure'),
            'Status': cwe.get('Status'),
            'Description': extract_text(cwe, 'cwe:Description', namespace),
            'Extended_Description': extract_text(cwe, 'cwe:Extended_Description', namespace),
            'Related_Weaknesses': [f"{safe_get(rw, 'Nature')}:{safe_get(rw, 'CWE_ID')}" for rw in cwe.findall('cwe:Related_Weaknesses/cwe:Related_Weakness', namespace)],
            'Weakness_Ordinalities': extract_list(cwe, 'cwe:Weakness_Ordinalities/cwe:Weakness_Ordinality/cwe:Ordinality', namespace),
            'Applicable_Platforms': {
                'Language': [safe_get(lang, 'Name') for lang in cwe.findall('cwe:Applicable_Platforms/cwe:Language', namespace)],
                'Technology': [safe_get(tech, 'Class') for tech in cwe.findall('cwe:Applicable_Platforms/cwe:Technology', namespace)]
            },
            'Background_Details': extract_list(cwe, 'cwe:Background_Details/cwe:Background_Detail', namespace),
            'Modes_Of_Introduction': [f"{extract_text(intro, 'cwe:Phase', namespace)}: {extract_text(intro, 'cwe:Note', namespace)}" for intro in cwe.findall('cwe:Modes_Of_Introduction/cwe:Introduction', namespace)],
            'Likelihood_Of_Exploit': extract_text(cwe, 'cwe:Likelihood_Of_Exploit', namespace),
            'Common_Consequences': [f"{extract_text(cons, 'cwe:Scope', namespace)}: {extract_text(cons, 'cwe:Impact', namespace)}" for cons in cwe.findall('cwe:Common_Consequences/cwe:Consequence', namespace)],
            'Detection_Methods': [f"{extract_text(method, 'cwe:Method', namespace)}: {extract_text(method, 'cwe:Description', namespace)}" for method in cwe.findall('cwe:Detection_Methods/cwe:Detection_Method', namespace)],
            'Potential_Mitigations': extract_mitigations(cwe, namespace),
            'Demonstrative_Examples': [extract_code_example(ex, namespace) for ex in cwe.findall('cwe:Demonstrative_Examples/cwe:Demonstrative_Example', namespace)],
            'Observed_Examples': [f"{extract_text(ex, 'cwe:Reference', namespace)}: {extract_text(ex, 'cwe:Description', namespace)}" for ex in cwe.findall('cwe:Observed_Examples/cwe:Observed_Example', namespace)],
            'Related_Attack_Patterns': extract_attack_patterns(cwe, namespace),
            'References': extract_references(cwe, namespace),
            'Taxonomy_Mappings': [f"{safe_get(tm, 'Taxonomy_Name')}: {safe_get(tm, 'Entry_Name')}" for tm in cwe.findall('cwe:Taxonomy_Mappings/cwe:Taxonomy_Mapping', namespace)],
            'Notes': [f"{safe_get(note, 'Type')}: {extract_text(note, '.', namespace)}" for note in cwe.findall('cwe:Notes/cwe:Note', namespace)],
            'CVEs': [extract_text(ex, 'cwe:Reference', namespace) for ex in cwe.findall('cwe:Observed_Examples/cwe:Observed_Example', namespace) if extract_text(ex, 'cwe:Reference', namespace).startswith('CVE-')]
        }
        return cwe_info
    else:
        return None

def format_output(cwe_info, yaml_info):
    output = ""
    
    if cwe_info:
        output += "\\section*{CWE Information}\n"
        for key, value in cwe_info.items():
            output += f"\\subsection*{{{escape_latex(key)}}}\n"
            if isinstance(value, list):
                if key == 'Demonstrative_Examples':
                    for item in value:
                        # Extract code snippets
                        code_snippets = re.findall(r'```(.+?)```', item, re.DOTALL)
                        if code_snippets:
                            for code in code_snippets:
                                output += f"\\begin{{lstlisting}}[breaklines=true,postbreak=\\mbox{{$\\hookrightarrow$\\space}}]\n{code.strip()}\n\\end{{lstlisting}}\n\n"
                        else:
                            output += f"{escape_latex(item)}\n\n"
                elif key == 'References':
                    for item in value:
                        parts = item.split(': ')
                        if len(parts) > 1:
                            output += f"\\href{{{parts[1]}}}{{{escape_latex(parts[0])}}}\\\\\n"
                        else:
                            output += f"{escape_latex(item)}\\\\\n"
                else:
                    for item in value:
                        output += f"{escape_latex(str(item))}\\\\\n"
            elif isinstance(value, dict):
                for k, vs in value.items():
                    output += f"{escape_latex(str(k))}: {escape_latex(', '.join(str(v) for v in vs if v))}\\\\\n"
            else:
                output += f"{escape_latex(str(value))}\n\n"
    
    if yaml_info:
        output += "\\section*{Template Information}\n"
        output += f"\\textbf{{ID:}} {escape_latex(str(yaml_info.get('id', 'N/A')))}\n\n"
        output += f"\\textbf{{Name:}} {escape_latex(str(yaml_info.get('info', {}).get('name', 'N/A')))}\n\n"
        output += f"\\textbf{{Severity:}} {escape_latex(str(yaml_info.get('info', {}).get('severity', 'N/A')))}\n\n"
        output += f"\\textbf{{Description:}} {escape_latex(str(yaml_info.get('info', {}).get('description', 'N/A')))}\n\n"
        
        classification = yaml_info.get('info', {}).get('classification', {})
        output += "\\textbf{Classification:}\n\\begin{itemize}\n"
        output += f"\\item CVSS Score: {escape_latex(str(classification.get('cvss-score', 'N/A')))}\n"
        output += f"\\item CVSS Metrics: {escape_latex(str(classification.get('cvss-metrics', 'N/A')))}\n"
        output += f"\\item CWE-ID: {escape_latex(str(classification.get('cwe-id', 'N/A')))}\n"
        output += f"\\item EPSS Score: {escape_latex(str(classification.get('epss-score', 'N/A')))}\n"
        output += f"\\item EPSS Percentile: {escape_latex(str(classification.get('epss-percentile', 'N/A')))}\n"
        output += "\\end{itemize}\n\n"
        
        if 'remediation' in yaml_info:
            output += f"\\textbf{{Remediation:}} {escape_latex(str(yaml_info['remediation']))}\n\n"
        
        if 'impact' in yaml_info:
            output += f"\\textbf{{Impact:}} {escape_latex(str(yaml_info['impact']))}\n\n"
        
        if 'metadata' in yaml_info:
            output += "\\textbf{Metadata:}\n\\begin{itemize}\n"
            for key, value in yaml_info['metadata'].items():
                output += f"\\item {escape_latex(str(key))}: {escape_latex(str(value))}\n"
            output += "\\end{itemize}\n\n"
        
        if 'tags' in yaml_info:
            output += f"\\textbf{{Tags:}} {escape_latex(', '.join(str(tag) for tag in yaml_info['tags']))}\n\n"
        
        if 'reference' in yaml_info:
            output += "\\textbf{References:}\n\\begin{itemize}\n"
            for ref in yaml_info['reference']:
                output += f"\\item {escape_latex(str(ref))}\n"
            output += "\\end{itemize}\n\n"
        
        if 'requests' in yaml_info:
            output += "\\textbf{Requests:}\n"
            for i, request in enumerate(yaml_info['requests'], 1):
                output += f"Request {i}:\n"
                if 'raw' in request:
                    output += "\\begin{lstlisting}[breaklines=true,postbreak=\\mbox{{$\\hookrightarrow$\\space}}]\n" + str(request['raw']) + "\n\\end{lstlisting}\n\n"
                if 'matchers' in request:
                    output += "Matchers:\n"
                    for matcher in request['matchers']:
                        output += "\\begin{lstlisting}[breaklines=true,postbreak=\\mbox{{$\\hookrightarrow$\\space}}]\n" + yaml.dump(matcher, default_flow_style=False) + "\n\\end{lstlisting}\n\n"
        
        for field in ['verified', 'max-request', 'shodan-query']:
            if field in yaml_info:
                output += f"\\textbf{{{field.capitalize().replace('-', ' ')}:}} {escape_latex(str(yaml_info[field]))}\n\n"
    
    return output

def get_cwe_info(root):
    namespace = {'cwe': 'http://cwe.mitre.org/cwe-7'}
    weaknesses = root.findall(".//cwe:Weakness", namespace)
    
    cwe_data = []
    
    for weakness in weaknesses:
        info = {
            'ID': safe_get(weakness, 'ID'),
            'Name': safe_get(weakness, 'Name'),
            'Abstraction': safe_get(weakness, 'Abstraction'),
            'Structure': safe_get(weakness, 'Structure'),
            'Status': safe_get(weakness, 'Status'),
            'Description': extract_text(weakness, 'cwe:Description', namespace),
            'Extended_Description': extract_text(weakness, 'cwe:Extended_Description', namespace),
            'Related_Weaknesses': [f"{safe_get(rw, 'Nature')}:{safe_get(rw, 'CWE_ID')}" for rw in weakness.findall('cwe:Related_Weaknesses/cwe:Related_Weakness', namespace)],
            'Weakness_Ordinalities': extract_list(weakness, 'cwe:Weakness_Ordinalities/cwe:Weakness_Ordinality/cwe:Ordinality', namespace),
            'Applicable_Platforms': {
                'Language': [safe_get(lang, 'Name') for lang in weakness.findall('cwe:Applicable_Platforms/cwe:Language', namespace)],
                'Technology': [safe_get(tech, 'Class') for tech in weakness.findall('cwe:Applicable_Platforms/cwe:Technology', namespace)]
            },
            'Background_Details': extract_list(weakness, 'cwe:Background_Details/cwe:Background_Detail', namespace),
            'Alternate_Terms': [f"{extract_text(term, 'cwe:Term', namespace)}: {extract_text(term, 'cwe:Description', namespace)}" for term in weakness.findall('cwe:Alternate_Terms/cwe:Alternate_Term', namespace)],
            'Modes_Of_Introduction': [f"{extract_text(intro, 'cwe:Phase', namespace)}: {extract_text(intro, 'cwe:Note', namespace)}" for intro in weakness.findall('cwe:Modes_Of_Introduction/cwe:Introduction', namespace)],
            'Likelihood_Of_Exploit': extract_text(weakness, 'cwe:Likelihood_Of_Exploit', namespace),
            'Common_Consequences': [f"{extract_text(cons, 'cwe:Scope', namespace)}: {extract_text(cons, 'cwe:Impact', namespace)}" for cons in weakness.findall('cwe:Common_Consequences/cwe:Consequence', namespace)],
            'Detection_Methods': [f"{extract_text(method, 'cwe:Method', namespace)}: {extract_text(method, 'cwe:Description', namespace)}" for method in weakness.findall('cwe:Detection_Methods/cwe:Detection_Method', namespace)],
            'Potential_Mitigations': extract_mitigations(weakness, namespace),
            'Demonstrative_Examples': [extract_code_example(ex, namespace) for ex in weakness.findall('cwe:Demonstrative_Examples/cwe:Demonstrative_Example', namespace)],
            'Observed_Examples': [f"{extract_text(ex, 'cwe:Reference', namespace)}: {extract_text(ex, 'cwe:Description', namespace)}" for ex in weakness.findall('cwe:Observed_Examples/cwe:Observed_Example', namespace)],
            'Related_Attack_Patterns': extract_attack_patterns(weakness, namespace),
            'References': extract_references(weakness, namespace),
            'Taxonomy_Mappings': [f"{safe_get(tm, 'Taxonomy_Name')}: {safe_get(tm, 'Entry_Name')}" for tm in weakness.findall('cwe:Taxonomy_Mappings/cwe:Taxonomy_Mapping', namespace)],
            'Notes': [f"{safe_get(note, 'Type')}: {extract_text(note, '.', namespace)}" for note in weakness.findall('cwe:Notes/cwe:Note', namespace)],
            'CVEs': [extract_text(ex, 'cwe:Reference', namespace) for ex in weakness.findall('cwe:Observed_Examples/cwe:Observed_Example', namespace) if extract_text(ex, 'cwe:Reference', namespace).startswith('CVE-')]
        }
        cwe_data.append(info)
    
    return pd.DataFrame(cwe_data)

def generate_vulnerability_info(template_id, vulnerability_number, hostname, xml_file, yaml_path):
    # Load CWE data
    root = ET.parse(xml_file).getroot()
    cwe_df = get_cwe_info(root)
    
    yaml_info = fetch_and_parse_yaml(yaml_path, template_id)
    
    if yaml_info:
        cwe_id = yaml_info.get('info', {}).get('classification', {}).get('cwe-id')
        if cwe_id:
            # Extract the numeric part of the CWE ID
            cwe_number = cwe_id.split('-')[-1]
            cwe_info = cwe_df[cwe_df['ID'] == cwe_number]
            if cwe_info.empty:
                print(f"CWE-{cwe_number} not found in the database.")
                cwe_info = None
            else:
                print(f"Found CWE-{cwe_number} in the database.")
                cwe_info = cwe_info.to_dict('records')[0]
        else:
            cwe_info = None
            print(f"No CWE ID found for template {template_id}")
    else:
        print(f"Template {template_id} not found")
        return ""
    
    latex_content = f"\\section*{{Vulnerability {vulnerability_number} - {escape_latex(hostname)}}}\n\n"
    latex_content += format_output(cwe_info, yaml_info)
    
    return latex_content

def md_to_latex(input_dir, output_file):
    # Get all markdown files in the input directory
    md_files = sorted([f for f in os.listdir(input_dir) if f.endswith('.txt')], key=lambda x: int(x.split('.')[0]))

    # LaTeX preamble
    latex_content = r"""
\documentclass[12pt,a4paper]{report}
\usepackage[utf8]{inputenc}
\usepackage[T1]{fontenc}
\usepackage{lmodern}
\usepackage{amsmath}
\usepackage{amsfonts}
\usepackage{amssymb}
\usepackage{graphicx}
\usepackage{hyperref}
\usepackage{geometry}
\usepackage{listings}
\usepackage{xcolor}
\usepackage{changepage}

\geometry{margin=2.5cm}

\lstset{
    breaklines=true,
    postbreak=\mbox{\textcolor{red}{$\hookrightarrow$}\space},
    frame=single,
    numbers=left,
    numberstyle=\tiny\color{gray},
    basicstyle=\ttfamily\footnotesize,
    keywordstyle=\color{blue},
    commentstyle=\color{green!40!black},
    stringstyle=\color{orange},
    showstringspaces=false,
    columns=flexible,
    keepspaces=true,
    breakatwhitespace=false
}

\newcommand{\customername}{Orizon}

\title{Security Vulnerability Analysis Report}
\author{Security Analysis Team \\ \large Customer: \customername}

\begin{document}

\maketitle

\tableofcontents

"""

    for index, md_file in enumerate(md_files):
        file_path = os.path.join(input_dir, md_file)
        
        with open(file_path, 'r', encoding='utf-8') as file:
            md_content = file.read()
        
        # Set a default chapter title
        chapter_title = f"Chapter {index + 1}"
        
        # Convert main title first, accounting for leading space
        chapter_match = re.search(r'^\s*# (.+)$', md_content, flags=re.MULTILINE)
        if chapter_match:
            chapter_title = chapter_match.group(1)
            latex_chapter = f"\\chapter{{{chapter_title}}}\n\n"
            md_content = md_content[chapter_match.end():].strip()
        else:
            latex_chapter = f"\\chapter{{{chapter_title}}}\n\n"
        
        # Convert other headers, accounting for possible leading spaces
        md_content = re.sub(r'^\s*## (.+)$', r'\\paragraph{\1}', md_content, flags=re.MULTILINE)
        md_content = re.sub(r'^\s*### (.+)$', r'\\paragraph{\1}', md_content, flags=re.MULTILINE)
        
        # Handle the specific format shown in the image
        md_content = re.sub(r'^\s*(\d+\.\d+)\s+{(.+)}$', r'\\section{\1 \2}', md_content, flags=re.MULTILINE)
        
        # Now escape special LaTeX characters
        latex_content_escaped = escape_latex(md_content)
        
        # Convert bold and italic
        latex_content_escaped = re.sub(r'\*\*(.+?)\*\*', r'\\textbf{\1}', latex_content_escaped)
        latex_content_escaped = re.sub(r'\*(.+?)\*', r'\\textit{\1}', latex_content_escaped)
        
        # Convert lists
        latex_content_escaped = re.sub(r'^\s*- (.+)$', r'\\begin{itemize}\n\\item \1\n\\end{itemize}', latex_content_escaped, flags=re.MULTILINE)
        latex_content_escaped = re.sub(r'^\s*\d+\. (.+)$', r'\\begin{itemize}\n\\item \1\n\\end{itemize}', latex_content_escaped, flags=re.MULTILINE)
        
        # Add images if they exist
        chapter_number = os.path.splitext(md_file)[0]
        image_dir = os.path.join(input_dir, 'pngs')
        image_files = sorted([f for f in os.listdir(image_dir) if f.startswith(f"{chapter_number}_") and f.lower().endswith(('.png', '.jpg', '.jpeg'))])
        
        image_latex = ""
        if image_files:
            image_latex += "\n\\begin{figure}[htbp]\n\\centering\n"
            for img_file in image_files:
                image_latex += f"\\includegraphics[width=0.8\\textwidth]{{pngs/{img_file}}}\n"
                image_latex += "\\vspace{1cm}\n"
            image_latex += f"\\caption{{Images related to {chapter_title}}}\n\\end{{figure}}\n"
        
        # Position images based on chapter number
        if index == 0:  # First chapter
            latex_content += latex_chapter + image_latex + latex_content_escaped + "\n\n"
        else:  # Other chapters
            latex_content += latex_chapter + latex_content_escaped + image_latex + "\n\n"

    # Add Top 10 Vulnerabilities section
    latex_content += r"\chapter{Top 10 Vulnerabilities}" + "\n\n"

    # Load and process the DataFrame
    dfs_dir = os.path.join(input_dir, 'dfs')
    top_10_vulnerabilities = load_and_process_dataframe(dfs_dir)

    for i, (_, vulnerability) in enumerate(top_10_vulnerabilities.iterrows(), 1):
        template_id = vulnerability['template_id']
        hostname = vulnerability['host']  # Assuming 'host' is the column name for hostname
        
        # Generate detailed information for the vulnerability
        vulnerability_info = generate_vulnerability_info(template_id, i, hostname, xml_file, yaml_path)
        
        # Add the vulnerability info to the LaTeX content
        latex_content += vulnerability_info + "\n\n"

    # Close the document
    latex_content += r"\end{document}"

    # Write the LaTeX content to the output file
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(latex_content)

def generate_tex_zip(input_directory, output_directory):

    output_file = f'{output_directory}/security_report.tex'

    # creating tex file
    md_to_latex(input_directory, output_file)
    print(f"LaTeX file '{output_file}' has been generated.")

    if not os.path.exists(f'{output_directory}/pngs'):
        os.makedirs(f'{output_directory}/pngs')

    # Itera attraverso tutti i file nella cartella di origine
    for filename in os.listdir(f'{input_directory}/pngs'):
        # Controlla se il file è un PNG
        if filename.lower().endswith('.png'):
            # Costruisci i percorsi completi per il file di origine e destinazione
            source_file = os.path.join(f'{input_directory}/pngs', filename)
            destination_file = os.path.join(f'{output_directory}/pngs', filename)
            
            # Copia il file
            shutil.copy2(source_file, destination_file)
            print(f"Copiato: {filename}")

    zip_buffer = io.BytesIO()
    
    with ZipFile(zip_buffer, 'w') as zip_file:
        for foldername, subfolders, filenames in os.walk(output_directory):
            for filename in filenames:
                file_path = os.path.join(foldername, filename)
                arcname = os.path.relpath(file_path, output_directory)
                zip_file.write(file_path, arcname)

    zip_buffer.seek(0)
    return zip_buffer

def read_tex_file(input_path):
    """Legge il contenuto di un file .tex."""
    try:
        with open(input_path, 'r', encoding='utf-8') as file:
            tex_content = file.read()
        print(f"Contenuto del file .tex letto con successo da {input_path}")
        return tex_content
    except FileNotFoundError:
        print(f"File {input_path} non trovato.")
        return None
    except Exception as e:
        print(f"Errore nella lettura del file .tex: {e}")
        return None

def generate_pdf(input_directory):
    pdf_path = os.path.join(f'{input_directory}/security_report.pdf')

    try:
        # Esegui pdflatex due volte
        for _ in range(2):
            result = subprocess.run(
                ['pdflatex', '-interaction=nonstopmode', 'security_report.tex'],
                check=True,
                cwd=input_directory,
                stdout=subprocess.PIPE,  # Cattura l'output standard
                stderr=subprocess.PIPE   # Cattura gli errori
            )

            # Mostra l'output del comando pdflatex
            print(result.stdout.decode('utf-8'))  # Stampa l'output del comando
            print(result.stderr.decode('utf-8'))  # Stampa eventuali errori

    except subprocess.CalledProcessError as e:
        # In caso di errore nella generazione del PDF, stampa l'output
        print(f"Errore nella generazione del PDF: {e}")
        print(e.stdout.decode('utf-8'))  # Output standard in caso di errore
        print(e.stderr.decode('utf-8'))  # Errori standard in caso di errore
    except Exception as e:
        print(f"Errore generico: {e}")

    # Fallback per tentare di leggere il PDF se esiste
    try: 
        if os.path.exists(pdf_path):
            with open(pdf_path, 'rb') as file:
                # Leggi il pdf
                file_content = file.read()
                print('PDF letto correttamente')

            buffer = io.BytesIO(file_content)
            return buffer
        else:
            print("Errore: il PDF non è stato generato.")
    
    except Exception as e:
        print(f'Errore nella lettura del file PDF: {e}')








if __name__ == "__main__":
    try:
        input_directory = 'trial_txts'  # Current directory
        output_directory = 'latex_template'

        zip_buffer = generate_tex_zip(input_directory, output_directory)

        # Definisci il nome del file di output
        output_filename = "Orizon_report.zip"

        # Scrivi il contenuto del buffer in un file locale
        with open(output_filename, "wb") as f:
            f.write(zip_buffer.getvalue())

        print(f"File ZIP creato con successo: {os.path.abspath(output_filename)}")

    except Exception as e:
        print(f"Si è verificato un errore: {str(e)}")