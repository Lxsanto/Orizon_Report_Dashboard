import os
import io
import re
import pandas as pd
import shutil
from zipfile import ZipFile
import subprocess
import yaml
import xml.etree.ElementTree as ET

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

def dataframe_to_latex(df, caption):
    """Convert a pandas DataFrame to a LaTeX longtable."""
    latex_table = df.to_latex(index=False, longtable=True, escape=False)
    latex_table = latex_table.replace('\\toprule', '\\hline').replace('\\midrule', '\\hline').replace('\\bottomrule', '\\hline')
    latex_table = latex_table.replace('\\begin{longtable}', '\\begin{longtable}[l]')
    return f"""
\\begin{{center}}
\\small
{latex_table}
\\caption{{{caption}}}
\\end{{center}}
"""

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
                        \usepackage{longtable}
                        \usepackage{booktabs}
                        \usepackage{array}
                        \usepackage{pdflscape}
                        \usepackage{geometry}

                        \geometry{margin=2.5cm}

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
        
        # Convert main title first, accounting for leading space
        chapter_match = re.search(r'^\s*# (.+)$', md_content, flags=re.MULTILINE)
        if chapter_match:
            chapter_title = chapter_match.group(1)
            latex_chapter = f"\\chapter{{{chapter_title}}}\n\n"
            md_content = md_content[chapter_match.end():].strip()
        else:
            latex_chapter = ""
        
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
        
        # Add pngs if they exist
        chapter_number = os.path.splitext(md_file)[0]
        image_dir = os.path.join(input_dir, 'pngs')
        image_files = sorted([f for f in os.listdir(image_dir) if f.startswith(f"{chapter_number}_") and f.lower().endswith(('.png', '.jpg', '.jpeg'))])
        
        image_latex = ""
        if image_files:
            image_latex += "\n\\begin{figure}[htbp]\n\\centering\n"
            for img_file in image_files:
                image_latex += f"\\includegraphics[width=0.8\\textwidth]{{pngs/{img_file}}}\n"
                image_latex += "\\vspace{1cm}\n"
            image_latex += f"\\caption{{pngs related to {chapter_title}}}\n\\end{{figure}}\n"
        
        # Position pngs based on chapter number
        if index == 0:  # First chapter
            latex_content += latex_chapter + image_latex + latex_content_escaped + "\n\n"
        else:  # Other chapters
            latex_content += latex_chapter + latex_content_escaped + image_latex + "\n\n"

    # Add appendix with DataFrames
    latex_content += "\\appendix\n\\chapter{Data Tables}\n\n"
    
    dfs_dir = os.path.join(input_dir, 'dfs')
    df_files = [f for f in os.listdir(dfs_dir) if f.endswith('.pkl')]
    
    for df_file in df_files:
        df_path = os.path.join(dfs_dir, df_file)
        df = pd.read_pickle(df_path)
        table_name = os.path.splitext(df_file)[0]
        latex_table = dataframe_to_latex(df, f"Table: {table_name}")
        latex_content += "\\begin{landscape}\n" + latex_table + "\\end{landscape}\n\n"

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
