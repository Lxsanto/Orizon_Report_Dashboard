

def save_fstring_to_file(fstring: str, name_file: str,  **kwargs):
    """
    Prende in input un' f-string e la salva in un file 'debug.txt' mantenendo la formattazione corretta.

    Parameters:
        fstring (str): La f-string da salvare.
        **kwargs: Variabili da utilizzare all'interno della f-string.
    """
    # Valuta l'f-string utilizzando le variabili passate
    #evaluated_string = eval(fstring, {}, kwargs)
    
    # Scrive l'output nel file debug.txt
    with open(f'debug/{name_file}', 'w', encoding='utf-8') as file:
        file.write(fstring)