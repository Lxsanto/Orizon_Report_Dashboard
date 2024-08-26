def taglia_fino_all_ultimo_punto(testo):
    # Trova l'indice dell'ultimo punto nella stringa
    indice_ultimo_punto = testo.rfind('.')
    
    # Se non c'è alcun punto nella stringa, restituisce la stringa originale
    if indice_ultimo_punto == -1:
        return testo
    
    # Taglia la stringa fino all'ultimo punto (incluso)
    return testo[:indice_ultimo_punto + 1]