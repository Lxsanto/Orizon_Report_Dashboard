import streamlit as st

vuln_defs_eng = '## Vulnerabilities Definition\n'\
                '## Critical Severity\n'\
                '* Exploitation is straightforward and usually results in system-level compromise. It is advised to form a plan of action and patch immediately.\n\n'\
                '## High Severity\n'\
                '* Exploitation is more difficult but could cause elevated privileges and potentially a loss of data or downtime. It is advised to form a plan of action and patch as soon as possible.\n\n'\
                '## Medium Severity\n'\
                '* Vulnerabilities exist but require extra steps such as social engineering. It is advised to form a plan of action and patch after high-priority issues have been resolved.\n\n'\
                '## Low Severity\n'\
                '* Vulnerabilities are non-exploitable but increase an organization\'s attack surface. It is advised to form a plan of action and patch during the next maintenance window.\n\n'\
                '## Informational Severity\n'\
                '* No known vulnerability exists. Additional information is provided regarding items noticed during testing, strong controls, and additional documentation.\n'

vuln_defs_ita = '## Definizione Vulnerabilità\n'\
                '## Gravità Critica\n'\
                '* Lo sfruttamento è semplice e di solito comporta una compromissione a livello di sistema. Si consiglia di pianificare un\'azione correttiva e applicare una patch immediatamente.\n\n'\
                '## Gravità Alta\n'\
                '* Lo sfruttamento è più difficile, ma potrebbe causare l\'elevazione dei privilegi e potenzialmente la perdita di dati o interruzioni del servizio. Si consiglia di pianificare un\'azione correttiva e applicare una patch il prima possibile.\n\n'\
                '## Gravità Media\n'\
                '* Le vulnerabilità esistono, ma richiedono passaggi aggiuntivi, come l\'ingegneria sociale. Si consiglia di pianificare un\'azione correttiva e applicare una patch dopo che le problematiche ad alta priorità sono state risolte.\n\n'\
                '## Gravità Bassa\n'\
                '* Le vulnerabilità non sono sfruttabili, ma aumentano la superficie d\'attacco di un\'organizzazione. Si consiglia di pianificare un\'azione correttiva e applicare una patch durante la prossima finestra di manutenzione.\n\n'\
                '## Gravità Informativa\n'\
                '* Non esiste alcuna vulnerabilità nota. Vengono fornite informazioni aggiuntive riguardanti elementi osservati durante i test, controlli solidi e documentazione aggiuntiva.\n'

vuln_defs_esp = '## Definición de vulnerabilidades\n'\
                '## Gravedad Crítica\n'\
                '* La explotación es sencilla y generalmente resulta en una compromisión a nivel de sistema. Se aconseja planificar una acción correctiva y aplicar un parche inmediatamente.\n\n'\
                '## Gravedad Alta\n'\
                '* La explotación es más difícil, pero podría causar una elevación de privilegios y potencialmente la pérdida de datos o interrupciones del servicio. Se aconseja planificar una acción correctiva y aplicar un parche lo antes posible.\n\n'\
                '## Gravedad Media\n'\
                '* Existen vulnerabilidades, pero no son explotables o requieren pasos adicionales, como la ingeniería social. Se aconseja planificar una acción correctiva y aplicar un parche después de que se hayan resuelto los problemas de alta prioridad.\n\n'\
                '## Gravedad Baja\n'\
                '* Las vulnerabilidades no son explotables, pero aumentan la superficie de ataque de una organización. Se aconseja planificar una acción correctiva y aplicar un parche durante la próxima ventana de mantenimiento.\n\n'\
                '## Gravedad Informativa\n'\
                '* No existe ninguna vulnerabilidad conocida. Se proporciona información adicional sobre elementos observados durante las pruebas, controles sólidos y documentación adicional.\n'

def generate_orizon_analysis(prompt, _pipeline, max_new_tokens=100000, name_client='', language = 'en', vuln_def = False):

    if language == 'en':
        init_prompt = f'''You are a Cybersecurity expert tasked with evaluating the attack surface for {name_client}. Your job is to generate a chapter of a professional report detailing the external analysis of the attachment surface results. 
                     Format your response in Markdown.
                     Ensure the tone is concise, technical, and professional. use only # for the title, and ## for subsections, use - for lists. Do not use tables'''
        if vuln_def:
            init_prompt += f'This is the definition of the vulnerabilities type: {vuln_defs_eng}'

    elif language == 'it':
        init_prompt = f'''Sei un esperto di Cybersecurity incaricato di valutare la superficie di attacco per {name_client}. Il tuo compito è generare un capitolo di un un rapporto professionale che illustri l'analisi esterna dei risultati della superficie d'attacco.
                     Formatta la tua risposta in Markdown.
                     Assicurati che il tono sia conciso, tecnico e professionale. Usa solo # per il titolo e ## per le sottosezioni, usa - per gli elenchi. non utilizzare le tabelle'''
        if vuln_def:
            init_prompt += f'Questa è la definizione del tipo di vulnerabilità: {vuln_defs_ita}'

    elif language == 'es':
        init_prompt = f'''Eres un experto en Ciberseguridad encargado de evaluar la superficie de ataque para {name_client}. Tu trabajo es generar un cun informe profesional que detalle el análisis externo de los resultados de la superficie de fijación.
                     Formatea tu respuesta en Markdown.
                     Asegúrate de que el tono sea conciso, técnico y profesional. Utiliza solo # para el título y ## para las subsecciones, usa - para las listas. No utilice tablas.'''
        if vuln_def:
            init_prompt += f'Esta es la definición del tipo de vulnerabilidad: {vuln_defs_esp}'

    try:
        messages = [{'role': 'system', 
                     'content': init_prompt},
            {'role': 'user', 'content': prompt}]
        response = _pipeline(messages, max_new_tokens=max_new_tokens)[0]['generated_text']
        response_text = response[-1]['content']

        return response_text
    
    except Exception as e:
        st.error(f"Error generating analysis: {str(e)}")
        return "Analysis generation failed. Please try again."


@st.cache_data
def analyze_overview(total, risk_score, critical, high, medium, low, _pipe, language='en', name_client='', clear_cache = False):
    """total: int (total number of vulnerabilities)
    risk_score: int (risk score from 0 to 100)
    critical: int (number of critical vulnerabilities)
    high: int (number of high vulnerabilities)
    medium: int (number of medium vulnerabilities)
    low: int (number of low vulnerabilities)
    _pipe: transformers.pipeline
    language: str (language of the prompt selected)
    name_client: str (the name of the client)"""

    if language == 'en':
        prompt = f"""You are a cybersecurity expert generating a chapter of a professional report for {name_client}. 
        Provide a detailed analysis of the following security overview:

        - Total vulnerabilities: {total}
        - Risk score: {risk_score}/100
        - Critical vulnerabilities: {critical}
        - High vulnerabilities: {high}
        - Medium vulnerabilities: {medium}
        - Low vulnerabilities: {low}

        Your analysis should include:

        - A brief overview of the security posture and the overall risk level, with interpretation of the risk score ({risk_score}/100).
        - Considerations about the total number of vulnerabilities.
        - Detailed discussion on the breakdown of vulnerability types: Critical ({critical}), High ({high}), Medium ({medium}), Low ({low}).

        Ensure the tone is concise, technical, and professional"""

    if language == 'it':
        prompt = f"""Sei un esperto di cybersecurity che sta generando un capitolo di un report professionale per {name_client}. 
        Fornisci un'analisi dettagliata della seguente panoramica di sicurezza:

        - Vulnerabilità totali: {total}
        - Punteggio di rischio: {risk_score}/100
        - Vulnerabilità critiche: {critical}
        - Vulnerabilità alte: {high}
        - Vulnerabilità medie: {medium}
        - Vulnerabilità basse: {low}

        La tua analisi dovrebbe includere:

        - Una breve panoramica della postura di sicurezza e del livello di rischio complessivo, con interpretazione del punteggio di rischio ({risk_score}/100).
        - Considerazioni sul numero totale di vulnerabilità.
        - Discussione dettagliata sulla suddivisione dei tipi di vulnerabilità: Critiche ({critical}), Alte ({high}), Medie ({medium}), Basse ({low}).

        Assicurati che il tono sia conciso, tecnico e professionale"""

    if language == 'es':
        prompt = f"""Eres un experto en ciberseguridad que está generando un capítulo de un informe profesional para {name_client}. 
        Proporciona un análisis detallado del siguiente resumen de seguridad:

        - Vulnerabilidades totales: {total}
        - Puntuación de riesgo: {risk_score}/100
        - Vulnerabilidades críticas: {critical}
        - Vulnerabilidades altas: {high}
        - Vulnerabilidades medias: {medium}
        - Vulnerabilidades bajas: {low}

        Tu análisis debe incluir:

        - Un breve resumen del estado de seguridad y del nivel general de riesgo, con interpretación de la puntuación de riesgo ({risk_score}/100).
        - Consideraciones sobre el número total de vulnerabilidades.
        - Discusión detallada sobre la distribución de los tipos de vulnerabilidades: Críticas ({critical}), Altas ({high}), Medias ({medium}), Bajas ({low}).

        Asegúrate de que el tono sea conciso, técnico y profesional"""

    return generate_orizon_analysis(prompt, _pipe, name_client=name_client, language=language, vuln_def=True)

@st.cache_data
def analyze_severity_distribution(severity_counts, _pipe, language='en', name_client='', clear_cache = False):

    if language == 'en':
        prompt = f"""Analyze the following vulnerability severity distribution for {name_client}:

        {severity_counts.to_dict()}

        Focus on:
        - Severity distribution summary
        - Most common severity level
        - Percentage of each severity level
        - Impact of critical and high vulnerabilities
        - Urgency of remediation
        - Cumulative risk from medium and low vulnerabilities
        - Overall risk and compliance/security impact."""

    elif language == 'it':
        prompt = f"""Analizza la seguente distribuzione della gravità delle vulnerabilità per {name_client}:

        {severity_counts.to_dict()}

        Concentrati su:
        - Riepilogo della distribuzione delle gravità
        - Livello di gravità più comune
        - Percentuale di ciascun livello di gravità
        - Impatto delle vulnerabilità critiche e alte
        - Urgenza della risoluzione
        - Rischio cumulativo delle vulnerabilità medie e basse
        - Rischio complessivo e impatto su conformità/sicurezza."""

    elif language == 'es':
        prompt = f"""Analiza la siguiente distribución de severidad de vulnerabilidades para {name_client}:

        {severity_counts.to_dict()}

        Enfócate en:
        - Resumen de la distribución de severidad
        - Nivel de severidad más común
        - Porcentaje de cada nivel de severidad
        - Impacto de las vulnerabilidades críticas y altas
        - Urgencia de la remediación
        - Riesgo acumulativo de las vulnerabilidades medias y bajas
        - Riesgo general e impacto en cumplimiento/seguridad."""

    return generate_orizon_analysis(prompt, _pipe, name_client=name_client, language=language, vuln_def=True)

@st.cache_data
def analyze_top_vulnerabilities(most_common_type, common_types, hosts_affected, most_affected_host, _pipe, language='en', name_client='', clear_cache = False):
    
    if language == 'en':
        prompt = f"""Analyze the top system vulnerabilities for {name_client}:

        - Most common vulnerability: '{most_common_type}' (Frequency: {common_types.iloc[0]})
        - Affected hosts: {hosts_affected}
        - Most vulnerable host: {most_affected_host}

        Focus on:
        - Summary of prevalent types and impact.
        - Analysis of '{most_common_type}', causes, attack vectors, and consequences.
        - Affected hosts ({hosts_affected}), network impact, and lateral movement risk.
        - Why {most_affected_host} is most affected and associated risks.
        - Common themes and systemic issues."""

    elif language == 'it':
        prompt = f"""Analizza le principali vulnerabilità del sistema per {name_client}:

        - Vulnerabilità più comune: '{most_common_type}' (Frequenza: {common_types.iloc[0]})
        - Host colpiti: {hosts_affected}
        - Host più vulnerabile: {most_affected_host}

        Concentrati su:
        - Riepilogo dei tipi prevalenti e dell'impatto.
        - Analisi di '{most_common_type}', cause, vettori di attacco e conseguenze.
        - Host colpiti ({hosts_affected}), impatto sulla rete e rischio di movimento laterale.
        - Perché {most_affected_host} è il più colpito e rischi associati.
        - Temi comuni e problemi sistemici."""

    elif language == 'es':
        prompt = f"""Analiza las principales vulnerabilidades del sistema para {name_client}:

        - Vulnerabilidad más común: '{most_common_type}' (Frecuencia: {common_types.iloc[0]})
        - Hosts afectados: {hosts_affected}
        - Host más vulnerable: {most_affected_host}

        Enfócate en:
        - Resumen de los tipos prevalentes e impacto.
        - Análisis de '{most_common_type}', causas, vectores de ataque y consecuencias.
        - Hosts afectados ({hosts_affected}), impacto en la red y riesgo de movimiento lateral.
        - Por qué {most_affected_host} es el más afectado y riesgos asociados.
        - Temas comunes y problemas sistémicos."""

    return generate_orizon_analysis(prompt, _pipe, name_client=name_client, language=language, vuln_def=True)

@st.cache_data
def generate_network_analysis(top_central, density, communities, _pipe, language='en', name_client='', clear_cache = False):
    if language == 'en':
        prompt = f"""Analyze the network topology for {name_client}:

        - Central nodes: {len(top_central)}
        - Network density: {density:.4f}
        - Communities: {len(communities)}

        Focus on:
        - Network structure and complexity.
        - Role of {len(top_central)} central nodes and security implications.
        - Density {density:.4f}: impact on threat propagation and resilience.
        - Security between {len(communities)} communities.
        - Weak points, potential attack vectors, and lateral movement risk.
        - Recommendations for improving resilience, segmentation, and scalability."""

    elif language == 'it':
        prompt = f"""Analizza la topologia di rete per {name_client}:

        - Nodi centrali: {len(top_central)}
        - Densità della rete: {density:.4f}
        - Comunità: {len(communities)}

        Concentrati su:
        - Struttura e complessità della rete.
        - Ruolo dei {len(top_central)} nodi centrali e implicazioni per la sicurezza.
        - Densità {density:.4f}: impatto sulla propagazione delle minacce e resilienza.
        - Sicurezza tra le {len(communities)} comunità.
        - Punti deboli, vettori di attacco e rischio di movimento laterale.
        - Raccomandazioni per migliorare resilienza, segmentazione e scalabilità."""

    elif language == 'es':
        prompt = f"""Analiza la topología de red para {name_client}:

        - Nodos centrales: {len(top_central)}
        - Densidad de la red: {density:.4f}
        - Comunidades: {len(communities)}

        Enfócate en:
        - Estructura y complejidad de la red.
        - Rol de los {len(top_central)} nodos centrales e implicaciones de seguridad.
        - Densidad {density:.4f}: impacto en la propagación de amenazas y resiliencia.
        - Seguridad entre las {len(communities)} comunidades.
        - Puntos débiles, vectores de ataque y riesgo de movimiento lateral.
        - Recomendaciones para mejorar la resiliencia, segmentación y escalabilidad."""

    return generate_orizon_analysis(prompt, _pipe, name_client=name_client, language=language)

@st.cache_data
def analyze_cvss_distribution(avg_cvss, high_cvss_count, total_vulns, _pipe, language = 'en', name_client= '', clear_cache = False):
    if language == 'en':
        prompt = f"""Analyze the following CVSS score distribution:

    - Average CVSS score: {avg_cvss:.2f}
    - High-risk vulnerabilities (CVSS > 7.0): {high_cvss_count}
    - Total vulnerabilities: {total_vulns}

    Your analysis should include:

    - Summary of the CVSS score distribution and initial severity assessment.
    - Interpretation of {avg_cvss:.2f} average score, and security implications.
    - Analysis of {high_cvss_count} high-risk vulnerabilities, their percentage, and urgency.
    - Distribution across ranges, pattern identification, and analysis of extremes.
    - Impact of these metrics on base CVSS scores and risk assessment recommendations.
    - Organizational risk assessment, consequences of the current distribution.
    - Strategies for addressing vulnerabilities based on CVSS scores and continuous management.
    - Allocation of security resources and effort estimation by severity levels.

    Answer my question with a precise tone, use a technical and formal language suitable for a professional pdf report."""
    
    if language == 'it':
        prompt = f"""Analizza la seguente distribuzione dei punteggi CVSS:

    - Punteggio CVSS medio: {avg_cvss:.2f}
    - Vulnerabilità ad alto rischio (CVSS > 7.0): {high_cvss_count}
    - Vulnerabilità totali: {total_vulns}

    La tua analisi dovrebbe includere:

    - Riepilogo della distribuzione dei punteggi CVSS e valutazione iniziale della gravità.
    - Interpretazione del punteggio medio di {avg_cvss:.2f} e implicazioni sulla sicurezza.
    - Analisi delle {high_cvss_count} vulnerabilità ad alto rischio, la loro percentuale e l'urgenza.
    - Distribuzione nei vari intervalli, identificazione di schemi e analisi degli estremi.
    - Impatto di queste metriche sui punteggi base CVSS e raccomandazioni per la valutazione del rischio.
    - Valutazione del rischio organizzativo, conseguenze della distribuzione attuale.
    - Strategie per affrontare le vulnerabilità in base ai punteggi CVSS e gestione continua.
    - Allocazione delle risorse per la sicurezza e stima dello sforzo in base ai livelli di gravità.

    rispondi alla mia domanda con un tono preciso, utilizza un linguaggio tecnico e formale adatto per un report pdf professionale."""
    
    if language == 'es':
        prompt = f"""Analiza la siguiente distribución de puntuaciones CVSS:

    - Puntuación CVSS promedio: {avg_cvss:.2f}
    - Vulnerabilidades de alto riesgo (CVSS > 7.0): {high_cvss_count}
    - Vulnerabilidades totales: {total_vulns}

    Tu análisis debe incluir:

    - Resumen de la distribución de puntuaciones CVSS y evaluación inicial de la gravedad.
    - Interpretación de la puntuación promedio de {avg_cvss:.2f} y las implicaciones de seguridad.
    - Análisis de las {high_cvss_count} vulnerabilidades de alto riesgo, su porcentaje y urgencia.
    - Distribución en los distintos rangos, identificación de patrones y análisis de los extremos.
    - Impacto de estas métricas en las puntuaciones base de CVSS y recomendaciones para la evaluación de riesgos.
    - Evaluación del riesgo organizacional y consecuencias de la distribución actual.
    - Estrategias para abordar las vulnerabilidades basadas en las puntuaciones CVSS y la gestión continua.
    - Asignación de recursos de seguridad y estimación del esfuerzo según los niveles de gravedad.

    Responda a mi pregunta con un tono preciso, use un lenguaje técnico y formal adecuado para un informe PDF profesional."""
    return generate_orizon_analysis(prompt, _pipe, name_client=name_client, language=language)

@st.cache_data
def analyze_vulnerability_types(most_common_type, frequency, top_10_types, _pipe, language='en', name_client='', clear_cache = False):
    if language == 'en':
        prompt = f"""Analyze the following vulnerability type distribution for {name_client}:

        - Most common type: '{most_common_type}' (Frequency: {frequency})
        - Top 10 types: {', '.join(top_10_types)}

        Focus on:
        - Summary of type distribution and initial security challenge assessment.
        - Detailed analysis of '{most_common_type}', including causes, attack vectors, and impact.
        - Brief description of each type, distribution analysis, and identification of patterns.
        - Evaluation of overall risk from the type distribution and interaction effects.
        
        Avoid providing any mitigation strategies or security recommendations."""

    elif language == 'it':
        prompt = f"""Analizza la seguente distribuzione dei tipi di vulnerabilità per {name_client}:

        - Tipo più comune: '{most_common_type}' (Frequenza: {frequency})
        - I 10 tipi principali: {', '.join(top_10_types)}

        Concentrati su:
        - Riepilogo della distribuzione dei tipi e valutazione iniziale delle sfide di sicurezza.
        - Analisi dettagliata di '{most_common_type}', inclusi cause, vettori d'attacco e impatto.
        - Breve descrizione di ciascun tipo, analisi della distribuzione e identificazione di schemi.
        - Valutazione del rischio complessivo derivante dalla distribuzione dei tipi e dagli effetti di interazione.
        
        Evita di fornire strategie di mitigazione o raccomandazioni di sicurezza."""

    elif language == 'es':
        prompt = f"""Analiza la siguiente distribución de tipos de vulnerabilidad para {name_client}:

        - Tipo más común: '{most_common_type}' (Frecuencia: {frequency})
        - Los 10 principales tipos: {', '.join(top_10_types)}

        Enfócate en:
        - Resumen de la distribución de tipos y evaluación inicial de los desafíos de seguridad.
        - Análisis detallado de '{most_common_type}', incluidas causas, vectores de ataque e impacto.
        - Breve descripción de cada tipo, análisis de la distribución e identificación de patrones.
        - Evaluación del riesgo general derivado de la distribución de tipos y efectos de interacción.
        
        Evita proporcionar estrategias de mitigación o recomendaciones de seguridad."""

    return generate_orizon_analysis(prompt, _pipe, name_client=name_client, language=language)

@st.cache_data
def analyze_geolocation(countries, cities, ip_top5, countries_top5, cities_top5, hosts_top5, _pipe, language='en', name_client='', clear_cache = False):
    if language == 'en':
        prompt = f"""Analyze the geolocation data for {name_client}:

        General Distribution:
        - Countries: {countries}
        - Cities: {cities}

        Top 5 Vulnerable Hosts:
        - Hosts: {hosts_top5}
        - IPs: {ip_top5}
        - Countries: {countries_top5}
        - Cities: {cities_top5}

        Focus on:
        - Summary of host distribution.
        - Geolocation of top 5 vulnerable hosts.
        - Any patterns or correlations between location and vulnerability.

        Avoid mitigations, focus on analysis only."""

    elif language == 'it':
        prompt = f"""Analizza i dati di geolocalizzazione per {name_client}:

        Distribuzione Generale:
        - Paesi: {countries}
        - Città: {cities}

        I 5 Host Più Vulnerabili:
        - Host: {hosts_top5}
        - IP: {ip_top5}
        - Paesi: {countries_top5}
        - Città: {cities_top5}

        Concentrati su:
        - Riepilogo della distribuzione degli host.
        - Geolocalizzazione dei 5 host più vulnerabili.
        - Schemi o correlazioni tra posizione e vulnerabilità.

        Evita mitigazioni, concentrati solo sull'analisi."""

    elif language == 'es':
        prompt = f"""Analiza los datos de geolocalización para {name_client}:

        Distribución General:
        - Países: {countries}
        - Ciudades: {cities}

        Los 5 Hosts Más Vulnerables:
        - Hosts: {hosts_top5}
        - IPs: {ip_top5}
        - Países: {countries_top5}
        - Ciudades: {cities_top5}

        Enfócate en:
        - Resumen de la distribución de hosts.
        - Geolocalización de los 5 hosts más vulnerables.
        - Patrones o correlaciones entre ubicación y vulnerabilidad.

        Evita mitigaciones, enfócate solo en el análisis."""

    return generate_orizon_analysis(prompt, _pipe, name_client=name_client, language=language)

@st.cache_data
def analyze_bash_results(urls: list, bash_results: list, _pipe, language = 'en', name_client = '', clear_cache = False):
    if language == 'en':
        prompt = f"""Analyze the results obtained from the commands executed in the bash terminal to verify vulnerabilities:
                    host: {urls}
                    bash terminal: {bash_results}"""
  
    if language == 'it':
        prompt = f"""Analizza i risultati ottenuti a partire dai comandi eseguiti a terminale bash per verificare le vurnerabilità:
                    host: {urls}
                    bash terminal: {bash_results} """

    if language == 'es':
        prompt = f"""Analiza los resultados obtenidos de los comandos ejecutados en el terminal bash para verificar vulnerabilidades:
                    host: {urls}
                    terminal bash: {bash_results}"""

    return generate_orizon_analysis(prompt, _pipe, name_client=name_client, language=language)