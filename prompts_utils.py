import streamlit as st

@st.cache_data
def generate_orizon_analysis(prompt, _pipeline, max_new_tokens=100000):

    try:
        messages = [{'role': 'system', 'content': 'You are a Cybersecurity expert, i need your help to evaluate an attack surface. Please format all your responses in Markdown and use a professional, concise, and technical style suitable for a professional report.'},
            {'role': 'user', 'content': prompt}]
        response = _pipeline(messages, max_new_tokens=max_new_tokens)[0]['generated_text']
        response_text = response[-1]['content']

        return response_text
    
    except Exception as e:
        st.error(f"Error generating analysis: {str(e)}")
        return "Analysis generation failed. Please try again."


@st.cache_data
def analyze_overview(total, risk_score, critical, high, medium, low, _pipe, language = 'en'):

    if language == 'en':
        prompt = f"""Provide a detailed analysis of the following security overview:

    - Total vulnerabilities: {total}
    - Risk score: {risk_score}/100
    - Critical vulnerabilities: {critical}
    - High vulnerabilities: {high}
    - Medium vulnerabilities: {medium}
    - Low vulnerabilities: {low}

    Your analysis should cover:

    - Brief overview of the security posture and overall risk level with interpretation of the risk score: {risk_score}/100.
    - Considerations about the total ammount of vulnerabilities.
    - Considerations about the different counts of types of vulnerabilites critical: {critical}, high: {high}, medium: {medium}, low: {low}

    Answer my question with a precise tone, use a technical and formal language suitable for a professional pdf report."""
        
    if language == 'it':
        prompt = f"""Fornisci un'analisi dettagliata della seguente panoramica di sicurezza:

    - Vulnerabilità totali: {total}
    - Punteggio di rischio: {risk_score}/100
    - Vulnerabilità critiche: {critical}
    - Vulnerabilità alte: {high}
    - Vulnerabilità medie: {medium}
    - Vulnerabilità basse: {low}

    La tua analisi dovrebbe coprire:

    - Breve panoramica della postura di sicurezza e del livello di rischio complessivo con un'interpretazione del punteggio di rischio: {risk_score}/100.
    - Considerazioni sul numero totale di vulnerabilità.
    - Considerazioni sui diversi tipi di vulnerabilità con i rispettivi conteggi: critiche: {critical}, alte: {high}, medie: {medium}, basse: {low}.
    
    rispondi alla mia domanda con un tono preciso, utilizza un linguaggio tecnico e formale adatto per un report pdf professionale."""
    
    if language == 'es':
        prompt = f"""Proporciona un análisis detallado del siguiente resumen de seguridad:

    - Vulnerabilidades totales: {total}
    - Puntuación de riesgo: {risk_score}/100
    - Vulnerabilidades críticas: {critical}
    - Vulnerabilidades altas: {high}
    - Vulnerabilidades medias: {medium}
    - Vulnerabilidades bajas: {low}

    Tu análisis debe cubrir:

    - Resumen breve del estado de seguridad y del nivel general de riesgo con una interpretación de la puntuación de riesgo: {risk_score}/100.
    - Consideraciones sobre la cantidad total de vulnerabilidades.
    - Consideraciones sobre los diferentes tipos de vulnerabilidades: críticas: {critical}, altas: {high}, medias: {medium}, bajas: {low}.
    
    Responda a mi pregunta con un tono preciso, use un lenguaje técnico y formal adecuado para un informe PDF profesional."""
        
    return generate_orizon_analysis(prompt, _pipe)

@st.cache_data
def analyze_severity_distribution(severity_counts, _pipe, language = 'en'):

    if language == 'en':
        prompt = f"""Provide an analysis of the following vulnerability severity distribution:

    {severity_counts.to_dict()}

    Your analysis should cover:
    - Summary of severity distribution
    - Most prevalent severity level
    - Percentage of each severity level
    - High (critical + high) vs. low (medium + low) severity ratio
    - Impact of critical and high vulnerabilities
    - Urgency of remediation
    - Cumulative risk of medium and low vulnerabilities
    - Importance of addressing alongside high-priority items
    - Overall risk from current distribution
    - Potential compliance/security impact

    Answer my question with a precise tone, use a technical and formal language suitable for a professional pdf report."""
        
    if language == 'it':
        prompt = f"""Fornisci un'analisi della seguente distribuzione della gravità delle vulnerabilità:

    {severity_counts.to_dict()}

    La tua analisi dovrebbe coprire:
    - Riepilogo della distribuzione delle gravità
    - Livello di gravità più diffuso
    - Percentuale di ciascun livello di gravità
    - Rapporto tra gravità alta (critica + alta) e bassa (media + bassa)
    - Impatto delle vulnerabilità critiche e alte
    - Urgenza della risoluzione
    - Rischio cumulativo delle vulnerabilità medie e basse
    - Importanza di affrontare insieme agli elementi ad alta priorità
    - Rischio complessivo derivante dalla distribuzione attuale
    - Potenziali impatti su conformità/sicurezza

    rispondi alla mia domanda con un tono preciso, utilizza un linguaggio tecnico e formale adatto per un report pdf professionale."""
    
    if language == 'es':
        prompt = f"""Proporciona un análisis de la siguiente distribución de severidad de vulnerabilidades:

    {severity_counts.to_dict()}

    Tu análisis debe cubrir:
    - Resumen de la distribución de severidad
    - Nivel de severidad más prevalente
    - Porcentaje de cada nivel de severidad
    - Relación entre severidad alta (crítica + alta) y baja (media + baja)
    - Impacto de las vulnerabilidades críticas y altas
    - Urgencia de la remediación
    - Riesgo acumulativo de las vulnerabilidades medias y bajas
    - Importancia de abordarlas junto a los elementos de alta prioridad
    - Riesgo general de la distribución actual
    - Potencial impacto en el cumplimiento/la seguridad

    Responda a mi pregunta con un tono preciso, use un lenguaje técnico y formal adecuado para un informe PDF profesional."""
        
    return generate_orizon_analysis(prompt, _pipe)

@st.cache_data
def analyze_top_vulnerabilities(most_common_type, common_types, hosts_affected, most_affected_host, _pipe, language = 'en'):
    
    if language == 'en':
        prompt = f"""Provide an in-depth analysis of the system's top vulnerabilities:

    - Most common vulnerability: '{most_common_type}' (Frequency: {common_types.iloc[0]})
    - Affected hosts: {hosts_affected}
    - Most vulnerable host: {most_affected_host}

    Your analysis should cover:
    - Summary of prevalent types and potential impact.
    - Description of '{most_common_type}', causes, attack vectors, and potential consequences.
    - Analysis of affected hosts ({hosts_affected}), percentage of network affected, and risk of lateral movement.
    - Examination of why {most_affected_host} is most affected, associated risks.
    - Identification of common themes, correlations, and systemic issues.

    Answer my question with a precise tone, use a technical and formal language suitable for a professional pdf report.
    """
        
    if language == 'it':
        prompt = f"""Fornisci un'analisi approfondita delle principali vulnerabilità del sistema:

    - Vulnerabilità più comune: '{most_common_type}' (Frequenza: {common_types.iloc[0]})
    - Host colpiti: {hosts_affected}
    - Host più vulnerabile: {most_affected_host}

    La tua analisi dovrebbe coprire:
    - Riepilogo dei tipi prevalenti e del potenziale impatto.
    - Descrizione di '{most_common_type}', cause, vettori di attacco e conseguenze potenziali.
    - Analisi degli host colpiti ({hosts_affected}), percentuale della rete interessata e rischio di movimento laterale.
    - Esame del motivo per cui {most_affected_host} è il più colpito, rischi associati.
    - Identificazione di temi comuni, correlazioni e problemi sistemici.
    
    rispondi alla mia domanda con un tono preciso, utilizza un linguaggio tecnico e formale adatto per un report pdf professionale."""
    
    if language == 'es':
        prompt = f"""Proporciona un análisis detallado de las principales vulnerabilidades del sistema:

    - Vulnerabilidad más común: '{most_common_type}' (Frecuencia: {common_types.iloc[0]})
    - Hosts afectados: {hosts_affected}
    - Host más vulnerable: {most_affected_host}

    Tu análisis debe cubrir:
    - Resumen de los tipos prevalentes y el impacto potencial.
    - Descripción de '{most_common_type}', causas, vectores de ataque y posibles consecuencias.
    - Análisis de los hosts afectados ({hosts_affected}), porcentaje de la red afectada y riesgo de movimiento lateral.
    - Examen de por qué {most_affected_host} es el más afectado, riesgos asociados.
    - Identificación de temas comunes, correlaciones y problemas sistémicos.
    
    Responda a mi pregunta con un tono preciso, use un lenguaje técnico y formal adecuado para un informe PDF profesional."""

    return generate_orizon_analysis(prompt, _pipe)

@st.cache_data
def generate_network_analysis(top_central, density, communities, _pipe, language = 'en'):
    if language == 'en':

        prompt = f"""Analyze the following network topology:

    - Central nodes: {len(top_central)}
    - Network density: {density:.4f}
    - Identified communities: {len(communities)}

    Provide an analysis including:
    - Summary of network structure and complexity.
    - Role and security implications of {len(top_central)} central nodes.
    - Protection and monitoring recommendations.
    - Interpretation of density {density:.4f} and its impact on threat propagation and resilience.
    - Comparison to ideal security and performance ranges.
    - Significance of {len(communities)} communities.
    - Security implications and inter-community measures.
    - Identification of weak points, potential attack vectors, and lateral movement risk.
    - Assessment of network resilience, redundancy, and recommendations for improvement.
    - Evaluation of current segmentation and optimization suggestions.
    - Potential for zero trust architecture implementation.
    - Impact of topology on traffic patterns, bottlenecks, and monitoring recommendations.
    - Network's scalability and security challenges with growth.
    - Scalable security architecture recommendations.
    - Prioritized actions to enhance security and redesign problematic areas.
    - Key metrics, reassessment frequency, and automated tools for continuous analysis.

    Answer my question with a precise tone, use a technical and formal language suitable for a professional pdf report."""
    
    if language == 'it':
        prompt = f"""Analizza la seguente topologia di rete:

    - Nodi centrali: {len(top_central)}
    - Densità della rete: {density:.4f}
    - Comunità identificate: {len(communities)}

    Fornisci un'analisi che includa:
    - Riepilogo della struttura e complessità della rete.
    - Ruolo e implicazioni per la sicurezza dei {len(top_central)} nodi centrali.
    - Raccomandazioni per la protezione e il monitoraggio.
    - Interpretazione della densità {density:.4f} e il suo impatto sulla propagazione delle minacce e la resilienza.
    - Confronto con intervalli ideali di sicurezza e prestazioni.
    - Significato delle {len(communities)} comunità.
    - Implicazioni di sicurezza e misure inter-comunità.
    - Identificazione dei punti deboli, vettori di attacco potenziali e rischio di movimento laterale.
    - Valutazione della resilienza della rete, ridondanza e raccomandazioni per miglioramenti.
    - Valutazione della segmentazione attuale e suggerimenti per l'ottimizzazione.
    - Potenziale per l'implementazione di un'architettura zero trust.
    - Impatto della topologia sui modelli di traffico, colli di bottiglia e raccomandazioni per il monitoraggio.
    - Scalabilità della rete e sfide di sicurezza con la crescita.
    - Raccomandazioni per un'architettura di sicurezza scalabile.
    - Azioni prioritarie per migliorare la sicurezza e riprogettare aree problematiche.
    - Metriche chiave, frequenza di rivalutazione e strumenti automatizzati per l'analisi continua.

    rispondi alla mia domanda con un tono preciso, utilizza un linguaggio tecnico e formale adatto per un report pdf professionale."""
        
    if language == 'es':
        prompt = f"""Analiza la siguiente topología de red:

    - Nodos centrales: {len(top_central)}
    - Densidad de la red: {density:.4f}
    - Comunidades identificadas: {len(communities)}

    Proporciona un análisis que incluya:
    - Resumen de la estructura y complejidad de la red.
    - Rol e implicaciones para la seguridad de los {len(top_central)} nodos centrales.
    - Recomendaciones para la protección y el monitoreo.
    - Interpretación de la densidad {density:.4f} y su impacto en la propagación de amenazas y la resiliencia.
    - Comparación con rangos ideales de seguridad y rendimiento.
    - Significado de las {len(communities)} comunidades.
    - Implicaciones de seguridad y medidas entre comunidades.
    - Identificación de puntos débiles, vectores de ataque potenciales y riesgo de movimiento lateral.
    - Evaluación de la resiliencia de la red, redundancia y recomendaciones para mejoras.
    - Evaluación de la segmentación actual y sugerencias para la optimización.
    - Potencial para la implementación de una arquitectura de confianza cero (zero trust).
    - Impacto de la topología en los patrones de tráfico, cuellos de botella y recomendaciones de monitoreo.
    - Escalabilidad de la red y desafíos de seguridad con el crecimiento.
    - Recomendaciones para una arquitectura de seguridad escalable.
    - Acciones prioritarias para mejorar la seguridad y rediseñar áreas problemáticas.
    - Métricas clave, frecuencia de reevaluación y herramientas automatizadas para el análisis continuo.

    Responda a mi pregunta con un tono preciso, use un lenguaje técnico y formal adecuado para un informe PDF profesional."""
    
    return generate_orizon_analysis(prompt, _pipe)

@st.cache_data
def analyze_cvss_distribution(avg_cvss, high_cvss_count, total_vulns, _pipe, language = 'en'):
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
    return generate_orizon_analysis(prompt, _pipe)

@st.cache_data
def analyze_vulnerability_types(most_common_type, frequency, top_10_types, _pipe, language = 'en'):
    if language == 'en':
        prompt = f"""Analyze the following vulnerability type distribution:

    - Most common type: '{most_common_type}' (Frequency: {frequency})
    - Top 10 types: {', '.join(top_10_types)}

    Your analysis should include:

    - Summary of type distribution and initial security challenge assessment.
    - Description of '{most_common_type}', causes, attack vectors, impact.
    - Brief description of each, distribution analysis, and pattern identification.
    - Evaluation of overall risk from the type distribution and interaction effects.
    - Suggestions for improving security controls and mitigating multiple types.

    Answer my question with a precise tone, use a technical and formal language suitable for a professional pdf report."""
  
    if language == 'it':
        prompt = f"""Analizza la seguente distribuzione dei tipi di vulnerabilità:

    - Tipo più comune: '{most_common_type}' (Frequenza: {frequency})
    - I 10 tipi principali: {', '.join(top_10_types)}

    La tua analisi dovrebbe includere:

    - Riepilogo della distribuzione dei tipi e valutazione iniziale delle sfide di sicurezza.
    - Descrizione di '{most_common_type}', cause, vettori d'attacco, impatto.
    - Breve descrizione di ciascun tipo, analisi della distribuzione e identificazione di schemi.
    - Valutazione del rischio complessivo derivante dalla distribuzione dei tipi e dagli effetti di interazione.
    - Suggerimenti per migliorare i controlli di sicurezza e mitigare più tipi di vulnerabilità.

    rispondi alla mia domanda con un tono preciso, utilizza un linguaggio tecnico e formale adatto per un report pdf professionale."""

    if language == 'es':
        prompt = f"""Analiza la siguiente distribución de tipos de vulnerabilidad:

    - Tipo más común: '{most_common_type}' (Frecuencia: {frequency})
    - Los 10 principales tipos: {', '.join(top_10_types)}

    Tu análisis debe incluir:

    - Resumen de la distribución de tipos y evaluación inicial de los desafíos de seguridad.
    - Descripción de '{most_common_type}', causas, vectores de ataque, impacto.
    - Breve descripción de cada tipo, análisis de la distribución e identificación de patrones.
    - Evaluación del riesgo general derivado de la distribución de tipos y efectos de interacción.
    - Sugerencias para mejorar los controles de seguridad y mitigar múltiples tipos de vulnerabilidades.

    Responda a mi pregunta con un tono preciso, use un lenguaje técnico y formal adecuado para un informe PDF profesional."""

    return generate_orizon_analysis(prompt, _pipe)

@st.cache_data
def analyze_geolocation(countries, cities, ip_top5, countries_top5, cities_top5, hosts_top5, _pipe, language = 'en'):
    if language == 'en':
        prompt = f"""Analyze the geolocation data for our hosts and provide a comprehensive report. Focus on two main aspects: general distribution and top 5 vulnerable hosts.

                    General Distribution Analysis
                    Data provided:
                    - Countries with hosts: {countries}
                    - Cities with hosts: {cities}

                    Your analysis should include:
                    a) A concise summary of our hosts' global distribution
                    b) An organized list of countries and cities where our hosts are located

                    Top 5 Vulnerable Hosts Analysis
                    Data provided:
                    - Hosts with highest vulnerability scores: {hosts_top5}
                    - IP addresses with highest vulnerability scores: {ip_top5}
                    - Countries with highest vulnerability scores: {countries_top5}
                    - Cities with highest vulnerability scores: {cities_top5}

                    Your analysis should include:
                    a) A detailed summary of the geolocation of our most vulnerable hosts
                    b) Any notable patterns or correlations between location and vulnerability

                    Presentation Guidelines
                    - Use a precise and professional tone
                    - Employ technical and formal language suitable for a professional PDF report
                    - Organize information logically, using headings and subheadings where appropriate
                    - Include any relevant statistics or percentages to support your analysis

                    Please provide a comprehensive analysis based on the data and guidelines provided above."""
  
    if language == 'it':
        prompt = f"""Analizza i dati di geolocalizzazione dei nostri host e fornisci un report completo. Concentrati su due aspetti principali: distribuzione generale e i 5 host più vulnerabili.

                    Analisi della Distribuzione Generale
                    Dati forniti:
                    - Paesi con host: {countries}
                    - Città con host: {cities}

                    La tua analisi dovrebbe includere:
                    a) Un riassunto conciso della distribuzione globale dei nostri host
                    b) Un elenco organizzato di paesi e città in cui si trovano i nostri host

                    Analisi dei 5 Host Più Vulnerabili
                    Dati forniti:
                    - Host con i punteggi di vulnerabilità più alti: {hosts_top5}
                    - Indirizzi IP con i punteggi di vulnerabilità più alti: {ip_top5}
                    - Paesi con i punteggi di vulnerabilità più alti: {countries_top5}
                    - Città con i punteggi di vulnerabilità più alti: {cities_top5}

                    La tua analisi dovrebbe includere:
                    a) Un riassunto dettagliato della geolocalizzazione dei nostri host più vulnerabili
                    b) Qualsiasi schema o correlazione significativa tra la posizione e la vulnerabilità

                    Linee Guida per la Presentazione
                    - Utilizza un tono preciso e professionale
                    - Impiega un linguaggio tecnico e formale adatto a un report professionale in formato PDF
                    - Organizza le informazioni in modo logico, utilizzando intestazioni e sottosezioni dove appropriato
                    - Includi eventuali statistiche o percentuali rilevanti a supporto della tua analisi

                    Si prega di fornire un'analisi completa basata sui dati e le linee guida sopra indicate."""

    if language == 'es':
        prompt = f"""Analiza los datos de geolocalización de nuestros hosts y proporciona un informe completo. Enfócate en dos aspectos principales: distribución general y los 5 hosts más vulnerables.

                    Análisis de Distribución General
                    Datos proporcionados:
                    - Países con hosts: {countries}
                    - Ciudades con hosts: {cities}

                    Tu análisis debe incluir:
                    a) Un resumen conciso de la distribución global de nuestros hosts
                    b) Una lista organizada de países y ciudades donde se encuentran nuestros hosts

                    Análisis de los 5 Hosts Más Vulnerables
                    Datos proporcionados:
                    - Hosts con las puntuaciones de vulnerabilidad más altas: {hosts_top5}
                    - Direcciones IP con las puntuaciones de vulnerabilidad más altas: {ip_top5}
                    - Países con las puntuaciones de vulnerabilidad más altas: {countries_top5}
                    - Ciudades con las puntuaciones de vulnerabilidad más altas: {cities_top5}

                    Tu análisis debe incluir:
                    a) Un resumen detallado de la geolocalización de nuestros hosts más vulnerables
                    b) Cualquier patrón o correlación notable entre la ubicación y la vulnerabilidad

                    Directrices de Presentación
                    - Utiliza un tono preciso y profesional
                    - Emplea un lenguaje técnico y formal adecuado para un informe profesional en PDF
                    - Organiza la información de manera lógica, usando encabezados y subtítulos cuando sea necesario
                    - Incluye cualquier estadística o porcentaje relevante para respaldar tu análisis

                    Por favor, proporciona un análisis completo basado en los datos y directrices proporcionados anteriormente."""

    return generate_orizon_analysis(prompt, _pipe)