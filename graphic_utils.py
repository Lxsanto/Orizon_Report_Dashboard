import streamlit as st
import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import plotly.io as pio
from wordcloud import WordCloud
from matplotlib.colors import LinearSegmentedColormap
from icecream import ic

# Define brand kit colors
kelly_green = "#4AC300"
mariana_blue = "#002430"
burnt_red = "#E5625E"
dodger_blue = "#2191FB"
dawn_mist = "#DBE2E9"
simple_white = "#FFFFFF"
sunglow = "#FFC857"

# Plotly configuration
# For more information on Plotly templates, visit:
# https://plotly.com/python/templates/
template = pio.templates['ggplot2']
pio.templates.default = 'ggplot2'

# Customize the template
# Font settings
template.layout.font.family = "Gill Sans, sans-serif"
template.layout.font.size = 12
template.layout.font.color = mariana_blue
template.layout.title.font.size = 20
template.layout.xaxis.title.font.size = 16
template.layout.yaxis.title.font.size = 16

# Background and grid colors
template.layout.paper_bgcolor = simple_white
template.layout.plot_bgcolor = dawn_mist
template.layout.xaxis.gridcolor = simple_white
template.layout.xaxis.linecolor = mariana_blue
template.layout.xaxis.tickcolor = mariana_blue
template.layout.yaxis.gridcolor = simple_white
template.layout.yaxis.linecolor = mariana_blue
template.layout.yaxis.tickcolor = mariana_blue

# Define custom color palette
colors = [kelly_green, dodger_blue, burnt_red, mariana_blue]
template.layout.colorway = colors

# Set the custom template as default
pio.templates["Orizon_template"] = template
pio.templates.default = "Orizon_template"

# Default chart dimensions
_width = 800 
_height = 600

@st.cache_data
def create_risk_score_gauge(risk_score):
    """
    Create a gauge chart to display the risk score.

    This function uses Plotly to generate a gauge chart. The color of the gauge
    changes based on the risk score value.

    Args:
        risk_score (float): The risk score to be displayed (0-100).

    Returns:
        go.Figure: A Plotly figure object containing the gauge chart.

    For more information on Plotly gauge charts, visit:
    https://plotly.com/python/gauge-charts/
    """
    # Determine gauge color based on risk_score
    if 20 < risk_score < 60:
        gauge_color = sunglow
    elif risk_score >= 60:
        gauge_color = burnt_red
    else:
        gauge_color = kelly_green
    
    # Create the gauge chart
    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=risk_score,
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': "Risk Score", 'font': {'size': 20}},
            gauge={
                'bar': {'color': gauge_color},
                'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': mariana_blue}
            }
        ),
        layout=go.Layout(
            width=_width,
            height=_height,
            font={'color': mariana_blue}
        )
    )
    
    return fig

def pie(severity_counts):
    """
    Create a pie chart to display vulnerability severity distribution.

    This function uses Plotly to generate a pie chart with a 3D effect.

    Args:
        severity_counts (pd.Series): A pandas Series containing severity levels as index and counts as values.

    Returns:
        go.Figure: A Plotly figure object containing the pie chart.

    For more information on Plotly pie charts, visit:
    https://plotly.com/python/pie-charts/
    """
    if 'critical' in severity_counts.keys():
        ic(severity_counts['critical'])
        
    fig_severity = go.Figure(data=[go.Pie(
        labels=severity_counts.index,
        values=severity_counts.values,
        textinfo='percent+label',
        textposition='inside',
        hole=0.3,
        pull=[0.1] * len(severity_counts),  # Creates the exploded effect
        marker=dict(colors=severity_counts.index),
    )])

    fig_severity.update_layout(
        title_text="Vulnerability Severity Distribution",
        title_x=0.5,  # Center the title
        width=_width,
        height=_height,
        scene=dict(
            xaxis_title='',
            yaxis_title='',
            zaxis_title='',
            aspectmode='manual',
            aspectratio=dict(x=1, y=1, z=0.5)  # Gives a 3D effect
        ),
        showlegend=True,
        legend=dict(orientation="h", yanchor="bottom", y=-0.1, xanchor="center", x=0.5)
    )

    fig_severity.update_traces(
        textfont_size=12,
        marker=dict(line=dict(color='#000000', width=2))  # Add a black outline to each slice
    )

    return fig_severity

def top10_vuln_hist(vuln_types: pd.DataFrame):
    """
    Create a bar chart to display the top 10 vulnerability types.

    This function uses Plotly Express to generate a bar chart.

    Args:
        vuln_types (pd.DataFrame): A pandas DataFrame containing vulnerability types and their counts.

    Returns:
        px.Bar: A Plotly Express bar chart object.

    For more information on Plotly Express bar charts, visit:
    https://plotly.com/python/bar-charts/
    """
    fig = px.bar(
        width=_width,
        height=_height,
        x=vuln_types.index, 
        y=vuln_types.values, 
        title="Top 10 Vulnerability Types",
        labels={'x': 'Vulnerability Type', 'y': 'Count'}
    )

    return fig

def worldcloud(tag_counts: pd.Series):
    """
    Create a word cloud image based on tag counts.

    This function uses the WordCloud library to generate a word cloud image
    with a custom color map based on the brand colors.

    Args:
        tag_counts (pd.Series): A pandas Series containing tags as index and their counts as values.

    Returns:
        PIL.Image.Image: A PIL Image object containing the word cloud.

    For more information on the WordCloud library, visit:
    https://amueller.github.io/word_cloud/
    """
    colors = [kelly_green, dodger_blue, burnt_red, mariana_blue]
    n_bins = len(colors)
    cmap_name = 'brand_colors'
    cm = LinearSegmentedColormap.from_list(cmap_name, colors, N=n_bins)

    wordcloud_ = WordCloud(width=_width, height=_height, 
                        background_color='white', 
                        max_font_size=300, 
                        scale=3, 
                        relative_scaling=0.5, 
                        collocations=False, 
                        colormap=cm).generate_from_frequencies(tag_counts)

    cloud_img = wordcloud_.to_image()

    return cloud_img

def create_plotly_map(risk_by_ip):
    """
    Create a world map with markers indicating server locations and risk scores.

    This function uses Plotly to generate a scatter geo plot on a world map.

    Args:
        risk_by_ip (pd.DataFrame): A pandas DataFrame containing IP information including latitude, longitude, country, city, and normalized risk score.

    Returns:
        go.Figure: A Plotly figure object containing the world map with markers.

    For more information on Plotly geo maps, visit:
    https://plotly.com/python/map-configuration/
    """
    # Group by location and get the maximum risk score for each location
    location_risk = risk_by_ip.groupby(['latitude', 'longitude', 'country', 'city'])['normalized_risk_score'].max().reset_index()

    latitudes = location_risk['latitude']
    longitudes = location_risk['longitude']
    texts = []
    sizes = []

    max_score = location_risk['normalized_risk_score'].max()
    min_score = location_risk['normalized_risk_score'].min()

    for index, row in location_risk.iterrows():
        country = row['country']
        city = row['city']
        score = row['normalized_risk_score']
        
        texts.append(f"Location: {city}, {country}<br>Max Risk Score: {score:.2f}")

        if max_score == min_score:
            size = 5 + (score - min_score) * 25
        else:
            # Calculate the size based on the normalized risk score
            size = 5 + (score - min_score) / (max_score - min_score) * 25

        sizes.append(size)
    
    # Create the scattergeo plot with markers
    fig = go.Figure(go.Scattergeo(
        lon = longitudes,
        lat = latitudes,
        text = texts,
        mode = 'markers',
        marker = dict(
            size = sizes,
            color = 'rgba(229, 98, 94, 0.7)',  
            symbol = 'circle',
            line = dict(width=1, color='rgba(229, 98, 94, 0.7)')
        )
    ))

    # Update the layout of the map
    fig.update_layout(
        title = 'Geolocation of Company Servers (Aggregated by Location)',
        showlegend = False,
        geo = dict(
            scope = 'world',
            showland = True,
            landcolor = "rgb(230, 230, 230)",
            countrycolor = "rgb(204, 204, 204)",
            coastlinecolor = "rgb(204, 204, 204)",
            projection_type='natural earth',
        ),
        margin=dict(l=0, r=0, t=50, b=0),
        paper_bgcolor='white',
    )

    return fig

def create_country_bubble_plot(risk_by_ip: pd.DataFrame):
    """
    Create a bubble plot showing country IP distribution by risk level.

    This function uses Plotly to generate a scatter plot with bubbles representing countries,
    where the size of the bubble indicates the number of IPs and the color represents the risk level.

    Args:
        risk_by_ip (pd.DataFrame): A pandas DataFrame containing IP information including country and normalized risk score.

    Returns:
        go.Figure: A Plotly figure object containing the bubble plot.

    For more information on Plotly scatter plots, visit:
    https://plotly.com/python/bubble-charts/
    """
    # Define color palette
    color_palette = {
        "kelly_green": "#4AC300",
        "mariana_blue": "#002430",
        "burnt_red": "#E5625E",
        "dodger_blue": "#2191FB",
        "dawn_mist": "#DBE2E9",
        "simple_white": "#FFFFFF",
        "sunglow": "#FFC857"
    }

    # Group by country and count IPs
    country_data = risk_by_ip.groupby('country').agg({
        'ip': 'count',
        'normalized_risk_score': 'mean'
    }).reset_index()

    #print(country_data)

    country_data = country_data.dropna(axis=0)

    # Calculate bubble sizes
    max_size = 150  # Maximum bubble size
    min_size = 20   # Minimum bubble size
    if country_data['ip'].max() == country_data['ip'].min():
        country_data['bubble_size'] = max_size // 2
    else:
        country_data['bubble_size'] = (country_data['ip'] - country_data['ip'].min()) / (country_data['ip'].max() - country_data['ip'].min()) * (max_size - min_size) + min_size

    # Generate positions for bubbles
    def generate_positions(n, k=0.5):
        positions = []
        phi = (1 + 5**0.5) / 2  # Golden ratio
        for i in range(n):
            r = i**0.5 / n**0.5
            theta = 2 * np.pi * i / phi**2
            x = r * np.cos(theta)
            y = r * np.sin(theta)
            positions.append((k*x, k*y))
        return positions

    positions = generate_positions(len(country_data))
    x, y = zip(*positions)

    # Create custom colorscale
    colorscale = [
        [0, color_palette["dawn_mist"]],
        [0.25, color_palette["kelly_green"]],
        [0.5, color_palette["dodger_blue"]],
        [0.75, color_palette["sunglow"]],
        [1, color_palette["burnt_red"]]
    ]

    # Create bubbles
    bubbles = go.Scatter(
        x=x,
        y=y,
        mode='markers+text',
        text=country_data['country'],
        marker=dict(
            size=country_data['bubble_size'],
            color=country_data['normalized_risk_score'],
            colorscale=colorscale,
            line=dict(width=2, color=color_palette["simple_white"])
        ),
        textfont=dict(size=10, color=color_palette["mariana_blue"]),
        hoverinfo='text',
        hovertext=[f"{country}<br>IPs: {ip_count}<br>Avg Risk: {risk:.2f}" 
                   for country, ip_count, risk in zip(country_data['country'], country_data['ip'], country_data['normalized_risk_score'])],
        showlegend=False
    )

    # Create legend traces with correct colors
    legend_traces = []
    risk_levels = ["Very Low", "Low", "Medium", "High", "Very High"]
    for i, level in enumerate(risk_levels):
        color = colorscale[i][1]
        legend_traces.append(go.Scatter(
            x=[None], y=[None],
            mode='markers',
            marker=dict(size=12, color=color, symbol='circle'),
            name=f"{level} Risk",
            legendgroup=level,
            showlegend=True
        ))

    # Layout
    layout = go.Layout(
        title=dict(
            text='Country IP Distribution by Risk Level',
            font=dict(size=24, color=color_palette["mariana_blue"])
        ),
        showlegend=True,
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-1, 1]),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-1, 1]),
        hovermode='closest',
        paper_bgcolor=color_palette["simple_white"],
        plot_bgcolor=color_palette["simple_white"],
        legend=dict(
            itemsizing='constant',
            title=dict(text='Risk Levels', font=dict(size=16, color=color_palette["mariana_blue"])),
            font=dict(size=14),
            yanchor="top",
            y=0.99,
            xanchor="left",
            x=0.01,
            bgcolor='rgba(255,255,255,0.8)',
            bordercolor='rgba(0,0,0,0)',
            orientation='h'
        ),
        margin=dict(l=20, r=20, t=50, b=20)
    )

    # Create figure
    fig = go.Figure(data=[bubbles] + legend_traces, layout=layout)

    return fig