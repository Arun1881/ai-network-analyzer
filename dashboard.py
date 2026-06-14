# final_network_dashboard.py

import pandas as pd
from scapy.all import sniff
from threading import Thread
from dash import Dash, html, dcc, Input, Output, State, ALL
import plotly.express as px
import plotly.graph_objects as go
import dash_bootstrap_components as dbc
import dash
import datetime
import io
import base64

# ----------------- GLOBAL DATA -----------------
columns = ['timestamp', 'src_ip', 'dst_ip', 'protocol', 'length']
df = pd.DataFrame(columns=columns)

# ----------------- PACKET CAPTURE -----------------
def capture_packets():
    def process_packet(packet):
        global df
        timestamp = pd.Timestamp.now()
        src = packet[0][1].src if hasattr(packet[0][1], 'src') else 'N/A'
        dst = packet[0][1].dst if hasattr(packet[0][1], 'dst') else 'N/A'
        proto = packet[0][1].proto if hasattr(packet[0][1], 'proto') else packet.name
        length = len(packet)
        new_row = pd.DataFrame([[timestamp, src, dst, proto, length]], columns=columns)
        df = pd.concat([df, new_row], ignore_index=True)
    sniff(prn=process_packet, store=False)

thread = Thread(target=capture_packets, daemon=True)
thread.start()

# ----------------- APP SETUP -----------------
app = Dash(__name__, external_stylesheets=[dbc.themes.DARKLY])
app.title = "Pro Live Network Analyzer"
server = app.server

# ----------------- FEATURES LIST -----------------
features_list = [
    {"name": "Live Packet Capture",
     "desc": "Capture network packets in real-time with advanced filtering."},
    {"name": "KPIs & Alerts",
     "desc": "Monitor key metrics and receive instant notifications for unusual traffic."},
    {"name": "Advanced Filters",
     "desc": "Filter captured data by IP, protocol, port, or time range."},
    {"name": "Interactive Graphs",
     "desc": "Click on graphs to view detailed packet info in real-time."},
    {"name": "MAC Traffic Charts",
     "desc": "Visualize per-device traffic and detect network bottlenecks."},
    {"name": "CSV Export",
     "desc": "Export captured packets and metrics for offline analysis."},
]

# ----------------- DASHBOARD PAGE -----------------
dashboard_layout = html.Div([
    html.H1("Live Network Analyzer Dashboard",
            style={'textAlign':'center','marginBottom':'30px','fontFamily':'Montserrat'}),

    # KPI Cards
    html.Div([
        html.Div([html.H4("Top Source IP"), html.H2(id='kpi-src',style={'fontSize':'19px'})],
                 className='kpi-card'),
        html.Div([html.H4("Top Destination IP"), html.H2(id='kpi-dst',style={'fontSize':'19px'})],
                 className='kpi-card'),
        html.Div([html.H4("Total Packets"), html.H2(id='kpi-packets',style={'fontSize':'19px'})],
                 className='kpi-card'),
        html.Div([html.H4("Total Data (Bytes)"), html.H2(id='kpi-data',style={'fontSize':'19px'})],
                 className='kpi-card'),
    ], style={'marginBottom':'30px','display':'flex','justifyContent':'space-between'}),

    # Graphs inside cards
    dbc.Row([
        dbc.Col(dbc.Card(dcc.Graph(id='graph-time'), body=True, style={'marginBottom':'20px'}), width=6),
        dbc.Col(dbc.Card(dcc.Graph(id='graph-src'), body=True, style={'marginBottom':'20px'}), width=6),
    ]),
    dbc.Row([
        dbc.Col(dbc.Card(dcc.Graph(id='graph-dst'), body=True, style={'marginBottom':'20px'}), width=6),
        dbc.Col(dbc.Card(dcc.Graph(id='graph-protocol'), body=True, style={'marginBottom':'20px'}), width=6),
    ]),
    dbc.Row([
        dbc.Col(dbc.Card(dcc.Graph(id='graph-geo'), body=True, style={'marginBottom':'20px'}), width=12),
    ]),

    # Auto-refresh interval
    dcc.Interval(id='interval-update', interval=2000, n_intervals=0)
], style={'fontFamily':'Montserrat','backgroundColor':'#0e1117','color':'white','padding':'20px'})

# ----------------- FEATURE DETAIL PAGE -----------------
features_layout = html.Div([
    html.H1("Dashboard Features", style={'textAlign':'center','marginBottom':'20px','fontFamily':'Montserrat'}),

    dbc.Row([
        # Left panel: feature buttons
        dbc.Col([
            html.Div([
                dbc.Button(f['name'], id={'type':'feature-card','index':i},
                           color="primary",
                           style={
                               'width':'100%',
                               'marginBottom':'10px',
                               'textAlign':'left',
                               'borderRadius':'10px',
                               'background': 'linear-gradient(to right, #667eea, #764ba2)',
                               'color':'white',
                               'boxShadow': '0px 4px 15px rgba(0,0,0,0.3)',
                               'transition': 'transform 0.2s'
                           },
                           n_clicks=0)
                for i, f in enumerate(features_list)
            ])
        ], width=4),

        # Right panel: feature mini-dashboard
        dbc.Col([
            html.Div(id='feature-detail', style={
                'backgroundColor':'#1a1a2e',
                'padding':'20px',
                'borderRadius':'10px',
                'minHeight':'600px',
                'boxShadow': '0px 4px 15px rgba(0,0,0,0.3)'
            })
        ], width=8)
    ])
], style={'padding':'20px','backgroundColor':'#0e1117','color':'white'})

# ----------------- PREDICTIONS & ALERTS PAGE -----------------
prediction_layout = html.Div([
    html.H1("Network Predictions & Alerts", style={'textAlign':'center','marginBottom':'20px','fontFamily':'Montserrat'}),

    # Alerts
    html.Div(id='alert-box', style={'padding':'15px','borderRadius':'10px','marginBottom':'20px'}),

    # Prediction Graphs inside cards
    dbc.Row([
        dbc.Col(dbc.Card(dcc.Graph(id='pred-traffic'), body=True, style={'marginBottom':'20px'}), width=6),
        dbc.Col(dbc.Card(dcc.Graph(id='pred-top-src'), body=True, style={'marginBottom':'20px'}), width=6)
    ]),
    dbc.Row([
        dbc.Col(dbc.Card(dcc.Graph(id='pred-top-dst'), body=True, style={'marginBottom':'20px'}), width=6),
        dbc.Col(dbc.Card(dcc.Graph(id='pred-protocol-trend'), body=True, style={'marginBottom':'20px'}), width=6)
    ]),

    # CSV export of predictions
    html.Div(id='pred-csv', style={'marginTop':'15px'}),

    # Auto-refresh
    dcc.Interval(id='interval-pred', interval=5000, n_intervals=0)
], style={'fontFamily':'Montserrat','backgroundColor':'#0e1117','color':'white','padding':'15px'})

# ----------------- NAVIGATION -----------------
navbar = dbc.NavbarSimple(
    children=[
        dbc.NavItem(dbc.NavLink("Dashboard", href="/", id='nav-dashboard')),
        dbc.NavItem(dbc.NavLink("Features Info", href="/features", id='nav-features')),
        dbc.NavItem(dbc.NavLink("Predictions & Alerts", href="/prediction", id='nav-prediction'))
    ],
    brand=html.B("Pro Live Network Analyzer"),
    color="#667eea",
    dark=True,
    style={'background': 'linear-gradient(to right, #667eea, #764ba2)'}
)

app.layout = html.Div([
    dcc.Location(id='url', refresh=False),
    navbar,
    html.Div(id='page-content')
])

# ----------------- PAGE NAVIGATION -----------------
@app.callback(
    Output('page-content', 'children'),
    Input('url', 'pathname')
)
def display_page(pathname):
    if pathname == '/features':
        return features_layout
    elif pathname == '/prediction':
        return prediction_layout
    else:
        return dashboard_layout

# ----------------- HELPER FUNCTION -----------------
def get_geo(ip):
    # Example: simple Geo-IP mapping (replace with real Geo-IP)
    # Returns lat, lon
    import random
    return random.uniform(-60, 60), random.uniform(-180, 180)

# ----------------- LIVE DASHBOARD CALLBACK -----------------
@app.callback(
    Output('kpi-src','children'),
    Output('kpi-dst','children'),
    Output('kpi-packets','children'),
    Output('kpi-data','children'),
    Output('graph-time','figure'),
    Output('graph-src','figure'),
    Output('graph-dst','figure'),
    Output('graph-protocol','figure'),
    Output('graph-geo','figure'),
    Input('interval-update','n_intervals')
)
def update_dashboard(n):
    global df
    dff = df.copy()

    top_src_ip = dff['src_ip'].mode()[0] if not dff.empty else "N/A"
    top_dst_ip = dff['dst_ip'].mode()[0] if not dff.empty else "N/A"
    total_packets = len(dff)
    total_data = dff['length'].sum() if 'length' in dff.columns else 0

    # Packets over time
    if not dff.empty:
        packets_over_time = dff.groupby(dff['timestamp'].dt.floor('S')).size().reset_index(name='count')
        fig_time = px.line(packets_over_time, x='timestamp', y='count', title='Packets Over Time',
                           template='plotly_dark', markers=True)
        fig_time.update_layout(plot_bgcolor='#0e1117', paper_bgcolor='#0e1117',
                               font=dict(family='Montserrat', color='white'),
                               xaxis=dict(showgrid=True, gridcolor='#444'),
                               yaxis=dict(showgrid=True, gridcolor='#444'))
    else:
        fig_time = go.Figure(); fig_time.update_layout(title="Packets Over Time (No Data)", template="plotly_dark")

    # Top Source IPs
    if not dff.empty:
        top_src = dff['src_ip'].value_counts().nlargest(10).reset_index()
        top_src.columns = ['src_ip','count']
        fig_src = px.bar(top_src, x='src_ip', y='count', title='Top Source IPs',
                         template='plotly_dark', text='count', color='count', color_continuous_scale='Viridis')
    else:
        fig_src = go.Figure()

    # Top Destination IPs
    if not dff.empty:
        top_dst = dff['dst_ip'].value_counts().nlargest(10).reset_index()
        top_dst.columns = ['dst_ip','count']
        fig_dst = px.bar(top_dst, x='dst_ip', y='count', title='Top Destination IPs',
                         template='plotly_dark', text='count', color='count', color_continuous_scale='Plasma')
    else:
        fig_dst = go.Figure()

    # Protocol Distribution
    if not dff.empty:
        protocol_count = dff['protocol'].value_counts().reset_index()
        protocol_count.columns = ['protocol','count']
        fig_protocol = px.pie(protocol_count, names='protocol', values='count',
                              title='Protocol Distribution', template='plotly_dark', hole=0.3)
    else:
        fig_protocol = go.Figure()

    # ----------------- Enhanced Geo-IP Heatmap -----------------
    if not dff.empty:
        geo_data = []
        for ip in dff['src_ip'].unique():
            lat, lon = get_geo(ip)
            count = len(dff[dff['src_ip']==ip])
            geo_data.append({'lat':lat,'lon':lon,'count':count, 'ip':ip})
        geo_df = pd.DataFrame(geo_data)

        if not geo_df.empty:
            fig_geo = px.scatter_mapbox(
                geo_df,
                lat="lat",
                lon="lon",
                size="count",
                color="count",
                color_continuous_scale=px.colors.sequential.Viridis,
                size_max=40,
                hover_name="ip",
                hover_data={"lat":True, "lon":True, "count":True},
                zoom=1,
                title="🌐 Source IP Geo Heatmap Pro"
            )
            fig_geo.update_layout(
                mapbox_style="carto-darkmatter",
                mapbox=dict(
                    center=dict(lat=0, lon=0),
                    zoom=1
                ),
                margin={"r":0,"t":40,"l":0,"b":0},
                font=dict(family="Montserrat", color="white"),
                paper_bgcolor='#0e1117',
                plot_bgcolor='#0e1117',
                coloraxis_colorbar=dict(
                    title="Packet Count",
                    tickvals=[geo_df['count'].min(), geo_df['count'].max()],
                    ticktext=["Low", "High"]
                )
            )
        else:
            fig_geo = go.Figure()
    else:
        fig_geo = go.Figure()

    return top_src_ip, top_dst_ip, total_packets, total_data, fig_time, fig_src, fig_dst, fig_protocol, fig_geo

# ----------------- FEATURE DETAIL CALLBACK -----------------
@app.callback(
    Output('feature-detail','children'),
    Input({'type':'feature-card','index':ALL}, 'n_clicks'),
    State({'type':'feature-card','index':ALL}, 'id')
)
def display_feature_detail(n_clicks, ids):
    ctx = dash.callback_context
    if not ctx.triggered or all(click is None for click in n_clicks):
        return html.Div("Click a feature on the left to see details", style={'fontSize':'18px','color':'#bbb'})

    button_id = ctx.triggered[0]['prop_id'].split('.')[0]
    idx = eval(button_id)['index']
    f = features_list[idx]

    global df
    dff = df.copy()

    total_packets = len(dff)
    total_data = dff['length'].sum() if 'length' in dff.columns else 0
    top_src = dff['src_ip'].mode()[0] if not dff.empty else "N/A"
    top_dst = dff['dst_ip'].mode()[0] if not dff.empty else "N/A"

    kpi_cards = dbc.Row([
        dbc.Col(dbc.Card([dbc.CardHeader("Total Packets"), dbc.CardBody(html.H4(total_packets))],
                         color="dark", inverse=True), width=3),
        dbc.Col(dbc.Card([dbc.CardHeader("Total Data (Bytes)"), dbc.CardBody(html.H4(total_data))],
                         color="dark", inverse=True), width=3),
        dbc.Col(dbc.Card([dbc.CardHeader("Top Source IP"), dbc.CardBody(html.H4(top_src))],
                         color="dark", inverse=True), width=3),
        dbc.Col(dbc.Card([dbc.CardHeader("Top Destination IP"), dbc.CardBody(html.H4(top_dst))],
                         color="dark", inverse=True), width=3),
    ], style={'marginBottom':'20px'})

    if not dff.empty:
        packets_over_time = dff.groupby(dff['timestamp'].dt.floor('S')).size().reset_index(name='count')
        fig_time = go.Figure()
        fig_time.add_trace(go.Scatter(x=packets_over_time['timestamp'], y=packets_over_time['count'],
                                      mode='lines+markers', line=dict(color='cyan')))
        fig_time.update_layout(template='plotly_dark', title="Packets Over Time")

        top_src_df = dff['src_ip'].value_counts().nlargest(5).reset_index()
        top_src_df.columns = ['src_ip','count']
        fig_src = go.Figure([go.Bar(x=top_src_df['src_ip'], y=top_src_df['count'], marker_color='magenta')])
        fig_src.update_layout(template='plotly_dark', title="Top Source IPs")
    else:
        fig_time = go.Figure(); fig_src = go.Figure()

    csv_string = dff.to_csv(index=False)
    csv_encoded = "data:text/csv;charset=utf-8," + csv_string
    csv_link = html.A("Download CSV", href=csv_encoded, download=f"{f['name']}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                      style={'color':'#00ffff','fontSize':'16px', 'display':'block', 'marginTop':'10px'})

    return html.Div([
        html.H2(f['name'], style={'marginBottom':'10px'}),
        html.P(f['desc'], style={'fontSize':'16px'}),
        kpi_cards,
        dbc.Row([
            dbc.Col(dcc.Graph(figure=fig_time), width=6),
            dbc.Col(dcc.Graph(figure=fig_src), width=6)
        ]),
        csv_link
    ])

# ----------------- PREDICTION HELPER -----------------
def predict_future_traffic(dff, future_seconds=10):
    if dff.empty:
        return None, None
    last_len = len(dff)
    last_traffic = dff['length'].iloc[-1]
    future_traffic = last_traffic * 1.2
    return future_seconds, future_traffic

# ----------------- PREDICTION & ALERT CALLBACK -----------------
@app.callback(
    Output('pred-traffic','figure'),
    Output('pred-top-src','figure'),
    Output('pred-top-dst','figure'),
    Output('pred-protocol-trend','figure'),
    Output('alert-box','children'),
    Output('pred-csv','children'),
    Input('interval-pred','n_intervals')
)
def update_prediction_page(n):
    global df
    dff = df.copy()

    if dff.empty:
        empty_fig = go.Figure(); empty_fig.update_layout(template='plotly_dark')
        return empty_fig, empty_fig, empty_fig, empty_fig, "No data yet", None

    future_time, future_traffic = predict_future_traffic(dff)
    traffic_fig = go.Figure()
    traffic_per_sec = dff.groupby(dff['timestamp'].dt.floor('S'))['length'].sum().reset_index()
    traffic_fig.add_trace(go.Scatter(x=traffic_per_sec['timestamp'], y=traffic_per_sec['length'],
                                     mode='lines+markers', name='Actual Traffic'))
    if future_time:
        last_time = traffic_per_sec['timestamp'].max()
        last_val = traffic_per_sec['length'].iloc[-1]
        traffic_fig.add_trace(go.Scatter(x=[last_time, last_time + pd.Timedelta(seconds=future_time)],
                                         y=[last_val, future_traffic],
                                         mode='lines+markers', line=dict(color='red'), name='Predicted Traffic'))
    traffic_fig.update_layout(template='plotly_dark', title="Traffic Prediction & Trend")

    top_src = dff['src_ip'].value_counts().nlargest(10).reset_index()
    top_src.columns = ['src_ip','count']
    top_src_fig = px.bar(top_src, x='src_ip', y='count', text='count', template='plotly_dark', title='Top Source IP Trend')

    top_dst = dff['dst_ip'].value_counts().nlargest(10).reset_index()
    top_dst.columns = ['dst_ip','count']
    top_dst_fig = px.bar(top_dst, x='dst_ip', y='count', text='count', template='plotly_dark', title='Top Destination IP Trend')

    proto_count = dff['protocol'].value_counts().reset_index()
    proto_count.columns = ['protocol','count']
    proto_fig = px.pie(proto_count, names='protocol', values='count', hole=0.3, template='plotly_dark', title='Protocol Distribution')

    alerts = []
    if future_traffic and future_traffic > traffic_per_sec['length'].mean()*2:
        alerts.append(html.Div("⚠️ High traffic predicted! Possible spike detected.",
                               style={'backgroundColor':'#ff4c4c','color':'white','padding':'10px','borderRadius':'8px','marginBottom':'10px','boxShadow':'0 4px 10px rgba(0,0,0,0.3)'}))
    if not top_src.empty and top_src['count'].iloc[0] > dff['src_ip'].value_counts().mean()*3:
        alerts.append(html.Div(f"⚠️ Unusual activity from {top_src['src_ip'].iloc[0]}",
                               style={'backgroundColor':'#ff9800','color':'white','padding':'10px','borderRadius':'8px','marginBottom':'10px','boxShadow':'0 4px 10px rgba(0,0,0,0.3)'}))

    csv_string = dff.to_csv(index=False)
    csv_encoded = "data:text/csv;charset=utf-8," + csv_string
    csv_link = html.A("Download Full Network Data CSV", href=csv_encoded,
                      download=f"NetworkData_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                      style={'color':'#00ffff','fontSize':'16px','display':'block','marginTop':'10px'})

    return traffic_fig, top_src_fig, top_dst_fig, proto_fig, alerts, csv_link

# ----------------- RUN APP -----------------
if __name__ == "__main__":
    app.run(debug=False, port=8050)
