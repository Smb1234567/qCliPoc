import dash
from dash import dcc, html, Input, Output, callback
import plotly.express as px
import plotly.graph_objs as go
import pandas as pd
from datetime import datetime, timedelta
import sqlite3
import sys
import os

# Add the src directory to the path so we can import our modules
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from log_ingestor import LogIngestor
from behavior_profiler import BehaviorProfiler
from anomaly_detector import AnomalyDetector
from alert_system import AlertManager


def create_dashboard_app():
    """
    Create the Dash web application for the anomaly detection dashboard.
    """
    app = dash.Dash(__name__, suppress_callback_exceptions=True)
    
    # App layout
    app.layout = html.Div([
        html.H1("AI-Based Anomaly Detection Dashboard", 
                 style={'textAlign': 'center', 'marginBottom': 30}),
        
        dcc.Tabs(id="tabs", value='overview', children=[
            dcc.Tab(label='Overview', value='overview'),
            dcc.Tab(label='Anomalies', value='anomalies'),
            dcc.Tab(label='Users', value='users'),
            dcc.Tab(label='Alerts', value='alerts'),
            dcc.Tab(label='Settings', value='settings')
        ]),
        
        html.Div(id='tab-content')
    ])
    
    # Callback to update tab content
    @app.callback(Output('tab-content', 'children'),
                  Input('tabs', 'value'))
    def render_content(tab):
        if tab == 'overview':
            return create_overview_tab()
        elif tab == 'anomalies':
            return create_anomalies_tab()
        elif tab == 'users':
            return create_users_tab()
        elif tab == 'alerts':
            return create_alerts_tab()
        elif tab == 'settings':
            return create_settings_tab()
    
    return app


def create_overview_tab():
    """
    Create the overview tab with summary statistics and charts.
    """
    # For demonstration purposes, we'll create some sample data
    # In a real application, this would come from the database or analysis results
    dates = pd.date_range(start='2023-01-01', periods=30, freq='D')
    anomaly_counts = [5, 3, 8, 12, 4, 7, 9, 15, 6, 11, 4, 8, 10, 14, 7, 9, 12, 5, 8, 11, 6, 9, 13, 7, 10, 12, 8, 6, 9, 11]
    
    df = pd.DataFrame({
        'Date': dates,
        'Anomaly_Count': anomaly_counts
    })
    
    fig = px.line(df, x='Date', y='Anomaly_Count', title='Daily Anomaly Count')
    
    # Severity distribution
    severity_data = pd.DataFrame({
        'Severity': ['High', 'Medium', 'Low'],
        'Count': [25, 45, 80]
    })
    severity_fig = px.pie(severity_data, values='Count', names='Severity', title='Anomaly Severity Distribution')
    
    return html.Div([
        html.H3("System Overview"),
        
        html.Div([
            html.Div([
                html.H4("Daily Anomalies"),
                dcc.Graph(figure=fig)
            ], className="six columns"),
            
            html.Div([
                html.H4("Severity Distribution"),
                dcc.Graph(figure=severity_fig)
            ], className="six columns")
        ], className="row"),
        
        html.Div([
            html.Div([
                html.H5("Total Anomalies Detected: "),
                html.P("150", style={'fontSize': 24, 'fontWeight': 'bold'})
            ], className="three columns", style={'textAlign': 'center'}),
            
            html.Div([
                html.H5("High Severity Alerts: "),
                html.P("25", style={'fontSize': 24, 'fontWeight': 'bold', 'color': 'red'})
            ], className="three columns", style={'textAlign': 'center'}),
            
            html.Div([
                html.H5("Active Users Monitored: "),
                html.P("1247", style={'fontSize': 24, 'fontWeight': 'bold'})
            ], className="three columns", style={'textAlign': 'center'}),
            
            html.Div([
                html.H5("Last Updated: "),
                html.P(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), style={'fontSize': 18})
            ], className="three columns", style={'textAlign': 'center'})
        ], className="row", style={'marginTop': 30})
    ])


def create_anomalies_tab():
    """
    Create the anomalies tab showing detected anomalies.
    """
    # Sample anomaly data
    anomaly_data = {
        'Timestamp': pd.date_range(start='2023-01-01', periods=10, freq='6H'),
        'Username': ['alice', 'bob', 'charlie', 'diana', 'eve', 'frank', 'grace', 'heidi', 'ivan', 'judy'],
        'IP_Address': ['192.168.1.10', '10.0.0.5', '203.0.113.10', '192.168.1.15', '10.0.0.8', 
                      '198.51.100.3', '192.168.1.20', '10.0.0.12', '203.0.113.15', '192.168.1.25'],
        'Severity': ['high', 'medium', 'low', 'high', 'medium', 'high', 'low', 'medium', 'high', 'low'],
        'Type': ['unusual_time', 'location_change', 'high_frequency', 'unusual_time', 'location_change',
                'unusual_time', 'high_frequency', 'location_change', 'unusual_time', 'high_frequency'],
        'Details': [
            'Login at 3 AM, unusual for this user',
            'Login from new IP address',
            'Higher than usual login frequency',
            'Login at 4 AM, highly unusual',
            'Access from different country',
            'Login at 2 AM, never seen before',
            'Burst of login attempts',
            'New device fingerprint',
            'Access during vacation period',
            'Unusual resource access pattern'
        ]
    }
    
    df = pd.DataFrame(anomaly_data)
    
    # Color map for severity
    colors = {'high': 'red', 'medium': 'orange', 'low': 'yellow'}
    df['Color'] = df['Severity'].map(colors)
    
    fig = go.Figure(data=go.Scatter(
        x=df['Timestamp'],
        y=df['Username'],
        mode='markers',
        marker=dict(
            size=15,
            color=df['Color'],
            colorscale=[[0, 'yellow'], [0.5, 'orange'], [1, 'red']],
            showscale=True,
            colorbar=dict(title="Severity")
        ),
        text=df.apply(lambda row: f"User: {row['Username']}<br>Type: {row['Type']}<br>Details: {row['Details']}", axis=1),
        hovertemplate='<b>%{text}</b><extra></extra>'
    ))
    
    fig.update_layout(
        title='Anomaly Timeline',
        xaxis_title='Time',
        yaxis_title='User',
        height=600
    )
    
    return html.Div([
        html.H3("Detected Anomalies"),
        
        html.Div([
            dcc.Graph(figure=fig)
        ]),
        
        html.Hr(),
        
        html.H4("Anomaly Details"),
        html.Table([
            html.Thead([
                html.Tr([
                    html.Th("Timestamp"),
                    html.Th("Username"),
                    html.Th("IP Address"),
                    html.Th("Severity"),
                    html.Th("Type"),
                    html.Th("Details")
                ])
            ]),
            html.Tbody([
                html.Tr([
                    html.Td(row['Timestamp'].strftime('%Y-%m-%d %H:%M:%S')),
                    html.Td(row['Username']),
                    html.Td(row['IP_Address']),
                    html.Td(row['Severity'], style={'color': colors[row['Severity']]}),
                    html.Td(row['Type']),
                    html.Td(row['Details'])
                ]) for _, row in df.iterrows()
            ])
        ], style={
            'width': '100%',
            'borderCollapse': 'collapse',
            'marginTop': 20
        })
    ])


def create_users_tab():
    """
    Create the users tab showing user behavior profiles.
    """
    # Sample user data
    user_data = {
        'Username': ['alice', 'bob', 'charlie', 'diana', 'eve', 'frank'],
        'Risk_Score': [0.2, 0.8, 0.4, 0.1, 0.9, 0.3],
        'Last_Active': pd.date_range(start='2023-01-01', periods=6, freq='12H'),
        'Login_Frequency': [5.2, 12.1, 3.8, 2.5, 15.3, 4.7],
        'Common_Locations': ['Office, Home', 'Home', 'Office, Cafe', 'Home', 'Various', 'Office']
    }
    
    df = pd.DataFrame(user_data)
    
    # Create risk score visualization
    fig = px.bar(df, x='Username', y='Risk_Score', 
                 title='User Risk Scores',
                 color='Risk_Score',
                 color_continuous_scale=['green', 'yellow', 'red'])
    
    fig.update_layout(height=500)
    
    return html.Div([
        html.H3("User Profiles and Risk Assessment"),
        
        html.Div([
            dcc.Graph(figure=fig)
        ]),
        
        html.Hr(),
        
        html.H4("User Details"),
        html.Table([
            html.Thead([
                html.Tr([
                    html.Th("Username"),
                    html.Th("Risk Score"),
                    html.Th("Last Active"),
                    html.Th("Login Frequency (per day)"),
                    html.Th("Common Locations")
                ])
            ]),
            html.Tbody([
                html.Tr([
                    html.Td(row['Username']),
                    html.Td(f"{row['Risk_Score']:.2f}", 
                           style={'color': 'red' if row['Risk_Score'] > 0.7 else 'orange' if row['Risk_Score'] > 0.4 else 'green'}),
                    html.Td(row['Last_Active'].strftime('%Y-%m-%d %H:%M:%S')),
                    html.Td(f"{row['Login_Frequency']:.1f}"),
                    html.Td(row['Common_Locations'])
                ]) for _, row in df.iterrows()
            ])
        ], style={
            'width': '100%',
            'borderCollapse': 'collapse',
            'marginTop': 20
        })
    ])


def create_alerts_tab():
    """
    Create the alerts tab showing generated alerts.
    """
    # Connect to alerts database to get real data
    try:
        conn = sqlite3.connect('alert_history.db')
        df = pd.read_sql_query("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 20", conn)
        conn.close()
        
        if df.empty:
            # If no data in DB, use sample data
            alert_data = {
                'timestamp': pd.date_range(start='2023-01-01', periods=10, freq='2H'),
                'username': ['alice', 'bob', 'charlie', 'diana', 'eve', 'frank', 'grace', 'heidi', 'ivan', 'judy'],
                'severity': ['high', 'medium', 'low', 'high', 'medium', 'high', 'low', 'medium', 'high', 'low'],
                'anomaly_type': ['unusual_time', 'location_change', 'high_frequency', 'unusual_time', 'location_change',
                                'unusual_time', 'high_frequency', 'location_change', 'unusual_time', 'high_frequency'],
                'details': [
                    'Login at 3 AM, unusual for this user',
                    'Login from new IP address',
                    'Higher than usual login frequency',
                    'Login at 4 AM, highly unusual',
                    'Access from different country',
                    'Login at 2 AM, never seen before',
                    'Burst of login attempts',
                    'New device fingerprint',
                    'Access during vacation period',
                    'Unusual resource access pattern'
                ]
            }
            df = pd.DataFrame(alert_data)
    except:
        # If database doesn't exist, use sample data
        alert_data = {
            'timestamp': pd.date_range(start='2023-01-01', periods=10, freq='2H'),
            'username': ['alice', 'bob', 'charlie', 'diana', 'eve', 'frank', 'grace', 'heidi', 'ivan', 'judy'],
            'severity': ['high', 'medium', 'low', 'high', 'medium', 'high', 'low', 'medium', 'high', 'low'],
            'anomaly_type': ['unusual_time', 'location_change', 'high_frequency', 'unusual_time', 'location_change',
                            'unusual_time', 'high_frequency', 'location_change', 'unusual_time', 'high_frequency'],
            'details': [
                'Login at 3 AM, unusual for this user',
                'Login from new IP address',
                'Higher than usual login frequency',
                'Login at 4 AM, highly unusual',
                'Access from different country',
                'Login at 2 AM, never seen before',
                'Burst of login attempts',
                'New device fingerprint',
                'Access during vacation period',
                'Unusual resource access pattern'
            ]
        }
        df = pd.DataFrame(alert_data)
    
    # Create alert timeline
    severity_colors = {'high': 'red', 'medium': 'orange', 'low': 'yellow'}
    df['color'] = df['severity'].map(severity_colors)
    
    fig = go.Figure(data=go.Scatter(
        x=df['timestamp'],
        y=df['username'],
        mode='markers',
        marker=dict(
            size=12,
            color=df['color']
        ),
        text=df.apply(lambda row: f"User: {row['username']}<br>Type: {row['anomaly_type']}<br>Details: {row['details']}", axis=1),
        hovertemplate='<b>%{text}</b><extra></extra>'
    ))
    
    fig.update_layout(
        title='Alert Timeline',
        xaxis_title='Time',
        yaxis_title='User',
        height=600
    )
    
    return html.Div([
        html.H3("Security Alerts"),
        
        html.Div([
            dcc.Graph(figure=fig)
        ]),
        
        html.Hr(),
        
        html.H4("Recent Alerts"),
        html.Table([
            html.Thead([
                html.Tr([
                    html.Th("Time"),
                    html.Th("User"),
                    html.Th("Severity"),
                    html.Th("Type"),
                    html.Th("Details")
                ])
            ]),
            html.Tbody([
                html.Tr([
                    html.Td(row['timestamp']),
                    html.Td(row['username']),
                    html.Td(row['severity'], 
                           style={'color': severity_colors[row['severity']], 'fontWeight': 'bold'}),
                    html.Td(row['anomaly_type']),
                    html.Td(row['details'])
                ]) for _, row in df.head(10).iterrows()
            ])
        ], style={
            'width': '100%',
            'borderCollapse': 'collapse',
            'marginTop': 20
        })
    ])


def create_settings_tab():
    """
    Create the settings tab for configuring the system.
    """
    return html.Div([
        html.H3("System Configuration"),
        
        html.Div([
            html.H4("Anomaly Detection Settings"),
            
            html.Label("High Severity Threshold:"),
            dcc.Slider(
                id='high-severity-threshold',
                min=1,
                max=10,
                value=3,
                marks={i: str(i) for i in range(1, 11)},
                tooltip={"placement": "bottom", "always_visible": True}
            ),
            
            html.Br(),
            
            html.Label("Medium Severity Threshold:"),
            dcc.Slider(
                id='medium-severity-threshold',
                min=1,
                max=20,
                value=5,
                marks={i: str(i) for i in range(1, 21, 2)},
                tooltip={"placement": "bottom", "always_visible": True}
            ),
            
            html.Br(),
            
            html.Label("Time Window (minutes):"),
            dcc.Slider(
                id='time-window',
                min=15,
                max=240,
                value=60,
                marks={i: str(i) for i in [15, 30, 60, 120, 180, 240]},
                tooltip={"placement": "bottom", "always_visible": True}
            ),
            
            html.Hr(),
            
            html.H4("Notification Settings"),
            
            dcc.Checklist(
                id='notification-channels',
                options=[
                    {'label': ' Email', 'value': 'email'},
                    {'label': ' Log', 'value': 'log'},
                ],
                value=['email', 'log'],
                labelStyle={'display': 'inline-block', 'margin-right': 10}
            ),
            
            html.Br(),
            
            html.Label("Recipient Emails:"),
            dcc.Textarea(
                id='recipient-emails',
                value='admin@example.com, security@example.com',
                style={'width': '100%', 'height': 60}
            )
        ])
    ])


def run_dashboard():
    """
    Run the dashboard application.
    """
    app = create_dashboard_app()

    # Run the server
    app.run(debug=True, host='0.0.0.0', port=8050)


if __name__ == "__main__":
    run_dashboard()