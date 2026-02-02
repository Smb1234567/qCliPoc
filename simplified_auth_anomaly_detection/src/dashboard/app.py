import dash
from dash import dcc, html, Input, Output
import plotly.express as px
import pandas as pd
import sqlite3
import os
from datetime import datetime, timedelta


def create_dashboard_app():
    """
    Create the Dash web application for the anomaly detection dashboard
    """
    app = dash.Dash(__name__)
    
    # Layout of the dashboard
    app.layout = html.Div([
        html.H1("Authentication Anomaly Detection Dashboard", 
                style={'textAlign': 'center', 'marginBottom': 30}),
        
        # Summary cards
        html.Div([
            html.Div([
                html.H3(id='total-alerts', children="Loading..."),
                html.P("Total Alerts")
            ], className="card", style={'display': 'inline-block', 'width': '23%', 'margin': '1%', 'textAlign': 'center'}),
            
            html.Div([
                html.H3(id='high-severity', children="Loading..."),
                html.P("High Severity")
            ], className="card", style={'display': 'inline-block', 'width': '23%', 'margin': '1%', 'textAlign': 'center'}),
            
            html.Div([
                html.H3(id='users-affected', children="Loading..."),
                html.P("Users Affected")
            ], className="card", style={'display': 'inline-block', 'width': '23%', 'margin': '1%', 'textAlign': 'center'}),
            
            html.Div([
                html.H3(id='anomaly-types', children="Loading..."),
                html.P("Anomaly Types")
            ], className="card", style={'display': 'inline-block', 'width': '23%', 'margin': '1%', 'textAlign': 'center'}),
        ]),
        
        # Charts
        html.Div([
            dcc.Graph(id='alerts-over-time'),
        ], style={'width': '48%', 'display': 'inline-block'}),
        
        html.Div([
            dcc.Graph(id='severity-distribution'),
        ], style={'width': '48%', 'float': 'right', 'display': 'inline-block'}),
        
        html.Div([
            dcc.Graph(id='top-users-anomalies'),
        ], style={'width': '48%', 'display': 'inline-block'}),
        
        html.Div([
            dcc.Graph(id='anomaly-types-chart'),
        ], style={'width': '48%', 'float': 'right', 'display': 'inline-block'}),
        
        # Recent alerts table
        html.Div([
            html.H3("Recent Alerts"),
            html.Table(id='recent-alerts-table', children=[
                html.Thead([
                    html.Tr([html.Th(col) for col in ["Timestamp", "Username", "IP Address", "Severity", "Details"]])
                ]),
                html.Tbody(id='recent-alerts-body')
            ])
        ], style={'marginTop': 30})
    ])
    
    # Callbacks to update dashboard content
    @app.callback(
        [Output('total-alerts', 'children'),
         Output('high-severity', 'children'),
         Output('users-affected', 'children'),
         Output('anomaly-types', 'children')],
        [Input('total-alerts', 'id')]  # Just to trigger on load
    )
    def update_summary_cards(_):
        # Get alert data from database
        alerts_df = get_alert_data()
        
        if alerts_df.empty:
            return ["0", "0", "0", "0"]
        
        total_alerts = len(alerts_df)
        high_severity = len(alerts_df[alerts_df['severity'] == 'high'])
        users_affected = alerts_df['username'].nunique()
        anomaly_types = alerts_df['anomaly_type'].nunique()
        
        return [str(total_alerts), str(high_severity), str(users_affected), str(anomaly_types)]
    
    @app.callback(
        Output('alerts-over-time', 'figure'),
        [Input('total-alerts', 'id')]
    )
    def update_alerts_over_time(_):
        alerts_df = get_alert_data()
        
        if alerts_df.empty:
            fig = px.line(title="No data available")
            return fig
        
        # Group by date
        alerts_df['date'] = pd.to_datetime(alerts_df['timestamp']).dt.date
        daily_counts = alerts_df.groupby('date').size().reset_index(name='count')
        
        fig = px.line(daily_counts, x='date', y='count', title="Alerts Over Time")
        return fig
    
    @app.callback(
        Output('severity-distribution', 'figure'),
        [Input('total-alerts', 'id')]
    )
    def update_severity_distribution(_):
        alerts_df = get_alert_data()
        
        if alerts_df.empty:
            fig = px.pie(title="No data available")
            return fig
        
        severity_counts = alerts_df['severity'].value_counts().reset_index()
        severity_counts.columns = ['severity', 'count']
        
        fig = px.pie(severity_counts, values='count', names='severity', title="Severity Distribution")
        return fig
    
    @app.callback(
        Output('top-users-anomalies', 'figure'),
        [Input('total-alerts', 'id')]
    )
    def update_top_users_anomalies(_):
        alerts_df = get_alert_data()
        
        if alerts_df.empty:
            fig = px.bar(title="No data available")
            return fig
        
        user_counts = alerts_df['username'].value_counts().head(10).reset_index()
        user_counts.columns = ['username', 'count']
        
        fig = px.bar(user_counts, x='username', y='count', title="Top Users with Anomalies")
        return fig
    
    @app.callback(
        Output('anomaly-types-chart', 'figure'),
        [Input('total-alerts', 'id')]
    )
    def update_anomaly_types_chart(_):
        alerts_df = get_alert_data()
        
        if alerts_df.empty:
            fig = px.bar(title="No data available")
            return fig
        
        type_counts = alerts_df['anomaly_type'].value_counts().reset_index()
        type_counts.columns = ['anomaly_type', 'count']
        
        fig = px.bar(type_counts, x='anomaly_type', y='count', title="Anomaly Types Distribution")
        return fig
    
    @app.callback(
        Output('recent-alerts-body', 'children'),
        [Input('total-alerts', 'id')]
    )
    def update_recent_alerts_table(_):
        alerts_df = get_alert_data()
        
        if alerts_df.empty:
            return [html.Tr([html.Td("No alerts available", colSpan=5)])]
        
        # Take the 10 most recent alerts
        recent_alerts = alerts_df.head(10)
        
        rows = []
        for _, row in recent_alerts.iterrows():
            rows.append(html.Tr([
                html.Td(row['timestamp']),
                html.Td(row['username']),
                html.Td(row['ip_address']),
                html.Td(row['severity'].upper()),
                html.Td(row['details'][:50] + "..." if len(row['details']) > 50 else row['details'])
            ]))
        
        return rows
    
    return app


def get_alert_data():
    """
    Retrieve alert data from the database
    """
    if not os.path.exists('alert_history.db'):
        return pd.DataFrame()  # Return empty dataframe if DB doesn't exist
    
    conn = sqlite3.connect('alert_history.db')
    query = '''
        SELECT timestamp, username, ip_address, severity, anomaly_type, details, status
        FROM alerts
        WHERE status = 'active'
        ORDER BY timestamp DESC
        LIMIT 100
    '''
    df = pd.read_sql_query(query, conn)
    conn.close()
    
    return df


def run_dashboard():
    """
    Run the dashboard application
    """
    app = create_dashboard_app()
    print("Starting dashboard on http://localhost:8050")
    app.run_server(debug=True, host='0.0.0.0', port=8050)


# Example usage
if __name__ == "__main__":
    run_dashboard()