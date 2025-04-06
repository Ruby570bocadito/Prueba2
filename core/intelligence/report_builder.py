from weasyprint import HTML
from datetime import datetime
import json
import os
import base64
from jinja2 import Environment, FileSystemLoader
import matplotlib.pyplot as plt
import io

class ReportBuilder:
    def __init__(self, template_dir='templates'):
        self.template_env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=True
        )
        self.report_data = {
            'title': 'TargetTrace Report',
            'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'findings': [],
            'graphs': []
        }

    def add_finding(self, title, description, evidence, severity='medium'):
        """Add a security finding to the report"""
        self.report_data['findings'].append({
            'title': title,
            'description': description,
            'evidence': evidence,
            'severity': severity.lower()
        })

    def add_graph(self, graph_path, caption=None):
        """Add a graph image to the report"""
        if not caption:
            caption = f"Graph generated on {datetime.now().strftime('%Y-%m-%d')}"
            
        # Convert graph to base64 for HTML embedding
        with open(graph_path, 'rb') as f:
            graph_data = base64.b64encode(f.read()).decode('utf-8')
            
        self.report_data['graphs'].append({
            'data': graph_data,
            'caption': caption,
            'format': os.path.splitext(graph_path)[1][1:].lower()
        })

    def generate_pdf(self, output_file='report.pdf'):
        """Generate PDF report from collected data"""
        try:
            # Render HTML template
            template = self.template_env.get_template('report_template.html')
            html_content = template.render(**self.report_data)
            
            # Generate PDF
            HTML(string=html_content).write_pdf(output_file)
            
            return output_file
        except Exception as e:
            print(f"Error generating report: {str(e)}")
            return None

    def generate_graph_from_data(self, data, output_file='graph.png'):
        """Generate a matplotlib graph from data"""
        try:
            # Parse data if it's JSON string
            if isinstance(data, str):
                data = json.loads(data)
                
            # Create simple bar chart (example visualization)
            labels = list(data.keys())
            values = list(data.values())
            
            plt.figure(figsize=(10, 6))
            plt.bar(labels, values)
            plt.title('Data Distribution')
            plt.xticks(rotation=45)
            plt.tight_layout()
            
            # Save to file
            plt.savefig(output_file, dpi=300)
            plt.close()
            
            return output_file
        except Exception as e:
            print(f"Error generating graph: {str(e)}")
            return None

    def save_json_report(self, output_file='report_data.json'):
        """Save report data as JSON file"""
        try:
            with open(output_file, 'w') as f:
                json.dump(self.report_data, f, indent=4)
            return output_file
        except Exception as e:
            print(f"Error saving JSON report: {str(e)}")
            return None

    def load_from_json(self, json_file):
        """Load report data from JSON file"""
        try:
            with open(json_file, 'r') as f:
                self.report_data = json.load(f)
            return True
        except Exception as e:
            print(f"Error loading JSON report: {str(e)}")
            return False
