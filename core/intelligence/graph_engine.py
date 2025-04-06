import networkx as nx
import matplotlib.pyplot as plt
from pyvis.network import Network
import json
import os
from datetime import datetime

class GraphEngine:
    def __init__(self):
        self.graph = nx.Graph()
        self.node_colors = {
            'domain': '#3498db',
            'ip': '#e74c3c', 
            'person': '#2ecc71',
            'organization': '#f39c12',
            'service': '#9b59b6'
        }

    def add_node(self, node_id, node_type, label=None, **kwargs):
        """Add a node to the graph"""
        if not label:
            label = node_id
            
        self.graph.add_node(node_id, 
                          label=label,
                          type=node_type,
                          color=self.node_colors.get(node_type, '#95a5a6'),
                          **kwargs)

    def add_edge(self, source, target, relationship, **kwargs):
        """Add an edge between nodes"""
        self.graph.add_edge(source, target, 
                          label=relationship,
                          **kwargs)

    def build_from_json(self, json_data):
        """Build graph from JSON data structure"""
        try:
            data = json.loads(json_data)
            
            # Add nodes
            if 'nodes' in data:
                for node in data['nodes']:
                    self.add_node(**node)
            
            # Add edges
            if 'edges' in data:
                for edge in data['edges']:
                    self.add_edge(**edge)
                    
        except Exception as e:
            print(f"Error building graph: {str(e)}")

    def visualize_matplotlib(self, filename=None):
        """Generate visualization using matplotlib"""
        plt.figure(figsize=(12, 8))
        
        # Get node colors
        colors = [self.graph.nodes[n]['color'] for n in self.graph.nodes()]
        
        # Draw the graph
        pos = nx.spring_layout(self.graph, k=0.5, iterations=50)
        nx.draw(self.graph, pos, 
               with_labels=True, 
               node_color=colors,
               node_size=800,
               font_size=10,
               edge_color='#bdc3c7')
        
        # Draw edge labels
        edge_labels = nx.get_edge_attributes(self.graph, 'label')
        nx.draw_networkx_edge_labels(self.graph, pos, edge_labels=edge_labels)
        
        if filename:
            plt.savefig(filename, dpi=300, bbox_inches='tight')
            plt.close()
        else:
            plt.show()

    def visualize_pyvis(self, filename='graph.html'):
        """Generate interactive visualization using pyvis"""
        net = Network(height='750px', width='100%', notebook=False)
        
        # Add nodes
        for node in self.graph.nodes():
            net.add_node(node,
                       label=self.graph.nodes[node]['label'],
                       color=self.graph.nodes[node]['color'],
                       title=self.graph.nodes[node].get('title', ''),
                       group=self.graph.nodes[node]['type'])
        
        # Add edges
        for edge in self.graph.edges():
            net.add_edge(edge[0], edge[1],
                        title=self.graph.edges[edge].get('label', ''))
        
        # Generate and save
        net.show(filename)
        return filename

    def save_graph(self, output_dir='output'):
        """Save graph data to file"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # Save graph data
        graph_data = {
            'nodes': [{'node_id': n, 
                      'node_type': self.graph.nodes[n]['type'],
                      'label': self.graph.nodes[n]['label'],
                      'color': self.graph.nodes[n]['color']} 
                     for n in self.graph.nodes()],
            'edges': [{'source': e[0], 
                      'target': e[1], 
                      'relationship': self.graph.edges[e].get('label', '')} 
                     for e in self.graph.edges()]
        }

        filename = f"{output_dir}/graph_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(graph_data, f, indent=4)

        return filename
