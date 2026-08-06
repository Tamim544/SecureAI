"""
Code Property Graph (CPG) Builder.

A CPG combines:
1. Abstract Syntax Tree (AST)
2. Control Flow Graph (CFG)
3. Program Dependence Graph (PDG) - Data flow + Control dependence

This file generates a unified graph representation using torch_geometric.Data,
which can be directly fed into the GNN classifier.
"""
from __future__ import annotations

import networkx as nx
import torch
try:
    from torch_geometric.data import Data
except ImportError:
    Data = None  # Handle gracefully if torch_geometric is not installed yet

from core.ast_engine.parser import CodeFunction
from core.cfg_builder.builder import CFGBuilder


class CPGEngine:
    """Builds a Code Property Graph from parsed code."""

    def __init__(self):
        self.cfg_builder = CFGBuilder()

    def build_cpg(self, func: CodeFunction, raw_ast: Any = None) -> nx.MultiDiGraph:
        """
        Builds a combined graph (AST + CFG + DataFlow).
        Uses NetworkX as the intermediate representation.
        """
        cpg = nx.MultiDiGraph()
        
        # 1. Build AST nodes
        # We will simplify by just adding a root node for the function
        # and attaching the CFG nodes as children to keep the graph manageable.
        root_id = "root_0"
        cpg.add_node(root_id, type="AST_ROOT", label=func.name)

        # 2. Build CFG
        cfg = self.cfg_builder.build(func, raw_ast)
        
        # Merge CFG into CPG
        for node_id, data in cfg.nodes(data=True):
            obj = data.get("obj")
            text = obj.text if obj else ""
            cpg.add_node(node_id, type="CFG_NODE", label=text)
            cpg.add_edge(root_id, node_id, edge_type="AST_CHILD")

        for u, v in cfg.edges():
            cpg.add_edge(u, v, edge_type="CFG_NEXT")

        # 3. Build Data Flow (PDG)
        # Very simplified heuristic data flow: link nodes that share variables
        import re
        variables_in_node = {}
        for node_id, data in cfg.nodes(data=True):
            obj = data.get("obj")
            text = obj.text if obj else ""
            # Extract basic words as variable approximations
            vars_found = set(re.findall(r'\b[a-zA-Z_]\w*\b', text))
            variables_in_node[node_id] = vars_found

        node_ids = list(cfg.nodes())
        for i in range(len(node_ids)):
            for j in range(i + 1, len(node_ids)):
                u, v = node_ids[i], node_ids[j]
                shared = variables_in_node[u].intersection(variables_in_node[v])
                # Filter out language keywords
                keywords = {"if", "else", "for", "while", "return", "def", "function", "const", "let", "var"}
                shared = shared - keywords
                if shared:
                    # Add data flow edge
                    cpg.add_edge(u, v, edge_type="DATA_FLOW", var=",".join(shared))

        return cpg

    def to_torch_geometric(self, cpg: nx.MultiDiGraph, tokenizer: Any) -> Any:
        """
        Converts the NetworkX CPG into a PyTorch Geometric Data object.
        Nodes are embedded using the tokenizer (mean of token embeddings or simply token ids).
        Edges are mapped to PyG edge_index and edge_attr (edge types).
        """
        if Data is None:
            raise ImportError("torch_geometric is required for to_torch_geometric")

        node_mapping = {n: i for i, n in enumerate(cpg.nodes())}
        
        # Edge indices and types
        edge_types_map = {"AST_CHILD": 0, "CFG_NEXT": 1, "DATA_FLOW": 2}
        
        edge_index = []
        edge_attr = []
        
        for u, v, data in cpg.edges(data=True):
            edge_index.append([node_mapping[u], node_mapping[v]])
            etype = edge_types_map.get(data.get("edge_type"), 0)
            edge_attr.append(etype)

        edge_index_tensor = torch.tensor(edge_index, dtype=torch.long).t().contiguous()
        edge_attr_tensor = torch.tensor(edge_attr, dtype=torch.long)

        # Node features (simplified: tokenize the label text and pad/truncate to fixed size)
        x_features = []
        for n in cpg.nodes():
            label = cpg.nodes[n].get("label", "")
            tokens = tokenizer.encode(label, add_special_tokens=False, max_length=16, truncation=True)
            # Pad to 16
            tokens = tokens + [tokenizer.pad_token_id or 0] * (16 - len(tokens))
            x_features.append(tokens)

        x_tensor = torch.tensor(x_features, dtype=torch.float)

        data = Data(x=x_tensor, edge_index=edge_index_tensor, edge_attr=edge_attr_tensor)
        return data
