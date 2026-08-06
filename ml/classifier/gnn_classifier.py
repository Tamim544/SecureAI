"""
Vulnerability Classifier (GNN + Transformer).

This model combines a Transformer (GraphCodeBERT) to encode code tokens
with a Graph Neural Network (GATv2) to process the Code Property Graph (CPG).
This fusion allows the model to understand both textual semantics and
structural data/control flow, achieving state-of-the-art vulnerability detection.
"""
from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F

try:
    from torch_geometric.nn import GATv2Conv, global_mean_pool
except ImportError:
    GATv2Conv = None
    global_mean_pool = None

from transformers import AutoModel


class GNNVulnClassifier(nn.Module):
    """
    Hybrid GNN-Transformer model for vulnerability classification.
    """
    
    def __init__(
        self,
        base_model_name: str = "microsoft/graphcodebert-base",
        num_classes: int = 26,  # 25 CWE types + 1 Safe class
        hidden_dim: int = 768,
        gnn_heads: int = 4
    ):
        super().__init__()
        
        # 1. Token Encoder (Transformer)
        self.encoder = AutoModel.from_pretrained(base_model_name)
        
        # 2. Graph Encoder (GNN)
        if GATv2Conv is not None:
            # We assume node features coming from the CPG are already embedded to hidden_dim
            # Or we can project them. Let's assume input node features are token IDs and we embed them.
            self.node_embedding = nn.Embedding(50000, 256)
            self.gnn1 = GATv2Conv(256, 128, heads=gnn_heads, edge_dim=1)
            self.gnn2 = GATv2Conv(128 * gnn_heads, hidden_dim // 2, heads=1, edge_dim=1)
        
        # 3. Fusion & Classification Head
        # Transformer outputs (hidden_dim) + GNN outputs (hidden_dim // 2)
        fusion_dim = hidden_dim + (hidden_dim // 2)
        
        self.classifier = nn.Sequential(
            nn.Linear(fusion_dim, 512),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(512, 128),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(128, num_classes)
        )

    def forward(self, input_ids, attention_mask, cpg_data=None):
        """
        Forward pass.
        
        Args:
            input_ids: Token IDs for the code snippet
            attention_mask: Attention mask for tokens
            cpg_data: PyTorch Geometric Data object containing the CPG
        """
        # --- 1. Sequence Encoding ---
        outputs = self.encoder(input_ids=input_ids, attention_mask=attention_mask)
        # Use [CLS] token representation for sequence
        seq_emb = outputs.last_hidden_state[:, 0, :]  # (batch_size, 768)
        
        # --- 2. Graph Encoding ---
        if cpg_data is not None and GATv2Conv is not None:
            x, edge_index, edge_attr, batch = (
                cpg_data.x, 
                cpg_data.edge_index, 
                cpg_data.edge_attr.float().unsqueeze(-1), 
                cpg_data.batch
            )
            
            # Embed token ids in nodes and average them (assuming x contains 16 token ids per node)
            x = self.node_embedding(x.long())  # (num_nodes, 16, 256)
            x = x.mean(dim=1)                  # (num_nodes, 256)
            
            x = self.gnn1(x, edge_index, edge_attr)
            x = F.elu(x)
            x = self.gnn2(x, edge_index, edge_attr)
            
            # Global pooling to get graph-level representation
            graph_emb = global_mean_pool(x, batch)  # (batch_size, 384)
        else:
            # Fallback if no graph data provided
            batch_size = input_ids.size(0)
            graph_emb = torch.zeros(batch_size, 384, device=input_ids.device)
            
        # --- 3. Fusion ---
        fused = torch.cat([seq_emb, graph_emb], dim=1)  # (batch_size, 768 + 384)
        
        # --- 4. Classification ---
        logits = self.classifier(fused)
        return logits
