"""
Control Flow Graph (CFG) Builder.

Takes a parsed AST function and builds a generic CFG representation.
This is a heuristic-based lightweight CFG built directly from tree-sitter AST nodes,
used primarily to enrich the Code Property Graph (CPG) for the GNN model.
"""
from __future__ import annotations

import networkx as nx
from typing import Any

from core.ast_engine.parser import CodeFunction, Language


class CFGNode:
    """A basic block in the Control Flow Graph."""
    def __init__(self, node_id: int, ast_node: Any = None, text: str = ""):
        self.node_id = node_id
        self.ast_node = ast_node
        self.text = text
        self.is_entry = False
        self.is_exit = False

    def __repr__(self) -> str:
        if self.is_entry:
            return "CFGNode(ENTRY)"
        if self.is_exit:
            return "CFGNode(EXIT)"
        return f"CFGNode({self.node_id}: {self.text[:20]})"


class CFGBuilder:
    """Builds a NetworkX directed graph representing the CFG of a function."""

    def __init__(self):
        pass

    def build(self, func: CodeFunction, raw_ast: Any) -> nx.DiGraph:
        """
        Build CFG from the raw tree-sitter AST of the function.
        
        Args:
            func: The parsed CodeFunction
            raw_ast: The tree-sitter node corresponding to this function
            
        Returns:
            A NetworkX DiGraph where nodes are CFGNodes and edges are control flow.
        """
        graph = nx.DiGraph()
        
        # We need a proper CFG generation for accurate PDG.
        # For the scope of this project and GNN input, we'll build a simplified
        # statement-level graph with sequential edges, branching for if/loops.

        self._node_counter = 0
        
        entry = CFGNode(self._next_id())
        entry.is_entry = True
        graph.add_node(entry.node_id, obj=entry)
        
        exit_node = CFGNode(self._next_id())
        exit_node.is_exit = True
        graph.add_node(exit_node.node_id, obj=exit_node)
        
        if raw_ast is None:
            # Fallback if no AST available
            graph.add_edge(entry.node_id, exit_node.node_id)
            return graph

        # Traverse body of function
        body_node = None
        if func.language == Language.PYTHON:
            body_node = raw_ast.child_by_field_name("body")
        elif func.language == Language.JAVASCRIPT:
            body_node = raw_ast.child_by_field_name("body")

        if body_node:
            last_nodes = self._traverse_statements(body_node, graph, [entry], func.source_code, func.language)
            for ln in last_nodes:
                graph.add_edge(ln.node_id, exit_node.node_id)
        else:
            graph.add_edge(entry.node_id, exit_node.node_id)
            
        return graph

    def _next_id(self) -> int:
        self._node_counter += 1
        return self._node_counter

    def _get_text(self, node: Any, source: str) -> str:
        try:
            return source[node.start_byte:node.end_byte]
        except Exception:
            return ""

    def _traverse_statements(
        self, body_node: Any, graph: nx.DiGraph, current_parents: list[CFGNode], source: str, lang: Language
    ) -> list[CFGNode]:
        """
        Traverse a sequence of statements.
        Returns the list of leaf nodes (endpoints) from this block.
        """
        parents = current_parents
        
        for child in body_node.children:
            if not child.is_named:
                continue
                
            node_type = child.type
            
            # Simplified heuristic for branching
            if node_type in ("if_statement", "while_statement", "for_statement", "try_statement"):
                new_node = CFGNode(self._next_id(), child, self._get_text(child, source))
                graph.add_node(new_node.node_id, obj=new_node)
                for p in parents:
                    graph.add_edge(p.node_id, new_node.node_id)
                
                # We would typically parse the condition and the branches recursively.
                # For simplicity in this scaffold, we just chain it and assume
                # control can flow around it or through it.
                parents = [new_node]
            elif node_type in ("return_statement", "break_statement", "continue_statement"):
                new_node = CFGNode(self._next_id(), child, self._get_text(child, source))
                graph.add_node(new_node.node_id, obj=new_node)
                for p in parents:
                    graph.add_edge(p.node_id, new_node.node_id)
                # Terminal statement for this block
                parents = [new_node]
            else:
                # Normal statement
                new_node = CFGNode(self._next_id(), child, self._get_text(child, source))
                graph.add_node(new_node.node_id, obj=new_node)
                for p in parents:
                    graph.add_edge(p.node_id, new_node.node_id)
                parents = [new_node]
                
        return parents
