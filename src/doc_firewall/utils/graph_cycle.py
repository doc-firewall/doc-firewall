"""Iterative DFS cycle detection on small reference graphs.

Used by PDF page-tree (D.14) and PPTX slide-master/layout reference graphs
to detect document structures that would cause infinite recursion in
downstream parsers.
"""
from __future__ import annotations

from typing import Hashable, Iterable, Mapping

_WHITE, _GRAY, _BLACK = 0, 1, 2


def has_cycle(graph: Mapping[Hashable, Iterable[Hashable]]) -> bool:
    """Return True if `graph` (adjacency map) contains a directed cycle.

    The graph need not be connected. Missing nodes (referenced but absent
    from the adjacency map) are treated as terminal (no out-edges).
    """
    if not graph:
        return False

    color: dict[Hashable, int] = {n: _WHITE for n in graph}

    def _dfs(start: Hashable) -> bool:
        stack: list[tuple[Hashable, Iterable[Hashable]]] = [
            (start, iter(graph.get(start, ())))
        ]
        color[start] = _GRAY
        while stack:
            node, children = stack[-1]
            advanced = False
            for nb in children:
                state = color.get(nb, _WHITE)
                if state == _GRAY:
                    return True
                if state == _WHITE and nb in graph:
                    color[nb] = _GRAY
                    stack.append((nb, iter(graph.get(nb, ()))))
                    advanced = True
                    break
            if not advanced:
                color[node] = _BLACK
                stack.pop()
        return False

    for node in list(graph):
        if color.get(node, _WHITE) == _WHITE and _dfs(node):
            return True
    return False
