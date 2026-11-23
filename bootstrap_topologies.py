"""Этап 2, часть 5: учебные bootstrap-графы и объективный экспорт DHT-метрик.

Это оркестратор эксперимента, НЕ часть рабочего поиска DHT. Он знает
NodeID тестовых целей для проверки, но НЕ передаёт полный реестр узлам.
"""
from __future__ import annotations

import json
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path

from dht_network import DHTNode
from identity import load_or_create_identity

NAMES = tuple('ABCDE')


def load_scheme(path: Path) -> dict:
    """Прочитать и строго проверить схему, не принимая внешние IP-адреса."""
    config = json.loads(Path(path).read_text(encoding='utf-8'))
    if not isinstance(config, dict):
        raise ValueError('Конфигурация должна быть JSON-объектом')
    if set(config) != {'scheme', 'nodes', 'bootstrap_edges', 'join_order', 'k', 'alpha', 'timeout_seconds'}:
        raise ValueError('Неожиданные или отсутствующие поля конфигурации')
    if config['scheme'] not in ('star', 'ring'):
        raise ValueError('Неизвестная bootstrap-схема')
    if config['nodes'] != list(NAMES):
        raise ValueError('В этом пилоте должны быть ровно узлы A, B, C, D, E')
    if config['k'] != 3 or config['alpha'] != 3:
        raise ValueError('Для базового уровня k=3, alpha=3')
    if not isinstance(config['timeout_seconds'], (float, int)) or isinstance(config['timeout_seconds'], bool) or not 0.2 <= config['timeout_seconds'] <= 4.0:
        raise ValueError('Неверный timeout_seconds')
    if len(config['join_order']) != len(set(config['join_order'])):
        raise ValueError('Повтор узла в join_order')
    edges = config['bootstrap_edges']
    if not isinstance(edges, list) or not all(isinstance(e, list) and len(e) == 2 for e in edges):
        raise ValueError('Неверный bootstrap_edges')
    mapping = {}
    for child, parent in edges:
        if child not in NAMES or parent not in NAMES or child == parent or child in mapping:
            raise ValueError('Неверная или повторная bootstrap-связь')
        mapping[child] = parent
    if config['scheme'] == 'star':
        if mapping != {'B': 'A', 'C': 'A', 'D': 'A', 'E': 'A'} or config['join_order'] != ['B', 'C', 'D', 'E']:
            raise ValueError('Star: все листья должны знать только seed A')
    else:
        if mapping != {'A': 'B', 'B': 'C', 'C': 'D', 'D': 'E', 'E': 'A'} or config['join_order'] != list(NAMES):
            raise ValueError('Ring: каждый узел должен знать следующего соседа')
    return config


def contact_ids(node: DHTNode) -> set[bytes]:
    """Считать текущие контакты конкретного узла; только для ОРКЕСТРАТОРА."""
    return {c.node_id for group in node.routing.bucket_contents().values() for c in group}


def snapshot(node: DHTNode) -> dict:
    buckets = node.routing.bucket_contents()
    return {
        'contact_count': sum(len(items) for items in buckets.values()),
        'buckets': {str(i): [c.node_id.hex() for c in items] for i, items in sorted(buckets.items())},
        'bucket_occupancy': {str(i): len(items) for i, items in sorted(buckets.items())},
    }


def summarize(lookups: list[dict]) -> dict:
    duration = [entry['elapsed_ms'] for entry in lookups]
    successes = sum(1 for item in lookups if item['found'])
    absent = [item for item in lookups if item['unknown_before']]
    return {
        'count': len(lookups),
        'successes': successes,
        'success_rate': round(successes / len(lookups), 4) if lookups else None,
        'unknown_before': len(absent),
        'unknown_successes': sum(1 for item in absent if item['found']),
        'multihop_unknown': sum(1 for item in absent if item['found'] and item['iterations'] >= 2),
        'mean_lookup_ms': round(statistics.mean(duration), 3) if duration else None,
        'median_lookup_ms': round(statistics.median(duration), 3) if duration else None,
        'min_lookup_ms': round(min(duration), 3) if duration else None,
        'max_lookup_ms': round(max(duration), 3) if duration else None,
        'mean_rpc': round(statistics.mean(item['rpc_count'] for item in lookups), 3) if lookups else None,
        'mean_iterations': round(statistics.mean(item['iterations'] for item in lookups), 3) if lookups else None,
    }


def run_scheme(config: dict, state_root: Path, *, pair_names: list[tuple[str, str]] | None = None) -> dict:
    """Запустить один холодный пилот. Только оркестратор знает все имена/ID.

    Узел в join() получает исключительно свой один seed-адрес; в его
    DHTNode нет ни полного реестра, ни списка участников эксперимента.
    """
    pair_names = pair_names if pair_names is not None else [
        (a, b) for a in NAMES for b in NAMES if a != b
    ]
    if any(a not in NAMES or b not in NAMES or a == b for a, b in pair_names):
        raise ValueError('Недопустимая тестовая пара узлов')
    nodes: dict[str, DHTNode] = {}
    report = {
        'experiment': 'stage2_bootstrap_pilot',
        'created_utc': datetime.now(timezone.utc).isoformat(),
        'config': config,
        'nodes': [],
        'joins': {},
        'routing_before_lookup': {},
        'lookups': [],
    }
    try:
        for name in NAMES:
            ident = load_or_create_identity(Path(state_root) / f'node_{name.lower()}')
            node = DHTNode(ident, name, timeout=config['timeout_seconds'], k=3, alpha=3)
            node.start()
            nodes[name] = node
            report['nodes'].append({'name': name, 'node_id': ident.node_id.hex(), 'host': node.host, 'port': node.port})
        mapping = {child: parent for child, parent in config['bootstrap_edges']}
        for name in config['join_order']:
            seed = nodes[mapping[name]]
            start = time.perf_counter()
            joined = nodes[name].join([(seed.host, seed.port)])
            joined['join_elapsed_ms'] = round((time.perf_counter() - start) * 1000, 3)
            report['joins'][name] = joined
        report['routing_before_lookup'] = {name: snapshot(n) for name, n in nodes.items()}
        for origin, target in pair_names:
            source = nodes[origin]
            target_id = nodes[target].identity.node_id
            unknown = target_id not in contact_ids(source)
            result = source.lookup_node(target_id).as_dict()
            report['lookups'].append({'from': origin, 'to': target,
                'unknown_before': unknown, **result})
        report['routing_after_lookup'] = {name: snapshot(n) for name, n in nodes.items()}
        report['summary'] = summarize(report['lookups'])
        report['summary'].update({
            'join_count': len(report['joins']),
            'mean_join_ms': round(statistics.mean(v['join_elapsed_ms'] for v in report['joins'].values()), 3),
            'mean_join_rpc': round(statistics.mean(v['self_lookup_rpc'] for v in report['joins'].values()), 3),
            'mean_contacts_after_join': round(statistics.mean(v['contact_count'] for v in report['routing_before_lookup'].values()), 3),
            'min_contacts_after_join': min(v['contact_count'] for v in report['routing_before_lookup'].values()),
            'max_contacts_after_join': max(v['contact_count'] for v in report['routing_before_lookup'].values()),
        })
        return report
    finally:
        for node in nodes.values():
            node.stop()
