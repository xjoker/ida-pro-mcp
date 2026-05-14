"""
分布式部署数据协议定义。

定义 Worker 注册信息、路由决策和心跳载荷的数据结构，
用于 Coordinator ↔ Worker ↔ Redis 之间的信息交换。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TypedDict


@dataclass(frozen=True)
class WorkerInfo:
    """Worker 节点的完整信息快照。

    worker_id: UUID4 hex 字符串，由 worker 端生成并在生命周期内不变。
    capabilities: 有序不可变元组，如 ("idalib", "headless", "x86_64")。
    score: 负载评分，数值越低表示节点越空闲，路由优先选低分节点。
    loaded_idb: 当前加载的 IDB 文件绝对路径；未加载任何文件时为 None。
    """

    worker_id: str
    host: str
    port: int
    pid: int
    capabilities: tuple[str, ...]
    loaded_idb: str | None
    score: float
    started_at: float
    last_heartbeat: float


@dataclass(frozen=True)
class RoutingDecision:
    """路由决策结果，由 Registry.select_best() 返回。

    reason 取值：
      "idb_affinity"  - 目标 IDB 已在该 worker 加载，优先复用。
      "lowest_load"   - 无 IDB 亲和性，按 score 选最低负载节点。
      "fallback"      - 兜底选择（当前实现中与 lowest_load 行为相同）。
    """

    worker: WorkerInfo
    reason: str
    candidates_evaluated: int


class HeartbeatPayload(TypedDict):
    """Worker 周期性心跳上报的字段集合（TypedDict，适合直接序列化为 JSON/dict）。

    由 worker 端每 ~5 秒发送一次，Registry.heartbeat() 用其刷新 TTL
    并更新 score / loaded_idb / last_heartbeat / in_flight_tasks。
    in_flight_tasks 仅用于监控，不参与路由决策。
    """

    worker_id: str
    loaded_idb: str | None
    score: float
    in_flight_tasks: int
