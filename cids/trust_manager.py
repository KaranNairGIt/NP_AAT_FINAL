"""Bounded, explainable peer credibility scores in [0, 1].

Rules (no hidden ground truth is used):
* start at `initial_trust`
* evidence that expires corroborated by another independent node: + reward
* evidence that expires uncorroborated: - penalty
* authenticated but invalid message (bad content / stale / replayed): - invalid_penalty
The node trusts itself fully (1.0). The collective decision is never used
as proof of honesty, which avoids circular updates.
"""
from __future__ import annotations


class TrustManager:
    def __init__(self, own_id: str, peers: list[str], initial: float,
                 reward: float, penalty: float, invalid_penalty: float) -> None:
        self.own_id = own_id
        self.reward, self.penalty, self.invalid_penalty = reward, penalty, invalid_penalty
        self.scores: dict[str, float] = {p: initial for p in peers if p != own_id}
        self.history: list[dict] = [
            {"round": 0, "node": own_id, "peer": p, "old": initial, "new": initial,
             "reason": "initial"} for p in self.scores]

    def get(self, peer: str) -> float:
        if peer == self.own_id:
            return 1.0
        return self.scores.get(peer, 0.0)

    def _update(self, peer: str, delta: float, reason: str, now: int) -> None:
        if peer not in self.scores or delta == 0:
            return
        old = self.scores[peer]
        new = round(min(1.0, max(0.0, old + delta)), 4)
        self.scores[peer] = new
        self.history.append({"round": now, "node": self.own_id, "peer": peer,
                             "old": old, "new": new, "reason": reason})

    def corroborated(self, peer: str, now: int) -> None:
        self._update(peer, self.reward, "evidence corroborated by another node", now)

    def uncorroborated(self, peer: str, now: int) -> None:
        self._update(peer, -self.penalty, "evidence never corroborated", now)

    def invalid(self, peer: str, reason: str, now: int) -> None:
        self._update(peer, -self.invalid_penalty, f"invalid authenticated message ({reason})", now)
