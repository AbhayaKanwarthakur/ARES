"""Synthetic defensive response environment for Gymnasium and Stable-Baselines3."""
import numpy as np
import gymnasium as gym
from gymnasium import spaces

from .features import extract_features
from .simulator import KINDS, generate_events, process_event

SCENARIOS = (
    "Normal Traffic", "Traffic Spike", "Legitimate Unusual Activity",
    "Port Scan", "Brute Force", "Traffic Flood", "DDoS",
)
THREATS = {"Port Scan", "Brute Force", "Traffic Flood", "DDoS"}
ACTION_NAMES = ("monitor", "alert", "simulated_rate_limit",
                "simulated_temporary_block", "human_review")
ACTION_COSTS = np.array([0.0, 0.15, 0.4, 0.8, 0.3], dtype=np.float32)
ACTION_DISRUPTION = np.array([0.0, 0.0, 0.15, 0.55, 0.0], dtype=np.float32)
OBSERVATION_FIELDS = (
    "packets_per_second", "failed_login_count", "request_count",
    "distinct_ports", "unusual_port", "login_frequency", "remaining_threat",
)


class ARESResponseEnv(gym.Env):
    """One scenario per episode; labels are used only to compute simulator feedback.

    Reward = +2.5 for verified containment, +0.6 for alerting a verified threat,
    -4.0 for falsely rate-limiting benign activity, -8.0 for falsely blocking it,
    and -1.5 for a false alert/review. Every step also pays response cost and
    availability disruption (each weighted by 1). Monitoring an uncontained threat
    costs 0.8. Containment requires choosing rate-limit or temporary-block on a threat.
    Action efficacy reduces severity visible in subsequent observations; temporary
    blocks suppress more traffic but harm availability. Labels never enter observations.
    """
    metadata = {"render_modes": []}

    def __init__(self, episode_length=8, seed=None):
        super().__init__()
        if episode_length < 1:
            raise ValueError("episode_length must be positive")
        self.episode_length = episode_length
        self.observation_space = spaces.Box(
            low=np.zeros(len(OBSERVATION_FIELDS), dtype=np.float32),
            high=np.ones(len(OBSERVATION_FIELDS), dtype=np.float32),
            dtype=np.float32,
        )
        self.action_space = spaces.Discrete(len(ACTION_NAMES))
        self._seed = seed
        self.np_random = None
        self._step = 0
        self._remaining = 1.0
        self._scenario = None
        self._features = None
        self._last_observation = None
        self._contained = False

    def _observe(self):
        f = self._features
        return np.asarray([
            min(1.0, f["packets_per_second"] / 5000),
            min(1.0, f["failed_login_count"] / 20),
            min(1.0, f["request_count"] / 2000),
            min(1.0, f["distinct_ports"] / 100),
            f["unusual_port"],
            min(1.0, f["login_frequency"] / 5),
            self._remaining,
        ], dtype=np.float32)

    def reset(self, *, seed=None, options=None):
        super().reset(seed=seed if seed is not None else self._seed)
        options = options or {}
        scenario = options.get("scenario")
        if scenario is not None and scenario not in SCENARIOS:
            raise ValueError(f"unsupported scenario: {scenario}")
        self._scenario = scenario or SCENARIOS[int(self.np_random.integers(len(SCENARIOS)))]
        event_seed = int(self.np_random.integers(0, 2**31))
        events = [process_event(e) for e in generate_events(
            self._scenario, n_events=20, seed=event_seed)]
        self._features = extract_features(events)
        self._step = 0
        self._remaining = 1.0
        self._contained = False
        obs = self._observe()
        self._last_observation = obs.copy()
        return obs, {"scenario": self._scenario}

    def step(self, action):
        if self._last_observation is None:
            raise RuntimeError("reset must be called before step")
        if not self.action_space.contains(action):
            raise ValueError(f"invalid action: {action}")
        action = int(action)
        threat = self._scenario in THREATS
        reward = -float(ACTION_COSTS[action] + ACTION_DISRUPTION[action])
        efficacy = (0.0, 0.05, 0.35, 0.75, 0.1)[action]
        remaining_after_action = self._remaining * (1.0 - efficacy)
        contained = bool(
            threat and action in (2, 3) and not self._contained
            and remaining_after_action <= 0.5
        )
        if contained:
            reward += 2.5
            self._contained = True
        elif threat and action == 1:
            reward += 0.6
        elif threat and action in (0, 4):
            reward -= 0.8
        elif not threat and action == 2:
            reward -= 4.0
        elif not threat and action == 3:
            reward -= 8.0
        elif not threat and action in (1, 4):
            reward -= 1.5

        self._remaining = max(0.0, remaining_after_action)
        for name in ("packets_per_second", "failed_login_count", "request_count",
                     "distinct_ports", "login_frequency"):
            self._features[name] = int(self._features[name] * (1.0 - efficacy)) if name in (
                "failed_login_count", "request_count", "distinct_ports"
            ) else self._features[name] * (1.0 - efficacy)
        self._step += 1
        terminated = self._remaining <= 0.01
        truncated = self._step >= self.episode_length and not terminated
        obs = self._observe()
        self._last_observation = obs.copy()
        info = {
            "scenario": self._scenario,
            "verified_threat": threat,
            "contained": contained,
            "false_positive": bool(not threat and action != 0),
            "action_name": ACTION_NAMES[action],
        }
        return obs, float(reward), terminated, truncated, info
