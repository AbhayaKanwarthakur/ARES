"""Train and evaluate the synthetic ARES DQN policy.

Examples:
  python train_rl.py --smoke
  python train_rl.py --timesteps 10000 --eval-episodes 50 --seed 7
"""
import argparse
import csv
import json
import os
import random

import numpy as np
import torch
from stable_baselines3 import DQN
from stable_baselines3.common.monitor import Monitor
from stable_baselines3.common.utils import set_random_seed

from agent.rl_env import ACTION_NAMES, ARESResponseEnv, SCENARIOS

ROOT = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(ROOT, "models", "ares_dqn")
RESULTS_PATH = os.path.join(ROOT, "data", "ares_rl_evaluation.json")
EPISODE_LOG_PATH = os.path.join(ROOT, "data", "ares_rl_episodes.csv")


def fixed_rule_policy(obs):
    """Fixed response baseline; thresholds use observations only."""
    pps, fails, requests, ports, unusual, login_rate, _ = obs
    if fails >= 0.2 and login_rate >= 0.1:
        return 3
    if ports >= 0.08:
        return 2
    if pps >= 0.2 or requests >= 0.25:
        return 2
    if unusual >= 0.4:
        return 4
    return 0


def evaluate_policy(policy, seeds, episode_length=8):
    totals = []
    action_counts = {name: 0 for name in ACTION_NAMES}
    episode_outcomes = []
    outcomes = {"threat_episodes": 0, "contained_episodes": 0,
                "false_positive_actions": 0, "episodes": 0}
    for seed in seeds:
        env = ARESResponseEnv(episode_length=episode_length)
        obs, _ = env.reset(seed=seed)
        total, labels = 0.0, []
        episode_actions = {name: 0 for name in ACTION_NAMES}
        done = False
        while not done:
            action = int(policy(obs))
            obs, reward, terminated, truncated, info = env.step(action)
            done = terminated or truncated
            total += reward
            action_counts[info["action_name"]] += 1
            episode_actions[info["action_name"]] += 1
            outcomes["false_positive_actions"] += int(info["false_positive"])
            labels.append(info)
        threat = labels[0]["verified_threat"]
        outcomes["threat_episodes"] += int(threat)
        outcomes["contained_episodes"] += int(threat and any(x["contained"] for x in labels))
        outcomes["episodes"] += 1
        totals.append(total)
        episode_outcomes.append({
            "seed": seed,
            "scenario": labels[0]["scenario"],
            "reward": total,
            "threat": threat,
            "contained": bool(threat and any(x["contained"] for x in labels)),
            "false_positive_actions": sum(x["false_positive"] for x in labels),
            "action_frequencies": episode_actions,
        })
    n = max(outcomes["episodes"], 1)
    t = outcomes["threat_episodes"]
    return {
        "episodes": n,
        "mean_reward": float(np.mean(totals)),
        "std_reward": float(np.std(totals)),
        "containment_rate": outcomes["contained_episodes"] / max(t, 1),
        "false_positive_actions": outcomes["false_positive_actions"],
        "action_frequencies": action_counts,
        "episode_outcomes": episode_outcomes,
    }


def train_and_evaluate(timesteps=10_000, eval_episodes=50, seed=7,
                      episode_length=8, model_path=MODEL_PATH,
                      results_path=RESULTS_PATH, episode_log_path=EPISODE_LOG_PATH):
    if timesteps < 1 or eval_episodes < 1:
        raise ValueError("timesteps and eval_episodes must be positive")
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    set_random_seed(seed)
    env = Monitor(ARESResponseEnv(episode_length=episode_length, seed=seed))
    model = DQN(
        "MlpPolicy", env, seed=seed, learning_rate=1e-3, buffer_size=10_000,
        learning_starts=min(100, max(1, timesteps // 10)), batch_size=32,
        gamma=0.95, train_freq=4, target_update_interval=250,
        exploration_fraction=0.3, exploration_final_eps=0.05, verbose=0,
    )
    model.learn(total_timesteps=timesteps)
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    model.save(model_path)
    loaded = DQN.load(model_path)

    # Same deterministic, held-out scenario seeds for both policies.
    heldout_seeds = [seed + 100_000 + i for i in range(eval_episodes)]
    trained = evaluate_policy(
        lambda obs: loaded.predict(obs, deterministic=True)[0], heldout_seeds, episode_length)
    baseline = evaluate_policy(fixed_rule_policy, heldout_seeds, episode_length)
    results = {
        "seed": seed, "timesteps": timesteps, "eval_episodes": eval_episodes,
        "heldout_seeds": heldout_seeds, "scenario_mix": list(SCENARIOS),
        "trained_policy": trained, "fixed_rule_policy": baseline,
        "checkpoint": model_path + ".zip",
    }
    os.makedirs(os.path.dirname(results_path), exist_ok=True)
    with open(results_path, "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2)
    # Monitor's training episode rewards and lengths are persisted separately.
    os.makedirs(os.path.dirname(episode_log_path), exist_ok=True)
    with open(episode_log_path, "w", newline="", encoding="utf-8") as target:
        writer = csv.DictWriter(target, fieldnames=("episode", "reward", "length"))
        writer.writeheader()
        writer.writerows(
            {"episode": index + 1, "reward": reward, "length": length}
            for index, (reward, length) in enumerate(zip(
                env.get_episode_rewards(), env.get_episode_lengths()))
        )
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timesteps", type=int, default=10_000)
    parser.add_argument("--eval-episodes", type=int, default=50)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--episode-length", type=int, default=8)
    parser.add_argument("--model-path", default=MODEL_PATH)
    parser.add_argument("--results-path", default=RESULTS_PATH)
    parser.add_argument("--episode-log-path", default=EPISODE_LOG_PATH)
    parser.add_argument("--smoke", action="store_true", help="quick 256-step, 4-episode check")
    args = parser.parse_args()
    if args.smoke:
        args.timesteps, args.eval_episodes = 256, 4
    results = train_and_evaluate(
        args.timesteps, args.eval_episodes, args.seed, args.episode_length,
        args.model_path, args.results_path, args.episode_log_path,
    )
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
