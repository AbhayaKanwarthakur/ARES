import os
import tempfile
import unittest

import numpy as np
from stable_baselines3 import DQN

from agent.rl_env import ACTION_NAMES, ARESResponseEnv
from train_rl import evaluate_policy, fixed_rule_policy, train_and_evaluate


class RLTests(unittest.TestCase):
    def test_spaces_reset_and_action_transition(self):
        env = ARESResponseEnv(episode_length=3)
        obs, info = env.reset(seed=12, options={"scenario": "Brute Force"})
        self.assertTrue(env.observation_space.contains(obs))
        self.assertEqual(info["scenario"], "Brute Force")
        next_obs, reward, terminated, truncated, result = env.step(3)
        self.assertTrue(env.observation_space.contains(next_obs))
        self.assertLess(next_obs[-1], obs[-1])
        self.assertGreater(reward, 0)
        self.assertTrue(result["contained"])
        self.assertFalse(terminated)
        self.assertFalse(truncated)

    def test_benign_block_penalty_exceeds_threat_containment_reward(self):
        env = ARESResponseEnv()
        env.reset(seed=1, options={"scenario": "Normal Traffic"})
        _, benign_reward, _, _, _ = env.step(3)
        env.reset(seed=1, options={"scenario": "Brute Force"})
        _, threat_reward, _, _, _ = env.step(3)
        self.assertLess(benign_reward, threat_reward)

    def test_training_saves_loadable_policy_and_evaluates_same_seeds(self):
        with tempfile.TemporaryDirectory() as tmp:
            model_path = os.path.join(tmp, "checkpoint")
            result = train_and_evaluate(
                timesteps=128, eval_episodes=3, seed=17, episode_length=3,
                model_path=model_path,
                results_path=os.path.join(tmp, "metrics.json"),
                episode_log_path=os.path.join(tmp, "episodes.csv"),
            )
            self.assertTrue(os.path.isfile(model_path + ".zip"))
            loaded = DQN.load(model_path)
            obs, _ = ARESResponseEnv().reset(seed=99)
            action, _ = loaded.predict(obs, deterministic=True)
            self.assertIn(int(action), range(len(ACTION_NAMES)))
            self.assertEqual(result["trained_policy"]["episodes"], 3)
            self.assertEqual(result["fixed_rule_policy"]["episodes"], 3)
            self.assertEqual(result["heldout_seeds"], [100017, 100018, 100019])

    def test_policy_evaluation_is_repeatable(self):
        seeds = [900, 901]
        first = evaluate_policy(fixed_rule_policy, seeds, episode_length=2)
        second = evaluate_policy(fixed_rule_policy, seeds, episode_length=2)
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
