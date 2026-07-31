"""
tqsc/deception/rl_agent.py — Reinforcement Learning Agent del ABH Engine.
Optimiza qué token generar y dónde plantarlo usando Tabular Q-learning with epsilon-greedy exploration.
State: 8-dimensional state vector
Action: Q-table based action selection
Reward: interacción × tiempo de retardo − detección + calidad de inteligencia
"""
import logging, time, math, json, random
from typing import Optional
from collections import deque

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    import torch.nn.functional as F
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

LOG = logging.getLogger("tqsc.deception.rl_agent")

# ──────────────────────────────────────────────────────────
# Tabular Q-learning Agent (Q-table based action selection)
# ──────────────────────────────────────────────────────────

TOKEN_TYPES = ["db_creds", "aws_key", "jwt", "ad_creds",
               "github_token", "slack_token", "ssh_key", "config_file"]
LOCATION_BUCKETS = ["filesystem_www", "filesystem_config", "filesystem_backup",
                    "memory_lsass", "cloud_iam", "ad_user", "ad_spn"]

# Reward weights
ALPHA = 1.0   # Interacción (peso positivo)
BETA = 0.5    # Tiempo de retardo (peso positivo)
GAMMA = 2.0   # Detección (peso negativo)
DELTA = 0.8   # Calidad de inteligencia (peso positivo)


if TORCH_AVAILABLE:
    class DQN(nn.Module):
        def __init__(self, state_dim, n_actions):
            super(DQN, self).__init__()
            self.fc1 = nn.Linear(state_dim, 64)
            self.fc2 = nn.Linear(64, 64)
            self.fc3 = nn.Linear(64, n_actions)

        def forward(self, x):
            x = F.relu(self.fc1(x))
            x = F.relu(self.fc2(x))
            return self.fc3(x)

class SimulatedPolicy:
    """Tabular Q-learning or Deep Q-Network with epsilon-greedy exploration."""

    def __init__(self, n_actions: int = 16, learning_rate: float = 0.1,
                 epsilon: float = 0.2, gamma: float = 0.9):
        self.n_actions = n_actions
        self.lr = learning_rate
        self.epsilon = epsilon
        self.gamma = gamma  # Discount factor
        self.episode_count = 0
        self.total_reward = 0.0

        self.use_torch = TORCH_AVAILABLE
        if self.use_torch:
            self.state_dim = 8
            self.model = DQN(self.state_dim, self.n_actions)
            # Adjust learning rate for Adam
            self.optimizer = optim.Adam(self.model.parameters(), lr=1e-3)
            self.loss_fn = nn.MSELoss()
        else:
            self.q_table: dict[int, list[float]] = {}

    def _hash_state(self, state_vector: list) -> int:
        """Convierte state vector en hash para Q-table lookups."""
        if not state_vector:
            return 0
        danger = int(state_vector[0] * 10) if len(state_vector) > 0 else 0
        ttp_idx = int(state_vector[1]) if len(state_vector) > 1 else 0
        return (danger * 100) + (ttp_idx % 100)

    def get_action(self, state_vector: list) -> int:
        """Selecciona acción usando ε-greedy."""
        # Exploración
        if random.random() < self.epsilon:
            return random.randint(0, self.n_actions - 1)

        # Explotación
        if self.use_torch:
            self.model.eval()
            state_tensor = torch.tensor(state_vector, dtype=torch.float32).unsqueeze(0)
            with torch.no_grad():
                q_values = self.model(state_tensor)
            return torch.argmax(q_values).item()
        else:
            state_hash = self._hash_state(state_vector)
            if state_hash not in self.q_table:
                self.q_table[state_hash] = [0.0] * self.n_actions
            return max(range(self.n_actions), key=lambda a: self.q_table[state_hash][a])

    def update(self, state_vector: list, action: int, reward: float,
               next_state_vector: list):
        """Actualiza la política con Q-learning o DQN."""
        if self.use_torch:
            self.model.train()
            
            state_tensor = torch.tensor(state_vector, dtype=torch.float32).unsqueeze(0)
            next_state_tensor = torch.tensor(next_state_vector, dtype=torch.float32).unsqueeze(0)
            reward_tensor = torch.tensor([reward], dtype=torch.float32)
            
            q_values = self.model(state_tensor)
            current_q = q_values[0, action]
            
            with torch.no_grad():
                next_q_values = self.model(next_state_tensor)
                max_next_q = torch.max(next_q_values)
                
            target_q = reward_tensor + self.gamma * max_next_q
            
            loss = self.loss_fn(current_q.unsqueeze(0), target_q.unsqueeze(0))
            
            self.optimizer.zero_grad()
            loss.backward()
            self.optimizer.step()
        else:
            state_hash = self._hash_state(state_vector)
            next_hash = self._hash_state(next_state_vector)

            if state_hash not in self.q_table:
                self.q_table[state_hash] = [0.0] * self.n_actions
            if next_hash not in self.q_table:
                self.q_table[next_hash] = [0.0] * self.n_actions

            best_next = max(self.q_table[next_hash])
            td_target = reward + self.gamma * best_next
            td_error = td_target - self.q_table[state_hash][action]
            self.q_table[state_hash][action] += self.lr * td_error

        self.episode_count += 1
        self.total_reward += reward

        # Decaer epsilon
        self.epsilon = max(0.01, self.epsilon * 0.999)

    def estado(self) -> dict:
        return {
            "model": "DQN" if self.use_torch else "Tabular",
            "q_table_size": 0 if self.use_torch else len(self.q_table),
            "episodes": self.episode_count,
            "total_reward": round(self.total_reward, 2),
            "epsilon": round(self.epsilon, 4),
        }


class RLAgent:
    """Agente RL completo del ABH Engine. Orquesta la política,
    gestiona episodios por sesión de atacante y calcula recompensas."""

    def __init__(self):
        self.policy = SimulatedPolicy(
            n_actions=len(TOKEN_TYPES) * len(LOCATION_BUCKETS),
        )
        self._episodes: dict[str, dict] = {}
        self._interaction_log: list[dict] = []
        self._max_history = 1000

    # ─────────────────────────────────────────────
    # State representation
    # ─────────────────────────────────────────────

    def _build_state_vector(self, profile: dict) -> list:
        """Construye 8-dimensional state vector a partir del perfil:
        [danger, ttp_idx, session_count, tool_count,
         has_high_value, is_night, is_burst, intent_code]"""
        if not profile:
            return [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]

        return [
            profile.get("danger_score", 0.0),
            # Índice de la TTP dominante
            float(hash(str(profile.get("ttp_sequence", []))) % 100) / 100.0,
            min(1.0, profile.get("session_count", 0) / 10.0),
            min(1.0, len(profile.get("tooling", [])) / 5.0),
            1.0 if profile.get("target_preference", {}).get("high_value_files") else 0.0,
            1.0 if profile.get("timing_profile", {}).get("nighttime_ops") else 0.0,
            1.0 if profile.get("timing_profile", {}).get("burst_detected") else 0.0,
            0.5,  # intent_code placeholder
        ]

    # ─────────────────────────────────────────────
    # Action to token type & location
    # ─────────────────────────────────────────────

    def decode_action(self, action: int) -> dict:
        """Convierte índice de acción en {token_type, location_bucket}."""
        n_types = len(TOKEN_TYPES)
        type_idx = action % n_types
        loc_idx = (action // n_types) % len(LOCATION_BUCKETS)
        return {
            "token_type": TOKEN_TYPES[type_idx],
            "location_bucket": LOCATION_BUCKETS[loc_idx],
        }

    def encode_action(self, token_type: str, location_bucket: str) -> int:
        """Convierte {token_type, location_bucket} en índice de acción."""
        type_idx = TOKEN_TYPES.index(token_type) if token_type in TOKEN_TYPES else 0
        loc_idx = LOCATION_BUCKETS.index(location_bucket) if location_bucket in LOCATION_BUCKETS else 0
        return type_idx + loc_idx * len(TOKEN_TYPES)

    # ─────────────────────────────────────────────
    # Episodios por sesión
    # ─────────────────────────────────────────────

    def start_episode(self, session_id: str, profile: dict) -> dict:
        """Inicia un nuevo episodio para una sesión de atacante."""
        self._episodes[session_id] = {
            "start_time": time.time(),
            "state": self._build_state_vector(profile),
            "actions_taken": [],
            "total_reward": 0.0,
        }
        return self.select_action(session_id, profile)

    def select_action(self, session_id: str, profile: dict) -> dict:
        """Selecciona la mejor acción (token a generar) para el estado actual."""
        episode = self._episodes.get(session_id)
        if not episode:
            return self.decode_action(0)

        state = self._build_state_vector(profile)
        action_idx = self.policy.get_action(state)
        decoded = self.decode_action(action_idx)

        episode["actions_taken"].append({
            "action_idx": action_idx,
            "timestamp": time.time(),
            "decoded": decoded,
        })

        return decoded

    # ─────────────────────────────────────────────
    # Feedback loop
    # ─────────────────────────────────────────────

    def process_feedback(self, session_id: str, profile: dict,
                         token_interacted: bool = False,
                         token_detected: bool = False,
                         time_delayed: float = 0.0,
                         intel_quality: float = 0.0) -> float:
        """Procesa feedback de la interacción con el token.
        Calcula recompensa y actualiza la política.

        Reward = α * I + β * D_t - γ * E + δ * Q

        donde:
          I = interacción (1.0 si usó, 0.0 si no)
          D_t = tiempo de retardo normalizado
          E = detección (1.0 si detectó)
          Q = calidad de inteligencia recolectada
        """
        episode = self._episodes.get(session_id)
        if not episode or not episode["actions_taken"]:
            return 0.0

        last_action = episode["actions_taken"][-1]

        # Calcular recompensa
        I = 1.0 if token_interacted else 0.0
        D_t = min(time_delayed / 300.0, 1.0)  # Normalizar a [0, 1]
        E = 1.0 if token_detected else 0.0
        Q = min(intel_quality, 1.0)

        reward = (ALPHA * I) + (BETA * D_t) - (GAMMA * E) + (DELTA * Q)

        # Actualizar política
        state = episode["state"]
        next_state = self._build_state_vector(profile)
        self.policy.update(state, last_action["action_idx"], reward, next_state)

        episode["state"] = next_state
        episode["total_reward"] += reward

        # Log
        self._interaction_log.append({
            "session_id": session_id,
            "timestamp": time.time(),
            "action": last_action["decoded"],
            "reward": round(reward, 4),
            "interacted": token_interacted,
            "detected": token_detected,
            "delay": round(time_delayed, 2),
            "intel_quality": round(intel_quality, 2),
        })
        if len(self._interaction_log) > self._max_history:
            self._interaction_log = self._interaction_log[-self._max_history:]

        # Si el agente interactuó mucho o detectó, siguiente acción muta
        if token_detected:
            self.policy.epsilon = min(0.5, self.policy.epsilon + 0.05)

        return round(reward, 4)

    def end_episode(self, session_id: str):
        """Finaliza un episodio y registra métricas."""
        episode = self._episodes.pop(session_id, None)
        if episode:
            LOG.info("RL: episodio %s finalizado — reward total=%.2f, acciones=%d",
                     session_id, episode["total_reward"], len(episode["actions_taken"]))

    def get_reward_breakdown(self, interacted: bool = False, detected: bool = False,
                              delay: float = 0.0, intel: float = 0.0) -> dict:
        """Muestra desglose teórico de una recompensa."""
        I = 1.0 if interacted else 0.0
        D_t = min(delay / 300.0, 1.0)
        E = 1.0 if detected else 0.0
        Q = min(intel, 1.0)
        return {
            "interaction": round(ALPHA * I, 2),
            "delay": round(BETA * D_t, 2),
            "detection_penalty": round(-GAMMA * E, 2),
            "intel_bonus": round(DELTA * Q, 2),
            "total": round(ALPHA * I + BETA * D_t - GAMMA * E + DELTA * Q, 2),
        }

    def estado(self) -> dict:
        return {
            "policy": self.policy.estado(),
            "active_episodes": len(self._episodes),
            "total_interactions": len(self._interaction_log),
            "reward_weights": {"alpha": ALPHA, "beta": BETA, "gamma": GAMMA, "delta": DELTA},
        }
