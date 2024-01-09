from dataclasses import dataclass, field
from typing import List
from enum import Enum
import numpy as np
from typing import Callable

from intvalpy import Interval


class DefenderCriteria(Enum):
    WALD_MAXIMIN = ('Критерий крайнего пессимизма Вальда', 'wald')
    BAYES_EXPECTATION = ('Критерий математического ожидания Байеса', 'bayes')
    LAPLACE_REASON = ('Критерий недостаточного основания Лапласа', 'laplace')
    SAVAGE_MINIMAX = ('Критерий Сэвиджа', 'savage')

    def __str__(self):
        return str(self.value[0])


class AttackerCriteria(Enum):
    WaldMaximin = ("Критерий крайнего пессимизма Вальда", 'wald')
    ExtremeOptimism = ("Критерий крайнего оптимизма", 'optimism')
    HurwiczOptimPessim = ("Критерий пессимизма-оптимизма Гурвица", "hurwicz")
    MinimalRisk = ("Критерий минимального риска", "minrisk")

    def __str__(self):
        return str(self.value[0])


class GameAlgorithm(Enum):
    PlainRandomMonteCarlo = ("Наивный случайный Монте-Карло", "plainrandommontecarlo")

    def __str__(self):
        return str(self.value[0])


@dataclass
class AppEntry:
    app_name: str
    app_price: str
    app_loss: Interval
    app_mitigations: List[str] = field(default_factory=list)

    def as_dict(self):
        return {'app_name': self.app_name, 'app_price': self.app_price, 'app_loss': self.app_loss,
                'app_mitigations': self.app_mitigations}

    def is_mitigation_present(self, mitigation_id: str) -> bool:
        return mitigation_id in self.app_mitigations


@dataclass
class ProjectSettings:
    mitre_domain: str
    mitre_version: str
    attacker_max_interval: int
    attacker_criteria: AttackerCriteria
    defender_criteria: DefenderCriteria
    attacker_tactics: List[str] = field(default_factory=list)
    defender_apps: List[AppEntry] = field(default_factory=list)
