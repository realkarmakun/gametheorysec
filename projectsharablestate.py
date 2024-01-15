from dataclasses import dataclass, field
from typing import List
from enum import Enum
import numpy as np
from typing import Callable

from intvalpy import Interval


class DefenderCriteria(Enum):
    WALD_MAXIMIN = ('Критерий крайнего пессимизма Вальда', r'''
    
    Ориентация на неблагоприятные условия. В худших условиях гарантирует минимальный ущерб.
    
    $$A, B$$ - матрицы администратора и злоумышленника соотвественно
    
    $$a_{ij}, b_{ij}$$ - элементы матриц
    
    $$W_{i_0}(A) = \underset{\min}{i} W_i (A) = \underset{\min}{i} \underset{\max}{j} a_{ij} $$
    
    Позволяет повысить значимость результата при защиты от наиболее частых атак.
    ''')
    #BAYES_EXPECTATION = ('Критерий математического ожидания Байеса', r'''
    #Предполагает известность вероятностей проведения атак $$p_j$$
    #
    #$$W_{i_0} (A) = \underset{\min}{i} W_i(A) = \underset{\min}{i} \sum\limits_{j} p_j a_{ij}$$
    #''')
    LAPLACE_REASON = ('Критерий недостаточного основания Лапласа', r'''
    
    Можно использовать при наличии неполной информации о вероятностях реализации атак 
    или одинаковых вероятностях стратегии злоумышленника.
    
    $$W_i (C) = \frac{1}{K} \sum\limits_{j=1}^{K} c_{ij}$$
    
    Минимизация проигрыша вместо максимизации среднего выигрыша.
    
    В случае использования Монте-Карло для каждой стратегии администратора:
    
    $$\overline{x_{y_i}} = \frac{1}{N_{y_i}} \sum\limits_{j=1}^{N_{y_i}} x_{y_i j}$$, $$N -$$ число симуляций
    
    С ростом числа симуляций $$\overline{x_{y_i}}$$ будет стремится к $$W_i (C)$$
    
    $$M \overline{x_{y_i}} \to W_i(C)$$, при $$N_{y_i} \to \infty$$
    
    ''')
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
    MonteCarlo = ("Монте-Карло", "plainrandommontecarlo")
    UpperConfidenceBound = ("Upper-Confidence-Bound", "ucb")

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
