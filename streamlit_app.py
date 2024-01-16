import math
import operator
import random
import time

import intvalpy
import matplotlib.pyplot as plt
import plotly.express as px
import matspy
import numpy as np
import pandas as pd
import scipy as sp
import streamlit as st
from intvalpy import Interval
from humanize.time import precisedelta

import stixlib as sx
from maths import CombinationGenerator
from projectsharablestate import ProjectSettings, AppEntry, DefenderCriteria, AttackerCriteria, GameAlgorithm


@st.cache_data(persist=True)
def cached_get_src():
    thesrc = sx.get_data_from_branch("enterprise-attack")
    # st.success("Fetched latest MITRE ATT&CK data")
    return thesrc


# @st.cache_data(presist=True)
def cached_get_technique_to_mitig_relations(thesrc):
    technique_to_mitig_relations = sx.technique_mitigated_by_mitigations(thesrc)
    return technique_to_mitig_relations


def find_price_for_mitigation(mitigation_id):
    price_val = 0
    loss_val = Interval(0, 0)
    for da in project_settings().defender_apps:
        if mitigation_id in da.app_mitigations:
            price_val += da.app_price
            loss_val += da.app_loss
    return price_val + loss_val.mid.real


def show_result(found_crit, crit_index):
    st.write(f'''
                ### Найденная стратегия Администратора
                Согласно выбранному критерию было найдено его значение:

                $$W_j(A) =$$ {found_crit}

                $$j = $$ {crit_index}
                ''')


def get_strategy_for_comb(combination):
    strategy_data_display = []
    for m in comb_for_criteria:
        name = m.get("name")
        url = ""
        mitre_id = ''
        for ref in m.get("external_references"):
            if ref.get("source_name") == "mitre-attack":
                url = ref.get("url")
                mitre_id = ref.get("external_id")
                break
        strategy_data_display.append((mitre_id, name, url))

    return pd.DataFrame(strategy_data_display, columns=["mitre_id", "name", "url"])


# mean_x_yi - текущее среднее значение для стратегии y_i
# n_yi  = уже проведенные симуляции
def calc_radical_ucb(mean_x_yi, n_yi, n, b):
    return mean_x_yi - (b * math.sqrt((2 * math.log(n)) / n_yi))


def ucb(mitig_max, att_max, simulations_amount, comb_res_m, comb_res_a, b):
    matrix = np.ndarray((simulations_amount, mitig_max), dtype=np.longlong)

    time_taken = time.time()

    progress_text = "Выполняем Upped-Confidence-Bound. Пожалуйста подождите. "
    progress_bar = st.progress(0.0, text=progress_text)

    radical_values = np.zeros(mitig_max)
    already_ran_sim_counts = np.ones(mitig_max, dtype=np.longlong)
    # Проводим для каждой стратегии M симуляций
    for j in range(mitig_max):
        mitig_comb = comb_res_m.unrankVaryingLengthCombination(j)
        # Проводим по одной симуляции для каждой стратегии
        # Случайно выбранная стратегия атаки
        i = random.randrange(0, att_max)
        attack_comb = comb_res_a.unrankVaryingLengthCombination(i)

        # Проверяем что каждая мера защиты в стратегии защиты защищает от стратегий атаки
        # Если хотя бы одна из стратегий защищиает current_val > 0
        for m in mitig_comb:
            for a in attack_comb:
                is_mitigated = sx.does_mitigation_mitigates_technique(
                    relations=m_to_t_relation,
                    technique_id=a.get("id"),
                    mitigation_id=m.get("id"))
                if is_mitigated:
                    matrix[0, j] += find_price_for_mitigation(m.get("id"))

        current_yi = np.ma.masked_equal(matrix[:, j], 0)
        current_mean_for_j = np.mean(current_yi)
        radical_values[j] = calc_radical_ucb(current_mean_for_j, already_ran_sim_counts[j], 1, b)
        progress_bar.progress(j / mitig_max, text=progress_text)

    for n_yi in range(1, simulations_amount):
        # Находим для какой стратегии защиты необходимо провести вычисления
        current_j = radical_values.argmin()
        # Выбираем случайную стратегию атаки
        mitig_comb = comb_res_m.unrankVaryingLengthCombination(current_j)
        i = random.randrange(0, att_max)
        attack_comb = comb_res_a.unrankVaryingLengthCombination(i)
        for m in mitig_comb:
            for a in attack_comb:
                is_mitigated = sx.does_mitigation_mitigates_technique(
                    relations=m_to_t_relation,
                    technique_id=a.get("id"),
                    mitigation_id=m.get("id"))
                if is_mitigated:
                    matrix[n_yi, current_j] += find_price_for_mitigation(m.get("id"))
        # Отмечаем что для данной стратегии проведена симуляция
        already_ran_sim_counts[current_j] += 1
        # Обновляем значение радикала с учетом подсчитанных данных
        for j in range(mitig_max):
            current_yi = np.ma.masked_equal(matrix[:, j], 0)
            current_mean_for_j = np.mean(current_yi)
            radical_values[j] = calc_radical_ucb(current_mean_for_j, already_ran_sim_counts[j], n_yi, b)

        progress_bar.progress(n_yi / simulations_amount,
                              text=progress_text + f" $$n_y = $$ {n_yi}, для $$j=$$ {current_j} радикал = {radical_values[current_j]}")

    time_taken -= time.time()
    st.success(f'Upper-Confidence-Bound занял: {precisedelta(time_taken, minimum_unit="microseconds")}')
    st.balloons()
    progress_bar.empty()
    return matrix


def show_heatmap_for_matrix(mat):
    mat_heat_fig = plt.figure()
    plt.imshow(mat, cmap='hot', interpolation='bilinear')
    st.pyplot(mat_heat_fig)


def interactive():
    st.session_state["interactive"] = not st.session_state["interactive"]


def save_sim_settings():
    project_settings().defender_criteria = st.session_state.form_admin_criteria
    # project_settings().attacker_criteria = st.session_state.form_attacker_criteria
    # st.session_state["sim_amount"] = st.session_state.form_sim_amount
    # st.session_state["algorithm"] = st.session_state.form_algorithm
    st.session_state["criteria_chosen"] = True


def ready_to_run_sim():
    st.session_state["sim_amount"] = st.session_state.form_sim_amount
    st.session_state["algorithm"] = st.session_state.form_algorithm
    st.session_state["b"] = st.session_state.form_b
    st.session_state["ready_to_sim"] = True


def save_attacker_settings():
    project_settings().attacker_tactics = [t.get("id") for t in st.session_state.form_available_tactics]
    project_settings().attacker_max_interval = st.session_state.form_app_max_interval


def add_app_entry():
    if not hasattr(project_settings(), 'defender_apps'):
        st.session_state["project_settings"].defender_apps = []
    st.session_state["project_settings"].defender_apps.append(AppEntry(app_name=st.session_state.form_app_name,
                                                                       app_price=st.session_state.form_app_price,
                                                                       app_loss=Interval(
                                                                           st.session_state.form_app_loss[0],
                                                                           st.session_state.form_app_loss[1]),
                                                                       app_mitigations=[m.get("id") for m in
                                                                                        st.session_state.form_app_mitig]
                                                                       ))


def project_settings() -> ProjectSettings:
    return st.session_state['project_settings']


st.set_page_config(page_title="Game Theory Security", page_icon='🧮', layout="wide")

src = cached_get_src()

if "intro" not in st.session_state:
    st.session_state["intro"] = False
    st.session_state["ready_to_sim"] = False
    st.session_state["criteria_chosen"] = False

if "newproject" not in st.session_state:
    st.session_state["newproject"] = True
    new_project = ProjectSettings
    new_project.mitre_domain = "enterprise-attack"
    new_project.mitre_version = "14.1"
    new_project.defender_criteria = DefenderCriteria.LAPLACE_REASON
    st.session_state["project_settings"] = ProjectSettings

col1, col2 = st.columns([2, 1])

col1.write('''# Анализ защищенности системы на основе теории игр 
Теория игр применяется во многих сферах жизни включая экономику, билогию и социальных науках. Основная идея заключается 
в построении математической игры между N агентами, борящимся за ограниченное число ресурсов. В более сложных играх 
цели агентов могут быть иными, помимо получения бо́льшого числа ресурсов.

Данное приложение использует теорию игр для анализа защищенности компьютерной системы, симулируя игру между 
потенциальным "злоумышленником" и "администратором" (т.е. вами). Приложение позволяет вывести оптимальную стратегию 
защиты системы (в рамках представленных значений).

Определения атак, мер защит и тактик используют спецификацию [**MITRE ATT&CK**](https://attack.mitre.org/), 
потенциально приблежая симуляцию к реальному миру.

Для начала нажмите кнопку начать ниже.
''')

col2.image('prisonerdillema.png', caption="Знаменитая диллема заключенного, представленная матричной игрой")

if st.button("Новый проект", key='start_') and not st.session_state['intro']:
    st.session_state['intro'] = True
    st.session_state['newproject'] = True

uploaded_file = st.file_uploader("Выберите файл проекта", accept_multiple_files=False)
if uploaded_file is not None:
    st.session_state['intro'] = True
    st.session_state['newproject'] = False
    bytes_data = uploaded_file.getvalue()

if st.session_state['intro']:
    tactics = sx.get_tactics(src)

    st.write("---")
    st.write("## Определите начальные условия игры")
    col3, col4 = st.columns(2)
    with col3:
        st.write('''
        Прежде чем начать, вам необходимо определить модель злоумышленника, его цель и потенциальное поведение, определяемое 
        "тактиками" в спецификации MITRE ATT&CK.
        
        Выбранные вами тактики будут влиять на набор атак, представленных в матрице игры, но не на набор мер защиты 
        (так как симулируемая игра является игрой с ограниченной информацией).
        В форме справа вы можете найти настройки злоумышленника.
        
        По окончанию нажмите кнопку Продолжить, чтобы перейти на следующий этап установки условий.
        ''')

    with col4:
        with st.form("attacker-settings"):
            available_tactis = st.multiselect(
                label="Тактики доступные злоумышленнику",
                options=tactics,
                format_func=lambda x: x.get("name"),
                help="Список тактик и их значения можно найти [здесь](https://attack.mitre.org/tactics/enterprise/)",
                key='form_available_tactics'
            )
            app_max_interval = st.number_input(
                value=1000,
                key="form_app_max_interval",
                label='Максимальный возможный ущерб',
                help='Необходим для выбора интервала ниже (в у.е.)'
            )
            bimatrix = st.toggle(
                label="Построение матрицы для злоумышленника",
                help="Включение делает игру биматричной",
                disabled=True
            )
            submit = st.form_submit_button('Сохранить', on_click=save_attacker_settings)

    if hasattr(project_settings(), 'attacker_tactics') and project_settings().attacker_tactics:
        with st.expander(label="Просмотреть выбранные тактики"):
            st.write("#### Выбранные вами тактики представленные как DataFrame:")
            form_tactics_df = pd.DataFrame(project_settings().attacker_tactics)
            st.dataframe(form_tactics_df)

        mitigations = sx.remove_revoked_deprecated(sx.get_mitigations(src))

        st.write('---')
        st.write("## Определение установленых мер защиты и цены")
        col5, col6 = st.columns([0.4, 0.6])
        with col5:
            '''
            Матричные игры в теории игр оперируют "платежными матрицами". Для осуществления симуляции нам необходимо 
            определить ресурсы используемые в системе, какие меры защиты реализует каждый ресурс, и "цену" ресурса.

            Игра рассматриваемая в приложении является *биматричной* означая, что злоумышленник и администратор 
            ориентируются на собственные платежные матрицы при выборе стратегий, не имея информации о матрице другого.

            Для злоумышленника это матрица потенциального ущерба при атаке на ресурс, для администратора это средства 
            затраченные на реализацию защитных мер.

            Ресурсами могут быть:
            - Написанное вами приложение
            - Сторонее ПО (антивирусы, брендмауеры и проч.)
            - Машины (сервера, рабочие места, сетевые контроллеры и др.)

            Определение цены является важным фактором для точности симуляции. Вы можете воспользоваться следующими советами:
            - Для определения цены написанного приложения, вы можете выставить цену разработки приложения 
            (например умножить затраченные часы на почасовой тариф разработчика)
            - Стороннеe ПО определяется его стоимостью при покупке
            - Физические машины могут быть представлены ценой о их закупке и сопровождению.
            '''

        with col6:
            with st.form("admin-app-specs"):
                app_name = st.text_input(
                    label='Название приложения',
                    key='form_app_name'
                )
                app_price = st.number_input(
                    label='Цена приложения',
                    key='form_app_price',
                    help='в у.е.'
                )
                app_loss = st.slider(
                    label='Выберите интервал ущерба при атаке',
                    min_value=0,
                    max_value=st.session_state.form_app_max_interval,
                    step=1,
                    value=(0, 100),
                    key='form_app_loss'
                )
                app_mitigations = st.multiselect(
                    label="Меры защиты реализуемые приложением",
                    options=mitigations,
                    format_func=lambda x: x.get("name"),
                    help="Список мер защиты есть [здесь](https://attack.mitre.org/mitigations/enterprise/)",
                    key='form_app_mitig'
                )
                submit = st.form_submit_button("Добавить", on_click=add_app_entry)

        if hasattr(project_settings(), 'defender_apps') and project_settings().defender_apps:
            st.write("#### Текущий список приложений")
            defender_apps_df = pd.DataFrame([da.as_dict() for da in project_settings().defender_apps])
            st.dataframe(defender_apps_df)

        st.write('---')
        st.write("## Настройки Задачи")
        col7, col8 = st.columns([0.5, 0.5])
        if "defender_criteria" not in st.session_state:
            st.session_state["defender_criteria"] = ''

        with col7:
            st.write("В данном пункте необходимо выбрать критерии выбора стратегий для администратора и злоумышленника")
            st.write("### Критерий администратора")
            st.write("#### " + project_settings().defender_criteria.value[0])
            st.write(project_settings().defender_criteria.value[1])

        with col8:
            with st.form("sim-settings"):
                admin_criteria = st.selectbox(
                    label="Критерий администратора",
                    options=[c for c in DefenderCriteria],
                    index=2,
                    key="form_admin_criteria",
                    placeholder="Выберите критерий",
                    format_func=lambda c: c.value[0],
                    disabled=False,
                )
                attacker_criteria = st.selectbox(
                    label="Критерий злоумышленника",
                    options=[c for c in AttackerCriteria],
                    index=None,
                    key="form_attacker_criteria",
                    placeholder="Выберите критерий",
                    format_func=lambda c: c.value[0],
                    disabled=True
                )

                submit = st.form_submit_button("Сохранить", on_click=save_sim_settings)
            if st.session_state.criteria_chosen:
                with st.form("criteria-settings"):
                    sim_amount = st.number_input(
                        label="Количество симуляций",
                        help="Определяет число симуляций для алгоритма Монте-Карло или UCB",
                        step=1,
                        value=10,
                        key="form_sim_amount"
                    )
                    algorithm = st.selectbox(
                        label="Алогритм игры",
                        options=[c for c in GameAlgorithm],
                        index=0,
                        key="form_algorithm",
                        placeholder="Выберете алгоритм",
                        format_func=lambda c: c.value[0],
                        disabled=(project_settings().defender_criteria != DefenderCriteria.LAPLACE_REASON)
                    )
                    b = st.number_input(
                        label="КСС",
                        help="Коэффицент Смены Стратегии для Upper-Confidence-Bound",
                        step=1,
                        value=1000,
                        disabled=(project_settings().defender_criteria != DefenderCriteria.LAPLACE_REASON),
                        key="form_b"
                    )
                    submit_sim = st.form_submit_button("Запустить", on_click=ready_to_run_sim)

        if st.session_state["ready_to_sim"]:
            st.write("# Симуляция")

            # 1. Составим список стратегий злоумышленника для каждой тактики.
            # Это все возможные уникальные комбинации техник для каждой тактики (по сути сочетание)

            tactics = sx.get_tactics_by_ids(src, tactics_ids=project_settings().attacker_tactics)

            attacker_strategies = list()
            for tactic in tactics:
                attacker_strategies += sx.get_techniques_by_tactics(src, tactics=[tactic.get("x_mitre_shortname")])
            # Sort lexicographically
            attacker_strategies.sort(key=operator.attrgetter("id"), reverse=True)

            defender_strategies = list()
            for app in project_settings().defender_apps:
                defender_strategies += sx.get_mitigations_by_ids(src, migitation_ids=app.app_mitigations)
            # Sort lexicographically
            defender_strategies.sort(key=operator.attrgetter("id"), reverse=True)

            # Комбинаторная система чисел,
            # позволяет получать нужную комбинацию от её лексографического положения
            # в наборе всех комбинаций без подсчета каждой комбинации
            combination_resolver_attacks = CombinationGenerator(attacker_strategies)
            combination_resolver_mitigations = CombinationGenerator(defender_strategies)

            M_for_defender = 2 ** len(defender_strategies) - 1
            M_for_attacker = 2 ** len(attacker_strategies) - 1

            st.write(f'''
                ### Количество стратегий:

                Формула:

                $$C = 2^S - 1$$, $$S$$ - число отдельных мер защиты или атак (техник)

                Для атакующего: $$K_A = 2^{{ {len(attacker_strategies)} }} - 1 = $$ {M_for_attacker}

                Для защищающего: $$M_A = 2^{{{len(defender_strategies)}}} - 1 = $$ {M_for_defender}
                ''')
            # Считаем
            # Количество симуляций
            N = st.session_state.sim_amount

            # STIRX маппинг отношений меры защиты в техники
            m_to_t_relation = sx.mitigation_mitigates_techniques(src)

            # Разряженная матрица значений

            # matrix_defender = sp.sparse.lil_matrix((N, M_for_defender), dtype=np.longlong)
            # chosen_def_crit = st.session_state.defender_criteria

            matrix_defender = np.zeros((N, M_for_defender))
            if "algorithm" in st.session_state and st.session_state["algorithm"] == GameAlgorithm.MonteCarlo:
                # matrix_defender = np.ndarray((N, M_for_defender), dtype=np.longlong)

                time_taken = time.time()

                progress_text = "Выполняем классический Монте-Карло. Пожалуйста подождите. "
                progress_bar = st.progress(0.0, text=progress_text)

                # Проводим для каждой стратегии N симуляций
                for j in range(M_for_defender):
                    # Комбинация дле текущей стратегии защиты
                    mitig_comb = combination_resolver_mitigations.unrankVaryingLengthCombination(j)

                    # Проводим N симуляций для текущей стратегии
                    for n in range(N):
                        # Случайно выбранная стратегия атаки
                        i = random.randrange(0, M_for_attacker)
                        attack_comb = combination_resolver_attacks.unrankVaryingLengthCombination(i)

                        # Проверяем что каждая мера защиты в стратегии защиты защищает от стратегий атаки
                        # Если хотя бы одна из стратегий защищиает current_val > 0
                        for m in mitig_comb:
                            for a in attack_comb:
                                is_mitigated = sx.does_mitigation_mitigates_technique(
                                    relations=m_to_t_relation,
                                    technique_id=a.get("id"),
                                    mitigation_id=m.get("id"))
                                if is_mitigated:
                                    matrix_defender[n, j] += find_price_for_mitigation(m.get("id"))
                        progress_bar.progress(j / M_for_defender, text=progress_text)
                        # f"{n} / {simulations_amount} симуляция для $$j = $$ {j}"

                time_taken -= time.time()
                st.success(f'Метод Монте-Карло занял: {precisedelta(time_taken, minimum_unit="microseconds")}')
                st.balloons()
                progress_bar.empty()
            elif st.session_state["algorithm"] == GameAlgorithm.UpperConfidenceBound:
                matrix_defender = ucb(M_for_defender, M_for_attacker, N,
                                      combination_resolver_mitigations,
                                      combination_resolver_attacks,
                                      st.session_state.b)

            # matrix_defender = matrix_defender.tocsr()

            st.write("### Диаграмма значений")
            col10, col11 = st.columns(2)

            with col10:
                """
                На диаграмме представлены значения полученные в процессе симуляций

                Важно отметить, так как число потенциальных стратегий слишком большое, в матрице количество строк
                соответсвует количеству симуляций Монте-Карло.
                Так как мы не будем использовать значения не полученные в процессе выполнения Монте-Карло,
                нет смысла подсчитывать значения для этих комбинаций
                """

            with col11:
                masked_matrix = np.ma.masked_equal(matrix_defender, 0)
                fig, ax = plt.subplots()
                cax = ax.imshow(masked_matrix, cmap='hot', interpolation='nearest')
                fig.colorbar(cax)
                st.pyplot(fig)

            """
            ---
            ### Результаты работы
            """

            j_index = 0
            found_criteria_val = 0
            top_three = None
            if project_settings().defender_criteria == DefenderCriteria.LAPLACE_REASON:
                # Найдем сумму для каждого стоблца
                sum_of_columns = matrix_defender.sum(axis=0).flatten()
                # Маскируем некорректные значения
                sum_of_columns = np.ma.masked_equal(sum_of_columns, 0)
                # Считаем критерий для каждого столбца: по Лапласу это математическое ожидание
                j_criteria = sum_of_columns * (1 / N)
                # Поиск критерия для всей матрицы
                found_criteria_val = np.min(j_criteria)
                # Индекс стратегии защиты для найденного критерия
                j_index = np.argmin(j_criteria)

                top_three = np.argpartition(j_criteria, 3)

                col1_laplace, col2_laplace = st.columns(2)
                with col1_laplace:
                    show_result(found_criteria_val, j_index)
                with col2_laplace:
                    '#### Сведение критерия Лапласа в процессе Монте-Карло'
                    # Выбранная нами стратегия
                    found_criteria_vals = matrix_defender[:, j_index]
                    # Сводим колонку стратегии в 1d массив
                    found_criteria_vals = found_criteria_vals.flatten()
                    # Считаем кумулятивную сумму (каждый элемент кумулятивной суммы это сумма всех предыдущих элемнетов)
                    cumulative_sum = np.cumsum(found_criteria_vals)
                    # Считаем математическое ожидание для каждой кумулятивной суммы
                    for j in range(len(cumulative_sum)):
                        cumulative_sum[j] = cumulative_sum[j] * (1 / (j + 1))
                    fig_laplace = px.line(y=cumulative_sum, x=range(len(cumulative_sum)))
                    fig_laplace.update_traces(connectgaps=True)
                    fig_laplace.update_layout(yaxis={"title": "Значение критерия", "range": [0, None]},
                                              xaxis={"title":
                                                         "Итерация Монте-Карло"})
                    st.plotly_chart(fig_laplace)
                    # elif st.session_state.algorithm == GameAlgorithm.UpperConfidenceBound:

            elif project_settings().defender_criteria == DefenderCriteria.WALD_MAXIMIN:
                # Найдем максимумы для каждой стратегии
                maxes_in_j = matrix_defender.max(axis=0).flatten()
                # Маскируем некорректные значения
                maxes_in_j = np.ma.masked_equal(maxes_in_j, 0)
                # Находим критерий для стратегии и индекс
                found_criteria_val = np.min(maxes_in_j)
                j_index = np.argmin(maxes_in_j)

                top_three = np.argpartition(maxes_in_j, 3)

                col1_wald, col2_wald = st.columns(2)
                with col1_wald:
                    show_result(found_criteria_val, j_index)
                with col2_wald:
                    '#### Значения критерия для каждой стратегии защиты'
                    fig_wald = px.line(y=maxes_in_j, x=range(len(maxes_in_j)))
                    fig_wald.update_traces(connectgaps=True)
                    st.plotly_chart(fig_wald)

            elif project_settings().defender_criteria == DefenderCriteria.SAVAGE_MINIMAX:
                # Для критерия Сэвиджа строится отдельная матрица рисков
                savage_matrix = np.ndarray((N, M_for_defender))

                mins_in_j = matrix_defender.min(axis=0).flatten()
                # Маскируем некорректные значения
                maxes_in_j = np.ma.masked_equal(mins_in_j, 0)

                # Наполняем матрицу рисков
                for i in range(N):
                    for j in range(M_for_defender):
                        savage_matrix[i, j] = matrix_defender[i, j] - mins_in_j[j]
                # Находим критерий для стратегии и индекс
                maxes_in_j_savage = savage_matrix.max(axis=0).flatten()
                maxes_in_j_savage = np.ma.masked_equal(maxes_in_j_savage, np.NaN)
                found_criteria_val = np.min(maxes_in_j_savage)
                j_index = np.argmin(maxes_in_j_savage)

                top_three = np.argpartition(maxes_in_j, 3)

                col1_savage, col2_savage = st.columns(2)
                with col1_savage:
                    show_result(found_criteria_val, j_index)

                with col2_savage:
                    '#### Матрица рисков'
                    fig_savage_matrix = plt.figure()
                    plt.imshow(savage_matrix, cmap='winter', interpolation='bilinear')
                    st.pyplot(fig_savage_matrix)
                    '#### Значения критерия для каждой стратегии защиты'
                    fig_savage = px.line(y=maxes_in_j_savage, x=range(len(maxes_in_j_savage)))
                    fig_savage.update_traces(connectgaps=True)
                    st.plotly_chart(fig_savage)


            if top_three is not None:
                "Топ 3 стратегий:"
                col1_final, col2_final, col3_final = st.columns(3)
                kth_vals = np.sort(top_three[:3])
                resulting_strategies = []
                with col1_final:
                    f"Топ 1: Для стратегии $$j =$$ {top_three[0]} комбинация:"
                    comb_for_criteria = combination_resolver_mitigations.unrankVaryingLengthCombination(top_three[0])
                    strat = get_strategy_for_comb(comb_for_criteria)
                    st.dataframe(strat)
                with col2_final:
                    f"Топ 2: Для стратегии $$j =$$ {top_three[1]} комбинация:"
                    comb1_for_criteria = combination_resolver_mitigations.unrankVaryingLengthCombination(top_three[1])
                    strat1 = get_strategy_for_comb(comb1_for_criteria)
                    st.dataframe(strat1)
                with col3_final:
                    f"Топ 3:Для стратегии $$j =$$ {top_three[2]} комбинация:"
                    comb2_for_criteria = combination_resolver_mitigations.unrankVaryingLengthCombination(top_three[2])
                    strat2 = get_strategy_for_comb(comb2_for_criteria)
                    st.dataframe(strat2)




            else:
                comb_for_criteria = combination_resolver_mitigations.unrankVaryingLengthCombination(j_index)
                f"Для стратегии $$j =$$ {j_index} комбинация:"
                strat = get_strategy_for_comb(comb_for_criteria)
                st.dataframe(strat,
                             column_config={
                                 "url": st.column_config.LinkColumn("URL")
                             })
