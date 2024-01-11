import operator
import random

import intvalpy
import matplotlib.pyplot as plt
import plotly.express as px
import matspy
import numpy as np
import pandas as pd
import scipy as sp
import streamlit as st
from intvalpy import Interval

import stixlib as sx
from maths import CombinationGenerator
from projectsharablestate import ProjectSettings, AppEntry, DefenderCriteria, AttackerCriteria, GameAlgorithm


@st.cache_data(persist=True)
def cached_get_src():
    thesrc = sx.get_data_from_branch("enterprise-attack")
    # st.success("Fetched latest MITRE ATT&CK data")
    return thesrc


def convert_n_range_to_0_100(old_min, old_max, new_min, new_max, old_value):
    old_range = old_max - old_min
    new_range = new_max - new_min
    return (((old_value - old_min) * new_range) / old_range) + new_min


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

def interactive():
    st.session_state["interactive"] = not st.session_state["interactive"]

def save_sim_settings():
    st.session_state["defender_criteria"] = st.session_state.form_admin_criteria
    st.session_state["attacker_criteria"] = st.session_state.form_attacker_criteria
    st.session_state["sim_amount"] = st.session_state.form_sim_amount
    st.session_state["algorithm"] = st.session_state.form_algorithm
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
    st.session_state["interactive"] = False

if "newproject" not in st.session_state:
    st.session_state["newproject"] = True
    new_project = ProjectSettings
    new_project.mitre_domain = "enterprise-attack"
    new_project.mitre_version = "14.1"
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
            if st.session_state["defender_criteria"] != '':
                st.write("#### " + st.session_state["defender_criteria"].value[0])
                st.write(st.session_state["defender_criteria"].value[1])

        with col8:
            with st.form("sim-settings"):
                sim_amount = st.number_input(
                    label="Количество симуляций",
                    help="Определяет число симуляций для алгоритма Монте-Карло",
                    step=1,
                    key="form_sim_amount"
                )
                admin_criteria = st.selectbox(
                    label="Критерий администратора",
                    options=[c for c in DefenderCriteria],
                    index=2,
                    key="form_admin_criteria",
                    placeholder="Выберите критерий",
                    format_func=lambda c: c.value[0],
                    disabled=True,
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
                algorithm = st.selectbox(
                    label="Алогритм игры",
                    help="Учитывайте, что не все алгоритмы нацелены на получение оптимальной стратегии или равновесия Нэша",
                    options=[c for c in GameAlgorithm],
                    index=None,
                    key="form_algorithm",
                    placeholder="Выберете алгоритм",
                    format_func=lambda c: c.value[0],
                    disabled=True
                )
                submit = st.form_submit_button("Сохранить", on_click=save_sim_settings)

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

                $$M = 2^S - 1$$, S - число стратегий 

                Для атакующего: $$M_A = 2^{{ {len(attacker_strategies)} }} - 1 = $$ {M_for_attacker}

                Для защищающего: $$M_A = 2^{{{len(defender_strategies)}}} - 1 = $$ {M_for_defender}
                ''')

            m_to_t_relation = sx.mitigation_mitigates_techniques(src)

            # Constructing matrix. lil_matrix for fast access and modification
            matrix_defender = sp.sparse.lil_array((st.session_state.sim_amount, M_for_defender))
            map_sims_to_m_combs = []

            with st.spinner('Считаем полностью случайный Монте-Карло'):
                for sim in range(st.session_state.sim_amount):
                    # Одна симуляция
                    i = random.randrange(0, M_for_attacker)
                    j = random.randrange(0, M_for_defender)
                    # print(f'{i}, {j}')
                    attack_comb = combination_resolver_attacks.unrankVaryingLengthCombination(i)
                    mitig_comb = combination_resolver_mitigations.unrankVaryingLengthCombination(j)
                    price_value = 0
                    loss_value = Interval(0, 0)
                    for m in mitig_comb:
                        for a in attack_comb:
                            is_mitigated = sx.does_mitigation_mitigates_technique(
                                relations=m_to_t_relation,
                                technique_id=a.get("id"),
                                mitigation_id=m.get("id"))
                            # print(is_mitigated)
                            if is_mitigated:
                                # Returns tuple: 0 is app price, 1 is app loss
                                value = find_price_for_mitigation(m.get("id"))
                                # print(values)
                                if value != Interval(0, 0):
                                    map_sims_to_m_combs.append(j)
                                    matrix_defender[sim, j] = matrix_defender[sim, j] + value
                    matrix_defender = matrix_defender.tocsr()

            st.balloons()

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
                    fig, ax = matspy.spy_to_mpl(matrix_defender)
                    st.pyplot(fig)
            """
            ---
            ### Результаты работы
            """

            sum_of_columns = matrix_defender.sum(axis=0)
            sum_of_columns = np.ma.masked_equal(sum_of_columns, 0)
            sum_of_columns = sum_of_columns * (1 / M_for_defender)
            # Поиск критерия
            found_criteria_val = np.min(sum_of_columns)
            comb_index_for_criteria = np.argmin(sum_of_columns)
            actual_comb_index = map_sims_to_m_combs[comb_index_for_criteria]

            comb_for_criteria = combination_resolver_mitigations.unrankVaryingLengthCombination(actual_comb_index)

            col12, col13 = st.columns(2)

            with col12:
                f'''
                #### Найденная стратегия Администратора
                
                Согласно выбранному критерию была найдена стратегия защиты:
                
                $$W_j(A) =$$ {found_criteria_val}
                
                Значение в матрице метода Монте-Карло = {comb_index_for_criteria}
                
                Индекс в платежной матрице:
                
                $$j = $$ {actual_comb_index}
                
                Данной стратегии соответсвует комбинация мер защиты:
                '''
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

                resulting_strategy_df = pd.DataFrame(strategy_data_display, columns=["mitre_id", "name", "url"])
                st.dataframe(resulting_strategy_df,
                             column_config={
                                 "url": st.column_config.LinkColumn("URL")
                             })

            with col13:
                '#### График критериев для Администратора'
                #'(интерактивный, наведите мышку)'
                fig_laplace = px.line(y=sum_of_columns, x=range(len(sum_of_columns)))
                fig_laplace.update_traces(connectgaps=True)
                fig_laplace.update_layout(yaxis={"title": "Значение критерия", "range": [0, None]},
                                          xaxis={"title": "Индекс стратегии меры защиты в матрице метода Монте-Карло"})
                st.plotly_chart(fig_laplace)
