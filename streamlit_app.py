import streamlit as st

import stixlib as sx
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd

from projectsharablestate import ProjectSettings, AppEntry, DefenderCriteria


@st.cache_data(persist=True)
def cached_get_src():
    thesrc = sx.get_data_from_branch("enterprise-attack")
    # st.success("Fetched latest MITRE ATT&CK data")
    return thesrc


def save_sim_settings():
    st.session_state["defender_criteria"] = st.session_state.form_admin_criteria


def save_attacker_settings():
    project_settings().attacker_tactics = [t.get("id") for t in st.session_state.form_available_tactics]
    project_settings().attacker_max_interval = st.session_state.form_app_max_interval


def add_app_entry():
    if not hasattr(project_settings(), 'defender_apps'):
        st.session_state["project_settings"].defender_apps = []

    new_entry = AppEntry
    new_entry.app_name = st.session_state.form_app_name
    new_entry.app_price = st.session_state.form_app_price
    new_entry.app_loss = st.session_state.form_app_loss
    new_entry.app_mitigations = [m.get("id") for m in st.session_state.form_app_mitig]
    st.session_state["project_settings"].defender_apps.append(new_entry)


def project_settings() -> ProjectSettings:
    return st.session_state['project_settings']


st.set_page_config(page_title="Game Theory Security", page_icon='🧮', layout="wide")

src = cached_get_src()

if "intro" not in st.session_state:
    st.session_state["intro"] = False

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

if st.button("Загрузить проект", key='loadproject_') and not st.session_state['intro']:
    st.session_state['intro'] = True
    st.session_state['newproject'] = False
    # TODO: add button for loading project

if st.session_state['intro']:
    tactics = sx.get_tactics(src)
    possible_win_conditions = ['UnlimitedResourcesMaxDamage']

    st.write("---")
    st.write("## Определите начальные условия игры")
    col3, col4 = st.columns(2)
    col3.write('''
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
            defender_apps_df = pd.DataFrame([da.as_dict(da) for da in project_settings().defender_apps])
            st.dataframe(defender_apps_df)

        st.write('---')
        st.write("## Настройки Задачи")
        col7, col8 = st.columns([0.5, 0.5])
        if "defender_criteria" not in st.session_state:
            st.session_state["defender_criteria"] = ''

        with col7:
            st.write("В данном пункте необходимо выбрать критерии выбора стратегий для администратора и злоумышленника")
            if st.session_state["defender_criteria"] != '':
                st.write(st.session_state["defender_criteria"].value[1])

        with col8:
            with st.form("sim-settings"):
                admin_criteria = st.selectbox(
                    label="Критерий администратора",
                    options=[c for c in DefenderCriteria],
                    index=None,
                    key="form_admin_criteria",
                    placeholder="Выберите критерий",
                    format_func=lambda c: c.value[0],
                )
                submit = st.form_submit_button("Сохранить", on_click=save_sim_settings)

        st.write("# Симуляция")

        # 1. Построение матрицы защитника
        # 1.1. Отображение выбранных тактик в атаки
        # 1.1.1. Получаем техники из настроек проекта
        tactics = sx.get_tactics_by_ids(thesrc=src, tactics_ids=project_settings().attacker_tactics)

        # 1.1.2. Получаем список атак из списка тактик
        techniques = sx.get_techniques_by_tactics(thesrc=src, tactics=[t.get("x_mitre_shortname") for t in tactics])

        # 1.1.3. Удаляем старые и неподдерживаемые техники
        techniques = sx.remove_revoked_deprecated(techniques)

        # 1.1.4. Получаем меры защиты

        mitigations = sx.remove_revoked_deprecated(sx.get_mitigations(src))

        # 1.2. Создание матрицы
        # Перевод наборов тактик и мер в листы для надежной индексации
        techniques_listed = [t for t in techniques]
        mitigations_listed = [m for m in mitigations]

        defender_matrix = np.empty((len(techniques_listed), len(mitigations_listed)), np.int32)


        df = pd.DataFrame(techniques)
        st.dataframe(sx.debug_dataframe_attack_pattern(df))



        # techniques_df = pd.DataFrame(techniques_data)
        # st.dataframe(techniques_df.loc[:, ~techniques_df.columns.isin(['kill_chain_phases', 'external_references'])])

    st.write("### Матрица")

    matrix = np.random.rand(3, 3)

    fig, ax = plt.subplots()

    ax.grid()

    plt.matshow(matrix, fig, cmap='cividis')

    st.pyplot(fig)
