import streamlit as st

import stixlib as sx
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd


@st.cache_data(persist=True)
def cached_get_src():
    thesrc = sx.get_data_from_branch("enterprise-attack")
    # st.success("Fetched latest MITRE ATT&CK data")
    return thesrc


st.set_page_config(page_title="Game Theory Security", page_icon='🧮', layout="wide")

src = cached_get_src()

if "intro" not in st.session_state:
    st.session_state["intro"] = False

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

if st.button("Начать!", key='start_'):
    st.session_state.intro = True

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
            win_condition = st.selectbox(
                label="Критерий злоумышленника",
                options=possible_win_conditions,
                help="На данный момент реализован единственный критерий: Нанесение максимального ущерба",
                key='win_condition'
            )
            available_tactis = st.multiselect(
                label="Тактики доступные злоумышленнику",
                options=tactics,
                format_func=lambda x: x.get("name"),
                help="Список тактик и их значения можно найти [здесь](https://attack.mitre.org/tactics/enterprise/)",
                key='available_tactics'
            )
            submit = st.form_submit_button('Сохранить')

    if st.session_state['available_tactics']:
        with st.expander(label="Просмотреть выбранные тактики"):
            st.write("#### Выбранные вами тактики представленные как DataFrame:")
            form_tactics_df = pd.DataFrame(st.session_state.available_tactics)
            st.dataframe(form_tactics_df)

    mitigations = sx.get_mitigations(src)

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
        - Сторонне ПО определяется его стоимостью при покупке
        - Физические машины могут быть представлены ценой о их закупке и сопровождению.
        '''

    with col6:
        with st.form("admin-app-specs"):
            app_name = st.text_input(
                label='Название приложения',
            )
            app_price = st.number_input(
                label='Цена приложения'
            )
            app_mitigations = st.multiselect(
                label="Меры защиты реализуемые приложением",
                options=mitigations,
                format_func=lambda x: x.get("name"),
                help="Список мер защиты есть [здесь](https://attack.mitre.org/mitigations/enterprise/)",
            )

    with st.expander(label="Просмотреть выбранные меры защиты"):
        st.warning("Streamlit не может показать ряд столбцов ввиду использования PyArrow. "
                   "Это исключительно проблема отображения в интерфейсе, стоблцы все еще присутсвуют, но их не видно.")
        st.write("#### Выбранные вами меры защиты: (ДЕБАГ, СЕЙЧАС ТУТ ВСЕ ВОЗМОЖНЫЕ МЕРЫ ЗАЩИТЫ)")
        form_mitigations_df = pd.DataFrame(sx.remove_revoked_deprecated(mitigations))
        st.dataframe(sx.debug_dataframe_attack_pattern(form_mitigations_df))

    # techniques_df = pd.DataFrame(techniques_data)
    # st.dataframe(techniques_df.loc[:, ~techniques_df.columns.isin(['kill_chain_phases', 'external_references'])])

    st.write("### Матрица")

    matrix = np.random.rand(3, 3)

    fig, ax = plt.subplots()

    ax.grid()

    plt.matshow(matrix, fig, cmap='cividis')

    st.pyplot(fig)
