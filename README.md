# Защищённая оверлейная P2P-сеть

Курсовая работа по разработке узла децентрализованной сети передачи данных.

**Реализовано и проверено:** TCP-обмен `PING/PONG`, кадрирование сообщений, постоянные криптографические идентификаторы узлов, XOR-маршрутизация Kademlia, сетевой `FIND_NODE`, присоединение к сети (`join`), обновление таблиц (`refresh`), проверка контактов через `PING` и сравнение bootstrap-схем `star` и `ring`. На этапе 3 реализованы подписанные `NodeRecord`, локальное хранение, сетевые `STORE/FIND_VALUE`, проверка подписи, TTL, защита от отката версии, репликация на трёх хранителях с порогом 2/3 подтверждений и автоматическое переопубликование владельцем. Реализован TLS 1.3 с взаимной проверкой сертификатов и NodeID: отдельно для PING/PONG и для сетевых DHT-запросов в защищённом режиме. Для TLS DHT RPC добавлены подписанные `session_id`/`message_id` и ограниченный журнал отклонения повторных запросов.

**Текущий масштаб:** учебная сеть из пяти узлов. Защищённый режим DHT включается явно; старые учебные демонстрации остаются на открытом TCP. Пока нет туннелей и подтверждения невырожденности DHT на 12–15 узлах. Пилотные результаты не заменяют итоговые эксперименты.

## 1. Подготовка к запуску

**Среда:** Windows 10, Python 3.11 или новее (проверено с Python 3.13.9). Код можно открывать в PyCharm; команды ниже выполняются в обычной командной строке **CMD**.

Откройте в Проводнике папку проекта, в которой находится `node.py`, введите `cmd` в адресной строке Проводника и нажмите Enter. Окно CMD откроется сразу в нужной папке.

Проверьте Python и установите зависимости:

```bat
py --version
py -m pip install -r requirements.txt
```

Если команда `py` не распознаётся, используйте `python` вместо `py`.

## 2. Проверка всех автоматических тестов

Перед демонстрациями рекомендуется запустить весь набор тестов:

```bat
py -m unittest discover -s tests -v
```

**Ожидаемый итог:**

```text
----------------------------------------------------------------------
Ran 145 tests in ...s

OK
```

Проверяются кадры TCP, ограничения формата, XOR и `k-bucket`, постоянство `NodeID`, сетевой поиск, `join` и `refresh`, вытеснение контактов, bootstrap-схемы, локальные подписанные записи DHT, сетевые `STORE/FIND_VALUE`, выбор трёх хранителей по XOR и восстановление чтения после одного отказа.

Чтобы сохранить полный вывод тестов в текстовый файл:

```bat
if not exist results mkdir results
py -m unittest discover -s tests -v > results\tests_current.txt 2>&1
type results\tests_current.txt
```

Отсутствие вывода сразу после команды с `>` — нормально: он записан в файл. Все тесты выполняются без ручного запуска узлов.

## 3. Этап 1 — TCP-обмен и кадрирование

**Реализовано:** два независимых узла могут устанавливать TCP-соединения и обмениваться сообщениями `PING/PONG`. Сообщения имеют 24-байтовый заголовок, а данные ограничены 65 536 байтами. Предусмотрена обработка частичных TCP-чтений и некорректных кадров.

Для демонстрации откройте **два окна CMD** в корневой папке проекта.

**Окно 1 — узел A:**

```bat
py node.py --config configs\node_a.json
```

**Окно 2 — узел B:**

```bat
py node.py --config configs\node_b.json
```

В окне A введите:

```text
ping 5002
```

Ожидаемый ответ:

```text
[A] Получен PONG от B: Я на связи!
```

В окне B проверьте обратное направление:

```text
ping 5001
```

Ожидаемый ответ:

```text
[B] Получен PONG от A: Я на связи!
```

Для завершения каждого узла введите `exit`. Корректность кодирования и декодирования кадров также проверяется общим набором автоматических тестов (раздел 2).

## 4. Этап 2 — XOR и таблицы маршрутизации

**Реализовано:** вычисление XOR-расстояния, распределение контактов по ограниченным `k-bucket` (`k = 3`) и выбор ближайших известных контактов. При заполнении bucket новый контакт не вытесняет старый до проверки его доступности.

**Запуск:**

```bat
py -m scripts.routing_demo
```

**Пример вывода:**

```text
Contact  8: added
Contact  9: added
Contact 10: added
Contact 11: needs_ping
...
bucket[3]: [5008, 5009, 5010]
```

`needs_ping` означает необходимость проверить самый старый контакт. Это локальная демонстрация таблицы, а не сетевой поиск.

## 5. Этап 2 — постоянная идентичность узлов

**Реализовано:** при первом запуске создаётся пара ключей Ed25519; `NodeID` определяется как SHA-256 от канонического представления открытого ключа. При повторном запуске того же узла идентификатор сохраняется.

**Запуск:**

```bat
py -m scripts.identity_demo --name A
py -m scripts.identity_demo --name A
py -m scripts.identity_demo --name B
```

**Пример ключевых строк:**

```text
Node: A
Status: NEW identity created
NodeID matches public key: True
Ed25519 signature verifies: True

Node: A
Status: Existing identity loaded

Node: B
Status: NEW identity created
```

При втором запуске A его `NodeID` должен совпасть с первым; у B — отличаться. Закрытые ключи хранятся вне проекта. **Нельзя публиковать `identity.pem`.**

## 6. Этап 2 — сетевой поиск FIND_NODE

**Реализовано:** пилотная сеть из пяти узлов A–E выполняет поиск контактов через промежуточные DHT-узлы. Проверяется поиск D, которого A не знал заранее, и поиск E после остановки начального узла B.

**Запуск:**

```bat
py -m scripts.dht_demo
```

**Пример ключевого вывода:**

```text
FIND_NODE: A searches for D (D was absent from A routing table)
...
"found": true,
"iterations": 3,
"rpc_count": 3,
...
Stopping B (seed) and searching E via other known contacts...
...
"found": true,
...
SUCCESS: live network FIND_NODE, seed failure recovery.
Results saved to: ...\results\dht_pilot_....json
```

Тайм-аут для отключённого B допустим, если поиск E завершается успешно. Порты, идентификаторы и длительность поиска могут отличаться между прогонами. Для демонстрации достаточно одного окна CMD.

## 7. Этап 2 — join, refresh и проверка контактов

**Реализовано:** присоединение через известный seed-узел, поиск соседей, ручное и периодическое обновление таблицы маршрутизации. При переполнении `k-bucket` живой старый контакт сохраняется, а отключённый заменяется после реального сетевого `PING`.

**Запуск:**

```bat
py -m scripts.dht_maintenance_demo
```

**Пример успешного вывода:**

```text
1) A connects only to seed B and runs self-lookup:
...
"contacts_before": 0,
"contacts_after": 4,
...
2) Lookup E after join: found = True
3) Manual refresh: 2 bucket(s); RPC = 8
4) Periodic refresh completed: 1
5) Full k-bucket: live/dead LRU contact network probes:
    live oldest: True -> kept_old
    dead oldest: False -> replaced

SUCCESS: join, manual+periodic refresh, live/dead LRU PING.
Results saved to: ...\results\dht_maintenance_....json
```

Число RPC и другие числовые показатели могут меняться. Проверять нужно успешность поиска, срабатывание `refresh` и оба результата сетевой проверки контактов.

## 8. Этап 2 — сравнение bootstrap-схем star и ring

**Реализовано:** запуск пятиузловой сети с двумя схемами первоначального знакомства: `star` («звезда») и `ring` («кольцо»). Сравниваются успешность поиска и задержки при неизменных остальных параметрах. Эти схемы относятся к **bootstrap-графу**, а не к физической IP-топологии.

**Один прогон каждой схемы:**

```bat
py -m scripts.bootstrap_compare --scheme both --runs 1
```

**Серия из трёх прогонов каждой схемы:**

```bat
py -m scripts.bootstrap_compare --scheme both --runs 3
```

**Пример вывода:**

```text
PILOT: localhost, N=5, k=3, ALPHA=3 (not the final 12-node experiment)
Run 1/1, scheme=star: starting 5 nodes...
  success 20/20, unknown at lookup 1, ...
Run 1/1, scheme=ring: starting 5 nodes...
  success 20/20, unknown at lookup 1, ...
SUCCESS: bootstrap pilot completed.
Raw data: ...\results\bootstrap_compare_...
```

Результаты сохраняются в новой папке `results\bootstrap_compare_...`: сырые JSON, `lookups.csv`, `summary.csv` и `manifest.json`. Посмотреть каталоги можно командой:

```bat
explorer results
```

**Результат проведённой серии:** по три прогона `star` и `ring`, в обеих схемах — 60 успешных поисков из 60. В каждом из шести прогонов только один поиск начинался с неизвестной цели. Поэтому эти данные показывают работоспособность схем начального подключения, но **не доказывают невырожденность DHT**. Для окончательной проверки по ТЗ нужны отдельные испытания на 12–15 узлах с не менее чем 30 поисками неизвестных заранее целей.

---

## Этап 3 — подписанные адресные записи (часть 1)

**Реализовано:** формирование и проверка подписанной записи `NodeRecord` с `NodeID`, публичным ключом, адресом, номером версии и временем действия. Локальное хранилище принимает актуальную запись, отклоняет неверную подпись и устаревшую версию, не выдаёт запись после окончания TTL.

**Все тесты с регрессионной проверкой этапов 1–2:**

```bat
py -m unittest discover -s tests -v
```

**Результат тестов на момент завершения этой части:**

```text
Ran 72 tests in ...s

OK
```

**Демонстрация:**

```bat
py -m scripts.records_demo
```

**Пример успешного вывода:**

```text
Signature valid: True
Local STORE: stored
Local GET: True
New version: updated
Rollback rejected: True
Expired record removed: True
SUCCESS: signed NodeRecord, TTL and rollback.
```

Результат демонстрации сохраняется в новый файл `results\record_local_....json`. Проверка истечения TTL производится с управляемым временем; ждать реального окончания срока действия не требуется.

**Важно:** `Local STORE/GET` — операции в памяти одного процесса, **не** сетевые RPC `STORE/FIND_VALUE`. В этой исторической части ещё не использовались сетевые `STORE/FIND_VALUE` и репликация; их проверки приведены ниже. TCP пока не защищён TLS.

---


## Этап 3 — сетевые STORE и FIND_VALUE (часть 2)

**Реализовано:** один узел может передать подписанную `NodeRecord` другому узлу по TCP (`STORE`), получить подтверждение от хранителя и найти запись через промежуточные контакты (`FIND_VALUE`). Перед сохранением и выдачей проверяются ключ записи, цифровая подпись, версия и срок действия.

**Автоматические тесты вместе с предыдущими этапами:**

```bat
py -m unittest discover -s tests -v
```

**Ожидаемый итог:**

```text
Ran 84 tests in ...s

OK
```

**Демонстрация сетевого хранения и поиска:**

```bat
py -m scripts.network_records_demo
```

**Пример вывода (числа и идентификаторы могут отличаться):**

```text
Bootstrap: A -> B -> C -> D -> E
A knows C before FIND_VALUE: False
1) E performs STORE on remote keeper C
   STORE result: stored
   Keeper C contains record: True
2) A searches signed record via FIND_VALUE (through B -> C)
   "found": true,
   "iterations": 2,
   "rpc_count": 2,
3) Stop single keeper C and retry FIND_VALUE
   After C stopped, found: False
SUCCESS: remote STORE, multihop FIND_VALUE and no-replica failure illustrated.
Results saved to: ...\results\record_network_....json
NOTE: R=3 replication and TLS are NOT implemented yet.
```

Сценарий использует **одного хранителя C**. После его отключения запись не находится: это ожидаемое ограничение текущей версии, а не успешная отказоустойчивость. На следующем подэтапе добавим **три реплики и проверку поиска после отказа одной**. Результаты сохраняются в новом JSON-файле папки `results`. Данные в нём не нужно изменять вручную.

**Ограничение этого эксперимента:** здесь использовался только один хранитель. В следующем сценарии описана уже работающая репликация R=3. Защищённые TLS-сессии и туннели ещё не реализованы. Сетевые эксперименты относятся к пятиузловому пилоту, а не к итоговому стенду на 12–15 узлах.


---

## Этап 3 — репликация R=3 и отказ хранителя (часть 3)

**Реализовано:** поиск доступных узлов по `FIND_NODE`, выбор трёх ближайших к ключу записи хранителей по XOR-расстоянию, отправка им подписанной `NodeRecord` через `STORE`. Операция считается успешной при двух или трёх действительных подтверждениях из трёх выбранных. Проверяется чтение через `FIND_VALUE` после остановки одного хранителя.

**Проверка всех тестов (включая прежние этапы):**

```bat
py -m unittest discover -s tests -v
```

**Ожидаемый итог:**

```text
Ran 145 tests in ...s

OK
```

**Запуск эксперимента:**

```bat
py -m scripts.replication_demo
```

**Пример вывода** (имена хранителей, задержки и число RPC могут отличаться):

```text
Bootstrap: A -> B -> C -> D -> E
1) E finds the three closest live keepers via FIND_NODE and STOREs a signed NodeRecord
  "replication_factor": 3,
  "required_acks": 2,
  "ack_count": 3,
  "succeeded": true
   Selected keepers: C, E, B
2) A reads signed record using FIND_VALUE
   Before failure: found = True
3) Stop keeper C and repeat FIND_VALUE from another running node
   After one keeper stopped: found = True
SUCCESS: R=3 replication, 2/3 threshold, and FIND_VALUE after one keeper failure.
Results saved to: ...\results\record_replication_....json
```

Файл `record_replication_....json` содержит выбранных хранителей, количество подтверждений, число RPC при поиске, идентификатор остановленного узла и результаты чтения до/после отказа. Все процессы автоматически завершаются после эксперимента.

**Границы проверки:** это пятиузловой пилот на `127.0.0.1`; TLS 1.3, многопереходные туннели и итоговая проверка DHT на 12–15 узлах ещё не выполнены. В показанном пользователем прогоне `RPC = 0` после отказа, поэтому для проверки именно сетевого повторного чтения используйте сценарий `republish_demo` ниже. Тест с 2/3 подтверждениями есть в автоматическом наборе, а демонстрация обычно показывает 3/3.


---

## Этап 3 — автоматическое переопубликование и TTL (часть 4)

**Реализовано:** владелец подписывает и размещает запись `NodeRecord` на трёх ближайших доступных хранителях. Через установленный интервал выпускает новую запись с увеличенным `sequence_number` и новым сроком действия. Интервал не превышает половины TTL. При сетевой ошибке повторяется **тот же подписанный пакет записи**; после успешной публикации следующий выпуск увеличивает версию. Номер следующей версии можно хранить в отдельном каталоге состояния, чтобы он не начинался заново после перезапуска.

**Проверка всех тестов:**

```bat
py -m unittest discover -s tests -v
```

**Ожидаемый итог:**

```text
Ran 145 tests in ...s

OK
```

**Запуск демонстрации:**

```bat
py -m scripts.republish_demo
```

**Примерный вывод** (имена хранителей и число RPC могут отличаться):

```text
Bootstrap: A -> B -> C -> D -> E
1) First signed publication: sequence = 1 | ACK = 3
2) Automatic republish completed: 1 | newest sequence = 2 | ACK = 3
3) Replicas: A, B, D
4) Stop keeper A; read from NON-keeper C: found = True | RPC = 3
5) Simulate TTL using controlled timestamps (no 120-second wait)
   Before TTL: exists = True
   At TTL: expired = True
SUCCESS: periodic republish, TTL and remote lookup after keeper failure.
Results saved to: ...\results\record_republish_....json
```

Сценарий подтверждает, что чтение после отказа произошло **по сети** (`RPC > 0`), поскольку инициатор выбран среди узлов без локальной копии. TTL проверяется с контролируемым временем, без ожидания двух минут. Для быстрой демонстрации интервал переопубликования уменьшен; обычная рекомендуемая настройка при `TTL=180` — `interval_seconds=60`.

**Ограничения:** это пилот на пяти узлах с незашифрованным транспортом; восстановление записи после перезапуска хранителей и долгосрочное хранение `highest_sequence` на диске не реализованы. Долговременное состояние владельца с номером версии храните отдельно от исходного кода и репозитория. Все результаты прогона — в JSON папки `results`.


## Этап 4 — TLS 1.3 и взаимная аутентификация (часть 1)

**Реализовано:** отдельный защищённый обмен `PING/PONG` между узлами A и B; TLS 1.3 с обязательными сертификатами обеих сторон, доверенным учебным центром сертификации и проверкой ожидаемого `NodeID` по открытому ключу сертификата. TLS 1.2 отклоняется. При неверном ключе, сертификате или недоверенном CA обработка прикладного сообщения не выполняется. Для демонстрации также проверяется отсутствие исходного текста в байтах, видимых промежуточному TCP-посреднику.

Для Windows 10 требуется Python с поддержкой TLS 1.3 и установленная зависимость из `requirements.txt`. Подготовка (один раз для сохранённой демонстрационной идентичности):

```bat
py -c "import ssl; print(ssl.OPENSSL_VERSION); print('TLS 1.3 supported:', ssl.HAS_TLSv1_3)"
py -m pip install -r requirements.txt
py -m scripts.tls_nodes init
```

**Быстрая проверка одной командой:**

```bat
py -m scripts.tls_nodes demo
```

**Пример ожидаемого вывода:**

```text
A and B negotiated: TLSv1.3
Server verified B NodeID: True
Client verified A NodeID: True
PING/PONG request_id match: True
Plaintext marker visible in TCP relay bytes: False
Captured TCP bytes: ...
SUCCESS: TLS 1.3 mutual auth, NodeID pin, encrypted payload
```

**Обмен двух независимых процессов через CMD** (сначала `init`, затем два окна в корне проекта):

**Окно A — сервер:**

```bat
py -m scripts.tls_nodes server
```

**Окно B — клиент:**

```bat
py -m scripts.tls_nodes client
```

**Примерный вывод клиента:**

```text
B: TLS version: TLSv1.3
B: verified server NodeID: ...
B: encrypted PING sent; matching PONG received
SUCCESS: mutual TLS 1.3 and expected NodeID checked
```

**Все автоматические тесты (включая 26 TLS-тестов частей 4.1 и 4.2):**

```bat
py -m unittest discover -s tests -v
```

**Ожидаемый результат:**

```text
Ran 145 tests in ...s
OK
```

Демонстрационные сертификаты и закрытые ключи автоматически сохраняются **вне репозитория**, в каталоге `%LOCALAPPDATA%\secure_p2p_coursework`. Не загружайте в GitHub `identity.pem` и `demo_ca_private.pem`. Учебная CA не является централизованным каталогом участников, но представляет собой отдельно настроенный корень доверия. Эти сертификаты предназначены только для учебного стенда.

**Границы этой демонстрации:** `tls_nodes` проверяет отдельный защищённый PING/PONG. Для DHT есть отдельная демонстрация TLS в разделе ниже. Автоматическая replay-дедупликация прикладных действий, контрольный `pcap` и сквозная end-to-end защита туннелей пока не реализованы.


## Этап 4 — взаимный TLS 1.3 для DHT RPC (часть 2)

**Реализовано:** пятиузловой TLS-стенд, в котором `PING`, `FIND_NODE`, `STORE`, `FIND_VALUE` и репликация записей выполняются через TLS 1.3 с сертификатами обеих сторон и проверкой `NodeID`. Подключение к первому известному узлу требует заранее известного `NodeID` и открытого ключа этого seed-узла; полноценного общего каталога участников нет. Ошибка TLS не приводит к переходу на открытый TCP. Проверяются неверный ключ, подмена подписанного RPC, недоверенный CA и TLS 1.2.

**Быстрая проверка: допускается одно окно CMD:**

```bat
py -m scripts.secure_dht_demo
```

**Пример вывода:**

```text
Bootstrap over mutual TLS 1.3: A -> B -> C -> D -> E
All DHT nodes require TLS: True
A knows C before FIND_VALUE: False
TLS PING A -> B: True
TLS STORE E -> C: stored
TLS FIND_VALUE A (through B -> C): found = True | RPC = 2 | iterations = 2
TLS FIND_NODE A -> D: found = True | RPC = 4
Plain TCP request accepted as DHT RPC: False
SUCCESS: mTLS 1.3 DHT PING, FIND_NODE, STORE and FIND_VALUE.
Results saved to: ...\results\tls_dht_....json
```

**Полная автоматическая проверка:**

```bat
py -m unittest discover -s tests -v
```

**Ожидаемый итог:**

```text
Ran 145 tests in ...s
OK
```

Число RPC и задержки могут меняться. Результаты защищённого пилота сохраняются в `results\tls_dht_....json`. Ключи, сертификаты учебной CA и состояние узлов создаются в временной папке системы и не должны попадать в Git. Режим включается только когда переданы TLS-сертификаты: **команды демонстраций этапов 1–3 по-прежнему используют незашифрованный TCP** и не доказывают защиту трафика. Для итоговой приёмки ещё нужны end-to-end защита внутри туннеля, прикладная replay-защита, `pcap` и эксперименты на 12–15 узлах.


## Этап 4 — replay-защита TLS RPC (часть 3)

**Реализовано:** защищённые DHT-запросы содержат подписанные 16-байтовые `session_id` и `message_id`. Сервер хранит уже обработанные идентификаторы сообщений **по каждому NodeID** и не выполняет повторный запрос ни в рамках прежней TLS-сессии, ни после нового TLS-подключения. Повторный `STORE` не вызывает второго сохранения. Ответы проверяются на совпадение `request_id`, `session_id`, `message_id`. Сервер не принимает TLS-запросы без полей replay-защиты.

**Полный запуск тестов:**

```bat
py -m unittest discover -s tests -v
```

Ожидаемый итог:

```text
Ran 145 tests in ...s
OK
```

**Демонстрация:**

```bat
py -m scripts.replay_demo
```

Пример вывода:

```text
Mutual TLS 1.3: A -> B
TLS version: TLSv1.3
1) First signed STORE: stored
2) Replay in SAME TLS session rejected: True
3) Replay in NEW TLS session rejected: True
4) STORE executions: 1
5) Different message_id accepted: True
Replay counters: {"accepted": 2, "rejected": 2, ...}
SUCCESS: same-session and new-session RPC replay blocked.
Results saved to: ...\results\tls_replay_....json
```

**Ограничение:** анти-replay журнал хранится только в памяти запущенного узла, удерживает до 4096 идентификаторов за окно 3600 секунд и при переполнении отклоняет новые запросы. После перезапуска узла журнал не восстанавливается; старые корректно подписанные сообщения потенциально могут пройти повторно. Поэтому это ещё не полная долговременная защита от replay. Подмена или отказ доверенной учебной CA, pcap, сквозная end-to-end защита и туннели остаются вне текущего подэтапа. Ранние демонстрации, запущенные явно без TLS, по-прежнему остаются учебным plaintext-режимом.


## Этап 4 — контрольный захват TLS-трафика (часть 4, инструкция)

**Цель:** сохранить реальный файл `.pcapng` и проверить, что PING/PONG передаются внутри TLS 1.3, а текст `TLS Stage4` не виден в захваченном потоке без ключей расшифрования. Захват выполняется в Windows через **Wireshark + Npcap**, на интерфейсе loopback (`127.0.0.1`). Это проверка шифрования транспортного канала, а не end-to-end туннеля.

**Подготовка:** установить Wireshark с компонентом Npcap с официального сайта https://www.wireshark.org/download.html . В списке интерфейсов выбрать `Adapter for loopback traffic capture` / `Npcap Loopback Adapter` (название зависит от версии). Сначала запустить захват; уже после — команды ниже.

**Окно CMD №1 (сервер):**

```bat
py -m scripts.tls_nodes init
py -m scripts.tls_nodes server
```

**Окно CMD №2 (клиент):**

```bat
py -m scripts.tls_nodes client
```

**Пример вывода клиента:**

```text
B: TLS version: TLSv1.3
B: verified server NodeID: ...
B: encrypted PING sent; matching PONG received
SUCCESS: mutual TLS 1.3 and expected NodeID checked
```

В Wireshark нажать красную кнопку **Stop**, задать display filter `tcp.port == 5331`, затем сохранить через **File → Save As** в `results\tls_stage4_4.pcapng` (или вне проекта). Если Wireshark отображает только `TCP`, применить **Analyze → Decode As... → TLS** для этого порта.

**Контроль:** выбрать пакет из потока и открыть **Follow → TCP Stream**; без предоставленных TLS session secrets прикладной текст не должен читаться. В строке display filter можно проверить `frame contains "TLS Stage4"`: ожидается **0 совпадений** для защищённого трафика. Положительным доказательством служат одновременно реальный трафик порта 5331, TLS-согласование, результат клиента и отсутствие читаемого маркера. Отсутствие строки само по себе не доказывает безопасность криптографии.

**По желанию — контрольный открытый TCP:** запустить узлы первого этапа, передать `ping 5002` и захватить порт 5002 отдельно в `results\tcp_plain_reference.pcapng`; JSON с приветствием там виден без TLS. Сохранять только тестовый локальный трафик, без секретных ключей и реальных конфиденциальных данных.

**Проверено на Windows:** захват сохранён пользователем в `results\tls_stage4_4.pcapng`, файл повторно открыт. При фильтре `tcp.port == 5331` видны TCP-рукопожатие, `Client Hello`, `Server Hello`, TLS 1.3 `Application Data` и завершение TCP. При `tcp.port == 5331 && frame contains "TLS Stage4"` совпадений нет. Этот результат относится к учебному PING/PONG через TLS на 127.0.0.1:5331, а не к end-to-end туннелю. При этом полный набор автоматических тестов прежних этапов остаётся доступен командой:

```bat
py -m unittest discover -s tests -v
```

Ожидаемый итог: `Ran 145 tests ...` и `OK`.


## Этап 4 — итоговая проверка и отрицательные сценарии

**Выполнено:** взаимная TLS 1.3 аутентификация, привязка к NodeID, защищённые DHT RPC, прикладная защита от повторов. На Windows подтверждено **145/145 тестов**, успешный `replay_demo`, TLS-пакеты в `results\tls_stage4_4.pcapng`. Открытый текст маркера в дампе не обнаружен; отсутствие совпадений является дополнительным наблюдением, а не самостоятельным криптографическим доказательством.

**Отрицательные проверки TLS (сертификат, неверный NodeID, чужой CA, TLS 1.2, отсутствие сертификата, plaintext):**

```bat
py -m unittest discover -s tests -p "test_tls_channel.py" -v
py -m unittest discover -s tests -p "test_tls_dht_rpc.py" -v
```

**Replay-проверки (повтор STORE, другая TLS-сессия, подмена сообщения):**

```bat
py -m unittest discover -s tests -p "test_replay_tls.py" -v
```

**Полная регрессия:**

```bat
py -m unittest discover -s tests -v
```

Ожидаемый итог полной регрессии: `Ran 145 tests in ...` / `OK`. Слово `ok` после `test_...rejected` означает, что тест **успешно подтвердил отказ** при некорректном подключении; это не означает успешное подключение нарушителя.

**Доказательства:** `results\tls_stage4_4.pcapng`, скриншот Wireshark с `tcp.port == 5331`, скриншот пустого поиска `frame contains "TLS Stage4"`, консольный результат TLS-клиента и лог `145 tests / OK`. В репозиторий не включать секретные `*.pem`, приватные ключи и TLS session secrets.

**Текущее ограничение:** replay-журнал хранится в памяти и очищается при перезапуске узла; сценарий TLS ещё не является сквозным туннелем, а полномасштабная сеть на 12–15 узлах не проверена.
