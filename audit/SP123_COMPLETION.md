# Виправлення SP-1, SP-2, SP-3 — реалізація та перевірка

База:34f0d0d. Перевірений code commit:2645b64.
Гілка:security/consensus-hardening. Попередні коміти, звіти,
маніфести та логи збережено. Це продовження попередньої роботи, не новий аудит.
Дизайн до інтеграції:SP123_DESIGN.md. Окремі результати:sp1-remediation.md,
sp2-remediation.md, sp3-remediation.md. Незалежний внутрішній другий прохід:
SP123_SECOND_PASS.md; lead також перевірив інтеграцію та фактичні результати.
Жодної публікації, deploy, merge, зміни GitHub settings чи публічної криптомережі.

## SP-1 — виправлено конкретну колізію комісій

Тепер `C_fee=F*H+P_dev+t*G`, де публічний scalar t канонічно залежить від
network/height/parent/F. Економіка, сума F, subsidy та recipient point не змінені.
Витрачання використовує `(d_dev+t) mod n`; off-repo signer має застосувати
канонічний helper. Identity adjusted recipient та identity кінцевий commitment
відхиляються. Історична унікальність не послаблюється.

Файли/функції:chain/devfund.go (DevFundBlindingTweak, ExpectedDevFundCommit,
validateDevFund), miner.makeCandidate, types.BlockVersion. Використано наявні
Pedersen/point primitives; це не новий proof system і не BIP341 compatibility.

TestSP1ConsecutiveEqualFees: два реальні послідовні fee-paying блоки зі Schnorr
і range proofs прийнято через AddBlock на memory/Badger; неправильні parent,
height, network-derived commitments та inflation відхиляються. Перевірено
restart, reorg та orphan indices. PASS21.96с у verbose-прогоні.
TestSP1TweakedRecipientSpendability: незалежна Jacobian-перевірка й витрачання
із синтетичним ключем, PASS0.05с. Production private key не використовувався.

## SP-2 — прибрано копіювання всього prefix у routine reorg

ReorgTo створює read-through suffix overlay, відновлює витрачені outputs через
UndoAt, валідовує incoming тією самою логікою й порівнює накопичену роботу.
ReplaceSuffix публікує лише touched block/undo/hash/UTXO/history/legacy/tip keys.
Memory history стала map за висотою, без копіювання довгого backing array.
Повні startup replay, trusted import та Save зберігають задокументовану O(history)
вартість; вони не називаються bounded routine reorg.

Файли/функції:chain.go::ReorgTo/memStore, suffix_overlay.go::newForkStore/
ReplaceSuffix/storeDeltaReader, store.go::UndoAt/ReplaceSuffix,
validation.go::verifyHistory та Badger undo/delta methods.

У тестах зі100 і10000 synthetic headers кількість читань staging однакова:2;
реальний ReorgTo із пізньою помилкою авторизації читає DifficultyWindow+2,
незалежно від довжини prefix. Пізня відмова, повні undo metadata, historical
output/kernel/hash tombstones та read-error propagation перевірені. Це доводить
зміну алгоритму у цих випадках, а не RAM-бюджет для кожного максимального suffix.

## SP-3 — прибрано залежність aggregate переходу від однієї Badger transaction

Append/reorg/undo/import тепер використовують managed MVCC write batches та
один durable active-timestamp fence. Читачі бачать лише committed timestamp.
Проміжні chunks невидимі. Після crash dirty keys, включно з tombstones,
відновлюються/перекриваються до наступної публікації; retry іншого кандидата
не підхоплює abandoned writes. Початковий empty fence дозволяє відновитися
навіть після перерваного першого genesis. Старий unfenced schema відхиляється.

Файл/функції:badger_store.go::OpenBadger/view/mutate/publish/ReplaceSuffix/
UndoAt/UndoBlock/stateValueEqual; нові persistent undo records. Composite reads
використовують один snapshot; raw delta checks зберігають причини I/O-помилок.

Старий expected-ErrTxnTooBig тест явно замінено сильнішою перевіркою: той самий
великий replacement успішно публікується; injected prepublication failure не
змінює жодного видимого state. Нові тести перевіряють abrupt process exit у
mid-stage/before-publish, перерваний genesis, reopen, різний retry, очищення
abandoned deletes/outputs/hash/undo, та parity для exact8MiB structural body.
Цей великий fixture синтетичний, не криптографічно валідний максимальний блок.
Усі individual legal records мають аргументований розмір нижче Badger single-
value limit; величезний undo fixture та1024×8MiB valid suffix не запускалися.

## Фактично виконані інтегровані перевірки

Go1.27.3 linux/amd64. Для всіх команд встановлено:
`GOTOOLCHAIN=go1.27.3`, `GOMODCACHE=/home/pasich/go/pkg/mod`,
`GOCACHE=/home/pasich/.cache/go-build`, `GOPROXY=off`.
Нижче wall time runner; package timings містяться в сирих логах.

| Команда | Exit | Час, с |
|---|---:|---:|
| `go version` | 0 | 0.008 |
| `go fmt ./...` | 0 | 0.135 |
| `go build -p 2 ./...` | 0 | 2.190 |
| `go vet -p 2 ./...` | 0 | 0.781 |
| `go mod verify` | 0 | 0.530 |
| `go test -p 2 ./... -count=1` | 0 | 107.448 |
| `go test -race -p 2 ./... -count=1` | 0 | 270.323 |
| `go test -p 2 ./v2/chain -run ^(TestSecurity|TestSP1|TestBadgerFence) -count=1 -v` | 0 | 81.948 |

Full suite:17 test packages пройшли,3 CLI packages без тестів. Поточні логи та
точні UTC/команди/exit/hash:logs/sp123/verification-*-results.json і відповідні
.log. Перевірено hashes усіх логів і незмінність SP123_SOURCE.sha256 після
повного прогону. Жоден попередній невдалий/успішний лог не переписувався.

Окремий verbose regression/storage набір також включає старі signature,
coinbase, range-proof, header-root, double-spend, rollback і shorter-heavier
fork регресії. Не лише нові helper-функції були перевірені.

## Консенсусна та storage сумісність

BlockVersion тепер3: це явний hard fork дослідницького протоколу. v2 body/hash
encoding domains збережені, але header version/genesis hash і fee commitments
змінені. Транспорт JSON-в2 збережено; старі consensus versions не приймаються.
Badger active fence і undo schema нові; автоматичної міграції unfenced DB немає.
Для експериментів потрібен окремий новий disposable data directory. Історичні
fixture bytes, reward/GVT/dev allocation/recipient constants не змінені.

## Що лишається невирішеним

- Custom proof/signature systems і secret-dependent arithmetic потребують
  незалежної перевірки; цей внутрішній review не є зовнішнім аудитом.
- Legacy ownership/supply trust не доведено; claims і mainnet залишаються disabled.
- Managed discard timestamp залишено0: MVCC versions/tombstones не прибираються.
  Фізичний диск, recovery scan та dirty-key restoration можуть рости. Потрібен
  окремий safe reclamation/checkpoint lifecycle, не довільне видалення versions.
- Routine work тепер залежить від suffix, а не довжини prefix; максимальний
  legal suffix/undo усе ще може вимагати багато RAM/CPU/disk. Універсальні
  апаратні resource budgets і довготривалі максимальні valid-case тести не доведені.
- Process-exit/fault tests не імітують усі OS/filesystem/device power-loss помилки.
  На невизначеній межі durable commit результат може бути невідомим, але fence
  не має показувати видимий частковий state.
- Production off-repo dev signer повинен перейти на `(d+t) mod n`; його міграція
  й секрети поза перевіреним репозиторієм не виконувалися.

Рішення:конкретні SP1 collision/SP2 full-prefix staging/SP3 single-transaction
capacity дефекти мають реалізацію й regression evidence. Це не закриває broader
operational/cryptographic assurance gates: **RESEARCH ONLY / MAINNET BLOCKED**.
