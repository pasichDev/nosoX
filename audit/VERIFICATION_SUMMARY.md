# Підсумок локальної верифікації NosoX

Дата:2026-10-26. Гілка:`security/consensus-hardening`.
Початкова база:`6179eb56d53768a19950f07e9c806fd384572c5d`.
Усі попередні зміни та findings збережено; аудит не починався заново.
На початку цього проходу створено приватний локальний знімок:
`/tmp/nosox-hardening-preserve-20261026T144154Z.tar.gz`,
SHA256`bcabb762342304b8baf0fb8dd4bde35c0708ca7fdd68ec40da433beae882d554`;
поряд збережено binary diff у файлі.patch. Код і докази залишаються у цій гілці. Перевірений код збережено локальним
комітом `ed5c2eb` (`Harden consensus authorization and atomic chain transitions`).

Перечитано SECOND_PASS.md, RELEASE_READINESS.md та актуальні логи. Цей прохід
перевіряє вже реалізовані захисні зміни; новий пошук вразливостей, fuzz-кампанії,
атакувальні симуляції, deploy/publish/merge не виконувалися.

## Фактичні результати

Go1.27.3 linux/amd64; GOPROXY=off; writable caches. Усі команди нижче
виконано з указаними в TEST_REPORT.md змінними середовища.

| Команда | Exit | Повний час, с |
|---|---:|---:|
| `go version` | 0 | 0.009 |
| `go fmt ./...` | 0 | 0.134 |
| `go build -p 2 ./...` | 0 | 2.115 |
| `go vet -p 2 ./...` | 0 | 0.621 |
| `go mod verify` | 0 | 0.736 |
| `go test -p 2 ./... -count=1` | 0 | 100.567 |
| `go test -race -p 2 ./... -count=1` | 0 | 190.019 |
| `go test -p 2 ./v2/chain -run ^TestSecurity -count=1 -v` | 0 | 56.927 |
| `go test -p 2 -coverprofile=audit/coverage.out ./... -count=1` | 0 | 77.603 |

У full-suite та race:17 test packages пройшли;3 CLI packages не мають тестів.
Загальне statement coverage62.9% не є доказом безпеки. Storage-пакет у
окремому verbose-прогоні:56.364с, runner56.927с.

У цьому проході виправлено звичайну build-регресію: видалено невикористаний
імпорт fmt з v2/p2p/sync.go. Невдалий перший прогін збережено як attempt1.
Попередню miner race-регресію також збережено в логах; актуальний повний
race-прогін її не виявив.

Після full-suite посилено лише assertion існуючого
TestSecurityBadgerOversizeTransactionRollback: потрібен саме
badger.ErrTxnTooBig, а не довільна помилка. Повторний targeted-race запуск:
exit0, test3.36с, package4.473с. Production-код після повних перевірок
не змінювався. Маніфести FULL_SUITE_SOURCE.sha256 і VERIFIED_SOURCE.sha256
відрізняються лише цим тестовим файлом.

## SP-1, SP-2, SP-3

| Finding | Стан | Що підтверджено та чого не доведено |
|---|---|---|
| SP-1: однакові комісії → однаковий fee commitment | **Не виправлено; High release blocker** | Існуючий TestExpectedDevFundCommitDeterministic пройшов0.022с і підтверджує незмінну детермінованість. Історична унікальність відхиляє повторний commitment навіть після витрати. Повний сценарій двох fee-paying блоків у цьому проході не додавався й не виконувався. Змінювати recipient або прибирати uniqueness не можна. |
| SP-2: reorg копіює всю історію | **Частково пом’якшено; High release blocker** | Існуючий ReorgRejectsMalformedBeforePrefixRead пройшов0.09с: структурно некоректний suffix відхиляється до читання prefix. Для структурно коректного кандидата staging/stateEntries досі O(вся історія) за RAM/CPU; bounded long-chain behavior не доведено. |
| SP-3: місткість атомарної Badger-транзакції | **Не вирішено; High release blocker / assurance gap** | Відтворено саме ErrTxnTooBig у наявному bounded fault-тесті; state лишається незмінним. Fixture навмисно поза consensus bounds. Це не доказ, що кожен допустимий append/reorg поміщається у Badger або збігається з memory backend; валідний максимальний suffix тут не конструювався. |

SP-4: miner уже припиняє роботу зі зміненим parent; відповідний regression
та актуальний повний race пройшли. SP-5: write-транзакції тепер повторно
перевіряють delta та помилки читання, але boolean lookup API у загальному
валідаційному інтерфейсі зберігає обмеження; повне поширення I/O-помилок
не оголошується завершеним.

## Підтверджений обсяг захисних змін

Реальні AddBlock/ValidateTransaction/ReorgTo регресії перевіряють kernel і
coinbase signatures, точну емісію, maturity, stored metadata, дублікати,
історичний replay, fail-closed legacy claims, відмову fake/mutated proofs,
повні body roots, accumulated-work fork choice та незмінність state при
невдалій операції. Обидва backends перевірено у зазначених малих сценаріях.
Детальна таблиця «файл → інваріант → тест → результат» є в TEST_REPORT.md.

## Невиконані перевірки й безпечні наступні кроки

1. Узгодити окрему консенсусну специфікацію унікальних fee outputs зі збереженням
   чинної економіки; після review додати послідовні fee-block/restart/reorg тести.
2. Спроєктувати bounded snapshot/delta staging та атомарний version switch для
   великих reorg; не розбивати перехід на видимі часткові коміти.
3. Визначити й перевірити зв’язок максимальних legal deltas із реальною місткістю
   обох backends. Нинішній rollback-тест вирішує лише атомарність відмови.
4. Залишити legacy claims/mainnet вимкненими до незалежної перевірки ownership,
   історичної емісії, custom proof system та secret-dependent arithmetic.
5. Окремо завершити secret/history review, reproducibility/cross-platform та
   глибшу crash/resource перевірку за майбутнім явним обсягом робіт.

Додатковий offline go list -m -json all повернув1 через відсутню cached metadata;
повний graph не завантажувався. go mod verify повернув0. Це зафіксовано окремо
від успішних build/test/race результатів. Не всі початкові фази аудиту завершено.

Рішення лишається **RESEARCH ONLY / MAINNET BLOCKED**. Це не independent audit
і не готовність до public testnet чи фінального release audit. Налаштування
репозиторію не змінювалися; нічого не розгорнуто, не опубліковано і не merged.
