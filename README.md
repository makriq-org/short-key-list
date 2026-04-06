# short-key-list

Репозиторий публикует списки из `200`, `100` и `50` VLESS-ключей, которые прошли проверку на момент последнего цикла.

Итоговые файлы:

- `data/short-key-list.txt`
- `data/short-key-list-100.txt`
- `data/short-key-list-50.txt`

## Как собирается список

Каждый цикл:

1. загружает ключи из публичных источников;
2. удаляет дубликаты;
3. поднимает для каждого кандидата временный `xray` outbound;
4. проверяет прохождение запроса к `https://www.gstatic.com/generate_204`;
5. сохраняет историю результатов;
6. выбирает основной список на `200` ключей из успешно прошедших проверку;
7. из этого же ранжированного набора дополнительно собирает списки на `100` и `50` ключей.

При отборе учитывается рейтинг ключа по предыдущим циклам. Он повышает шансы для ключей с более стабильной недавней историей и более низкой задержкой. Медленные, флапающие и недавно деградировавшие ключи попадают в итоговый список реже.

## Что это значит на практике

- список не является зеркалом апстримов;
- в него не попадают дубликаты;
- в него не попадают ключи, которые не прошли текущую проверку;
- публикация не гарантирует, что ключ продолжит работать позже.

## Источники

- `https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt`
- `https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt`
- `https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile-2.txt`

## Структура

- `data/short-key-list.txt` — публикуемый список на 200 ключей.
- `data/short-key-list-100.txt` — публикуемый список на 100 ключей.
- `data/short-key-list-50.txt` — публикуемый список на 50 ключей.
- `scripts/check_key_list.py` — проверка и отбор.
- `scripts/run_pipeline.py` — запуск полного цикла.
- `scripts/publish_key_list.py` — публикация обновленного файла.

## Локальный запуск

```bash
cp .env.example .env
python3 scripts/run_pipeline.py
```

## Основные переменные окружения

- `KEY_LIST_LIMIT` — размер основного списка.
- `EXTRA_KEY_LIST_LIMITS` — дополнительные размеры списков через запятую.
- `WORKERS` — параллелизм проверок.
- `TCP_PRECHECK` — быстрый TCP-предчек перед запуском `xray`.
