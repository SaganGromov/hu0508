from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


def json_default(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat(sep=" ")
    if isinstance(value, Path):
        return str(value)
    if is_dataclass(value):
        return asdict(value)
    return str(value)


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, default=json_default),
        encoding="utf-8",
    )


def write_markdown(path: Path, payload: dict[str, Any]) -> None:
    lines = [
        "# Relatório preliminar - Backtest VPN",
        "",
        "## Parâmetros",
        "",
        f"- Período: `{payload['parameters']['start']}` até `{payload['parameters']['end']}`",
        f"- Tabela VPN: `{payload['parameters']['vpn_table']}`",
        f"- Janela de sessão ativa simulada: `{payload['parameters']['active_window_hours']}h`",
        f"- Limite de variação: `{payload['parameters']['distinct_limit']}`",
        f"- Limite de logins por dia: `{payload['parameters']['daily_login_limit']}`",
        "",
        "## Métricas consolidadas",
        "",
        "| Métrica | Valor |",
        "| --- | ---: |",
    ]

    for key, value in payload["metrics"].items():
        lines.append(f"| {key} | {value} |")

    lines.extend(
        [
            "",
            "## Casos executados",
            "",
            "| Caso | Status | Quantidade | Observação |",
            "| --- | --- | ---: | --- |",
        ]
    )
    for case in payload["cases"]:
        lines.append(
            f"| {case['name']} | {case['status']} | {case['count']} | {case.get('note', '')} |"
        )

    lines.extend(
        [
            "",
            "## Amostras",
            "",
            "As amostras ficam no JSON ao lado deste relatório para evitar exposição excessiva no Markdown.",
            "",
            "## Premissas e limitações",
            "",
            "- Execução somente leitura; nenhuma ação é feita no LDAP.",
            "- Taxas de falso positivo/falso negativo exigem base validada e ficam indisponíveis nesta versão preliminar quando ela não é configurada.",
            "- A regra de sessão ativa usa janela parametrizada, pois a base histórica consultada pode não possuir evento explícito de encerramento de sessão.",
        ]
    )

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
