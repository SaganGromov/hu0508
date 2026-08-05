"""Geracao dos relatorios JSON e Markdown do backtest."""

import dataclasses
import json
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path


def json_default(value):
    """Serializador JSON para datetime/date, Path, dataclasses e Decimal."""
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return dataclasses.asdict(value)
    if isinstance(value, Decimal):
        if value == value.to_integral_value():
            return int(value)
        return float(value)
    raise TypeError("Tipo nao serializavel em JSON: {0!r}".format(type(value)))


def write_json(path, payload):
    """Escreve o payload como JSON UTF-8 identado."""
    path = Path(path)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2, default=json_default)
        handle.write("\n")


def write_markdown(path, payload):
    """Escreve o relatorio pt-BR em Markdown para publico nao tecnico."""
    params = payload["parameters"]
    metrics = payload["metrics"]
    cases = payload["cases"]

    lines = []
    lines.append("# Relatorio preliminar - Backtest VPN")
    lines.append("")
    lines.append("Gerado em: {0}".format(payload["generated_at"]))
    lines.append("")
    lines.append("## Parametros")
    lines.append("")
    lines.append(
        "- Periodo analisado: {0} (inclusive) ate {1} (exclusivo)".format(
            params["start"], params["end"]
        )
    )
    lines.append(
        "- Tabela VPN: {0}.{1}".format(params["vpn_schema"], params["vpn_table"])
    )
    lines.append(
        "- Janela de sessao ativa: {0} hora(s)".format(params["active_window_hours"])
    )
    lines.append(
        "- Limite de valores distintos por usuario: {0}".format(
            params["distinct_limit"]
        )
    )
    lines.append(
        "- Limite de logins por usuario por dia: {0}".format(
            params["daily_login_limit"]
        )
    )
    lines.append("")
    lines.append("## Metricas consolidadas")
    lines.append("")
    lines.append("| Metrica | Valor |")
    lines.append("| --- | --- |")
    for key, value in metrics.items():
        lines.append("| {0} | {1} |".format(key, value))
    lines.append("")
    lines.append("## Casos executados")
    lines.append("")
    lines.append("| Caso | Status | Quantidade | Observacao |")
    lines.append("| --- | --- | --- | --- |")
    for case in cases:
        lines.append(
            "| {0} | {1} | {2} | {3} |".format(
                case["name"], case["status"], case["count"], case["note"]
            )
        )
    lines.append("")
    lines.append("## Amostras")
    lines.append("")
    lines.append(
        "As amostras detalhadas de cada caso (ate {0} linhas por caso) estao no"
        " arquivo JSON gerado junto com este relatorio, no campo"
        " `cases[].sample`.".format(params["sample_limit"])
    )
    lines.append("")
    lines.append("## Premissas e limitacoes")
    lines.append("")
    lines.append(
        "- Execucao 100% somente leitura sobre a base historica;"
        " nenhuma escrita em DB2."
    )
    lines.append(
        "- Nenhuma acao e executada no LDAP; a politica principal apenas"
        " simula a elegibilidade de encerramento de sessao."
    )
    lines.append(
        "- Taxas de falso positivo e falso negativo ficam indisponiveis"
        " enquanto nao houver base rotulada validada"
        " (valor reportado: not_available_without_validated_labels)."
    )
    lines.append(
        "- A janela de sessao ativa e parametrizada (--active-window-hours)"
        " porque a base historica pode nao conter um evento explicito de"
        " encerramento de sessao."
    )
    lines.append("")

    Path(path).write_text("\n".join(lines), encoding="utf-8")
