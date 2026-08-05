"""Gerador HTML autocontido para o bundle do backtest VPN."""

import html
import json
import re
from pathlib import Path

from .bundle import sanitize_for_html
from . import svgchart

MAX_ARTIFACT_BYTES = 3 * 1024 * 1024
RULE_TITLES = {
    "R1": ("Usuário com IPs demais", "Procura chaves com muitos IPs de origem ou corporativos no período."),
    "R2": ("Usuário com hostnames demais", "Procura chaves usadas em mais máquinas/nomes de host do que o esperado."),
    "R3": ("Usuário com dispositivos demais", "Procura chaves com muitos identificadores de dispositivo."),
    "R4": ("Volume diário alto", "Procura dias em que a mesma chave fez logins em excesso."),
    "R5": ("VPN ativa + login em DB2PEP.MTA_AUT_CLI_TRAN (OpenAM)", "Detecta sessões autenticadas na tabela DB2PEP.MTA_AUT_CLI_TRAN (tabela de produção dos logins do OpenAM) que ocorrem em paralelo a uma sessão VPN ativa do mesmo usuário, com IP diferente do IP tunelado."),
    "R6": ("R5 + múltiplos dispositivos simultâneos", "Subconjunto de R5 em que o usuário também apresentou múltiplos hostnames ou dispositivos distintos no período — sinal reforçado de sessão paralela."),
}


def e(value):
    return html.escape("" if value is None else str(value), quote=True)


def pct(value):
    if value is None:
        return "n/a"
    return "{0:.2%}".format(float(value))


def num(value):
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return "{0:.4g}".format(value)
    return str(value)


def _ci_lower(obj):
    try:
        return obj.get("ci95", [None, None])[0]
    except Exception:
        return None


def _ci_upper(obj):
    try:
        return obj.get("ci95", [None, None])[1]
    except Exception:
        return None


def verdict(rule):
    """Veredito mecanico conforme handoff 05 §5."""
    reasons = []
    adj = rule.get("adjudicated_precision") or {}
    inj = rule.get("injected_recall") or {}
    neg = rule.get("negative_control") or {}
    temp = rule.get("temporal_stability") or {}
    benign = rule.get("benign_twin") or {}
    reviewer_reliability = rule.get("reviewer_reliability")

    adj_absent = not adj or adj.get("status") == "not_run" or adj.get("value") is None
    inj_absent = not inj or inj.get("status") == "not_run" or inj.get("value") is None
    if adj_absent and inj_absent:
        outcome = "indefinida"
        reasons.append("adjudicação e injeção sintética ausentes")
    else:
        low = False
        if _ci_upper(adj) is not None and _ci_upper(adj) < 0.3:
            low = True; reasons.append("limite superior da precisão adjudicada abaixo de 0,3")
        if neg.get("fpr_bound_wilson95_upper") is not None and neg.get("fpr_bound_wilson95_upper") > 0.05:
            low = True; reasons.append("limite de falso positivo no controle negativo acima de 5%")
        if _ci_lower(benign) is not None and _ci_lower(benign) > 0.5:
            low = True; reasons.append("benign-twin aciona com limite inferior acima de 50%")
        if temp.get("verdict") == "unstable":
            low = True; reasons.append("série temporal instável")
        if low:
            outcome = "baixa"
        else:
            scenarios = inj.get("scenarios") if isinstance(inj, dict) else None
            every_recall = False
            if scenarios:
                every_recall = all((row.get("recall") or 0) >= 0.8 for row in scenarios)
            elif inj.get("value") is not None:
                every_recall = inj.get("value") >= 0.8
            high = (
                _ci_lower(adj) is not None and _ci_lower(adj) >= 0.5 and
                every_recall and
                neg.get("fpr_bound_wilson95_upper") is not None and neg.get("fpr_bound_wilson95_upper") <= 0.01 and
                temp.get("verdict") == "stable" and
                (rule.get("kappa") is not None and rule.get("kappa") >= 0.4)
            )
            outcome = "alta" if high else "média"
            if not high:
                reasons.append("critérios de alta confiança incompletos")
    if reviewer_reliability == "low" and outcome == "alta":
        outcome = "média"
        reasons.append("concordância baixa entre revisores")
    elif reviewer_reliability == "low":
        reasons.append("concordância baixa entre revisores")
    return outcome, reasons


def _chip(status):
    label = {"measured": "Medido", "estimated": "Estimado", "bounded": "Limite", "skipped": "Pulado", "not_run": "Não executado", "deferred": "Adiado", "not_applicable": "Não aplicável"}.get(status, status or "n/a")
    return "<span class=\"vpnbt-chip vpnbt-chip--{0}\">{1}</span>".format(e(status or "unknown"), e(label))


def _status_for(rule, key, default="measured"):
    return (rule.get("status_tags") or {}).get(key, default)


def _metric_row(name, value, status, assumptions=None):
    detail = ""
    if assumptions:
        detail = "<details class=\"vpnbt-details\"><summary>Premissas</summary><ul>{0}</ul></details>".format("".join("<li>{0}</li>".format(e(a)) for a in assumptions))
    return "<tr><th>{0}</th><td>{1}</td><td>{2}{3}</td></tr>".format(e(name), e(value), _chip(status), detail)


def _rule_card(rid, rule):
    title, desc = RULE_TITLES[rid]
    skipped = rule.get("status") == "skipped"
    cls = "vpnbt-card vpnbt-card--muted" if skipped else "vpnbt-card"
    if skipped:
        verdict_text = "indefinida"
        reasons = ["R5 não configurada: detecção via MTA_AUT_CLI_TRAN desligada"]
        next_step = "Ativar a detecção via MTA (padrão ligado) removendo --no-mta-physical."
    else:
        verdict_text, reasons = verdict(rule)
        next_step = "Revisar casos convergentes e amostras de maior extremidade."
    return (
        "<article class=\"{cls}\"><h3>{rid} — {title}</h3><p>{desc}</p>"
        "<p><strong>Alertas:</strong> {flagged} ({rate})</p>"
        "<p><strong>Confiança:</strong> <span class=\"vpnbt-verdict vpnbt-verdict--{verdict}\">{verdict}</span></p>"
        "<ul class=\"vpnbt-reasons\">{reasons}</ul><p><strong>Próximo passo:</strong> {next}</p></article>"
    ).format(cls=cls, rid=e(rid), title=e(title), desc=e(desc), flagged=e(rule.get("flagged", 0)), rate=e(pct(rule.get("alert_rate"))), verdict=e(verdict_text), reasons="".join("<li>{0}</li>".format(e(r)) for r in reasons), next=e(next_step))


def _rule_table(rid, rule):
    rows = []
    rows.append(_metric_row("Flagged", rule.get("flagged"), _status_for(rule, "flagged")))
    rows.append(_metric_row("Alert rate", pct(rule.get("alert_rate")), _status_for(rule, "alert_rate")))
    pe = rule.get("percentile_extremity") or {}
    rows.append(_metric_row("Percentil mediano/mínimo", "{0} / {1}".format(pct(pe.get("median")), pct(pe.get("min"))), _status_for(rule, "percentile_extremity.median")))
    for pc in rule.get("precision_ceiling") or []:
        rows.append(_metric_row("Teto de precisão π={0}".format(pc.get("pi")), pct(pc.get("ceiling")), "bounded", pc.get("assumptions")))
    pa = rule.get("proxy_agreement") or {}
    if pa:
        rows.append(_metric_row("Acordo proxy — precisão surrogate", pct((pa.get("agreement_precision_surrogate") or {}).get("value")), pa.get("status", "estimated"), pa.get("assumptions")))
        rows.append(_metric_row("Acordo proxy — recall surrogate", pct((pa.get("agreement_recall_surrogate") or {}).get("value")), pa.get("status", "estimated"), pa.get("assumptions")))
        rows.append(_metric_row("Proxies admissíveis", ", ".join(pa.get("admissible_proxies") or []), pa.get("status", "estimated")))
    inj = rule.get("injected_recall") or {"status": "not_run"}
    rows.append(_metric_row("Injected recall", "não executado nesta rodada" if inj.get("status") == "not_run" else pct(inj.get("value")), inj.get("status", "not_run")))
    adj = rule.get("adjudicated_precision") or {"status": "not_run"}
    rows.append(_metric_row("Adjudicated precision", "não executado nesta rodada" if adj.get("status") == "not_run" else pct(adj.get("value")), adj.get("status", "not_run")))
    nc = rule.get("negative_control") or {}
    rows.append(_metric_row("Controle negativo — FPR Wilson upper", pct(nc.get("fpr_bound_wilson95_upper")), nc.get("status", "bounded"), nc.get("assumptions")))
    rows.append(_metric_row("true FP/FN", rule.get("true_rates", "not_available_without_validated_labels"), "not_available_without_validated_labels"))
    return "<div class=\"vpnbt-scroll\"><table class=\"vpnbt-table\"><tbody>{0}</tbody></table></div>".format("".join(rows))


def _rule_charts(rid, rule):
    sweep = [(row.get("threshold"), row.get("flagged")) for row in (rule.get("threshold_sweep") or [])]
    suggested = rule.get("suggested_threshold") or {}
    marks = []
    if suggested.get("threshold") is not None:
        marks.append({"x": suggested.get("threshold"), "label": "cotovelo"})
    if sweep:
        cap = "Sweep de limiar" + (" — sem cotovelo claro; limiar arbitrário" if "sem cotovelo" in str(suggested.get("note")) else "")
        sweep_html = svgchart.line_chart(sweep, x_label="limiar", y_label="flagged", marks=marks, caption=cap, aria_label="Quantidade de alertas por limiar para {0}".format(rid))
    else:
        sweep_html = "<p class=\"vpnbt-muted\">Sweep não executado nesta rodada.</p>"
    ts = rule.get("temporal_stability") or {}
    buckets = [(row.get("bucket"), row.get("flagged")) for row in ts.get("buckets") or []]
    if buckets:
        temp_html = svgchart.bar_chart(buckets, x_label="bucket", y_label="flagged", caption="Estabilidade temporal CV={0} ({1})".format(num(ts.get("cv")), ts.get("verdict")), aria_label="Série temporal de alertas para {0}".format(rid))
    else:
        temp_html = "<p class=\"vpnbt-muted\">Estabilidade temporal {0}: {1}</p>".format(e(ts.get("status", "não disponível")), e(ts.get("note", "")))
    return sweep_html + temp_html


def _rule_panel(rid, rule):
    return "<section class=\"vpnbt-panel\" data-vpnbt-panel=\"{0}\"><h3>{0}</h3>{1}{2}</section>".format(e(rid), _rule_table(rid, rule), _rule_charts(rid, rule))


def _cross_panel(bundle):
    cross = bundle.get("cross_rule") or {}
    matrix = cross.get("overlap_matrix") or []
    rows = []
    if matrix:
        headers = ["rule"] + [k for k in matrix[0].keys() if k != "rule"]
        rows.append("<thead><tr>{0}</tr></thead><tbody>".format("".join("<th>{0}</th>".format(e(h)) for h in headers)))
        for row in matrix:
            rows.append("<tr>{0}</tr>".format("".join("<td>{0}</td>".format(e(row.get(h))) for h in headers)))
        rows.append("</tbody>")
    lp = cross.get("lincoln_petersen") or {}
    convergent = cross.get("convergent_users") or []
    conv_html = "<details class=\"vpnbt-details\"><summary>Usuários convergentes ({0})</summary><ul>{1}</ul></details>".format(e(cross.get("convergent_total", len(convergent))), "".join("<li>{0}: {1}</li>".format(e(row.get("user")), e(",".join(row.get("rules") or []))) for row in convergent[:100]))
    return (
        "<section class=\"vpnbt-panel\" data-vpnbt-panel=\"TRANS\"><h3>Transversal</h3>"
        "<div class=\"vpnbt-scroll\"><table class=\"vpnbt-table\">{matrix}</table></div>"
        "<p>Lincoln-Petersen: N={n}, recall da união={recall}. Premissa: famílias independentes.</p>{conv}"
        "<p class=\"vpnbt-muted\">Benign-twin, adjudicação e parity: não executados nesta rodada quando ausentes do bundle.</p></section>"
    ).format(matrix="".join(rows), n=e(num(lp.get("population_estimate"))), recall=e(pct(lp.get("union_recall_estimate"))), conv=conv_html)


def _parameters_table(params):
    rows = []
    for key in sorted(params.keys()):
        rows.append("<tr><th>{0}</th><td>{1}</td></tr>".format(e(key), e(params[key])))
    return "<table class=\"vpnbt-table\"><tbody>{0}</tbody></table>".format("".join(rows))


def _json_island(bundle):
    text = json.dumps(sanitize_for_html(bundle), ensure_ascii=False, sort_keys=True, default=str)
    text = text.replace("</", "<\\/").replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    return "<script type=\"application/json\" class=\"vpnbt-data\">{0}</script>".format(text)


def render_fragment(bundle, stamp, title="Relatorio Backtest VPN"):
    safe_bundle = sanitize_for_html(bundle)
    params = safe_bundle.get("parameters") or {}
    rules = safe_bundle.get("rules") or {}
    total_alerts = sum((rule.get("flagged") or 0) for rule in rules.values())
    period = "{0} a {1}".format(params.get("start", "?"), params.get("end", "?"))
    root_attrs = "class=\"vpnbt-root\" id=\"vpnbt-{0}\" data-generated-at=\"{1}\" data-period=\"{2}\" data-methodology-version=\"{3}\" data-bundle-stamp=\"{0}\"".format(e(stamp), e(safe_bundle.get("generated_at")), e(period), e(safe_bundle.get("methodology_version")))
    css = """
<style class="vpnbt-style">
.vpnbt-root{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;font-size:16px;line-height:1.45;color:#1f2933;background:#fff;box-sizing:border-box;padding:1rem}.vpnbt-root .vpnbt-card,.vpnbt-root .vpnbt-tile,.vpnbt-root .vpnbt-disclaimer{box-sizing:border-box}.vpnbt-header{border-bottom:2px solid #0072B2;margin-bottom:1rem}.vpnbt-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:1rem}.vpnbt-card,.vpnbt-tile,.vpnbt-disclaimer{border:1px solid #cbd5e1;border-radius:.6rem;padding:1rem;background:#f8fafc}.vpnbt-card--muted,.vpnbt-muted{opacity:.72;color:#52616b}.vpnbt-disclaimer{border-color:#D55E00;background:#fff7ed}.vpnbt-chip{display:inline-block;border-radius:999px;padding:.15rem .5rem;margin:.1rem;font-size:.85em}.vpnbt-chip--measured{background:#0072B2;color:#fff}.vpnbt-chip--estimated{border:1px solid #0072B2;color:#0072B2}.vpnbt-chip--bounded{border:1px dashed #D55E00;color:#D55E00}.vpnbt-chip--skipped,.vpnbt-chip--not_run,.vpnbt-chip--deferred{background:#e5e7eb;color:#374151}.vpnbt-verdict{font-weight:700}.vpnbt-verdict--alta{color:#009E73}.vpnbt-verdict--média{color:#E69F00}.vpnbt-verdict--baixa{color:#D55E00}.vpnbt-verdict--indefinida{color:#52616b}.vpnbt-scroll{overflow-x:auto}.vpnbt-table{border-collapse:collapse;width:100%;margin:.5rem 0}.vpnbt-table th,.vpnbt-table td{border:1px solid #d9e2ec;padding:.35rem;text-align:left;vertical-align:top}.vpnbt-tabs{display:flex;flex-wrap:wrap;gap:.35rem;margin:1rem 0}.vpnbt-tab{border:1px solid #0072B2;background:#fff;color:#0072B2;border-radius:.4rem;padding:.35rem .7rem;cursor:pointer}.vpnbt-tab--active{background:#0072B2;color:#fff}.vpnbt-panel{border-top:1px solid #d9e2ec;padding-top:1rem;margin-top:1rem}.vpnbt-figure{margin:1rem 0}.vpnbt-svg{max-width:100%;height:auto}.vpnbt-svg-axis{stroke:#52616b;stroke-width:1}.vpnbt-svg-line{fill:none;stroke:#0072B2;stroke-width:2}.vpnbt-svg-bar{fill:#0072B2}.vpnbt-svg-mark{stroke:#E69F00;stroke-width:2;stroke-dasharray:4 3}.vpnbt-svg-label{font-size:12px;fill:#243b53}.vpnbt-footer{border-top:1px solid #cbd5e1;margin-top:1rem;padding-top:1rem}.vpnbt-details{margin:.3rem 0}@media print{.vpnbt-root{color:#000;background:#fff}.vpnbt-tabs,.vpnbt-tab{display:none}.vpnbt-panel{display:block!important}.vpnbt-card,.vpnbt-tile{break-inside:avoid}}
</style>"""
    script = """
<script class="vpnbt-script">(function(){var root=document.currentScript.closest('.vpnbt-root');if(!root){return;}var tabs=root.querySelectorAll('.vpnbt-tab');var panels=root.querySelectorAll('.vpnbt-panel');function show(name){panels.forEach(function(p){p.style.display=(p.getAttribute('data-vpnbt-panel')===name)?'block':'none';});tabs.forEach(function(t){if(t.getAttribute('data-vpnbt-tab')===name){t.classList.add('vpnbt-tab--active');}else{t.classList.remove('vpnbt-tab--active');}});}tabs.forEach(function(t){t.addEventListener('click',function(){show(t.getAttribute('data-vpnbt-tab'));});});if(tabs.length){show(tabs[0].getAttribute('data-vpnbt-tab'));}}());</script>"""
    header = "<header class=\"vpnbt-header\"><h1>{0}</h1><p>Período: {1}. Gerado em: {2}. Metodologia: {3}.</p><p>{4}{5}{6}</p></header>".format(e(title), e(period), e(safe_bundle.get("generated_at")), e(safe_bundle.get("methodology_version")), _chip("measured"), _chip("estimated"), _chip("bounded"))
    tiles = "<div class=\"vpnbt-grid\"><div class=\"vpnbt-tile\"><strong>Total de logins analisados</strong><br>{0}</div><div class=\"vpnbt-tile\"><strong>Total de usuários</strong><br>{1}</div><div class=\"vpnbt-tile\"><strong>Total de alertas no período</strong><br>{2}</div></div>".format(e((safe_bundle.get("summary") or {}).get("metrics", {}).get("total_events_analyzed")), e((safe_bundle.get("summary") or {}).get("metrics", {}).get("total_users_analyzed")), e(total_alerts))
    cards = "<div class=\"vpnbt-grid\">{0}</div>".format("".join(_rule_card(rid, rules.get(rid, {})) for rid in ("R1", "R2", "R3", "R4", "R5", "R6")))
    disclaimer = "<div class=\"vpnbt-disclaimer\"><strong>Limitação obrigatória:</strong> Não existem registros confirmados de fraude neste período; os números desta página são medições diretas, estimativas por amostragem/simulação e limites sob premissas declaradas — as taxas verdadeiras de falso positivo/negativo permanecem indisponíveis (not_available_without_validated_labels).</div>"
    conv = (safe_bundle.get("cross_rule") or {}).get("convergent_total", 0)
    executive = "<section class=\"vpnbt-section\"><h2>Resumo executivo</h2>{0}{1}<div class=\"vpnbt-card\"><strong>Casos convergentes:</strong> {2} usuários com pelo menos duas famílias de regra.</div>{3}</section>".format(tiles, cards, e(conv), disclaimer)
    tabs = ["R1", "R2", "R3", "R4", "R5", "R6", "TRANS"]
    tab_html = "<nav class=\"vpnbt-tabs\">{0}</nav>".format("".join("<button type=\"button\" class=\"vpnbt-tab\" data-vpnbt-tab=\"{0}\">{0}</button>".format(e(t)) for t in tabs))
    panels = "".join(_rule_panel(rid, rules.get(rid, {})) for rid in ("R1", "R2", "R3", "R4", "R5", "R6")) + _cross_panel(safe_bundle)
    technical = "<section class=\"vpnbt-section\"><h2>Painel técnico</h2>{0}{1}</section>".format(tab_html, panels)
    methodology = "<section class=\"vpnbt-section\"><h2>Metodologia e premissas</h2><p>A camada label-free mede carga de alertas, extremidade, estabilidade, sobreposição e limites por controle negativo. Proxies são evidências surrogate; não substituem rótulos reais. As fases B e C aparecem como não executadas nesta rodada quando ausentes.</p><ul>{0}</ul><p>Roadmap: shadow mode, loop com SOC, adjudicação persistida e reexecução com rótulos reais. Referência: docs/vpn_backtest_without_ground_truth.tex.</p></section>".format("".join("<li>{0}</li>".format(e(x)) for x in safe_bundle.get("limitations", [])))
    footer = "<footer class=\"vpnbt-footer\"><h2>Reprodutibilidade</h2>{0}<p>Git commit: {1}. Seed: {2}. Bundle stamp: {3}.</p></footer>".format(_parameters_table(params), e(safe_bundle.get("git_commit")), e(params.get("seed")), e(stamp))
    return "<div {attrs}>{css}{data}{header}{executive}{technical}{methodology}{footer}{script}</div>".format(attrs=root_attrs, css=css, data=_json_island(safe_bundle), header=header, executive=executive, technical=technical, methodology=methodology, footer=footer, script=script)


def render_standalone(bundle, stamp, title="Relatorio Backtest VPN"):
    frag = render_fragment(bundle, stamp, title=title)
    return "<!doctype html><html lang=\"pt-BR\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{0}</title></head><body>{1}</body></html>".format(e(title), frag)


def _stamp_from_bundle_path(path):
    name = Path(path).name
    m = re.search(r"(\d{8}_\d{6})", name)
    return m.group(1) if m else "bundle"


def write_readme(out_dir):
    text = """# Integração do relatório HTML VPN

Opções de inclusão:

1. **Iframe do arquivo standalone** (`relatorio_backtest_vpn_*.htm`) — recomendado e de menor risco.
2. **Include server-side do fragmento** (`*.fragment.htm`) dentro da página hospedeira.
3. **Renderizar o fragmento como template/string** no aplicativo hospedeiro.

A página não faz requisições externas. Para estilo inline, a CSP do host precisa permitir `style-src 'unsafe-inline'`; sem `script-src 'unsafe-inline'`, o conteúdo degrada graciosamente e permanece visível em layout empilhado. Cada execução gera um arquivo imutável com carimbo; o host pode montar o diretório e apontar para o mais recente. Identificadores de usuário estão pseudonimizados; mapear de volta exige autorização e o mapa reverso local, quando gerado.
"""
    path = Path(out_dir) / "README.md"
    path.write_text(text, encoding="utf-8")
    return path


def write_html_report(bundle_path, out_dir="reports/html", standalone=True, fragment=True, title="Relatorio Backtest VPN"):
    bundle_path = Path(bundle_path)
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    stamp = _stamp_from_bundle_path(bundle_path)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths = {}
    if fragment:
        fragment_html = render_fragment(bundle, stamp, title=title)
        fragment_path = out / "relatorio_backtest_vpn_{0}.fragment.htm".format(stamp)
        fragment_path.write_text(fragment_html, encoding="utf-8")
        if fragment_path.stat().st_size > MAX_ARTIFACT_BYTES:
            raise ValueError("Fragmento HTML excede 3 MB")
        paths["fragment"] = fragment_path
    if standalone:
        standalone_html = render_standalone(bundle, stamp, title=title)
        standalone_path = out / "relatorio_backtest_vpn_{0}.htm".format(stamp)
        standalone_path.write_text(standalone_html, encoding="utf-8")
        if standalone_path.stat().st_size > MAX_ARTIFACT_BYTES:
            raise ValueError("Standalone HTML excede 3 MB")
        paths["standalone"] = standalone_path
    paths["readme"] = write_readme(out)
    return paths
