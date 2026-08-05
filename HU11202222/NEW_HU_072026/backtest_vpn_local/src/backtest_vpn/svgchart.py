"""Helpers SVG pequenos e deterministas para o relatorio HTML."""

import html
import math


def _esc(value):
    return html.escape(str(value), quote=True)


def _points(series, width, height, pad):
    data = [(str(x), float(y or 0)) for x, y in series]
    if not data:
        return [], 0.0, 1.0
    ymax = max(y for _, y in data)
    ymin = min(y for _, y in data)
    if ymax == ymin:
        ymax = ymin + 1.0
    pts = []
    denom = max(1, len(data) - 1)
    for idx, (x, y) in enumerate(data):
        px = pad + (width - 2 * pad) * idx / denom
        py = height - pad - (height - 2 * pad) * ((y - ymin) / (ymax - ymin))
        pts.append((px, py, x, y))
    return pts, ymin, ymax


def _table(series):
    rows = ["<details class=\"vpnbt-chart-data\"><summary>Dados do grafico</summary><table class=\"vpnbt-table\"><thead><tr><th>X</th><th>Y</th></tr></thead><tbody>"]
    for x, y in series:
        rows.append("<tr><td>{0}</td><td>{1}</td></tr>".format(_esc(x), _esc(y)))
    rows.append("</tbody></table></details>")
    return "".join(rows)


def line_chart(series, *, width=560, height=240, x_label="x", y_label="y", marks=None, caption="", aria_label=""):
    marks = marks or []
    pts, ymin, ymax = _points(series, width, height, 36)
    path = " ".join(("M" if i == 0 else "L") + "{0:.1f},{1:.1f}".format(px, py) for i, (px, py, _, _) in enumerate(pts))
    mark_svg = []
    labels = [x for _, _, x, _ in pts]
    for mark in marks:
        mx = str(mark.get("x"))
        if mx in labels:
            idx = labels.index(mx)
            px = pts[idx][0]
            mark_svg.append("<line class=\"vpnbt-svg-mark\" x1=\"{0:.1f}\" y1=\"20\" x2=\"{0:.1f}\" y2=\"{1}\"></line>".format(px, height - 28))
            mark_svg.append("<text class=\"vpnbt-svg-label\" x=\"{0:.1f}\" y=\"18\">{1}</text>".format(px + 3, _esc(mark.get("label", "marco"))))
    svg = (
        "<figure class=\"vpnbt-figure\"><figcaption>{caption}</figcaption>"
        "<svg class=\"vpnbt-svg\" role=\"img\" aria-label=\"{aria}\" viewBox=\"0 0 {w} {h}\">"
        "<line class=\"vpnbt-svg-axis\" x1=\"36\" y1=\"{yb}\" x2=\"{xr}\" y2=\"{yb}\"></line>"
        "<line class=\"vpnbt-svg-axis\" x1=\"36\" y1=\"20\" x2=\"36\" y2=\"{yb}\"></line>"
        "<text class=\"vpnbt-svg-label\" x=\"{xmid}\" y=\"{hminus}\">{xl}</text>"
        "<text class=\"vpnbt-svg-label\" x=\"4\" y=\"18\">{yl}</text>"
        "<text class=\"vpnbt-svg-label\" x=\"38\" y=\"32\">{ymax}</text>"
        "<path class=\"vpnbt-svg-line\" d=\"{path}\"></path>{marks}</svg>{table}</figure>"
    ).format(
        caption=_esc(caption), aria=_esc(aria_label or caption), w=width, h=height,
        yb=height - 36, xr=width - 18, xmid=width / 2, hminus=height - 6,
        xl=_esc(x_label), yl=_esc(y_label), ymax=_esc(round(ymax, 3)), path=path,
        marks="".join(mark_svg), table=_table(series)
    )
    return svg


def bar_chart(series, *, width=560, height=240, x_label="x", y_label="y", caption="", aria_label=""):
    pts, ymin, ymax = _points(series, width, height, 36)
    bar_w = (width - 72) / max(1, len(pts)) * 0.7 if pts else 10
    bars = []
    for px, py, x, y in pts:
        h = max(1.0, height - 36 - py)
        bars.append("<rect class=\"vpnbt-svg-bar\" x=\"{0:.1f}\" y=\"{1:.1f}\" width=\"{2:.1f}\" height=\"{3:.1f}\"><title>{4}: {5}</title></rect>".format(px - bar_w / 2, py, bar_w, h, _esc(x), _esc(y)))
    return (
        "<figure class=\"vpnbt-figure\"><figcaption>{caption}</figcaption>"
        "<svg class=\"vpnbt-svg\" role=\"img\" aria-label=\"{aria}\" viewBox=\"0 0 {w} {h}\">"
        "<line class=\"vpnbt-svg-axis\" x1=\"36\" y1=\"{yb}\" x2=\"{xr}\" y2=\"{yb}\"></line>"
        "<line class=\"vpnbt-svg-axis\" x1=\"36\" y1=\"20\" x2=\"36\" y2=\"{yb}\"></line>"
        "<text class=\"vpnbt-svg-label\" x=\"{xmid}\" y=\"{hminus}\">{xl}</text>"
        "<text class=\"vpnbt-svg-label\" x=\"4\" y=\"18\">{yl}</text>{bars}</svg>{table}</figure>"
    ).format(caption=_esc(caption), aria=_esc(aria_label or caption), w=width, h=height, yb=height - 36, xr=width - 18, xmid=width / 2, hminus=height - 6, xl=_esc(x_label), yl=_esc(y_label), bars="".join(bars), table=_table(series))
