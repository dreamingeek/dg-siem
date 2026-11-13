// ECharts rendering for DG SIEM, themed from the page's CSS variables.
// render(element, { series: [{ name, points: [[epochMs, value], ...] }], stacked: bool })
const charts = new Map();

function theme() {
  const css = getComputedStyle(document.documentElement);
  const v = name => css.getPropertyValue(name).trim();
  return { amber: v("--dg-amber"), text: v("--dg-text"), muted: v("--dg-muted"), rule: v("--dg-rule"), panel: v("--dg-slate") };
}

// Amber first, then calm, distinguishable hues for further series.
function palette(t) {
  return [t.amber, "#5aa9d6", "#4cb782", "#b48ce0", "#e8913a", "#7f8ea1", "#d6c35a", "#e25c8a"];
}

function options(data) {
  const t = theme();
  const bars = data.stacked || data.series.length === 1;
  return {
    animation: false,
    color: palette(t),
    textStyle: { fontFamily: "Plex Sans, system-ui, sans-serif", color: t.muted },
    grid: { left: 44, right: 12, top: data.series.length > 1 ? 28 : 10, bottom: data.zoom ? 40 : 22 },
    legend: data.series.length > 1 ? { type: "scroll", top: 0, textStyle: { color: t.text }, itemWidth: 10, itemHeight: 10 } : undefined,
    tooltip: { trigger: "axis", backgroundColor: t.panel, borderColor: t.rule, textStyle: { color: t.text } },
    xAxis: { type: "time", axisLine: { lineStyle: { color: t.rule } }, axisLabel: { color: t.muted }, splitLine: { show: false } },
    yAxis: { type: "value", axisLabel: { color: t.muted }, splitLine: { lineStyle: { color: t.rule } } },
    dataZoom: data.zoom ? [{ type: "inside" }, { type: "slider", height: 14, bottom: 6, borderColor: t.rule, textStyle: { color: t.muted } }] : undefined,
    series: data.series.map(s => ({
      name: s.name,
      type: bars ? "bar" : "line",
      stack: data.stacked ? "total" : undefined,
      barMaxWidth: 18,
      showSymbol: false,
      data: s.points,
    })),
  };
}

export function render(element, data) {
  if (!element || !window.echarts) return;
  let entry = charts.get(element);
  if (!entry) {
    const chart = window.echarts.init(element, null, { renderer: "canvas" });
    const onTheme = () => chart.setOption(options(entry.data), true);
    window.addEventListener("dg-theme", onTheme);
    const observer = new ResizeObserver(() => chart.resize());
    observer.observe(element);
    entry = { chart, observer, onTheme, data };
    charts.set(element, entry);
  }
  entry.data = data;
  entry.chart.setOption(options(data), true);
}

export function dispose(element) {
  const entry = charts.get(element);
  if (entry) {
    window.removeEventListener("dg-theme", entry.onTheme);
    entry.observer.disconnect();
    entry.chart.dispose();
    charts.delete(element);
  }
}
