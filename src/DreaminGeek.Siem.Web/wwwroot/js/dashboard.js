// Dashboards: the drag-and-resize grid (gridstack) and panel charts (ECharts), themed from CSS variables.
const grids = new Map();
const charts = new Map();
let world = null;

// ---------------------------------------------------------------- grid

export function initGrid(element, dotnet, editable) {
  if (!element || !window.GridStack) return;
  destroyGrid(element);
  const grid = window.GridStack.init({
    column: 12,
    cellHeight: 76,
    margin: 5,
    float: false,
    animate: false,
    staticGrid: !editable,
    handle: ".dg-tile-head",
    resizable: { handles: "se" },
    columnOpts: { breakpoints: [{ w: 760, c: 1 }] },
  }, element);
  grid.on("change", () => {
    // Only report the real 12-column layout (not the phone's 1-column view).
    if (grid.getColumn() !== 12 || grid.opts.staticGrid) return;
    const items = grid.save(false).map(i => ({ id: i.id, x: i.x ?? 0, y: i.y ?? 0, w: i.w ?? 1, h: i.h ?? 1 }));
    dotnet.invokeMethodAsync("OnLayoutChanged", items);
  });
  grids.set(element, grid);
}

/** Re-reads the tiles Blazor rendered (after panels are added or removed). */
export function syncGrid(element) {
  const grid = grids.get(element);
  if (!grid) return;
  grid.batchUpdate();
  grid.removeAll(false);
  element.querySelectorAll(":scope > .grid-stack-item").forEach(item => grid.makeWidget(item));
  grid.batchUpdate(false);
}

export function setEditable(element, editable) {
  grids.get(element)?.setStatic(!editable);
}

export function destroyGrid(element) {
  const grid = grids.get(element);
  if (grid) {
    grid.destroy(false);
    grids.delete(element);
  }
}

// ---------------------------------------------------------------- formatting

export function format(v, unit) {
  if (v === null || v === undefined || Number.isNaN(v)) return "—";
  switch (unit) {
    case "Duration":
      return v >= 1e9 ? `${+(v / 1e9).toFixed(2)} s` : v >= 1e6 ? `${+(v / 1e6).toFixed(1)} ms` : `${+(v / 1e3).toFixed(1)} µs`;
    case "Bytes":
      return v >= 2 ** 30 ? `${+(v / 2 ** 30).toFixed(1)} GB` : v >= 2 ** 20 ? `${+(v / 2 ** 20).toFixed(1)} MB` : v >= 1024 ? `${+(v / 1024).toFixed(1)} KB` : `${Math.round(v)} B`;
    case "Percent":
      return `${+v.toFixed(1)}%`;
    default:
      return Math.abs(v) >= 1e6 ? `${+(v / 1e6).toFixed(2)}M` : Math.abs(v) >= 1e4 ? `${+(v / 1e3).toFixed(1)}k` : Number.isInteger(v) ? v.toLocaleString("en-US") : `${+v.toFixed(2)}`;
  }
}

// ---------------------------------------------------------------- charts

function theme() {
  const css = getComputedStyle(document.documentElement);
  const v = name => css.getPropertyValue(name).trim();
  return { amber: v("--dg-amber"), text: v("--dg-text"), muted: v("--dg-muted"), rule: v("--dg-rule"), panel: v("--dg-slate"), ink: v("--dg-ink") };
}

const palette = t => [t.amber, "#5aa9d6", "#4cb782", "#b48ce0", "#e8913a", "#7f8ea1", "#d6c35a", "#e25c8a", "#6fc3c0", "#c98d6b"];

function base(t) {
  return {
    animation: false,
    color: palette(t),
    textStyle: { fontFamily: "Plex Sans, system-ui, sans-serif", color: t.muted, fontSize: 11 },
    tooltip: { backgroundColor: t.panel, borderColor: t.rule, textStyle: { color: t.text, fontSize: 12 }, confine: true },
  };
}

function timeOptions(spec, unit, t) {
  const multi = spec.series.length > 1;
  const kind = spec.kind;
  return {
    ...base(t),
    grid: { left: 8, right: 12, top: multi ? 26 : 10, bottom: 4, containLabel: true },
    legend: multi ? { type: "scroll", top: 0, textStyle: { color: t.text, fontSize: 11 }, itemWidth: 10, itemHeight: 10, pageIconColor: t.amber, pageTextStyle: { color: t.muted } } : undefined,
    tooltip: { ...base(t).tooltip, trigger: "axis", valueFormatter: v => format(v, unit) },
    xAxis: { type: "time", axisLine: { lineStyle: { color: t.rule } }, axisLabel: { color: t.muted, hideOverlap: true }, splitLine: { show: false } },
    yAxis: { type: "value", axisLabel: { color: t.muted, formatter: v => format(v, unit) }, splitLine: { lineStyle: { color: t.rule } } },
    series: spec.series.map(s => ({
      name: s.name,
      type: kind === "bars" ? "bar" : "line",
      stack: kind === "area" || (kind === "bars" && spec.stacked) ? "total" : undefined,
      areaStyle: kind === "area" ? { opacity: 0.35 } : undefined,
      barMaxWidth: 16,
      showSymbol: false,
      lineStyle: { width: 1.5 },
      data: s.points,
    })),
  };
}

function hbarOptions(spec, unit, t) {
  const items = [...spec.items].reverse(); // largest at the top
  return {
    ...base(t),
    grid: { left: 8, right: 56, top: 6, bottom: 6, containLabel: true },
    tooltip: { ...base(t).tooltip, trigger: "item", valueFormatter: v => format(v, unit) },
    xAxis: { type: "value", show: false },
    yAxis: {
      type: "category", data: items.map(i => i.name), axisLine: { show: false }, axisTick: { show: false },
      axisLabel: { color: t.text, width: 170, overflow: "truncate", fontFamily: "Plex Mono, ui-monospace, monospace", fontSize: 11 },
    },
    series: [{
      type: "bar", data: items.map(i => i.value), barMaxWidth: 14, itemStyle: { color: t.amber, borderRadius: [0, 2, 2, 0] },
      label: { show: true, position: "right", color: t.muted, formatter: p => format(p.value, unit) },
    }],
  };
}

function pieOptions(spec, unit, t) {
  return {
    ...base(t),
    tooltip: { ...base(t).tooltip, trigger: "item", formatter: p => `${p.marker}${p.name}<br><b>${format(p.value, unit)}</b> (${p.percent}%)` },
    legend: { type: "scroll", orient: "vertical", right: 0, top: "middle", textStyle: { color: t.text, fontSize: 11 }, itemWidth: 10, itemHeight: 10, pageIconColor: t.amber },
    series: [{
      type: "pie", radius: ["48%", "74%"], center: ["36%", "50%"], avoidLabelOverlap: true, label: { show: false },
      itemStyle: { borderColor: t.panel, borderWidth: 2 }, data: spec.items,
    }],
  };
}

async function loadWorld() {
  if (!world) {
    world = fetch("lib/world-map/world.geo.json").then(r => r.json()).then(geo => {
      window.echarts.registerMap("world", geo);
      return Object.fromEntries(geo.features.map(f => [f.properties.name, f.properties.label]));
    });
  }
  return world;
}

function mapOptions(spec, unit, t, labels) {
  return {
    ...base(t),
    tooltip: {
      ...base(t).tooltip, trigger: "item",
      formatter: p => `${labels[p.name] ?? p.name}<br><b>${Number.isFinite(p.value) ? format(p.value, unit) : "none"}</b>`,
    },
    visualMap: {
      min: 0, max: Math.max(1, spec.max), calculable: false, orient: "horizontal", left: 8, bottom: 4, itemWidth: 10, itemHeight: 90,
      text: [format(spec.max, unit), "0"], textStyle: { color: t.muted, fontSize: 10 },
      inRange: { color: [t.rule, t.amber] },
    },
    series: [{
      type: "map", map: "world", roam: false, left: 4, right: 4, top: 4, bottom: 22,
      itemStyle: { areaColor: t.ink || t.panel, borderColor: t.rule, borderWidth: 0.5 },
      emphasis: { label: { show: false }, itemStyle: { areaColor: t.text } },
      select: { disabled: true },
      data: spec.items,
    }],
  };
}

function sparkOptions(spec, t) {
  return {
    animation: false,
    grid: { left: 0, right: 0, top: 2, bottom: 0 },
    xAxis: { type: "time", show: false },
    yAxis: { type: "value", show: false, min: 0 },
    series: [{ type: "line", data: spec.points, showSymbol: false, lineStyle: { width: 1.25, color: t.amber }, areaStyle: { color: t.amber, opacity: 0.18 } }],
  };
}

async function optionsFor(spec, unit) {
  const t = theme();
  switch (spec.kind) {
    case "hbar": return hbarOptions(spec, unit, t);
    case "pie": return pieOptions(spec, unit, t);
    case "map": return mapOptions(spec, unit, t, await loadWorld());
    case "spark": return sparkOptions(spec, t);
    default: return timeOptions(spec, unit, t);
  }
}

export async function renderPanel(element, spec, unit) {
  if (!element || !window.echarts || !spec) return;
  let entry = charts.get(element);
  if (!entry) {
    const chart = window.echarts.init(element, null, { renderer: "canvas" });
    const observer = new ResizeObserver(() => chart.resize());
    observer.observe(element);
    entry = { chart, observer };
    entry.onTheme = async () => chart.setOption(await optionsFor(entry.spec, entry.unit), true);
    window.addEventListener("dg-theme", entry.onTheme);
    charts.set(element, entry);
  }
  entry.spec = spec;
  entry.unit = unit;
  entry.chart.setOption(await optionsFor(spec, unit), true);
}

export function disposePanel(element) {
  const entry = charts.get(element);
  if (entry) {
    window.removeEventListener("dg-theme", entry.onTheme);
    entry.observer.disconnect();
    entry.chart.dispose();
    charts.delete(element);
  }
}
