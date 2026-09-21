const status = document.querySelector('#status');
const details = document.querySelector('#details');
let worker;
let rejectRun;
let ticks = 0;
let lastTick = performance.now();
let maxGap = 0;
let active = false;
setInterval(() => {
  const now = performance.now();
  if (active) maxGap = Math.max(maxGap, now - lastTick);
  lastTick = now;
  document.querySelector('#pulse').textContent = `Page heartbeat: ${++ticks}`;
}, 100);

window.cancelExperiment = () => {
  if (!worker) return false;
  worker.terminate();
  worker = null;
  active = false;
  const error = new Error('Worker terminated by caller');
  rejectRun?.(error);
  rejectRun = null;
  return true;
};

window.runExperiment = async (options = {}) => {
  if (worker) throw new Error('An experiment is already running');
  const startTicks = ticks;
  maxGap = 0;
  active = true;
  const events = [];
  const runs = [];
  worker = new Worker('/worker.js', { type: 'module' });
  document.querySelector('#run').disabled = true;
  document.querySelector('#cancel').disabled = false;
  const started = performance.now();
  try {
    const result = await new Promise((resolve, reject) => {
      rejectRun = reject;
      worker.onerror = e => reject(new Error(e.message));
      worker.onmessage = ({ data }) => {
        events.push(data);
        window.lastExperimentEvent = data;
        console.log('MEMBERSHIP_EVENT ' + JSON.stringify(data));
        status.textContent = data.phase || data.type;
        details.textContent = JSON.stringify(data, null, 2);
        if (data.type === 'run') {
          runs.push(data);
          const tr = document.createElement('tr');
          for (const value of [data.run, `${(data.elapsed_ms / 1000).toFixed(2)} s`, `${(data.memory_after_bytes / 2**30).toFixed(3)} GiB`, String(data.matches_native)]) {
            const td = document.createElement('td'); td.textContent = value; tr.append(td);
          }
          document.querySelector('#rows').append(tr);
        }
        if (data.type === 'complete') resolve(data);
        if (data.type === 'failure') reject(Object.assign(new Error(data.message), { detail: data }));
      };
      worker.postMessage({ repeat: 3, ...options });
    });
    return { ...result, runs, events, page_heartbeat_ticks: ticks - startTicks, page_max_heartbeat_gap_ms: maxGap, page_elapsed_ms: performance.now() - started };
  } catch (e) {
    e.experiment = { runs, events, page_heartbeat_ticks: ticks - startTicks, page_max_heartbeat_gap_ms: maxGap, page_elapsed_ms: performance.now() - started };
    throw e;
  } finally {
    worker?.terminate(); worker = null; rejectRun = null; active = false;
    document.querySelector('#run').disabled = false;
    document.querySelector('#cancel').disabled = true;
  }
};
document.querySelector('#run').onclick = () => window.runExperiment().catch(e => { status.textContent = e.message; });
document.querySelector('#cancel').onclick = window.cancelExperiment;
