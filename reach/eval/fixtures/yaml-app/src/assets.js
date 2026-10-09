// Unrelated uses of the same bare name, which is exactly why `load` is on the
// generic-noise list at all. These should rank below, and read as, false
// matches — the qualified-form rescue must not turn the filter off wholesale.
function load(name) {
  return fetch(`/assets/${name}`);
}

async function warmUp(names) {
  // load every asset up front
  return Promise.all(names.map(load));
}

module.exports = { load, warmUp };
