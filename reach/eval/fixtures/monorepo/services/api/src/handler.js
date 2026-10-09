const fastyaml = require('fastyaml');

function handle(body) {
  return fastyaml.unsafeLoad(body);
}

module.exports = { handle };
