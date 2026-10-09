// Way 1 of 3: a real, direct call to the vulnerable API on a request path.
// This is the occurrence an analyst must be shown first.
const fastyaml = require('fastyaml');

function importConfig(uploadedBytes) {
  // unsafeLoad instantiates arbitrary types named in the document.
  return fastyaml.unsafeLoad(uploadedBytes);
}

module.exports = { importConfig };
