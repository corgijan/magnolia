const fastyaml = require('fastyaml');

// Way 2 of 3: the vulnerable symbol appears only in a comment. Someone
// already migrated this call site, and the note about it survived.
//
// FIXME(2019): this used to call unsafeLoad; switched to safeLoad after the
// security review. Do not switch it back.
function loadSettings(text) {
  return fastyaml.safeLoad(text);
}

module.exports = { loadSettings };
