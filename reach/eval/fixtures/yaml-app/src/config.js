// The occurrence that matters: a qualified call to a member whose bare name
// (`load`) is on stage B's generic-noise list. The advisory for this fixture
// names it only as `yaml.load`, which is how the real CVE-2017-18342 advisory
// names it too — so this file is the regression test for that whole class of
// advisory being dropped before any search ran.
const yaml = require('pyyamlish');

function readUserConfig(uploadedBytes) {
  return yaml.load(uploadedBytes);
}

module.exports = { readUserConfig };
