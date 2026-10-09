const { importConfig } = require('../src/importer');

// Test code exercises the vulnerable API by design, so this occurrence
// should rank below the production one.
test('importConfig parses a document', () => {
  expect(importConfig('a: 1')).toEqual({ a: 1 });
});
