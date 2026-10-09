const test = require('node:test');
const assert = require('node:assert');
const { newOrderId } = require('../src/ids');

test('order ids are prefixed', () => {
  assert.match(newOrderId(), /^ord_[0-9a-f-]{36}$/);
});
