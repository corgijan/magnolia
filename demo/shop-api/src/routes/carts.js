const express = require('express');
const _ = require('underscore');
const store = require('../store');

const router = express.Router();

// A client sends back the cart it last saw; we only write if nothing
// changed underneath it.
router.post('/:id/compare', (req, res) => {
  const seen = JSON.parse(req.body.snapshot);
  const current = store.cart(req.params.id);
  res.json({ unchanged: _.isEqual(seen, current) });
});

// Tag lists arrive nested from the mobile client (one array per screen).
router.post('/:id/tags', (req, res) => {
  const nested = JSON.parse(req.body.tags);
  const tags = _.uniq(_.flatten(nested));
  store.setTags(req.params.id, tags);
  res.json({ tags });
});

module.exports = router;
