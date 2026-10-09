// In-memory stand-in for the real cart store.
const carts = new Map();

module.exports = {
  cart: (id) => carts.get(id) || { id, items: [] },
  setTags: (id, tags) => carts.set(id, { ...(carts.get(id) || { id, items: [] }), tags }),
};
