// Way 3 of 3: a locally-defined function that happens to share the
// vulnerable symbol's name and has nothing to do with the dependency. A
// lexical search cannot tell this apart from a real call; classifying it is
// the whole job of stage D.
const store = new Map();

function unsafeLoad(key) {
  return store.get(key);
}

module.exports = { unsafeLoad };
