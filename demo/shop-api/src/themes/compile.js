const postcss = require('postcss');

// Strip vendor hacks merchants copy from old themes.
const dropIeHacks = postcss.plugin('drop-ie-hacks', () => (root) => {
  root.walkDecls(/^\*/, (decl) => decl.remove());
});

async function compileTheme(css) {
  const result = await postcss([dropIeHacks]).process(css, { map: { inline: false } });
  return result.css;
}

module.exports = { compileTheme };
