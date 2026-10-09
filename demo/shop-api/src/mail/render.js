const ejs = require('ejs');

// Merchants edit their own mail templates in the dashboard and may pick
// their own delimiters, because some of them paste templates from other
// shop systems that use `{{ }}`-style tags.
function renderMail(template, settings = {}, data = {}) {
  return ejs.render(template, data, {
    openDelimiter: settings.openDelimiter || '<',
    closeDelimiter: settings.closeDelimiter || '>',
    rmWhitespace: true,
  });
}

module.exports = { renderMail };
