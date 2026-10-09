const express = require('express');
const carts = require('./routes/carts');
const { renderMail } = require('./mail/render');
const { compileTheme } = require('./themes/compile');
const { newOrderId, requestId } = require('./ids');

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(express.text({ type: 'text/css', limit: '512kb' }));

app.use((req, res, next) => {
  res.set('x-request-id', requestId());
  next();
});

app.use('/carts', carts);

// Merchants preview their own order-confirmation mail before saving it.
app.post('/merchants/:id/mail/preview', (req, res) => {
  const { template, settings } = req.body;
  const html = renderMail(template, settings, {
    orderId: newOrderId(),
    customer: 'Ada Lovelace',
    total: '42.00 EUR',
  });
  res.type('html').send(html);
});

// Merchants upload a theme stylesheet; we normalise it and serve it back.
app.put('/merchants/:id/theme', async (req, res, next) => {
  try {
    res.type('css').send(await compileTheme(req.body));
  } catch (err) {
    next(err);
  }
});

if (require.main === module) {
  app.listen(process.env.PORT || 8080);
}

module.exports = app;
