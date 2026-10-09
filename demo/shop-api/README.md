# shop-api

Storefront backend: orders, saved carts, merchant themes and transactional
mail. Deliberately small — it exists as the source repository behind the
`/demo/api` namespace in the Magnolia demo, so CVE-reachability analysis has
real code to look at.

| Path | What it does |
|---|---|
| `src/server.js` | Express app, route wiring |
| `src/mail/render.js` | Renders merchant-editable mail templates |
| `src/routes/carts.js` | Saved carts: compare, merge tag lists |
| `src/themes/compile.js` | Compiles merchant-uploaded theme CSS |
| `src/ids.js` | Order and request ids |

Not meant to be deployed.
