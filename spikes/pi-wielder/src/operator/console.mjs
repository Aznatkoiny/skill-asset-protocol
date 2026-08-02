import fs from 'node:fs';

import { Hono } from 'hono';

const ASSETS = Object.freeze({
  '/operator/': Object.freeze({
    body: fs.readFileSync(new URL('../../operator-console/index.html', import.meta.url), 'utf8'),
    contentType: 'text/html; charset=UTF-8',
  }),
  '/operator/app.mjs': Object.freeze({
    body: fs.readFileSync(new URL('../../operator-console/app.mjs', import.meta.url), 'utf8'),
    contentType: 'text/javascript; charset=UTF-8',
  }),
  '/operator/styles.css': Object.freeze({
    body: fs.readFileSync(new URL('../../operator-console/styles.css', import.meta.url), 'utf8'),
    contentType: 'text/css; charset=UTF-8',
  }),
});

const SECURITY_HEADERS = Object.freeze({
  'cache-control': 'no-store',
  'content-security-policy': "default-src 'self'; connect-src 'self'; frame-ancestors 'none'",
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin',
  'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=()',
  'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff',
});

function captureOperatorApp(options) {
  if (!options || typeof options !== 'object' || Array.isArray(options)
      || Object.getPrototypeOf(options) !== Object.prototype
      || Reflect.ownKeys(options).length !== 1) {
    throw new TypeError('Operator console requires exactly one operatorApp');
  }
  const descriptor = Object.getOwnPropertyDescriptor(options, 'operatorApp');
  if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
    throw new TypeError('Operator console requires one operatorApp data field');
  }
  const operatorApp = descriptor.value;
  if (!operatorApp || typeof operatorApp.fetch !== 'function'
      || !Array.isArray(operatorApp.routes)) {
    throw new TypeError('operatorApp must be a Hono application');
  }
  return operatorApp;
}

export function createOperatorConsoleApp(options) {
  const operatorApp = captureOperatorApp(options);
  const app = new Hono();

  app.use('*', async (context, next) => {
    await next();
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
      context.header(name, value);
    }
  });

  for (const [pathname, asset] of Object.entries(ASSETS)) {
    app.get(pathname, (context) => context.body(asset.body, 200, {
      'content-type': asset.contentType,
    }));
  }

  app.route('/', operatorApp);
  app.notFound((context) => context.json({ code: 'OPERATOR_ROUTE_NOT_FOUND' }, 404));
  return app;
}
