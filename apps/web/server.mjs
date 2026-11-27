import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';

const page = await readFile(new URL('./index.html', import.meta.url));
const port = Number(process.env.PORT ?? 10000);

createServer((request, response) => {
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    response.writeHead(405, { Allow: 'GET, HEAD' }).end();
    return;
  }

  const path = request.url?.split('?')[0];
  if (path === '/healthz') {
    response.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    response.end(request.method === 'HEAD' ? undefined : 'ok\n');
    return;
  }

  if (path !== '/' && path !== '/index.html') {
    response.writeHead(404).end();
    return;
  }

  response.writeHead(200, {
    'Content-Type': 'text/html; charset=utf-8',
    'Content-Length': page.length,
    'X-Content-Type-Options': 'nosniff',
  });
  response.end(request.method === 'HEAD' ? undefined : page);
}).listen(port, '0.0.0.0', () => {
  console.log(`DeadLock UI listening on port ${port}`);
});
