import { loadInferenceConfig } from './config.js';
import { createInferenceServer } from './server.js';

const config = loadInferenceConfig();
const server = await createInferenceServer(config);

server.listen(config.port, config.host, () => {
  process.stdout.write(JSON.stringify({ event: 'inference_listening', host: config.host, port: config.port }) + '\n');
});

for (const signal of ['SIGTERM', 'SIGINT'] as const) {
  process.once(signal, () => {
    server.close((error) => {
      process.exitCode = error === undefined ? 0 : 1;
    });
  });
}
