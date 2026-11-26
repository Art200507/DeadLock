#!/usr/bin/env node
// condlock lock | unlock | status | log — implemented in milestone 3 (local) and 6 (escrow).
const [cmd] = process.argv.slice(2);
const commands = ["lock", "unlock", "status", "log"] as const;
if (!cmd || !(commands as readonly string[]).includes(cmd)) {
  console.error(`usage: condlock <${commands.join("|")}>`);
  process.exit(2);
}
console.error(`condlock ${cmd}: not implemented yet`);
process.exit(1);
