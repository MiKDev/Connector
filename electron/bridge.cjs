const { runBridge } = require('./mcp.cjs');
const directory = process.argv[2];
if (!directory) { process.stderr.write('Connector data directory required. Copy configuration from the desktop app.\n'); process.exit(1); }
runBridge(directory).catch(error => { process.stderr.write(error.message + '\n'); process.exitCode = 1; });
