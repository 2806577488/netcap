// A client that starts a CONNECT tunnel and then walks away in various ways.
// It never completes the TLS handshake, which is exactly what a program that
// does not trust our CA does -- the shape of traffic that once killed the
// proxy mid-handshake.
const net = require('net');
const port = Number(process.argv[2] || 8114);
const rounds = Number(process.argv[3] || 40);
const modes = ['destroy', 'header', 'partial', 'end'];

function once(mode, cb) {
  const s = net.connect(port, '127.0.0.1', () => {
    s.write('CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n');
  });
  let first = false;
  s.on('data', () => {
    if (first) return;
    first = true;
    if (mode === 'destroy') { s.destroy(); return; }
    if (mode === 'header') { s.write(Buffer.from([0x16, 0x03, 0x01, 0x40, 0x00])); s.destroy(); return; }
    if (mode === 'partial') { s.write(Buffer.from([0x16, 0x03, 0x01, 0x00, 0x30, 0x01, 0x00, 0x00, 0x2c])); s.destroy(); return; }
    s.end();
  });
  s.on('error', () => {});
  s.on('close', cb);
}

let i = 0;
(function loop() {
  if (i >= rounds) { console.log('probe done, ' + rounds + ' aborted tunnels'); return; }
  const mode = modes[i % modes.length];
  i++;
  once(mode, () => setTimeout(loop, 25));
})();
