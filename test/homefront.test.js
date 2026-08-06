'use strict';
// Fixture tests for the census parsers. The parsers are where the bugs live,
// so they are pure functions and testable on any platform -- including the
// Windows paths, which cannot be exercised on the build machine.
const assert = require('assert');
const H = require('../lib/homefront');

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); pass++; console.log('  ok   ' + name); }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + e.message); }
}

// Real `netstat -ano` output shape, including the header block Windows emits.
const NETSTAT = `
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1044
  TCP    127.0.0.1:5354         0.0.0.0:0              LISTENING       6432
  TCP    192.168.1.42:52341     140.82.114.3:443       ESTABLISHED     9120
  TCP    192.168.1.42:52999     13.107.42.14:443       ESTABLISHED     9120
  TCP    192.168.1.42:53001     162.159.61.3:443       ESTABLISHED     4404
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [fe80::1%12]:139       [::]:0                 LISTENING       4
  UDP    0.0.0.0:5353           *:*                                    3288
  UDP    127.0.0.1:1900         *:*                                    7712
`;

const TASKLIST = `
"System","4","Services","0","144 K"
"svchost.exe","1044","Services","0","12,004 K"
"chrome.exe","9120","Console","1","410,232 K"
"Discord.exe","4404","Console","1","198,120 K"
"mDNSResponder.exe","3288","Services","0","6,120 K"
`;

t('parseNetstat extracts every TCP and UDP row, skipping headers', () => {
  const rows = H.parseNetstat(NETSTAT);
  assert.strictEqual(rows.length, 9, `expected 9 rows, got ${rows.length}`);
});

t('parseNetstat reads TCP state and pid from the right columns', () => {
  const rows = H.parseNetstat(NETSTAT);
  const est = rows.find((r) => r.localPort === 52341);
  assert.strictEqual(est.state, 'ESTABLISHED');
  assert.strictEqual(est.pid, 9120);
  assert.strictEqual(est.remote, '140.82.114.3');
  assert.strictEqual(est.remotePort, 443);
});

t('parseNetstat handles UDP rows, which carry no state column', () => {
  const rows = H.parseNetstat(NETSTAT);
  const udp = rows.find((r) => r.proto === 'UDP' && r.localPort === 5353);
  assert.strictEqual(udp.state, null);
  assert.strictEqual(udp.pid, 3288, 'pid must not be read from the state slot');
});

t('splitAddr handles bracketed IPv6 without truncating the address', () => {
  assert.deepStrictEqual(H.splitAddr('[::1]:443'), { host: '::1', port: 443 });
  assert.deepStrictEqual(H.splitAddr('[fe80::1%12]:139'), { host: 'fe80::1%12', port: 139 });
  assert.deepStrictEqual(H.splitAddr('1.2.3.4:443'), { host: '1.2.3.4', port: 443 });
  assert.deepStrictEqual(H.splitAddr('*:*'), { host: '*', port: null });
});

t('parseTasklist maps pid to image name through quoted CSV', () => {
  const m = H.parseTasklist(TASKLIST);
  assert.strictEqual(m.get(9120), 'chrome.exe');
  assert.strictEqual(m.get(4404), 'Discord.exe');
  assert.strictEqual(m.size, 5);
});

t('parseTasklist survives the comma inside a quoted memory figure', () => {
  // "410,232 K" would break a naive split(',')
  const m = H.parseTasklist('"chrome.exe","9120","Console","1","410,232 K"');
  assert.strictEqual(m.get(9120), 'chrome.exe');
});

t('classifyListener separates reachable listeners from loopback', () => {
  assert.strictEqual(H.classifyListener({ local: '127.0.0.1' }).exposure, 'loopback');
  assert.strictEqual(H.classifyListener({ local: '0.0.0.0' }).exposure, 'all-interfaces');
  assert.strictEqual(H.classifyListener({ local: '192.168.1.42' }).exposure, 'lan');
  assert.strictEqual(H.classifyListener({ local: '203.0.113.9' }).exposure, 'public');
  assert.strictEqual(H.classifyListener({ local: '203.0.113.9' }).severity, 'warning');
});

t('isPrivate covers RFC1918, CGNAT-adjacent link-local and IPv6 ULA', () => {
  assert.ok(H.isPrivate('10.1.2.3'));
  assert.ok(H.isPrivate('172.16.0.1'));
  assert.ok(H.isPrivate('172.31.255.254'));
  assert.ok(!H.isPrivate('172.32.0.1'), '172.32 is public, outside the /12');
  assert.ok(H.isPrivate('192.168.0.1'));
  assert.ok(H.isPrivate('fe80::1'));
  assert.ok(!H.isPrivate('140.82.114.3'));
});

t('parseSs reads the Linux shape including users:(("name",pid=N', () => {
  const SS = `Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
tcp   ESTAB  0      0      10.0.0.5:44120      140.82.114.3:443  users:(("node",pid=812,fd=21))
tcp   LISTEN 0      511    0.0.0.0:4173        0.0.0.0:*         users:(("node",pid=812,fd=19))`;
  const rows = H.parseSs(SS);
  assert.strictEqual(rows.length, 2);
  assert.strictEqual(rows[0].state, 'ESTABLISHED', 'ESTAB must normalize to ESTABLISHED');
  assert.strictEqual(rows[0].process, 'node');
  assert.strictEqual(rows[0].pid, 812);
  assert.strictEqual(rows[1].state, 'LISTENING');
  assert.strictEqual(rows[1].localPort, 4173);
});

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
