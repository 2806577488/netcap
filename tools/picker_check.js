// Exercises the *real* element-picker script without a browser.
//
// The script is not copied here: it is extracted out of `src/picker.cpp` (the
// raw string between R"NCPICKER( and )NCPICKER"), so this test can never drift
// from what netcap actually injects.  A tiny DOM plus a small selector engine
// (tag, #id, .class, :nth-of-type, `>` chains) stands in for the page.
//
//   node tools/picker_check.js
//
// Exits non-zero when an assertion fails.
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');

let checks = 0;
let failures = 0;
function ok(cond, what) {
  checks++;
  if (cond) {
    console.log('  ok  ' + what);
  } else {
    failures++;
    console.log('  FAIL ' + what);
  }
}

// ---------------------------------------------------------------- the script
const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'picker.cpp'), 'utf8');
const start = src.indexOf('R"NCPICKER(');
const end = src.indexOf(')NCPICKER"');
if (start < 0 || end < 0) {
  console.log('FAIL could not find the picker script in src/picker.cpp');
  process.exit(1);
}
const script = src.slice(start + 'R"NCPICKER('.length, end);

// ------------------------------------------------------------------- the DOM
function makeEl(tag) {
  const el = {
    nodeType: 1,
    tagName: String(tag).toUpperCase(),
    id: '',
    className: '',
    _attrs: {},
    children: [],
    parentElement: null,
    parentNode: null,
    style: { cssText: '' },
    textContent: '',
    value: '',
    offsetWidth: 100,
    offsetHeight: 40,
    firstChild: null,
    onclick: null,
    oninput: null,
    onmousedown: null,
    setAttribute(k, v) {
      this._attrs[k] = String(v);
      if (k === 'id') this.id = String(v);
      if (k === 'class') this.className = String(v);
    },
    getAttribute(k) {
      return Object.prototype.hasOwnProperty.call(this._attrs, k) ? this._attrs[k] : null;
    },
    removeAttribute(k) {
      delete this._attrs[k];
    },
    appendChild(c) {
      this.children.push(c);
      c.parentElement = this;
      c.parentNode = this;
      this.firstChild = this.children[0];
      return c;
    },
    removeChild(c) {
      const i = this.children.indexOf(c);
      if (i >= 0) this.children.splice(i, 1);
      c.parentElement = null;
      c.parentNode = null;
      this.firstChild = this.children[0] || null;
      return c;
    },
    contains(n) {
      let cur = n;
      while (cur) {
        if (cur === this) return true;
        cur = cur.parentElement;
      }
      return false;
    },
  };
  return el;
}

function el(tag, opts) {
  const e = makeEl(tag);
  if (opts && opts.id) e.setAttribute('id', opts.id);
  if (opts && opts.cls) e.setAttribute('class', opts.cls);
  if (opts && opts.text) e.textContent = opts.text;
  if (opts && opts.w) e.offsetWidth = opts.w;
  if (opts && opts.h) e.offsetHeight = opts.h;
  return e;
}

function descend(root, out) {
  for (const c of root.children) {
    out.push(c);
    descend(c, out);
  }
  return out;
}

function matchSimple(node, part) {
  let rest = String(part).replace(/\\/g, '');
  const nth = /:nth-of-type\((\d+)\)/.exec(rest);
  if (nth) rest = rest.replace(nth[0], '');
  const idm = /#([A-Za-z0-9_-]+)/.exec(rest);
  if (idm) {
    if (node.id !== idm[1]) return false;
    rest = rest.replace(idm[0], '');
  }
  const classes = [];
  rest = rest.replace(/\.([A-Za-z0-9_-]+)/g, (m, c) => {
    classes.push(c);
    return '';
  });
  const tag = rest.trim();
  if (tag && node.tagName !== tag.toUpperCase()) return false;
  const have = String(node.className || '').split(/\s+/).filter(Boolean);
  for (const c of classes) if (have.indexOf(c) < 0) return false;
  if (nth) {
    const idx = Number(nth[1]);
    const sibs = (node.parentElement ? node.parentElement.children : [node]).filter(
      (s) => s.tagName === node.tagName
    );
    if (sibs.indexOf(node) + 1 !== idx) return false;
  }
  return true;
}

function matchesChain(node, parts) {
  let cur = node;
  for (let i = parts.length - 1; i >= 0; i--) {
    if (!cur || !matchSimple(cur, parts[i])) return false;
    if (i > 0) cur = cur.parentElement;
  }
  return true;
}

function queryAll(root, sel) {
  const text = String(sel);
  if (/[{};<]/.test(text)) throw new Error('bad selector: ' + text);
  const parts = text.split('>').map((s) => s.trim());
  if (parts.some((p) => p === '')) throw new Error('bad selector: ' + text);
  return descend(root, []).filter((n) => matchesChain(n, parts));
}

function findById(root, id) {
  return descend(root, []).find((n) => n.id === id) || null;
}
function countMarked(root) {
  return descend(root, []).filter((n) => n.getAttribute('data-nc-mark') !== null).length;
}

// ------------------------------------------------------------------ fixtures
const html = makeEl('html');
const head = el('head');
const body = el('body');
const main = el('div', { id: 'main', cls: 'container' });
const sidebar = el('div', { cls: 'sidebar' });
const adSlot = el('div', { cls: 'ad-slot' });
const adInner = el('div', { cls: 'ad-inner banner', w: 300, h: 250 });
const content = el('div', { id: 'content' });
const para = el('p', { cls: 'para', text: 'body text' });
const adWide = el('div', { cls: 'ad-slot ad-wide' });
const adLabel = el('span', { cls: 'ad-label', text: 'ad' });
html.appendChild(head);
html.appendChild(body);
body.appendChild(main);
main.appendChild(sidebar);
sidebar.appendChild(adSlot);
adSlot.appendChild(adInner);
main.appendChild(content);
content.appendChild(para);
content.appendChild(adWide);
adWide.appendChild(adLabel);

const listeners = {};
const documentStub = {
  documentElement: html,
  createElement: (tag) => makeEl(tag),
  addEventListener(type, fn) {
    (listeners[type] = listeners[type] || []).push(fn);
  },
  removeEventListener(type, fn) {
    const a = listeners[type] || [];
    const i = a.indexOf(fn);
    if (i >= 0) a.splice(i, 1);
  },
  querySelectorAll: (sel) => queryAll(html, sel),
  fire(type, ev) {
    for (const fn of (listeners[type] || []).slice()) fn(ev);
  },
  listenerCount(type) {
    return (listeners[type] || []).length;
  },
};

let lastXhr = null;
function XMLHttpRequestStub() {
  this.method = '';
  this.url = '';
  this.status = 0;
  this.responseText = '';
  this.onload = null;
  this.onerror = null;
}
XMLHttpRequestStub.prototype.open = function (method, url) {
  this.method = method;
  this.url = url;
};
XMLHttpRequestStub.prototype.send = function () {
  lastXhr = this;
  this.status = 200;
  this.responseText = '{"ok":true,"rule":"example.com##.ad-inner"}';
  if (this.onload) this.onload();
};

const windowStub = {};
const locationStub = { hostname: 'example.com', href: 'http://example.com/page' };
const sandbox = {
  window: windowStub,
  document: documentStub,
  location: locationStub,
  XMLHttpRequest: XMLHttpRequestStub,
  console,
  parseInt,
  Number,
  String,
  isNaN,
  encodeURIComponent,
  setTimeout,
};
vm.createContext(sandbox);

function ev(target) {
  return {
    target,
    clientX: 0,
    clientY: 0,
    preventDefault() {},
    stopPropagation() {},
  };
}

// ------------------------------------------------------------------ the checks
console.log('netcap element picker — script behaviour');
ok(script.indexOf('</script>') < 0, 'the injected script contains no </script> sequence');
ok(script.indexOf('nc-pick-panel') > 0, 'the script carries the picker panel markup');
ok(script.indexOf('nth-of-type') > 0, 'the selector generator can pin down siblings');
ok(script.indexOf('cursor:crosshair') > 0, 'the mouse turns into a crosshair while picking');

vm.runInContext(script, sandbox, { filename: 'picker.js' });

const bar = findById(html, 'nc-pick-bar');
ok(!!bar, 'entering picker mode adds the bottom bar');
ok(!!bar && bar.textContent.indexOf('元素选择器') >= 0, 'the bar explains the picker');
ok(!!bar && bar.textContent.indexOf('Esc') >= 0, 'the bar tells you how to leave');
ok(documentStub.listenerCount('click') === 1, 'the script listens for clicks');
ok(documentStub.listenerCount('mousemove') >= 1, 'the script listens for the mouse');

documentStub.fire('mousemove', ev(adInner));
ok(adInner.getAttribute('data-nc-hover') !== null, 'hovering outlines the element under the cursor');
ok(
  bar.textContent.indexOf('div 300×250') >= 0,
  'the bar shows the element and its size (got: ' + bar.textContent + ')'
);

documentStub.fire('click', ev(adInner));
let panel = findById(html, 'nc-pick-panel');
ok(!!panel, 'clicking an element opens the rule panel');
ok(!!findById(html, 'nc-pick-text'), 'the panel has an editable selector field');
ok(!!findById(html, 'nc-pick-create'), 'the panel has 创建');
ok(!!findById(html, 'nc-pick-select'), 'the panel has 选择');
ok(!!findById(html, 'nc-pick-quit'), 'the panel has 放弃');
ok(!!findById(html, 'nc-pick-depth') && !!findById(html, 'nc-pick-spec'), 'the panel has both sliders');
ok(adInner.getAttribute('data-nc-hover') === null, 'entering the panel stops the hover outline');

const text = findById(html, 'nc-pick-text');
const create = findById(html, 'nc-pick-create');
const note = findById(html, 'nc-pick-note');
const ruleLine = findById(html, 'nc-pick-rule');
const sug = findById(html, 'nc-pick-sug');
ok(sug.children.length >= 6, 'the panel suggests several selectors (' + sug.children.length + ')');
ok(/^[.#A-Za-z]/.test(text.value), 'the field starts with a suggested selector (' + text.value + ')');
ok(create.getAttribute('disabled') === null, '创建 is enabled for a suggestion that matches');
ok(ruleLine.textContent.indexOf('example.com##') === 0, 'the panel shows the rule to be saved: ' + ruleLine.textContent);
ok(countMarked(html) >= 1, 'the suggestion is previewed on the page');
ok(note.textContent.indexOf('会隐藏') >= 0, 'the panel says how many elements it would hide');

// clicking a suggestion loads it and previews it
const second = sug.children[1];
const secondSel = second.textContent;
second.onclick();
ok(text.value === secondSel, 'clicking a suggestion loads it into the field');
ok(second.className === 'on', 'the clicked suggestion is marked as the current one');
ok(countMarked(html) >= 1, 'the clicked suggestion is previewed too');

// sliders regenerate the selector from the clicked element
const depth = findById(html, 'nc-pick-depth');
const spec = findById(html, 'nc-pick-spec');
const beforeSlider = text.value;
depth.value = '3';
spec.value = '2';
spec.oninput();
ok(text.value !== beforeSlider, 'the sliders change the selector (' + beforeSlider + ' -> ' + text.value + ')');
ok(create.getAttribute('disabled') === null, 'the slider result still matches, so 创建 stays enabled');

// a selector that matches nothing is refused
text.value = '.definitely-not-here';
text.oninput();
ok(create.getAttribute('disabled') !== null, '创建 is disabled when nothing matches');
ok(note.textContent.indexOf('没有元素匹配') >= 0, 'the panel explains why: ' + note.textContent);
ok(countMarked(html) === 0, 'nothing is previewed for a selector that matches nothing');

// a selector the browser cannot parse is refused too
text.value = 'div >';
text.oninput();
ok(create.getAttribute('disabled') !== null, '创建 is disabled for a selector that cannot be parsed');
ok(note.textContent.indexOf('解析不了') >= 0, 'the panel says it cannot be parsed');

// create writes the rule through the proxy and hides the element locally
text.value = 'div.ad-slot > div.ad-inner';
text.oninput();
// Regression: in a browser the capture-phase document listener runs *before*
// the button's own handler.  It used to swallow every click while the panel was
// open, so 创建/选择/放弃 (and the suggestion rows) could not be pressed at all.
let swallowed = false;
documentStub.fire('click', {
  target: create,
  preventDefault() {
    swallowed = true;
  },
  stopPropagation() {
    swallowed = true;
  },
});
ok(!swallowed, 'a click on our own panel is not swallowed by the capture listener');
ok(findById(html, 'nc-pick-panel') !== null, 'and the panel stays open while you use it');
create.onclick();
ok(!!lastXhr, '创建 talks to the proxy');
ok(
  lastXhr && lastXhr.url.indexOf('/__netcap/pick?h=example.com&s=') === 0,
  'the request carries the host and the selector: ' + (lastXhr ? lastXhr.url : '(none)')
);
ok(
  lastXhr && decodeURIComponent(lastXhr.url).indexOf('s=div.ad-slot > div.ad-inner') > 0,
  'the edited selector is what gets sent'
);
ok(findById(html, 'nc-pick-panel') === null, 'the panel closes after 创建');
ok(bar.textContent.indexOf('已创建') >= 0, 'the bar confirms the rule: ' + bar.textContent);
const hideStyles = html.children.filter(
  (n) => n.tagName === 'STYLE' && n.textContent.indexOf('display:none') >= 0
);
ok(hideStyles.length === 1, 'the element is hidden on the spot, before the next reload');

// escaping with the panel open keeps picking; a second Esc leaves
documentStub.fire('click', ev(adInner));
ok(!!findById(html, 'nc-pick-panel'), 'you can pick again after creating');
documentStub.fire('keydown', { key: 'Escape', preventDefault() {}, stopPropagation() {} });
ok(findById(html, 'nc-pick-panel') === null, 'Esc closes the panel');
ok(!!findById(html, 'nc-pick-bar'), 'Esc keeps you in picker mode when the panel was open');
documentStub.fire('click', ev(adLabel));
const quitPanel = findById(html, 'nc-pick-panel');
ok(!!quitPanel, 'a second element opens the panel again');
findById(html, 'nc-pick-quit').onclick();
ok(findById(html, 'nc-pick-bar') === null, '放弃 leaves picker mode');
ok(windowStub.__ncPickerOn === 0, 'the script is torn down');
ok(documentStub.listenerCount('click') === 0, 'the click listener is removed');

// ------------------------------------------------- the bootstrap (live channel)
//
// This is the piece that makes the interface button behave like an ad blocker's
// eyedropper: the page keeps asking the proxy "are we picking?" and pulls the
// picker script in the moment the answer flips — no reload.
const bStart = src.indexOf('R"NCBOOT(');
const bEnd = src.indexOf(')NCBOOT"');
ok(bStart > 0 && bEnd > bStart, 'the bootstrap script is embedded in src/picker.cpp');
const bootstrap = bStart > 0 ? src.slice(bStart + 'R"NCBOOT('.length, bEnd) : '';
ok(bootstrap.indexOf('</script>') < 0, 'the bootstrap contains no </script> sequence');
ok(bootstrap.length < 1200, 'the bootstrap stays small (' + bootstrap.length + ' bytes)');

function bootstrapPage() {
  const root = makeEl('html');
  const headEl = el('head');
  root.appendChild(headEl);
  const doc = {
    documentElement: root,
    head: headEl,
    createElement: (tag) => makeEl(tag),
    addEventListener() {},
    removeEventListener() {},
    querySelectorAll: (sel) => queryAll(root, sel),
  };
  const win = {};
  const timers = [];
  const requests = [];
  let answer = { picker: false };
  function Xhr() {
    this.onload = null;
    this.onerror = null;
    this.url = '';
  }
  Xhr.prototype.open = function (method, url) {
    this.url = url;
  };
  Xhr.prototype.send = function () {
    requests.push(this.url);
    this.status = 200;
    this.responseText = JSON.stringify(answer);
    if (this.onload) this.onload();
  };
  const sandbox2 = {
    window: win,
    document: doc,
    location: locationStub,
    XMLHttpRequest: Xhr,
    console,
    parseInt,
    Number,
    String,
    isNaN,
    encodeURIComponent,
    setTimeout: (fn) => {
      timers.push(fn);
      return timers.length;
    },
  };
  vm.createContext(sandbox2);
  return {
    sandbox: sandbox2,
    win,
    timers,
    requests,
    setAnswer(v) {
      answer = v;
    },
    run() {
      const fn = timers.shift();
      if (fn) fn();
    },
    scripts() {
      return headEl.children.filter((c) => c.tagName === 'SCRIPT');
    },
  };
}

console.log('');
console.log('netcap element picker — the live channel (bootstrap)');
const page = bootstrapPage();
vm.runInContext(bootstrap, page.sandbox, { filename: 'bootstrap.js' });
ok(page.requests.length === 1, 'the bootstrap asks the proxy right away');
ok(
  page.requests[0] && page.requests[0].indexOf('/__netcap/ctl?t=') === 0,
  'it asks the control path: ' + page.requests[0]
);
ok(page.scripts().length === 0, 'picking is off, so no picker script is loaded');
page.run();
ok(page.requests.length === 2, 'it keeps asking (the poll is rescheduled)');

page.setAnswer({ picker: true });
page.run();
ok(page.scripts().length === 1, 'when picking turns on it pulls in the picker script');
ok(
  page.scripts()[0] &&
    page.scripts()[0].src.indexOf('/__netcap/picker.js') === 0 &&
    page.scripts()[0].src.indexOf('://') < 0,
  'from a relative URL, so an https page has no mixed content'
);

let teardowns = 0;
page.win.__ncPickerOff = () => {
  teardowns++;
};
page.setAnswer({ picker: false });
page.run();
ok(teardowns === 1, 'switching picking off calls the picker script teardown');
ok(page.scripts().length === 0, 'and takes the script element back out');
ok(!!page.win.__ncPickerCtl, 'the bootstrap stays in place for next time');

page.setAnswer({ picker: true });
page.run();
ok(page.scripts().length === 1, 'turning it on again loads the script once more');

console.log('');
console.log(checks + '/' + checks + ' checks passed' + (failures ? ' — ' + failures + ' FAILED' : ' (all good)'));
process.exit(failures ? 1 : 0);
