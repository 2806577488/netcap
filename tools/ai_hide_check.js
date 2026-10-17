// Checks the "hide the AI写代码 button" logic that rules/adblock.txt injects into
// CSDN pages.  The real page cannot be driven from here (Edge hands a new
// --user-data-dir launch over to the already running instance), so the shipped
// function is run against the button shapes CSDN is known to build:
//   <button class="btn-code-notes mdeditor"><i class="icon"></i>AI写代码</button>
// plus the code text and the copy / run buttons that must survive.
//
//   node tools/ai_hide_check.js
//
// The ownText/hideAi bodies below are copied verbatim out of the $script= rule.

function ownText(el){var t='';for(var i=0;i<el.childNodes.length;i++){if(el.childNodes[i].nodeType===3)t+=el.childNodes[i].nodeValue}return t.replace(/\s+/g,'')}
function hideAi(){var all=document.querySelectorAll('body *');for(var i=0;i<all.length;i++){var el=all[i];var t=ownText(el);if(t.length===0||t.length>12||t.indexOf('写代码')<0)continue;if(el.closest&&el.closest('pre'))continue;var b=el.closest?el.closest('button'):null;if(b){b.style.display='none';continue}var p=el.parentElement;if(p&&!p.querySelector('.hljs-button')&&!String(p.className||'').match(/run|hljs/)){p.style.display='none';continue}el.style.display='none'}}

// ---- the smallest DOM this needs ------------------------------------------
let all = [];
function el(tag, className = '', text = '', kids = []) {
  const node = {
    tagName: tag, className, style: { display: '' }, childNodes: [], children: kids,
    parentElement: null, querySelector(sel) { return find(this, sel); },
    closest(sel) { let n = this; while (n) { if (matches(n, sel)) return n; n = n.parentElement; } return null; },
    textContent: '',
  };
  if (text) node.childNodes.push({ nodeType: 3, nodeValue: text });
  for (const k of kids) { k.parentElement = node; node.childNodes.push(k); }
  node.textContent = text + kids.map((k) => k.textContent).join('');
  all.push(node);
  return node;
}
function matches(node, sel) {
  if (sel === 'body *') return true;
  if (sel.startsWith('.')) return String(node.className).split(/\s+/).includes(sel.slice(1));
  return node.tagName.toLowerCase() === sel.toLowerCase();
}
function find(node, sel) { for (const n of all) { let p = n; while (p) { if (p === node && matches(n, sel)) return n; p = p.parentElement; } } return null; }
const body = { childNodes: [], children: [], parentElement: null, querySelector: () => null, closest: () => null };

let failures = 0;
function check(what, ok) { if (!ok) { failures++; console.log('FAIL ' + what); } else { console.log('ok   ' + what); } }

function build(shape) {
  all = [];
  const bar = el('div', 'opt-box');
  let ai;
  if (shape === 'icon+text button') ai = el('button', 'btn-code-notes mdeditor', '', [el('i', 'icon')]), ai.childNodes.push({ nodeType: 3, nodeValue: 'AI写代码' }), ai.textContent = 'AI写代码';
  else if (shape === 'plain button') ai = el('button', 'btn-code-notes mdeditor', 'AI写代码');
  else if (shape === 'span wrapper') ai = el('span', 'btn-code-notes', '', [el('span', '', 'AI写代码')]);
  else ai = el('div', 'ai-write-code', 'AI写代码');
  const copy = el('div', 'hljs-button', '复制');
  const run = el('span', 'code-run-btn', '运行');
  bar.children.push(ai, copy, run);
  for (const k of [ai, copy, run]) k.parentElement = bar;
  bar.childNodes.push(ai, copy, run);
  const code = el('pre', 'set-code-show');
  const line = el('code', '', '# 写代码');
  line.parentElement = code; code.children.push(line); code.childNodes.push(line);
  globalThis.document = { querySelectorAll: (sel) => (sel === 'body *' ? all : []) };
  return { ai, copy, run, line };
}

for (const shape of ['icon+text button', 'plain button', 'span wrapper', 'div']) {
  const { ai, copy, run, line } = build(shape);
  hideAi();
  check(shape + ': AI element hidden', ai.style.display === 'none' || (ai.children[0] && ai.children[0].style.display === 'none'));
  check(shape + ': copy button kept', copy.style.display !== 'none');
  check(shape + ': run button kept', run.style.display !== 'none');
  check(shape + ': code text kept', line.style.display !== 'none');
}

console.log(failures === 0 ? '\nall good' : `\n${failures} failure(s)`);
process.exit(failures === 0 ? 0 : 1);
