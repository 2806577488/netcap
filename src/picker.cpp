#include "netcap/picker.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <system_error>

namespace netcap {
namespace {

std::string lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return s;
}

int hex_value(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

std::string percent_decode(const std::string& in) {
  std::string out;
  out.reserve(in.size());
  for (std::size_t i = 0; i < in.size(); ++i) {
    if (in[i] == '%' && i + 2 < in.size()) {
      const int hi = hex_value(in[i + 1]);
      const int lo = hex_value(in[i + 2]);
      if (hi >= 0 && lo >= 0) {
        out.push_back(static_cast<char>((hi << 4) | lo));
        i += 2;
        continue;
      }
    }
    out.push_back(in[i]);
  }
  return out;
}

std::string query_value(const std::string& query, const std::string& key) {
  std::size_t pos = 0;
  while (pos <= query.size()) {
    const std::size_t amp = query.find('&', pos);
    const std::string pair = query.substr(pos, amp == std::string::npos ? std::string::npos : amp - pos);
    const std::size_t eq = pair.find('=');
    if (eq != std::string::npos && pair.substr(0, eq) == key) {
      return percent_decode(pair.substr(eq + 1));
    }
    if (amp == std::string::npos) break;
    pos = amp + 1;
  }
  return std::string();
}

bool host_ok(const std::string& host) {
  if (host.empty() || host.size() > 253) return false;
  for (const char c : host) {
    const unsigned char u = static_cast<unsigned char>(c);
    if (std::isalnum(u) || c == '.' || c == '-' || c == '_') continue;
    return false;
  }
  return host.find('.') != std::string::npos || host == "localhost";
}

}  // namespace

const char* const kPickerPath = "/__netcap/pick";
const char* const kPickerCtlPath = "/__netcap/ctl";
const char* const kPickerScriptPath = "/__netcap/picker.js";

std::string picker_bootstrap_script() {
  // This one is *always* in the page while the proxy runs, so the interface can
  // arm the picker without a reload — which is how every real ad blocker feels:
  // press the button, the cursor changes, pick.  It only polls the proxy over
  // the page's own origin (loopback, answered locally, never forwarded) and
  // pulls in the real picker script when the answer flips to true.
  //
  // 1.5 s is the worst case between pressing the button and the crosshair
  // appearing on an already-open page; the poll is a few hundred bytes.
  static const char* const kBootstrap = R"NCBOOT((function(){
if(window.__ncPickerCtl)return;
window.__ncPickerCtl=1;
var on=false,el=null,warned=0;
function log(m){try{console.log('[netcap picker] '+m);}catch(e){}}
function apply(next){
  if(next===on)return;
  on=next;
  if(on){
    if(el)return;
    log('armed: crosshair on (Esc quits)');
    el=document.createElement('script');
    el.setAttribute('data-nc-picker','1');
    el.src='/__netcap/picker.js?v='+(new Date()).getTime();
    (document.head||document.documentElement).appendChild(el);
  }else{
    log('off: the switch is off');
    if(window.__ncPickerOff)window.__ncPickerOff();
    if(el&&el.parentNode)el.parentNode.removeChild(el);
    el=null;
  }
}
function poll(){
  var xhr=new XMLHttpRequest();
  xhr.open('GET','/__netcap/ctl?t='+(new Date()).getTime(),true);
  xhr.onload=function(){
    try{apply(!!(JSON.parse(xhr.responseText||'{}').picker));}catch(e){}
    setTimeout(poll,1500);
  };
  xhr.onerror=function(){
    if(!warned){warned=1;log('the proxy did not answer');}
    setTimeout(poll,4000);
  };
  try{xhr.send();}catch(e){setTimeout(poll,4000);}
}
log('waiting for the switch');
poll();
})())NCBOOT";
  return std::string(kBootstrap);
}

bool picker_is_ctl_path(const std::string& path_and_query) {
  const std::size_t q = path_and_query.find('?');
  const std::string path = q == std::string::npos ? path_and_query : path_and_query.substr(0, q);
  return path == kPickerCtlPath;
}

bool picker_is_script_path(const std::string& path_and_query) {
  const std::size_t q = path_and_query.find('?');
  const std::string path = q == std::string::npos ? path_and_query : path_and_query.substr(0, q);
  return path == kPickerScriptPath;
}

std::string picker_script() {
  // ES5 only, no dependencies, and never the sequence `</script>` — the whole
  // thing is injected straight into a <script> block.  It talks to the proxy
  // through the page's own origin (no CORS, and nothing is ever forwarded).
  //
  // The interaction follows what uBlock Origin and AdGuard do, because that is
  // what people already know: hover to outline, click to open a *draggable*
  // panel, pick from suggested selectors, watch the suggestion light up the
  // page before committing, nudge it with two sliders (how far up the tree the
  // selector reaches / how much of the element it pins down), edit the text by
  // hand, and only then press 创建 — which is the only thing that writes a rule.
  static const char* const kScript = R"NCPICKER((function(){
if(window.__ncPickerOn)return;
window.__ncPickerOn=1;
var HOST=location.hostname;
var MARK='data-nc-mark';
var style=document.createElement('style');
style.setAttribute('data-nc-pick','1');
style.textContent=
 '#nc-pick-bar{position:fixed;z-index:2147483647;left:0;right:0;bottom:0;padding:7px 12px;'+
 'font:13px/1.5 "Microsoft YaHei",system-ui,sans-serif;background:#111;color:#eee;'+
 'border-top:2px solid #ff4d4f;text-align:center}'+
 '#nc-pick-panel{position:fixed;z-index:2147483647;right:18px;bottom:44px;width:430px;'+
 'background:#161b22;color:#e6edf3;border:1px solid #30363d;border-radius:10px;'+
 'box-shadow:0 12px 32px rgba(0,0,0,.55);font:13px/1.6 "Microsoft YaHei",system-ui,sans-serif}'+
 '#nc-pick-panel *{box-sizing:border-box}'+
 // The mouse has to *look* like it is picking — that is half of what makes an
 // ad blocker's eyedropper feel right.  Crosshair everywhere on the page, back
 // to normal inside our own bar and panel.
 'html,body,body *{cursor:crosshair!important}'+
 '#nc-pick-bar,#nc-pick-bar *,#nc-pick-panel,#nc-pick-panel *{cursor:auto!important}'+
 '#nc-pick-head{cursor:move!important}'+
 '#nc-pick-head b,#nc-pick-sug div,#nc-pick-btns button{cursor:pointer!important}'+
 '#nc-pick-head{padding:8px 12px;border-bottom:1px solid #30363d;font-weight:600;cursor:move;user-select:none}'+
 '#nc-pick-head b{float:right;cursor:pointer;opacity:.7;font-weight:400;padding:0 4px}'+
 '#nc-pick-body{padding:10px 12px}'+
 '#nc-pick-el{color:#8b949e;margin-bottom:8px}'+
 '#nc-pick-sug{max-height:126px;overflow:auto;margin-bottom:10px}'+
 '#nc-pick-sug div{padding:4px 8px;border-radius:6px;cursor:pointer;white-space:nowrap;'+
 'overflow:hidden;text-overflow:ellipsis;font-family:Consolas,monospace;font-size:12px}'+
 '#nc-pick-sug div:hover{background:#21262d}'+
 '#nc-pick-sug div.on{background:rgba(31,111,235,.25);outline:1px solid #1f6feb}'+
 '#nc-pick-sug em{font-style:normal;color:#8b949e;font-size:11px}'+
 '#nc-pick-sliders label{display:block;color:#8b949e;margin:6px 0 2px}'+
 '#nc-pick-sliders input{width:100%}'+
 '#nc-pick-text{width:100%;background:#0d1117;color:#e6edf3;border:1px solid #30363d;'+
 'border-radius:6px;padding:6px 8px;font-family:Consolas,monospace;font-size:12px}'+
 '#nc-pick-rule{font-family:Consolas,monospace;font-size:12px;color:#7ee787;margin:8px 0 4px;word-break:break-all}'+
 '#nc-pick-note{color:#d29922;min-height:18px;margin-bottom:8px}'+
 '#nc-pick-btns{display:flex;gap:8px;justify-content:flex-end}'+
 '#nc-pick-btns button{border:1px solid #30363d;background:#21262d;color:#e6edf3;border-radius:6px;'+
 'padding:5px 14px;cursor:pointer;font:13px "Microsoft YaHei",system-ui,sans-serif}'+
 '#nc-pick-btns button#nc-pick-create{background:#238636;border-color:#2ea043}'+
 '#nc-pick-btns button[disabled]{opacity:.45;cursor:not-allowed}'+
 '[data-nc-hover]{outline:2px solid #2f81f7 !important;outline-offset:-2px !important}'+
 '[data-nc-mark]{outline:2px solid #ff4d4f !important;outline-offset:-2px !important;'+
 'background:rgba(255,77,79,.12) !important}';
document.documentElement.appendChild(style);
var bar=document.createElement('div');
bar.id='nc-pick-bar';
bar.textContent='netcap 元素选择器：鼠标移到要去掉的东西上点一下，会弹出可编辑的规则窗口；Esc 退出。';
document.documentElement.appendChild(bar);
try{console.log('[netcap picker] armed on '+HOST+' - click an element (Esc quits)');}catch(e){}
var over=null,picked=null,panel=null,marks=[],depth=0,spec=1,cur='';
function say(t){bar.textContent=t;}
function esc(s){return String(s).replace(/[^A-Za-z0-9_-]/g,function(c){return '\\'+c;});}
function classes(el){
  var cn=el.getAttribute?el.getAttribute('class'):null;
  if(!cn)return [];
  return cn.split(/\s+/).filter(function(c){return c&&c.indexOf('nc-')!==0;});
}
function nodesFor(sel){
  try{return document.querySelectorAll(sel);}catch(e){return null;}
}
function countFor(sel){
  var m=nodesFor(sel);
  return m?m.length:-1;
}
function nthPart(node){
  var parent=node.parentElement;
  if(!parent||!parent.children)return '';
  var same=0,idx=0,kids=parent.children;
  for(var k=0;k<kids.length;k++){
    if(kids[k].tagName===node.tagName){same++;if(kids[k]===node)idx=same;}
  }
  return same>1?(':nth-of-type('+idx+')'):'';
}
function pathFor(el,d,sp){
  if(!el||el.nodeType!==1)return '';
  // `d` extra ancestors above the element (0 = the element alone), `sp` how much
  // of each level to pin down: 0 = tag only, 1 = one class, 2 = two classes plus
  // :nth-of-type.  Both come straight from the two sliders, so every step of a
  // slider produces a different (still valid) selector.
  var parts=[],node=el,level=0;
  while(node&&node.nodeType===1&&level<=d){
    var part=node.tagName.toLowerCase();
    var list=classes(node);
    for(var i=0;i<list.length&&i<sp;i++){part+='.'+esc(list[i]);}
    if(sp>=2)part+=nthPart(node);
    parts.unshift(part);
    node=node.parentElement;
    level++;
  }
  return parts.join('>');
}
function candidates(el){
  var out=[],seen={};
  function add(sel,label){
    if(!sel||seen[sel])return;
    var n=countFor(sel);
    if(n<1)return;
    seen[sel]=1;
    out.push({sel:sel,n:n,label:label});
  }
  if(el.id)add('#'+esc(el.id),'用 id');
  // Seven levels because a forum thread is a table inside a table inside a
  // div: with only four the most specific chain still matched 28 rows, and the
  // panel then handed the user a rule that hides 43 elements when they had
  // clicked exactly one.  `:nth-of-type` at depth 6 is what pins it down.
  for(var d=0;d<=6;d++){
    for(var sp=0;sp<=2;sp++){
      add(pathFor(el,d,sp),'深度 '+(d+1)+' · 具体度 '+sp);
    }
  }
  out.sort(function(a,b){return a.n-b.n||a.sel.length-b.sel.length;});
  return out;
}
// uBlock starts you on the shortest suggestion that pins down exactly one
// element; falling back to the most specific one when nothing is unique.
function bestIndex(list){
  var best=-1;
  for(var i=0;i<list.length;i++){
    if(list[i].n!==1)continue;
    if(best<0||list[i].sel.length<list[best].sel.length)best=i;
  }
  return best<0?0:best;
}
function clearMarks(){
  for(var i=0;i<marks.length;i++){
    if(marks[i]&&marks[i].removeAttribute)marks[i].removeAttribute(MARK);
  }
  marks=[];
}
function mark(sel){
  clearMarks();
  var m=nodesFor(sel);
  if(!m)return 0;
  for(var i=0;i<m.length&&i<400;i++){
    if(m[i].setAttribute)m[i].setAttribute(MARK,'1');
    marks.push(m[i]);
  }
  return m.length;
}
function tagOf(el){
  var t=el.tagName?el.tagName.toLowerCase():'?';
  var w=el.offsetWidth||0,h=el.offsetHeight||0;
  return t+(w&&h?(' '+w+'×'+h):'');
}
function ruleLine(sel){return HOST+'##'+sel;}
var P=null,drag=null;
function node(tag,cls,text){
  var el=document.createElement(tag);
  if(cls)el.className=cls;
  if(text!==undefined&&text!==null)el.textContent=text;
  return el;
}
function refresh(){
  var sel=(P.text.value||'').replace(/^\s+|\s+$/g,'');
  cur=sel;
  var n=sel?countFor(sel):-1;
  P.rule.textContent=sel?ruleLine(sel):'';
  if(!sel){P.note.textContent='写一个选择器，或者在上面点一条建议。';}
  else if(n<0){P.note.textContent='这个选择器浏览器解析不了。';}
  else if(n===0){P.note.textContent='页面上没有元素匹配它 —— 换一条。';}
  else if(n===1){P.note.textContent='只会隐藏这一个元素。';}
  else{P.note.textContent='会隐藏 '+n+' 个元素（红色边框就是它们）——它不是唯一的：想只藏一个，把「具体度」调到 2、或把「深度」调大，再挑一条建议。';}
  mark(sel);
  if(sel&&n>0){P.create.removeAttribute('disabled');}
  else{P.create.setAttribute('disabled','disabled');}
}
function setText(sel){
  P.text.value=sel;
  refresh();
}
function buildSuggestions(el){
  var box=P.sug;
  var list=candidates(el),rows=[];
  var pick=list.length?bestIndex(list):0;
  var unique=false;
  for(var u=0;u<list.length;u++){if(list[u].n===1){unique=true;break;}}
  while(box.firstChild){box.removeChild(box.firstChild);}
  if(list.length&&!unique){
    // Say it before the user picks: on a page that repeats the same markup there
    // is no one-element selector, and silently handing over "43 个" is how you
    // end up hiding a whole table after clicking one cell.
    var warn=node('div',null,'这一页没有只命中 1 个的选择器：下面每条都会隐藏多个元素，最少的是 '+list[pick].n+' 个。');
    warn.setAttribute('data-nc-warn','1');
    box.appendChild(warn);
  }
  for(var i=0;i<list.length;i++){
    (function(item,idx){
      var row=node('div',idx===pick?'on':null,item.sel);
      row.appendChild(node('em',null,'  '+item.n+' 个 · '+item.label));
      row.onclick=function(){
        for(var k=0;k<rows.length;k++){rows[k].className='';}
        row.className='on';
        setText(item.sel);
      };
      rows.push(row);
      box.appendChild(row);
    })(list[i],i);
  }
  return list.length?list[pick].sel:'';
}
function slidersChanged(){
  var d=parseInt(P.depth.value,10);
  var s=parseInt(P.spec.value,10);
  depth=d;spec=s;
  if(!picked)return;
  setText(pathFor(picked,(isNaN(d)?1:d)-1,isNaN(s)?1:s));
}
function finish(msg){
  say(msg);
  closepanel();
}
function send(){
  if(!cur)return;
  var url='/__netcap/pick?h='+encodeURIComponent(HOST)+
          '&s='+encodeURIComponent(cur)+'&u='+encodeURIComponent(location.href);
  var xhr=new XMLHttpRequest();
  xhr.open('GET',url,true);
  xhr.onload=function(){
    if(xhr.responseText&&xhr.responseText.indexOf('"ok":true')>=0){
      var hide=document.createElement('style');
      hide.textContent=cur+'{display:none !important}';
      document.documentElement.appendChild(hide);
      finish('已创建：'+ruleLine(cur)+'（规则写进了你的过滤列表，重启代理也还在）');
      try{console.log('[netcap picker] rule created: '+ruleLine(cur));}catch(e){}
    }else{
      say('netcap 拒绝了这条规则：'+(xhr.responseText||xhr.status));
      try{console.log('[netcap picker] the proxy refused the rule: '+(xhr.responseText||xhr.status));}catch(e){}
    }
  };
  xhr.onerror=function(){
    say('没能连上 netcap，代理还在跑吗？');
    try{console.log('[netcap picker] the rule request failed (is the proxy still running?)');}catch(e){}
  };
  xhr.timeout=6000;
  xhr.ontimeout=function(){
    say('netcap 6 秒没回应，代理还在跑吗？');
    try{console.log('[netcap picker] the proxy did not answer within 6 s');}catch(e){}
  };
  xhr.send();
}
function closepanel(){
  if(panel&&panel.parentNode)panel.parentNode.removeChild(panel);
  panel=null;picked=null;P=null;drag=null;clearMarks();
}
function buildPanel(el){
  closepanel();
  picked=el;
  panel=node('div');
  panel.id='nc-pick-panel';
  var head=node('div');
  head.id='nc-pick-head';
  head.appendChild(node('span',null,'netcap 元素选择器'));
  var close=node('b',null,'✕');
  close.id='nc-pick-close';
  head.appendChild(close);
  var body=node('div');
  body.id='nc-pick-body';
  var info=node('div',null,'选中的元素：'+tagOf(el));
  info.id='nc-pick-el';
  var sug=node('div');
  sug.id='nc-pick-sug';
  var sliders=node('div');
  sliders.id='nc-pick-sliders';
  var dl=node('label');
  dl.appendChild(node('span',null,'深度'));
  var dn=node('span',null,'1');
  dl.appendChild(dn);
  dl.appendChild(node('span',null,'（往上是选到父级，区域更大）'));
  var depthInput=document.createElement('input');
  depthInput.id='nc-pick-depth';
  depthInput.setAttribute('type','range');
  depthInput.setAttribute('min','1');
  depthInput.setAttribute('max','7');
  depthInput.value='1';
  var sl=node('label');
  sl.appendChild(node('span',null,'具体度'));
  var sn=node('span',null,'1');
  sl.appendChild(sn);
  sl.appendChild(node('span',null,'（越大越只针对这一个元素）'));
  var specInput=document.createElement('input');
  specInput.id='nc-pick-spec';
  specInput.setAttribute('type','range');
  specInput.setAttribute('min','0');
  specInput.setAttribute('max','2');
  specInput.value='1';
  sliders.appendChild(dl);sliders.appendChild(depthInput);sliders.appendChild(sl);sliders.appendChild(specInput);
  var text=document.createElement('input');
  text.id='nc-pick-text';
  text.setAttribute('type','text');
  text.setAttribute('spellcheck','false');
  var rule=node('div');
  rule.id='nc-pick-rule';
  var note=node('div');
  note.id='nc-pick-note';
  var btns=node('div');
  btns.id='nc-pick-btns';
  var create=node('button',null,'创建');
  create.id='nc-pick-create';
  var select=node('button',null,'选择');
  select.id='nc-pick-select';
  var quit=node('button',null,'放弃');
  quit.id='nc-pick-quit';
  btns.appendChild(create);btns.appendChild(select);btns.appendChild(quit);
  body.appendChild(info);body.appendChild(sug);body.appendChild(sliders);
  body.appendChild(text);body.appendChild(rule);body.appendChild(note);body.appendChild(btns);
  panel.appendChild(head);panel.appendChild(body);
  document.documentElement.appendChild(panel);
  P={head:head,close:close,body:body,info:info,sug:sug,depth:depthInput,depthN:dn,
     spec:specInput,specN:sn,text:text,rule:rule,note:note,btns:btns,create:create,
     select:select,quit:quit};
  var first=buildSuggestions(el);
  text.value=first;
  text.oninput=refresh;
  depthInput.oninput=function(){dn.textContent=String(depthInput.value);slidersChanged();};
  specInput.oninput=function(){sn.textContent=String(specInput.value);slidersChanged();};
  create.onclick=function(){send();};
  select.onclick=function(){say('再点一个元素。Esc 退出。');closepanel();};
  quit.onclick=function(){stop();};
  close.onclick=function(){stop();};
  head.onmousedown=function(ev){
    drag={x:ev.clientX,y:ev.clientY,
          l:parseInt(panel.style.left||'0',10),t:parseInt(panel.style.top||'0',10)};
    ev.preventDefault();ev.stopPropagation();
  };
  panel.onmousedown=function(ev){ev.stopPropagation();};
  panel.onclick=function(ev){ev.stopPropagation();};
  document.addEventListener('mousemove',function(ev){
    if(!drag||!panel)return;
    panel.style.left=(drag.l+ev.clientX-drag.x)+'px';
    panel.style.top=(drag.t+ev.clientY-drag.y)+'px';
    panel.style.right='auto';panel.style.bottom='auto';
    ev.preventDefault();ev.stopPropagation();
  },true);
  refresh();
}
function onMove(ev){
  if(panel)return;
  var el=ev.target;
  if(!el||el===bar||el===style)return;
  if(el!==over){
    if(over&&over.removeAttribute)over.removeAttribute('data-nc-hover');
    over=el;
    if(el.setAttribute)el.setAttribute('data-nc-hover','1');
    say('netcap 元素选择器：'+tagOf(el)+' —— 点一下打开规则窗口；Esc 退出。');
  }
  ev.preventDefault();ev.stopPropagation();
}
// Clicks inside our own panel have to reach the panel.  This listener sits in
// the capture phase, and it used to swallow *every* click while the panel was
// open — which is why 创建/选择/放弃 and the suggestion rows felt unpressable.
function inOwnUi(el){
  while(el){
    if(el===panel||el===bar||el===style)return true;
    el=el.parentNode||null;
  }
  return false;
}
function onClick(ev){
  if(inOwnUi(ev.target))return;
  ev.preventDefault();ev.stopPropagation();
  var el=ev.target;
  if(!el)return;
  if(el.removeAttribute)el.removeAttribute('data-nc-hover');
  over=null;
  buildPanel(el);
}
function onKey(ev){
  if(ev.key==='Escape'||ev.keyCode===27){
    ev.preventDefault();ev.stopPropagation();
    if(panel){closepanel();say('netcap 元素选择器：再点一个元素；Esc 退出。');}
    else{stop();}
  }
}
function stop(){
  document.removeEventListener('mousemove',onMove,true);
  document.removeEventListener('click',onClick,true);
  document.removeEventListener('keydown',onKey,true);
  if(over&&over.removeAttribute)over.removeAttribute('data-nc-hover');
  closepanel();
  if(bar.parentNode)bar.parentNode.removeChild(bar);
  if(style.parentNode)style.parentNode.removeChild(style);
  window.__ncPickerOn=0;
  window.__ncPickerOff=null;
  try{console.log('[netcap picker] off');}catch(e){}
}
document.addEventListener('mousemove',onMove,true);
document.addEventListener('click',onClick,true);
document.addEventListener('keydown',onKey,true);
// The bootstrap script (always in the page while the proxy runs) calls this
// when picking is switched off from the interface, so the page does not have to
// be reloaded to get rid of the crosshair and the bar.
window.__ncPickerOff=stop;
})())NCPICKER";
  return std::string(kScript);
}

bool picker_is_pick_path(const std::string& path_and_query) {
  const std::size_t q = path_and_query.find('?');
  const std::string path = q == std::string::npos ? path_and_query : path_and_query.substr(0, q);
  return path == kPickerPath;
}

bool picker_selector_ok(const std::string& selector, std::string* why) {
  const auto fail = [&](const char* reason) {
    if (why != nullptr) *why = reason;
    return false;
  };
  if (selector.empty()) return fail("empty selector");
  if (selector.size() > 300) return fail("selector is longer than 300 bytes");
  if (selector.find("/*") != std::string::npos || selector.find("*/") != std::string::npos) {
    return fail("selector contains a comment marker");
  }
  for (const char c : selector) {
    const unsigned char u = static_cast<unsigned char>(c);
    if (u < 0x20 || u == 0x7f) return fail("selector contains a control character");
    switch (c) {
      // `<` is what could start a `</style>` and escape the block; braces and
      // semicolons could turn the selector into declarations.  `>` is fine (the
      // child combinator) and so are `+` and `~`.
      case '{': case '}': case ';': case '<':
        return fail("selector contains a character that could break the style block");
      default: break;
    }
  }
  return true;
}

bool picker_parse_pick(const std::string& path_and_query, std::string* host,
                       std::string* selector, std::string* url) {
  if (!picker_is_pick_path(path_and_query)) return false;
  const std::size_t q = path_and_query.find('?');
  const std::string query = q == std::string::npos ? std::string() : path_and_query.substr(q + 1);
  const std::string h = query_value(query, "h");
  const std::string s = query_value(query, "s");
  const std::string u = query_value(query, "u");
  if (!host_ok(lower(h))) return false;
  if (!picker_selector_ok(s)) return false;
  if (host != nullptr) *host = lower(h);
  if (selector != nullptr) *selector = s;
  if (url != nullptr) *url = u;
  return true;
}

std::string picker_rule_line(const std::string& host, const std::string& selector) {
  if (!host_ok(lower(host))) return std::string();
  if (!picker_selector_ok(selector)) return std::string();
  return lower(host) + "##" + selector;
}

bool picker_append_rule(const std::string& path, const std::string& rule,
                        const std::string& picked_url, std::string* error) {
  if (path.empty()) {
    if (error != nullptr) *error = "no rule file was given for picked rules";
    return false;
  }
  if (rule.empty()) {
    if (error != nullptr) *error = "refusing to write an empty rule";
    return false;
  }
  std::error_code ec;
  const std::filesystem::path file(path);
  if (file.has_parent_path()) {
    std::filesystem::create_directories(file.parent_path(), ec);
    if (ec) {
      if (error != nullptr) *error = "cannot create " + file.parent_path().string() + ": " + ec.message();
      return false;
    }
  }
  std::ofstream out(path, std::ios::binary | std::ios::app);
  if (!out) {
    if (error != nullptr) *error = "cannot open " + path + " for appending";
    return false;
  }
  out << "\n! netcap 点选：在 " << (picked_url.empty() ? std::string("(未记录网址)") : picked_url)
      << " 上点出来的\n"
      << rule << "\n";
  out.flush();
  if (!out) {
    if (error != nullptr) *error = "the write to " + path + " did not complete";
    return false;
  }
  return true;
}

bool picker_host_matches(const std::string& rule_host, const std::string& document_host) {
  const std::string rule = lower(rule_host);
  const std::string doc = lower(document_host);
  if (rule.empty() || doc.empty()) return false;
  if (doc == rule) return true;
  if (doc.size() > rule.size() && doc.compare(doc.size() - rule.size(), rule.size(), rule) == 0 &&
      doc[doc.size() - rule.size() - 1] == '.') {
    return true;
  }
  return false;
}

}  // namespace netcap
