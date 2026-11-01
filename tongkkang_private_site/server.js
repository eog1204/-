const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const ROOT = __dirname, PUB = path.join(ROOT, 'public');
const DB = path.join(ROOT, 'data.json');
const PORT = Number(process.env.PORT || 3000);
const COOKIE = 'tongkkang_admin';
const sessions = new Map();
const attempts = new Map();

function load() {
  try { return JSON.parse(fs.readFileSync(DB, 'utf8')); }
  catch { return { admin:null, isPublic:false, title:'통깡이 기다리기', startDate:'2026-10-13', comments:[], visitors:{}, createdAt:new Date().toISOString() }; }
}
let data = load();
function save(){ fs.writeFileSync(DB, JSON.stringify(data,null,2)); }
function send(res, code, obj, headers={}) {
  res.writeHead(code, {'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',...headers});
  res.end(JSON.stringify(obj));
}
function cookieToken(req) {
  const raw=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith(COOKIE+'='));
  return raw ? decodeURIComponent(raw.slice(COOKIE.length+1)) : '';
}
function isAdmin(req) { const token=cookieToken(req); return !!token && sessions.has(token); }
function parseBody(req) {
  return new Promise((resolve,reject)=>{
    let body=''; req.on('data',c=>{body+=c;if(body.length>20000) reject(new Error('too_large'));});
    req.on('end',()=>{try{resolve(JSON.parse(body||'{}'));}catch{reject(new Error('bad_json'));}});
  });
}
function dayKey(d=new Date()){ return new Intl.DateTimeFormat('en-CA',{timeZone:'Asia/Seoul',year:'numeric',month:'2-digit',day:'2-digit'}).format(d); }
function publicStats(){
  const today=dayKey();
  const todays=data.comments.filter(c=>c.date===today);
  const chars=todays.reduce((n,c)=>n + Array.from(c.message).length,0);
  return {today,comments: todays.length,chars,total:data.comments.length,visitors:data.visitors[today]||0};
}
function safeComment(c){ return {id:c.id,message:c.message,date:c.date,time:c.time}; }
function serveFile(res,file,type){
  fs.readFile(file,(err,b)=>{if(err){res.writeHead(404);return res.end('Not found');}
    res.writeHead(200,{'Content-Type':type,'Cache-Control':'no-cache'});res.end(b);});
}
const mime={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.png':'image/png','.ico':'image/x-icon'};
http.createServer(async(req,res)=>{
  const url=new URL(req.url,'http://localhost');
  const ip=req.socket.remoteAddress||'unknown';
  if(req.method==='GET' && url.pathname.startsWith('/api/')){
    if(url.pathname==='/api/status') return send(res,200,{setup:!!data.admin,isPublic:data.isPublic,loggedIn:isAdmin(req),title:data.title});
    if(url.pathname==='/api/data'){
      if(!data.isPublic && !isAdmin(req)) return send(res,403,{error:'비공개 사이트입니다.'});
      const today=dayKey(); data.visitors[today]=(data.visitors[today]||0)+1; save();
      return send(res,200,{stats:publicStats(),comments:data.comments.slice(-80).reverse().map(safeComment),startDate:data.startDate,title:data.title});
    }
    if(url.pathname==='/api/admin/data'){
      if(!isAdmin(req)) return send(res,401,{error:'관리자 로그인이 필요합니다.'});
      return send(res,200,{isPublic:data.isPublic,title:data.title,startDate:data.startDate,comments:data.comments.slice().reverse().map(safeComment),stats:publicStats()});
    }
    return send(res,404,{error:'not found'});
  }
  if(req.method==='POST' && url.pathname.startsWith('/api/')){
    let b; try{b=await parseBody(req);}catch{return send(res,400,{error:'요청 형식이 올바르지 않습니다.'});}
    if(url.pathname==='/api/setup'){
      if(data.admin) return send(res,409,{error:'관리자 계정이 이미 만들어졌습니다.'});
      const username=String(b.username||'').trim(), password=String(b.password||'');
      if(username.length<3 || password.length<10) return send(res,400,{error:'아이디는 3자 이상, 비밀번호는 10자 이상이어야 합니다.'});
      const salt=crypto.randomBytes(16).toString('hex');
      const hash=crypto.scryptSync(password,salt,64).toString('hex');
      data.admin={username,salt,hash}; save();
      const token=crypto.randomBytes(32).toString('hex');sessions.set(token,true);
      return send(res,200,{ok:true},{'Set-Cookie':`${COOKIE}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400`});
    }
    if(url.pathname==='/api/login'){
      const now=Date.now(), arr=(attempts.get(ip)||[]).filter(t=>now-t<600000);
      if(arr.length>=8) return send(res,429,{error:'로그인 시도가 많습니다. 10분 뒤 다시 시도하세요.'});
      arr.push(now);attempts.set(ip,arr);
      if(!data.admin || String(b.username||'')!==data.admin.username) return send(res,401,{error:'아이디 또는 비밀번호가 틀렸습니다.'});
      const hash=crypto.scryptSync(String(b.password||''),data.admin.salt,64).toString('hex');
      if(!crypto.timingSafeEqual(Buffer.from(hash,'hex'),Buffer.from(data.admin.hash,'hex'))) return send(res,401,{error:'아이디 또는 비밀번호가 틀렸습니다.'});
      const token=crypto.randomBytes(32).toString('hex');sessions.set(token,true);
      return send(res,200,{ok:true},{'Set-Cookie':`${COOKIE}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400`});
    }
    if(url.pathname==='/api/logout'){
      const token=cookieToken(req);sessions.delete(token);
      return send(res,200,{ok:true},{'Set-Cookie':`${COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`});
    }
    if(url.pathname==='/api/comment'){
      if(!data.isPublic && !isAdmin(req)) return send(res,403,{error:'현재 비공개 상태입니다.'});
      const message=String(b.message||'').trim();
      if(!message || Array.from(message).length>500) return send(res,400,{error:'댓글은 1~500자로 작성해 주세요.'});
      if(/(https?:\/\/|www\.)/i.test(message)) return send(res,400,{error:'링크가 포함된 댓글은 등록할 수 없습니다.'});
      const d=new Date(), item={id:crypto.randomBytes(8).toString('hex'),message,date:dayKey(d),time:new Intl.DateTimeFormat('ko-KR',{timeZone:'Asia/Seoul',hour:'2-digit',minute:'2-digit',hour12:false}).format(d)};
      data.comments.push(item);save();return send(res,200,{ok:true,comment:safeComment(item)});
    }
    if(url.pathname==='/api/admin/settings'){
      if(!isAdmin(req)) return send(res,401,{error:'관리자 로그인이 필요합니다.'});
      if(typeof b.isPublic==='boolean') data.isPublic=b.isPublic;
      if(typeof b.title==='string' && b.title.trim()) data.title=b.title.trim().slice(0,40);
      if(typeof b.startDate==='string' && /^\d{4}-\d{2}-\d{2}$/.test(b.startDate)) data.startDate=b.startDate;
      save();return send(res,200,{ok:true,isPublic:data.isPublic});
    }
    if(url.pathname==='/api/admin/delete'){
      if(!isAdmin(req)) return send(res,401,{error:'관리자 로그인이 필요합니다.'});
      data.comments=data.comments.filter(c=>c.id!==b.id);save();return send(res,200,{ok:true});
    }
    return send(res,404,{error:'not found'});
  }
  if(url.pathname.startsWith('/api/')) return send(res,404,{error:'not found'});
  let p=url.pathname==='/'?'/index.html':url.pathname;
  const file=path.normalize(path.join(PUB,p));
  if(!file.startsWith(PUB)) return send(res,403,{error:'forbidden'});
  serveFile(res,file,mime[path.extname(file)]||'application/octet-stream');
}).listen(PORT,()=>console.log(`Tongkkang site running: http://localhost:${PORT}`));
