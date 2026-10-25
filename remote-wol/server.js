'use strict';
const http=require('node:http'),crypto=require('node:crypto'),fs=require('node:fs'),path=require('node:path');
const PORT=Number(process.env.PORT||10000);
const CLIENT=process.env.WOL_CLIENT_TOKEN||'',AGENT=process.env.WOL_ROUTER_TOKEN||'';
if(CLIENT.length<32||AGENT.length<32||CLIENT===AGENT){console.error('Missing distinct WOL secrets');process.exit(1);}
let job=null,lastRequest=0,agentLastSeen=0;
function same(a,b){if(typeof a!=='string'||typeof b!=='string')return false;return crypto.timingSafeEqual(crypto.createHash('sha256').update(a).digest(),crypto.createHash('sha256').update(b).digest());}
function auth(req,token){const a=req.headers.authorization||'';return a.startsWith('Bearer ')&&a.length<512&&same(a.slice(7),token);}
function send(res,code,v){res.writeHead(code,{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff'});res.end(JSON.stringify(v));}
const html=fs.readFileSync(path.join(__dirname,'index.html'),'utf8');
async function jsonbody(req){let str='';for await(const c of req){str+=c;if(str.length>1024)throw Error('too_large');}return str?JSON.parse(str):{};}
function expire(){if(job&&['queued','claimed'].includes(job.state)&&Date.now()-job.created>300000){job.state='expired';job.changed=Date.now();}}
http.createServer(async(req,res)=>{
 const u=new URL(req.url,'https://internal.local');
 if(req.method==='GET'&&u.pathname==='/'){res.writeHead(200,{'content-type':'text/html; charset=utf-8','cache-control':'no-store','x-frame-options':'DENY','referrer-policy':'no-referrer','content-security-policy':"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"});return res.end(html);}
 if(req.method==='GET'&&u.pathname==='/healthz')return send(res,200,{service:'noblekey-pc3-wol',ok:true,version:1});
 expire();
 if(u.pathname.startsWith('/api/')){
  if(!auth(req,CLIENT))return send(res,401,{error:'unauthorized'});
  if(req.method==='POST'&&u.pathname==='/api/wake'){
   if(Date.now()-lastRequest<30000)return send(res,429,{error:'wait_30_seconds'});
   if(job&&['queued','claimed'].includes(job.state))return send(res,202,{id:job.id,state:job.state});
   job={id:crypto.randomUUID(),state:'queued',created:Date.now(),changed:Date.now()};
   lastRequest=Date.now();return send(res,202,{id:job.id,state:'queued'});
  }
  if(req.method==='GET'&&u.pathname==='/api/status'){
   if(!job||u.searchParams.get('id')!==job.id)return send(res,404,{error:'no_matching_job'});
   return send(res,200,{id:job.id,state:job.state,agentLastSeen});
  }
  return send(res,404,{error:'not_found'});
 }
 if(u.pathname.startsWith('/agent/')){
  if(!auth(req,AGENT))return send(res,401,{error:'unauthorized'});
  agentLastSeen=Date.now();
  if(req.method==='GET'&&u.pathname==='/agent/next'){
   if(!job||job.state!=='queued')return send(res,200,{job:null});
   job.state='claimed';job.changed=Date.now();return send(res,200,{job:{id:job.id,action:'wake_pc3'}});
  }
  if(req.method==='POST'&&u.pathname==='/agent/complete'){
   try{const b=await jsonbody(req);if(!job||b.id!==job.id||job.state!=='claimed')return send(res,409,{error:'not_claimed'});if(!['sent','failed'].includes(b.state))return send(res,400,{error:'invalid_state'});job.state=b.state;job.changed=Date.now();return send(res,200,{accepted:true});}
   catch{return send(res,400,{error:'invalid_json'});}
  }
  return send(res,404,{error:'not_found'});
 }
 return send(res,404,{error:'not_found'});
}).listen(PORT,'0.0.0.0',()=>console.log('PC3 WOL gateway online'));