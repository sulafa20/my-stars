import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const root=path.dirname(fileURLToPath(import.meta.url));
// For local development only: load .env without extra dependencies
if(fs.existsSync(path.join(root,'.env'))) for(const line of fs.readFileSync(path.join(root,'.env'),'utf8').split(/\r?\n/)) {
  const m=line.match(/^\s*([A-Z_]+)\s*=\s*(.*)\s*$/);if(m&&!process.env[m[1]])process.env[m[1]]=m[2];
}
const PIN=process.env.ADMIN_PIN;
if(!PIN||PIN.includes('CHANGE_THIS')||PIN.length<8) { console.error('Set ADMIN_PIN (8+ characters) in .env or host environment.'); process.exit(1); }
const dataDir=path.resolve(root,process.env.DATA_DIR||'./data');
fs.mkdirSync(dataDir,{recursive:true});
const file=path.join(dataDir,'students.json');
const seed=JSON.parse(fs.readFileSync(path.join(root,'seed-data.json'),'utf8'));
const app=express();app.disable('x-powered-by');app.use(express.json({limit:'2mb'}));
app.use((req,res,next)=>{res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('X-Frame-Options','DENY');next()});
const normalize=s=>String(s||'').normalize('NFKC').replace(/[\u064B-\u065F\u0670\u0640]/g,'').replace(/[أإآٱ]/g,'ا').replace(/ى/g,'ي').replace(/ة/g,'ه').replace(/\s+/g,' ').trim().toLowerCase();
const library=[
 'Your kindness makes the world a softer, brighter place. Never underestimate the power of your beautiful heart.',
 'You have wonderful ideas waiting to be discovered. Be curious, ask questions, and let your imagination lead the way.',
 'Every small step you take matters. Your effort today is building something amazing for tomorrow.',
 'You are braver than you think. Trying something new is already a beautiful kind of success.',
 'Your voice and your ideas are important. Keep sharing them with confidence and joy.',
 'Your creativity is a gift. Keep exploring, making, and seeing the world in your own special way.',
 'Difficult moments do not define you. Your patience and courage help you grow stronger every day.',
 'There is so much potential inside you. Give yourself time to learn, shine, and surprise yourself.',
 'Your thoughtful actions can make someone’s day better. Keep spreading that quiet magic.',
 'Believe in your journey. You do not have to know everything today; learning is a beautiful adventure.',
 'Your determination is inspiring. Keep going, even when progress comes one little step at a time.',
 'You bring your own sparkle to every room. Stay true to yourself and celebrate what makes you unique.',
 'You are capable of learning wonderful things. Ask, practice, discover, and keep your heart open.',
 'Your dreams deserve your effort. A little curiosity and courage can take you to surprising places.',
 'The way you keep trying matters more than getting everything right the first time.',
 'Your gentle heart and strong spirit are both treasures. Let them guide you toward lovely things.',
 'Great ideas often start with a simple question. Never stop wondering what is possible.',
 'Take pride in your growth. Every new word, new skill, and new attempt is worth celebrating.',
 'You have a bright future to create, one thoughtful choice and courageous step at a time.',
 'Even on rainy days, your light is still there. Rest, try again, and keep believing in yourself.'
];
const hash=s=>{let h=2166136261;for(const c of s)h=Math.imul(h^c.charCodeAt(0),16777619);return h>>>0};
const defaultMessage=name=>library[hash(normalize(name))%library.length];
let students;
if(fs.existsSync(file)) students=JSON.parse(fs.readFileSync(file,'utf8'));
else {students=seed.map((s,i)=>({...s,id:crypto.randomUUID(),message:library[(hash(normalize(s.name))+i)%library.length]}));save()}
function save(){const tmp=file+'.tmp';fs.writeFileSync(tmp,JSON.stringify(students,null,2));fs.renameSync(tmp,file)}
const sessions=new Map();const attempts=new Map();const TTL=8*60*60*1000;
const cookieName='teacher_session';
function session(req){const id=(req.headers.cookie||'').split(';').map(s=>s.trim()).find(s=>s.startsWith(cookieName+'='))?.slice(cookieName.length+1);const exp=sessions.get(id);if(!exp||exp<Date.now()){if(id)sessions.delete(id);return false}return true}
function admin(req,res,next){if(!session(req))return res.status(401).json({error:'يرجى تسجيل الدخول للوحة المعلمة'});next()}
function validName(s){return typeof s==='string'&&s.trim().length>=2&&s.length<=100}
const lookupLimits=new Map();
app.post('/api/message',(req,res)=>{
 const ip=req.ip;const now=Date.now();const old=lookupLimits.get(ip)||{n:0,until:now+60000};const t=now>old.until?{n:0,until:now+60000}:old;t.n++;lookupLimits.set(ip,t);if(t.n>35)return res.status(429).json({error:'حاولي مجددًا بعد قليل'});
 const name=String(req.body?.name||'').slice(0,100);if(!validName(name))return res.status(400).json({error:'اكتبي اسمكِ الأول والثاني'});
 const found=students.filter(s=>normalize(s.name)===normalize(name));
 // Ambiguous names across classes: return a general uplifting note rather than another student's private note.
 const selected=found.length===1?found[0]:null;
 res.json({name:selected?.name||name.trim().replace(/\s+/g,' '),message:selected?.message||defaultMessage(name),closing:'I am proud of you, and I believe beautiful things are ahead of you.'});
});
app.post('/api/admin/login',(req,res)=>{
 const key=req.ip;const now=Date.now();const a=attempts.get(key)||{n:0,until:now+15*60000};if(now>a.until){a.n=0;a.until=now+15*60000}
 if(a.n>=8){attempts.set(key,a);return res.status(429).json({error:'محاولات كثيرة. حاولي بعد 15 دقيقة.'})}
 const input=String(req.body?.pin||'');const ah=crypto.createHash('sha256').update(input).digest(),bh=crypto.createHash('sha256').update(PIN).digest();
 if(!crypto.timingSafeEqual(ah,bh)){a.n++;attempts.set(key,a);return res.status(401).json({error:'رمز الدخول غير صحيح'})}
 attempts.delete(key);const id=crypto.randomBytes(32).toString('hex');sessions.set(id,now+TTL);
 res.cookie(cookieName,id,{httpOnly:true,sameSite:'strict',secure:process.env.SECURE_COOKIES==='1',maxAge:TTL,path:'/'}).json({ok:true});
});
app.post('/api/admin/logout',admin,(req,res)=>{const id=(req.headers.cookie||'').split(';').map(s=>s.trim()).find(s=>s.startsWith(cookieName+'='))?.slice(cookieName.length+1);sessions.delete(id);res.clearCookie(cookieName,{path:'/'}).json({ok:true})});
app.get('/api/admin/students',admin,(req,res)=>res.json({students,library}));
app.post('/api/admin/students',admin,(req,res)=>{
 const name=String(req.body.name||'').trim().replace(/\s+/g,' '),className=String(req.body.className||'').trim().slice(0,40),message=String(req.body.message||'').trim();
 if(!validName(name)||message.length>1600)return res.status(400).json({error:'تحققي من الاسم وطول الرسالة'});
 if(students.some(s=>normalize(s.name)===normalize(name)&&s.className===className))return res.status(409).json({error:'هذا الاسم موجود في الفصل نفسه'});
 const item={id:crypto.randomUUID(),name,className,message:message||defaultMessage(name)};students.push(item);save();res.json({student:item});
});
app.put('/api/admin/students/:id',admin,(req,res)=>{
 const s=students.find(x=>x.id===req.params.id);if(!s)return res.status(404).json({error:'الطالبة غير موجودة'});
 const name=String(req.body.name||'').trim().replace(/\s+/g,' '),className=String(req.body.className||'').trim().slice(0,40),message=String(req.body.message||'').trim();
 if(!validName(name)||!message||message.length>1600)return res.status(400).json({error:'تحققي من الاسم والرسالة'});
 if(students.some(x=>x.id!==s.id&&normalize(x.name)===normalize(name)&&x.className===className))return res.status(409).json({error:'هذا الاسم موجود في الفصل نفسه'});
 Object.assign(s,{name,className,message});save();res.json({student:s});
});
app.delete('/api/admin/students/:id',admin,(req,res)=>{students=students.filter(x=>x.id!==req.params.id);save();res.json({ok:true})});
app.post('/api/admin/import',admin,(req,res)=>{
 const raw=String(req.body.text||'');if(raw.length>100000)return res.status(400).json({error:'القائمة طويلة جدًا'});
 let added=0,skipped=0;const className=String(req.body.className||'').trim().slice(0,40);
 for(const line of raw.split(/\r?\n/).slice(0,1000)){
  const name=line.replace(/^\s*\d+[.)\-]\s*/,'').trim().replace(/\s+/g,' ');if(!validName(name)){if(name)skipped++;continue}
  if(students.some(s=>normalize(s.name)===normalize(name)&&s.className===className)){skipped++;continue}
  students.push({id:crypto.randomUUID(),name,className,message:defaultMessage(name)});added++;
 }
 save();res.json({added,skipped});
});
app.post('/api/admin/generate',admin,(req,res)=>{
 const s=students.find(x=>x.id===req.body.id);if(!s)return res.status(404).json({error:'غير موجود'});
 const n=Number(req.body.index);s.message=library[Number.isInteger(n)&&n>=0&&n<library.length?n:crypto.randomInt(library.length)];save();res.json({student:s});
});
app.get('/api/admin/export',admin,(req,res)=>{res.setHeader('Content-Type','application/json; charset=utf-8');res.setHeader('Content-Disposition','attachment; filename="student-messages.json"');res.send(JSON.stringify(students.map(({name,className,message})=>({name,className,message})),null,2))});
app.use(express.static(path.join(root,'public'),{index:'index.html'}));
app.listen(Number(process.env.PORT)||3000,()=>console.log('Site running on port '+(process.env.PORT||3000)));
