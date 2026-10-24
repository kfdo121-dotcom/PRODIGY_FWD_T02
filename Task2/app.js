"use strict";
const $=s=>document.querySelector(s), enc=new TextEncoder(), dec=new TextDecoder();
const ITER=210000, IDLE_MS=10*60*1000, MAX_FAILS=5, LOCK_MS=60000;
const DEPTS=["Engineering","Finance","HR","Marketing","Operations","Sales","Support"];
const STATUS=["Active","On leave","Terminated"];
const FIELDS=[
 ["firstName","First name","text"],["lastName","Last name","text"],["email","Work email","email"],["phone","Phone","tel"],
 ["department","Department","select",DEPTS],["title","Job title","text"],["salary","Annual salary (USD)","number"],
 ["hireDate","Hire date","date"],["nationalId","National ID","text"],["status","Status","select",STATUS]];
const S={key:null,user:"",emp:[],editing:null,reveal:false,last:Date.now(),deleting:null};

/* ---------- helpers ---------- */
const b64=u=>btoa(String.fromCharCode(...new Uint8Array(u)));
const unb64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const rd=k=>{try{return JSON.parse(localStorage.getItem(k))}catch(e){return null}};
const wr=(k,v)=>{try{localStorage.setItem(k,JSON.stringify(v));return true}catch(e){return false}};
function toast(m){const t=$("#toast");t.textContent=m;t.classList.add("on");clearTimeout(toast.t);toast.t=setTimeout(()=>t.classList.remove("on"),2600)}
async function base(pw){return crypto.subtle.importKey("raw",enc.encode(pw),"PBKDF2",false,["deriveBits","deriveKey"])}
async function hashPw(pw,salt){return b64(await crypto.subtle.deriveBits({name:"PBKDF2",salt,iterations:ITER,hash:"SHA-256"},await base(pw),256))}
async function dataKey(pw,salt){return crypto.subtle.deriveKey({name:"PBKDF2",salt,iterations:ITER,hash:"SHA-256"},await base(pw),{name:"AES-GCM",length:256},false,["encrypt","decrypt"])}
async function save(){
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const ct=await crypto.subtle.encrypt({name:"AES-GCM",iv},S.key,enc.encode(JSON.stringify(S.emp)));
  return wr("sl_data",{iv:b64(iv),ct:b64(ct)});
}
async function load(){
  const d=rd("sl_data"); if(!d) return [];
  const pt=await crypto.subtle.decrypt({name:"AES-GCM",iv:unb64(d.iv)},S.key,unb64(d.ct));
  return JSON.parse(dec.decode(pt));
}
const strongPw=p=>p.length>=12&&/[a-z]/.test(p)&&/[A-Z]/.test(p)&&/\d/.test(p)&&/[^A-Za-z0-9]/.test(p);

/* ---------- authentication ---------- */
function authMode(){
  const setup=!rd("sl_auth"); S.setup=setup;
  $("#aSub").textContent=setup?"Create the administrator account to get started.":"Sign in to manage employee records.";
  $("#aBtn").textContent=setup?"Create admin account":"Sign in";
  $("#confWrap").classList.toggle("hide",!setup);
  $("#aPass").autocomplete=setup?"new-password":"current-password";
  $("#aNote").textContent=setup
    ?"Use 12+ characters with upper and lower case letters, a number and a symbol. Records are encrypted with a key derived from this password, so it cannot be recovered. Keep it safe."
    :"After 5 failed attempts sign-in locks for 60 seconds. Sessions end after 10 minutes of inactivity.";
  $("#resetBtn").classList.toggle("hide",setup);
}
async function submitAuth(){
  const err=m=>{$("#aErr").textContent=m};err("");
  const user=$("#aUser").value.trim(), pw=$("#aPass").value;
  if(!/^[A-Za-z0-9_.-]{3,40}$/.test(user)) return err("Username must be 3–40 letters, numbers, dots, dashes or underscores.");
  $("#aBtn").disabled=true;
  try{
    if(S.setup){
      if(!strongPw(pw)) return err("Password needs 12+ characters with upper and lower case letters, a number and a symbol.");
      if(pw!==$("#aConf").value) return err("Passwords don’t match.");
      const salt=crypto.getRandomValues(new Uint8Array(16)), ksalt=crypto.getRandomValues(new Uint8Array(16));
      wr("sl_auth",{user,salt:b64(salt),ksalt:b64(ksalt),hash:await hashPw(pw,salt)});
      S.key=await dataKey(pw,ksalt); S.emp=[]; await save();
    }else{
      const lock=rd("sl_lock")||{fails:0,until:0};
      if(Date.now()<lock.until) return err("Too many attempts. Try again in "+Math.ceil((lock.until-Date.now())/1000)+" seconds.");
      const a=rd("sl_auth"), h=await hashPw(pw,unb64(a.salt));
      if(user!==a.user||h!==a.hash){
        lock.fails++; if(lock.fails>=MAX_FAILS){lock.until=Date.now()+LOCK_MS;lock.fails=0}
        wr("sl_lock",lock); return err("Username or password is incorrect.");
      }
      wr("sl_lock",{fails:0,until:0});
      S.key=await dataKey(pw,unb64(a.ksalt)); S.emp=await load();
    }
    S.user=user; $("#aPass").value=$("#aConf").value=""; enter();
  }catch(e){err("Could not sign in. Stored data may be damaged.")}
  finally{$("#aBtn").disabled=false}
}
function enter(){
  $("#auth").classList.add("hide");$("#app").classList.remove("hide");
  $("#who").textContent="Signed in as "+S.user; S.last=Date.now(); render();
}
function signOut(msg){
  S.key=null;S.emp=[];S.reveal=false;S.user="";
  $("#app").classList.add("hide");$("#auth").classList.remove("hide");
  ["formDlg","delDlg"].forEach(i=>{const d=$("#"+i);if(d.open)d.close()});
  $("#aErr").textContent=msg||""; authMode();
}
["click","keydown","touchstart"].forEach(e=>document.addEventListener(e,()=>S.last=Date.now(),{passive:true}));
setInterval(()=>{if(S.key&&Date.now()-S.last>IDLE_MS) signOut("You were signed out after 10 minutes of inactivity.")},15000);

/* ---------- validation ---------- */
function validate(v,id){
  const e={}, nm=/^\p{L}[\p{L}\s'’.-]{1,49}$/u;
  if(!nm.test(v.firstName)) e.firstName="Enter 2–50 letters.";
  if(!nm.test(v.lastName)) e.lastName="Enter 2–50 letters.";
  if(!/^[^\s@]{1,64}@[^\s@]+\.[^\s@]{2,}$/.test(v.email)||v.email.length>120) e.email="Enter a valid email address.";
  else if(S.emp.some(x=>x.id!==id&&x.email.toLowerCase()===v.email.toLowerCase())) e.email="Another employee already uses this email.";
  if(!/^\+?[0-9 ()-]{7,20}$/.test(v.phone)) e.phone="Use 7–20 digits; spaces, dashes, brackets and a leading + are allowed.";
  if(!DEPTS.includes(v.department)) e.department="Choose a department.";
  if(v.title.length<2||v.title.length>60) e.title="Enter 2–60 characters.";
  const s=Number(v.salary);
  if(v.salary===""||!Number.isFinite(s)||s<=0||s>10000000) e.salary="Enter an amount between 1 and 10,000,000.";
  const d=new Date(v.hireDate+"T00:00:00");
  if(!v.hireDate||isNaN(d)) e.hireDate="Pick a hire date.";
  else if(d>new Date()) e.hireDate="Hire date can’t be in the future.";
  else if(d.getFullYear()<1950) e.hireDate="Hire date must be 1950 or later.";
  if(!/^[A-Za-z0-9-]{5,20}$/.test(v.nationalId)) e.nationalId="Use 5–20 letters, numbers or dashes.";
  else if(S.emp.some(x=>x.id!==id&&x.nationalId.toLowerCase()===v.nationalId.toLowerCase())) e.nationalId="This National ID is already on file.";
  if(!STATUS.includes(v.status)) e.status="Choose a status.";
  return e;
}

/* ---------- CRUD UI ---------- */
function el(t,txt,cls){const n=document.createElement(t);if(txt!=null)n.textContent=txt;if(cls)n.className=cls;return n}
function render(){
  const q=$("#q").value.trim().toLowerCase(), tb=$("#rows"); tb.replaceChildren();
  const list=S.emp.filter(x=>!q||[x.firstName,x.lastName,x.email,x.department,x.title].join(" ").toLowerCase().includes(q))
    .sort((a,b)=>a.lastName.localeCompare(b.lastName));
  $("#empty").classList.toggle("hide",list.length>0);
  $("#empty").textContent=S.emp.length?"No employees match your search.":"No employees yet. Add the first record.";
  for(const x of list){
    const tr=el("tr");
    tr.append(el("td",x.firstName+" "+x.lastName),el("td",x.email),el("td",x.department),el("td",x.title));
    const st=el("td");st.append(el("span",x.status,"chip"));tr.append(st);
    tr.append(el("td",S.reveal?"$"+Number(x.salary).toLocaleString("en-US"):"••••••"));
    tr.append(el("td",S.reveal?x.nationalId:"•••• "+x.nationalId.slice(-2)));
    const a=el("td"),ed=el("button","Edit"),del=el("button","Delete");
    ed.setAttribute("aria-label","Edit "+x.firstName+" "+x.lastName);del.setAttribute("aria-label","Delete "+x.firstName+" "+x.lastName);
    ed.onclick=()=>openForm(x);del.onclick=()=>askDelete(x);
    a.append(ed," ",del);tr.append(a);tb.append(tr);
  }
}
function buildForm(){
  const g=$("#fields");
  for(const [k,label,type,opts] of FIELDS){
    const w=el("div"),l=el("label",label);l.htmlFor="f_"+k;
    let i;
    if(type==="select"){i=el("select");opts.forEach(o=>{const op=el("option",o);op.value=o;i.append(op)})}
    else{i=el("input");i.type=type;i.maxLength=k==="email"?120:60;if(type==="number"){i.min=1;i.step="any"}if(type==="date")i.max=new Date().toISOString().slice(0,10)}
    i.id="f_"+k;i.name=k;i.autocomplete="off";
    const er=el("p",null,"err");er.id="e_"+k;er.setAttribute("role","alert");
    w.append(l,i,er);g.append(w);
  }
}
function openForm(x){
  S.editing=x?x.id:null;$("#fTitle").textContent=x?"Edit employee":"Add employee";
  for(const [k] of FIELDS){$("#f_"+k).value=x?x[k]:(k==="status"?"Active":"");$("#e_"+k).textContent=""}
  $("#formDlg").showModal();$("#f_firstName").focus();
}
$("#form").addEventListener("submit",async ev=>{
  ev.preventDefault();
  const v={};for(const [k] of FIELDS)v[k]=$("#f_"+k).value.trim();
  const e=validate(v,S.editing);
  for(const [k] of FIELDS)$("#e_"+k).textContent=e[k]||"";
  const first=Object.keys(e)[0]; if(first){$("#f_"+first).focus();return}
  v.salary=Number(v.salary);
  const prev=JSON.stringify(S.emp);
  if(S.editing){const i=S.emp.findIndex(x=>x.id===S.editing);S.emp[i]={...S.emp[i],...v,updated:Date.now()}}
  else S.emp.push({id:crypto.randomUUID(),...v,created:Date.now()});
  if(!(await save())){S.emp=JSON.parse(prev);return toast("Couldn’t save. Browser storage is unavailable.")}
  $("#formDlg").close();render();toast(S.editing?"Employee updated.":"Employee added.");
});
function askDelete(x){S.deleting=x.id;$("#delMsg").textContent="This permanently removes "+x.firstName+" "+x.lastName+" ("+x.email+"). It can’t be undone.";$("#delDlg").showModal()}
$("#delYes").onclick=async()=>{
  const prev=S.emp;S.emp=S.emp.filter(x=>x.id!==S.deleting);
  if(!(await save())){S.emp=prev;toast("Couldn’t delete. Browser storage is unavailable.")}else toast("Employee deleted.");
  $("#delDlg").close();render();
};
$("#delNo").onclick=()=>$("#delDlg").close();
$("#fCancel").onclick=()=>$("#formDlg").close();
$("#addBtn").onclick=()=>openForm(null);
$("#q").oninput=render;
$("#revealBtn").onclick=e=>{S.reveal=!S.reveal;e.target.setAttribute("aria-pressed",S.reveal);e.target.textContent=S.reveal?"Hide sensitive fields":"Show sensitive fields";render()};
$("#outBtn").onclick=()=>signOut("");
$("#aBtn").onclick=submitAuth;
["aUser","aPass","aConf"].forEach(i=>$("#"+i).addEventListener("keydown",e=>{if(e.key==="Enter")submitAuth()}));
$("#resetBtn").onclick=()=>{if(confirm("Delete the admin account and ALL employee records stored in this browser?")){["sl_auth","sl_data","sl_lock"].forEach(k=>{try{localStorage.removeItem(k)}catch(e){}});authMode();toast("All data cleared.")}};
buildForm();authMode();
