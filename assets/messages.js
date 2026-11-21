/* Private collaboration inbox. Uses the same verified member session as Oracle,
   with the credential kept in sessionStorage (never in a URL or localStorage). */
(function(){
"use strict";
const API="https://oracle-api.andrewdonenko.workers.dev";
const MEMBER_KEY="oracle-member-session-v1", EMAIL_KEY="oracle-member-email-v1";
const DRAFT_KEY="ms-chat-draft-v1";
const $=id=>document.getElementById(id);
const state={token:"",email:"",threadId:null,threads:[],lastSeq:0,ready:false,
  sitekey:"",challenge:"",widget:null,busy:false};
const time=t=>t?new Date(Number(t)*1000).toLocaleString("uk-UA"):"—";
const txt=(tag,text,cls)=>{const e=document.createElement(tag);e.textContent=String(text??"");if(cls)e.className=cls;return e;};
function notice(msg,error=false){$("chat-state").textContent=msg||"";$("chat-state").dataset.error=error?"true":"false";}
function storeGet(key){try{return sessionStorage.getItem(key)}catch{return null}}
function storeSet(key,value){try{sessionStorage.setItem(key,value)}catch{}}
function storeRemove(key){try{sessionStorage.removeItem(key)}catch{}}
async function req(path,{method="GET",body,auth=false}={}){
  const controller=new AbortController();
  const timeout=setTimeout(()=>controller.abort(),18000);
  try{
    const r=await fetch(API+path,{method,
      headers:{"Content-Type":"application/json",...(auth&&state.token?{Authorization:"Bearer "+state.token}:{})},
      ...(body===undefined?{}:{body:JSON.stringify(body)}),cache:"no-store",signal:controller.signal});
    let d;try{d=await r.json()}catch{d={}}
    if(!r.ok){
      if(r.status===401&&auth){state.token="";storeRemove(MEMBER_KEY);storeRemove(EMAIL_KEY);$("chat-app").hidden=true;$("chat-login").hidden=false;}
      throw Error(d.error||"Помилка сервера: "+r.status);
    }
    return d;
  }finally{clearTimeout(timeout)}
}
function renderChallenge(){
  if(!state.sitekey||state.widget!==null)return;
  const container=$("chat-turnstile");
  if(window.turnstile?.render){
    state.widget=window.turnstile.render(container,{
      sitekey:state.sitekey,callback:token=>{state.challenge=token;notice("Перевірку пройдено. Можна отримати код.");},
      "expired-callback":()=>{state.challenge="";notice("Потрібно повторити перевірку.");},
      "error-callback":()=>{state.challenge="";notice("Перевірка тимчасово недоступна.",true);}
    });
    return;
  }
  if(document.getElementById("chat-turnstile-script"))return;
  const sc=document.createElement("script");sc.id="chat-turnstile-script";
  sc.src="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
  sc.async=true;sc.onload=renderChallenge;
  sc.onerror=()=>notice("Не вдалося завантажити перевірку.",true);
  document.head.append(sc);
}
function resetChallenge(){
  state.challenge="";
  if(state.widget!==null&&window.turnstile)window.turnstile.reset(state.widget);
}
function loadDraft(){
  try{
    const raw=storeGet(DRAFT_KEY);
    if(!raw)return false;
    const d=JSON.parse(raw);
    if(!d||Date.now()-Number(d.created||0)>2*3600*1000){storeRemove(DRAFT_KEY);return false}
    if(["model","feniks","demo","oracle"].includes(d.source_page))state.source=d.source_page;
    const interest=$("chat-interest");
    if([...interest.options].some(x=>x.value===d.interest))interest.value=d.interest;
    const intent=$("chat-intent");
    if([...intent.options].some(x=>x.value===d.intent))intent.value=d.intent;
    $("chat-initial-message").value=String(d.message||"").slice(0,5000);
    return true;
  }catch{return false}
}
function compose(clear=false){
  state.threadId=null;state.lastSeq=0;
  $("chat-compose").hidden=false;$("chat-conversation").hidden=true;$("chat-empty").hidden=true;
  if(clear){
    storeRemove(DRAFT_KEY);
    $("chat-initial-message").value="";
    $("chat-consent").checked=false;
  }
}
function renderList(){
  const root=$("chat-threads");root.replaceChildren();
  const rows=state.threads;
  const unread=rows.reduce((n,x)=>n+Number(x.unread||0),0);
  const counter=$("chat-unread-count");
  counter.hidden=unread===0;counter.textContent=unread>99?"99+":String(unread);
  if(!rows.length){root.append(txt("p","Ваших звернень поки немає.","chat-none"));return}
  for(const t of rows){
    const b=txt("button","","chat-thread");
    b.type="button";
    b.classList.toggle("active",t.id===state.threadId);
    b.setAttribute("aria-current",String(t.id===state.threadId));
    const top=txt("div","","chat-thread-top");
    top.append(txt("strong",t.interest||"Звернення"));
    if(Number(t.unread||0)>0)top.append(txt("span",String(t.unread),"chat-pill"));
    b.append(top);
    b.append(txt("small",time(t.updated_at)+" · "+(t.status==="closed"?"Закрито":"Відкрито")));
    b.addEventListener("click",()=>openThread(t.id));
    root.append(b);
  }
}
async function loadThreads(){
  const data=await req("/access/chat/threads",{auth:true});
  state.threads=Array.isArray(data.threads)?data.threads:[];
  renderList();
}
async function openThread(id,quiet=false){
  if(!/^[0-9a-f-]{36}$/i.test(id))return;
  try{
    const d=await req("/access/chat/thread?id="+encodeURIComponent(id),{auth:true});
    if(!d.thread)return;
    const t=d.thread;
    state.threadId=t.id;
    $("chat-compose").hidden=true;$("chat-empty").hidden=true;$("chat-conversation").hidden=false;
    $("chat-thread-title").textContent=t.interest||"Діалог";
    $("chat-thread-summary").textContent=(t.intent||"")+" · "+time(t.created_at);
    $("chat-thread-state").textContent=t.status==="closed"?"Закрито":"Відкрито";
    const area=$("chat-messages");
    const latest=(d.messages||[]).at(-1)?.seq||0;
    if(!quiet||latest!==state.lastSeq){
      area.replaceChildren();
      for(const m of d.messages||[]){
        const row=txt("article","",m.sender==="member"?"chat-bubble mine":"chat-bubble admin");
        row.append(txt("strong",m.sender==="member"?"Ви":"Адміністратор"));
        row.append(txt("p",m.message||""));
        row.append(txt("small",time(m.created_at)));
        area.append(row);
      }
      state.lastSeq=latest;
      area.scrollTop=area.scrollHeight;
    }
    $("chat-reply-text").disabled=t.status!=="open";
    $("chat-reply-send").disabled=t.status!=="open";
    $("chat-closed-note").hidden=t.status==="open";
    await req("/access/chat/read",{method:"POST",auth:true,body:{thread_id:id}});
    await loadThreads();
    if(!quiet)notice("");
  }catch(e){notice(e.message,true)}
}
async function verifySession(){
  const token=storeGet(MEMBER_KEY);
  if(!token)return false;
  state.token=token;
  try{
    const d=await req("/access/me",{auth:true});
    if(d.kind!=="member")throw Error("Email-verified account required");
    state.email=d.email||storeGet(EMAIL_KEY)||"Підтверджений користувач";
    $("chat-current-email").textContent=state.email;
    $("chat-login").hidden=true;$("chat-app").hidden=false;
    await loadThreads();
    const draft=loadDraft();
    const hash=new URLSearchParams(location.search).get("thread");
    if(draft||new URLSearchParams(location.search).has("compose"))compose(false);
    else if(hash&&state.threads.some(x=>x.id===hash))await openThread(hash);
    else if(state.threads.length)await openThread(state.threads[0].id);
    else compose(false);
    notice("");
    return true;
  }catch{
    state.token="";storeRemove(MEMBER_KEY);storeRemove(EMAIL_KEY);
    $("chat-app").hidden=true;return false;
  }
}
async function init(){
  let config;
  try{config=await req("/access/config")}catch{notice("Сервіс повідомлень поки не підключено.",true);return}
  if(!config.db_enabled||!config.member_enabled||!config.chat_enabled){
    notice("Переписка стане доступною після підключення Cloudflare D1, поштової авторизації та нового Worker.",true);
    return;
  }
  state.ready=true;state.sitekey=config.turnstile_site_key;
  if(await verifySession())return;
  $("chat-login").hidden=false;
  const previous=storeGet(EMAIL_KEY);
  if(previous)$("chat-email").value=previous;
  renderChallenge();
  notice("Для доступу до особистих повідомлень увійдіть через email.");
}
async function sendCode(){
  if(state.busy)return;
  if(!state.challenge){notice("Спочатку пройдіть перевірку.",true);renderChallenge();return}
  const email=$("chat-email").value.trim();
  if(!$("chat-email").validity.valid||!email){notice("Вкажіть коректний email.",true);return}
  state.busy=true;$("chat-send-code").disabled=true;
  notice("Надсилаємо код підтвердження…");
  try{
    await req("/access/email/start",{method:"POST",body:{email,turnstile_token:state.challenge}});
    $("chat-code-area").hidden=false;notice("Код надіслано. Перевірте email. Код дійсний 10 хвилин.");
  }catch(e){notice(e.message,true)}
  finally{state.busy=false;$("chat-send-code").disabled=false;resetChallenge()}
}
async function verifyCode(){
  if(state.busy)return;
  const email=$("chat-email").value.trim(),code=$("chat-code").value.trim();
  if(!/^\d{6}$/.test(code)){notice("Введіть шестизначний код.",true);return}
  state.busy=true;$("chat-verify").disabled=true;
  try{
    const d=await req("/access/email/verify",{method:"POST",body:{email,code}});
    if(d.kind!=="member"||!/^[a-f0-9]{64}$/.test(d.token||""))
      throw Error("Не вдалося відкрити сесію.");
    state.token=d.token;state.email=d.email||email;
    storeSet(MEMBER_KEY,d.token);storeSet(EMAIL_KEY,state.email);
    $("chat-current-email").textContent=state.email;
    $("chat-login").hidden=true;$("chat-app").hidden=false;
    await loadThreads();
    if(loadDraft()||new URLSearchParams(location.search).has("compose"))compose(false);
    else if(state.threads.length)await openThread(state.threads[0].id);
    else compose(false);
    notice("");
  }catch(e){notice(e.message,true)}
  finally{state.busy=false;$("chat-verify").disabled=false}
}
async function submitNew(){
  if(state.busy)return;
  if(!$("chat-consent").checked){notice("Для переписки потрібна згода на обробку повідомлень.",true);return}
  const message=$("chat-initial-message").value.trim();
  if(message.length<15||message.length>5000){notice("Звернення має містити 15–5000 символів.",true);return}
  const body={source_page:state.source||"model",
    interest:$("chat-interest").value,intent:$("chat-intent").value,
    message,contact_consent:true};
  state.busy=true;$("chat-start").disabled=true;notice("Надсилаємо звернення…");
  try{
    const d=await req("/access/chat/start",{method:"POST",auth:true,body});
    if(!d.created)throw Error("Звернення не збережено.");
    storeRemove(DRAFT_KEY);
    $("chat-initial-message").value="";$("chat-consent").checked=false;
    await loadThreads();await openThread(d.thread_id);
    notice("Звернення отримано. Відповідь з’явиться в цьому діалозі.");
  }catch(e){notice(e.message,true)}
  finally{state.busy=false;$("chat-start").disabled=false}
}
async function reply(){
  if(state.busy||!state.threadId)return;
  const message=$("chat-reply-text").value.trim();
  if(!message||message.length>5000){notice("Введіть повідомлення до 5000 символів.",true);return}
  state.busy=true;$("chat-reply-send").disabled=true;
  try{
    const d=await req("/access/chat/reply",{method:"POST",auth:true,body:{
      thread_id:state.threadId,message}});
    if(!d.sent)throw Error("Повідомлення не збережене.");
    $("chat-reply-text").value="";
    await openThread(state.threadId);
    notice("Повідомлення надіслано.");
  }catch(e){notice(e.message,true)}
  finally{state.busy=false;if(!$("chat-closed-note").hidden)$("chat-reply-send").disabled=true;else $("chat-reply-send").disabled=false}
}
document.addEventListener("DOMContentLoaded",()=>{
  $("chat-send-code").addEventListener("click",sendCode);
  $("chat-verify").addEventListener("click",verifyCode);
  $("chat-new").addEventListener("click",()=>{state.source="model";compose(true);});
  $("chat-start").addEventListener("click",submitNew);
  $("chat-reply-send").addEventListener("click",reply);
  $("chat-logout").addEventListener("click",async()=>{
    const token=state.token;
    try{if(token)await req("/access/logout",{method:"POST",auth:true,body:{}})}catch{}
    state.token="";state.threadId=null;state.threads=[];
    storeRemove(MEMBER_KEY);storeRemove(EMAIL_KEY);
    $("chat-app").hidden=true;$("chat-login").hidden=false;
    $("chat-code-area").hidden=true;notice("Ви вийшли з облікового запису.");
    renderChallenge();
  });
  const q=new URLSearchParams(location.search);
  state.source=["model","feniks","demo"].includes(q.get("source"))?q.get("source"):"model";
  init();
  setInterval(async()=>{
    if(!state.token||document.visibilityState!=="visible"||state.busy)return;
    try{
      await loadThreads();
      if(state.threadId)await openThread(state.threadId,true);
    }catch{/* No visible error for transient polling failures. */}
  },30000);
  window.addEventListener("pageshow",()=>{if(!state.token&&state.ready)verifySession().catch(()=>{});});
});
})();
