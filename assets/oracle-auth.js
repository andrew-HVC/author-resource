/* Oracle client access: one trial/browser, email OTP, opt-in analytics.
 * No OpenAI keys or billing secrets are stored on this client. */
(function(){
  "use strict";
  const API="https://oracle-api.andrewdonenko.workers.dev";
  const GUEST_KEY="oracle-guest-credential-v1";
  const MEMBER_KEY="oracle-member-session-v1";
  const EMAIL_KEY="oracle-member-email-v1";
  const state={mode:"legacy",credential:"",config:null,challengeToken:"",
    widget:null,ready:false,remaining:null};
  const $ = id => document.getElementById(id);
  const hex = n => [...crypto.getRandomValues(new Uint8Array(n))]
    .map(x=>x.toString(16).padStart(2,"0")).join("");
  const api = async (path,body,auth)=>{
    const controller=new AbortController();
    const abort=setTimeout(()=>controller.abort(),20000);
    try{
      const r=await fetch(API+path,{
        method:body===undefined?"GET":"POST",
        headers:{"Content-Type":"application/json",...(auth?{Authorization:"Bearer "+auth}:{})},
        ...(body===undefined?{}:{body:JSON.stringify(body)}),
        signal:controller.signal,cache:"no-store"
      });
      const data=await r.json();
      if(!r.ok)throw Error(data?.error||("HTTP "+r.status));
      return data;
    }finally{clearTimeout(abort)}
  };
  function status(text,kind="info"){
    const el=$("access-status");
    if(el){el.textContent=text;el.dataset.state=kind;}
  }
  function limit(value){
    if(typeof value==="number")state.remaining=value;
    const el=$("access-remaining");
    if(el)el.textContent=state.remaining===null?"":(
      state.remaining>0?"Залишилося запитань: "+state.remaining:
      "Ліміт запитань вичерпано. Для продовження потрібна реєстрація або наступний день."
    );
  }
  function showMode(mode,credential){
    state.mode=mode;
    state.credential=credential||"";
    const input=$("token");
    if(input){
      input.required=mode==="legacy";
      input.disabled=mode!=="legacy";
    }
    const tabs=$("access-tabs");
    if(tabs)tabs.querySelectorAll("[data-mode]").forEach(b=>{
      b.setAttribute("aria-pressed",String(b.dataset.mode===mode));
    });
    const guest=$("access-guest");
    const member=$("access-member");
    if(guest)guest.hidden=mode!=="guest";
    if(member)member.hidden=mode!=="member";
    const legacy=$("legacy-auth");
    if(legacy)legacy.open=mode==="legacy"&&!state.config?.db_enabled;
    const info=$("access-identity");
    if(info)info.textContent=mode==="member"?"Зареєстрований користувач":
      mode==="guest"?"Гостьова пробна сесія":"Тестовий доступ";
  }
  function turnstileDone(token){state.challengeToken=token;status("Перевірку пройдено. Можна продовжувати.");}
  function prepareTurnstile(){
    if(!state.config?.turnstile_site_key)return;
    if(state.widget!==null)return;
    const node=$("access-turnstile");
    if(!node)return;
    if(window.turnstile && typeof window.turnstile.render==="function"){
      state.widget=window.turnstile.render(node,{
        sitekey:state.config.turnstile_site_key,
        callback:turnstileDone,
        "expired-callback":()=>{state.challengeToken="";status("Повторіть перевірку.");},
        "error-callback":()=>{state.challengeToken="";status("Перевірка недоступна. Спробуйте пізніше.","error");}
      });
      return;
    }
    if(document.getElementById("turnstile-script"))return;
    const script=document.createElement("script");
    script.id="turnstile-script";
    script.src="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
    script.async=true;
    script.onload=()=>prepareTurnstile();
    script.onerror=()=>status("Сервіс перевірки тимчасово недоступний.","error");
    document.head.append(script);
  }
  function resetChallenge(){
    state.challengeToken="";
    if(state.widget!==null&&window.turnstile)window.turnstile.reset(state.widget);
  }
  async function memberStatus(credential){
    const data=await api("/access/me",undefined,credential);
    if(data.kind!=="member")throw Error("Invalid login session");
    showMode("member",credential);
    limit(data.remaining);
    status("Ви увійшли. Можна ставити запитання.");
    const signin=$("access-signin-fields");
    if(signin)signin.hidden=true;
    const active=$("access-signed-in");
    if(active)active.hidden=false;
  }
  async function resume(){
    const member=sessionStorage.getItem(MEMBER_KEY);
    if(member){
      try{await memberStatus(member);return true;}
      catch{sessionStorage.removeItem(MEMBER_KEY);}
    }
    const guest=localStorage.getItem(GUEST_KEY);
    if(guest){
      try{
        const data=await api("/access/me",undefined,guest);
        if(data.kind==="guest"){
          showMode("guest",guest);limit(data.remaining);
          status(data.remaining?"Продовжуйте пробний діалог.":"Пробна сесія завершена. Зареєструйтеся.");
          return true;
        }
      }catch{/* Initial guest session may not have been activated. */}
    }
    return false;
  }
  async function startGuest(){
    if(!state.config?.guest_enabled){status("Гостьовий доступ поки не налаштовано.","error");return}
    let key=localStorage.getItem(GUEST_KEY);
    if(!key){key=hex(32);localStorage.setItem(GUEST_KEY,key);}
    status("Перевіряємо доступ до гостьової сесії…");
    try{
      const data=await api("/access/guest",{guest_key:key,
        turnstile_token:state.challengeToken||""});
      showMode("guest",key);limit(data.remaining);
      if(data.remaining>0)status("Пробну сесію відкрито. Поставте своє питання.");
      else status("Гостьову сесію завершено. Увійдіть через email.");
      resetChallenge();
    }catch(e){
      status(!state.challengeToken?"Пройдіть перевірку нижче й натисніть ще раз.":e.message,"error");
      prepareTurnstile();
    }
  }
  async function startEmail(){
    if(!state.config?.member_enabled){status("Реєстрацію ще не налаштовано.","error");return}
    const email=String($("access-email")?.value||"").trim();
    if(!email){status("Вкажіть email.","error");return;}
    if(!state.challengeToken){prepareTurnstile();status("Пройдіть перевірку нижче й повторіть.","error");return}
    status("Надсилаємо код для входу…");
    try{
      await api("/access/email/start",{email,turnstile_token:state.challengeToken});
      $("access-code-wrap").hidden=false;
      status("Перевірте пошту. Код дійсний 10 хвилин.");
      resetChallenge();
    }catch(e){status(e.message,"error");resetChallenge();}
  }
  async function verifyEmail(){
    const email=String($("access-email")?.value||"").trim();
    const code=String($("access-code")?.value||"").trim();
    if(!/^\d{6}$/.test(code)){status("Введіть 6 цифр коду.","error");return}
    status("Перевіряємо код…");
    try{
      const data=await api("/access/email/verify",{email,code});
      sessionStorage.setItem(MEMBER_KEY,data.token);
      sessionStorage.setItem(EMAIL_KEY,email);
      await memberStatus(data.token);
      $("access-code").value="";
    }catch(e){status(e.message,"error");}
  }
  function feedback(node,id){
    if(!id||!state.credential||!node)return;
    const box=document.createElement("div");box.className="oracle-feedback";
    const label=document.createElement("span");label.textContent="Відповідь була корисною?";
    box.append(label);
    for(const [value,caption] of [[1,"Так"],[-1,"Ні"]]){
      const btn=document.createElement("button");
      btn.type="button";btn.textContent=caption;
      btn.addEventListener("click",async()=>{
        try{
          await api("/access/feedback",{question_id:id,value},state.credential);
          box.replaceChildren(document.createTextNode("Дякуємо за оцінку."));
        }catch{box.replaceChildren(document.createTextNode("Оцінку не вдалося зберегти."));}
      });
      box.append(btn);
    }
    node.append(box);
  }
  async function init(){
    if(!$("access-panel"))return;
    try{
      state.config=await api("/access/config");
      if(!state.config.db_enabled){
        status("Гостьовий доступ і реєстрація ще налаштовуються. Поки доступний тестовий пароль.");
        showMode("legacy");
        return;
      }
      await resume();
      const guest=$("access-start-guest");
      const signup=$("access-start-email");
      if(guest)guest.disabled=!state.config.guest_enabled;
      if(signup)signup.disabled=!state.config.member_enabled;
      const explanation=$("access-config-note");
      if(explanation)explanation.textContent=
        "Без реєстрації: "+state.config.guest_limit+" запитань у пробній сесії. "+
        "Після входу: до "+state.config.member_daily_limit+" запитань на день.";
      if(!state.credential){
        showMode(state.config.guest_enabled?"guest":"member");
        status("Оберіть спосіб входу до Оракула.");
      }
      state.ready=true;
    }catch(e){
      showMode("legacy");
      status("Сервіс авторизації недоступний. Для адміністрування використовуйте тестовий пароль.","error");
    }
  }
  document.addEventListener("DOMContentLoaded",()=>{
    $("access-tabs")?.addEventListener("click",event=>{
      const button=event.target.closest("[data-mode]");
      if(!button)return;
      const mode=button.dataset.mode;
      if(mode==="member"&&state.credential&&state.mode==="member"){return}
      if(mode==="guest"&&state.credential&&state.mode==="guest"){return}
      showMode(mode,mode==="legacy"?"":(mode==="member"?sessionStorage.getItem(MEMBER_KEY):localStorage.getItem(GUEST_KEY)));
      if(mode==="guest"||mode==="member")prepareTurnstile();
      if(mode==="member"&&state.credential){memberStatus(state.credential).catch(()=>{});}
      if(mode==="guest"&&state.credential){
        api("/access/me",undefined,state.credential).then(d=>limit(d.remaining)).catch(()=>{});
      }
    });
    $("access-start-guest")?.addEventListener("click",startGuest);
    $("access-start-email")?.addEventListener("click",startEmail);
    $("access-verify-email")?.addEventListener("click",verifyEmail);
    $("access-logout")?.addEventListener("click",async()=>{
      const current=state.credential;
      try{await api("/access/logout",{},current);}catch{}
      sessionStorage.removeItem(MEMBER_KEY);sessionStorage.removeItem(EMAIL_KEY);
      state.credential="";
      showMode("member");$("access-signin-fields").hidden=false;
      $("access-signed-in").hidden=true;
      limit(null);status("Ви вийшли з облікового запису.");
    });
    $("access-delete")?.addEventListener("click",async()=>{
      if(!confirm("Видалити обліковий запис і пов'язані з ним записи діалогів?"))return;
      try{
        await api("/access/privacy/delete",{},state.credential);
        sessionStorage.removeItem(MEMBER_KEY);
        sessionStorage.removeItem(EMAIL_KEY);
        location.reload();
      }catch(e){status("Видалення не виконано: "+e.message,"error");}
    });
    init();
  });
  window.OracleAccess={
    credential:()=>state.credential||($("token")?.value||""),
    consent:()=>$("access-consent")?.checked===true,
    source:()=>{const v=new URLSearchParams(location.search).get("source");
      return ["model","feniks","demo"].includes(v)?v:"oracle";},
    onAnswer:data=>{
      if(typeof data.remaining==="number")limit(data.remaining);
      if(state.mode==="guest"&&data.remaining===0)
        status("Пробна сесія завершена. Для наступних запитань увійдіть через email.");
    },
    onError:(statusCode,message)=>{
      if(statusCode===429)status(message+" Перейдіть до входу через email.","error");
    },
    feedback
  };
})();