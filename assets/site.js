(function(){
  "use strict";
  // Public counters: total recorded views and distinct anonymous browser IDs.
  // The server persists only an HMAC of the browser's random ID, not an IP/name.
  const currentPage=location.pathname.endsWith("/feniks.html")?"feniks":
    location.pathname.endsWith("/demo.html")?"demo":
    location.pathname.endsWith("/model.html")?"model":null;
  const counter=document.querySelector("[data-public-counter]");
  if(counter&&currentPage){
    const API="https://oracle-api.andrewdonenko.workers.dev";
    const totalEl=counter.querySelector("[data-counter-total]");
    const uniqueEl=counter.querySelector("[data-counter-unique]");
    const note=counter.querySelector("[data-counter-note]");
    const modes=[...counter.querySelectorAll("[data-counter-scope]")];
    const format=new Intl.NumberFormat("uk-UA");
    let stats=null,scope="page";
    function render(){
      for(const button of modes)button.setAttribute("aria-pressed",
        String(button.dataset.counterScope===scope));
      const values=scope==="site"?stats?.site:stats?.current_page;
      totalEl.textContent=Number.isFinite(values?.total_views)?
        format.format(values.total_views):"—";
      uniqueEl.textContent=Number.isFinite(values?.unique_browsers)?
        format.format(values.unique_browsers):"—";
      if(stats&&note){
        const date=stats.started_at?
          new Date(stats.started_at*1000).toLocaleDateString("uk-UA"):"дня запуску";
        note.textContent="Облік із "+date+
          ". Унікальні — різні браузери з постійним випадковим ідентифікатором, не окремі люди.";
      }
    }
    for(const button of modes)button.addEventListener("click",()=>{
      scope=button.dataset.counterScope==="site"?"site":"page";
      render();
    });
    function visitorId(){
      const key="ms-public-visitor-v1";
      let value=localStorage.getItem(key);
      if(!/^[a-f0-9]{64}$/.test(value||"")){
        const bytes=crypto.getRandomValues(new Uint8Array(32));
        value=Array.from(bytes,x=>x.toString(16).padStart(2,"0")).join("");
        localStorage.setItem(key,value);
      }
      return value;
    }
    async function recordAndLoad(){
      let identifier=null;
      try{identifier=visitorId();}catch{/* Private storage may be blocked. */}
      const marker="ms-public-pageview-v1:"+currentPage+":"+
        new Date().toISOString().slice(0,10);
      if(identifier){
        let already=false;
        try{already=sessionStorage.getItem(marker)==="1";}catch{}
        if(!already){
          try{
            const response=await fetch(API+"/access/pageview",{
              method:"POST",
              headers:{"Content-Type":"application/json"},
              body:JSON.stringify({source_page:currentPage,visitor_id:identifier}),
              cache:"no-store"
            });
            if(response.ok){
              stats=await response.json();
              try{sessionStorage.setItem(marker,"1");}catch{}
            }
          }catch{/* The public page remains readable during outages. */}
        }
      }
      if(!stats){
        try{
          const response=await fetch(API+"/access/counters?page="+currentPage,
            {cache:"no-store"});
          if(response.ok)stats=await response.json();
        }catch{}
      }
      if(!stats&&note)note.textContent=
        "Статистика стане доступною після підключення Cloudflare D1. Показники поки не сформовані.";
      render();
    }
    recordAndLoad();
  }
  // The same Oracle test interface is displayed inside a single retained iframe.
  // Keeping the iframe mounted when folded preserves the active dialog on this page.
  const oracleShell=document.querySelector("[data-oracle-shell]");
  if(oracleShell){
    const toggle=oracleShell.querySelector("[data-oracle-trigger]");
    const drawer=oracleShell.querySelector("[data-oracle-drawer]");
    const close=oracleShell.querySelector("[data-oracle-close]");
    const iframe=oracleShell.querySelector("[data-oracle-frame]");
    if(toggle&&drawer&&close&&iframe){
      let hasLoaded=false;
      let lastFocus=null;
      function updateHeaderHeight(){
        document.documentElement.style.setProperty("--oracle-header-height",
          Math.ceil(oracleShell.getBoundingClientRect().bottom)+"px");
      }
      function focusOracleInput(){
        try{
          if(drawer.hidden||!iframe.contentDocument)return;
          const doc=iframe.contentDocument;
          const token=doc.getElementById("token");
          const question=doc.getElementById("question");
          const target=(token&&!token.value)?token:question;
          if(target)target.focus({preventScroll:true});
        }catch(error){
          // Browser privacy rules may prevent access if the hosting origin changes.
          iframe.focus({preventScroll:true});
        }
      }
      function fold(returnFocus=true){
        if(drawer.hidden)return;
        drawer.hidden=true;
        toggle.setAttribute("aria-expanded","false");
        if(returnFocus)toggle.focus({preventScroll:true});
      }
      function unfold(){
        lastFocus=document.activeElement;
        updateHeaderHeight();
        drawer.hidden=false;
        toggle.setAttribute("aria-expanded","true");
        if(!hasLoaded){
          const source=location.pathname.endsWith("/feniks.html")?"feniks":
            location.pathname.endsWith("/demo.html")?"demo":"model";
          iframe.src="oracle.html?embedded=1&source="+encodeURIComponent(source);
          hasLoaded=true;
        }else{
          window.requestAnimationFrame(focusOracleInput);
        }
      }
      iframe.addEventListener("load",()=>{
        if(!drawer.hidden)window.requestAnimationFrame(focusOracleInput);
      });
      toggle.addEventListener("click",()=>{
        if(drawer.hidden)unfold();
        else fold();
      });
      close.addEventListener("click",()=>fold());
      document.addEventListener("keydown",event=>{
        if(event.key==="Escape"&&!drawer.hidden)fold();
      });
      document.addEventListener("pointerdown",event=>{
        if(!drawer.hidden&&!oracleShell.contains(event.target))fold(false);
      });
      window.addEventListener("resize",updateHeaderHeight,{passive:true});
      updateHeaderHeight();
    }
  }
  const panel = document.querySelector("[data-inquiry]");
  if(!panel) return;
  const interest=panel.querySelector("[name=interest]");
  const intent=panel.querySelector("[name=intent]");
  const message=panel.querySelector("[name=message]");
  const copy=panel.querySelector("[data-copy]");
  const status=panel.querySelector("[role=status]");
  const params=new URLSearchParams(location.search);
  const selected=params.get("topic");
  if(selected&&[...interest.options].some(o=>o.value===selected))interest.value=selected;
  const intentParam=params.get("intent");
  if(intentParam&&[...intent.options].some(o=>o.value===intentParam))intent.value=intentParam;
  function draft(){
    const issue=params.get("issue");
    const lines=["Вітаю!","", "Мене цікавить «"+interest.value+"».","Формат участі: "+intent.value+"."];
    if(params.get("focus")==="author")lines.push("Маю питання до автора Моделі середовища.");
    if(params.get("focus")==="demo")lines.push("Мене цікавить участь у громадській передпроєктній роботі та підготовці Демонстраційної моделі.");
    if(issue)lines.push("Предмет уточнення з Оракула: "+issue.slice(0,250));
    lines.push("", "Моє питання або можливий внесок: ");
    message.value=lines.join("\n");status.textContent="";
  }
  interest.addEventListener("change",draft);
  intent.addEventListener("change",draft);
  draft();
  // Preserve the intent of older Oracle links after the root homepage was removed.
  if(params.get("focus")==="demo" || params.get("focus")==="author" || params.has("issue")) {
    requestAnimationFrame(()=>{
      const target=document.getElementById("participate");
      if(target) target.scrollIntoView({block:"start"});
    });
  }
  copy.addEventListener("click",async()=>{
    if(!message.value.trim()){status.textContent="Спочатку додайте текст звернення.";return}
    try {await navigator.clipboard.writeText(message.value);status.textContent="Текст скопійовано. Це ще не надсилання звернення.";}
    catch {message.focus();message.select();status.textContent="Текст виділено. Натисніть Ctrl+C або Command+C.";}
  });

  // Contact delivery remains disabled unless server confirms D1 + Turnstile.
  const contact=panel.querySelector(".contact-delivery");
  if(contact){
    const API="https://oracle-api.andrewdonenko.workers.dev";
    const send=contact.querySelector("[data-send-contact]");
    const note=contact.querySelector("[data-delivery-status]");
    const email=contact.querySelector("[name=contact_email]");
    const consent=contact.querySelector("#contact-consent");
    const challenge=contact.querySelector("#contact-turnstile");
    let sitekey="",token="",widget=null,enabled=false,loading=false;
    const statusText=(message)=>{note.textContent=message;};
    function loadChallenge(){
      if(!sitekey||widget!==null)return;
      if(window.turnstile?.render){
        widget=window.turnstile.render(challenge,{
          sitekey,callback(value){token=value;send.disabled=false;
            statusText("Перевірку завершено. Можна надіслати звернення.");},
          "expired-callback"(){token="";send.disabled=true;statusText("Повторіть перевірку.");},
          "error-callback"(){token="";send.disabled=true;statusText("Перевірка тимчасово недоступна.");}
        });
        return;
      }
      if(document.getElementById("contact-turnstile-script"))return;
      const script=document.createElement("script");
      script.id="contact-turnstile-script";
      script.src="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
      script.async=true;
      script.onload=loadChallenge;
      script.onerror=()=>statusText("Не вдалося завантажити перевірку.");
      document.head.append(script);
    }
    fetch(API+"/access/config",{cache:"no-store"}).then(async response=>{
      if(!response.ok)throw Error("Access configuration unavailable");
      const cfg=await response.json();
      if(!cfg.contact_enabled || !cfg.turnstile_site_key){
        statusText("Надсилання звернень поки не активоване. Ви можете скопіювати текст вище.");
        return;
      }
      sitekey=cfg.turnstile_site_key;enabled=true;
      statusText("Пройдіть перевірку, щоб надіслати повідомлення.");
      loadChallenge();
    }).catch(()=>statusText("Сервер поки не приймає звернень. Текст можна скопіювати."));
    send.addEventListener("click",async()=>{
      if(!enabled||loading||!token)return;
      if(!consent.checked){statusText("Для надсилання потрібно погодитися з обробкою звернення.");return;}
      if(!email.validity.valid||!email.value.trim()){statusText("Вкажіть дійсну електронну пошту.");return;}
      if(message.value.trim().length<15||message.value.trim().length>5000){
        statusText("Текст звернення має містити від 15 до 5000 символів.");return;
      }
      loading=true;send.disabled=true;statusText("Надсилаємо звернення…");
      try{
        const source=location.pathname.endsWith("/feniks.html")?"feniks":
          location.pathname.endsWith("/demo.html")?"demo":"model";
        const response=await fetch(API+"/access/contact",{
          method:"POST",headers:{"Content-Type":"application/json"},
          body:JSON.stringify({
            source_page:source,interest:interest.value,intent:intent.value,
            message:message.value.trim(),email:email.value.trim(),
            contact_consent:true,turnstile_token:token
          })
        });
        const data=await response.json();
        if(!response.ok||!data.received)throw Error(data.error||"Server error");
        statusText("Звернення отримано та збережено для розгляду. Дякуємо!");
        consent.checked=false;
        // Prevent accidental duplicates; drafting remains available.
        enabled=false;
      }catch(error){
        statusText("Не вдалося надіслати: "+error.message);
      }finally{
        token="";loading=false;
        if(widget!==null&&window.turnstile&&enabled){
          window.turnstile.reset(widget);send.disabled=true;
        }
      }
    });
  }
})();