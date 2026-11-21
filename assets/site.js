(function(){
  "use strict";
  // Aggregate public pageviews without cookies, names or IP storage.
  // A single event per thematic page per tab/day avoids accidental double counting.
  const currentPage=location.pathname.endsWith("/feniks.html")?"feniks":
    location.pathname.endsWith("/demo.html")?"demo":
    location.pathname.endsWith("/model.html")?"model":null;
  if(currentPage){
    try{
      const marker="oracle-pageview:"+currentPage+":"+new Date().toISOString().slice(0,10);
      if(!sessionStorage.getItem(marker)){
        fetch("https://oracle-api.andrewdonenko.workers.dev/access/pageview",{
          method:"POST",headers:{"Content-Type":"application/json"},
          body:JSON.stringify({source_page:currentPage}),keepalive:true
        }).then(response=>{if(response.ok)sessionStorage.setItem(marker,"1");}).catch(()=>{});
      }
    }catch{/* Visit analytics must not interrupt the public content. */}
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