/* Private unread message badge for a verified member in the current browser tab.
   No notification contents are visible to logged-out users. */
(function(){
"use strict";
const KEY="oracle-member-session-v1";
const API="https://oracle-api.andrewdonenko.workers.dev";
const nodes=[...document.querySelectorAll("[data-chat-link]")];
if(!nodes.length)return;
let busy=false;
async function check(){
  if(busy)return;
  let token;try{token=sessionStorage.getItem(KEY)}catch{token=null}
  for(const node of nodes){
    const badge=node.querySelector("[data-chat-badge]");
    if(badge)badge.hidden=true;
  }
  if(!/^[a-f0-9]{64}$/.test(token||""))return;
  busy=true;
  try{
    const r=await fetch(API+"/access/chat/unread",{
      headers:{Authorization:"Bearer "+token},cache:"no-store"});
    if(!r.ok)return;
    const data=await r.json();
    const count=Number(data.unread||0);
    for(const node of nodes){
      const badge=node.querySelector("[data-chat-badge]");
      if(!badge)continue;
      badge.hidden=count<1;
      badge.textContent=count>99?"99+":String(count);
      node.setAttribute("aria-label",count>0?"Повідомлення: "+count+" непрочитаних відповідей":"Повідомлення");
    }
  }catch{/* Notification polling never interrupts the public page. */}
  finally{busy=false}
}
check();
document.addEventListener("visibilitychange",()=>{if(document.visibilityState==="visible")check()});
window.addEventListener("pageshow",check);
window.addEventListener("focus",check);
window.addEventListener("storage",e=>{if(e.key===KEY)check()});
window.addEventListener("oracle-login",check);
setInterval(()=>{if(document.visibilityState==="visible")check()},30000);
})();
