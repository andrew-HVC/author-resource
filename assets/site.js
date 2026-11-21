(function(){
  "use strict";
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
  copy.addEventListener("click",async()=>{
    if(!message.value.trim()){status.textContent="Спочатку додайте текст звернення.";return}
    try {await navigator.clipboard.writeText(message.value);status.textContent="Текст скопійовано. Це ще не надсилання звернення.";}
    catch {message.focus();message.select();status.textContent="Текст виділено. Натисніть Ctrl+C або Command+C.";}
  });
})();