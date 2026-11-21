/* Shared topical update registry. Nothing is fabricated: only published items from
   assets/updates.json appear in the sidebar and complete archive. */
(()=>{
"use strict";
const TOPICS=["model","feniks","demo"];
const labels={model:"Модель середовища",feniks:"Фенікс",demo:"Демонстраційна модель"};
const node=(tag,cls,content)=>{
  const x=document.createElement(tag);
  if(cls)x.className=cls;
  if(content!==undefined)x.textContent=content;
  return x;
};
function normalize(entry){
  if(!entry||typeof entry!=="object")return null;
  const id=String(entry.id||"").trim();
  const title=String(entry.title||"").trim();
  const summary=String(entry.summary||"").trim();
  const date=String(entry.date||"").trim();
  const topics=Array.isArray(entry.topics)?entry.topics.filter(t=>TOPICS.includes(t)):[];
  const type=["publication","authorial","discussion"].includes(entry.type)?entry.type:"publication";
  const source=String(entry.source||"").trim().slice(0,120);
  const uri=String(entry.url||"").trim();
  if(!/^[a-z0-9][a-z0-9-]{0,55}$/i.test(id)||
    !title||title.length>180||!summary||summary.length>650||
    !/^\d{4}-\d{2}-\d{2}$/.test(date)||
    !Number.isFinite(Date.parse(date+"T12:00:00Z"))||
    !topics.length||new Set(topics).size!==topics.length)return null;
  if(uri){
    try{
      const u=new URL(uri);
      if(u.protocol!=="https:")return null;
    }catch{return null;}
  }
  return {id,title,summary,date,topics,type,source,url:uri};
}
const types={publication:"Зовнішня публікація",authorial:"Авторська актуалізація",discussion:"Тема для обговорення"};
function dateLabel(date){
  return new Date(date+"T12:00:00Z").toLocaleDateString("uk-UA",{year:"numeric",month:"long",day:"numeric",timeZone:"UTC"});
}
function card(item,compact=false){
  const article=node("article",compact?"updates-entry compact":"updates-entry");
  const info=node("div","updates-meta");
  info.append(node("span",null,dateLabel(item.date)));
  info.append(node("span",null," · "+types[item.type]));
  if(item.source)info.append(node("span",null," · "+item.source));
  article.append(info);
  const h=node(compact?"h3":"h2","updates-entry-title");
  if(item.url){
    const a=node("a",null,item.title);
    a.href=item.url;a.target="_blank";a.rel="noopener noreferrer";
    h.append(a);
  }else h.textContent=item.title;
  article.append(h);
  article.append(node("p","updates-summary",item.summary));
  if(!compact){
    const themes=node("p","updates-topics");
    themes.textContent=item.topics.map(t=>labels[t]).join(" · ");
    article.append(themes);
  }
  return article;
}
const EMPTY="Публікацій поки немає.";
function renderSidebar(el,items){
  const topic=el.dataset.updatesSidebar;
  if(!TOPICS.includes(topic))return;
  const list=el.querySelector(".updates-sidebar-list");
  if(!list)return;
  // Leave the header and "Всі статті" link always visible; scroll only the previews.
  const subset=items.filter(x=>x.topics.includes(topic)).slice(0,12);
  list.replaceChildren();
  if(!subset.length)list.append(node("p","updates-empty","Публікацій за цією темою поки немає."));
  else for(const item of subset)list.append(card(item,true));
}
function renderArchive(el,items){
  const list=el.querySelector("[data-updates-list]");
  const search=el.querySelector("[data-updates-search]");
  const select=el.querySelector("[data-updates-filter]");
  const counter=el.querySelector("[data-updates-count]");
  if(!list||!search||!select||!counter)return;
  const params=new URLSearchParams(location.search);
  const initialTopic=params.get("topic");
  if(TOPICS.includes(initialTopic))select.value=initialTopic;
  function refresh(){
    const query=search.value.trim().toLocaleLowerCase("uk-UA");
    const topic=select.value;
    const result=items.filter(item=>
      (topic==="all"||item.topics.includes(topic))&&
      (!query||(item.title+" "+item.summary+" "+item.source).toLocaleLowerCase("uk-UA").includes(query))
    );
    list.replaceChildren();
    counter.textContent=result.length===0?"Матеріалів не знайдено.":"Матеріалів: "+result.length;
    if(!result.length)list.append(node("p","updates-empty",items.length? "Нічого не знайдено за обраними умовами.":EMPTY));
    else for(const item of result)list.append(card(item));
  }
  search.addEventListener("input",refresh);
  select.addEventListener("change",refresh);
  refresh();
}
async function init(){
  const sides=[...document.querySelectorAll("[data-updates-sidebar]")];
  const archive=document.querySelector("[data-updates-archive]");
  if(!sides.length&&!archive)return;
  try{
    const r=await fetch("assets/updates.json",{cache:"no-cache"});
    if(!r.ok)throw Error("missing");
    const data=await r.json();
    if(data?.version!==1||!Array.isArray(data.items)||data.items.length>1000)
      throw Error("invalid");
    const used=new Set();
    const items=data.items.map(normalize).filter(x=>{
      if(!x||used.has(x.id))return false;
      used.add(x.id);return true;
    }).sort((a,b)=>b.date.localeCompare(a.date)||a.id.localeCompare(b.id));
    for(const el of sides)renderSidebar(el,items);
    if(archive)renderArchive(archive,items);
  }catch{
    for(const el of sides){
      const list=el.querySelector(".updates-sidebar-list");
      if(list)list.replaceChildren(node("p","updates-empty","Добірка тимчасово недоступна."));
    }
    if(archive){
      const list=archive.querySelector("[data-updates-list]");
      if(list)list.replaceChildren(node("p","updates-empty","Не вдалося завантажити перелік. Спробуйте оновити сторінку."));
    }
  }
}
if(document.readyState==="loading")document.addEventListener("DOMContentLoaded",init,{once:true});
else init();
})();
