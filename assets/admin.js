/* Oracle administration: no private payload is embedded into static HTML. */
(function(){
 "use strict";
 const API="https://oracle-api.andrewdonenko.workers.dev";
 const $=id=>document.getElementById(id);
 const el=(tag,text,className)=>{
   const e=document.createElement(tag);
   if(text!==undefined&&text!==null)e.textContent=String(text);
   if(className)e.className=className;
   return e;
 };
 const formatNum=n=>new Intl.NumberFormat("uk-UA").format(Number(n||0));
 const time=n=>n?new Date(Number(n)*1000).toLocaleString("uk-UA"):"—";
 const normalize=v=>String(v??"").toLocaleLowerCase("uk-UA").replace(/\s+/g," ").trim();
 const classify=text=>{
  const t=String(text||"");
  const rules=[
   ["Екологія",/еколог|довкіл|природ|ґрунт|грунт|водн|екосистем|рекультив/iu],
   ["Енергетика",/енергі|енергет|гак|гідроакум|сонячн|електр|накопич/iu],
   ["Інфраструктура",/інфраструктур|транспорт|коридор|логіст|віадук|дорог|перевезен/iu],
   ["Фенікс",/фенікс|зруйнован|відбудов|післявоєн|розмінуван/iu],
   ["Агровиробництво",/агро|зерн|поле|культур|рослин|біотехнолог|агроробот/iu],
   ["Економіка",/економ|вартіст|грош|kwatt|редемпц|фракталь|капітал|облік/iu],
   ["Цифрові системи",/цифров|алгоритм|програм|інтелект|датацентр|керуюч|моделюван/iu],
   ["Суспільство",/соціаль|громад|людськ|антропоном|суспільств|кластер|спільнот/iu]
  ];
  return rules.find(([name,re])=>re.test(t))?.[0]||"Загальні питання";
 };
 let secret="";
 let overview=null;
 let searchRows=[];
 const errText=(text)=>{$("dashboard-error").textContent=text||"";};
 const req=async (path,opt={})=>{
   if(!secret)throw Error("Потрібен адміністративний ключ");
   const response=await fetch(API+path,{
     method:opt.method||"GET",
     headers:{"Authorization":"Bearer "+secret,...(opt.method?{"Content-Type":"application/json"}:{})},
     ...(opt.body?{body:JSON.stringify(opt.body)}:{}),
     cache:"no-store"
   });
   if(opt.blob){
     if(!response.ok)throw Error("Помилка експорту: "+response.status);
     return response.blob();
   }
   const data=await response.json();
   if(!response.ok)throw Error(data?.error||"Помилка сервера: "+response.status);
   return data;
 };
 const drawBars=(rootId,items,field="count",label="topic")=>{
   const root=$(rootId);root.replaceChildren();
   const arr=Array.isArray(items)?items.filter(x=>Number(x[field])>0):[];
   if(!arr.length){root.append(el("div","Немає даних за обраний період.","empty"));return;}
   const max=Math.max(1,...arr.map(x=>Number(x[field]||0)));
   arr.slice(0,12).forEach(row=>{
     const item=el("div",null,"bar-row");
     const title=el("span",row[label]||"Невідомо","name");
     title.title=String(row[label]||"Невідомо");
     const track=el("div",null,"bar-bg");
     const fill=el("div",null,"bar-fill");
     fill.style.width=Math.max(1,Math.round(Number(row[field])/max*100))+"%";
     track.append(fill);
     item.append(title,track,el("span",formatNum(row[field]),"number"));root.append(item);
   });
 };
 function renderOverview(data){
   overview=data;
   const t=data.totals||{};
   $("kpi-questions").textContent=formatNum(t.questions);
   $("kpi-visitors").textContent=formatNum(t.visitors);
   $("kpi-members").textContent=formatNum(t.members);
   $("kpi-tokens").textContent=formatNum(Number(t.input_tokens||0)+Number(t.output_tokens||0));
   $("kpi-pageviews").textContent=formatNum(t.pageviews);
   $("kpi-cost").textContent=(typeof t.estimated_cost_usd==="number")?
     "$"+t.estimated_cost_usd.toFixed(3):"—";
   $("kpi-guests").textContent=formatNum(t.guests);
   $("kpi-members2").textContent=formatNum(t.members);
   $("kpi-optins").textContent=formatNum(t.saved_texts);
   $("kpi-positive").textContent=formatNum(t.feedback_helpful);
   $("kpi-contacts").textContent=formatNum(t.contacts);
   $("feedback-totals").textContent=
     "Корисно: "+formatNum(t.feedback_helpful)+" · Не допомогло: "+formatNum(t.feedback_unhelpful)+".";
   $("privacy-totals").textContent=
     "Тексти за згодою: "+formatNum(t.saved_texts)+
     ". Усі інші питання зберігаються тільки як метадані. Дані за останні 30 днів.";
   drawBars("topics-chart",data.topics||[]);
   drawBars("pages-chart",data.pages||[],"count","source_page");
   const topic=$("question-topic"),current=topic.value;
   topic.replaceChildren(el("option","Усі теми"));
   topic.firstChild.value="";
   for(const row of data.topics||[]){
     const opt=el("option",row.topic);opt.value=row.topic;topic.append(opt);
   }
   topic.value=current&&[...topic.options].some(x=>x.value===current)?current:"";
   if(searchRows.length)compareSearch(searchRows);
 }
 async function loadOverview(){
   const data=await req("/admin/overview");
   renderOverview(data);
 }
 async function loadQuestions(){
   const topic=$("question-topic").value;
   const query="/admin/questions?limit=200"+(topic?"&topic="+encodeURIComponent(topic):"");
   const data=await req(query);
   const root=$("question-rows");
   root.replaceChildren();
   if(!(data.questions||[]).length){
     const tr=el("tr");const td=el("td","Немає звернень за вибраними умовами.");td.colSpan=5;tr.append(td);root.append(tr);return;
   }
   for(const q of data.questions){
     const tr=el("tr");
     for(const v of [
       time(q.created_at),q.topic||"—",q.source_page||"—",
       q.stored_with_consent?String(q.question_text||"Термін зберігання минув"):"[Без згоди на збереження тексту]",
       q.feedback===1?"Корисно":q.feedback===-1?"Не відповідає":"—"
     ])tr.append(el("td",v));
     tr.children[3].className="question";
     root.append(tr);
   }
 }
 async function loadContacts(){
   const data=await req("/admin/contacts");
   const root=$("contact-rows");root.replaceChildren();
   const rows=data.contacts||[];
   if(!rows.length){const tr=el("tr"),td=el("td","Поки немає надісланих звернень.");td.colSpan=7;tr.append(td);root.append(tr);return;}
   for(const item of rows){
     const tr=el("tr");
     for(const value of [
       time(item.created_at),item.interest||"—",item.intent||"—",
       item.contact_email||"—",item.message||"—",item.status||"new"
     ]){
       const td=el("td",value);tr.append(td);
     }
     tr.children[4].className="question";
     const last=el("td");
     if(item.status!=="closed"){
       const button=el("button",item.status==="new"?"Прочитано":"Закрити");
       button.type="button";
       button.addEventListener("click",async()=>{
         button.disabled=true;
         try{
           await req("/admin/contacts/update",{method:"POST",body:{
             id:item.id,status:item.status==="new"?"read":"closed"
           }});
           await loadContacts();
         }catch(error){errText(error.message);button.disabled=false;}
       });
       last.append(button);
     }else last.append(el("span","Завершено","muted"));
     tr.append(last);root.append(tr);
   }
 }
 async function exportCSV(){
   const topic=$("question-topic").value;
   const blob=await req("/admin/export?limit=200"+(topic?"&topic="+encodeURIComponent(topic):""),{blob:true});
   const url=URL.createObjectURL(blob);
   const a=document.createElement("a");a.href=url;a.download="oracle-questions.csv";
   document.body.append(a);a.click();a.remove();
   setTimeout(()=>URL.revokeObjectURL(url),1500);
 }
 // Parse quoted CSV from Search Console locally; Excel may use ";".
 function parseCSV(text){
   const src=String(text||"").replace(/^\uFEFF/,"");
   const firstLine=src.split(/\r?\n/)[0]||"";
   const d=(firstLine.match(/;/g)||[]).length>(firstLine.match(/,/g)||[]).length?";":",";
   const rows=[];let row=[],value="",quoted=false;
   for(let i=0;i<src.length;i++){
     const c=src[i];
     if(c==='"'){
       if(quoted&&src[i+1]==='"'){value+='"';i++;}
       else quoted=!quoted;
     }else if(c===d&&!quoted){row.push(value);value="";}
     else if((c==="\n"||c==="\r")&&!quoted){
       if(c==="\r"&&src[i+1]==="\n")i++;
       row.push(value);if(row.some(x=>x.trim()))rows.push(row);
       row=[];value="";
     }else value+=c;
   }
   row.push(value);if(row.some(x=>x.trim()))rows.push(row);
   return rows;
 }
 const numberCell=x=>{
   const n=String(x||"").trim().replace(/[\u00A0\s]/g,"").replace("%","");
   return Number(n.replace(",","."))||0;
 };
 const parseSearchCSV=text=>{
   const rows=parseCSV(text);
   if(rows.length<2)return [];
   const titles=rows[0].map(normalize);
   const find=(names)=>titles.findIndex(x=>names.some(n=>x.includes(n)));
   const q=find(["query","top queries","запит","пошукові"]);
   const clicks=find(["clicks","кліки","клики"]);
   const impr=find(["impressions","покази"]);
   const page=find(["page","url","сторінк"]);
   if(q<0||impr<0)throw Error("Не знайдено стовпці запитів та показів у CSV Search Console");
   return rows.slice(1).filter(row=>String(row[q]||"").trim()).slice(0,5000).map(row=>({
     query:String(row[q]||"").slice(0,250),page:page>=0?String(row[page]||""):"",
     impressions:numberCell(row[impr]),clicks:clicks>=0?numberCell(row[clicks]):0,
     topic:classify(row[q])
   }));
 };
 function compareSearch(rows){
   const totals=new Map();
   for(const q of rows){
     const topic=q.topic||classify(q.query);
     const old=totals.get(topic)||0;totals.set(topic,old+Number(q.impressions||0));
   }
   const arr=[...totals].map(([topic,impressions])=>({topic,impressions}))
     .sort((a,b)=>b.impressions-a.impressions);
   drawBars("gsc-chart",arr,"impressions","topic");
   const root=$("gsc-compare");root.replaceChildren();
   if(!arr.length){root.append(el("div","Немає даних для зіставлення."));return;}
   const counts=new Map((overview?.topics||[]).map(x=>[x.topic,Number(x.count||0)]));
   for(const item of arr.slice(0,8)){
     const p=el("p",item.topic+": "+formatNum(item.impressions)+
       " показів у Google / "+formatNum(counts.get(item.topic)||0)+" запитань Оракулу.");
     root.append(p);
   }
   root.append(el("p","Це тематичне зіставлення двох агрегованих джерел, а не статистична кореляція між окремими користувачами.","note"));
 }
 function renderSearch(rows){
   searchRows=rows;
   compareSearch(rows);
   const root=$("gsc-rows");root.replaceChildren();
   if(!rows.length){const tr=el("tr");const cell=el("td","Немає даних");cell.colSpan=5;tr.append(cell);root.append(tr);return;}
   for(const v of rows.slice(0,150).sort((a,b)=>b.impressions-a.impressions)){
     const tr=el("tr");
     for(const item of [v.query,v.page||"—",formatNum(v.impressions),formatNum(v.clicks),v.topic||classify(v.query)]){
       const td=el("td",item);tr.append(td);
     }
     root.append(tr);
   }
 }
 async function syncSearch(){
   $("gsc-status").textContent="Отримуємо дані…";
   try{
     const data=await req("/admin/search");
     if(!data.configured){
       $("gsc-status").textContent="API не підключено. Імпортуйте CSV локально або налаштуйте доступ Google.";
       return;
     }
     $("gsc-status").textContent="Дані "+data.start+" — "+data.end+" · "+data.rows.length+" рядків.";
     renderSearch(data.rows);
   }catch(e){$("gsc-status").textContent="Search Console недоступна: "+e.message;}
 }
 async function report(){
   const btn=$("generate-insights");btn.disabled=true;
   $("insights-status").textContent="Формуємо звіт на основі фактичних звернень…";
   try{
     const data=await req("/admin/insights",{method:"POST",body:{}});
     if(!data.available)throw Error(data.error||"Звіт недоступний");
     $("insights-report").textContent=data.report;
     $("insights-status").textContent="Проаналізовано прикладів запитань за згодою: "+data.sample_count;
   }catch(e){$("insights-status").textContent="Помилка: "+e.message;}
   finally{btn.disabled=false;}
 }
 function tab(id){
   for(const b of document.querySelectorAll("[data-tab]"))
     b.setAttribute("aria-selected",String(b.dataset.tab===id));
   for(const view of document.querySelectorAll("[data-view]"))view.hidden=view.dataset.view!==id;
   errText("");
   if(id==="questions")loadQuestions().catch(e=>errText(e.message));
   if(id==="contacts")loadContacts().catch(e=>errText(e.message));
 }
 async function login(){
   const entered=$("admin-secret").value.trim();
   if(!entered){$("login-error").textContent="Введіть ключ адміністратора.";return;}
   secret=entered;
   $("admin-login").disabled=true;
   try{
     await loadOverview();
     $("admin-secret").value="";
     $("login").hidden=true;$("dashboard").hidden=false;
     $("login-error").textContent="";
   }catch(e){
     secret="";$("login-error").textContent=e.message;
   }finally{$("admin-login").disabled=false;}
 }
 $("admin-login").addEventListener("click",login);
 $("admin-secret").addEventListener("keydown",e=>{if(e.key==="Enter")login();});
 $("admin-logout").addEventListener("click",()=>{
   secret="";overview=null;searchRows=[];$("dashboard").hidden=true;
   $("login").hidden=false;$("login-error").textContent="";
   $("admin-secret").focus();
 });
 for(const b of document.querySelectorAll("[data-tab]"))
   b.addEventListener("click",()=>tab(b.dataset.tab));
 $("questions-refresh").addEventListener("click",()=>loadQuestions().catch(e=>errText(e.message)));
 $("contacts-refresh").addEventListener("click",()=>loadContacts().catch(e=>errText(e.message)));
 $("questions-export").addEventListener("click",()=>exportCSV().catch(e=>errText(e.message)));
 $("gsc-sync").addEventListener("click",syncSearch);
 $("gsc-file").addEventListener("change",async e=>{
   const file=e.target.files?.[0];if(!file)return;
   try{
     const rows=parseSearchCSV(await file.text());
     renderSearch(rows);
     $("gsc-status").textContent="CSV відкрито локально: "+formatNum(rows.length)+" рядків.";
   }catch(err){$("gsc-status").textContent=err.message;}
 });
 $("generate-insights").addEventListener("click",report);
})();