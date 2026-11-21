/* Add a focused Oracle action to source-backed textual sections.
   Text and its id are supplied by the public context manifest, never inferred by AI. */
(()=>{
 "use strict";
 const page=location.pathname.split("/").pop()?.replace(/\.html$/,"");
 if(!["model","feniks","demo"].includes(page))return;
 const start=async()=>{
   let items;
   try{
     const response=await fetch("assets/context.json",{cache:"no-cache"});
     if(!response.ok)return;
     const data=await response.json();
     if(data?.version!==1||!Array.isArray(data.items))return;
     items=data.items;
   }catch{return;}
   for(const item of items){
     if(item?.page!==page||item?.type!=="text"||
        !/^[a-z][a-z0-9-]*$/.test(item.section||"")||
        item.id!=="text:"+page+":"+item.section||
        typeof item.title!=="string")continue;
     const section=document.getElementById(item.section);
     if(!section||!section.classList.contains("content-section")||
        section.querySelector(".focus-discuss"))continue;
     const h2=section.querySelector("h2");
     if(!h2)continue;
     const link=document.createElement("a");
     link.className="focus-discuss";
     link.href="oracle.html?source="+page+"&focus="+encodeURIComponent(item.id);
     link.target="_blank";
     link.rel="noopener noreferrer";
     link.textContent="Обговорити з Оракулом ↗";
     link.setAttribute("aria-label","Обговорити з Оракулом: "+item.title);
     h2.insertAdjacentElement("afterend",link);
   }
 };
 if(document.readyState==="loading")document.addEventListener("DOMContentLoaded",start,{once:true});
 else start();
})();
