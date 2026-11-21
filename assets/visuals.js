/* Illustrations for authorial pages.
   Source: assets/visuals.json. Never generate placeholder content.
   Every item names its editorial section, caption, alt and evidence status. */
(()=>{
  "use strict";
  const page=(location.pathname.split("/").pop()||"").replace(/\.html$/,"");
  if(!["model","feniks","demo"].includes(page))return;
  const asset=/^assets\/media\/[a-zA-Z0-9_\-/]+\.(?:avif|webp|png|jpe?g|gif|svg|mp4|webm)$/i;
  const sectionName=/^[a-z][a-z0-9-]{0,49}$/;
  const label=(value,max=300)=>typeof value==="string"?value.trim().slice(0,max):"";
  const valid=(item)=>{
    if(!item||typeof item!=="object"||item.page!==page||
       !sectionName.test(String(item.section||""))||
       !asset.test(String(item.src||""))||String(item.src).includes(".."))return false;
    if(!label(item.title,100)||!label(item.caption,600)||!label(item.alt,300))return false;
    if(!["image","video"].includes(item.type))return false;
    if(item.type==="video"&&!/\.(mp4|webm)$/i.test(item.src))return false;
    if(item.type==="image"&&/\.(mp4|webm)$/i.test(item.src))return false;
    if(item.id!==undefined&&!/^GR-[0-9]{3,5}$/.test(String(item.id)))return false;
    return Boolean(document.getElementById(item.section));
  };
  const element=(tag,cls,text)=>{
    const el=document.createElement(tag);
    if(cls)el.className=cls;
    if(text!==undefined)el.textContent=text;
    return el;
  };
  let viewer=null;
  function openImage(item){
    if(!viewer){
      viewer=document.createElement("dialog");
      viewer.className="visual-viewer";
      viewer.setAttribute("aria-label","Збільшений графічний матеріал");
      const close=element("button","visual-viewer-close","Закрити ×");
      close.type="button";
      close.addEventListener("click",()=>viewer.close());
      viewer.append(close);
      viewer.addEventListener("click",e=>{
        if(e.target===viewer)viewer.close();
      });
      document.body.append(viewer);
    }
    viewer.querySelectorAll(".visual-viewer-content").forEach(el=>el.remove());
    const content=element("figure","visual-viewer-content");
    const image=document.createElement("img");
    image.src=item.src;image.alt=label(item.alt);image.decoding="async";
    content.append(image);
    content.append(element("figcaption",null,label(item.caption)));
    viewer.append(content);
    viewer.showModal();
  }
  function drawItem(item){
    const figure=element("figure","visual-item");
    const visualBox=element("div","visual-media");
    if(item.type==="video"){
      const video=document.createElement("video");
      video.src=item.src;video.controls=true;video.preload="metadata";
      video.playsInline=true;video.setAttribute("aria-label",label(item.alt));
      visualBox.append(video);
    }else{
      const button=element("button","visual-expand");
      button.type="button";button.title="Збільшити графічний матеріал";
      button.setAttribute("aria-label","Збільшити: "+label(item.title,100));
      const image=document.createElement("img");
      image.src=item.src;image.alt=label(item.alt);image.loading="lazy";image.decoding="async";
      button.append(image);
      button.addEventListener("click",()=>openImage(item));
      visualBox.append(button);
    }
    figure.append(visualBox);
    const meta=element("figcaption","visual-caption");
    meta.append(element("strong",null,label(item.title,100)));
    meta.append(element("span",null,label(item.caption)));
    const status=label(item.status,120);
    if(status)meta.append(element("small","visual-status",status));
    const attribution=label(item.credit,150);
    if(attribution)meta.append(element("small","visual-credit",attribution));
    if(item.id){
      const discuss=element("a","visual-discuss","Обговорити з Оракулом ↗");
      discuss.href="oracle.html?source="+page+"&focus="+encodeURIComponent("graphic:"+item.id);
      discuss.target="_blank";discuss.rel="noopener noreferrer";
      discuss.setAttribute("aria-label","Обговорити з Оракулом: "+label(item.title,100));
      meta.append(discuss);
    }
    figure.append(meta);
    return figure;
  }
  async function init(){
    let response;
    try{
      response=await fetch("assets/visuals.json",{cache:"no-cache"});
      if(!response.ok)return;
      const manifest=await response.json();
      if(manifest?.version!==1||!Array.isArray(manifest.items))return;
      const grouped=new Map();
      for(const item of manifest.items){
        if(!valid(item))continue;
        const list=grouped.get(item.section)||[];
        if(list.length<20){list.push(item);grouped.set(item.section,list);}
      }
      for(const [section,items] of grouped){
        const target=document.getElementById(section);
        if(!target)continue;
        const region=element("div","visual-gallery");
        region.setAttribute("aria-label","Графічні матеріали до розділу");
        region.append(element("h3","visual-gallery-title","Графічні матеріали"));
        const grid=element("div","visual-gallery-grid");
        for(const item of items)grid.append(drawItem(item));
        region.append(grid);
        // Draw just below the text of the related section, not in a separate unrelated gallery.
        target.append(region);
      }
    }catch{/* Never obstruct the article if the illustration catalog is unavailable. */}
  }
  if(document.readyState==="loading")document.addEventListener("DOMContentLoaded",init,{once:true});
  else init();
})();
