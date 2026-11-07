'use strict';
const $ = id => document.getElementById(id);
const state = {csrf:null,overview:null,incidents:[],history:[],currentDevice:null,enrollments:[],installPrompt:null,secret:null,tab:'overview'};
const titles = {overview:'Centre de contrôle',incidents:'Gestion des incidents',devices:'Terminaux supervisés',agents:'Intelligence multi-agents',audit:'Traçabilité administrative',enroll:'Enrôlement sécurisé',guide:'Documentation'};
const localDate = ts => ts ? new Date(ts*1000).toLocaleString('fr-FR',{dateStyle:'short',timeStyle:'short'}) : '—';
const el = (tag,cls,text) => {const node=document.createElement(tag);if(cls)node.className=cls;if(text!==undefined)node.textContent=String(text);return node;};
const replace = (parent,children) => {parent.replaceChildren(...children);};
const text = (id,value) => {$(id).textContent=String(value);};

async function call(path,options={}){
 const headers = {'Accept':'application/json',...(options.body?{'Content-Type':'application/json'}:{}),...(options.headers||{})};
 if(options.method && options.method!=='GET' && state.csrf && path!=='/api/login') headers['X-Aegis-CSRF']=state.csrf;
 const resp=await fetch(path,{credentials:'same-origin',cache:'no-store',...options,headers});
 const body=await resp.json().catch(()=>({}));
 if(!resp.ok){const detail=typeof body.detail==='string'?body.detail:`Erreur HTTP ${resp.status}`;const error=new Error(detail);error.status=resp.status;throw error;}
 return body;
}
function loggedIn(ok){$('auth').hidden=ok;$('app').hidden=!ok; if(!ok){state.csrf=null;state.overview=null;state.secret=null;$('enrollResult').hidden=true;} }
async function checkLogin(){try{const me=await call('/api/me');state.csrf=me.csrf;loggedIn(true);await refresh();}catch(e){loggedIn(false);}}
$('loginForm').addEventListener('submit',async ev=>{
 ev.preventDefault();text('loginError','');const btn=ev.target.querySelector('button');btn.disabled=true;
 try{const ans=await call('/api/login',{method:'POST',body:JSON.stringify({password:$('password').value})});state.csrf=ans.csrf;$('password').value='';loggedIn(true);await refresh();}
 catch(e){text('loginError',e.message);}finally{btn.disabled=false;}
});
$('logout').addEventListener('click',async()=>{try{await call('/api/logout',{method:'POST'});}catch(_){/* Local signout even if connection fails. */}loggedIn(false);});
function switchTab(tab){
 if(!titles[tab]) return;
 state.tab=tab;text('pageTitle',titles[tab]);
 document.querySelectorAll('.tab-panel').forEach(p=>p.classList.toggle('active',p.id===`tab-${tab}`));
 document.querySelectorAll('.nav-btn').forEach(b=>b.classList.toggle('active',b.dataset.tab===tab));
 if(tab!=='enroll'){state.secret=null;$('enrollResult').hidden=true;$('enrollToken').value='';}
 if(tab==='enroll') renderEnrollments();
 if(tab==='audit') loadAudit().catch(showRefreshFailure);
 if(tab==='incidents') loadIncidents().catch(showRefreshFailure);
 window.scrollTo({top:0,behavior:'smooth'});
}
document.querySelectorAll('[data-tab]').forEach(b=>b.addEventListener('click',()=>switchTab(b.dataset.tab)));
document.querySelectorAll('[data-goto]').forEach(b=>b.addEventListener('click',()=>switchTab(b.dataset.goto)));
$('reload').addEventListener('click',()=>refresh().catch(showRefreshFailure));
$('incidentFilter').addEventListener('change',()=>loadIncidents().catch(showRefreshFailure));
$('deviceSelect').addEventListener('change',()=>{state.currentDevice=$('deviceSelect').value||null;loadHistory().catch(showRefreshFailure);renderPosture();});

function showRefreshFailure(e){
 text('lastUpdate',e.status===401?'Session expirée':'Connexion interrompue');
 if(e.status===401) loggedIn(false);
}
async function refresh(){
 if(!state.csrf) return;
 try{
  const [overview,incidents]=await Promise.all([call('/api/overview'),call('/api/incidents?status=open&limit=100')]);
  state.overview=overview;state.incidents=incidents;
  text('lastUpdate','Actualisé '+new Date().toLocaleTimeString('fr-FR',{hour:'2-digit',minute:'2-digit'}));
  text('footerTime',new Date().toLocaleString('fr-FR'));renderOverview();renderRecentIncidents();renderDevices();renderPosture();
  renderAgentModel();await loadHistory();
 }catch(e){showRefreshFailure(e);}
}
function renderOverview(){
 const ov=state.overview;if(!ov)return;
 text('deviceCount',ov.devices.length);text('onlineCount',ov.online_devices);
 text('incidentCount',ov.open_incidents);text('urgentCount',ov.urgent_incidents);text('sideIncidents',ov.open_incidents);
 const sel=$('deviceSelect'),previous=state.currentDevice;
 replace(sel,ov.devices.length?ov.devices.map(d=>{const opt=el('option','',d.name);opt.value=d.device_id;return opt;}):[(()=>{const n=el('option','','Aucun appareil');n.value='';return n;})()]);
 state.currentDevice = ov.devices.some(d=>d.device_id===previous)?previous:(ov.devices[0]?.device_id||null);
 sel.value=state.currentDevice||'';
}
function currentDevice(){return state.overview?.devices.find(d=>d.device_id===state.currentDevice)||null;}
function renderPosture(){
 const d=currentDevice();const box=$('postureContent');
 if(!d){replace(box,[el('div','empty-mini','Aucun appareil n’a envoyé de mesure. Démarrez un collecteur pour afficher son état.')]);return;}
 const info=[
  ['Appareil',d.name,''],
  ['Collecte',d.online?'Active':'Interrompue',d.online?'good':'warn'],
  ['Pare-feu',readCheck(d.checks.firewall),checkClass(d.checks.firewall)],
  ['Antivirus Defender',readCheck(d.checks.defender),checkClass(d.checks.defender)],
  ['Connexions établies',d.metrics.established??'—',''],
  ['Ports TCP en écoute',d.metrics.listener_count??'—',''],
  ['Score de risque',`${d.last_risk} / 100`,d.last_risk>=50?'bad':d.last_risk>=20?'warn':'good'],
  ['Tendance indicative',d.last_forecast==null?'En attente':`${d.last_forecast} / 100`,'']
 ];
 replace(box,info.map(([a,b,c])=>{const row=el('div','posture-row');row.append(el('span','',a),el('b',c,b));return row;}));
}
function readCheck(x){return ({enabled:'Activé',disabled:'Désactivé',not_applicable:'Non applicable',unknown:'Non vérifié'})[x]||'Non vérifié';}
function checkClass(x){return x==='enabled'?'good':x==='disabled'?'bad':'warn';}
function makeIncident(inc,full){
 const row=el('div','incident-row');
 const severity=el('span',`severity ${inc.severity}`,({critical:'Critique',high:'Élevée',medium:'Moyenne',low:'Faible'})[inc.severity]||inc.severity);
 const content=el('div','incident-main');content.append(el('strong','',inc.title));content.append(el('p','',inc.description));
 const meta=el('div','incident-meta');meta.append(el('span','',`Appareil ${inc.device_id.slice(0,8)}…`),el('span','',localDate(inc.last_seen)),el('span','',`${inc.occurrences} observation(s)`));content.append(meta);
 row.append(severity,content);
 if(full){const btn=el('button','btn outline',inc.status==='open'?'Résoudre':'Rouvrir');btn.addEventListener('click',()=>changeIncident(inc));row.append(btn);}
 return row;
}
function renderRecentIncidents(){
 replace($('recentIncidents'),state.incidents.length?state.incidents.slice(0,5).map(x=>makeIncident(x,false)):[el('div','empty-mini','Aucune alerte ouverte. Ce n’est pas une garantie d’absence d’intrusion.')]);
}
async function loadIncidents(){
 const filter=$('incidentFilter').value;
 const result=await call('/api/incidents?status='+encodeURIComponent(filter)+'&limit=250');
 replace($('fullIncidents'),result.length?result.map(x=>makeIncident(x,true)):[el('div','empty-mini','Aucun incident correspondant au filtre.')]);
}
async function changeIncident(inc){
 const next=inc.status==='open'?'resolved':'open';
 if(!window.confirm(next==='resolved'?'Marquer cet incident comme résolu ? Aucun contrôle système ne sera modifié.':'Rouvrir cet incident ?'))return;
 try{await call(`/api/incidents/${inc.id}/status`,{method:'POST',body:JSON.stringify({status:next})});await refresh();await loadIncidents();}
 catch(e){window.alert('Impossible de modifier : '+e.message);}
}
function renderDevices(){
 const devices=state.overview?.devices||[];
 if(!devices.length){replace($('devicesGrid'),[el('div','panel empty-mini','Aucun terminal avec mesure réelle. Cliquez sur « Ajouter un appareil » pour l’enrôler.')]);return;}
 replace($('devicesGrid'),devices.map(d=>{
  const card=el('article','device-card'),top=el('div','device-top'),left=el('div');
  left.append(el('h3','',d.name),el('p','',d.platform));top.append(left,el('span',`pill ${d.online?'online':''}`,d.online?'● En ligne':'● Hors ligne'));card.append(top);
  card.append(el('p','',`Dernière collecte : ${localDate(d.last_seen)}`));
  const grid=el('div','device-metrics');[
   ['RISQUE',`${d.last_risk}/100`],['CPU',`${d.metrics.cpu??'—'}%`],
   ['MÉMOIRE',`${d.metrics.memory??'—'}%`],['CONNEXIONS',d.metrics.established??'—']
  ].forEach(([a,b])=>{const item=el('div');item.append(el('small','',a),el('b','',b));grid.append(item);});
  card.append(grid);card.append(el('p','',`Modèle : ${d.last_model}`));
  const btn=el('button','btn outline','Afficher l’historique →');btn.addEventListener('click',()=>{state.currentDevice=d.device_id;switchTab('overview');renderOverview();renderPosture();loadHistory();});card.append(btn);
  return card;
 }));
}
async function loadHistory(){
 if(!state.currentDevice){state.history=[];drawChart();return;}
 state.history=await call('/api/history/'+encodeURIComponent(state.currentDevice));drawChart();
}
function drawChart(){
 const canvas=$('riskChart'),empty=$('chartEmpty'),items=state.history;empty.hidden=items.length>0;
 const width=canvas.clientWidth||700, height=canvas.clientHeight||250,dpr=window.devicePixelRatio||1;
 canvas.width=Math.max(1,Math.floor(width*dpr));canvas.height=Math.max(1,Math.floor(height*dpr));
 const ctx=canvas.getContext('2d');if(!ctx)return;ctx.scale(dpr,dpr);ctx.clearRect(0,0,width,height);
 if(!items.length)return;
 const L=36,R=14,T=16,B=28,w=width-L-R,h=height-T-B;
 ctx.font='11px system-ui';ctx.lineWidth=1;ctx.textAlign='right';
 for(let v=0;v<=100;v+=25){const y=T+h-(v/100)*h;ctx.strokeStyle='#233b50';ctx.beginPath();ctx.moveTo(L,y);ctx.lineTo(width-R,y);ctx.stroke();ctx.fillStyle='#7d91a8';ctx.fillText(String(v),L-9,y+4);}
 const x=i=>L+(items.length===1?w/2:(i/(items.length-1))*w),y=v=>T+h-(v/100)*h;
 const gradient=ctx.createLinearGradient(0,T,0,height);gradient.addColorStop(0,'rgba(62,214,235,.28)');gradient.addColorStop(1,'rgba(62,214,235,0)');
 ctx.beginPath();items.forEach((p,i)=>{i?ctx.lineTo(x(i),y(p.risk)):ctx.moveTo(x(i),y(p.risk));});
 ctx.lineTo(x(items.length-1),T+h);ctx.lineTo(x(0),T+h);ctx.closePath();ctx.fillStyle=gradient;ctx.fill();
 ctx.beginPath();items.forEach((p,i)=>{i?ctx.lineTo(x(i),y(p.risk)):ctx.moveTo(x(i),y(p.risk));});
 ctx.strokeStyle='#43d6ef';ctx.lineWidth=2.5;ctx.stroke();
 const last=items.at(-1);ctx.beginPath();ctx.arc(x(items.length-1),y(last.risk),4.5,0,Math.PI*2);ctx.fillStyle='#6cedf9';ctx.fill();
 ctx.textAlign='center';ctx.fillStyle='#758ba2';
 ctx.fillText(new Date(items[0].ts*1000).toLocaleTimeString('fr-FR',{hour:'2-digit',minute:'2-digit'}),L+35,height-6);
 ctx.fillText(new Date(last.ts*1000).toLocaleTimeString('fr-FR',{hour:'2-digit',minute:'2-digit'}),width-R-35,height-6);
 text('modelStatus',currentDevice()?.last_model||'Modèle : en attente');
}
window.addEventListener('resize',()=>{if(state.tab==='overview')drawChart();});
function renderAgentModel(){
 const d=currentDevice();text('agentModelNote',d?`Dernier modèle pour ${d.name} : ${d.last_model}. Score calculé : ${d.last_risk}/100. Projection : ${d.last_forecast??'non disponible'}.`:'Aucun apprentissage en cours : aucun collecteur n’a encore transmis de mesure.');
}
$('enrollForm').addEventListener('submit',async ev=>{
 ev.preventDefault();text('enrollError','');
 const button=ev.target.querySelector('button');button.disabled=true;
 try{
  const result=await call('/api/enrollments',{method:'POST',body:JSON.stringify({name:$('enrollName').value.trim()})});
  state.secret=result;$('enrollDeviceId').value=result.device_id;$('enrollToken').value=result.token;$('enrollResult').hidden=false;
  $('enrollName').value='';await renderEnrollments();
 }catch(e){text('enrollError',e.message);}finally{button.disabled=false;}
});
$('clearSecret').addEventListener('click',()=>{state.secret=null;$('enrollToken').value='';$('enrollDeviceId').value='';$('enrollResult').hidden=true;});
$('copyConfig').addEventListener('click',async()=>{
 if(!state.secret)return;
 const origin=window.location.origin;
 const content=`AEGIS_SERVER_URL=${origin}\nAEGIS_DEVICE_ID=${state.secret.device_id}\nAEGIS_AGENT_TOKEN=${state.secret.token}\nAEGIS_INTERVAL=60\n`;
 try{await navigator.clipboard.writeText(content);text('copyConfig','Configuration copiée');setTimeout(()=>text('copyConfig','Copier la configuration .agent.env'),1800);}
 catch(_){window.alert('Copie indisponible ; utilisez le contenu affiché.');}
});
async function loadAudit(){
 const payload=await call('/api/audit');
 const integrity=payload.integrity;
 text('auditIntegrity',integrity.valid
  ? `Chaîne valide (${integrity.checked} événements locaux)`
  : `RUPTURE au numéro ${integrity.broken_at} — enquête nécessaire`);
 replace($('auditEvents'),payload.events.length?payload.events.map(item=>{
  const wrapper=el('div','enrollment-row'), detail=el('div');
  detail.append(el('strong','',`${item.action} — ${item.target||'système'}`),
                el('small','',`${localDate(item.timestamp)} · acteur ${item.actor}`));
  wrapper.append(detail);return wrapper;
 }):[el('div','empty-mini','Aucune action administrative journalisée.')]);
}
async function renderEnrollments(){
 if(!state.csrf)return;
 try{
  const credentials=await call('/api/enrollments');state.enrollments=credentials;
  replace($('enrollmentList'),credentials.length?credentials.map(c=>{
   const row=el('div','enrollment-row'),info=el('div');info.append(el('strong','',c.name),el('small','',`${c.device_id} · ${c.active?'Autorisé':'Révoqué'}`));row.append(info);
   if(c.active){
    const rotate=el('button','btn outline','Renouveler le jeton');
    rotate.addEventListener('click', async()=>{
     if(!window.confirm('Invalider immédiatement l’ancien jeton de ce terminal ? Il faudra mettre à jour .agent.env.'))return;
     try{
      const r=await call('/api/enrollments/'+encodeURIComponent(c.device_id)+'/rotate',{method:'POST'});
      state.secret=r;$('enrollDeviceId').value=r.device_id;$('enrollToken').value=r.token;
      $('enrollResult').hidden=false;$('enrollResult').scrollIntoView({behavior:'smooth'});
     }catch(e){window.alert(e.message);}
    });row.append(rotate);
    const btn=el('button','btn ghost','Révoquer');btn.addEventListener('click',async()=>{
    if(!window.confirm('Révoquer définitivement ce collecteur ?'))return;
    try{await call('/api/enrollments/'+encodeURIComponent(c.device_id),{method:'DELETE'});await renderEnrollments();}
    catch(e){window.alert(e.message);}
   });row.append(btn);}return row;
  }):[el('div','empty-mini','Aucun collecteur autorisé.')]);
 }catch(e){replace($('enrollmentList'),[el('div','empty-mini',e.message)]);}
}
window.addEventListener('beforeinstallprompt',event=>{event.preventDefault();state.installPrompt=event;$('install').hidden=false;});
$('install').addEventListener('click',async()=>{if(!state.installPrompt)return;await state.installPrompt.prompt();state.installPrompt=null;$('install').hidden=true;});
if('serviceWorker' in navigator && (location.protocol==='https:' || location.hostname==='localhost' || location.hostname==='127.0.0.1'))navigator.serviceWorker.register('/service-worker.js').catch(()=>{});
checkLogin();
setInterval(()=>{if(state.csrf)refresh();},20000);

$('requestAdvice').addEventListener('click',async()=>{
 const button=$('requestAdvice');button.disabled=true;text('adviceOutput','Analyse locale demandée...');
 try{const result=await call('/api/advice',{method:'POST'});text('adviceOutput',result.advice+'\n\n'+result.disclaimer);}
 catch(e){text('adviceOutput','Conseiller indisponible : '+e.message);}
 finally{button.disabled=false;}
});
