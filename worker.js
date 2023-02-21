/*
url arguments
key:string (required)
  verify who has access
method:setOne,setJson,get (required)
  default is get
source:string (required)
  github.com project name,like better-cloudflare-ip,ip-scanner

method arguments
setOne:
  ip:string (required) 
    ipv4 or ipv6 address
  loc:string 
    ip location
  speed:number
    ip speed
  delay:number
    ip ping delay
  url example:https://cf_fast_ip.example.workers.dev/?key=abc&method=setOne&source=better-cf-ip&ip=1.1.1.1&speed=22
setJson:
  url example:https://cf_fast_ip.example.workers.dev/?key=abc&method=setJson&source=ip-scanner
  post json example:{"ip-scanner":[{"ip":"1.1.1.1","loc":"US","delay":123,"speed":3}]}
  note:source value must in json attribute
get:
  maxLen:number
    default is 10
    maximum number of proxies
  type:clash,v2ray,ip
    default is clash
    clash use by clash provider,v2ray use by v2rayN
  lastDay:number,latest
    7 is last 7 days,latest is latest day
  maxDelay:number
  minSpeed:number
  uuid,path,host,alterId,cipher,port,tls:string
    vmess proxy config
  url example:
  https://cf_fast_ip.example.workers.dev/?key=abc&method=get&source=better-cf-ip
    &maxLen=10&type=v2ray
  https://cf_fast_ip.example.workers.dev/?key=abc&method=get&source=better-cf-ip
    &maxLen=10&type=clash
  https://cf_fast_ip.example.workers.dev/?key=abc&method=get&source=ip-scanner
    &maxLen=1000&type=ip&lastDay=100
  https://cf_fast_ip.example.workers.dev/?key=abc&method=get&source=ip-scanner
    &maxLen=1000&type=clash&lastDay=latest

*/

//CF_KV: worker settings bind KV namespace
CF_KV = CF_FAST_IP
//pwd: verify who has access,compare with key
pwd = "pwd"
//proxy config
uuid="uuid"
path="/path"
host="host"
alterId="8"
cipher="auto"
port="443"
tls="true"

//expiration time
expirTime=365*24*3600*1000
//different code
diffHostCode=""

searchParams={}
source=""
addEventListener('fetch', function(event) {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  searchParams = new URL(request.url).searchParams
  const key = searchParams.get("key")
  const method = searchParams.get("method")
  source = searchParams.get("source")
  if(key != pwd){
    return new Response("error key")
  }
  if(source === null || source == ""){
    return new Response("error source") 
  }
  switch (method) {
    case "setOne":
      return setOne(request)
    case "setJson":
      return setJson(request)
    default:
      return get(request)
  }
}

async function setOne(request){
  const ip = searchParams.get("ip") || ""
  if(!isValidIP(ip)){
    return new Response("error ip")
  }
  const loc = searchParams.get("loc") || ""
  const speed = searchParams.get("speed") || 1
  const delay = searchParams.get("delay") || 200
  const time = new Date().getTime()
  const oneIp=JSON.stringify({"ip":ip,"loc":loc,"speed":speed,"delay":delay,"time":time})
  let allIp = await CF_KV.get(source,{type: "json"}) || []
  allIp.unshift(oneIp)
  allIp = await deleteOldIp(allIp)
  await CF_KV.put(source,JSON.stringify(allIp))
  return new Response("ok")
}

async function setJson(request){
  const contentType = request.headers.get('content-type') || ""
  let ips = {}
  if (contentType.includes('application/json')) {
    ips = JSON.parse(JSON.stringify(await request.json()))
  }
  ips[source].forEach((element, index, array) => {
    element["time"]=new Date().getTime()
    array[index]=JSON.stringify(element)
  })
  let allIp = await CF_KV.get(source,{type: "json"}) || []

  for(i=ips[source].length-1;i>=0;i--){
    allIp.unshift(ips[source][i])
  }

  allIp = await deleteOldIp(allIp)
  await CF_KV.put(source,JSON.stringify(allIp))
  return new Response("ok")
}

async function deleteOldIp(allIp){
  const map = new Map()
  let newIp = []
  const now = new Date().getTime()
  let oneIp={}
  for(i=0;i<allIp.length;i++){
    oneIp=JSON.parse(allIp[i])
    if(!oneIp.time){
      continue
    }
    if(oneIp.time+expirTime < now){
      break
    }
    if(!map.has(oneIp.ip)) {
      map.set(oneIp.ip, true)
      newIp.push(JSON.stringify(oneIp))
    }
  }
  return newIp
}

async function get(request){
  let allIp = await CF_KV.get(source,{type: "json"})
  if(allIp === null){
    return new Response("no ip")
  }
  allIp = await deleteOldIp(allIp)
  if(allIp.length == 0){
    return new Response("no ip")
  }

  let len = searchParams.get("maxLen") || 10
  const lastDay = searchParams.get("lastDay") || 365
  const maxDelay = searchParams.get("maxDelay") || 5000
  const minSpeed = searchParams.get("minSpeed") || 0

  uuid = searchParams.get("uuid") || uuid
  host = searchParams.get("host") || host
  path = searchParams.get("path") || path
  alterId = searchParams.get("alterId") || alterId
  cipher = searchParams.get("cipher") || cipher
  port = searchParams.get("port") || port
  tls = searchParams.get("tls") || tls

  diffHostCode = searchParams.get("diffHostCode") || diffHostCode

  let minTime = 0

  len = Math.min(len,allIp.length)
  const allIpObj=[]
  let oneIp={}
  for(i=0;i<allIp.length;i++){
    oneIp = JSON.parse(allIp[i])
    if(i==0){
      minTime = (lastDay == "latest" ? 
        (oneIp.time ? oneIp.time-5*60*1000 : 0) : 
        new Date().getTime() - lastDay*24*3600*1000)
    }
    if((oneIp.time || new Date().getTime() - 30*24*3600*1000) - minTime > 0
      && (oneIp.delay || 200) - maxDelay < 0
      && (oneIp.speed || 1) - minSpeed > 0){
      allIpObj.push(oneIp)
    }
    if(oneIp.time < minTime || allIpObj.length >= len){
      break
    }
  }
  const type = searchParams.get("type")
  switch (type) {
      case "v2ray":
        return new Response(getV2ray(allIpObj))
      case "ip":
        return new Response(getIp(allIpObj))
      default:
        return new Response(getClash(allIpObj))
    }
}

function getIp(ips){
  let proxies = ""
  for(i=0;i<ips.length;i++){
    ip = ips[i]
    proxies += ip.ip + "\n"
  }
  return proxies
}

function getClash(ips){
  let proxies="proxies:\n"
  let tempIp=""
  for(i=0;i<ips.length;i++){
    ip = ips[i]
    if(ipVersion(ip.ip)=="ipv4"){
      tempIp = ip.ip;
    }else if(ipVersion(ip.ip)=="ipv6"){
      tempIp = ip.ip.substr(0,findStrIndex(ip.ip,":",2));
    }
    proxies += "  - {name: \""+tempIp+"|"+(ip.loc||"")+"|"+
      getdate(ip.time||new Date().getTime()-30*24*3600*1000)+"|"+
      (ip.speed||"")+"|"+diffHostCode+
      "\", server: "+ip.ip+
      ", port: "+port+
      ", type: vmess, uuid: "+uuid+
      ", alterId: "+alterId+
      ", cipher: "+cipher+
      ", tls: "+ (tls == "true" ? "true" : "false") +
      ", network: ws, ws-opts: {path: "+path+
      ", headers: {Host: "+host+"}}}\n"
  }
  return proxies
}

function getV2ray(ips){
  let proxies = ""
  let tempIp=""
  for(i=0;i<ips.length;i++){
    ip = ips[i]
    if(ipVersion(ip.ip)=="ipv4"){
      tempIp = ip.ip;
    }else if(ipVersion(ip.ip)=="ipv6"){
      tempIp = ip.ip.substr(0,findStrIndex(ip.ip,":",2));
    }
    proxies += "vmess://" + btoa(JSON.stringify({
      "v": "2",
      "ps": tempIp+"|"+(ip.loc||"")+"|"+
        getdate(ip.time||new Date().getTime()-30*24*3600*1000)+"|"+
        (ip.speed||"")+"|"+diffHostCode,
      "add": ip.ip,
      "port": port,
      "id": uuid,
      "aid": alterId,
      "net": "ws",
      "type": "none",
      "host": host,
      "path": path,
      "tls": tls == "true" ? "tls" : "",
      "sni": ""
    })) + "\n"
  }
  return btoa(proxies)
}

function getdate(time){
  const timezone = 8
  const offset_GMT = new Date().getTimezoneOffset()
  const dateTime = new Date(time + offset_GMT * 60 * 1000 + timezone * 60 * 60 * 1000)
  return dateTime.getMonth()+1+"/"+dateTime.getDate()+"-"+dateTime.getHours()+":"+dateTime.getMinutes()
}

function isValidIP(ip) {
    return ipVersion(ip) != "error"
} 

function ipVersion(ip) {
    const reg = /^(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])$/
    const regv6 = /^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$/
    if(reg.test(ip)){
      return "ipv4";
    }else if(regv6.test(ip)){
      return "ipv6";
    }else {
      return "error";
    }
} 
/**
 * find index of char in string
 * @param {Object} str: source string
 * @param {Object} cha: find char
 * @param {Object} num: first is 0
 */
function findStrIndex(str, cha, num) {
    let x = str.indexOf(cha);
    for (let i = 0; i < num; i++) {
        x = str.indexOf(cha, x + 1);
    }
    return x;
}
