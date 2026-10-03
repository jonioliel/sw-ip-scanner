(() => {
  'use strict';
  const names = [
    [1,'router.home','Ubiquiti','Gateway'],[10,'homeassistant.local','Home Assistant','Home Assistant'],
    [12,'nas.local','Synology','NAS · גיבויים'],[15,'office-mac.local','Apple','מחשב העבודה'],
    [20,'living-room-tv.local','Samsung','טלוויזיה · סלון'],[21,'chromecast.local','Google','Chromecast'],
    [24,'jon-iphone.local','Apple','iPhone'],[30,'hue-bridge.local','Philips','Hue Bridge'],
    [31,'shelly-kitchen.local','Shelly','תאורה · מטבח'],[32,'shelly-bedroom.local','Shelly','תריס · חדר שינה'],
    [40,'esp-living-room.local','Espressif','חיישן · סלון'],[41,'esp-office.local','Espressif','חיישן · משרד'],
    [50,'front-door.local','Reolink','מצלמה · כניסה'],[51,'garden.local','Reolink','מצלמה · גינה'],
    [65,'laserjet.local','HP','מדפסת'],[80,'vacuum.local','Roborock','שואב אבק'],
    [100,'access-point.local','Ubiquiti','נקודת גישה'],[120,'sonos.local','Sonos','רמקול · סלון']
  ];
  const timestamp = '2026-10-03T07:42:00+00:00';
  const rows = Array.from({length:254},(_,i) => ({ip:`192.168.1.${i+1}`,status:'unobserved',name:'',alias:'',hostname:'',vendor:'',mac:'',source:'',last_seen:null}));
  for (const [n,hostname,vendor,alias] of names) Object.assign(rows[n-1],{hostname,vendor,alias,name:alias,status:'occupied',mac:`02:00:00:00:01:${n.toString(16).padStart(2,'0').toUpperCase()}`,source:'ARP/mDNS',last_seen:timestamp});
  for (const [n,name,vendor] of [[25,'tablet.local','Apple'],[60,'laptop.local','Lenovo'],[81,'guest-phone.local','Samsung']]) {
    Object.assign(rows[n-1],{name,hostname:name,vendor,status:'known',last_seen:'2026-10-02T19:10:00+00:00',mac:`02:00:00:00:01:${n.toString(16).padStart(2,'0').toUpperCase()}`});
  }
  const selected = {cidr:'192.168.1.0/24',interface:'eth0',host_ip:'192.168.1.10',gateway:'192.168.1.1',supported:true,default:true,host_count:254};
  let scan = {running:false,phase:'idle',error:null}, scanned_at=timestamp, duration=7.8, timer=null;
  function payload() {
    const ranges=[];
    for (const row of rows) {
      if (ranges.length && ranges.at(-1).status===row.status) { ranges.at(-1).end=row.ip; ranges.at(-1).count++; }
      else ranges.push({start:row.ip,end:row.ip,status:row.status,count:1});
    }
    const counts={occupied:0,known:0,unobserved:0,unscanned:0};
    rows.forEach(row => counts[row.status]++);
    return {demo:true,selected,networks:[selected],network_error:null,scan_interval:300,scan:{...scan},snapshot:{
      cidr:selected.cidr,rows:rows.map(row=>({...row})),ranges,counts,total:254,scanned_at,duration,warnings:[],reserved:['192.168.1.0','192.168.1.255']
    }};
  }
  window.IPScannerTransport = {
    state: async () => payload(),
    network: async () => payload(),
    scan: async () => {
      if (scan.running) throw new Error('סריקה כבר מתבצעת');
      scan={running:true,phase:'discovery',error:null,started_at:Date.now()/1000,cidr:selected.cidr};
      timer=setTimeout(() => {scan.phase='names';timer=setTimeout(()=>{scan.running=false;scan.phase='idle';scanned_at=new Date().toISOString();duration=1.4;rows.filter(r=>r.status==='occupied').forEach(r=>r.last_seen=scanned_at);},700);},700);
      return payload();
    },
    stop: async () => { clearTimeout(timer);scan.running=false;scan.phase='cancelled';return payload(); },
    alias: async (ip,alias) => {
      const row=rows.find(r=>r.ip===ip);
      if (!row || alias.length>80) throw new Error('שם לא תקין');
      row.alias=alias;row.name=alias||row.hostname;return payload();
    },
    export: () => {
      const keys=['ip','status','name','hostname','mac','vendor','last_seen'];
      const quote=value=>{let text=String(value||'');if(/^[\s]*[=+\-@]/.test(text))text="'"+text;return '"'+text.replaceAll('"','""')+'"';};
      const data='\ufeff'+[keys.join(','),...rows.map(r=>keys.map(k=>quote(r[k])).join(','))].join('\r\n');
      const url=URL.createObjectURL(new Blob([data],{type:'text/csv;charset=utf-8'}));
      const anchor=document.createElement('a');anchor.href=url;anchor.download='ip-scanner-demo.csv';anchor.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
    }
  };
})();
