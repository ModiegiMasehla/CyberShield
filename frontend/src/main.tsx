import {useEffect,useState} from "react"
import {createRoot} from "react-dom/client"
import "./style.css"

const API=import.meta.env.VITE_API_URL||"http://localhost:8000/api/v1"
async function api(path:string,options:RequestInit={},token?:string){
  const headers:any={"Content-Type":"application/json",...(options.headers||{})}
  if(token) headers.Authorization=`Bearer ${token}`
  const r=await fetch(API+path,{...options,headers})
  if(!r.ok){
    if(r.status===401&&token){localStorage.removeItem("token");window.dispatchEvent(new Event("cybershield:logout"))}
    const body=await r.json().catch(()=>({detail:"Request failed"}))
    const d=body.detail
    throw new Error(Array.isArray(d)?d.map((x:any)=>x.msg||x).join(" "):(d||"Request failed"))
  }
  const ct=r.headers.get("content-type")||""
  return ct.includes("application/json")?r.json():r
}

function App(){
 const [token,setToken]=useState(localStorage.getItem("token")||"")
 const [login,setLogin]=useState(import.meta.env.DEV?{email:"admin@cybershield.local",password:"CyberShield!Admin123"}:{email:"",password:""})
 const [dash,setDash]=useState<any>(null); const [msg,setMsg]=useState("")
 const [password,setPassword]=useState("")
 const [pw,setPw]=useState<any>(null)
 const [url,setUrl]=useState("https://example.com"); const [urlResult,setUrlResult]=useState<any>(null)
 const [incidents,setIncidents]=useState<any[]>([])
 async function refresh(t=token){ if(!t)return; try{setDash(await api("/dashboard",{},t));setIncidents(await api("/incidents",{},t))}catch(e:any){setMsg(e.message)}}
 useEffect(()=>{refresh()},[token])
 useEffect(()=>{const h=()=>{setToken("");setMsg("Session expired. Please sign in again.")};window.addEventListener("cybershield:logout",h);return()=>window.removeEventListener("cybershield:logout",h)},[])
 async function run(fn:()=>Promise<void>){try{setMsg("");await fn()}catch(e:any){setMsg(e.message)}}
 async function downloadReport(){await run(async()=>{const r:any=await api("/reports/security.pdf",{},token);const blob=await r.blob();const u=URL.createObjectURL(blob);const a=document.createElement("a");a.href=u;a.download="cybershield-security-assessment.pdf";a.click();URL.revokeObjectURL(u)})}
 async function doLogin(e:any){e.preventDefault();try{const x:any=await api("/auth/login",{method:"POST",body:JSON.stringify(login)});localStorage.setItem("token",x.access_token);setToken(x.access_token);setMsg("Authenticated successfully.")}catch(e:any){setMsg(e.message)}}
 if(!token) return <main className="login"><section className="panel"><h1>CYBERSHIELD</h1><p>Defensive cybersecurity fundamentals & monitoring platform</p><form onSubmit={doLogin}><input value={login.email} onChange={e=>setLogin({...login,email:e.target.value})}/><input type="password" value={login.password} onChange={e=>setLogin({...login,password:e.target.value})}/><button>Sign in</button></form>{import.meta.env.DEV&&<small>Demo: admin@cybershield.local / CyberShield!Admin123</small>}{msg&&<p className="error">{msg}</p>}</section></main>
 return <main><header><div><h1>CYBERSHIELD</h1><span>Security Operations Dashboard</span></div><button onClick={()=>{localStorage.removeItem("token");setToken("")}}>Logout</button></header>
 <p className="notice">Only scan systems you own or have explicit permission to test.</p>
 {msg&&<p className="notice">{msg}</p>}
 {dash&&<section className="cards">{[['Security Score',dash.security_score+'/100'],['Critical',dash.critical_alerts],['High',dash.high_alerts],['Medium',dash.medium_alerts],['Open Incidents',dash.open_incidents],['Vulnerabilities',dash.vulnerabilities]].map(x=><div className="card" key={x[0]}><b>{x[0]}</b><strong>{x[1]}</strong></div>)}</section>}
 <section className="grid">
 <div className="panel"><h2>Password Security Analyzer</h2><input type="password" placeholder="Test in memory only" value={password} onChange={e=>{setPassword(e.target.value);setPw(null)}}/><button onClick={()=>run(async()=>setPw(await api("/tools/password/analyze",{method:"POST",body:JSON.stringify({password})})))}>Analyze</button>{pw&&<pre>{JSON.stringify(pw,null,2)}</pre>}</div>
 <div className="panel"><h2>URL Security Analyzer</h2><input value={url} onChange={e=>setUrl(e.target.value)}/><button onClick={()=>run(async()=>setUrlResult(await api("/tools/url/analyze",{method:"POST",body:JSON.stringify({url})},token)))}>Analyze</button>{urlResult&&<pre>{JSON.stringify(urlResult,null,2)}</pre>}</div>
 <div className="panel"><h2>Incidents</h2>{incidents.map(i=><div className="row" key={i.id}><b>#{i.id} {i.title}</b><span>{i.severity} · {i.status}</span></div>)}<button onClick={downloadReport}>Security Report</button></div>
 <div className="panel"><h2>Learning Centre</h2><p><b>CIA Triad:</b> confidentiality, integrity and availability.</p><p><b>Defense in depth:</b> use multiple independent controls.</p><p><b>Least privilege:</b> grant only the access required.</p><p><b>Incident response:</b> preparation → identification → containment → eradication → recovery → lessons learned.</p></div>
 </section></main>
}
createRoot(document.getElementById("root")!).render(<App/>)
