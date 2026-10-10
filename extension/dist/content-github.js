function u(e){document.getElementById(e)?.remove();let t=document.createElement("div");t.id=e,t.className="heimdall-overlay-host",t.style.cssText="all: initial; position: fixed; z-index: 2147483647;";let n=t.attachShadow({mode:"open"}),o=document.createElement("link");o.rel="stylesheet",o.href=chrome.runtime.getURL("app.css"),n.appendChild(o);let c=document.createElement("div");return n.appendChild(c),document.documentElement.appendChild(t),{host:t,root:n,mount:c,destroy:()=>t.remove()}}function r(e){return e.replace(/[&<>"']/g,t=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[t])}function p(e){return{critical:"#ef4444",high:"#f97316",medium:"#eab308",low:"#84cc16",info:"#22d3ee"}[e]}var f={dashboardUrl:"https://sentinel-security-console.sg1670.chatgpt.site",promptShield:!0,secretGuard:!0,githubOverlay:!0,notifications:!0};var m="heimdall.settings";async function y(){let e=await chrome.storage.sync.get(m);return{...f,...e[m]??{}}}async function a(e){let t=await chrome.runtime.sendMessage(e);if(!t)throw new Error("No response from Heimdall background worker");if(!t.ok)throw new Error(t.error);return t.data}var k=new Set(["settings","marketplace","notifications","explore","topics","collections","sponsors","features","about","pricing","login","join","new","orgs","organizations","dashboard","search","apps","codespaces","account"]);function b(){let e=location.pathname.split("/").filter(Boolean);if(e.length<2)return null;let[t,n]=e;return k.has(t.toLowerCase())||n.includes(".")&&/\.(json|md)$/i.test(n)?null:{owner:t,repo:n.replace(/\.git$/,"")}}function w(e){switch((e??"").toUpperCase()){case"A":return"#3fb950";case"B":return"#84cc16";case"C":return"#eab308";case"D":return"#f97316";default:return"#ef4444"}}function C(e){return e>=90?"low":e>=70?"medium":e>=50?"high":"critical"}var i=u("heimdall-github-overlay");i.host.style.cssText="all: initial; position: fixed; z-index: 2147483600; bottom: 18px; right: 18px; width: 320px;";var s=!1;function l(e){return`
    <div style="background:linear-gradient(160deg,#0b1220,#060b18);border:1px solid rgba(56,189,248,0.25);
      border-radius:16px;box-shadow:0 18px 50px rgba(0,0,0,0.55);overflow:hidden;font-family:ui-sans-serif,system-ui;">
      <div id="hdr" style="display:flex;align-items:center;gap:8px;padding:11px 13px;cursor:pointer;
        background:rgba(255,255,255,0.02);border-bottom:1px solid rgba(255,255,255,0.06);">
        <div style="width:22px;height:22px;border-radius:7px;background:linear-gradient(135deg,#22d3ee,#0ea5e9);
          display:flex;align-items:center;justify-content:center;font-size:13px;">\u{1F6E1}\uFE0F</div>
        <span style="font:800 13px ui-sans-serif;color:#fff;flex:1;">Heimdall</span>
        <span style="font:600 11px ui-sans-serif;color:#64748b;">${s?"\u25B4":"\u25BE"}</span>
      </div>
      <div id="body" style="display:${s?"none":"block"};padding:13px;">${e}</div>
    </div>`}function g(e,t,n="#e8eef6"){return`<div style="flex:1;text-align:center;">
    <div style="font:800 17px ui-sans-serif;color:${n};">${t}</div>
    <div style="font:600 10px ui-sans-serif;color:#64748b;text-transform:uppercase;letter-spacing:0.04em;">${e}</div>
  </div>`}function h(e,t){let n=C(t.trustScore);i.mount.innerHTML=l(`
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;">
      <div style="position:relative;width:62px;height:62px;border-radius:999px;flex-shrink:0;
        background:conic-gradient(${p(n)} ${t.trustScore*3.6}deg, rgba(255,255,255,0.08) 0);
        display:flex;align-items:center;justify-content:center;">
        <div style="width:48px;height:48px;border-radius:999px;background:#0b1220;display:flex;flex-direction:column;align-items:center;justify-content:center;">
          <span style="font:800 18px ui-sans-serif;color:${p(n)};">${t.trustScore}</span>
          <span style="font:600 8px ui-sans-serif;color:#64748b;">TRUST</span>
        </div>
      </div>
      <div>
        <div style="font:700 13px ui-sans-serif;color:#e8eef6;">${r(e.owner)}/${r(e.repo)}</div>
        <div style="display:inline-flex;align-items:center;gap:6px;margin-top:5px;">
          <span style="font:800 12px ui-sans-serif;padding:3px 9px;border-radius:7px;color:#04121f;background:${w(t.grade)};">Grade ${r(t.grade??"\u2014")}</span>
        </div>
      </div>
    </div>
    <div style="display:flex;gap:6px;padding:11px;border-radius:12px;background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.06);margin-bottom:11px;">
      ${g("Agents",String(t.agentsCount),"#a371f7")}
      ${g("MCP",String(t.mcpCount),"#56d4dd")}
      ${g("Findings",String(t.findingsCount),t.findingsCount>0?"#f97316":"#3fb950")}
    </div>
    <div style="font:500 11px ui-sans-serif;color:#64748b;margin-bottom:11px;">
      Latest scan ${new Date(t.createdAt).toLocaleString()} \xB7 via ${r(t.source)}
    </div>
    <div style="display:flex;gap:7px;">
      <button id="rescan" style="flex:1;padding:9px;border:none;border-radius:10px;cursor:pointer;font:700 12px ui-sans-serif;background:linear-gradient(135deg,#22d3ee,#0ea5e9);color:#04121f;">Re-scan</button>
      <button id="dash" style="flex:1;padding:9px;border-radius:10px;cursor:pointer;font:700 12px ui-sans-serif;background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.12);color:#e8eef6;">Dashboard</button>
    </div>`),d(e),i.mount.querySelector("#rescan")?.addEventListener("click",()=>E(e)),i.mount.querySelector("#dash")?.addEventListener("click",()=>a({type:"OPEN_DASHBOARD",path:"/agent-security"}).catch(()=>{}))}function x(e,t){i.mount.innerHTML=l(`
    <div style="font:700 13px ui-sans-serif;color:#e8eef6;margin-bottom:6px;">${r(e.owner)}/${r(e.repo)}</div>
    <p style="margin:0 0 12px;font:400 12px/1.5 ui-sans-serif;color:#94a3b8;">
      ${t?"This repository hasn\u2019t been scanned yet. Run Heimdall\u2019s agent-security analysis to get a trust score, agent/MCP inventory and findings.":"Connect your Heimdall account to scan this repository for AI-agent &amp; MCP risk."}
    </p>
    <button id="act" style="width:100%;padding:11px;border:none;border-radius:11px;cursor:pointer;font:700 13px ui-sans-serif;background:linear-gradient(135deg,#22d3ee,#0ea5e9);color:#04121f;">
      ${t?"Scan with Heimdall":"Connect & scan"}
    </button>`),d(e),i.mount.querySelector("#act")?.addEventListener("click",async()=>{if(!t){await a({type:"OPEN_DASHBOARD",path:"/connect/extension"}).catch(()=>{});return}E(e)})}function v(e){i.mount.innerHTML=l(`
    <div style="display:flex;align-items:center;gap:10px;padding:6px 0;">
      <div style="width:18px;height:18px;border:2px solid rgba(255,255,255,0.15);border-top-color:#22d3ee;border-radius:999px;animation:heimdall-spin 0.8s linear infinite;"></div>
      <span style="font:600 12px ui-sans-serif;color:#94a3b8;">${r(e)}</span>
    </div>
    <style>@keyframes heimdall-spin{to{transform:rotate(360deg)}}</style>`),d(b())}function A(e,t){i.mount.innerHTML=l(`
    <div style="font:700 12px ui-sans-serif;color:#fca5a5;margin-bottom:6px;">Couldn\u2019t load Heimdall</div>
    <p style="margin:0 0 10px;font:400 12px/1.5 ui-sans-serif;color:#94a3b8;">${r(t)}</p>
    <button id="retry" style="width:100%;padding:9px;border-radius:10px;cursor:pointer;font:700 12px ui-sans-serif;background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.12);color:#e8eef6;">Retry</button>`),d(e),i.mount.querySelector("#retry")?.addEventListener("click",()=>T(e))}function d(e){i.mount.querySelector("#hdr")?.addEventListener("click",()=>{s=!s;let t=i.mount.querySelector("#body");t&&(t.style.display=s?"none":"block");let n=i.mount.querySelector("#hdr span:last-child");n&&(n.textContent=s?"\u25B4":"\u25BE")})}async function E(e){v(`Scanning ${e.owner}/${e.repo}\u2026`);try{let t=await a({type:"API_AGENT_SCAN",repoUrl:`https://github.com/${e.owner}/${e.repo}`}),n=Math.max(0,100-t.result.riskScore);h(e,{id:"live",repo:`${e.owner}/${e.repo}`,commitSha:t.repo.commitSha,trustScore:n,riskScore:t.result.riskScore,grade:t.result.grade,findingsCount:t.result.findings.length,agentsCount:t.result.agents.length,mcpCount:t.result.mcpServers.length,source:"extension",createdAt:new Date().toISOString()})}catch(t){A(e,t instanceof Error?t.message:String(t))}}async function T(e){if(!(await y()).githubOverlay){i.host.style.display="none";return}i.host.style.display="block",v("Checking Heimdall\u2026");try{let n=await a({type:"GET_STATE"});if(!n.signedIn){x(e,!1);return}let o=n.scans.find(c=>c.repo.toLowerCase()===`${e.owner}/${e.repo}`.toLowerCase());o?h(e,o):x(e,!0)}catch(n){A(e,n instanceof Error?n.message:String(n))}}var S="";function N(){if(location.pathname===S)return;S=location.pathname;let e=b();e?T(e):i.host.style.display="none"}var I=new MutationObserver(()=>N());I.observe(document.body,{childList:!0,subtree:!0});N();
