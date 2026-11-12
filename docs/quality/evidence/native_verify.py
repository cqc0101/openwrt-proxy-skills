import os,subprocess,pathlib,json,sys,importlib.util
root=pathlib.Path('/root/src');os.chdir(root)
sys.path.insert(0,str(root/'skills/singbox-openwrt/scripts'))
import auto_config
nodes=['trojan://audit-password@proxy.example:443?sni=proxy.example#test','hysteria2://audit-password@proxy.example:443?sni=proxy.example#hy2','vless://00000000-0000-4000-8000-000000000001@proxy.example:443?security=tls&sni=proxy.example&type=tcp#vless']
nodes += ['trojan://audit-password@proxy.example:443?sni=proxy.example#%E4%B8%AD%E6%96%87%E8%8A%82%E7%82%B9', 'trojan://audit-password@proxy.example:443#node_4', 'trojan://audit-password@proxy.example:443#x%27%3B%7D%20routing%7B']
results=[]; out=pathlib.Path('/root/native-cases');out.mkdir(exist_ok=True)
def run(label,cmd,expected=0):
 p=subprocess.run(cmd,capture_output=True,text=True,timeout=90)
 results.append(dict(label=label,cmd=cmd,returncode=p.returncode,expected=expected,pass_=p.returncode==0 if expected==0 else p.returncode!=0,stdout=p.stdout,stderr=p.stderr))
 print(label,p.returncode,flush=True)
 if p.returncode:print(p.stderr[-1500:],flush=True)
for v in ['1.13','1.14']:
 b='/root/bin/sing-box-'+v
 run('version-'+v,[b,'version'])
 for mode in ['realip','fakeip']:
  run('template-'+v+'-'+mode,[b,'check','-c',str(root/f'skills/singbox-openwrt/assets/templates/openwrt-{v}-tun-{mode}.json')])
  for topo in ['main','bypass']:
   config=auto_config.build_config(version=v,dns_mode=mode,node_uris=nodes,topology=topo,main_router_ip='192.168.1.1' if topo=='bypass' else None)
   p=out/f'sing-{v}-{mode}-{topo}.json';p.write_text(json.dumps(config));run(p.stem,[b,'check','-c',str(p)])
 p=out/'bad.json';p.write_text('{"outbounds":[{"type":"audit-invalid"}]}');run('reject-invalid-'+v,[b,'check','-c',str(p)],1)
spec=importlib.util.spec_from_file_location('sub_to_dae',root/'skills/dae-openwrt/scripts/sub_to_dae.py');dae=importlib.util.module_from_spec(spec);spec.loader.exec_module(dae)
from sub_parser import parse_subscription_text
parsed=parse_subscription_text('\n'.join(nodes))
b='/root/bin/dae';run('dae-version',[b,'--version'])
run('dae-template',[b,'validate','-c',str(root/'skills/dae-openwrt/assets/templates/openwrt.dae')])
for v in ['legacy','modern']:
 for topo in ['main','bypass']:
  p=out/f'dae-{v}-{topo}.dae';p.write_text(dae.build_full_dae_config(parsed,dae_version=v,topology=topo,main_router_ip='192.168.1.1',ram_mb=256));p.chmod(0o600);run(p.stem,[b,'validate','-c',str(p)])
p=out/'invalid.dae';p.write_text('global { invalid_audit_key: true }');p.chmod(0o600);run('dae-invalid',[b,'validate','-c',str(p)],1)
pathlib.Path('/root/native-results.json').write_text(json.dumps(results,indent=2))
sys.exit(not all(x['pass_'] for x in results))

