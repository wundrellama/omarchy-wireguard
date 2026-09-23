import sys, json, os, time
from pathlib import Path
sys.path[:0] = ['/test', '/backend']
import sandbox as s
s.HOST = json.loads(sys.argv[sys.argv.index('--host') + 1]); s.guard()
from omarchy_wireguard.system import HostSystem, CommandRunner
from omarchy_wireguard.controller import Controller
from omarchy_wireguard.storage import StateStore
s.CURRENT = {k: os.readlink('/proc/self/ns/' + k) for k in s.HOST}
result = {'checks': s.CHECKS}
try:
    s.services()
    s.write('/etc/nsswitch.conf', 'passwd: files\ngroup: files\nhosts: mymachines mdns_minimal [NOTFOUND=return] resolve files myhostname dns\n')
    peer = s.Peer()
    s.cmd(['ip','link','add','eth0','type','veth','peer','name','ethpeer'])
    s.cmd(['ip','link','set','ethpeer','netns',str(peer.pid)])
    s.cmd(['ip','addr','add','192.0.2.1/24','dev','eth0'])
    s.cmd(['ip','link','set','eth0','up'])
    s.cmd(['ip','route','add','default','via','192.0.2.2','dev','eth0'])
    peer.ip('link','set','lo','up'); peer.ip('addr','add','192.0.2.2/24','dev','ethpeer'); peer.ip('link','set','ethpeer','up')
    peer.ip('addr','add','192.0.2.88/32','dev','lo'); peer.ip('addr','add','198.51.100.80/32','dev','lo')
    peer.ip('link','add','wgpeer','type','wireguard'); peer.ip('addr','add','10.77.0.1/24','dev','wgpeer')
    private = s.cmd(['wg','genkey']).strip(); peer_private = s.cmd(['wg','genkey']).strip()
    public = s.cmd(['wg','pubkey'],private).strip(); peer_public=s.cmd(['wg','pubkey'],peer_private).strip()
    peer.call('wg',config=f'[Interface]\nPrivateKey = {peer_private}\nListenPort = 51820\n[Peer]\nPublicKey = {public}\nAllowedIPs = 10.77.0.2/32\n')
    peer.ip('link','set','wgpeer','up'); peer.call('start')
    s.cmd(['resolvectl','dns','eth0','192.0.2.2']); s.cmd(['resolvectl','domain','eth0','~original.test']); s.cmd(['resolvectl','default-route','eth0','yes'])
    commands=[]
    class Runner(CommandRunner):
        def run(self, argv, **kwargs):
            s.guard(); commands.append(argv)
            return super().run(argv, **kwargs)
    system=HostSystem(Runner(),controller_uid=0)
    controller=Controller(StateStore(Path('/var/lib/omarchy-wireguard')),system,controller_uid=0); controller.boot()
    endpoint='fresh-' + str(time.monotonic_ns()) + '.endpoint.test'
    s.check('disabled_positive_control', bool(system.resolve_endpoint('disabled-control.endpoint.test',51820)))
    config=f'[Interface]\nPrivateKey = {private}\nAddress = 10.77.0.2/24\nDNS = 10.77.0.1\n[Peer]\nPublicKey = {peer_public}\nAllowedIPs = 0.0.0.0/0\nEndpoint = {endpoint}:51820\nPersistentKeepalive = 1\n'
    s.write('/run/synthetic.conf',config); os.chmod('/run/synthetic.conf',0o600)
    controller.import_profiles({'path':'/run/synthetic.conf','locations':{'synthetic.conf':{'country':'Test','city':'Private'}}})
    profile=controller.catalog[0]
    original_activate = system.activate
    def activate(uuid, timeout=10):
        unrelated_failed = False
        try: system.resolve_endpoint('unrelated-fresh.endpoint.test', 51820, timeout=3)
        except Exception: unrelated_failed = True
        s.check('bootstrap_unrelated_hostname_still_blocked', unrelated_failed and
                not any(p.get('name') == 'unrelated-fresh.endpoint.test'
                        for p in peer.call('seen')['packets']))
        descendant = 'child.' + endpoint
        s.check('bootstrap_route_is_suffix_not_exact_qname',
                bool(system.resolve_endpoint(descendant, 51820, timeout=3)) and
                any(p.get('name') == descendant and p['ingress'] == 'ethpeer'
                    for p in peer.call('seen')['packets']))
        s.cmd(['resolvectl', 'flush-caches'])
        before = len([p for p in peer.call('seen')['packets'] if p.get('name') == endpoint])
        interface = original_activate(uuid, timeout)
        after = len([p for p in peer.call('seen')['packets'] if p.get('name') == endpoint])
        s.check('NM_itself_resolves_hostname_after_cache_flush', after > before, before=before, after=after)
        return interface
    # Observation/cache invalidation only: never modifies DNS routing or activation.
    system.activate = activate
    commands.clear(); controller.connect({'profile': profile['id']}); controller.tick()
    s.check('hostname_controller_connects_real_NM', controller.mode == 'connected',
            mode=controller.mode, error=controller.last_error, verification=controller.last_checks,
            domains=s.cmd(['resolvectl', 'domain', 'eth0']),
            endpoint_packets=[p for p in peer.call('seen')['packets'] if p.get('name') == endpoint])
    domains=s.cmd(['resolvectl','domain','eth0'])
    s.check('bootstrap_route_removed_after_activation',endpoint not in domains and '~lan' in domains,domains=domains)
    packets=peer.call('seen')['packets']
    s.check('endpoint_resolved_on_underlay',any(p.get('name')==endpoint and p['ingress']=='ethpeer' for p in packets),packets=packets)
    public_answer=s.cmd(['resolvectl','query','--type=A','fresh-public-after.test'])
    s.check('public_dns_after_connect_uses_tunnel','203.0.113.80' in public_answer and any(p.get('name')=='fresh-public-after.test' and p['ingress']=='wgpeer' for p in peer.call('seen')['packets']))
    controller.disconnect({})
    s.check('disconnect_restores_original_domains','~original.test' in s.cmd(['resolvectl','domain','eth0']))
    result['status']='passed'
except Exception as e:
    result.update(status='failed',error=str(e))
finally:
    result['logs']={}
    for name,p,log in reversed(s.CHILDREN):
        if p.poll() is None: p.terminate()
        try: p.wait(timeout=2)
        except Exception: p.kill();p.wait(timeout=2)
        log.flush();log.seek(0);result['logs'][name]=log.read()[-4000:];log.close()
    result['children_reaped']=all(p.poll() is not None for _,p,_ in s.CHILDREN)
print(json.dumps(result,indent=2))
sys.exit(result['status']!='passed')
