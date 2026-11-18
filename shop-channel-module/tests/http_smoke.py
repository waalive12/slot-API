#!/usr/bin/env python3
"""Ephemeral loopback HTTP test, no persistent credentials or database."""
import json, os, secrets, socket, subprocess, tempfile, time, urllib.request, urllib.error
from pathlib import Path
root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='shop-smoke-') as tmp:
    env = os.environ.copy()
    env.update(SHOP_ADMIN_TOKEN=secrets.token_hex(32), SHOP_INTEGRATION_TOKEN=secrets.token_hex(32), SHOP_DB=tmp+'/test.sqlite')
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0)); port = sock.getsockname()[1]
    p = subprocess.Popen(['php','-S',f'127.0.0.1:{port}','-t',str(root/'public'),str(root/'public/index.php')],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    count = 0
    def req(path, method='GET', data=None, token=None, headers=None):
        h = headers or {}
        if token: h['Authorization']='Bearer '+token
        if data is not None: h['Content-Type']='application/json'
        r=urllib.request.Request(f'http://127.0.0.1:{port}'+path,data=None if data is None else json.dumps(data).encode(),headers=h,method=method)
        try:
            with urllib.request.urlopen(r,timeout=3) as x: return x.status,json.loads(x.read()),x.headers
        except urllib.error.HTTPError as x: return x.code,json.loads(x.read()),x.headers
    def check(ok,label):
        global count
        assert ok,label
        count+=1;print('PASS',label)
    try:
        for _ in range(50):
            try: req('/'); break
            except OSError: time.sleep(.1)
        check(req('/')[0]==200,'public root accessible')
        check(req('/',headers={'User-Agent':'Other Agent','CF-IPCountry':'US','X-Forwarded-For':'203.0.113.5'})[1]==req('/')[1],'public root invariant')
        check(req('/admin/networks')[0]==401,'admin authentication required')
        a=env['SHOP_ADMIN_TOKEN']; i=env['SHOP_INTEGRATION_TOKEN']
        check(req('/admin/networks',token=i)[0]==401,'integration token cannot administer')
        check(req('/admin/networks','POST',{'entries':[{'cidr':'2001:db8::123/64','expires_at':int(time.time())+3600}]},a)[0]==200,'network import')
        check(req('/admin/networks',token=a)[1]['entries'][0]['cidr']=='2001:db8::/64','canonical import exposed')
        check(req('/admin/products','PUT',{'product':'demo','countries':['BR']},a)[0]==200,'product configuration')
        check(req('/internal/shipping/check','POST',{'product':'demo','shipping_country':'BR'},i)[1]['allowed'],'shipping supported')
        check(not req('/internal/shipping/check','POST',{'product':'demo','shipping_country':'US'},i)[1]['allowed'],'shipping unsupported')
        check(req('/admin/rates','PUT',{'scope':'login','mode':'limit','max_hits':1,'window_seconds':3600},a)[0]==200,'rate policy')
        payload={'scope':'login','subject':'a'*64,'client_ip':'192.0.2.1'}
        check(req('/internal/rate/consume','POST',payload,i)[0]==200,'first request allowed')
        code,_,headers=req('/internal/rate/consume','POST',payload,i)
        check(code==429 and int(headers['Retry-After'])>0,'limit returns retry header')
        check(req('/internal/rate/consume','POST',{'scope':'landing','subject':'a'*64,'client_ip':'192.0.2.1'},i)[0]==400,'landing classification unavailable')
        check(req('/src/Core.php')[0]==404,'source not served')
        check(req('/admin/audit',token=a)[2]['Cache-Control']=='no-store','admin no-store')
        check(req('/internal/shipping/check','POST',{'product':'demo','shipping_country':'BR'},a)[0]==401,'admin token cannot integrate')
        row={'scope':'coupon','cidr':'192.0.2.0/24','expires_at':int(time.time())+3600}
        check(req('/admin/operation-denies','POST',{'entries':[row]},a)[0]==200,'deny import')
        entries=req('/admin/operation-denies',token=a)[1]['entries']
        deny_id=entries[0]['id']
        blocked={'scope':'coupon','subject':'b'*64,'client_ip':'::ffff:192.0.2.8'}
        check(req('/internal/rate/consume','POST',blocked,i)[0]==403,'mapped operation deny 403')
        check(req('/')[0]==200,'deny never affects public root')
        blocked['scope']='register'
        check(req('/internal/rate/consume','POST',blocked,i)[0]==200,'deny scope isolation')
        check(req('/internal/rate/consume','POST',{**blocked,'path':'/'},i)[0]==400,'arbitrary public path rejected')
        check(req('/internal/rate/consume','POST',{'scope':'login','subject':'a'*64},i)[0]==400,'missing observed IP fails closed')
        row['cidr']='2001:db8::/32'
        check(req(f'/admin/operation-denies/{deny_id}','PUT',row,a)[0]==200,'deny update')
        blocked.update(scope='coupon',client_ip='2001:db8::123')
        check(req('/internal/rate/consume','POST',blocked,i)[0]==403,'IPv6 operation deny')
        check(req(f'/admin/operation-denies/{deny_id}','DELETE',token=a)[0]==200,'deny deletion')
        check(req('/internal/rate/consume','POST',blocked,i)[0]==200,'deleted deny released')
        row['cidr']='::/0'
        check(req('/admin/operation-denies','POST',{'entries':[row]},a)[0]==400,'mass deny rejected')

        print(f'{count} HTTP assertions passed')
    finally:
        p.terminate();p.wait(timeout=5)
