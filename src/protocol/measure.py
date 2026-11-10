"""Actual sequential process wall, CPU and peak-RSS observations."""
import json,os,signal,subprocess,sys,time
from src.config import ROOT, MODE
from src.protocol.io import canonical,contained,save,rel
SUITE = ROOT / ".artifacts"

def measure(label,command,request=None,timeout=14400,logdir=None):
    base=contained((logdir or SUITE/'logs')/(label+'_'+str(time.time_ns())))
    base.parent.mkdir(parents=True,exist_ok=True)
    out=base.with_suffix('.out');err=base.with_suffix('.err');began=time.perf_counter()
    with out.open('wb') as stdout,err.open('wb') as stderr:
        child=subprocess.Popen(command,cwd=ROOT,stdin=subprocess.PIPE if request is not None else subprocess.DEVNULL,stdout=stdout,stderr=stderr,start_new_session=True)
        if request is not None:
            try:child.stdin.write(canonical(request));child.stdin.close()
            except BrokenPipeError:pass
        expired=False
        try:
            while True:
                pid,status,usage=os.wait4(child.pid,os.WNOHANG)
                if pid:break
                if time.perf_counter()-began>timeout:
                    os.killpg(child.pid,signal.SIGKILL);pid,status,usage=os.wait4(child.pid,0);expired=True;break
                time.sleep(.04)
        except BaseException:
            try:os.killpg(child.pid,signal.SIGTERM)
            except ProcessLookupError:pass
            os.wait4(child.pid,0);raise
        child.returncode=os.waitstatus_to_exitcode(status)
    record=dict(mode=MODE,measurement_type='ACTUAL',wall_seconds=format(time.perf_counter()-began,'.9f'),cpu_seconds=format(usage.ru_utime+usage.ru_stime,'.9f'),peak_rss_bytes=int(usage.ru_maxrss*(1 if sys.platform=='darwin' else 1024)),exit_code=child.returncode,timed_out=expired,stdout=rel(out),stderr=rel(err))
    save(base.with_suffix('.measurement.json'),record)
    if expired or child.returncode:raise RuntimeError(f'{label}: process failed; see {rel(err)}')
    return (json.loads(out.read_bytes()) if request is not None else None),record

def operation(label,request,timeout=14400,logdir=None):return measure(label,['node','src/witnesses/crypto.mjs'],request,timeout,logdir)
def require(result,key='status',value='PASS'):
    if result.get(key)!=value:raise RuntimeError('Required actual cryptographic result missing')
