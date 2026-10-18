import queue,time
from odmm_desktop_async_v2273 import AsyncReader

def wait(reader):
    for _ in range(100):
        reader.drain()
        if not reader.scheduler.empty():continue
        time.sleep(.01)

def test_success():
    q=queue.Queue();r=AsyncReader(q);out=[]
    r.submit(lambda:42,out.append,lambda e:out.append(e))
    wait(r);r.close();assert out==[42]

def test_error_no_sensitive_detail():
    q=queue.Queue();r=AsyncReader(q);out=[]
    def fail():raise ValueError('sensitive-token')
    r.submit(fail,out.append,out.append)
    wait(r);r.close();assert out==['ValueError']

def test_stale_discard():
    q=queue.Queue();r=AsyncReader(q);out=[]
    r.submit(lambda:1,out.append,out.append)
    r.invalidate();wait(r);r.close();assert out==[]

def test_closed():
    q=queue.Queue();r=AsyncReader(q);r.close();assert not r.submit(lambda:1,lambda x:None,lambda x:None)
