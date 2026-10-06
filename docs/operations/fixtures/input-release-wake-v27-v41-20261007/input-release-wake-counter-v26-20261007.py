from pathlib import Path
import threading,time,sys
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');sys.path.insert(0,str(r/'tools'));import interstellar_tcp as tcp
server=object.__new__(tcp.Server);server.guard=threading.Lock();server.running=True;server.input_wake=threading.Event();server.input_active=('unacknowledged-original-slot-model',);server.tcp_mesh_waiters=set();ready=threading.Event();done=threading.Event();observed=[]
def input_owner():
 with server.guard:server.tcp_mesh_waiters.add(threading.current_thread())
 ready.set();started=time.monotonic();woken=server.input_wake.wait(.25);observed.append(dict(woken=woken,seconds=time.monotonic()-started));done.set()
thread=threading.Thread(target=input_owner,name='rld-release-wake-counter');server.input_thread=thread;server.local_mesh_owner=threading.current_thread();thread.start();assert ready.wait(1)
try:
 server._release_mesh_turn();assert server.local_mesh_owner is None
 assert done.wait(.1),'original local release left an actual retained input waiter in fixed .25-second polling sleep'
 assert observed[0]['woken']
finally:
 server.input_wake.set();thread.join(1);assert not thread.is_alive()
print(observed)
