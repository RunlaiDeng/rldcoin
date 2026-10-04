"""Additional OS CPU observation for an explicit retained live-process anchor.

Uses the SDK-defined proc_pid_rusage V1 ABI and a real-child capability check.
This is not a census of Native commands, live-child RSS or independent identity.
Never sum overlapping parent/child aggregates as a node-wide total.
"""
import ctypes
import platform
import subprocess
import time

from regional_ground_resources import process_read,require


class RusageV1(ctypes.Structure):
    _fields_=[('ri_uuid',ctypes.c_uint8*16)]+[(name,ctypes.c_uint64) for name in (
        'ri_user_time','ri_system_time','ri_pkg_idle_wkups','ri_interrupt_wkups','ri_pageins',
        'ri_wired_size','ri_resident_size','ri_phys_footprint','ri_proc_start_abstime','ri_proc_exit_abstime',
        'ri_child_user_time','ri_child_system_time','ri_child_pkg_idle_wkups','ri_child_interrupt_wkups',
        'ri_child_pageins','ri_child_elapsed_abstime')]


class Timebase(ctypes.Structure):
    _fields_=[('numer',ctypes.c_uint32),('denom',ctypes.c_uint32)]


def inclusive_read(pid):
    require(platform.system()=='Darwin','exited-child CPU backend currently verified on macOS only')
    require(type(pid) is int and 0<pid<2**31,'explicit positive PID required')
    library=ctypes.CDLL('/usr/lib/libproc.dylib',use_errno=True)
    function=library.proc_pid_rusage
    function.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_void_p]
    function.restype=ctypes.c_int
    usage=RusageV1()
    require(function(pid,1,ctypes.byref(usage))==0,'kernel process resource observation unavailable')
    clock=ctypes.CDLL('/usr/lib/libSystem.B.dylib')
    clock.mach_timebase_info.argtypes=[ctypes.POINTER(Timebase)]
    clock.mach_timebase_info.restype=ctypes.c_int
    scale=Timebase()
    require(clock.mach_timebase_info(ctypes.byref(scale))==0 and scale.numer>0 and scale.denom>0,
            'kernel CPU clock conversion unavailable')
    seconds=lambda ticks:ticks*scale.numer/scale.denom/1e9
    identity=process_read(pid)
    return dict(start=identity['start'],command_sha256=identity['command_sha256'],
                cpu_seconds=seconds(usage.ri_user_time+usage.ri_system_time+usage.ri_child_user_time+usage.ri_child_system_time),
                process_start_abstime=usage.ri_proc_start_abstime,
                exited_children_cpu_seconds=seconds(usage.ri_child_user_time+usage.ri_child_system_time),
                clock_timebase_numer=scale.numer,clock_timebase_denom=scale.denom)


class ExitedChildCpu:
    def __init__(self, process):
        self.pid,self.label,self.identity=process.pid,process.label,process.identity
        self.previous=None
        self.kernel_start=None

    def sample(self):
        try:
            before=time.monotonic()
            own=process_read(self.pid)
            combined=inclusive_read(self.pid)
            require((own['start'],own['command_sha256'])==self.identity
                    and (combined['start'],combined['command_sha256'])==self.identity,
                    'process identity changed during inclusive observation')
            kernel_start=combined['process_start_abstime']
            require(type(kernel_start) is int and kernel_start>0
                    and (self.kernel_start is None or kernel_start==self.kernel_start),
                    'kernel process start changed')
            end=time.monotonic()
            require(combined['cpu_seconds']+.02>=own['cpu_seconds'],'inclusive CPU observation regressed')
            child_cpu=combined['exited_children_cpu_seconds']
            percent=None
            if self.previous is not None:
                old_at,old_cpu,old_child_cpu=self.previous
                require(end>old_at and combined['cpu_seconds']>=old_cpu and child_cpu>=old_child_cpu,
                        'inclusive CPU counter or time regressed')
                percent=100*(combined['cpu_seconds']-old_cpu)/(end-old_at)
            self.kernel_start=kernel_start
            self.previous=(end,combined['cpu_seconds'],child_cpu)
            return dict(label=self.label,available=True,monotonic_start=before,monotonic_end=end,
                        own_cpu_lifetime_seconds=own['cpu_seconds'],
                        own_plus_exited_children_cpu_lifetime_seconds=combined['cpu_seconds'],
                        own_plus_exited_children_one_core_percent=percent,
                        non_atomic_exited_children_estimate_seconds=child_cpu,
                        observation_includes_all_live_child_cpu=False,live_child_rss_measured=False,
                        Native_command_census_verified=False,atomic_snapshot=False)
        except (OSError,ValueError,subprocess.SubprocessError):
            self.previous=None
            return dict(label=self.label,available=False,reason='unsupported_changed_or_unavailable',
                        own_cpu_lifetime_seconds=None,own_plus_exited_children_cpu_lifetime_seconds=None,
                        own_plus_exited_children_one_core_percent=None,
                        non_atomic_exited_children_estimate_seconds=None,
                        observation_includes_all_live_child_cpu=False,live_child_rss_measured=False,
                        Native_command_census_verified=False,atomic_snapshot=False)
