from utils import Variant, StaticTuple
from sys.ffi import c_uint, c_int

# Below is a straightforward translaation of the Rust FAF (Fast As Fuck) code: 
# Courtesy of the original author @errantmind
# https://github.com/errantmind/faf/blob/master/src/epoll.rs

alias MAX_EPOLL_EVENTS_RETURNED = 1024
alias REQ_BUF_SIZE = 1024
alias RES_BUF_SIZE = 35
alias MAX_CONN = 1024

# should be union
# alias EpollData = Variant[OpaquePointer, c_int, c_uint, UInt64]
alias EpollData = UInt64

# should be packed
@fieldwise_init
@register_passable("trivial")
struct EpollEvent(Copyable, Movable):
    var events: c_uint
    var data: EpollData

# this and following should be 64 aligned
@fieldwise_init
@register_passable("trivial")
struct AlignedHttpDate:
    var data: StaticTuple[UInt8, 35]

@fieldwise_init
@register_passable("trivial")
struct AlignedEpollEvents:
    var data: StaticTuple[EpollEvent, MAX_EPOLL_EVENTS_RETURNED]

@fieldwise_init
struct AlignedEpollEvent:
    var data: EpollEvent

@fieldwise_init
@register_passable("trivial")
struct ReqBufAligned:
    var data: StaticTuple[UInt8, REQ_BUF_SIZE * MAX_CONN]

@fieldwise_init
@register_passable("trivial")
struct ResBufAligned:
    var data: StaticTuple[UInt8, RES_BUF_SIZE]