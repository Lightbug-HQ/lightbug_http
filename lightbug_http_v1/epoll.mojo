from utils import Variant
from memory import UnsafePointer
from sys.ffi import c_uint, c_int

alias EpollData = Variant[UnsafePointer[NoneType], c_int, c_uint, UInt64]

@fieldwise_init
struct EpollEvent:
    var events: c_uint
    var data: EpollData