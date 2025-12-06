from .common_response import *
from .request import *
from .response import *


trait Encodable:
    fn encode(var self) -> Bytes:
        ...


@always_inline
fn encode[T: Encodable](var data: T) -> Bytes:
    return data^.encode()
