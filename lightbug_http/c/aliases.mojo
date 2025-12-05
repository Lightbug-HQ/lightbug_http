comptime ExternalMutUnsafePointer = UnsafePointer[origin = MutOrigin.external]
comptime ExternalImmutUnsafePointer = UnsafePointer[origin = ImmutOrigin.external]

comptime c_void = NoneType
