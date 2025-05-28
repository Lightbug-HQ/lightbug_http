from sys.param_env import env_get_string


struct LogLevel:
    alias FATAL = 0
    alias ERROR = 1
    alias WARN = 2
    alias INFO = 3
    alias DEBUG = 4


fn get_log_level() -> Int:
    """Returns the log level based on the parameter environment variable `LOG_LEVEL`.

    Returns:
        The log level.
    """
    alias level = env_get_string["LB_LOG_LEVEL", "INFO"]()

    @parameter
    if level == "INFO":
        return LogLevel.INFO
    elif level == "WARN":
        return LogLevel.WARN
    elif level == "ERROR":
        return LogLevel.ERROR
    elif level == "DEBUG":
        return LogLevel.DEBUG
    elif level == "FATAL":
        return LogLevel.FATAL
    else:
        return LogLevel.INFO


alias LOG_LEVEL = get_log_level()
"""Logger level determined by the `LB_LOG_LEVEL` param environment variable.

When building or running the application, you can set `LB_LOG_LEVEL` by providing the the following option:

```bash
mojo build ... -D LB_LOG_LEVEL=DEBUG
# or
mojo ... -D LB_LOG_LEVEL=DEBUG
```
"""


@value
struct Logger[level: Int]:
    alias STDOUT = 1
    alias STDERR = 2

    fn _log_message[event_level: Int](self, message: String):
        @parameter
        if level >= event_level:

            @parameter
            if event_level < LogLevel.WARN:
                # Write to stderr if FATAL or ERROR
                print(message, file=FileDescriptor(Self.STDERR))
            else:
                print(message)

    fn info[*Ts: Writable](self, *messages: *Ts):
        var msg = String.write("\033[36mINFO\033[0m  - ")

        @parameter
        fn write_message[T: Writable](message: T):
            msg.write(message, " ")

        messages.each[write_message]()
        self._log_message[LogLevel.INFO](msg)

    fn warn[*Ts: Writable](self, *messages: *Ts):
        var msg = String.write("\033[33mWARN\033[0m  - ")

        @parameter
        fn write_message[T: Writable](message: T):
            msg.write(message, " ")

        messages.each[write_message]()
        self._log_message[LogLevel.WARN](msg)

    fn error[*Ts: Writable](self, *messages: *Ts):
        var msg = String.write("\033[31mERROR\033[0m - ")

        @parameter
        fn write_message[T: Writable](message: T):
            msg.write(message, " ")

        messages.each[write_message]()
        self._log_message[LogLevel.ERROR](msg)

    fn debug[*Ts: Writable](self, *messages: *Ts):
        var msg = String.write("\033[34mDEBUG\033[0m - ")

        @parameter
        fn write_message[T: Writable](message: T):
            msg.write(message, " ")

        messages.each[write_message]()
        self._log_message[LogLevel.DEBUG](msg)

    fn fatal[*Ts: Writable](self, *messages: *Ts):
        var msg = String.write("\033[35mFATAL\033[0m - ")

        @parameter
        fn write_message[T: Writable](message: T):
            msg.write(message, " ")

        messages.each[write_message]()
        self._log_message[LogLevel.FATAL](msg)


alias logger = Logger[LOG_LEVEL]()
