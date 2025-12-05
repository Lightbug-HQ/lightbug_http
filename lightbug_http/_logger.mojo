from sys import stderr, stdout
from sys.param_env import env_get_string


struct LogLevel:
    comptime FATAL = 0
    comptime ERROR = 1
    comptime WARN = 2
    comptime INFO = 3
    comptime DEBUG = 4


fn get_log_level() -> Int:
    """Returns the log level based on the parameter environment variable `LOG_LEVEL`.

    Returns:
        The log level.
    """
    comptime level = env_get_string["LB_LOG_LEVEL", "INFO"]()

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


comptime LOG_LEVEL = get_log_level()
"""Logger level determined by the `LB_LOG_LEVEL` param environment variable.

When building or running the application, you can set `LB_LOG_LEVEL` by providing the the following option:

```bash
mojo build ... -D LB_LOG_LEVEL=DEBUG
# or
mojo ... -D LB_LOG_LEVEL=DEBUG
```
"""


@fieldwise_init
struct Logger[level: Int](ImplicitlyCopyable, Movable):
    fn _log_message[event_level: Int](self, message: String):
        @parameter
        if level >= event_level:

            @parameter
            if event_level < LogLevel.WARN:
                # Write to stderr if FATAL or ERROR
                print(message, file=stderr)
            else:
                print(message)

    fn info[*Ts: Writable](self, *messages: *Ts):
        var msg = String.write("\033[36mINFO\033[0m  - ")

        @parameter
        for i in range(messages.__len__()):
            msg.write(messages[i], " ")

        self._log_message[LogLevel.INFO](msg)

    fn warn[*Ts: Writable](self, *messages: *Ts):
        var msg = String.write("\033[33mWARN\033[0m  - ")

        @parameter
        for i in range(messages.__len__()):
            msg.write(messages[i], " ")

        self._log_message[LogLevel.WARN](msg)

    fn error[*Ts: Writable](self, *messages: *Ts):
        var msg = String.write("\033[31mERROR\033[0m - ")

        @parameter
        for i in range(messages.__len__()):
            msg.write(messages[i], " ")

        self._log_message[LogLevel.ERROR](msg)

    fn debug[*Ts: Writable](self, *messages: *Ts):
        var msg = String.write("\033[34mDEBUG\033[0m - ")

        @parameter
        for i in range(messages.__len__()):
            msg.write(messages[i], " ")

        self._log_message[LogLevel.DEBUG](msg)

    fn fatal[*Ts: Writable](self, *messages: *Ts):
        var msg = String.write("\033[35mFATAL\033[0m - ")

        @parameter
        for i in range(messages.__len__()):
            msg.write(messages[i], " ")

        self._log_message[LogLevel.FATAL](msg)


comptime logger = Logger[LOG_LEVEL]()
