hget() {
    if [ "$2" = "-" ] && [ -t 1 ]; then
        command hget "$@"
    else
        { command hget "$@" 3>&1 1>&4 | bar >&2; } 4>&1
    fi
}
