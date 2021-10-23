#include "kernel/param.h"
#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int main(int argc, char *argv[])
{
    int i;
    char *new_arguments[MAXARG];

    int is_valid_num = (argv[1][0] < '0' || argv[1][0] > '9');
    // just check if the number is in the integer range ascii value 48(0) - 57(9)
    int valid_num_args = argc >= 3;
    if (!valid_num_args || is_valid_num)
    {
        fprintf(2, "Usage: %s <mask> <command>\n", argv[0]);
        exit(1);
    }
    if (trace(atoi(argv[1])) < 0)
    {
        fprintf(2, "%s: strace failed\n", argv[0]);
        exit(1);
    }

    for (i = 2; i < argc && i < MAXARG; i++)
    {
        new_arguments[i - 2] = argv[i];
    }
    exec(new_arguments[0], new_arguments);
    exit(0);
}