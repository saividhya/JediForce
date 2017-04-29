int ret;
 ret = fcntl(fd, F_SETFD, FD_CLOEXEC)
    if (ret < 0) {
        perror("fnctl()");
        close(fd);
        return -1;
    }

/*have to copy and paste it in source file - ultimate prevention from duplicate files*/
