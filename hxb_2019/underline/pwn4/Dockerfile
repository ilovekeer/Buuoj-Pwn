FROM ubuntu:18.04
RUN apt-get update && apt-get install -y \
    xinetd \
    qemu-user-static \
    libc6-i386 \
    && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /home/ctf && useradd -U ctf
COPY xinetd /etc/xinetd.d/ctf
COPY flag /home/ctf/
RUN chmod 444 /home/ctf/flag
COPY pwn4 /usr/local/bin/
EXPOSE 8888
CMD ["/usr/sbin/xinetd", "-dontfork"]
