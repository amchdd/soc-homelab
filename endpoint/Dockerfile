FROM wazuh/wazuh-agent:4.14.8@sha256:32215f51b62b072b9ff010d1c03da4e1f586947aaa686c40b927509fc85855cc
# Fixed Amazon Linux repository and package versions for the portfolio snapshot.
RUN dnf install -y --releasever=2023.12.20260831 \
      openssh-server-9.9p1-10.amzn2023.0.2 \
      openssh-clients-9.9p1-10.amzn2023.0.2 \
      rsyslog-8.2204.0-3.amzn2023.0.5 \
    && dnf clean all \
    && useradd --create-home --shell /bin/bash labuser
COPY sshd_config /etc/ssh/sshd_config
COPY rsyslog.conf /etc/rsyslog-lab.conf
COPY start.sh /usr/local/bin/start-lab
COPY askpass.sh /usr/local/bin/lab-askpass
RUN chmod 755 /usr/local/bin/start-lab /usr/local/bin/lab-askpass
ENTRYPOINT ["/usr/local/bin/start-lab"]
