FROM amazoncorretto:16

WORKDIR /root

RUN yum install -y git zip unzip make wget ocaml maven "perl(JSON::PP)" "perl(IPC::Cmd)" && git clone https://github.com/mareebsiddiqui/vuln-regex-detector.git

WORKDIR /root/vuln-regex-detector/

ENV VULN_REGEX_DETECTOR_ROOT /root/vuln-regex-detector
ENV SKIP_PKG_DEPS 1
ENV REGEX_DEBUG 1

RUN ./configure

RUN wget https://download-ib01.fedoraproject.org/pub/epel/7/x86_64/Packages/e/epel-release-7-13.noarch.rpm && rpm -Uvh epel-release*rpm && yum install perl-HTTP-Server-Simple -y

EXPOSE 8080

CMD perl server.pl