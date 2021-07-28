FROM amazoncorretto:16

WORKDIR /root

RUN yum install -y git zip unzip make wget ocaml maven && git clone https://github.com/mareebsiddiqui/vuln-regex-detector.git

WORKDIR /root/vuln-regex-detector/

ENV VULN_REGEX_DETECTOR_ROOT /root/vuln-regex-detector/
ENV SKIP_PKG_DEPS 1

RUN ./configure

RUN yum install -y "perl(JSON::PP) perl(HTTP::Daemon)"

EXPOSE 4444

RUN perl server.pl