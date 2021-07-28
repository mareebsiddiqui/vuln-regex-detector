FROM amazoncorretto:16

WORKDIR /root

RUN yum install -y git && git clone https://github.com/mareebsiddiqui/vuln-regex-detector.git

WORKDIR /root/vuln-regex-detector/

ENV VULN_REGEX_DETECTOR_ROOT /root/vuln-regex-detector/

RUN ./configure

RUN yum install -y "perl(JSON::PP)"