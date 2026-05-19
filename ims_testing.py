#!/usr/bin/env python3

import argparse
import socket
import re
import base64
from milenage import Milenage
from hashlib import md5
import random
import time
from scapy.layers.ipsec import ESP, SecurityAssociation
from scapy.layers.inet import TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.sendrecv import send, sniff
from scapy.config import conf

# 2602:6:0:1::1

IMSI=311588152000000
MSISDN=17003330000
KI="335e891dfcbcbed4fbdbde0b2d242faf"
OPC="f586b8dd12c9e2d2056765c0d958c101"
PORT = 5060
B = "+10223456789"

class IMSClient:
    ESP_PORT_CLIENT=random.randrange(10000, 25000)
    ESP_PORT_SERVER=random.randrange(10000, 25000)
    ESP_SPI_CLIENT=random.randint(0, 69000)
    ESP_SPI_SERVER=random.randint(0, 69000)
    PCSCF_PORT_CLIENT=None
    PCSCF_PORT_SERVER=None
    PCSCF_SPI_CLIENT=None
    PCSCF_SPI_SERVER=None
    CALL_ID=random.randbytes(20).hex()
    SESSION_ID=random.randbytes(20).hex()
    USER_AGENT="test"
    BRANCH=random.randbytes(11).hex()
    FROM_TAG=random.randbytes(11).hex()

    def __init__(self, source_ip, pcscf, imsi, ipsec = False, interface = "tun10"):
        self._socket = None
        self.source_ip = source_ip
        self.pcscf = pcscf
        self.security_server = {}
        self.is_registered = False
        self._sa = [None, None]
        self._reg = REGISTER(source_ip, imsi, ipsec)
        self.imsi = imsi
        self.ipsec = ipsec
        self.interface = interface

        conf.route6.add(dst=self.pcscf, gw="fe80::1", dev=self.interface)
        self.connect()

    def connect(self, ik = None):
        if ik and self.ipsec:
            if self._socket:
                self._socket.close()
            #self._socket = socket.socket(socket.AF_INET6, socket.SOCK_RAW,proto=50)
            self._sa[0] = SecurityAssociation(ESP, spi=self.PCSCF_SPI_SERVER, crypt_algo="NULL", auth_algo="HMAC-MD5-96", auth_key=ik)
            self._sa[1] = SecurityAssociation(ESP, spi=self.ESP_SPI_SERVER, crypt_algo="NULL", auth_algo="HMAC-MD5-96", auth_key=ik)
            sport = dport = 0
        elif not self._socket:
            self._socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sport = PORT
            dport = 5060
            self._socket.bind((self.source_ip, sport))
            self._socket.connect((self.pcscf, dport))

    def register(self):
        challenge = self._reg.first_register(self)
        # WWW-Authenticate: Digest realm="ims.mnc588.mcc311.3gppnetwork.org",nonce="7lknstsUC/nZZLiK7qjb5w0wAndwXYAA1O+hICw1IKk=",algorithm=AKAv1-MD5
        auth = parse_sip_dict_line(challenge['WWW-Authenticate'])
        nonce = auth.get("nonce", None)
        if not nonce:
            raise Exception("Nonce not found in response: {}".format(challenge))
        rand = base64.b64decode(nonce)[:32]
        # autn = base64.b64decode(nonce)[32:]

        # calculate response
        res, _ = Milenage.f2_f5(bytes.fromhex(KI), rand, bytes.fromhex(OPC))
        ha1=md5("{}@ims.mnc588.mcc311.3gppnetwork.org:{}:".format(self.imsi, auth["realm"]).encode("utf-8") + res).hexdigest()
        ha2=md5("REGISTER:sip:ims.mnc588.mcc311.3gppnetwork.org".encode("utf-8")).hexdigest()
        response=md5("{}:{}:{}".format(ha1, nonce, ha2).encode("utf-8")).hexdigest()

        # calculate CK and IK
        ik = Milenage.f4(bytes.fromhex(KI), rand, bytes.fromhex(OPC))
        print(ik.hex(), res.hex())
        # upgrade socket to IPSEC port
        if self.ipsec:
            security_server = parse_sip_dict_line(challenge['Security-Server'], ";")
            self.__class__.PCSCF_PORT_CLIENT = int(security_server["port-c"])
            self.__class__.PCSCF_PORT_SERVER = int(security_server["port-s"])
            self.__class__.PCSCF_SPI_CLIENT = int(security_server["spi-c"])
            self.__class__.PCSCF_SPI_SERVER = int(security_server["spi-s"])
            self.connect(ik)

        self._reg.auth_register(self, nonce, response)
        # parse response
        # setup esp tunnel
        # compute RES
        # send_authentication

    def refresh_callid(self):
        self.__class__.CALL_ID=random.randbytes(20).hex()
        self.__class__.SESSION_ID=random.randbytes(20).hex()
        self.__class__.BRANCH=random.randbytes(11).hex()
        self.__class__.FROM_TAG=random.randbytes(11).hex()

    def send_sms(self):
        self.refresh_callid()
        MESSAGE(self.ipsec).send_message(self)

    def receive_sms(self):
        pass

    def make_call(self):
        self.refresh_callid()
        sip = INVITE(self.ipsec)
        sip.send_invite(self) # waits for 183
        sip.send_prack(self) # waits for 200 OK
        sip.send_update(self)

    def send(self, message):
        if self._sa[0]:
            packet = IPv6(src=self.source_ip, dst=self.pcscf) / UDP(sport=self.ESP_PORT_CLIENT, dport=self.PCSCF_PORT_SERVER) / message
            send(self._sa[0].encrypt(packet))
        else:
            self._socket.send(message)

    def receive(self):
        if self._sa[1]:
            return self._sa[1].decrypt(sniff(iface=self.interface, count=1)[0]).load
        return self._socket.recv(2048)

    def __del__(self):
        self._socket.close()


class SIPTransaction:
    def __init__(self, ipsec):
        self._cseq = 1
        self.ipsec = ipsec

    def build_payload(self, payload, **kwargs):
        kwargs.update({
            "FROM_TAG"          : IMSClient.FROM_TAG,
            "BRANCH"            : IMSClient.BRANCH,
            "CSEQ"              : self._cseq,
            "CALL_ID"           : IMSClient.CALL_ID,
            "SESSION_ID"        : IMSClient.SESSION_ID,
            "USER_AGENT"        : IMSClient.USER_AGENT,
            "ESP_SPI_CLIENT"    : IMSClient.ESP_SPI_CLIENT,
            "ESP_SPI_SERVER"    : IMSClient.ESP_SPI_SERVER,
            "ESP_PORT_CLIENT"   : IMSClient.ESP_PORT_CLIENT,
            "ESP_PORT_SERVER"   : IMSClient.ESP_PORT_SERVER,
            "PCSCF_SPI_CLIENT"  : IMSClient.PCSCF_SPI_CLIENT,
            "PCSCF_SPI_SERVER"  : IMSClient.PCSCF_SPI_SERVER,
            "PCSCF_PORT_CLIENT" : IMSClient.PCSCF_PORT_CLIENT,
            "PCSCF_PORT_SERVER" : IMSClient.PCSCF_PORT_SERVER,
            "PORT"              : PORT,
            "B"                 : B,
        })
        return payload.format(**kwargs).replace('\x0a', '\x0d\x0a').encode('utf-8')

    def send(self, client, payload, **kwargs):
        payload = self.build_payload(payload, **kwargs)
        self._cseq += 1
        client.send(payload)

    def parse(self, message):
        sip_message = {}
        response_code = 0
        for line in message.decode('utf-8').strip().split("\r\n"):
            if line.startswith("SIP"):
                response_code = int(line.split(" ")[1])
                continue
            try:
                header, value = line.split(": ")
                sip_message[header] = value
            except:
                break
        return response_code, sip_message


class REGISTER(SIPTransaction):
    challenged_reg = """REGISTER sip:ims.mnc588.mcc311.3gppnetwork.org SIP/2.0
To: <sip:{IMSI}@ims.mnc588.mcc311.3gppnetwork.org>
From: <sip:{IMSI}@ims.mnc588.mcc311.3gppnetwork.org>;tag={FROM_TAG}
Expires: 600000
Call-ID: {CALL_ID}
Session-ID: {SESSION_ID}
Contact: <sip:[{IP}]:{PORT}>;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel";+g.3gpp.smsip;+sip.instance="<urn:gsma:imei:12345678-123456-0>"
Via: SIP/2.0/UDP [{IP}]:{PORT};branch={BRANCH};rport
Authorization: Digest nonce="",uri="sip:ims.mnc588.mcc311.3gppnetwork.org",response="",username="{IMSI}@ims.mnc588.mcc311.3gppnetwork.org",realm="ims.mnc588.mcc311.3gppnetwork.org"
CSeq: {CSEQ} REGISTER
Max-Forwards: 70
Supported: 100rel,path,replaces
User-Agent: {USER_AGENT}
Content-Length: 0

"""

    challenged_reg_ipsec = """REGISTER sip:ims.mnc588.mcc311.3gppnetwork.org SIP/2.0
To: <sip:{IMSI}@ims.mnc588.mcc311.3gppnetwork.org>
From: <sip:{IMSI}@ims.mnc588.mcc311.3gppnetwork.org>;tag={FROM_TAG}
Require: sec-agree
Expires: 600000
Call-ID: {CALL_ID}
Session-ID: {SESSION_ID}
Contact: <sip:[{IP}]:{PORT}>;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel";+g.3gpp.smsip;+sip.instance="<urn:gsma:imei:12345678-123456-0>"
Via: SIP/2.0/UDP [{IP}]:{PORT};branch={BRANCH};rport
Authorization: Digest nonce="",uri="sip:ims.mnc588.mcc311.3gppnetwork.org",response="",username="{IMSI}@ims.mnc588.mcc311.3gppnetwork.org",realm="ims.mnc588.mcc311.3gppnetwork.org"
CSeq: {CSEQ} REGISTER
Max-Forwards: 70
Supported: 100rel,path,replaces
User-Agent: {USER_AGENT}
Security-Client: ipsec-3gpp;alg=hmac-md5-96;prot=esp;mod=trans;ealg=null;spi-c={ESP_SPI_CLIENT};spi-s={ESP_SPI_SERVER};port-c={ESP_PORT_CLIENT};port-s={ESP_PORT_SERVER}
Content-Length: 0

"""

    authentication_reg = """REGISTER sip:ims.mnc588.mcc311.3gppnetwork.org SIP/2.0
To: <sip:{IMSI}@ims.mnc588.mcc311.3gppnetwork.org>
From: <sip:{IMSI}@ims.mnc588.mcc311.3gppnetwork.org>;tag={FROM_TAG}
Expires: 600000
Call-ID: {CALL_ID}
Session-ID: {SESSION_ID}
Contact: <sip:[{IP}]:{PORT}>;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel";+g.3gpp.smsip;+sip.instance="<urn:gsma:imei:12345678-123456-0>"
CSeq: {CSEQ} REGISTER
Authorization: Digest nonce="{NONCE}",uri="sip:ims.mnc588.mcc311.3gppnetwork.org",response="{RESPONSE}",username="{IMSI}@ims.mnc588.mcc311.3gppnetwork.org",algorithm=AKAv1-MD5,realm="ims.mnc588.mcc311.3gppnetwork.org"
Via: SIP/2.0/UDP [{IP}]:{PORT};branch={BRANCH};rport
Max-Forwards: 70
User-Agent: {USER_AGENT}
Content-Length: 0

"""

    authentication_reg_ipsec = """REGISTER sip:ims.mnc588.mcc311.3gppnetwork.org SIP/2.0
To: <sip:{IMSI}@ims.mnc588.mcc311.3gppnetwork.org>
From: <sip:{IMSI}@ims.mnc588.mcc311.3gppnetwork.org>;tag={FROM_TAG}
Expires: 600000
Require: sec-agree
Proxy-Require: sec-agree
Security-Client: ipsec-3gpp;alg=hmac-md5-96;prot=esp;mod=trans;ealg=null;spi-c={ESP_SPI_CLIENT};spi-s={ESP_SPI_SERVER};port-c={ESP_PORT_CLIENT};port-s={ESP_PORT_SERVER}
Call-ID: {CALL_ID}
Session-ID: {SESSION_ID}
Contact: <sip:[{IP}]:{ESP_PORT_SERVER}>;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel";+g.3gpp.smsip;+sip.instance="<urn:gsma:imei:12345678-123456-0>"
CSeq: {CSEQ} REGISTER
Authorization: Digest nonce="{NONCE}",uri="sip:ims.mnc588.mcc311.3gppnetwork.org",response="{RESPONSE}",username="{IMSI}@ims.mnc588.mcc311.3gppnetwork.org",algorithm=AKAv1-MD5,realm="ims.mnc588.mcc311.3gppnetwork.org"
Via: SIP/2.0/UDP [{IP}]:{ESP_PORT_SERVER};branch={BRANCH};rport
Max-Forwards: 70
User-Agent: {USER_AGENT}
Security-Verify: ipsec-3gpp;alg=hmac-md5-96;ealg=null;mod=trans;port-c={PCSCF_PORT_SERVER};port-s={PCSCF_PORT_SERVER};prot=esp;spi-c={PCSCF_SPI_CLIENT};spi-s={PCSCF_SPI_SERVER}
Content-Length: 0

"""

    def __init__(self, source_ip, imsi, ipsec):
        self.imsi = imsi
        self.source_ip = source_ip
        self.msisdn = None
        super().__init__(ipsec)

    def first_register(self, client):
        # send first
        challenge = self.challenged_reg_ipsec if self.ipsec else self.challenged_reg
        self.send(client, challenge, IP=self.source_ip, IMSI=self.imsi)
        # expect 401
        code, resp = self.parse(client.receive())
        if code != 401:
            raise Exception("Have not received a challenge from IMS, got {} instead. Aborting.".format(code))
        return resp

    def auth_register(self, client, nonce, response):
        auth_reg = self.authentication_reg_ipsec if self.ipsec else self.authentication_reg
        self.send(client, auth_reg, IP=self.source_ip, IMSI=self.imsi, NONCE=nonce, RESPONSE=response)
        time.sleep(1)
        # code, resp = self.parse(client.receive())
        # if code == 100:
        #     print("Got 100 trying when REGISTER. Waiting for 200 OK...")
        # code, resp = self.parse(client.receive())
        # if code != 200:
        #     raise Exception("Failed authentication, got {} instead. Aborting.".format(code))

class MESSAGE(SIPTransaction):
    message = """MESSAGE tel:+13125550100 SIP/2.0
Call-ID: 0jtmK65R2oW3njSKz3wB3pYV
From: <sip:+{MSISDN}@ims.mnc588.mcc311.3gppnetwork.org>;tag=cd5yQnqmgf
To: <tel:+13125550100>
Request-Disposition: no-fork
Accept-Contact: *;+g.3gpp.smsip
CSeq: 1 MESSAGE
Via: SIP/2.0/UDP [{IP}]:{PORT};branch=z9hG4bK7wJsJJdpZdfhHdL;rport
Allow: ACK,BYE,CANCEL,INFO,INVITE,MESSAGE,NOTIFY,OPTIONS,PRACK,REFER,UPDATE
P-Preferred-Identity: sip:+{MSISDN}@ims.mnc588.mcc311.3gppnetwork.org
Max-Forwards: 70
Supported: 100rel,path,replaces
User-Agent: {USER_AGENT}
P-Access-Network-Info: 3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=31041043114b4cae5
Route: <sip:[2602:f6dc:0:1ff::f]:5060;lr>
Content-Type: application/vnd.3gpp.sms
Content-Length: {LEN}

"""

    message_ipsec = """MESSAGE tel:+13125550100 SIP/2.0
Call-ID: 0jtmK65R2oW3njSKz3wB3pYV
From: <sip:+{MSISDN}@ims.mnc588.mcc311.3gppnetwork.org>;tag=cd5yQnqmgf
To: <tel:+13125550100>
Request-Disposition: no-fork
Accept-Contact: *;+g.3gpp.smsip
CSeq: 1 MESSAGE
Via: SIP/2.0/UDP [{IP}]:{ESP_PORT_SERVER};branch=z9hG4bK7wJsJJdpZdfhHdL;rport
Allow: ACK,BYE,CANCEL,INFO,INVITE,MESSAGE,NOTIFY,OPTIONS,PRACK,REFER,UPDATE
P-Preferred-Identity: sip:+{MSISDN}@ims.mnc588.mcc311.3gppnetwork.org
Max-Forwards: 70
Supported: 100rel,path,replaces
User-Agent: {USER_AGENT}
P-Access-Network-Info: 3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=31041043114b4cae5
Security-Verify: ipsec-3gpp;alg=hmac-md5-96;ealg=null;mod=trans;port-c={PCSCF_PORT_SERVER};port-s={PCSCF_PORT_SERVER};prot=esp;spi-c={PCSCF_SPI_CLIENT};spi-s={PCSCF_SPI_SERVER}
Require: sec-agree
Proxy-Require: sec-agree
Route: <sip:[2602:f6dc:0:1ff::f]:15060;lr>
Content-Type: application/vnd.3gpp.sms
Content-Length: {LEN}

"""

    def send(self, client, payload, **kwargs):
        content = "00010007913121550501f01901ff0b917100330350f300000dc7f79b0c6abfe5eeb4fb1c02"
        kwargs.update({
            "LEN": int(len(content) / 2),
            "MSISDN" : MSISDN,
            "IP": client.source_ip
        })
        payload = self.build_payload(payload, **kwargs)
        payload += bytes.fromhex(content)
        self._cseq += 1
        client.send(payload)

    def send_message(self, client):
        message = self.message_ipsec if self.ipsec else self.message
        self.send(client, message)


class INVITE(SIPTransaction):
    invite_ipsec = """INVITE tel:{B};phone-context=ims.mnc588.mcc311.3gppnetwork.org SIP/2.0
Accept-Contact: *;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"
P-Early-Media: supported
From: <tel:+{MSISDN}>;tag={FROM_TAG}
To: <tel:{B};phone-context=ims.mnc588.mcc311.3gppnetwork.org>
Require: 100rel, precondition
Call-ID: {CALL_ID}
Session-ID: {SESSION_ID}
Contact: <sip:[{IP}]:{ESP_PORT_SERVER}>;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel";+g.3gpp.smsip;+sip.instance="<urn:gsma:imei:12345678-123456-0>"
CSeq: 1 INVITE
Via: SIP/2.0/UDP [{IP}]:{ESP_PORT_SERVER};branch={BRANCH};rport
P-Preferred-Identity: tel:+{MSISDN}
Max-Forwards: 7
User-Agent: {USER_AGENT}
Security-Verify: ipsec-3gpp;alg=hmac-md5-96;ealg=null;mod=trans;port-c={PCSCF_PORT_SERVER};port-s={PCSCF_PORT_SERVER};prot=esp;spi-c={PCSCF_SPI_CLIENT};spi-s={PCSCF_SPI_SERVER}
Content-Type: application/sdp
Content-Length: {LEN}

v=0
o=tel:+170 17 17 IN IP6 {IP}
s=-
c=IN IP6 {IP}
t=0 0
a=sendrecv
m=audio 49120 RTP/AVP 108
a=rtpmap:108 AMR/8000
a=des:qos mandatory local sendrecv
a=curr:qos local none
a=des:qos optional remote sendrecv
a=curr:qos remote none
a=sendrecv

"""

    invite = """INVITE tel:{B};phone-context=ims.mnc588.mcc311.3gppnetwork.org SIP/2.0
Accept-Contact: *;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"
P-Early-Media: supported
From: <tel:+{MSISDN}>;tag={FROM_TAG}
To: <tel:{B};phone-context=ims.mnc588.mcc311.3gppnetwork.org>
Require: 100rel, precondition
Call-ID: {CALL_ID}
Session-ID: {SESSION_ID}
Contact: <sip:[{IP}]:{PORT}>;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel";+g.3gpp.smsip;+sip.instance="<urn:gsma:imei:12345678-123456-0>"
CSeq: 1 INVITE
Via: SIP/2.0/UDP [{IP}]:{PORT};branch={BRANCH};rport
P-Preferred-Identity: tel:+{MSISDN}
Max-Forwards: 7
User-Agent: {USER_AGENT}
Content-Type: application/sdp
Content-Length: {LEN}

v=0
o=tel:+170 17 17 IN IP6 {IP}
s=-
c=IN IP6 {IP}
t=0 0
a=sendrecv
m=audio 49120 RTP/AVP 108
a=rtpmap:108 AMR/8000
a=des:qos mandatory local sendrecv
a=curr:qos local none
a=des:qos optional remote sendrecv
a=curr:qos remote none
a=sendrecv
"""

    prack = """PRACK sip:[2602:f6dc:0:1ff::f]:15060 SIP/2.0
Via: SIP/2.0/UDP [{IP}]:{ESP_PORT_SERVER};branch={BRANCH};rport
From: <tel:+{MSISDN}>;tag={FROM_TAG}
To: <tel:{B};phone-context=ims.mnc588.mcc311.3gppnetwork.org>;tag={TO_TAG}
Call-ID: {CALL_ID}
CSeq: 2 PRACK
RAck: 1 1 INVITE
Contact: <sip:[{IP}]:{ESP_PORT_SERVER}>;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"
Max-Forwards: 7
Route: <sip:[2602:f6dc:0:1ff::f]:15060;lr>
Content-Length: 0

"""

    update = """UPDATE sip:[2602:f6dc:0:1ff::f]:15060 SIP/2.0
Require: precondition, 100rel
Supported: 100rel,path,precondition,replaces,timer
Via: SIP/2.0/UDP [{IP}]:{ESP_PORT_SERVER};branch={BRANCH};rport
From: <tel:+{MSISDN}>;tag={FROM_TAG}
To: <tel:{B};phone-context=ims.mnc588.mcc311.3gppnetwork.org>;tag={TO_TAG}
Call-ID: {CALL_ID}
Session-ID: {SESSION_ID}
Contact: <sip:[{IP}]:{ESP_PORT_SERVER}>;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"
CSeq: 3 UPDATE
Max-Forwards: 7
Route: <sip:[2602:f6dc:0:1ff::f]:15060;lr>
Content-Type: application/sdp
Content-Length: {LEN}

v=0
o=tel:+170 18 18 IN IP6 {IP}
s=-
c=IN IP6 {IP}
t=0 0
a=sendrecv
m=audio 49120 RTP/AVP 108
a=rtpmap:108 AMR/8000
a=ptime:20
a=sendrecv
a=des:qos mandatory local sendrecv
a=curr:qos local sendrecv
a=des:qos mandatory remote sendrecv
a=curr:qos remote none
"""

    def __init__(self, *args, **kwargs):
        self.to_tag = ""
        super().__init__(*args, **kwargs)

    def send(self, client, payload, **kwargs):
        base_content_len = 264 if "UPDATE sip" in payload else 235
        kwargs.update({
            "MSISDN" : MSISDN,
            "IP": client.source_ip,
            "LEN": base_content_len + (len(client.source_ip) * 2),
            "TO_TAG": self.to_tag
        })
        payload = self.build_payload(payload, **kwargs)
        client.send(payload)

    def send_invite(self, client):
        invite = self.invite_ipsec if self.ipsec else self.invite
        self.send(client, invite)
        code, resp = self.parse(client.receive())
        if code == 100:
            print("Got 100 trying, still waiting for 183.")
            code, resp = self.parse(client.receive())
        if code != 183:
            raise Exception("Did not receive SIP/183, got {} instead. Aborting.".format(code))
        # extract to tag
        for e in resp['To'].split(";"):
            if "tag=" in e:
                self.to_tag = e.split("=")[1]
                break
        if not self.to_tag:
            print("Not able to extract To tag. Continuing without it...")

    def send_prack(self, client):
        self.send(client, self.prack)
        code, resp = self.parse(client.receive())
        print("Got {} to PRACK".format(code))

    def send_update(self, client):
        self.send(client, self.update)
        code, resp = self.parse(client.receive())
        print("Got {} to UPDATE".format(code))

# set up IPSEC
def parse_sip_dict_line(line, delimiter=","):
    # parse a SIP line like key=value
    sip_dict = {}
    for elem in line.split(delimiter):
        split = re.match('(?:.*? )?(?P<key>[a-z\-]+)=["\']?(?P<value>[^"\']*)["\']?', elem)
        if split:
            sip_dict[split['key']] = split['value'].strip()
    return sip_dict

if "__main__" == __name__:
    parser = argparse.ArgumentParser(
                    prog='ims_testing',
                    description='Generate SIP REGISTER, INVITE and MESSAGE to test the IMS core')
    parser.add_argument('--ipsec', action='store_true', help='Enable IPSEC. Disabled by default')
    parser.add_argument('--no-register', action='store_false', help='Do not register the user.')
    parser.add_argument('--send-sms', action='store_true', help='Send an SMS.')
    parser.add_argument('--make-call', action='store_true', help='Makes a voice call.')
    parser.add_argument('--interface', default="tun10", help='Network interface used to communicate with P-CSCF. Default: tun10')
    parser.add_argument('client_ip', help="Source IPv6 address to use")
    parser.add_argument('pcscf_ip', help="P-CSCF IPv6 address")
    parser.add_argument('imsi', default="311588152000000")
    args = parser.parse_args()

    client = IMSClient(args.client_ip, args.pcscf_ip, args.imsi, ipsec=args.ipsec, interface=args.interface)
    if args.no_register:
        client.register()
    if args.send_sms:
        client.send_sms()
        #client.receive_sms()
    if args.make_call:
        client.make_call()

    del client
