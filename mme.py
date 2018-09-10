import socket
import queue
import struct
import time
from threading import Thread
from gtp_v2 import *
import logging
import sys
from collections import OrderedDict
import json
from copy import deepcopy
from template import *

def is_digit(x):
    try:
        x = int(x)
        return isinstance(x, int)
    except ValueError:
        return False

short_struct = struct.Struct('!H')

GTPV2MessageNameToType = {
      "echo_request": 1,
      "echo_response": 2,
      "create_session_req": 32,
      "create_session_res": 33,
      "modify_bearer_req": 34,
      "modify_bearer_res": 35,
      "delete_session_req": 36,
      "delete_session_res": 37,
      "downlink_data_notif_failure_indic": 70,
      "realease_bearers_req": 170,
      "realease_bearers_res": 171,
      "downlink_data_notif": 176,
      "downlink_data_notif_ack": 177,
}

ProfileAttrNameToIEAttrName = {
    "imsi": "IMSI",
    "msisdn": "digits",
    "cbresp-cause": "Cause",
    "dbresp-cause": "Cause",
    "apn": "APN",
    "pdn-type": "PDN Type",
    "bearer-context": "Bearer Context",
    "default-bearer-context": "Bearer Context",
    "timezone": "UE Time zone",
    "apn-ambr": "AMBR",
    "selection-mode": "Selection Mode",
    "apn-restriction-type": "APN Restriction",
}

IEAttrNameToProfileAttrName = {
    "IMSI": "imsi",
    "digits": "msisdn",
}

GTPV2HeadField = ["version", "P", "T", "gtp_type", "length", "teid", "seq"]
IEHeadField = ["ietype", "instance"]

BearerEvent = {
    "CreateSessionResponse": 1,
    "ModifyBearerResponse": 2,
}
BearerStatus = {
    "CreateSessionRequestSent": 1,
    "CreateSessionResponseReceived": 2,
    "ModifyBearerRequestSent": 3,
    "ModifyBearerRequestReceived": 4,
}

PeerEvent = {
    "EchoRequest": 1,
    "EchoResponse": 2,
}
PeerStatus = {
    "Down": 0,
    "EchoRequestSent": 1,
    "EchoResponseReceived": 2,
}


class Error(Exception):
    """Base class for exceptions in this module."""
    pass


class ParamNameError(Error):
    def __init__(self, name, message):
        self.name = name
        self.message = message

    def __str__(self):
        info = "{m}: {n}".format(m=self.message, n=self.name)
        return info


class ParamValueError(Error):
    def __init__(self, value, message):
        self.value = value
        self.message = message

    def __str__(self):
        info = "{m}: {v}".format(m=self.message, v=self.value)
        return info


class Server:
    def __init__(self, config, template):
        self.config_file = config
        self.template = template
        self.template_dict = OrderedDict()
        self.run = False
        self.socket = None
        self.events_queue = queue.Queue()
        self.mme_list = []
        self.profile_list = []
        self.config_dict = {}

    def start(self):
        self.load_config()
        self.load_template()
        self.run = True

        mme_s11c_address = self.config_dict.get("mme-s11c-address", "0.0.0.0")
        mme_s11c_port = int(self.config_dict.get('mme-s11c-port', 2123))
        sgw_s11c_address = self.config_dict.get('sgw-s11c-address', "0.0.0.0")
        sgw_s11c_port = int(self.config_dict.get('sgw-s11c-port', 2123))

        default_profile = self.create_profile(0)

        for mme_id, mme_address in enumerate(mme_s11c_address.split(','), 1):
            self.create_mme(mme_id, mme_address.strip(), mme_s11c_port, sgw_s11c_address, sgw_s11c_port,
                            default_profile)

        while self.run:
            try:
                received_event = self.events_queue.get(block=True, timeout=60)
            except queue.Empty:
                continue

            print(received_event)
            if received_event[0] == 'set':
                if received_event[1] == "profile":
                    profile = self.find_profile(received_event[2])
                    if profile:
                        profile.set_parameter_value(received_event[3], received_event[4])
                    else:
                        print("Profile {i} not exist".format(i=received_event[2]))

            elif received_event[0] == "create":
                if received_event[1] == "profile":
                    try:
                        self.create_profile(received_event[2])
                    except IndexError:
                        print("Mandatory argument missing: prof-id.")
            elif received_event[0] == "show":
                if received_event[1] == "mme":
                    self.show_all_mmes()
                elif received_event[1] == "profile":
                    if len(received_event) == 2:
                        for profile in self.profile_list:
                            print(profile)
                    else:
                        self.show_profile(received_event[2])

            elif received_event[0] == "proc":
                if received_event[1] == "attach":
                    self.mme_list[0].send_create_session_request()
            else:
                pass

    def load_config(self):
        try:
            with open(self.config_file) as f:
                for line in f.readlines():
                    if line.strip().startswith('#') or line.strip().startswith('[') or len(line.strip()) == 0:
                        continue
                    if "#" in line:
                        line = line[:line.find("#")]
                    k, v = line.split('=')
                    self.config_dict[k.strip()] = v.strip()
        except FileNotFoundError as e:
            info = "Configuration file '{e}' not found.".format(e=e)
            print(info)
            logging.info(info)
            self.terminate()

    def load_template(self):
        try:
            with open(self.template) as f:
                self.template_dict = OrderedDict(json.load(f))
        except FileNotFoundError as e:
            print("Missing template file, {e}".format(e=e))
            self.terminate()
        except json.decoder.JSONDecodeError as e:
            print("template file format error, {e}".format(e=e))
            self.terminate()

    def create_mme(self, mme_id, address1, port1, address2, port2, profile):
        mme = MME(mme_id, profile)
        mme.set_socket(address1, port1, address2, port2)
        peer_thread = Thread(target=mme.start, daemon=True)
        peer_thread.start()
        self.mme_list.append(mme)

    def show_all_mmes(self):
        for mme in self.mme_list:
            print(mme)

    def show_mme(self, address):
        pass

    def find_mme(self):
        pass

    def create_profile(self, profile_id):
        profile = self.find_profile(int(profile_id))
        if not profile:
            new_profile = Profile(int(profile_id), self.template_dict)
            new_profile.get_information_from_server(**self.config_dict)
            self.profile_list.append(new_profile)
            return new_profile
        else:
            print("Profile {i} already exist".format(i=profile_id))
            return profile

    def show_profile(self, profile_id):
        profile = self.find_profile(int(profile_id))
        if profile:
            print(profile)
        else:
            print("Profile {i} not exist".format(i=profile_id))

    def find_profile(self, profile_id):
        for profile in self.profile_list:
            if int(profile_id) == profile.get_id():
                return profile
        return None

    def is_alive(self):
        return all([mme_peer.is_alive() for mme_peer in self.mme_list])

    def terminate(self):
        if self.socket:
            self.socket.close()
        self.run = False
        sys.exit(1)


class MME:
    def __init__(self, mme_id, profle):
        self.mme_id = mme_id
        self.profile = profle
        self.mme_s11c_address = "0.0.0.0"
        self.mme_s11c_port = 2123
        self.sgw_s11c_address = "0.0.0.0"
        self.sgw_s11c_port = 2123
        self.socket = None
        self.run = False
        self.start_time = ""
        self.status = PeerStatus["Down"]
        self.received_message_queue = queue.Queue()
        self.events_queue = queue.Queue()
        self.process_received_message_thread = None
        self.sessions = set()

    def __str__(self):
        info = """-------------------------------------------------------------------------------
MME ID                :  {i}
MME S11c Address      :  {a1}
MME S11c Port         :  {p1}
SGW S11c Address      :  {a2}
SGW S11c Port         :  {p2}
Create time           :  {t}
Active sessions       :  {s}
-------------------------------------------------------------------------------""".format(i=self.mme_id,
                                                                                          a1=self.mme_s11c_address,
                                                                                          p1=self.mme_s11c_port,
                                                                                          a2=self.sgw_s11c_address,
                                                                                          p2=self.sgw_s11c_port,
                                                                                          t=self.start_time,
                                                                                          s=len(self.sessions),)
        return info

    def start(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.socket.bind((self.mme_s11c_address, self.mme_s11c_port))
        except OSError as error:
            if error.errno == 98:
                info = "Address {ip}:{port} already in use.".format(ip=self.mme_s11c_address, port=self.mme_s11c_port)
                print(info)
                logging.info(info)
                self.terminate()

        self.run = True
        self.start_time = time.strftime("%m/%d/%Y %H:%M:%S", time.localtime())
        self.socket.connect((self.sgw_s11c_address, self.sgw_s11c_port))
        self.process_received_message_thread = Thread(target=self.process_received_message, daemon=True)
        self.process_received_message_thread.start()

        while self.run:
            try:
                data_buffer = self.socket.recv(1500)
                self.received_message_queue.put(data_buffer)
            except socket.timeout:
                info = "Socket timeout, Address:Port {a}:{p}".format(a=self.mme_s11c_address, p=self.mme_s11c_port)
                logging.info(info)
                continue
            except OSError as e:
                if e.errno == 9:
                    info = "Socket error{e}, Address:Port {a}:{p}".format(e=e, a=self.mme_s11c_address,
                                                                          p=self.mme_s11c_port)
                    logging.warning(info)
                    break

        self.terminate()

    def set_socket(self, source_address, source_port, dest_address, dest_port):
        self.mme_s11c_address = source_address
        self.mme_s11c_port = source_port
        self.sgw_s11c_address = dest_address
        self.sgw_s11c_port = dest_port

    def process_received_message(self):
        if self.status is PeerStatus["Down"]:
            echo_request = self.send_echo_request()
            # recovery_restart = IE_RecoveryRestart(ietype='Recovery Restart', length=1, restart_counter=1)
            # echo_request = GTPHeader(version=2, length=4+len(recovery_restart),  gtp_type=1)
            # send_data = bytes(echo_request/recovery_restart)

            self.socket.send(echo_request)
            self.status = PeerStatus["EchoRequestSent"]

        while self.run:
            try:
                received_message = self.received_message_queue.get(block=True, timeout=60)
            except queue.Empty:
                continue

            try:
                gtp_message = GTPHeader(received_message)
                for ie in gtp_message.IE_list:
                    pass
                gtp_message_type = gtp_message.gtp_type
            except AttributeError:
                print("AttributeError")
                continue

            if gtp_message_type == GTPV2MessageNameToType["echo_request"]:
                recovery_restart = IE_RecoveryRestart(ietype='Recovery Restart', length=1, restart_counter=1)
                echo_response = GTPHeader(version=2, gtp_type=2, ) / recovery_restart
                send_data = bytes(echo_response)
                self.socket.send(send_data)
            elif gtp_message_type == GTPV2MessageNameToType["echo_response"]:
                self.status = PeerStatus["EchoResponseReceived"]
            elif gtp_message_type == GTPV2MessageNameToType["create_session_res"]:
                self.events_queue.put(BearerEvent['ModifyBearerResponse'])

    def process_event_queue(self):
        while self.run:
            try:
                received_event = self.events_queue.get(block=True, timeout=60)
            except queue.Empty:
                continue

            if received_event == BearerEvent['CreateSessionResponse']:
                pass
            elif received_event == BearerEvent['ModifyBearerResponse']:
                pass
            else:
                pass

    def is_alive(self):
        return self.run

    def terminate(self):
        if self.socket:
            self.socket.close()
        self.run = False
        sys.exit(1)

    def send_echo_request(self):
        echo_request_template = self.profile.get_message_template("echo_request")
        echo_request_head = GTPHeader(length=4)
        for key, value in echo_request_template.items():
            if key in GTPV2HeadField:
                setattr(echo_request_head, key, value)
            else:
                ie = self.create_ie(value)
                if ie:
                    echo_request_head.add_payload(ie)
                    setattr(echo_request_head, "length", echo_request_head.length + len(ie))
                # ie_template = value
                # cls_name = value["class"]
                # cls = globals()[cls_name]
                # ie = cls()
                # for key, value in ie_template.items():
                #     try:
                #         setattr(ie, key, value)
                #     except AttributeError as e:
                #         if key == "class":
                #             pass
                #         else:
                #             print("Attribute {a} not implemented for IE {i}".format(a=key, i=cls_name))
                # echo_request_head.add_payload(ie)
                # setattr(echo_request_head, "length", echo_request_head.length + len(ie))

        return bytes(echo_request_head)

    def create_ie(self, template):
        ie_template = template
        try:
            if template["instance"] is None:
                return None
        except KeyError:
            pass
        cls_name = template["class"]
        cls = globals()[cls_name]
        try:
            ie = cls(length=0)
        except KeyError:
            ie = cls()
        for key, value in ie_template.items():
            if isinstance(value, dict):
                sub_ie = self.create_ie(value)
                if sub_ie:
                    setattr(ie, key, sub_ie)
                    setattr(ie, "length", ie.length + len(sub_ie))
                    print("ie:length:{l} add sub_ie length:{sl}".format(l=ie.length, sl=len(sub_ie)))
            elif isinstance(value, list):
                ie_list = []
                length = 0
                for item in value:
                    for key1, value1 in item.items():
                        print("create ", key1)
                        sub_ie = self.create_ie(value1)
                        if sub_ie:
                            ie_list.append(sub_ie)
                            length += len(ie)
                            print("ie:'{i}' length:{l}add sub_ie '{si}' length:{sl}".format(i=key, si=key1, l=length, sl=len(ie)))
                setattr(ie, key, ie_list)
                setattr(ie, "length", ie.length + length)
            else:
                try:
                    setattr(ie, key, value)
                except AttributeError as e:
                    if key == "class":
                        pass
                    else:
                        print("Attribute {a} not implemented for IE {i}".format(a=key, i=cls_name), e)
        return ie

    def create_tlv_ie(self, name):
        try:
            ie_template = IE_dict[name]
        except KeyError:
            return None

        try:
            cls_name = ie_template["class"]
        except KeyError:
            return None

        cls = globals()[cls_name]
        ie = cls()
        for attribute, value in ie_template.items():
            if attribute in ["class", "length"]:
                pass
            elif attribute in IEHeadField:
                setattr(ie, attribute, value)
            else:
                value = self.profile.get_attribute_value_by_name(attribute)
                setattr(ie, attribute, value)
        setattr(ie, "length", len(ie) - 4)

        return ie

    def create_csreq(self):
        pass

    # def create_csreq(self):
    #     echo_request_template = self.profile.get_message_template("create_session_req")
    #     echo_request_head = GTPHeader(length=8)
    #     for key, value in echo_request_template.items():
    #         if key in GTPV2HeadField:
    #             setattr(echo_request_head, key, value)
    #         else:
    #             ie = self.create_ie(value)
    #             if ie:
    #                 echo_request_head.add_payload(ie)
    #                 setattr(echo_request_head, "length", echo_request_head.length + len(ie))
    #
    #     echo_request_head.show()
    #     return bytes(echo_request_head)

    def send_create_session_request(self):
        imsi = IE_IMSI(ietype='IMSI', length=8, IMSI=self.profile.get_parameter_value("imsi"))
        msisdn = IE_MSISDN(ietype='MSISDN', length=7, digits=self.profile.get_parameter_value("msisdn"))
        uli = IE_ULI(ietype='ULI', length=13, LAI_Present=0, ECGI_Present=1, TAI_Present=1, RAI_Present=0,
                     SAI_Present=0,
                     CGI_Present=0, TAI=ULI_TAI(MCC='460', MNC='02', TAC=12345),
               ECGI=ULI_ECGI(MCC='460', MNC='02', ECI=123456))
        serving_network = IE_ServingNetwork(ietype='Serving Network', length=3, MCC='460', MNC='02')
        rat = IE_RAT(ietype='RAT', length=1, RAT_type='EUTRAN')
        fteid_s11c = IE_FTEID(ietype='F-TEID', length=9, ipv4_present=1, InterfaceType=10, GRE_Key=0x1092,
                              ipv4='172.86.40.130')
        fteid_s5s8c = IE_FTEID(ietype='F-TEID', length=9, ipv4_present=1, instance=1, InterfaceType=7, GRE_Key=0x0,
                              ipv4='172.21.30.99')
        apn = IE_APN(ietype='APN', length=14, APN='cmnet.lab.com')
        selection_mode = IE_SelectionMode(ietype='Selection Mode', length=1, SelectionMode=0)
        pdn_type = IE_PDN_type(ietype='PDN Type', length=1, PDN_type='IPv4')
        paa = IE_PAA(ietype='PAA', length=5, PDN_type='IPv4', ipv4='0.0.0.0')
        apn_restriction = IE_APN_Restriction(ietype='APN Restriction', length=1, APN_Restriction=0)
        ambr = IE_AMBR(ietype='AMBR', length=8, AMBR_Uplink=5000, AMBR_Downlink=5000)
        pco = IE_PCO(ietype='Protocol Configuration Options', length=14, Extension=1, PPP=0, Protocols=[
            PCO_IPCP(type='IPCP', length=10, PPP=PCO_PPP(Code=1, Identifier=68, length=10, Options=[
                PCO_Primary_DNS(type='Primary DNS Server IP address', length=6, address='0.0.0.0')]))])
        bearer_qos = IE_Bearer_QoS(ietype='Bearer QoS', length=22, PCI=0, PriorityLevel=15, PVI=0, QCI=9,
                                   MaxBitRateForUplink=1000, MaxBitRateForDownlink=1000,
                                   GuaranteedBitRateForUplink=1000, GuaranteedBitRateForDownlink=1000)
        bearer_context = IE_BearerContext(ietype='Bearer Context', length=31,
                                          IE_list=[IE_EPSBearerID(ietype='EPS Bearer ID', length=1, EBI=5), bearer_qos])
        cc = IE_ChargingCharacteristics(ietype='Charging Characteristics', length=2, ChargingCharacteristric=0x0800)
        create_session_request = GTPHeader(version=2, T=1,
                                           length=4 + 4 + 12 + 11 + 17 + 7 + 5 + 13 + 13 + 18 + 5 + 5 + 9 + 5 + 12 + 18 + 35 + 6,
                                           teid=0,
                                           gtp_type="create_session_req") / imsi / msisdn / uli / serving_network / rat / fteid_s11c / fteid_s5s8c / apn / selection_mode / pdn_type / paa / apn_restriction / ambr / pco / bearer_context / cc
        send_data = bytes(create_session_request)
        self.socket.send(send_data)

        send_data = self.create_csreq()
        self.socket.send(send_data)


class Profile:
    def __init__(self, profile_id, template_dict):
        self.profile_id = profile_id
        self.template_dict = deepcopy(template_dict)
        self.parameters_dict = OrderedDict()
        self.ie_list = []
        self.message_list = []
        self.implemented_parameter_list = []
        self.ImplementedAttributesDecoder = {"imsi": self.set_string_value,
                                             "cbresp-cause": self.set_int_value,
                                             "dbresp-cause": self.set_int_value,
                                             "apn": self.set_string_value,
                                             "pdn-type": self.set_int_value,
                                             "bearer-context": self.decode_bearer_context,
                                             "default-bearer-context": self.decode_bearer_context,
                                             "timezone": self.set_int_value,
                                             "apn-ambr": self.decode_apn_ambr,
                                             "selection-mode": self.set_int_value,
                                             "msisdn": self.set_string_value,
                                             "apn-restriction-type": self.set_int_value,
                                             "uli-mcc-mnc-tai": self.decode_uli_mcc_mnc_tai,
                                             "uli-mcc-mnc-ecgi": self.decode_uli_mcc_mnc_ecgi,
                                             "serving-network-mcc-mnc": self.decode_serving_network_mcc_mnc,
                                             "chg-characteristics": self.set_hex_int_value,
                                             "static-paa": self.decode_paa,
                                             "restart-counter": self.set_int_value,
                                             "mme-s11c-address": self.set_ipv4_address,
                                             "mme-s11c-port": self.set_int_value,
                                             "sgw-s11c-address": self.set_ipv4_address,
                                             "enb-s1u-address": self.set_ipv4_address,
                                             "sgw-s11c-port": self.set_int_value,
                                             "pgw-s5s8-address": self.set_ipv4_address,
                                             }
        self.attribute_prefix = "attrib_"
        self.set_parameters_default_value()

    def __str__(self):
        info = "-------------------------------------------------------------------------------\n"
        info += "Received Parameters:\n"
        for name, value in self.parameters_dict.items():
            info += "    {n:30} :  {v}\n".format(n=name, v=value)
        info += "\nCurrent Attribute:\n"

        start = len(self.attribute_prefix)
        for attr in sorted(dir(self)):
            if attr.startswith(self.attribute_prefix):
                info += "    {n:30} :  {v}\n".format(n=attr[start:], v=getattr(self, attr))
        info += "-------------------------------------------------------------------------------"
        return info

    def get_id(self):
        return self.profile_id

    def set_parameters_default_value(self):
        self.parameters_dict["apn"] = "cmnet"
        self.parameters_dict["imsi"] = "460020100030241"
        self.parameters_dict["msisdn"] = "8618912345678"
        self.parameters_dict["pdn-type"] = "4"
        self.parameters_dict["apn-ambr"] = "5000,5000"
        self.parameters_dict["default-bearer-context"] = "5,15,9,1000000,1000000,1000000,1000000"
        self.parameters_dict["bearer-context"] = "6,1,5,1000000,1000000,1000000,1000000"
        self.parameters_dict["uli-mcc-mnc-tai"] = "46002,0x1234"
        self.parameters_dict["uli-mcc-mnc-ecgi"] = "46002,0x1234567"
        self.parameters_dict["serving-network-mcc-mnc"] = "46002"
        self.parameters_dict["chg-characteristics"] = "0x2048"
        self.parameters_dict["static-paa"] = "false"
        self.parameters_dict["apn-restriction-type"] = "0"
        self.parameters_dict["selection-mode"] = "0"
        self.parameters_dict["cbresp-cause"] = "16"
        self.parameters_dict["dbresp-cause"] = "16"
        self.parameters_dict["restart-counter"] = "126"

        for name, value in self.parameters_dict.items():
            self.decode_parameter(name, value)

    def get_information_from_server(self, **kwargs):
        for name, value in kwargs.items():
            self.decode_parameter(name, value)

    def set_parameter_value(self, name, value):
        self.decode_parameter(name, value)
        self.parameters_dict[name] = value

    def get_parameter_value(self, name):
        return self.parameters_dict.get(name, None)

    def decode_parameter(self, name, value):
        try:
            decoder = self.ImplementedAttributesDecoder[name]
        except KeyError:
            print("Decoder for attribute: {k} no implemented".format(k=name))
            return
        decoder(name, value)

    def set_string_value(self, name, value):
        setattr(self, self.attribute_prefix + name, value)

    def set_int_value(self, name, value):
        setattr(self, self.attribute_prefix + name, int(value))

    def set_hex_int_value(self, name, value):
        setattr(self, self.attribute_prefix + name, eval(value))

    def set_ipv4_address(self, name, value):
        address_list = value.split(',')
        setattr(self, self.attribute_prefix + name, address_list)

    def decode_bearer_context(self, name, bearer_context):
        bearer_id, arp, qci, mbr_uplink, mbr_downlink, gbr_uplink, gbr_downlink = bearer_context.split(',')
        if name == "default-bearer-context":
            bearer_name_prefix = "default-bearer-"
            setattr(self, self.attribute_prefix + bearer_name_prefix + "id", int(bearer_id))
        else:
            bearer_name_prefix = "bearer-id-" + bearer_id + "-"

        setattr(self, self.attribute_prefix + bearer_name_prefix + "arp", int(arp))
        setattr(self, self.attribute_prefix + bearer_name_prefix + "qci", int(qci))
        setattr(self, self.attribute_prefix + bearer_name_prefix + "mbr_uplink", int(mbr_uplink))
        setattr(self, self.attribute_prefix + bearer_name_prefix + "mbr_downlink", int(mbr_downlink))
        setattr(self, self.attribute_prefix + bearer_name_prefix + "gbr_uplink", int(gbr_uplink))
        setattr(self, self.attribute_prefix + bearer_name_prefix + "gbr_downlink", int(gbr_downlink))

    def decode_apn_ambr(self, name, apn_ambr):
        ambr_uplink, ambr_downlink = apn_ambr.split(',')
        setattr(self, self.attribute_prefix + "ambr_uplink", int(ambr_uplink))
        setattr(self, self.attribute_prefix + "ambr_downlink", int(ambr_downlink))

    def decode_uli_mcc_mnc_tai(self, name, uli_mcc_mnc_tai):
        mcc_mnc, tac = uli_mcc_mnc_tai.split(',')
        mcc = mcc_mnc[:3]
        mnc = mcc_mnc[3:]
        setattr(self, self.attribute_prefix + "mcc-tai", mcc)
        setattr(self, self.attribute_prefix + "mnc-tai", mnc)
        setattr(self, self.attribute_prefix + "tac-tai", eval(tac))

    def decode_uli_mcc_mnc_ecgi(self, name, uli_mcc_mnc_ecgi):
        mcc_mnc, tac = uli_mcc_mnc_ecgi.split(',')
        mcc = mcc_mnc[:3]
        mnc = mcc_mnc[3:]
        setattr(self, self.attribute_prefix + "mcc-ecgi", mcc)
        setattr(self, self.attribute_prefix + "mnc-ecgi", mnc)
        setattr(self, self.attribute_prefix + "eci-ecgi", eval(tac))

    def decode_serving_network_mcc_mnc(self, name, serving_network_mcc_mnc):
        mcc = serving_network_mcc_mnc[:3]
        mnc = serving_network_mcc_mnc[3:]
        setattr(self, self.attribute_prefix + "mcc-serving-network", mcc)
        setattr(self, self.attribute_prefix + "mnc-serving-network", mnc)

    def decode_paa(self, name, static_paa):
        if static_paa == "false":
            setattr(self, self.attribute_prefix + "static-paa", "0.0.0.0")
        else:
            pass

    def get_attribute_value_by_name(self, name):
        name = self.attribute_prefix + name
        if hasattr(self, name):
            return getattr(self, name)
        else:
            return None

    def get_message_template(self, name):
        return self.template_dict.get(name, None)


class GTPV2IETemplate:
    def __init__(self, name, value):
        self.name = name
        self.value = value
        self.instance = None

    def set_value(self, value):
        pass


class GTPV2MessageTemplate:
    def __init__(self, name):
        self.name = name
        self.message_type = GTPV2MessageNameToType[name]
        self.ie_list = []
        self.teid = 0
        self.sequence_number = 0

    def add_ie(self, ie):
        self.ie_list.append(ie)

    def find_ie(self, name, instance):
        for ie in self.ie_list:
            if ie.name == name and ie.instance == instance:
                return ie
        return None

    def remove_ie(self, name, instance):
        ie = self.find_ie(name, instance)
        if ie:
            self.ie_list.remove(ie)


class GTPV2Message:
    def __init__(self, name):
        self.version = 2
        self.name = name
        self.p_flag = False
        self.t_flag = False
        self.message_length = 0
        self.message_type = 0
        self.teid = 0
        self.sequence_number = 0
        self.ie_list = []
        self.bytes_value = None

    def __bytes__(self):
        return self.bytes_value

    def __repr__(self):
        str_ie = "name:{n} type:{t} len:{l} teid:{cr} sequence_number:{i} ".format(n=self.name, t=self.message_type,
                                                                                   l=self.message_length, cr=self.teid,
                                                                                   i=self.sequence_number)
        return str_ie


class GTPV2IE:
    def __init__(self):
        self.type = "V"  # V: Variable length, F: "Fixed length", E: "Extendable", refer to 3gpp 29.274 8.1
        self.code = 0
        self.name = ""
        self.length = 0
        self.value = None
        self.bytes_value = b''
        self.cr_flag = 0
        self.instance = 0
        self.ie_grouped = []

    def __repr__(self):
        str_ie = "name:{n} code:{c} len:{l} cr_flag:{cr} instance:{i} value:{v}".format(n=self.name, c=self.code,
                                                                                        l=self.length, cr=self.cr_flag,
                                                                                        i=self.instance, v=self.value)
        return str_ie

    def __bytes__(self):
        return self.bytes_value


class Session:
    def __init__(self, imsi):
        self.imsi = imsi
        self.bearer_list = []


class Bearer:
    def __init__(self, imsi, bearer_id):
        self.imsi = imsi
        self.bearer_id = bearer_id



