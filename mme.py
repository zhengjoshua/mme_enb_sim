import socket
from queue import Queue, Empty
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
from protocol import *
STOP_THREAD = 0


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
    "msisdn": "MSISDN",
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
    "MSISDN": "msisdn",
    "mme-s11c-address": "mme-s11c-address",
    "pgw-s5s8-address": "pgw-s5s8-address",
    "mme-s11c-teid": "mme-s11c-teid",
    "restart-counter": "restart-counter"
}

IENameToProfileParamName = {
    "GTPV2IE_IMSI": "imsi",
    "GTPV2IE_MSISDN": "msisdn",
    "GTPV2IE_MEI": "mei",
    "ULI_TAI": "uli-mcc-mnc-tai",
    "ULI_ECGI": "uli-mcc-mnc-ecgi",
    "GTPV2IE_ServingNetwork": "serving-network-mcc-mnc",
    "GTPV2IE_Indication": "indication",
    "mme-s11c-address": "mme-s11c-address",
    "pgw-s5s8-address": "pgw-s5s8-address",
    "GTPv2IE_RAT": "rat-type",
    "GTPV2IE_APN": "apn",
    "GTPV2IE_SelectionMode": "selection-mode",
    "GTPV2IE_PDN_type": "pdn-type",
    "GTPV2IE_PAA": "static-paa",
    "GTPV2IE_APN_Restriction": "apn-restriction-type",
    "GTPV2IE_AMBR": "apn-ambr",
    "GTPV2IE_PCO": "pco",
    "GTPV2IE_BearerContext": "default-bearer-context",
    "GTPV2IE_ChargingCharacteristics": "chg-characteristics"
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
        self.events_queue = Queue()
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
            except Empty:
                continue

            print(received_event)
            if received_event[0] == 'set':
                if received_event[1] == "profile":
                    profile = self.find_profile(received_event[2])
                    if profile:
                        profile.set_parameter_value(received_event[3], received_event[4])
                        if received_event[3] == "mei":
                            if "GTPV2IE_MEI" not in GTPV2Message_dict["create_session_req"]:
                                GTPV2Message_dict["create_session_req"].insert(2, "GTPV2IE_MEI")
                        if received_event[3] == "indication":
                            if "GTPV2IE_Indication" not in GTPV2Message_dict["create_session_req"]:
                                index = GTPV2Message_dict["create_session_req"].index("GTPv2IE_RAT") + 1
                                GTPV2Message_dict["create_session_req"].insert(index, "GTPV2IE_Indication")
                    else:
                        print("Profile {i} not exist".format(i=received_event[2]))

            elif received_event[0] == "create":
                if received_event[1] == "profile":
                    try:
                        self.create_profile(received_event[2])
                    except IndexError:
                        print("Mandatory argument missing: prof-id.")
                elif received_event[1] == "session-group":
                    if len(received_event) == 5:
                        group_id = received_event[2]
                        profile_id = received_event[3]
                        size = received_event[4]
                        profile = self.find_profile(profile_id)
                        if not profile:
                            print("profile id {i} not found".format(i=profile_id))
                            continue
                        self.mme_list[0].create_session_group(group_id, profile, size)
                else:
                    pass
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
                    if received_event[2] == "group":
                        group_id = received_event[3]
                        session_group = self.mme_list[0].find_session_group(group_id)
                        if session_group:
                            self.mme_list[0].send_create_session_request(session_group.profile)
                        else:
                            print("session-group {i} not found".format(i=group_id))
                    elif received_event[2] == "imsi":
                        pass
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
        self.received_message_queue = Queue()
        self.sent_message_queue = Queue()
        self.events_queue = Queue()
        self.process_received_message_thread = None
        self.process_sent_message_thread = None
        self.session_group_list = []
        self.sessions = set()
        self.sequence_number = 1

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
        self.process_sent_message_thread = Thread(target=self.process_sent_message, daemon=True)
        self.process_sent_message_thread.start()

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
            echo_request = self.generate_echo_request(self.profile)
            # recovery_restart = IE_RecoveryRestart(ietype='Recovery Restart', length=1, restart_counter=1)
            # echo_request = GTPHeader(version=2, length=4+len(recovery_restart),  gtp_type=1)
            # send_data = bytes(echo_request/recovery_restart)

            self.sent_message_queue.put(echo_request)
            self.status = PeerStatus["EchoRequestSent"]

        while self.run:
            try:
                received_message = self.received_message_queue.get(block=True, timeout=60)
            except Empty:
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
                self.sent_message_queue.put(bytes(echo_response))
            elif gtp_message_type == GTPV2MessageNameToType["echo_response"]:
                self.status = PeerStatus["EchoResponseReceived"]
            elif gtp_message_type == GTPV2MessageNameToType["create_session_res"]:
                gtp_message.show()
                self.events_queue.put(BearerEvent['ModifyBearerResponse'])

    def process_event_queue(self):
        while self.run:
            try:
                received_event = self.events_queue.get(block=True, timeout=60)
            except Empty:
                continue

            if received_event == BearerEvent['CreateSessionResponse']:
                pass
            elif received_event == BearerEvent['ModifyBearerResponse']:
                pass
            else:
                pass

    def process_sent_message(self):
        while self.run:
            try:
                send_buffer = self.sent_message_queue.get(block=True, timeout=60)
                if send_buffer == STOP_THREAD:
                    break
                self.socket.send(send_buffer)
                self.sequence_number += 1
            except Empty:
                continue
            except OSError as e:
                if e.errno == 9:
                    break

    def is_alive(self):
        return self.run

    def terminate(self):
        if self.socket:
            self.socket.close()
        self.run = False
        sys.exit(1)

    def generate_echo_request(self, profile):
        echo_request_head = GTPHeader(length=4, gtp_type=1, seq=self.sequence_number)
        message_ie_list = GTPV2Message_dict.get("echo_request")
        length_of_all_ies = 0
        for ie_name in message_ie_list:
            ie = self.create_ie(ie_name, profile)
            if ie:
                echo_request_head.add_payload(ie)
                length_of_all_ies += len(ie)
        setattr(echo_request_head, "length", 4 + length_of_all_ies)
        return bytes(echo_request_head)

    def create_ie(self, name, profile):
        if '-' in name:
            cls_name = name[:name.find('-')]
        else:
            cls_name = name

        cls = globals()[cls_name]
        ie = cls()
        if name == "GTPV2IE_ULI":
            uli_tai = profile.get_parameter_by_name("ULI_TAI")
            uli_ecgi = profile.get_parameter_by_name("ULI_ECGI")
            ie.set_field_value(uli_tai, uli_ecgi)
        elif name in ["GTPV2IE_IMSI", "GTPV2IE_MSISDN", "GTPV2IE_IMEI"]:
            value = profile.get_parameter_by_name(name)
            ie.set_field_value(value)
        elif name == "GTPV2IE_FTEID-S11":
            teid = profile.get_attribute_value_by_name("mme-s11c-teid")
            f_teid_ipv4 = profile.get_attribute_value_by_name("mme-s11c-address")[0]
            ie.set_field_value(0, teid, 10, f_teid_ipv4)
        elif name == "GTPV2IE_FTEID-S5S8":
            teid = 0x0
            f_teid_ipv4 = profile.get_attribute_value_by_name("pgw-s5s8-address")[0]
            ie.set_field_value(1, teid, 7, f_teid_ipv4)
        elif name == "GTPV2IE_RecoveryRestart":
            restart_count = profile.get_attribute_value_by_name("restart-counter")
            ie.set_field_value(restart_count)
        elif name == "GTPV2IE_PAA":
            static_paa = profile.get_parameter_by_name(name)
            if static_paa == "false":
                ie.set_field_value(1, "0.0.0.0")
        else:
            value = profile.get_parameter_by_name(name)
            ie.set_field_value(value)

        return ie

    def proc_attach_group(self, session_group):
        message_ie_list = GTPV2Message_dict.get("create_session_req")
        for i in range(session_group.size):
            imsi = session_group.current_imsi
            session = Session(imsi)
            bearer = Bearer(imsi, 5)
            session.bearer_list.append(bearer)
            session_group.sessions.append(session)

    def send_create_session_request(self, profile):
        create_session_request = GTPHeader(length=8, gtp_type=32, T=1, teid=0, seq=self.sequence_number)
        message_ie_list = GTPV2Message_dict.get("create_session_req")
        length_of_all_ies = 0
        for ie_name in message_ie_list:
            ie = self.create_ie(ie_name, profile)
            if ie:
                create_session_request.add_payload(ie)
                length_of_all_ies += len(ie)
        setattr(create_session_request, "length", 8 + length_of_all_ies)
        send_data = bytes(create_session_request)
        self.sent_message_queue.put(send_data)

    def create_session_group(self, group_id, profile, size):
        session_group = self.find_session_group(group_id)
        if not session_group:
            session_group = SessionGroup(int(group_id), int(size))
            session_group.set_profile(profile)
            self.session_group_list.append(session_group)

        return session_group

    def find_session_group(self, group_id):
        for session_group in self.session_group_list:
            if session_group.group_id == int(group_id):
                return session_group
        return None


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
                                             "rat-type": self.set_int_value,
                                             "indication": self.decode_indication,
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
                                             "mme-s11c-teid": self.set_hex_int_value,
                                             "csg-cr-support": self.set_indication_flag,
                                             "pco": self.set_ipv4_address,
                                             "mei": self.set_string_value
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
        self.parameters_dict["pdn-type"] = "1"
        self.parameters_dict["rat-type"] = "6"
        self.parameters_dict["indication"] = "0x0000"
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
        self.parameters_dict["pco"] = "0.0.0.0"

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

    def decode_indication(self, name, indication):
        indication_length = len(indication)
        indication = int(indication, 16)
        if indication_length == 8:
            setattr(self, self.attribute_prefix + "indication.ccrsi", bool(indication & 0x01))
            setattr(self, self.attribute_prefix + "indication.israu", bool(indication & 0x02))
            setattr(self, self.attribute_prefix + "indication.mbmdt", bool(indication & 0x04))
            setattr(self, self.attribute_prefix + "indication.s4af", bool(indication & 0x08))
            setattr(self, self.attribute_prefix + "indication.s6af", bool(indication & 0x10))
            setattr(self, self.attribute_prefix + "indication.srni", bool(indication & 0x20))
            setattr(self, self.attribute_prefix + "indication.pbic", bool(indication & 0x40))
            setattr(self, self.attribute_prefix + "indication.retloc", bool(indication & 0x80))
        elif indication_length == 6:
            setattr(self, self.attribute_prefix + "indication.msv", bool(indication & 0x01))
            setattr(self, self.attribute_prefix + "indication.si", bool(indication & 0x02))
            setattr(self, self.attribute_prefix + "indication.pt", bool(indication & 0x04))
            setattr(self, self.attribute_prefix + "indication.ps", bool(indication & 0x08))
            setattr(self, self.attribute_prefix + "indication.crsi", bool(indication & 0x10))
            setattr(self, self.attribute_prefix + "indication.cfsi", bool(indication & 0x20))
            setattr(self, self.attribute_prefix + "indication.uimsi", bool(indication & 0x40))
            setattr(self, self.attribute_prefix + "indication.sqci", bool(indication & 0x80))
        else:
            pass

    def set_indication_flag(self, name, value):
        pass

    def get_parameter_by_name(self, name):
        parameter_name = IENameToProfileParamName[name]
        return self.parameters_dict[parameter_name]

    def get_attribute_value_by_name(self, name):
        name = IEAttrNameToProfileAttrName[name]
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


class SessionGroup:
    def __init__(self, group_id, size):
        self.group_id = group_id
        self.current_imsi = ""
        self.current_msisdn = ""
        self.current_imei = ""
        self.current_mme_s11c_f_teid = 0x0
        self.profile = None
        self.size = size
        self.sessions = []

    def set_profile(self, profile):
        self.profile = profile
        self.current_imsi = profile.get_parameter_by_name("GTPV2IE_IMSI")
        self.current_msisdn = profile.get_parameter_by_name("GTPV2IE_MSISDN")
        self.current_mme_s11c_f_teid = profile.get_attribute_value_by_name("mme-s11c-teid")

    def next(self):
        self.current_imsi = str(int(self.current_imsi) + 1)
        self.current_msisdn = str(int(self.current_msisdn) + 1)
        self.current_mme_s11c_f_teid += 1


class Session:
    def __init__(self, imsi):
        self.imsi = imsi
        self.bearer_list = []
        self.apn = ""


class Bearer:
    def __init__(self, imsi, bearer_id):
        self.imsi = imsi
        self.bearer_id = bearer_id
        self.bearer_type = "bearer"
        self.bearer_status = ""
        self.apn = ""
        self.qci = 9
        self.arp = 15



