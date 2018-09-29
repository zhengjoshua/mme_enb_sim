from queue import Queue, Empty
from threading import Thread
from collections import OrderedDict
from protocol import *
STOP_THREAD = 0
from transitions import Machine

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
    "GTPV2IE_RAT": "rat-type",
    "GTPV2IE_APN": "apn",
    "GTPV2IE_SelectionMode": "selection-mode",
    "GTPV2IE_PDN_type": "pdn-type",
    "GTPV2IE_PAA": "static-paa",
    "GTPV2IE_APN_Restriction": "apn-restriction-type",
    "GTPV2IE_AMBR": "apn-ambr",
    "GTPV2IE_PCO": "pco",
    "GTPV2IE_BearerContext": "default-bearer-context",
    "GTPV2IE_ChargingCharacteristics": "chg-characteristics",
    "cbresp-cause": "cbresp-cause",
    "ubresp-cause": "ubresp-cause",
    "dbresp-cause": "dbresp-cause"
}

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
    "WaitForEchoResponse": 1,
    "Up": 2,
}
PeerStatusToName = {
    0: "Down",
    1: "WaitForEchoResponse",
    2: "Up"
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
        self.run = False
        self.socket = None
        self.events_queue = Queue()
        self.mme_list = []
        self.profile_list = []
        self.config_dict = {}

    def start(self):
        self.load_config()
        self.run = True

        mme_s11c_address = self.config_dict.get("mme-s11c-address", "0.0.0.0")
        mme_s11c_port = int(self.config_dict.get('mme-s11c-port', 2123))
        sgw_s11c_address = self.config_dict.get('sgw-s11c-address', "0.0.0.0")
        sgw_s11c_port = int(self.config_dict.get('sgw-s11c-port', 2123))
        restart_counter = int(self.config_dict.get('restart-counter', 1))

        default_profile = self.create_profile(0)

        for mme_id, mme_address in enumerate(mme_s11c_address.split(','), 1):
            self.create_mme(mme_id, mme_address.strip(), mme_s11c_port, sgw_s11c_address, sgw_s11c_port,
                            default_profile, restart_counter)

        while self.run:
            try:
                received_event = self.events_queue.get(block=True, timeout=60)
            except Empty:
                continue

            # print(received_event)
            if received_event[0] == 'set':
                if received_event[1] == "profile":
                    profile = self.find_profile(received_event[2])
                    if profile:
                        profile.set_parameter_value(received_event[3], received_event[4])
                        if received_event[3] == "mei":
                            if "GTPV2IE_MEI" not in GTPV2MessageOptionalIEdict["create_session_req"]:
                                GTPV2MessageOptionalIEdict["create_session_req"].append("GTPV2IE_MEI")
                        if received_event[3] == "indication":
                            if "GTPV2IE_Indication" not in GTPV2MessageOptionalIEdict["create_session_req"]:
                                GTPV2MessageOptionalIEdict["create_session_req"].append("GTPV2IE_Indication")
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
                elif received_event[1] == "session":
                    if len(received_event) == 2:
                        pass
                    elif len(received_event) == 3:
                        if received_event[2] == "pdn":
                            self.mme_list[0].show_all_session()
                    elif len(received_event) == 4:
                        if received_event[2] == "pdn":
                            imsi = received_event[3]
                            self.mme_list[0].show_session_by_imsi(imsi)
                        elif received_event[2] == "bearer":
                            imsi = received_event[3]
                            session = self.mme_list[0].find_session_by_imsi(imsi)
                            if session:
                                session.show_bearer()

            elif received_event[0] == "proc":
                if received_event[1] == "attach":
                    if received_event[2] == "group":
                        group_id = received_event[3]
                        session_group = self.mme_list[0].find_session_group(group_id)
                        if session_group:
                            self.mme_list[0].process_attach_group(session_group)
                        else:
                            print("session-group {i} not found".format(i=group_id))
                    elif received_event[2] == "imsi":
                        pass
                elif received_event[1] == "detach":
                    if received_event[2] == "group":
                        group_id = received_event[3]
                        session_group = self.mme_list[0].find_session_group(group_id)
                        if session_group:
                            # self.mme_list[0].send_create_session_request(session_group.profile)
                            self.mme_list[0].process_detach_group(session_group)
                        else:
                            print("session-group {i} not found".format(i=group_id))
                    elif received_event[2] == "imsi":
                        pass
                elif received_event[1] == "idle":
                    if len(received_event) <= 3:
                        pass
                    else:
                        group_id = received_event[3]
                        session_group = self.mme_list[0].find_session_group(group_id)
                        if session_group:
                            self.mme_list[0].process_idle_group(session_group)
                        else:
                            print("session-group {i} not found".format(i=group_id))

                elif received_event[1] == "mbr":
                    if len(received_event) <= 4:
                        pass
                    else:
                        group_id = received_event[3]
                        bearer_id = int(received_event[4])
                        session_group = self.mme_list[0].find_session_group(group_id)
                        if session_group:
                            for session in session_group.sessions:
                                self.mme_list[0].send_modify_bearer_request(session, bearer_id)
                        else:
                            print("session-group {i} not found".format(i=group_id))
            else:
                pass

    def load_config(self):
        try:
            with open(self.config_file) as f:
                with open(self.config_file + ".bak", 'w+') as f_bak:
                    for line in f.readlines():
                        if line.strip().startswith('#') or line.strip().startswith('[') or len(line.strip()) == 0:
                            continue
                        if "#" in line:
                            line = line[:line.find("#")]
                        k, v = line.split('=')
                        if "restart-counter" in line:
                            v = str(int(v.strip()) + 1)
                            line = ' = '.join([k.strip(), v])

                        self.config_dict[k.strip()] = v.strip()
                        f_bak.write(line)
            os.remove(self.config_file)
            os.rename(self.config_file + ".bak", self.config_file)

        except FileNotFoundError as e:
            info = "Configuration file '{e}' not found.".format(e=e)
            print(info)
            logging.info(info)
            self.terminate()

    def create_mme(self, mme_id, address1, port1, address2, port2, profile, restart_counter):
        mme = MME(mme_id, profile)
        mme.set_socket(address1, port1, address2, port2)
        mme.set_restart_counter(restart_counter)
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
            new_profile = Profile(int(profile_id))
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
    def __init__(self, mme_id, profile):
        self.mme_id = mme_id
        self.default_profile = profile
        self.profile_list = [profile]
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
        self.restart_counter = 1

    def __str__(self):
        info = """-----------------------------------------------------------------------------------------
MME ID                :  {i}
Status                :  {st}
MME S11c Address      :  {a1}
MME S11c Port         :  {p1}
SGW S11c Address      :  {a2}
SGW S11c Port         :  {p2}
Create time           :  {t}
Active sessions       :  {s}
-----------------------------------------------------------------------------------------""".format(i=self.mme_id,
                                                                                    st=PeerStatusToName[self.status],
                                                                                    a1=self.mme_s11c_address,
                                                                                    p1=self.mme_s11c_port,
                                                                                    a2=self.sgw_s11c_address,
                                                                                    p2=self.sgw_s11c_port,
                                                                                    t=self.start_time,
                                                                                    s=len(self.sessions))
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

    def set_restart_counter(self, restart_counter):
        self.restart_counter = restart_counter

    def process_received_message(self):
        if self.status is PeerStatus["Down"]:
            self.sent_echo_request()
            self.status = PeerStatus["WaitForEchoResponse"]

        while self.run:
            try:
                received_message = self.received_message_queue.get(block=True, timeout=60)
            except Empty:
                continue

            try:
                gtp_message = GTPHeader(received_message)
                gtp_message_type = gtp_message.gtp_type
            except AttributeError:
                print("AttributeError")
                continue

            if gtp_message_type == GTPV2MessageNameToType["echo_request"]:
                self.process_echo_request(gtp_message)
            elif gtp_message_type == GTPV2MessageNameToType["echo_response"]:
                self.status = PeerStatus["Up"]
            elif gtp_message_type == GTPV2MessageNameToType["create_session_res"]:
                self.process_create_session_response(gtp_message)
            elif gtp_message_type == GTPV2MessageNameToType["delete_session_res"]:
                self.process_delete_session_response(gtp_message)
            elif gtp_message_type == GTPV2MessageNameToType["create_bearer_req"]:
                self.process_create_bearer_request(gtp_message)
            elif gtp_message_type == GTPV2MessageNameToType["update_bearer_req"]:
                self.process_update_bearer_request(gtp_message)
            elif gtp_message_type == GTPV2MessageNameToType["delete_bearer_req"]:
                self.process_delete_bearer_request(gtp_message)
            elif gtp_message_type == GTPV2MessageNameToType["realease_bearers_res"]:
                self.process_release_access_bearers_response(gtp_message)

    # def process_event_queue(self):
    #     while self.run:
    #         try:
    #             received_event = self.events_queue.get(block=True, timeout=60)
    #         except Empty:
    #             continue
    #
    #         if received_event == BearerEvent['CreateSessionResponse']:
    #             pass
    #         elif received_event == BearerEvent['ModifyBearerResponse']:
    #             pass
    #         else:
    #             pass

    def process_sent_message(self):
        while self.run:
            try:
                send_buffer = self.sent_message_queue.get(block=True, timeout=60)
                if send_buffer == STOP_THREAD:
                    break
                self.socket.send(send_buffer)
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

    def sent_echo_request(self):
        echo_request = GTPHeader(length=4, gtp_type=1, seq=self.sequence_number)
        self.sequence_number += 1
        recovery_restart = IE_RecoveryRestart(ietype='Recovery Restart', length=1,
                                              restart_counter=self.restart_counter)
        echo_request /= recovery_restart
        setattr(echo_request, "length", 4 + len(recovery_restart))
        self.sent_message_queue.put(bytes(echo_request))

    def process_echo_request(self, gtp_message):
        recovery_restart = IE_RecoveryRestart(ietype='Recovery Restart', length=1,
                                              restart_counter=self.restart_counter)

        ack_seq_number = gtp_message.seq
        echo_response = GTPHeader(version=2, gtp_type=2, seq=ack_seq_number) / recovery_restart
        setattr(echo_response, "length", 4 + len(recovery_restart))
        self.sent_message_queue.put(bytes(echo_response))

    def process_attach_group(self, session_group):
        profile = session_group.profile
        for i in range(session_group.size):
            imsi = session_group.current_imsi
            session = self.find_session_by_imsi(imsi)
            if not session:
                session = Session(imsi)
                session_group.sessions.append(session)
                session.first_enodeb_s1u_teid = session_group.current_enodeb_s1u_f_teid
                session.profile_id = session_group.profile.profile_id

                bearer = Bearer(imsi, 5)
                session.bearer_list.append(bearer)
                bearer.enodeb_s1u_teid = session.first_enodeb_s1u_teid
                session.enodeb_s1u_teid_ipv4 = session_group.enodeb_s1u_teid_ipv4
                bearer.enodeb_s1u_teid_ipv4 = session.enodeb_s1u_teid_ipv4
            else:
                bearer = session.bearer_list[0]

            create_session_request = GTPHeader(length=8, gtp_type=32, T=1, teid=0, seq=self.sequence_number)
            self.sequence_number += 1
            length_of_all_ies = 0

            ie_imsi = GTPV2IE_IMSI()
            ie_imsi.set_field_value(imsi)
            create_session_request.add_payload(ie_imsi)
            length_of_all_ies += len(ie_imsi)

            ie_msisdn = GTPV2IE_MSISDN()
            ie_msisdn.set_field_value(session_group.current_msisdn)
            create_session_request.add_payload(ie_msisdn)
            length_of_all_ies += len(ie_msisdn)
            session.msisdn = ie_msisdn.MSISDN

            if "GTPV2IE_MEI" in GTPV2MessageOptionalIEdict.get("create_session_req"):
                ie_mei = GTPV2IE_MEI()
                ie_mei.set_field_value(session_group.current_mei)
                create_session_request.add_payload(ie_mei)
                length_of_all_ies += len(ie_mei)
                session.mei = ie_mei.MEI

            ie_uli = GTPV2IE_ULI()
            uli_tai = profile.get_parameter_by_name("ULI_TAI")
            uli_ecgi = profile.get_parameter_by_name("ULI_ECGI")
            ie_uli.set_field_value(uli_tai, uli_ecgi)
            create_session_request.add_payload(ie_uli)
            session.tai_mcc = ie_uli.TAI.MCC
            session.tai_mnc = ie_uli.TAI.MNC
            session.tac = ie_uli.TAI.TAC
            session.ecgi_mcc = ie_uli.ECGI.MCC
            session.ecgi_mnc = ie_uli.ECGI.MNC
            session.eci = ie_uli.ECGI.ECI
            length_of_all_ies += len(ie_uli)

            ie_serving_network = GTPV2IE_ServingNetwork()
            value = profile.get_parameter_by_name("GTPV2IE_ServingNetwork")
            ie_serving_network.set_field_value(value)
            create_session_request.add_payload(ie_serving_network)
            length_of_all_ies += len(ie_serving_network)
            session.mcc = ie_serving_network.MCC
            session.mnc = ie_serving_network.MNC

            ie_rat_type = GTPV2IE_RAT()
            value = profile.get_parameter_by_name("GTPV2IE_RAT")
            ie_rat_type.set_field_value(value)
            create_session_request.add_payload(ie_rat_type)
            length_of_all_ies += len(ie_rat_type)
            session.rat_type = ie_rat_type.RAT_type

            if "GTPV2IE_Indication" in GTPV2MessageOptionalIEdict.get("create_session_req"):
                ie_indication = GTPV2IE_Indication()
                value = profile.get_parameter_by_name("GTPV2IE_Indication")
                ie_indication.set_field_value(value)
                create_session_request.add_payload(ie_indication)
                length_of_all_ies += len(ie_indication)
                session.indication = value

            ie_mme_s11c_f_teid = GTPV2IE_FTEID()
            teid = session_group.current_mme_s11c_f_teid
            f_teid_ipv4 = profile.get_attribute_value_by_name("mme-s11c-address")[0]
            ie_mme_s11c_f_teid.set_field_value(0, teid, 10, f_teid_ipv4)
            create_session_request.add_payload(ie_mme_s11c_f_teid)
            length_of_all_ies += len(ie_mme_s11c_f_teid)
            session.mme_s11c_f_teid = teid
            session.mme_s11c_f_teid_ipv4 = f_teid_ipv4

            ie_mme_s5s8c_f_teid = GTPV2IE_FTEID()
            teid = 0x0
            f_teid_ipv4 = profile.get_attribute_value_by_name("pgw-s5s8-address")[0]
            ie_mme_s5s8c_f_teid.set_field_value(1, teid, 7, f_teid_ipv4)
            create_session_request.add_payload(ie_mme_s5s8c_f_teid)
            length_of_all_ies += len(ie_mme_s5s8c_f_teid)
            session.mme_s5s8c_f_teid = teid
            session.mme_s5s8c_f_teid_ipv4 = f_teid_ipv4

            ie_apn = GTPV2IE_APN()
            value = profile.get_parameter_by_name("GTPV2IE_APN")
            ie_apn.set_field_value(value)
            create_session_request.add_payload(ie_apn)
            length_of_all_ies += len(ie_apn)
            session.apn = value
            bearer.apn = session.apn

            ie_selection_mode = GTPV2IE_SelectionMode()
            value = profile.get_parameter_by_name("GTPV2IE_SelectionMode")
            ie_selection_mode.set_field_value(value)
            create_session_request.add_payload(ie_selection_mode)
            length_of_all_ies += len(ie_selection_mode)
            session.selection_mode = ie_selection_mode.SelectionMode

            ie_pdn_type = GTPV2IE_PDN_type()
            value = profile.get_parameter_by_name("GTPV2IE_PDN_type")
            ie_pdn_type.set_field_value(value)
            create_session_request.add_payload(ie_pdn_type)
            length_of_all_ies += len(ie_pdn_type)
            if int(value) == 4:
                session.pdn_type = 1
            elif int(value) == 6:
                session.pdn_type = 2

            ie_paa = GTPV2IE_PAA()
            static_paa = profile.get_parameter_by_name("GTPV2IE_PAA")
            if static_paa == "false":
                if session.pdn_type == 1:
                    ie_paa.set_field_value(1, "0.0.0.0")
                    create_session_request.add_payload(ie_paa)
                    length_of_all_ies += len(ie_paa)
                    session.paa = ie_paa.ipv4
                elif session.pdn_type == 2:
                    ie_paa.set_field_value(2, "2001:db8:0:42::")
                    create_session_request.add_payload(ie_paa)
                    length_of_all_ies += len(ie_paa)
                    session.paa = ie_paa.ipv6
                else:
                    pass

            ie_apn_restriction = GTPV2IE_APN_Restriction()
            value = profile.get_parameter_by_name("GTPV2IE_APN_Restriction")
            ie_apn_restriction.set_field_value(value)
            create_session_request.add_payload(ie_apn_restriction)
            length_of_all_ies += len(ie_apn_restriction)
            session.apn_restriction = ie_apn_restriction.APN_Restriction

            ie_ambr = GTPV2IE_AMBR()
            value = profile.get_parameter_by_name("GTPV2IE_AMBR")
            ie_ambr.set_field_value(value)
            create_session_request.add_payload(ie_ambr)
            length_of_all_ies += len(ie_ambr)
            session.ambr_uplink = ie_ambr.AMBR_Uplink
            session.ambr_downlink = ie_ambr.AMBR_Downlink

            ie_pco = GTPV2IE_PCO()
            value = profile.get_parameter_by_name("GTPV2IE_PCO")
            ie_pco.set_field_value(value)
            create_session_request.add_payload(ie_pco)
            length_of_all_ies += len(ie_pco)
            session.pco = value

            ie_bearer_context = GTPV2IE_BearerContext()
            value = profile.get_parameter_by_name("GTPV2IE_BearerContext")
            ie_bearer_context.set_field_value(value)
            create_session_request.add_payload(ie_bearer_context)
            length_of_all_ies += len(ie_bearer_context)
            bearer.qci = ie_bearer_context.IE_list[1].QCI
            bearer.arp = ie_bearer_context.IE_list[1].PriorityLevel
            bearer.mbr_uplink = ie_bearer_context.IE_list[1].MaxBitRateForUplink
            bearer.mbr_downlink = ie_bearer_context.IE_list[1].MaxBitRateForDownlink
            bearer.gbr_uplink = ie_bearer_context.IE_list[1].GuaranteedBitRateForUplink
            bearer.gbr_downlink = ie_bearer_context.IE_list[1].GuaranteedBitRateForDownlink
            bearer.bearer_id = ie_bearer_context.IE_list[0].EBI

            if "GTPV2IE_ChargingCharacteristics" in GTPV2MessageOptionalIEdict.get("create_session_req"):
                ie_cc = GTPV2IE_ChargingCharacteristics()
                value = profile.get_parameter_by_name("GTPV2IE_ChargingCharacteristics")
                ie_cc.set_field_value(value)
                create_session_request.add_payload(ie_cc)
                length_of_all_ies += len(ie_cc)
                session.cc = value

            if "GTPV2IE_UE_Timezone" in GTPV2MessageOptionalIEdict.get("create_session_req"):
                ie_timezone = GTPV2IE_UE_Timezone()
                value = profile.get_parameter_by_name("GTPV2IE_UE_Timezone")
                ie_timezone.set_field_value(value)
                create_session_request.add_payload(ie_timezone)
                length_of_all_ies += len(ie_timezone)
                session.timezone = ie_timezone.Timezone
                session.DST = ie_timezone.DST

            setattr(create_session_request, "length", 8 + length_of_all_ies)
            send_data = bytes(create_session_request)
            self.sent_message_queue.put(send_data)
            session_group.generate_next_id()
        session_group.reset()

    def process_detach_group(self, session_group):
        for session in session_group.sessions:
            self.send_delete_session_request(session)

    def process_idle_group(self, session_group):
        for session in session_group.sessions:
            self.send_release_access_bearers_request(session)

    def process_create_session_response(self, message):
        session = self.find_session_by_teid(message.teid)
        if session:
            cause = self.find_ie(message, IETypeNameToCode["Cause"], 0).Cause
            if cause == CauseNameToValue["Request Accepted"]:
                session.status = "ATTACHED_ACTIVE"
                # pco = self.find_ie(message, IETypeNameToCode["Cause"], 0)
                # if pco:
                #     session.pco = pco.Protocols[0].PPP.Options[0].address

                f_teid = self.find_ie(message, IETypeNameToCode["F-TEID"], 0)
                if f_teid.InterfaceType == 11:  #SGW GTP-C
                    session.sgw_s11s4c_teid = f_teid.GRE_Key
                    session.sgw_s11s4c_teid_ipv4 = f_teid.ipv4

                f_teid = self.find_ie(message, IETypeNameToCode["F-TEID"], 1)
                if f_teid.InterfaceType == 7:  #SGW GTP-C
                    session.pgw_s5s8c_teid = f_teid.GRE_Key
                    session.pgw_s5s8c_teid_ipv4 = f_teid.ipv4

                paa = self.find_ie(message, IETypeNameToCode["PAA"], 0)
                if paa:
                    session.pdn_type = paa.PDN_type
                    if session.pdn_type == 1:
                        session.paa = paa.ipv4
                    elif session.pdn_type == 2:
                        session.paa = paa.ipv6
                    else:
                        pass

                ie_ambr = self.find_first_ie_by_type(message, IETypeNameToCode["AMBR"])
                if ie_ambr:
                    session.ambr_uplink = ie_ambr.AMBR_Uplink
                    session.ambr_downlink = ie_ambr.AMBR_Downlink

                bearer_context = self.find_ie(message, IETypeNameToCode["Bearer Context"], 0)
                if bearer_context:
                    ie_bearer_id = self.find_ie(bearer_context, IETypeNameToCode["EPS Bearer ID"], 0)
                    if ie_bearer_id:
                        bearer_id = ie_bearer_id.EBI
                        bearer = session.get_bearer_by_id(bearer_id)
                        if bearer:
                            f_teid = self.find_ie(bearer_context, IETypeNameToCode["F-TEID"], 0)
                            if f_teid.InterfaceType == 1:  # SGW S1U
                                bearer.sgw_s1u_teid = f_teid.GRE_Key
                                bearer.sgw_s1u_teid_ipv4 = f_teid.ipv4

                            f_teid = self.find_ie(bearer_context, IETypeNameToCode["F-TEID"], 2)
                            if f_teid.InterfaceType == 5:  # PGW S5S8U
                                bearer.pgw_s5s8u_teid = f_teid.GRE_Key
                                bearer.pgw_s5s8u_teid_ipv4 = f_teid.ipv4

                            ie_bearer_qos = self.find_first_ie_by_type(bearer_context, IETypeNameToCode["Bearer QoS"])
                            if ie_bearer_qos:
                                bearer.qci = ie_bearer_qos.QCI
                                bearer.arp = ie_bearer_qos.PriorityLevel
                                bearer.mbr_uplink = ie_bearer_qos.MaxBitRateForUplink
                                bearer.mbr_downlink = ie_bearer_qos.MaxBitRateForDownlink
                                bearer.gbr_uplink = ie_bearer_qos.GuaranteedBitRateForUplink
                                bearer.gbr_downlink = ie_bearer_qos.GuaranteedBitRateForDownlink

                        self.send_modify_bearer_request(session, bearer_id)

            else:
                self.delete_session_by_teid(message.teid)

    def process_modify_bearer_response(self, message):
        pass

    def process_delete_session_response(self, message):
        self.delete_session_by_teid(message.teid)

    def send_modify_bearer_request(self, session, bearer_id):
        modify_bearer_request = GTPHeader(length=8, gtp_type=34, T=1, teid=session.sgw_s11s4c_teid,
                                          seq=self.sequence_number)
        self.sequence_number += 1
        length_of_all_ies = 0

        bearer = session.get_bearer_by_id(bearer_id)
        if bearer:
            profile = self.find_profile(session.profile_id)
            enodeb_s1u_fteid = IE_FTEID(ietype='F-TEID', length=9, ipv4_present=1, InterfaceType=0,
                                        GRE_Key=bearer.enodeb_s1u_teid,
                                        ipv4=bearer.enodeb_s1u_teid_ipv4)
            ie_bearer_context = IE_BearerContext(ietype='Bearer Context', length=18,
                                              IE_list=[IE_EPSBearerID(ietype='EPS Bearer ID', length=1, EBI=bearer_id),
                                                       enodeb_s1u_fteid])
            modify_bearer_request.add_payload(ie_bearer_context)
            length_of_all_ies += len(ie_bearer_context)

            ie_uli = GTPV2IE_ULI()
            uli_tai = profile.get_parameter_by_name("ULI_TAI")
            uli_ecgi = profile.get_parameter_by_name("ULI_ECGI")
            ie_uli.set_field_value(uli_tai, uli_ecgi)

            if any([session.tai_mcc != ie_uli.TAI.MCC, session.tai_mnc != ie_uli.TAI.MNC, session.tac != ie_uli.TAI.TAC]):
                ie_tai = ULI_TAI(MCC=ie_uli.TAI.MCC, MNC=ie_uli.TAI.MNC, TAC=ie_uli.TAI.TAC)
                tai_changed = True
                session.tai_mcc = ie_uli.TAI.MCC
                session.tai_mnc = ie_uli.TAI.MNC
                session.tac = ie_uli.TAI.TAC
            else:
                tai_changed = False
            if any([session.ecgi_mcc != ie_uli.ECGI.MCC, session.ecgi_mnc != ie_uli.ECGI.MNC,
                    session.eci != ie_uli.ECGI.ECI]):
                ie_ecgi = ULI_ECGI(MCC=ie_uli.ECGI.MCC, MNC=ie_uli.ECGI.MNC, ECI=ie_uli.ECGI.ECI)
                ecgi_changed = True
                session.ecgi_mcc = ie_uli.ECGI.MCC
                session.ecgi_mnc = ie_uli.ECGI.MNC
                session.eci = ie_uli.ECGI.ECI
            else:
                ecgi_changed = False

            if tai_changed or ecgi_changed:
                uli = IE_ULI(ietype='ULI')
                length = 1
                if tai_changed:
                    uli.TAI_Present = True
                    length += 5
                    uli.TAI = ie_tai
                if ecgi_changed:
                    length += 7
                    uli.ECGI_Present = True
                    uli.ECGI = ie_ecgi

                uli.length = length
                modify_bearer_request.add_payload(uli)
                length_of_all_ies += len(uli)

            setattr(modify_bearer_request, "length", 8 + length_of_all_ies)
            send_data = bytes(modify_bearer_request)
            self.sent_message_queue.put(send_data)

    def send_delete_session_request(self, session):
        delete_session_request = GTPHeader(length=8, gtp_type=36, T=1, teid=session.sgw_s11s4c_teid,
                                          seq=self.sequence_number)
        self.sequence_number += 1

        bearer = session.bearer_list[0]
        length_of_all_ies = 0

        ie_bearer_id = IE_EPSBearerID(ietype='EPS Bearer ID', length=1, EBI=bearer.bearer_id)
        delete_session_request /= ie_bearer_id
        length_of_all_ies += len(ie_bearer_id)

        setattr(delete_session_request, "length", 8 + length_of_all_ies)
        send_data = bytes(delete_session_request)
        self.sent_message_queue.put(send_data)

    def send_create_bearer_response(self, session, bearer, ack_seq_num):
        create_bearer_response = GTPHeader(length=8, gtp_type=96, T=1, teid=session.sgw_s11s4c_teid,
                                           seq=ack_seq_num)
        self.sequence_number += 1
        length_of_all_ies = 0

        if bearer:
            profile = self.find_profile(session.profile_id)
            cbresp_cause = profile.get_parameter_by_name("cbresp-cause")
            ie_cause = IE_Cause(Cause=int(cbresp_cause), length=2)
            create_bearer_response /= ie_cause
            length_of_all_ies += len(ie_cause)

            ie_bearer_context_cause = IE_Cause(Cause=int(cbresp_cause), length=2)
            ie_bearer_id = IE_EPSBearerID(ietype='EPS Bearer ID', length=1, EBI=bearer.bearer_id)
            ie_enodeb_s1u_fteid = IE_FTEID(ietype='F-TEID', length=9, ipv4_present=1, InterfaceType=0,
                                        GRE_Key=bearer.enodeb_s1u_teid,
                                        ipv4=bearer.enodeb_s1u_teid_ipv4)
            ie_sgw_s1u_teid = IE_FTEID(ietype='F-TEID', instance=1, length=9, ipv4_present=1, InterfaceType=1,
                                           GRE_Key=bearer.sgw_s1u_teid,
                                           ipv4=bearer.sgw_s1u_teid_ipv4)
            bearer_context = IE_BearerContext(ietype='Bearer Context', length=37,
                                              IE_list=[ie_bearer_id, ie_bearer_context_cause, ie_enodeb_s1u_fteid,
                                                       ie_sgw_s1u_teid])
            create_bearer_response /= bearer_context
            length_of_all_ies += len(bearer_context)

        setattr(create_bearer_response, "length", 8 + length_of_all_ies)
        send_data = bytes(create_bearer_response)
        self.sent_message_queue.put(send_data)

    def process_create_bearer_request(self, message):
        ack_seq_number = message.seq
        session = self.find_session_by_teid(message.teid)
        if session:
            next_bearer_id = 5 + len(session.bearer_list)
            bearer = Bearer(session.imsi, next_bearer_id)
            bearer.bearer_type = "Ded"
            bearer.enodeb_s1u_teid = session.first_enodeb_s1u_teid + len(session.bearer_list)
            bearer.enodeb_s1u_teid_ipv4 = session.enodeb_s1u_teid_ipv4
            bearer.apn = session.apn
            session.bearer_list.append(bearer)

            bearer_context = self.find_ie(message, IETypeNameToCode["Bearer Context"], 0)
            if bearer_context:
                f_teid = self.find_ie(bearer_context, IETypeNameToCode["F-TEID"], 0)
                if f_teid.InterfaceType == 1:  # SGW S1U
                    bearer.sgw_s1u_teid = f_teid.GRE_Key
                    bearer.sgw_s1u_teid_ipv4 = f_teid.ipv4

                f_teid = self.find_ie(bearer_context, IETypeNameToCode["F-TEID"], 1)
                if f_teid.InterfaceType == 5:  # PGW S5S8U
                    bearer.pgw_s5s8u_teid = f_teid.GRE_Key
                    bearer.pgw_s5s8u_teid_ipv4 = f_teid.ipv4

                bearer_qos = self.find_ie(bearer_context, IETypeNameToCode["Bearer QoS"], 0)
                bearer.arp = bearer_qos.PriorityLevel
                bearer.qci = bearer_qos.QCI
                bearer.mbr_uplink = bearer_qos.MaxBitRateForUplink
                bearer.mbr_downlink = bearer_qos.MaxBitRateForDownlink
                bearer.gbr_uplink = bearer_qos.GuaranteedBitRateForUplink
                bearer.gbr_downlink = bearer_qos.GuaranteedBitRateForDownlink

            self.send_create_bearer_response(session, bearer, ack_seq_number)

    def process_update_bearer_request(self, message):
        ack_seq_number = message.seq
        session = self.find_session_by_teid(message.teid)
        if session:
            bearer_context = self.find_ie(message, IETypeNameToCode["Bearer Context"], 0)
            if bearer_context:
                retloc = False
                ie_bearer_id = self.find_ie(bearer_context, IETypeNameToCode["EPS Bearer ID"], 0)
                if ie_bearer_id:
                    bearer_id = ie_bearer_id.EBI
                    bearer = session.get_bearer_by_id(bearer_id)
                    if bearer:
                        ie_bearer_tft = self.find_ie(bearer_context, IETypeNameToCode["Bearer TFT"], 0)
                        if ie_bearer_tft:
                            pass
                        ie_ambr = self.find_ie(bearer_context, IETypeNameToCode["AMBR"], 0)
                        if ie_ambr:
                            session.ambr_uplink = ie_ambr.AMBR_Uplink
                            session.ambr_downlink = ie_ambr.AMBR_Downlink
                        ie_indication = self.find_ie(message, IETypeNameToCode["Indication"], 0)
                        try:
                            retloc = ie_indication.RetLoc
                        except AttributeError:
                            pass

                    update_bearer_response = GTPHeader(length=8, gtp_type=98, T=1, teid=session.sgw_s11s4c_teid,
                                                       seq=ack_seq_number)
                    self.sequence_number += 1
                    length_of_all_ies = 0
                    if bearer:
                        profile = self.find_profile(session.profile_id)
                        ubresp_cause = profile.get_parameter_by_name("ubresp-cause")
                        ie_cause = IE_Cause(Cause=int(ubresp_cause), length=2)
                        update_bearer_response /= ie_cause
                        length_of_all_ies += len(ie_cause)

                        ie_bearer_context_cause = IE_Cause(Cause=int(ubresp_cause), length=2)
                        ie_bearer_id = IE_EPSBearerID(ietype='EPS Bearer ID', length=1, EBI=bearer.bearer_id)
                        bearer_context = IE_BearerContext(ietype='Bearer Context', length=11,
                                                          IE_list=[ie_bearer_id, ie_bearer_context_cause])
                        update_bearer_response /= bearer_context
                        length_of_all_ies += len(bearer_context)

                        if retloc:
                            profile = self.find_profile(session.profile_id)
                            ie_uli = GTPV2IE_ULI()
                            uli_tai = profile.get_parameter_by_name("ULI_TAI")
                            uli_ecgi = profile.get_parameter_by_name("ULI_ECGI")
                            ie_uli.set_field_value(uli_tai, uli_ecgi)
                            update_bearer_response.add_payload(ie_uli)
                            session.tai_mcc = ie_uli.TAI.MCC
                            session.tai_mnc = ie_uli.TAI.MNC
                            session.tac = ie_uli.TAI.TAC
                            session.ecgi_mcc = ie_uli.ECGI.MCC
                            session.ecgi_mnc = ie_uli.ECGI.MNC
                            session.eci = ie_uli.ECGI.ECI
                            length_of_all_ies += len(ie_uli)
                            #
                            # ie_uli_tai = ULI_TAI(MCC=session.tai_mcc, MNC=session.tai_mnc, TAC=session.tac)
                            # ie_uli_ecgi = ULI_ECGI(MCC=session.ecgi_mcc, MNC=session.ecgi_mnc, ECI=session.eci)
                            # uli = IE_ULI(ietype='ULI', length=13, LAI_Present=0, ECGI_Present=1, TAI_Present=1,
                            #              RAI_Present=0,
                            #              SAI_Present=0,
                            #              CGI_Present=0, TAI=ie_uli_tai,
                            #              ECGI=ie_uli_ecgi)
                            #
                            # update_bearer_response /= uli
                            # length_of_all_ies += len(uli)

                    setattr(update_bearer_response, "length", 8 + length_of_all_ies)
                    send_data = bytes(update_bearer_response)
                    self.sent_message_queue.put(send_data)

    def process_delete_bearer_request(self, message):
        ack_seq_number = message.seq
        session = self.find_session_by_teid(message.teid)
        if session:
            ie_bearer_id = self.find_first_ie_by_type(message, IETypeNameToCode["EPS Bearer ID"])
            if ie_bearer_id:
                bearer_id = ie_bearer_id.EBI
                bearer = session.get_bearer_by_id(bearer_id)
                delete_bearer_response = GTPHeader(length=8, gtp_type=100, T=1, teid=session.sgw_s11s4c_teid,
                                                       seq=ack_seq_number)
                self.sequence_number += 1
                length_of_all_ies = 0
                if bearer:
                    profile = self.find_profile(session.profile_id)
                    dbresp_cause = profile.get_parameter_by_name("dbresp-cause")
                    ie_cause = IE_Cause(Cause=int(dbresp_cause), length=2)
                    delete_bearer_response /= ie_cause
                    length_of_all_ies += len(ie_cause)

                    ie_bearer_context_cause = IE_Cause(Cause=int(dbresp_cause), length=2)
                    ie_bearer_id = IE_EPSBearerID(ietype='EPS Bearer ID', length=1, EBI=bearer.bearer_id)
                    bearer_context = IE_BearerContext(ietype='Bearer Context', length=11,
                                                      IE_list=[ie_bearer_id, ie_bearer_context_cause])
                    delete_bearer_response /= bearer_context
                    length_of_all_ies += len(bearer_context)
                    session.bearer_list.remove(bearer)

                setattr(delete_bearer_response, "length", 8 + length_of_all_ies)
                send_data = bytes(delete_bearer_response)
                self.sent_message_queue.put(send_data)

                if bearer_id == 5:  # if default bearer is deleted, all bearers and session should be removed
                    self.delete_session_by_teid(message.teid)

    def send_release_access_bearers_request(self, session):
        release_access_bearers_request = GTPHeader(length=8, gtp_type=170, T=1, teid=session.sgw_s11s4c_teid,
                                           seq=self.sequence_number)

        self.sequence_number += 1

        send_data = bytes(release_access_bearers_request)
        self.sent_message_queue.put(send_data)

    def process_release_access_bearers_response(self, message):
        session = self.find_session_by_teid(message.teid)
        if session:
            session.status = "ATTACHED_IDLE"

    def find_profile(self, profile_id):
        for profile in self.profile_list:
            if profile.profile_id == profile_id:
                return profile
        return None

    def create_session_group(self, group_id, profile, size):
        if not self.find_profile(profile.profile_id):
            self.profile_list.append(profile)

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

    def find_session_by_imsi(self, imsi):
        for session_group in self.session_group_list:
            for session in session_group.sessions:
                if session.imsi == imsi:
                    return session

    def find_session_by_teid(self, teid):
        for session_group in self.session_group_list:
            for session in session_group.sessions:
                if session.mme_s11c_f_teid == teid:
                    return session
        return None

    def delete_session_by_teid(self, teid):
        for session_group in self.session_group_list:
            for session in session_group.sessions:
                if session.mme_s11c_f_teid == teid:
                    for bearer in session.bearer_list:
                        session.bearer_list.remove(bearer)
                    session_group.sessions.remove(session)

    def show_all_session(self):
        print("-" * 90)
        print("     IMSI            APN       Type     Bearers    UE Address          Status")
        for session_group in self.session_group_list:
            for session in session_group.sessions:
                print(session)
        print("-" * 90)

    def show_session_by_imsi(self, imsi):
        session = self.find_session_by_imsi(imsi)
        if session:
            print("-"*90)
            print("     IMSI            APN       Type     Bearers    UE Address          Status")
            print(session)
            print("-"*90)

    @staticmethod
    def find_ie(message, ietype, instance=0):
        for ie in message.IE_list:
            if ie.ietype == ietype and ie.instance == instance:
                return ie

    @staticmethod
    def find_first_ie_by_type(message, ietype):
        for ie in message.IE_list:
            if ie.ietype == ietype:
                return ie

    @staticmethod
    def find_all_ie_by_type(message, ietype):
        return [ie for ie in message.IE_list if ie.ietype == ietype]


class Profile:
    def __init__(self, profile_id):
        self.profile_id = profile_id
        self.parameters_dict = OrderedDict()
        self.ie_list = []
        self.message_list = []
        self.implemented_parameter_list = []
        self.ImplementedAttributesDecoder = {"imsi": self.set_string_value,
                                             "cbresp-cause": self.set_int_value,
                                             "ubresp-cause": self.set_int_value,
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
                                             "enodeb-s1u-teid": self.set_hex_int_value,
                                             "csg-cr-support": self.set_indication_flag,
                                             "pco": self.set_ipv4_address,
                                             "mei": self.set_string_value
                                             }
        self.attribute_prefix = "attrib_"
        self.set_parameters_default_value()

    def __str__(self):
        info = "-----------------------------------------------------------------------------------------\n"
        info += "Current Attribute:\n"

        start = len(self.attribute_prefix)
        for attr in sorted(dir(self)):
            if attr.startswith(self.attribute_prefix):
                info += "    {n:30} :  {v}\n".format(n=attr[start:], v=getattr(self, attr))
        info += "-----------------------------------------------------------------------------------------"
        return info

    def get_id(self):
        return self.profile_id

    def set_parameters_default_value(self):
        self.parameters_dict["apn"] = "cmnet"
        self.parameters_dict["imsi"] = "460020100030241"
        self.parameters_dict["msisdn"] = "8618912345678"
        self.parameters_dict["mei"] = "123456789012345"
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
        self.parameters_dict["ubresp-cause"] = "16"
        self.parameters_dict["dbresp-cause"] = "16"
        self.parameters_dict["restart-counter"] = "1"
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
        # name = IEAttrNameToProfileAttrName[name]
        name = self.attribute_prefix + name
        if hasattr(self, name):
            return getattr(self, name)
        else:
            return None


class SessionGroup:
    def __init__(self, group_id, size):
        self.group_id = group_id
        self.start_imsi = ""
        self.start_msisdn = ""
        self.start_mei = ""
        self.start_mme_s11c_f_teid = 0x0
        self.start_enodeb_s1u_f_teid = 0x0
        self.current_imsi = ""
        self.current_msisdn = ""
        self.current_mei = ""
        self.current_mme_s11c_f_teid = 0x0
        self.current_enodeb_s1u_f_teid = 0x0
        self.enodeb_s1u_teid_ipv4 = "0.0.0.0"
        self.profile = None
        self.size = size
        self.sessions = []

    def set_profile(self, profile):
        self.profile = profile
        self.start_imsi = profile.get_parameter_by_name("GTPV2IE_IMSI")
        self.start_msisdn = profile.get_parameter_by_name("GTPV2IE_MSISDN")
        self.start_mei = profile.get_parameter_by_name("GTPV2IE_MEI")
        self.start_mme_s11c_f_teid = profile.get_attribute_value_by_name("mme-s11c-teid")
        self.start_enodeb_s1u_f_teid = profile.get_attribute_value_by_name("enodeb-s1u-teid")
        self.enodeb_s1u_teid_ipv4 = profile.get_attribute_value_by_name("enb-s1u-address")[0]
        self.current_imsi = self.start_imsi
        self.current_msisdn = self.start_msisdn
        self.current_mei = self.start_mei
        self.current_mme_s11c_f_teid = self.start_mme_s11c_f_teid
        self.current_enodeb_s1u_f_teid = self.start_enodeb_s1u_f_teid

    def generate_next_id(self):
        self.current_imsi = str(int(self.current_imsi) + 1)
        self.current_msisdn = str(int(self.current_msisdn) + 1)
        if len(self.current_mei) in (15, 16):
            self.current_mei = str(int(self.current_mei[:14]) + 1) + self.current_mei[14:]
        else:
            self.current_mei = str(int(self.current_mei) + 1)
        self.current_mme_s11c_f_teid += 1
        self.current_enodeb_s1u_f_teid += 9  # 9 s1u teid for each session

    def reset(self):
        self.current_imsi = self.start_imsi
        self.current_msisdn = self.start_msisdn
        self.current_mei = self.start_mei
        self.current_mme_s11c_f_teid = self.start_mme_s11c_f_teid
        self.current_enodeb_s1u_f_teid = self.start_enodeb_s1u_f_teid


class Session:
    def __init__(self, imsi):
        self.imsi = imsi
        self.msisdn = ""
        self.mei = ""
        self.tai_mcc = ""
        self.tai_mnc = ""
        self.tac = 0
        self.ecgi_mcc = ""
        self.ecgi_mnc = ""
        self.eci = 0
        self.mcc = ""
        self.mnc = ""
        self.bearer_list = []
        self.apn = ""
        self.rat_type = 0
        self.indication = 0x0000
        self.mme_s11c_f_teid = 0
        self.mme_s11c_f_teid_ipv4 = "0.0.0.0"
        self.mme_s5s8c_f_teid = 0
        self.mme_s5s8c_f_teid_ipv4 = "0.0.0.0"
        self.selection_mode = 0
        self.pdn_type = 1
        self.paa = "0.0.0.0"
        self.apn_restriction = 0
        self.ambr_uplink = 0
        self.ambr_downlink = 0
        self.pco = "0.0.0.0"
        self.cc = "0x0800"
        self.timezone = 0
        self.DST = 0
        self.status = None
        self.attach_rejected_reason = ""
        self.sgw_s11s4c_teid = 0
        self.sgw_s11s4c_teid_ipv4 = "0.0.0.0"
        self.pgw_s5s8c_teid = 0
        self.pgw_s5s8c_teid_ipv4 = "0.0.0.0"
        self.first_enodeb_s1u_teid = 0
        self.enodeb_s1u_teid_ipv4 = "0.0.0.0"
        self.profile_id = 0
        self.trigger = {
            "TAI_CHANGE": False,
            "ECGI_CHANGE": False,
            "UE_TIME_ZONE_CHANGE": False,
            "USER_CSG_INFORMATION_CHANGE": False,
            "QOS_CHANGE": False,
            "PLMN_CHANGE": False
        }

    def __eq__(self, other):
        return self.imsi == other.imsi

    def __str__(self):
        if len(self.apn) > 10:
            apn = self.apn[:10] + "*"
        else:
            apn = self.apn
        text = """{imsi:^16} {apn:^10}   {type:^5}      {bearer:2}     {address:^16} {status:^15}""".format(
            imsi=self.imsi, apn=apn, type=PDN_TYPES[self.pdn_type], bearer=len(self.bearer_list),
            address=self.paa, status=self.status)
        return text

    def get_bearer_by_id(self, bearer_id):
        for bearer in self.bearer_list:
            if bearer.bearer_id == bearer_id:
                return bearer
        return None

    def show_bearer(self):
        print("-"*90)
        print("     IMSI            APN       Bearer ID    Type    QCI/ARP        MBR/GBR")
        for bearer in self.bearer_list:
            print(bearer)
        print("-"*90)


class Bearer:
    def __init__(self, imsi, bearer_id):
        self.imsi = imsi
        self.apn = ""
        self.bearer_id = bearer_id
        self.bearer_status = "None"
        self.bearer_type = "Def"
        self.qci = 9
        self.arp = 15
        self.mbr_uplink = 0
        self.mbr_downlink = 0
        self.gbr_uplink = 0
        self.gbr_downlink = 0
        self.sgw_s1u_teid = 0
        self.sgw_s1u_teid_ipv4 = "0.0.0.0"
        self.pgw_s5s8u_teid = 0
        self.pgw_s5s8u_teid_ipv4 = "0.0.0.0"
        self.enodeb_s1u_teid = 0
        self.enodeb_s1u_teid_ipv4 = "0.0.0.0"

    def __str__(self):
        if len(self.apn) > 10:
            apn = self.apn[:10] + "*"
        else:
            apn = self.apn
        qa = str(self.qci) + '/' + str(self.arp)
        mg = str(self.mbr_downlink) + '/' + str(self.gbr_downlink)
        text = """{imsi:^16} {apn:^10}      {id:1}         {type:3}       {qa:^4}  {mg:^21}""".format(
            imsi=self.imsi, apn=apn, id=self.bearer_id, type=self.bearer_type, qa=qa, mg=mg)
        return text



