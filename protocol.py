from gtp_v2 import *
from collections import OrderedDict

CauseNameToValue = {
    "Request Accepted": 16,
}

IETypeNameToCode = {
    "IMSI": 1,
    "Cause": 2,
    "Recovery Restart": 3,
    "APN": 71,
    "AMBR": 72,
    "EPS Bearer ID": 73,
    "IPv4": 74,
    "MEI": 75,
    "MSISDN": 76,
    "Indication": 77,
    "Protocol Configuration Options": 78,
    "PAA": 79,
    "Bearer QoS": 80,
    "RAT": 82,
    "Serving Network": 83,
    "ULI": 86,
    "F-TEID": 87,
    "Bearer Context": 93,
    "Charging ID": 94,
    "Charging Characteristics": 95,
    "PDN Type": 99,
    "UE Time zone": 114,
    "Port Number": 126,
    "APN Restriction": 127,
    "Selection Mode": 128,
    "Node Features": 152,
    "Max MBR/APN-AMBR (MMBR)": 161
}

GTPV2MessageOptionalIEdict = {
    "echo_request":
    ["GTPV2IE_RecoveryRestart"],

    "create_session_req":
    [
        "GTPV2IE_IMSI",
        "GTPV2IE_MSISDN",
        "GTPV2IE_ULI",
        "GTPV2IE_ServingNetwork",
        "GTPV2IE_RAT",
        # "GTPV2IE_Indication",
        "GTPV2IE_FTEID-S11",
        "GTPV2IE_FTEID-S5S8",
        "GTPV2IE_APN",
        "GTPV2IE_SelectionMode",
        "GTPV2IE_PDN_type",
        "GTPV2IE_PAA",
        "GTPV2IE_APN_Restriction",
        "GTPV2IE_AMBR",
        "GTPV2IE_PCO",
        "GTPV2IE_BearerContext",
        "GTPV2IE_ChargingCharacteristics"
    ]
}


class GTPV2IE_RecoveryRestart(IE_RecoveryRestart):
    def __init__(self):
        super(IE_RecoveryRestart, self).__init__()

    def set_field_value(self, *parameter):
        self.restart_counter = int(parameter[0])
        self.length = 1


class GTPV2IE_IMSI(IE_IMSI):
    def __init__(self):
        super(IE_IMSI, self).__init__()

    def set_field_value(self, *parameter):
        self.IMSI = parameter[0]
        if len(self.IMSI) % 2 == 1:
            self.length = len(self.IMSI) // 2 + 1
        else:
            self.length = len(self.IMSI) // 2

class GTPV2IE_MSISDN(IE_MSISDN):
    def __init__(self):
        super(IE_MSISDN, self).__init__()

    def set_field_value(self, *parameter):
        self.MSISDN = parameter[0]
        if len(self.MSISDN) % 2 == 1:
            self.length = len(self.MSISDN) // 2 + 1
        else:
            self.length = len(self.MSISDN) // 2


class GTPV2IE_MEI(IE_MEI):
    def __init__(self):
        super(IE_MEI, self).__init__()

    def set_field_value(self, *parameter):
        self.MEI = parameter[0]
        if len(self.MEI) % 2 == 1:
            self.length = len(self.MEI) // 2 + 1
        else:
            self.length = len(self.MEI) // 2


class GTPV2IE_ULI(IE_ULI):
    def __init__(self):
        super(IE_ULI, self).__init__()

    def set_field_value(self, *parameter):
        self.TAI_Present = True
        mcc_mnc, tac = parameter[0].split(',')
        mcc = mcc_mnc[:3]
        mnc = mcc_mnc[3:]
        tai = ULI_TAI(MCC=mcc, MNC=mnc, TAC=eval(tac))
        self.TAI = tai

        self.ECGI_Present = True
        mcc_mnc, tac = parameter[1].split(',')
        mcc = mcc_mnc[:3]
        mnc = mcc_mnc[3:]
        ecgi = ULI_ECGI(MCC=mcc, MNC=mnc, ECI=eval(tac))
        self.ECGI = ecgi

        length = 1
        if self.TAI_Present:
            length += 5
        if self.ECGI_Present:
            length += 7
        self.length = length


class GTPV2IE_ServingNetwork(IE_ServingNetwork):
    def __init__(self):
        super(IE_ServingNetwork, self).__init__()

    def set_field_value(self, *parameter):
        mcc = parameter[0][:3]
        mnc = parameter[0][3:]
        self.MCC = mcc
        self.MNC = mnc
        self.length = 3


class GTPV2IE_RAT(IE_RAT):
    def __init__(self):
        super(IE_RAT, self).__init__()

    def set_field_value(self, *parameter):
        self.RAT_type = int(parameter[0])
        self.length = 1


class GTPV2IE_Indication(IE_Indication):
    def __init__(self):
        super(IE_Indication, self).__init__()

    def set_field_value(self, *parameter):
        indication_length = len(parameter[0])
        indication = int(parameter[0], 16)
        if indication_length == 8:
            self.length = 3
            self.CCRSI = int(bool(indication & 0x00001))
            self.ISRAU = int(bool(indication & 0x000002))
            self.MBMDT = int(bool(indication & 0x000004))
            self.S4AF = int(bool(indication & 0x000008))
            self.S6AF = int(bool(indication & 0x000010))
            self.SRNI = int(bool(indication & 0x000020))
            self.PBIC = int(bool(indication & 0x000040))
            self.RetLoc = int(bool(indication & 0x000080))
            self.MSV = int(bool(indication & 0x000100))
            self.SI = int(bool(indication & 0x000200))
            self.PT = int(bool(indication & 0x000400))
            self.PS = int(bool(indication & 0x000800))
            self.CRSI = int(bool(indication & 0x001000))
            self.CFSI = int(bool(indication & 0x002000))
            self.UIMSI = int(bool(indication & 0x004000))
            self.SQCI = int(bool(indication & 0x008000))
            self.SGWCI = int(bool(indication & 0x010000))
            self.ISRAI = int(bool(indication & 0x020000))
            self.ISRSI = int(bool(indication & 0x040000))
            self.OI = int(bool(indication & 0x080000))
            self.DFI = int(bool(indication & 0x100000))
            self.HI = int(bool(indication & 0x200000))
            self.DTF = int(bool(indication & 0x400000))
            self.DAF = int(bool(indication & 0x800000))
        elif indication_length == 6:
            self.length = 2
            self.MSV = int(bool(indication & 0x0001))
            self.SI = int(bool(indication & 0x0002))
            self.PT = int(bool(indication & 0x0004))
            self.PS = int(bool(indication & 0x0008))
            self.CRSI = int(bool(indication & 0x0010))
            self.CFSI = int(bool(indication & 0x0020))
            self.UIMSI = int(bool(indication & 0x0040))
            self.SQCI = int(bool(indication & 0x0080))
            self.SGWCI = int(bool(indication & 0x0100))
            self.ISRAI = int(bool(indication & 0x0200))
            self.ISRSI = int(bool(indication & 0x0400))
            self.OI = int(bool(indication & 0x0800))
            self.DFI = int(bool(indication & 0x1000))
            self.HI = int(bool(indication & 0x2000))
            self.DTF = int(bool(indication & 0x4000))
            self.DAF = int(bool(indication & 0x8000))
        else:
            pass


class GTPV2IE_FTEID(IE_FTEID):
    def __init__(self):
        super(IE_FTEID, self).__init__()

    def set_field_value(self, *parameter):
        self.ipv4_present = 1
        self.instance = parameter[0]
        self.GRE_Key = parameter[1]
        self.InterfaceType = int(parameter[2])
        self.ipv4 = parameter[3]
        self.length = 9


class GTPV2IE_APN(IE_APN):
    def __init__(self):
        super(IE_APN, self).__init__()

    def set_field_value(self, *parameter):
        apn = parameter[0].strip('.')
        self.APN = apn
        self.length = len(apn) + 1


class GTPV2IE_SelectionMode(IE_SelectionMode):
    def __init__(self):
        super(IE_SelectionMode, self).__init__()

    def set_field_value(self, *parameter):
        self.SelectionMode = int(parameter[0])
        self.length = 1


class GTPV2IE_PDN_type(IE_PDN_type):
    def __init__(self):
        super(IE_PDN_type, self).__init__()

    def set_field_value(self, *parameter):
        if int(parameter[0]) == 4:
            self.PDN_type = 1
        elif int(parameter[0]) == 6:
            self.PDN_type = 2
        else:
            self.PDN_type = int(parameter[0])

        self.length = 1


class GTPV2IE_PAA(IE_PAA):
    def __init__(self):
        super(IE_PAA, self).__init__()

    def set_field_value(self, *parameter):
        self.PDN_type = int(parameter[0])
        if self.PDN_type == 1:
            self.ipv4 = parameter[1]
            self.length = 5
        elif self.PDN_type == 2:
            self.ipv6_prefix_length = 0
            self.ipv6 = parameter[1]
            self.length = 18
        else:
            pass


class GTPV2IE_APN_Restriction(IE_APN_Restriction):
    def __init__(self):
        super(IE_APN_Restriction, self).__init__()

    def set_field_value(self, *parameter):
        self.APN_Restriction = int(parameter[0])
        self.length = 1


class GTPV2IE_AMBR(IE_AMBR):
    def __init__(self):
        super(IE_AMBR, self).__init__()

    def set_field_value(self, *parameter):
        AMBR_Uplink_Downlink = parameter[0].split(',')
        AMBR_Uplink = AMBR_Uplink_Downlink[0]
        AMBR_Downlink = AMBR_Uplink_Downlink[1]
        self.AMBR_Uplink = int(AMBR_Uplink)
        self.AMBR_Downlink = int(AMBR_Downlink)
        self.length = 8


class GTPV2IE_PCO(IE_PCO):
    def __init__(self):
        super(IE_PCO, self).__init__()

    def set_field_value(self, *parameter):
        pco_primary_dns = PCO_Primary_DNS(type='Primary DNS Server IP address', length=6, address=parameter[0])
        pco_ipcp = PCO_IPCP(type='IPCP', length=10, PPP=PCO_PPP(Code=1, Identifier=68, length=10, Options=[pco_primary_dns]))
        self.Extension = 1
        self.PPP = 0
        self.Protocols = [pco_ipcp]
        self.length = 14


class GTPV2IE_BearerContext(IE_BearerContext):
    def __init__(self):
        super(IE_BearerContext, self).__init__()

    def set_field_value(self, *parameters):
        parameters_list = [int(x) for x in parameters[0].split(',')]
        bearer_id, arp, qci, mbr_uplink, mbr_downlink, gbr_uplink, gbr_downlink = parameters_list

        bearer_qos = IE_Bearer_QoS(ietype='Bearer QoS', length=22, PCI=0, PriorityLevel=arp, PVI=0, QCI=qci,
                                   MaxBitRateForUplink=mbr_uplink, MaxBitRateForDownlink=mbr_downlink,
                                   GuaranteedBitRateForUplink=gbr_uplink, GuaranteedBitRateForDownlink=gbr_downlink)
        ie_list = [IE_EPSBearerID(ietype='EPS Bearer ID', length=1, EBI=5), bearer_qos]
        self.IE_list = ie_list
        self.length = 31


class GTPV2IE_UE_Timezone(IE_UE_Timezone):
    def __init__(self):
        super(IE_UE_Timezone, self).__init__()

    def set_field_value(self, *parameter):
        timezone, dst = parameter[0].split(',')
        self.Timezone = int(timezone)
        self.DST = int(dst)


class GTPV2IE_ChargingCharacteristics(IE_ChargingCharacteristics):
    def __init__(self):
        super(IE_ChargingCharacteristics, self).__init__()

    def set_field_value(self, *parameter):
        self.ChargingCharacteristric = eval(parameter[0])
        self.length = 2

# imsi = IE_IMSI(ietype='IMSI', length=8, IMSI=self.profile.get_parameter_value("imsi"))
# msisdn = IE_MSISDN(ietype='MSISDN', length=7, MSISDN=self.profile.get_parameter_value("msisdn"))
# uli = IE_ULI(ietype='ULI', length=13, LAI_Present=0, ECGI_Present=1, TAI_Present=1, RAI_Present=0,
#              SAI_Present=0,
#              CGI_Present=0, TAI=ULI_TAI(MCC='460', MNC='02', TAC=12345),
#        ECGI=ULI_ECGI(MCC='460', MNC='02', ECI=123456))
# serving_network = IE_ServingNetwork(ietype='Serving Network', length=3, MCC='460', MNC='02')
# rat = IE_RAT(ietype='RAT', length=1, RAT_type='EUTRAN')
# fteid_s11c = IE_FTEID(ietype='F-TEID', length=9, ipv4_present=1, InterfaceType=10, GRE_Key=0x1092,
#                       ipv4='172.86.40.130')
# fteid_s5s8c = IE_FTEID(ietype='F-TEID', length=9, ipv4_present=1, instance=1, InterfaceType=7, GRE_Key=0x0,
#                       ipv4='172.21.30.99')
# apn = IE_APN(ietype='APN', length=14, APN='cmnet.lab.com')
# selection_mode = IE_SelectionMode(ietype='Selection Mode', length=1, SelectionMode=0)
# pdn_type = IE_PDN_type(ietype='PDN Type', length=1, PDN_type='IPv4')
# paa = IE_PAA(ietype='PAA', length=5, PDN_type='IPv4', ipv4='0.0.0.0')
# apn_restriction = IE_APN_Restriction(ietype='APN Restriction', length=1, APN_Restriction=0)
# ambr = IE_AMBR(ietype='AMBR', length=8, AMBR_Uplink=5000, AMBR_Downlink=5000)
# pco = IE_PCO(ietype='Protocol Configuration Options', length=14, Extension=1, PPP=0, Protocols=[
#     PCO_IPCP(type='IPCP', length=10, PPP=PCO_PPP(Code=1, Identifier=68, length=10, Options=[
#         PCO_Primary_DNS(type='Primary DNS Server IP address', length=6, address='0.0.0.0')]))])
# bearer_qos = IE_Bearer_QoS(ietype='Bearer QoS', length=22, PCI=0, PriorityLevel=15, PVI=0, QCI=9,
#                            MaxBitRateForUplink=1000, MaxBitRateForDownlink=1000,
#                            GuaranteedBitRateForUplink=1000, GuaranteedBitRateForDownlink=1000)
# bearer_context = IE_BearerContext(ietype='Bearer Context', length=31,
#                                   IE_list=[IE_EPSBearerID(ietype='EPS Bearer ID', length=1, EBI=5), bearer_qos])
# cc = IE_ChargingCharacteristics(ietype='Charging Characteristics', length=2, ChargingCharacteristric=0x0800)
# create_session_request = GTPHeader(version=2, T=1,
#                                    length=4 + 4 + 12 + 11 + 17 + 7 + 5 + 13 + 13 + 18 + 5 + 5 + 9 + 5 + 12 + 18 + 35 + 6,
#                                    teid=0,
#                                    gtp_type="create_session_req") / imsi / msisdn / uli / serving_network / rat / fteid_s11c / fteid_s5s8c / apn / selection_mode / pdn_type / paa / apn_restriction / ambr / pco / bearer_context / cc
# send_data = bytes(create_session_request)
# self.socket.send(send_data)
