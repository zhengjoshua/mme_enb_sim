from collections import OrderedDict
IE_dict = {
    "IMSI": {
        "ietype": "IMSI",
        "class": "IE_IMSI",
        "length": 8,
        "instance": 0,
        "IMSI": "460020100030241"
    },
    "MSISDN": {
        "ietype": "MSISDN",
        "class": "IE_MSISDN",
        "length": 7,
        "instance": 0,
        "digits": "8618912345678"
    }
}

GTPV2Message_dict = {
    "create_session_req":
    [
        "IMSI",
        "MSISDN",
        "ULI"
    ]
}