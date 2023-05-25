
import logging


def makerules():
    data = [
        {
            "name": "expire",
            "iszone": True
        },
        {
            "name": "retry",
            "iszone": True
        },
        {
            "name": "refresh",
            "iszone": True
        },
        {
            "name": "master",
            "iszone": True
        },
        {
            "name": "TSIG-key",
            "iszone": True
        }
    ]
    return data