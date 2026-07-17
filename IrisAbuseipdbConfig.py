#!/usr/bin/env python3
#
#
#  IRIS abuseipdb Source Code
#  Copyright (C) 2026 - iris
#  andre.c.carvalhais@aubay.pt
#  Created by iris - 2026-07-17
#
#  License MIT

module_name = "IrisAbuseipdb"
module_description = ""
interface_version = 1.1
module_version = 1.0

pipeline_support = True
pipeline_info = {
    "pipeline_internal_name": "abuseipdb_pipeline",
    "pipeline_human_name": "abuseipdb Pipeline",
    "pipeline_args": [
        ['abuseipdb_arg', 'optional']
    ],
    "pipeline_update_support": True,
    "pipeline_import_support": True
}


module_configuration = [
    {
        "param_name": "abuseipdb_url",
        "param_human_name": "abuseipdb URL",
        "param_description": "",
        "default": None,
        "mandatory": True,
        "type": "string"
    },
    {
        "param_name": "abuseipdb_key",
        "param_human_name": "abuseipdb key",
        "param_description": "abuseipdb API key",
        "default": None,
        "mandatory": True,
        "type": "sensitive_string"
    },
    
]