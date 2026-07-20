#!/usr/bin/env python3
#
#
#  IRIS abuseipdb Source Code
#  Copyright (C) 2026 - cyber
#  hello@cyber.com
#  Created by cyber - 2026-07-20
#
#  License MIT

module_name = "IrisAbuseipdb"
module_description = ""
interface_version = 1.1
module_version = 1.0

pipeline_support = False
pipeline_info = {}


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
    
    {
        "param_name": "abuseipdb_manual_hook_enabled",
        "param_human_name": "Manual triggers on IOCs",
        "param_description": "Set to True to offers possibility to manually triggers the module via the UI",
        "default": True,
        "mandatory": True,
        "type": "bool",
        "section": "Triggers"
    },
    {
        "param_name": "abuseipdb_on_create_hook_enabled",
        "param_human_name": "Triggers automatically on IOC create",
        "param_description": "Set to True to automatically add a abuseipdb insight each time an IOC is created",
        "default": False,
        "mandatory": True,
        "type": "bool",
        "section": "Triggers"
    },
    {
        "param_name": "abuseipdb_on_update_hook_enabled",
        "param_human_name": "Triggers automatically on IOC update",
        "param_description": "Set to True to automatically add a abuseipdb insight each time an IOC is updated",
        "default": False,
        "mandatory": True,
        "type": "bool",
        "section": "Triggers"
    },
    {
        "param_name": "abuseipdb_report_as_attribute",
        "param_human_name": "Add abuseipdb report as new IOC attribute",
        "param_description": "Creates a new attribute on the IOC, base on the abuseipdb report. Attributes are based "
                             "on the templates of this configuration",
        "default": True,
        "mandatory": True,
        "type": "bool",
        "section": "Insights"
    },# TODO: careful here, remove backslashes from \{\{ results| tojson(indent=4) \}\}
    {
        "param_name": "abuseipdb_domain_report_template",
        "param_human_name": "Domain report template",
        "param_description": "Domain report template used to add a new custom attribute to the target IOC",
        "default": "<div class=\"row\">\n    <div class=\"col-12\">\n        <div "
                   "class=\"accordion\">\n            <h3>abuseipdb raw results</h3>\n\n           "
                   " <div class=\"card\">\n                <div class=\"card-header "
                   "collapsed\" id=\"drop_r_abuseipdb\" data-toggle=\"collapse\" "
                   "data-target=\"#drop_raw_abuseipdb\" aria-expanded=\"false\" "
                   "aria-controls=\"drop_raw_abuseipdb\" role=\"button\">\n                    <div "
                   "class=\"span-icon\">\n                        <div "
                   "class=\"flaticon-file\"></div>\n                    </div>\n              "
                   "      <div class=\"span-title\">\n                        abuseipdb raw "
                   "results\n                    </div>\n                    <div "
                   "class=\"span-mode\"></div>\n                </div>\n                <div "
                   "id=\"drop_raw_abuseipdb\" class=\"collapse\" aria-labelledby=\"drop_r_abuseipdb\" "
                   "style=\"\">\n                    <div class=\"card-body\">\n              "
                   "          <div id='abuseipdb_raw_ace'>\{\{ results| tojson(indent=4) \}\}</div>\n  "
                   "                  </div>\n                </div>\n            </div>\n    "
                   "    </div>\n    </div>\n</div> \n<script>\nvar abuseipdb_in_raw = ace.edit("
                   "\"abuseipdb_raw_ace\",\n{\n    autoScrollEditorIntoView: true,\n    minLines: "
                   "30,\n});\nabuseipdb_in_raw.setReadOnly(true);\nabuseipdb_in_raw.setTheme("
                   "\"ace/theme/tomorrow\");\nabuseipdb_in_raw.session.setMode("
                   "\"ace/mode/json\");\nabuseipdb_in_raw.renderer.setShowGutter("
                   "true);\nabuseipdb_in_raw.setOption(\"showLineNumbers\", "
                   "true);\nabuseipdb_in_raw.setOption(\"showPrintMargin\", "
                   "false);\nabuseipdb_in_raw.setOption(\"displayIndentGuides\", "
                   "true);\nabuseipdb_in_raw.setOption(\"maxLines\", "
                   "\"Infinity\");\nabuseipdb_in_raw.session.setUseWrapMode("
                   "true);\nabuseipdb_in_raw.setOption(\"indentedSoftWrap\", "
                   "true);\nabuseipdb_in_raw.renderer.setScrollMargin(8, 5);\n</script> ",
        "mandatory": False,
        "type": "textfield_html",
        "section": "Templates"
    }
    
]