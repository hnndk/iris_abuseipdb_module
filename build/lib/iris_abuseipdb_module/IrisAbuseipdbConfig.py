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
module_description = "Enrich IP and Domain IOCs with AbuseIPDB threat intelligence"
interface_version = 1.1
module_version = 1.0

pipeline_support = False
pipeline_info = {}


module_configuration = [
    {
        "param_name": "abuseipdb_url",
        "param_human_name": "AbuseIPDB URL",
        "param_description": "Base URL for AbuseIPDB API (default: https://api.abuseipdb.com/api/v2)",
        "default": "https://api.abuseipdb.com/api/v2",
        "mandatory": True,
        "type": "string"
    },
    {
        "param_name": "abuseipdb_key",
        "param_human_name": "AbuseIPDB API Key",
        "param_description": "Your AbuseIPDB API key",
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
        "param_description": "Set to True to automatically add a AbuseIPDB insight each time an IOC is created",
        "default": False,
        "mandatory": True,
        "type": "bool",
        "section": "Triggers"
    },
    {
        "param_name": "abuseipdb_on_update_hook_enabled",
        "param_human_name": "Triggers automatically on IOC update",
        "param_description": "Set to True to automatically add a AbuseIPDB insight each time an IOC is updated",
        "default": False,
        "mandatory": True,
        "type": "bool",
        "section": "Triggers"
    },
    {
        "param_name": "abuseipdb_report_as_attribute",
        "param_human_name": "Add AbuseIPDB report as new IOC attribute",
        "param_description": "Creates a new attribute on the IOC, based on the AbuseIPDB report",
        "default": True,
        "mandatory": True,
        "type": "bool",
        "section": "Insights"
    },
    {
        "param_name": "abuseipdb_ip_report_template",
        "param_human_name": "IP report template",
        "param_description": "Template used to display AbuseIPDB results for IP addresses",
        "default": """<div class="row">
    <div class="col-12">
        <div class="accordion">
            <h3>AbuseIPDB Results</h3>
            <div class="card">
                <div class="card-header collapsed" id="drop_r_abuseipdb" data-toggle="collapse" data-target="#drop_raw_abuseipdb" aria-expanded="false" aria-controls="drop_raw_abuseipdb" role="button">
                    <div class="span-icon">
                        <div class="flaticon-file"></div>
                    </div>
                    <div class="span-title">AbuseIPDB Raw Results</div>
                    <div class="span-mode"></div>
                </div>
                <div id="drop_raw_abuseipdb" class="collapse" aria-labelledby="drop_r_abuseipdb">
                    <div class="card-body">
                        <div id="abuseipdb_raw_ace">{{ results|tojson(indent=4) }}</div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
<script>
var abuseipdb_in_raw = ace.edit("abuseipdb_raw_ace", {
    autoScrollEditorIntoView: true,
    minLines: 30,
});
abuseipdb_in_raw.setReadOnly(true);
abuseipdb_in_raw.setTheme("ace/theme/tomorrow");
abuseipdb_in_raw.session.setMode("ace/mode/json");
abuseipdb_in_raw.renderer.setShowGutter(true);
abuseipdb_in_raw.setOption("showLineNumbers", true);
abuseipdb_in_raw.setOption("showPrintMargin", false);
abuseipdb_in_raw.setOption("displayIndentGuides", true);
abuseipdb_in_raw.setOption("maxLines", "Infinity");
abuseipdb_in_raw.session.setUseWrapMode(true);
abuseipdb_in_raw.setOption("indentedSoftWrap", true);
abuseipdb_in_raw.renderer.setScrollMargin(8, 5);
</script>""",
        "mandatory": False,
        "type": "textfield_html",
        "section": "Templates"
    },
    {
        "param_name": "abuseipdb_domain_report_template",
        "param_human_name": "Domain report template",
        "param_description": "Template used to display AbuseIPDB results for domains (note: limited support)",
        "default": """<div class="row">
    <div class="col-12">
        <div class="accordion">
            <h3>AbuseIPDB Results (Domain)</h3>
            <div class="card">
                <div class="card-header collapsed" id="drop_r_abuseipdb_domain" data-toggle="collapse" data-target="#drop_raw_abuseipdb_domain" aria-expanded="false" aria-controls="drop_raw_abuseipdb_domain" role="button">
                    <div class="span-icon">
                        <div class="flaticon-file"></div>
                    </div>
                    <div class="span-title">AbuseIPDB Raw Results</div>
                    <div class="span-mode"></div>
                </div>
                <div id="drop_raw_abuseipdb_domain" class="collapse" aria-labelledby="drop_r_abuseipdb_domain">
                    <div class="card-body">
                        <div id="abuseipdb_domain_raw_ace">{{ results|tojson(indent=4) }}</div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
<script>
var abuseipdb_domain_raw = ace.edit("abuseipdb_domain_raw_ace", {
    autoScrollEditorIntoView: true,
    minLines: 30,
});
abuseipdb_domain_raw.setReadOnly(true);
abuseipdb_domain_raw.setTheme("ace/theme/tomorrow");
abuseipdb_domain_raw.session.setMode("ace/mode/json");
abuseipdb_domain_raw.renderer.setShowGutter(true);
abuseipdb_domain_raw.setOption("showLineNumbers", true);
abuseipdb_domain_raw.setOption("showPrintMargin", false);
abuseipdb_domain_raw.setOption("displayIndentGuides", true);
abuseipdb_domain_raw.setOption("maxLines", "Infinity");
abuseipdb_domain_raw.session.setUseWrapMode(true);
abuseipdb_domain_raw.setOption("indentedSoftWrap", true);
abuseipdb_domain_raw.renderer.setScrollMargin(8, 5);
</script>""",
        "mandatory": False,
        "type": "textfield_html",
        "section": "Templates"
    }
]