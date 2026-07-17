#!/usr/bin/env python3
#
#
#  IRIS abuseipdb Source Code
#  Copyright (C) 2026 - iris
#  Created by iris - 2026-07-17
#
#  License MIT

module_name = "AbuseIPDB Integration Module"
module_description = "Module to enrich IOCs with AbuseIPDB threat intelligence data. Provides IP reputation, abuse confidence scores, and detailed reports from the AbuseIPDB database."
interface_version = 1.1
module_version = 1.0

pipeline_support = True
pipeline_info = {
    "pipeline_internal_name": "abuseipdb_pipeline",
    "pipeline_human_name": "AbuseIPDB Enrichment Pipeline",
    "pipeline_args": [
        ['ip_address', 'required'],
        ['verbose', 'optional']
    ],
    "pipeline_update_support": True,
    "pipeline_import_support": True
}

module_configuration = [
    # === CONFIGURAÇÕES DA API ===
    {
        "param_name": "abuseipdb_api_key",
        "param_human_name": "AbuseIPDB API Key",
        "param_description": "Your AbuseIPDB API key. Obtain from https://www.abuseipdb.com/account/api",
        "default": None,
        "mandatory": True,
        "type": "sensitive_string",
        "section": "API Configuration"
    },
    {
        "param_name": "abuseipdb_base_url",
        "param_human_name": "AbuseIPDB Base URL",
        "param_description": "Base URL for AbuseIPDB API (default: https://api.abuseipdb.com/api/v2)",
        "default": "https://api.abuseipdb.com/api/v2",
        "mandatory": False,
        "type": "string",
        "section": "API Configuration"
    },
    {
        "param_name": "abuseipdb_timeout",
        "param_human_name": "API Timeout (seconds)",
        "param_description": "Timeout for API requests in seconds",
        "default": 30,
        "mandatory": False,
        "type": "integer",
        "section": "API Configuration"
    },
    {
        "param_name": "abuseipdb_max_retries",
        "param_human_name": "Max Retries",
        "param_description": "Number of retry attempts on API failure",
        "default": 3,
        "mandatory": False,
        "type": "integer",
        "section": "API Configuration"
    },

    # === PARÂMETROS DE CONSULTA ===
    {
        "param_name": "abuseipdb_max_age_days",
        "param_human_name": "Maximum Age (Days)",
        "param_description": "Maximum age of reports to consider (1-365 days). Default: 90",
        "default": 90,
        "mandatory": False,
        "type": "integer",
        "section": "Query Parameters"
    },
    {
        "param_name": "abuseipdb_min_confidence",
        "param_human_name": "Minimum Confidence Score",
        "param_description": "Minimum Abuse Confidence Score to trigger alerts (0-100). Default: 0",
        "default": 0,
        "mandatory": False,
        "type": "integer",
        "section": "Query Parameters"
    },
    {
        "param_name": "abuseipdb_verbose",
        "param_human_name": "Verbose Reporting",
        "param_description": "Include detailed report information in the response",
        "default": True,
        "mandatory": False,
        "type": "boolean",
        "section": "Query Parameters"
    },
    {
        "param_name": "abuseipdb_include_reports",
        "param_human_name": "Include Full Reports",
        "param_description": "Include full report details (comments, reporter IDs, etc.) in the attribute",
        "default": True,
        "mandatory": False,
        "type": "boolean",
        "section": "Query Parameters"
    },
    {
        "param_name": "abuseipdb_max_reports_display",
        "param_human_name": "Max Reports to Display",
        "param_description": "Maximum number of reports to show in the HTML report",
        "default": 20,
        "mandatory": False,
        "type": "integer",
        "section": "Query Parameters"
    },

    # === TRIGGERS (hooks) ===
    {
        "param_name": "abuseipdb_manual_hook_enabled",
        "param_human_name": "Manual Triggers on IOCs",
        "param_description": "Enable manual triggering of this module via the UI",
        "default": True,
        "mandatory": False,
        "type": "boolean",
        "section": "Triggers"
    },
    {
        "param_name": "abuseipdb_on_create_hook_enabled",
        "param_human_name": "Auto-Trigger on IOC Creation",
        "param_description": "Automatically enrich IOCs when they are created",
        "default": True,
        "mandatory": False,
        "type": "boolean",
        "section": "Triggers"
    },
    {
        "param_name": "abuseipdb_on_update_hook_enabled",
        "param_human_name": "Auto-Trigger on IOC Update",
        "param_description": "Automatically enrich IOCs when they are updated",
        "default": False,
        "mandatory": False,
        "type": "boolean",
        "section": "Triggers"
    },

    # === IOC TYPES TO PROCESS ===
    {
        "param_name": "abuseipdb_process_ip",
        "param_human_name": "Process IP Addresses",
        "param_description": "Enable enrichment for IP address IOCs",
        "default": True,
        "mandatory": False,
        "type": "boolean",
        "section": "IOC Types"
    },
    {
        "param_name": "abuseipdb_process_domain",
        "param_human_name": "Process Domains",
        "param_description": "Enable enrichment for domain IOCs (AbuseIPDB may have limited domain data)",
        "default": False,
        "mandatory": False,
        "type": "boolean",
        "section": "IOC Types"
    },
    {
        "param_name": "abuseipdb_process_filehash",
        "param_human_name": "Process File Hashes",
        "param_description": "Enable enrichment for file hash IOCs (AbuseIPDB does not support hashes)",
        "default": False,
        "mandatory": False,
        "type": "boolean",
        "section": "IOC Types"
    },

    # === ATTRIBUTE CONFIGURATION ===
    {
        "param_name": "abuseipdb_add_as_attribute",
        "param_human_name": "Add Report as IOC Attribute",
        "param_description": "Creates a new HTML attribute on the IOC with the AbuseIPDB report",
        "default": True,
        "mandatory": False,
        "type": "boolean",
        "section": "Attributes"
    },
    {
        "param_name": "abuseipdb_add_summary_attribute",
        "param_human_name": "Add Summary Attribute",
        "param_description": "Add a text summary attribute with key findings (score, reports, country)",
        "default": True,
        "mandatory": False,
        "type": "boolean",
        "section": "Attributes"
    },
    {
        "param_name": "abuseipdb_add_tags",
        "param_human_name": "Add Tags to IOC",
        "param_description": "Automatically add tags based on Abuse Confidence Score (High/Medium/Low Risk)",
        "default": True,
        "mandatory": False,
        "type": "boolean",
        "section": "Attributes"
    },
    {
        "param_name": "abuseipdb_tag_prefix",
        "param_human_name": "Tag Prefix",
        "param_description": "Prefix for auto-generated tags (e.g., 'AbuseIPDB:' creates 'AbuseIPDB:HighRisk')",
        "default": "AbuseIPDB:",
        "mandatory": False,
        "type": "string",
        "section": "Attributes"
    },

    # === TEMPLATES ===
    {
        "param_name": "abuseipdb_ioc_report_template",
        "param_human_name": "HTML Report Template",
        "param_description": "HTML template for the AbuseIPDB report attribute. Uses Jinja2 templating.",
        "default": """<div class="container">
    <div class="card">
        <div class="card-header bg-primary text-white">
            <h3>AbuseIPDB Report - {{ ip_address }}</h3>
        </div>
        <div class="card-body">
            <div class="row">
                <div class="col-md-6">
                    <h5>Abuse Confidence Score</h5>
                    <div class="progress">
                        <div class="progress-bar {% if abuse_confidence_score >= 80 %}bg-danger{% elif abuse_confidence_score >= 50 %}bg-warning{% else %}bg-success{% endif %}" 
                             role="progressbar" 
                             style="width: {{ abuse_confidence_score }}%;" 
                             aria-valuenow="{{ abuse_confidence_score }}" 
                             aria-valuemin="0" 
                             aria-valuemax="100">
                            {{ abuse_confidence_score }}%
                        </div>
                    </div>
                    <br>
                    <table class="table table-bordered">
                        <tr><td><strong>IP Address</strong></td><td>{{ ip_address }}</td></tr>
                        <tr><td><strong>Country</strong></td><td>{{ country_name }} ({{ country_code }})</td></tr>
                        <tr><td><strong>ISP</strong></td><td>{{ isp }}</td></tr>
                        <tr><td><strong>Domain</strong></td><td>{{ domain }}</td></tr>
                        <tr><td><strong>Total Reports</strong></td><td>{{ total_reports }}</td></tr>
                        <tr><td><strong>Distinct Users</strong></td><td>{{ num_distinct_users }}</td></tr>
                        <tr><td><strong>Last Reported</strong></td><td>{{ last_reported_at }}</td></tr>
                    </table>
                </div>
                <div class="col-md-6">
                    <h5>Recent Reports</h5>
                    <div class="list-group">
                        {% for report in reports[:max_reports_display] %}
                        <div class="list-group-item">
                            <p><strong>Categories:</strong> {{ report.categories|join(', ') }}</p>
                            <p><strong>Comment:</strong> {{ report.comment or 'N/A' }}</p>
                            <p><strong>Reported:</strong> {{ report.reportedAt }}</p>
                            <p><strong>Reporter:</strong> {{ report.reporterId or 'Anonymous' }}</p>
                        </div>
                        {% endfor %}
                        {% if reports|length > max_reports_display %}
                        <div class="alert alert-info">Showing {{ max_reports_display }} of {{ reports|length }} reports</div>
                        {% endif %}
                    </div>
                </div>
            </div>
        </div>
        <div class="card-footer">
            <small>Data from <a href="https://www.abuseipdb.com/check/{{ ip_address }}" target="_blank">AbuseIPDB</a></small>
        </div>
    </div>
</div>""",
        "mandatory": False,
        "type": "textfield_html",
        "section": "Templates"
    },
    {
        "param_name": "abuseipdb_summary_template",
        "param_human_name": "Summary Template",
        "param_description": "Template for the text summary attribute. Use {{ variables }} for placeholders.",
        "default": """AbuseIPDB Report for {{ ip_address }}:
- Abuse Confidence Score: {{ abuse_confidence_score }}%
- Total Reports: {{ total_reports }}
- Country: {{ country_name }} ({{ country_code }})
- ISP: {{ isp }}
- Last Reported: {{ last_reported_at }}
- Risk Level: {% if abuse_confidence_score >= 80 %}HIGH RISK{% elif abuse_confidence_score >= 50 %}MEDIUM RISK{% else %}LOW RISK{% endif %}""",
        "mandatory": False,
        "type": "textfield",
        "section": "Templates"
    },

    # === LOGGING AND DEBUG ===
    {
        "param_name": "abuseipdb_debug_mode",
        "param_human_name": "Debug Mode",
        "param_description": "Enable debug logging for troubleshooting",
        "default": False,
        "mandatory": False,
        "type": "boolean",
        "section": "Debug"
    },
    {
        "param_name": "abuseipdb_log_requests",
        "param_human_name": "Log API Requests",
        "param_description": "Log API request and response details (may contain sensitive data)",
        "default": False,
        "mandatory": False,
        "type": "boolean",
        "section": "Debug"
    }
]
