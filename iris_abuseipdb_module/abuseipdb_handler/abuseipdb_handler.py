#!/usr/bin/env python3
#
#
#  IRIS abuseipdb Source Code
#  Copyright (C) 2026 - cyber
#  hello@cyber.com
#  Created by cyber - 2026-07-20
#
#  License MIT


import traceback
import json
import requests
import re
from urllib.parse import urlparse
from jinja2 import Template

import iris_interface.IrisInterfaceStatus as InterfaceStatus
from app.datamgmt.manage.manage_attribute_db import add_tab_attribute_field


class AbuseipdbHandler(object):
    def __init__(self, mod_config, server_config, logger):
        self.mod_config = mod_config
        self.server_config = server_config
        self.log = logger
        self.base_url = self.mod_config.get('abuseipdb_url', 'https://api.abuseipdb.com/api/v2')
        self.api_key = self.mod_config.get('abuseipdb_key')
        self.session = self._create_session()

    def _create_session(self):
        """
        Create a requests session with proxy configuration
        """
        session = requests.Session()
        session.headers.update({
            'Key': self.api_key,
            'Accept': 'application/json'
        })
        
        proxies = {}
        if self.server_config.get('http_proxy'):
            proxies['http'] = self.server_config.get('http_proxy')
        if self.server_config.get('https_proxy'):
            proxies['https'] = self.server_config.get('https_proxy')
        
        if proxies:
            session.proxies.update(proxies)
        
        return session

    def _make_request(self, endpoint, params):
        """
        Make a request to AbuseIPDB API
        
        :param endpoint: API endpoint (e.g., '/check')
        :param params: Query parameters
        :return: JSON response or None on error
        """
        url = f"{self.base_url}{endpoint}"
        
        try:
            self.log.info(f"Making request to {url} with params {params}")
            response = self.session.get(url, params=params, timeout=30)
            
            if response.status_code == 200:
                return response.json()
            else:
                self.log.error(f"AbuseIPDB API error: {response.status_code} - {response.text}")
                return None
                
        except requests.exceptions.RequestException as e:
            self.log.error(f"Request error: {str(e)}")
            return None

    def _is_ip_address(self, value):
        """
        Check if a string is a valid IPv4 or IPv6 address
        """
        # IPv4
        ipv4_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        if ipv4_pattern.match(value):
            octets = value.split('.')
            for octet in octets:
                if int(octet) < 0 or int(octet) > 255:
                    return False
            return True
        
        # IPv6 (simplified)
        ipv6_pattern = re.compile(r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,7}:$|^::$')
        return bool(ipv6_pattern.match(value))

    def _extract_domain_from_url(self, url):
        """
        Extract domain from URL
        """
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            if not domain:
                # Try without scheme
                parsed = urlparse(f"//{url}")
                domain = parsed.netloc
            return domain
        except:
            return None

    def gen_report_from_template(self, html_template, abuseipdb_report):
        """
        Generates an HTML report displayed as an attribute in the IOC
        
        :param html_template: A string representing the HTML template
        :param abuseipdb_report: The JSON report from AbuseIPDB API
        :return: Rendered HTML string or None on error
        """
        if not html_template:
            self.log.error("HTML template is empty")
            return None
        
        # Prepare context for template
        context = {"results": abuseipdb_report}
        
        try:
            # Try to render with Jinja2
            template = Template(html_template)
            rendered = template.render(context)
            return rendered
            
        except Exception as e:
            self.log.error(f"Template rendering error: {str(e)}")
            self.log.error(traceback.format_exc())
            
            # Fallback: try to render manually if Jinja2 fails
            try:
                if '{{ results|tojson(indent=4) }}' in html_template:
                    json_data = json.dumps(abuseipdb_report, indent=4)
                    rendered = html_template.replace('{{ results|tojson(indent=4) }}', json_data)
                    return rendered
            except:
                pass
            
            return None

    def handle_ip(self, ioc):
        """
        Handle an IOC of type IP address and add AbuseIPDB insights
        
        :param ioc: IOC instance
        :return: IIStatus
        """
        self.log.info(f'Getting IP report for {ioc.ioc_value}')
        
        # Check if it's a valid IP
        if not self._is_ip_address(ioc.ioc_value):
            self.log.error(f'Invalid IP address: {ioc.ioc_value}')
            return InterfaceStatus.I2Error(f'Invalid IP address: {ioc.ioc_value}')
        
        # Make API request to /check endpoint
        params = {
            'ipAddress': ioc.ioc_value,
            'maxAgeInDays': '90',
            'verbose': 'true'
        }
        
        response = self._make_request('/check', params)
        
        if not response:
            self.log.error(f'Failed to get AbuseIPDB data for {ioc.ioc_value}')
            return InterfaceStatus.I2Error(f'Failed to get AbuseIPDB data')
        
        # Check if there's data
        if 'data' not in response:
            self.log.warning(f'No data found for IP {ioc.ioc_value}')
            response = {'data': {'ipAddress': ioc.ioc_value, 'abuseConfidenceScore': 0, 'totalReports': 0}}
        
        report_data = response.get('data', {})
        
        # Add attribute if enabled
        if self.mod_config.get('abuseipdb_report_as_attribute') is True:
            self.log.info('Adding new attribute AbuseIPDB Report to IOC')
            
            rendered_report = self.gen_report_from_template(
                self.mod_config.get('abuseipdb_ip_report_template'), 
                report_data
            )
            
            if not rendered_report:
                self.log.error('Failed to render template')
                return InterfaceStatus.I2Error('Failed to render template')
            
            try:
                add_tab_attribute_field(
                    ioc, 
                    tab_name='AbuseIPDB Report', 
                    field_name="IP Report", 
                    field_type="html",
                    field_value=rendered_report
                )
                self.log.info('Successfully added AbuseIPDB report attribute')
                
            except Exception as e:
                self.log.error(f'Error adding attribute: {str(e)}')
                self.log.error(traceback.format_exc())
                return InterfaceStatus.I2Error(traceback.format_exc())
        else:
            self.log.info('Skipped adding attribute report. Option disabled')
        
        return InterfaceStatus.I2Success()

    def handle_domain(self, ioc):
        """
        Handles an IOC of type domain and adds AbuseIPDB insights
        
        :param ioc: IOC instance
        :return: IIStatus
        """
        self.log.info(f'Getting domain report for {ioc.ioc_value}')
        
        # Extract domain if it's a URL
        ioc_value = ioc.ioc_value
        if ioc_value.startswith(('http://', 'https://')):
            domain = self._extract_domain_from_url(ioc_value)
            if domain:
                ioc_value = domain
                self.log.info(f'Extracted domain from URL: {ioc_value}')
        
        # Try to get IP from domain (for AbuseIPDB we need IP)
        # First try to resolve domain to IP
        try:
            import socket
            ip_address = socket.gethostbyname(ioc_value)
            self.log.info(f'Resolved {ioc_value} to {ip_address}')
        except:
            self.log.warning(f'Could not resolve domain {ioc_value} to IP')
            # Return a default response
            report_data = {
                'domain': ioc_value,
                'ipAddress': 'Unknown',
                'abuseConfidenceScore': 0,
                'totalReports': 0,
                'message': 'Domain could not be resolved to an IP address'
            }
            
            if self.mod_config.get('abuseipdb_report_as_attribute') is True:
                rendered_report = self.gen_report_from_template(
                    self.mod_config.get('abuseipdb_domain_report_template'), 
                    report_data
                )
                
                if rendered_report:
                    try:
                        add_tab_attribute_field(
                            ioc, 
                            tab_name='AbuseIPDB Report', 
                            field_name="Domain Report", 
                            field_type="html",
                            field_value=rendered_report
                        )
                    except Exception as e:
                        self.log.error(f'Error adding attribute: {str(e)}')
                        return InterfaceStatus.I2Error(traceback.format_exc())
            
            return InterfaceStatus.I2Success()
        
        # Now query AbuseIPDB with the resolved IP
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': '90',
            'verbose': 'true'
        }
        
        response = self._make_request('/check', params)
        
        if not response:
            self.log.error(f'Failed to get AbuseIPDB data for {ioc.ioc_value}')
            return InterfaceStatus.I2Error(f'Failed to get AbuseIPDB data')
        
        # Add domain info to the report
        report_data = response.get('data', {})
        report_data['domain'] = ioc_value
        report_data['resolved_ip'] = ip_address
        
        # Add attribute if enabled
        if self.mod_config.get('abuseipdb_report_as_attribute') is True:
            self.log.info('Adding new attribute AbuseIPDB Domain Report to IOC')
            
            rendered_report = self.gen_report_from_template(
                self.mod_config.get('abuseipdb_domain_report_template'), 
                report_data
            )
            
            if not rendered_report:
                self.log.error('Failed to render template')
                return InterfaceStatus.I2Error('Failed to render template')
            
            try:
                add_tab_attribute_field(
                    ioc, 
                    tab_name='AbuseIPDB Report', 
                    field_name="Domain Report", 
                    field_type="html",
                    field_value=rendered_report
                )
                self.log.info('Successfully added AbuseIPDB domain report attribute')
                
            except Exception as e:
                self.log.error(f'Error adding attribute: {str(e)}')
                self.log.error(traceback.format_exc())
                return InterfaceStatus.I2Error(traceback.format_exc())
        else:
            self.log.info('Skipped adding attribute report. Option disabled')
        
        return InterfaceStatus.I2Success()