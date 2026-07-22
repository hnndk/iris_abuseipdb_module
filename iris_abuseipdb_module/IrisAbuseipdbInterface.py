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
from pathlib import Path
import re

import iris_interface.IrisInterfaceStatus as InterfaceStatus
from iris_interface.IrisModuleInterface import IrisPipelineTypes, IrisModuleInterface, IrisModuleTypes

import iris_abuseipdb_module.IrisAbuseipdbConfig as interface_conf
from iris_abuseipdb_module.abuseipdb_handler.abuseipdb_handler import AbuseipdbHandler


class IrisAbuseipdbInterface(IrisModuleInterface):
    """
    Provide the interface between Iris and abuseipdbHandler
    """
    name = "IrisAbuseipdbInterface"
    _module_name = interface_conf.module_name
    _module_description = interface_conf.module_description
    _interface_version = interface_conf.interface_version
    _module_version = interface_conf.module_version
    _pipeline_support = interface_conf.pipeline_support
    _pipeline_info = interface_conf.pipeline_info
    _module_configuration = interface_conf.module_configuration
    
    _module_type = IrisModuleTypes.module_processor
    
     
    def register_hooks(self, module_id: int):
        """
        Registers all the hooks

        :param module_id: Module ID provided by IRIS
        :return: Nothing
        """
        self.module_id = module_id
        module_conf = self.module_dict_conf
        if module_conf.get('abuseipdb_on_create_hook_enabled'):
            status = self.register_to_hook(module_id, iris_hook_name='on_postload_ioc_create')
            if status.is_failure():
                self.log.error(status.get_message())
                self.log.error(status.get_data())

            else:
                self.log.info("Successfully registered on_postload_ioc_create hook")
        else:
            self.deregister_from_hook(module_id=self.module_id, iris_hook_name='on_postload_ioc_create')

        if module_conf.get('abuseipdb_on_update_hook_enabled'):
            status = self.register_to_hook(module_id, iris_hook_name='on_postload_ioc_update')
            if status.is_failure():
                self.log.error(status.get_message())
                self.log.error(status.get_data())

            else:
                self.log.info("Successfully registered on_postload_ioc_update hook")
        else:
            self.deregister_from_hook(module_id=self.module_id, iris_hook_name='on_postload_ioc_update')

        if module_conf.get('abuseipdb_manual_hook_enabled'):
            status = self.register_to_hook(module_id, iris_hook_name='on_manual_trigger_ioc',
                                           manual_hook_name='Get abuseipdb insight')
            if status.is_failure():
                self.log.error(status.get_message())
                self.log.error(status.get_data())

            else:
                self.log.info("Successfully registered on_manual_trigger_ioc hook")

        else:
            self.deregister_from_hook(module_id=self.module_id, iris_hook_name='on_manual_trigger_ioc')


    def hooks_handler(self, hook_name: str, hook_ui_name: str, data: any):
        """
        Hooks handler table. Calls corresponding methods depending on the hooks name.

        :param hook_name: Name of the hook which triggered
        :param hook_ui_name: Name of the ui hook
        :param data: Data associated with the trigger.
        :return: Data
        """

        self.log.info(f'Received {hook_name}')
        if hook_name in ['on_postload_ioc_create', 'on_postload_ioc_update', 'on_manual_trigger_ioc']:
            status = self._handle_ioc(data=data)

        else:
            self.log.critical(f'Received unsupported hook {hook_name}')
            return InterfaceStatus.I2Error(data=data, logs=list(self.message_queue))

        if status.is_failure():
            self.log.error(f"Encountered error processing hook {hook_name}")
            return InterfaceStatus.I2Error(data=data, logs=list(self.message_queue))

        self.log.info(f"Successfully processed hook {hook_name}")
        return InterfaceStatus.I2Success(data=data, logs=list(self.message_queue))


    def _is_ip_address(self, value: str) -> bool:
        """
        Check if a string is a valid IPv4 or IPv6 address
        
        :param value: String to check
        :return: True if valid IP address, False otherwise
        """
        # IPv4 pattern
        ipv4_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        if ipv4_pattern.match(value):
            # Validate each octet is between 0-255
            octets = value.split('.')
            for octet in octets:
                if int(octet) < 0 or int(octet) > 255:
                    return False
            return True
        
        # IPv6 pattern (simplified)
        ipv6_pattern = re.compile(r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,7}:$|^::$')
        if ipv6_pattern.match(value):
            return True
            
        return False

    def _handle_ioc(self, data) -> InterfaceStatus.IIStatus:
        """
        Handle the IOC data the module just received. The module registered
        to on_postload hooks, so it receives instances of IOC object.
        These objects are attached to a dedicated SQLAlchemy session so data can
        be modified safely.

        :param data: Data associated to the hook, here IOC object
        :return: IIStatus
        """

        abuseipdb_handler = AbuseipdbHandler(mod_config=self.module_dict_conf,
                               server_config=self.server_dict_conf,
                               logger=self.log)

        in_status = InterfaceStatus.IIStatus(code=InterfaceStatus.I2CodeNoError)

        # Lista de tipos de IOC que são IPs
        ip_ioc_types = ['ip', 'ip-src', 'ip-dst', 'ip-any', 'ipv4', 'ipv6', 'ipv4-src', 'ipv4-dst', 'ipv6-src', 'ipv6-dst']
        
        # Lista de tipos de IOC que são domínios
        domain_ioc_types = ['domain', 'hostname', 'domain-src', 'domain-dst', 'fqdn']

        for element in data:
            ioc_type = element.ioc_type.type_name.lower()
            ioc_value = element.ioc_value
            
            self.log.info(f'Processing IOC: {ioc_value} (type: {ioc_type})')
            
            # Verifica se é um tipo de IP pelo nome
            if ioc_type in ip_ioc_types:
                self.log.info(f'Detected IP IOC type: {ioc_type} with value: {ioc_value}')
                status = abuseipdb_handler.handle_ip(ioc=element)
                in_status = InterfaceStatus.merge_status(in_status, status)
            
            # Verifica se o valor parece ser um IP (mesmo que o tipo não seja específico)
            elif self._is_ip_address(ioc_value):
                self.log.info(f'Detected IP address from value: {ioc_value} (type: {ioc_type})')
                status = abuseipdb_handler.handle_ip(ioc=element)
                in_status = InterfaceStatus.merge_status(in_status, status)
            
            # Verifica se é um domínio
            elif ioc_type in domain_ioc_types or 'domain' in ioc_type:
                self.log.info(f'Detected domain: {ioc_value}')
                status = abuseipdb_handler.handle_domain(ioc=element)
                in_status = InterfaceStatus.merge_status(in_status, status)
            
            # Verifica se é uma URL (extrai o domínio)
            elif 'url' in ioc_type:
                self.log.info(f'Detected URL: {ioc_value}')
                # Extrai domínio da URL e processa
                status = abuseipdb_handler.handle_domain(ioc=element)
                in_status = InterfaceStatus.merge_status(in_status, status)
            
            # Suporte para FQDN (Fully Qualified Domain Name)
            elif 'fqdn' in ioc_type:
                self.log.info(f'Detected FQDN: {ioc_value}')
                status = abuseipdb_handler.handle_domain(ioc=element)
                in_status = InterfaceStatus.merge_status(in_status, status)
            
            # Unsupported IOC type
            else:
                self.log.warning(f'IOC type {ioc_type} not handled by abuseipdb module. Skipping')

        return in_status(data=data)
