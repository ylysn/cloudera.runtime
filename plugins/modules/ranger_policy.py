#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2021 Cloudera, Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging

from json import JSONDecodeError

from ansible.module_utils.basic import AnsibleModule
from ansible.utils.vars import merge_hash
from apache_ranger.client.ranger_client import RangerClient
from apache_ranger.exceptions import RangerServiceException

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: ranger_policy
short_description: Create, update, and delete Apache Ranger policies
description:
  - Gather information about Apache Ranger policies.
  - The module supports check_mode.
author:
  - "Webster Mudge (@wmudge)"
requirements:
  - apache-ranger
options:
  debug:
    description:
      - Flag to capture and return the debugging log of the underlying CDP SDK.
      - If set, the log level will be set from ERROR to DEBUG.
    aliases:
      - debug_cdpsdk
    default: False
    type: bool
'''

EXAMPLES = r'''

'''

RETURN = r'''
---
account:
    description: Returns the authentication settings for the CDP Account
    returned: always
    type: dict
    contains:
        clouderaSSOLoginEnabled:
            description: Flag indicating whether interactive login using Cloudera SSO is enabled.
            returned: always
            type: bool
        workloadPasswordPolicy:
            description: Information about the workload password policy for an account.
            returned: always
            type: dict
            contains:
                maxPasswordLifetimeDays:
                    description: The max lifetime, in days, of the password. If '0', passwords never expire.
                    returned: always
                    type: int
sdk_out:
    description: Returns the captured CDP SDK log.
    returned: when supported
    type: str
sdk_out_lines:
    description: Returns a list of each line of the captured CDP SDK log.
    returned: when supported
    type: list
    elements: str
'''


class RangerPolicy(AnsibleModule):
    def __init__(self, module):
        self.module = module
        
        self.endpoint = self._get_param('endpoint')
        self.username = self._get_param('username')
        self.password = self._get_param('password')
        
        self.name = self._get_param('name')
        self.id = self._get_param('id')
        self.description = self._get_param('description')
        self.labels = self._get_param('labels')
        
        self.enabled = self._get_param('enabled')
        self.priority = self._get_param('priority')
        
        self.service = self._get_param('service')
        self.service_type = self._get_param('service_type')
        
        self.resource_signature = self._get_param('resource_signature')
        self.options = self._get_param('options')
        self.resources = self._get_param('resources')
        self.zone_name = self._get_param('zone_name')
        
        self.deny_all_else = self._get_param('deny_all_else')
        self.enable_audit = self._get_param('enable_audit')
        
        self.conditions = self._get_param('conditions')
        self.allow_exceptions = self._get_param('allow_exceptions')
        self.deny_exceptions = self._get_param('deny_exceptions')
        
        self.access_policies = self._get_param('access_policies')
        self.deny_policies = self._get_param('deny_policies')
        
        self.row_filter_policies = self._get_param('row_filter_policies')
        self.data_mask_policies = self._get_param('data_mask_policies')
        
        self.schedules = self._get_param('schedules')
        
        self.merge = self._get_param('merge')
        self.state = self._get_param('state')
        
        # Set up the client
        self.ranger = RangerClient(self.endpoint, (self.username, self.password))
        logging.getLogger("apache_ranger").setLevel(logging.DEBUG)
        
        # Initialize the return values
        self.policy = {}
        self.changed = False

        # Execute logic process
        self.process()

    def process(self):
        if self.state == 'present':
            payload = dict()
            self.populate_payload(payload)
            
            if self.id is not None:
                existing = self._get_policy_by_id()
            else:
                existing = self._get_policy()              
                
            if existing is not None:
                # Merge
                if self.merge:
                    is_subset = compare_dicts(payload, existing)
                    # If changed
                    if not is_subset:
                        self.changed = True
                        # Run update
                        if not self.module.check_mode:
                            merged_payload = merge_hash(existing, payload, True)
                            self.policy = self.ranger.update_policy_by_id(existing.id, merged_payload)                            
                # Overwrite
                else:
                    self.changed = True
                    if not self.module.check_mode:
                        self.policy = self.ranger.update_policy_by_id(existing.id, payload)
            else:
                self.changed = True
                # Create
                if not self.module.check_mode: 
                    payload = dict(name=self.name)
                    self.populate_payload(payload)                  
                    self.policy = self.ranger.create_policy(payload)
                
    def _get_policy(self):
        try:
            return self.ranger.get_policy(self.service, self.name)
        except RangerServiceException as err:
            _CLIENT_ERROR_PATTERN = re.compile(
                r"(.*?) failed: expected_status=(.*?), status=(.*?), message=(.*?)"
            )
            error = re.search(_CLIENT_ERROR_PATTERN, str(err))
            if error.group(3) == '400':
                return None
            else:
                self.module.fail_json("Unexpected error: %s" % err)
        except JSONDecodeError as err:
            return None
        
    def _get_policy_by_id(self):
        try:
            return self.ranger.get_policy_by_id(self.id)
        except RangerServiceException as err:
            _CLIENT_ERROR_PATTERN = re.compile(
                r"(.*?) failed: expected_status=(.*?), status=(.*?), message=(.*?)"
            )
            error = re.search(_CLIENT_ERROR_PATTERN, str(err))
            if error.group(3) == '400':
                return None
            else:
                self.module.fail_json("Unexpected error: %s" % err)
                
    def populate_payload(self, payload):
        if self.name is not None:
            payload.update(name=self.name)
        if self.description is not None:
            payload.update(description=self.description)
        if self.labels is not None:
            payload.update(labels=self.labels)
        if self.enabled is not None:
            payload.update(isEnabled=self.enabled)
        if self.priority is not None:
            payload.update(policyPriority=self.priority)
        if self.service is not None:
            payload.update(service=self.service)
        if self.service_type is not None:
            payload.update(serviceType=self.service_type)
        if self.resource_signature is not None:
            payload.update(resourceSignature=self.resource_signature)
        if self.options is not None:
            payload.update(options=self.options)
        if self.resources is not None:
            # TODO Validate resource contents
            payload.update(resources=self.resources)
        if self.zone_name is not None:
            payload.update(zoneName=self.zoneName)
        if self.deny_all_else is not None:
            payload.update(isDenyAllElse=self.deny_all_else)
        if self.enable_audit is not None:
            payload.update(isAuditEnabled=self.enable_audit)
        if self.conditions is not None:
            payload.update(conditions=self.conditions)
        if self.allow_exceptions is not None:
            payload.update(allowExceptions=self.allow_exceptions)
        if self.deny_exceptions is not None:
            payload.update(denyExceptions=self.deny_exceptions)
        if self.access_policies is not None:
            payload.update(policyType=0)
            payload.update(policyItems=self.access_policies)
        if self.deny_policies is not None:
            payload.update(denyPolicyItems=self.deny_policies)
        if self.row_filter_policies is not None:
            payload.update(policyType=2)
            payload.update(rowFilterPolicyItems=self.row_filter_policies)
        if self.data_mask_policies is not None:
            payload.update(policyType=1)
            payload.update(dataMaskPolicyItems=self.data_mask_policies)
        if self.schedules is not None:
            payload.update(validitySchedules=self.schedules)

    def _get_param(self, param, default=None):
        """Fetches an Ansible Input Parameter if it exists, else returns optional default or None"""
        if self.module is not None:
            return self.module.params[param] if param in self.module.params else default
        return default
    
    
def compare_dicts(a, b):
    for key, value in a.items():
        if key in b:
            if isinstance(a[key], dict):
                if not compare_dicts(a[key], b[key]):
                    return False
            elif value != b[key]:
                return False
        else:
            return False
    return True


RANGER_POLICY_ITEM_CONDITION=dict(
    # RangerPolicyItemCondition
    type=dict(required=True, type='str'),
    values=dict(required=True, type='list', elements='str')
)

RANGER_POLICY_ITEM = dict(
    # RangerPolicyItem
    roles=dict(required=False, type='list', elements='str'),
    groups=dict(required=False, type='list', elements='str'),
    conditions=dict(required=False, type='list', elements='dict', contains=RANGER_POLICY_ITEM_CONDITION),
    delegateAdmin=dict(required=False, type='bool', default=True),
    accesses=dict(required=False, type='list', elements='dict', contains=dict(
        # RangerPolicyItemAccess
        type=dict(required=True, type='str'),
        isAllowed=dict(required=True, type='bool', default=True)
    )),
    users=dict(required=False, type='list', elements='str')
)


def main():
    module = AnsibleModule(
        argument_spec=dict(           
            name=dict(required=False, type='str'),
            id=dict(required=False, type='int'),
            
            enabled=dict(required=False, type='bool'), # isEnabled
                               
            priority=dict(required=False, type='int'), # policyPriority
            description=dict(required=False, type='str'),
            
            service=dict(required=False, type='str'),
            service_type=dict(required=False, type='str'), # serviceType
            
            # Implied by access_policies, row_filter_policies, or data_mask_policies
            #type=dict(required=False, type='str', choices=['access', 'data_mask', 'row_filter']), # policyType (as int)
            
            resource_signature=dict(required=False, type='str', aliases=['signature']), # resourceSignature
            labels=dict(required=False, type='list', elements='str'), # policyLabels
            options=dict(required=False, type='dict'),
            resources=dict(required=False, type='dict'), # How to handle arbitrary keys to a value object with known keys?
            zone_name=dict(required=False, type='str'), # zoneName
            
            deny_all_else=dict(required=False, type='bool'), # isDenyAllElse
            enable_audit=dict(required=False, type='bool'), # isAuditEnabled  
             
            conditions=dict(required=False, type='list', elements='dict', contains=RANGER_POLICY_ITEM_CONDITION),
            allow_exceptions=dict(required=False, type='list', elements='dict', contains=RANGER_POLICY_ITEM), # allowExceptions
            deny_exceptions=dict(required=False, type='list', elements='dict', contains=RANGER_POLICY_ITEM), # denyExceptions
            
            access_policies=dict(required=False, type='list', elements='dict', contains=RANGER_POLICY_ITEM), # policyItems
            deny_policies=dict(required=False, type='list', elements='dict', contains=RANGER_POLICY_ITEM), # denyPolicyItems
                    
            row_filter_policies=dict(required=False, type='list', elements='dict', contains=dict(
                # RangerRowFilterPolicyItem
                RANGER_POLICY_ITEM,
                rowFilterInfo=dict(required=True, type='dict', contains=dict(
                    # RangerPolicyItemRowFilterInfo
                    filterExpr=dict(required=True, type='str')
                ))
            )), # rowFilterPolicyItems
             
            data_mask_policies=dict(required=False, type='list', elements='dict', contains=dict(
                # RangerDataMaskPolicyItem
                RANGER_POLICY_ITEM,
                dataMaskInfo=dict(required=True, type='dict', contains=dict(
                    # RangerPolicyItemDataMaskInfo
                    dataMaskType=dict(required=True, type='str'),
                    valueExpr=dict(required=True, type='str'),
                    conditionExpr=dict(required=True, type='str')
                ))
            )), # dataMaskPolicyItems
            
            schedules=dict(required=False, type='list', elements='dict', contains=dict(
                # RangerValiditySchedule
                recurrences=dict(required=False, type='list', elements='dict', contains=dict(
                    # RangerValidityRecurrence
                    schedule=dict(required=False, type='dict', contains=dict(
                        # RecurrenceSchedule
                        hour=dict(required=False, type='str'),
                        minute=dict(required=False, type='str'),
                        year=dict(required=False, type='str'),
                        month=dict(required=False, type='str'),
                        dayOfWeek=dict(required=False, type='str'),
                        dayOfMonth=dict(required=False, type='str')
                    )),
                    interval=dict(required=False, type='dict', contains=dict(
                        # ValidityInterval
                        hours=dict(required=False, type='int'),
                        days=dict(required=False, type='int'),
                        minutes=dict(required=False, type='int'),
                    ))
                )),
                endTime=dict(required=False, type='str'),
                startTime=dict(required=False, type='str'),
                timeZone=dict(required=False, type='str')
            )), # validitySchedules                         
            
            merge=dict(required=False, type='bool', default=True),
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            
            endpoint=dict(required=True, type='str', aliases=['url']),
            username=dict(required=True, type='str', aliases=['user']),
            password=dict(required=True, type='str', no_log=True),
            debug=dict(required=False, type='bool', default=False)
        ),
        #required_one_of=[ 'name', 'id' ],
        supports_check_mode=True
    )

    result = RangerPolicy(module)

    output = dict(
        changed=result.changed,
        policy=result.policy,
    )

    #if result.debug:
        #output.update(
        #    sdk_out=result.log_out,
        #    sdk_out_lines=result.log_lines
        #)

    module.exit_json(**output)


if __name__ == '__main__':
    main()
