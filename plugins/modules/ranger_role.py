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
import re

from ansible.module_utils.basic import AnsibleModule
from apache_ranger.client.ranger_client import RangerClient
from apache_ranger.exceptions import RangerServiceException

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: ranger_role
short_description: Create, update, and delete Apache Ranger roles
description:
  - Gather information about Apache Ranger roles.
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


class RangerRole(AnsibleModule):
    def __init__(self, module):
        # Set parameters
        self.module = module
        self.endpoint = self._get_param('endpoint')
        self.username = self._get_param('username')
        self.password = self._get_param('password')
        self.name = self._get_param('name')
        self.id = self._get_param('id')
        self.groups = self._get_param('groups')
        self.state = self._get_param('state')
        
        # Set up the client
        self.ranger = RangerClient(self.endpoint, (self.username, self.password))
        logging.getLogger("apache_ranger").setLevel(logging.DEBUG)
        
        # Initialize the return values
        self.role = {}

        # Execute logic process
        self.process()

    def process(self):
        if self.state == 'present':
            if self.name is not None:
                existing = self._get_role()
                if existing is None:
                    payload = dict(name=self.name)
                    if self.groups:
                        payload.update(groups=self.groups)
                    self.role = self.ranger.create_role(None, payload)
                else:
                    # TODO Reconcile
                    self.role = existing

    def _get_role(self):
        try:
            return self.ranger.get_role(self.name, None, None)
        except RangerServiceException as err:
            _CLIENT_ERROR_PATTERN = re.compile(
                r"(.*?) failed: expected_status=(.*?), status=(.*?), message=(.*?)"
            )
            error = re.search(_CLIENT_ERROR_PATTERN, str(err))
            if error.group(3) == '400':
                return None
            else:
                self.module.fail_json("Unexpected error: %s" % err)

    def _get_param(self, param, default=None):
        """Fetches an Ansible Input Parameter if it exists, else returns optional default or None"""
        if self.module is not None:
            return self.module.params[param] if param in self.module.params else default
        return default


def main():
    module = AnsibleModule(
        argument_spec=dict(
            endpoint=dict(required=True, type='str', aliases=['url']),
            username=dict(required=True, type='str', aliases=['user']),
            password=dict(required=True, type='str', no_log=True),
            name=dict(required=False, type='str'),
            id=dict(required=False, type='int'),
            groups=dict(required=False, type='list', elements='dict', contains=dict(
                name=dict(required=True, type='str'),
                isAdmin=dict(required=False, type='bool', default=False)
            )),
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            debug=dict(required=False, type='bool', default=False)
        ),
        #required_one_of=[ 'name', 'id' ],
        supports_check_mode=True
    )

    result = RangerRole(module)

    output = dict(
        changed=False,
        role=result.role,
    )

    #if result.debug:
        #output.update(
        #    sdk_out=result.log_out,
        #    sdk_out_lines=result.log_lines
        #)

    module.exit_json(**output)


if __name__ == '__main__':
    main()
