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

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cloudera.runtime.plugins.module_utils.cdp_ssb import CdpSsbModule

logging.basicConfig(level=logging.INFO)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: ranger
short_description: Create, update, and delete Apache Ranger services and policies
description:
  - Create, update, and delete Apache Ranger services and policies
author:
  - "Andre Araujo (@asdaraujo)"
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


class SsbUserKeytab(CdpSsbModule):
    def __init__(self, module):
        super(SsbUserKeytab, self).__init__(module)

        self.principal = self._get_param('principal')
        self.keytab_password = self._get_param('keytab_password')
        self.keytab_file = self._get_param('keytab_file')
        self.keytab_base64_data = self._get_param('keytab_base64_data')

        self.state = self._get_param('state')

        self.logger = logging.getLogger("ssb_user_keytab_module")
        if self._get_param('debug'):
            self.logger.setLevel(logging.DEBUG)

        # Initialize the return values
        self.changed = False

    def process(self):
        if self.state == 'present':
            self.changed = True
            if not self.module.check_mode:
                self._delete_keytab(self.principal)
                if self.keytab_password:
                    self._generate_keytab(self.principal, self.keytab_password)
                else:
                    self._upload_keytab(self.principal, self.keytab_file, self.keytab_base64_data)


def main():
    module = AnsibleModule(
        **SsbUserKeytab.module_spec(
            argument_spec=dict(
                principal=dict(required=True, type='str'),
                keytab_password=dict(required=False, type='str', no_log=True),
                keytab_file=dict(required=False, type='str'),
                keytab_base64_data=dict(required=False, type='str', no_log=True),

                state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            ),
            mutually_exclusive=[
                ('keytab_file', 'keytab_base64_data'),
                ('keytab_password', 'keytab_file'),
                ('keytab_password', 'keytab_base64_data'),
            ],
            required_one_of=[
                ('keytab_file', 'keytab_base64_data', 'keytab_password'),
            ],
            supports_check_mode=True
        )
    )

    result = SsbUserKeytab(module)
    result.process()

    output = dict(
        changed=result.changed,
    )

    # if result.debug:
    #     output.update(
    #        sdk_out=result.log_out,
    #        sdk_out_lines=result.log_lines
    #     )

    module.exit_json(**output)


if __name__ == '__main__':
    main()
