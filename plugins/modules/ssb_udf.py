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
from ansible_collections.cloudera.runtime.plugins.module_utils.cdp_ssb import CdpSsbProjectEntityModule

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

CSRF_PATTERNS = [
    r'.*var csrf_token = "([^"]*)".*',
]


class SsbUdf(CdpSsbProjectEntityModule):
    def __init__(self, module):
        super(SsbUdf, self).__init__(module)

        self.name = self._get_param('name')
        self.description = self._get_param('description')
        self.language = self._get_param('language')
        self.code = self._get_param('code')
        self.output_type = self._get_param('output_type')
        self.input_types = self._get_param('input_types')

        self.state = self._get_param('state')

        self.logger = logging.getLogger("ssb_udf_module")
        if self._get_param('debug'):
            self.logger.setLevel(logging.DEBUG)

        # Initialize the return values
        self.changed = False
        self.udf = None

    def _is_same_udf(self, func):
        return \
            self.name == func['name'] and \
            self.description == func['description'] and \
            self.language == func['language'] and \
            self.code == func['code'] and \
            self.output_type == func['output_type'] and \
            self.input_types == func['input_types']

    def process(self):
        existing_udf = self._get_udfs(self.name)
        if self.state == 'present':
            if not existing_udf or not self._is_same_udf(existing_udf[0]):
                self.changed = True
                if not self.module.check_mode:
                    if existing_udf:
                        self._delete_udf(existing_udf[0]['name'])
                    self.udf = self._create_udf(self.name, self.language, self.code, self.output_type,
                                                     self.input_types, self.description)
            else:
                self.udf = existing_udf[0]
        else:  # state == absent
            if existing_udf:
                self.changed = True
                if not self.module.check_mode:
                    self._delete_udf(existing_udf[0]['name'])


def main():
    module = AnsibleModule(
        **SsbUdf.module_spec(
            argument_spec=dict(
                name=dict(required=True, type='str'),
                description=dict(required=True, type='str'),
                language=dict(required=True, type='str'),
                code=dict(required=True, type='str'),
                output_type=dict(required=True, type='str'),
                input_types=dict(required=True, type='list', elements='str'),
                state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            ),
            supports_check_mode=True
        )
    )

    result = SsbUdf(module)
    result.process()

    output = dict(
        changed=result.changed,
        udf=result.udf,
    )

    module.exit_json(**output)


if __name__ == '__main__':
    main()
