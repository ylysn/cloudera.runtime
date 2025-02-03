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


class SsbDataSource(CdpSsbProjectEntityModule):
    def __init__(self, module):
        super(SsbDataSource, self).__init__(module)

        self.data_sources = self._get_param('data_sources')

        self.state = self._get_param('state')

        self.output_data_sources = []

        # Additional checks
        if self.state == 'present':
            for source in self.data_sources:
                if not source['type'] or not source['properties']:
                    self.module.fail_json(msg='Each data source must specify both these attributes: type, properties.'
                                              ' Source: {}'.format(source))

        self.logger = logging.getLogger("ssb_data_source_module")
        if self._get_param('debug'):
            self.logger.setLevel(logging.DEBUG)

        # Initialize the return values
        self.changed = False

    def process(self):
        for source in self.data_sources:
            existing_source = self._get_data_sources(source['name'], data_source_type='kafka')
            if self.state == 'present':
                if not existing_source:
                    self.changed = True
                    if not self.module.check_mode:
                        existing_source = self._create_data_source(source)
                self.output_data_sources.append(existing_source)
            elif self.state == 'absent' and existing_source:
                self.changed = True
                if not self.module.check_mode:
                    self._delete_data_source(data_source_name=existing_source[0]['name'])


DATA_SOURCE = dict(
    name=dict(required=True, type='str'),
    type=dict(required=False, type='str'),
    properties=dict(required=False, type='dict'),
)


def main():
    # module = AnsibleModule(
    #     argument_spec=CdpSsbProjectEntityModule.argument_spec(
    #         data_sources=dict(required=True, type='list', elements='dict', options=DATA_SOURCE),
    #
    #         state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
    #     ),
    #     # mutually_exclusive=[
    #     #     ('project_name', 'project_id'),
    #     # ],
    #     # required_one_of=[
    #     #     ('project_name', 'project_id'),
    #     # ],
    #     supports_check_mode=True
    # )

    module = AnsibleModule(
        **CdpSsbProjectEntityModule.module_spec(
            argument_spec=dict(
                data_sources=dict(required=True, type='list', elements='dict', options=DATA_SOURCE),
                state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            ),
            supports_check_mode=True
        )
    )

    result = SsbDataSource(module)
    result.process()

    output = dict(
        changed=result.changed,
        data_sources=result.output_data_sources,
    )

    # if result.debug:
    #     output.update(
    #        sdk_out=result.log_out,
    #        sdk_out_lines=result.log_lines
    #     )

    module.exit_json(**output)


if __name__ == '__main__':
    main()
