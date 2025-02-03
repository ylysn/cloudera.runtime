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

import json
import logging
import re

from ansible.module_utils.basic import AnsibleModule
from apache_atlas.client.base_client import AtlasClient
from apache_atlas.model.instance import AtlasEntity, AtlasEntityWithExtInfo, AtlasEntitiesWithExtInfo, AtlasRelatedObjectId
from apache_atlas.model.enums import EntityOperation, TypeCategory
from apache_atlas.model.misc import SearchFilter
from apache_atlas.model.typedef   import AtlasTypesDef
from apache_atlas.exceptions import AtlasServiceException    

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: atlas_discovery
short_description: Search Apache Atlas
description:
  - The module supports check_mode.
author:
  - "Webster Mudge (@wmudge)"
requirements:
  - apache-atlas
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


class AtlasDiscovery(AnsibleModule):
    def __init__(self, module):
        # Set parameters
        self.module = module
        self.endpoint = self._get_param('endpoint')
        self.username = self._get_param('username')
        self.password = self._get_param('password')
        self.query = self._get_param('query')
        self.type = self._get_param('type')
        self.exclude_deleted = self._get_param('exclude_deleted')
        self.limit = self._get_param('limit')
        self.offset = self._get_param('offset')
        self.debug = self._get_param('debug')
        
        # Set up the client
        self.atlas = AtlasClient(self.endpoint, (self.username, self.password))
        if self.debug:
            logging.getLogger("apache_atlas").setLevel(logging.DEBUG)
        
        # Initialize the return values
        self.results = []

        # Execute logic process
        self.process()

    def process(self):
        results = self.atlas.discovery.basic_search(self.type, None, self.query, self.exclude_deleted)
        if results.entities is not None:
            self.results = results.entities
                
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
            query=dict(required=True, type='str'),
            type=dict(required=True, type='str', aliases=['typeName']),
            exclude_deleted=dict(required=False, type='bool', default=True, aliases=['excludeDeletedEntities']),
            limit=dict(required=False, type='int'),
            offset=dict(required=False, type='int'),
            debug=dict(required=False, type='bool', default=False)
        ),
        #required_one_of=[ 'name', 'id' ],
        supports_check_mode=True
    )

    result = AtlasDiscovery(module)

    output = dict(
        changed=False,
        entities=result.results,
    )

    if result.debug:
        output.update(
            sdk_out=result.log_out,
            sdk_out_lines=result.log_lines
        )

    module.exit_json(**output)


if __name__ == '__main__':
    main()
