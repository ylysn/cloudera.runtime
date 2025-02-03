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
import time

import requests

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cloudera.runtime.plugins.module_utils.cdp_ssb import CdpSsbProjectEntityModule

logging.basicConfig(level=logging.INFO)

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


class SsbJob(CdpSsbProjectEntityModule):
    def __init__(self, module):
        super(SsbJob, self).__init__(module)

        self.name = self._get_param('name')
        self.name_prefix = self._get_param('name_prefix')
        self.sql = self._get_param('sql')
        self.mv_name = self._get_param('mv_name')
        self.mv_retention_secs = self._get_param('mv_retention_secs')
        self.mv_retention_rows = self._get_param('mv_retention_rows')
        self.mv_recreate = self._get_param('mv_recreate')
        self.mv_key_column_name = self._get_param('mv_key_column_name')
        self.mv_api_key = self._get_param('mv_api_key')
        self.mv_ignore_nulls = self._get_param('mv_ignore_nulls')
        self.mv_enabled = self._get_param('mv_enabled')
        self.mv_batch_size = self._get_param('mv_batch_size')

        self.execution_mode = self._get_param('execution_mode')
        self.parallelism = self._get_param('parallelism')
        self.sample_interval = self._get_param('sample_interval')
        self.sample_count = self._get_param('sample_count')
        self.window_size = self._get_param('window_size')
        self.start_with_savepoint = self._get_param('start_with_savepoint')
        self.log4j_config = self._get_param('log4j_config')
        self.execute_in_session = self._get_param('execute_in_session')
        self.add_to_history = self._get_param('add_to_history')
        self.stop_savepoint = self._get_param('stop_savepoint')
        self.stop_savepoint_path = self._get_param('stop_savepoint_path')
        self.stop_timeout_secs = self._get_param('stop_timeout_secs')

        # Additional checks
        if self.mv_name:
            if not self.mv_key_column_name or not self.mv_api_key:
                self.module.fail_json(msg='When a mv_name is specified, the following parameter are require: '
                                          'mv_key_column_name, mv_api_key')

        self.state = self._get_param('state')

        self.job = None

        self.logger = logging.getLogger("sr_schema_module")
        if self._get_param('debug'):
            self.logger.setLevel(logging.DEBUG)

        # Initialize the return values
        self.changed = False

    def _get_job_name(self):
        if self.name_prefix:
            return '{}_{}'.format(self.name_prefix, int(time.time() * 1000))
        else:
            return self.name

    def _create_this_job(self):
        return self._create_job(job_name=self._get_job_name(),
                                sql=self.sql,
                                runtime_config={
                                    'execution_mode': self.execution_mode,
                                    'parallelism': self.parallelism,
                                    'sample_interval': self.sample_interval,
                                    'sample_count': self.sample_count,
                                    'window_size': self.window_size,
                                    'start_with_savepoint': self.start_with_savepoint,
                                    'log_config': {
                                        'type': 'LOG4J_PROPERTIES',
                                        'content': self.log4j_config,
                                    },
                                },
                                checkpoint_config=None,
                                mv_endpoints=None,
                                mv_config={
                                    'name': self.mv_name,
                                    'retention': self.mv_retention_secs,
                                    'min_row_retention_count': self.mv_retention_rows,
                                    'recreate': self.mv_recreate,
                                    'key_column_name': self.mv_key_column_name,
                                    'api_key': self.mv_api_key,
                                    'ignore_nulls': self.mv_ignore_nulls,
                                    'batch_size': self.mv_batch_size,
                                    'enabled': self.mv_enabled,
                                },
                                execute_in_session=self.execute_in_session,
                                add_to_history=self.add_to_history)

    def process(self):
        self.job = self._get_jobs(job_name=self._get_job_name())
        if self.state == 'started' or self.state == 'present':
            if not self.job:
                self.changed = True
                if not self.module.check_mode:
                    self.job = self._create_this_job()

            if self.state == 'started' and self.job['state'] != 'RUNNING':
                self.changed = True
                if not self.module.check_mode:
                    self._execute_job(job_id=self.job['job_id'])
                    self.job = self.job = self._get_jobs(job_name=self._get_job_name())

        elif self.state == 'stopped' or self.state == 'absent':
            if self.job:
                if self.job['state'] == 'RUNNING':
                    self.changed = True
                    if not self.module.check_mode:
                        self._stop_job(job_id=self.job['job_id'], savepoint=self.stop_savepoint,
                                       savepoint_path=self.stop_savepoint_path,
                                       timeout_secs=self.stop_timeout_secs)

                if self.state == 'absent':
                    self.changed = True
                    if not self.module.check_mode:
                        self._delete_job(job_id=self.job['job_id'])
                        self.job = None
                else:
                    self.job = self._get_jobs(job_id=self.job['job_id'])


TABLE = dict(
    name=dict(required=True, type='str'),
    sql=dict(required=True, type='str'),
)

UDF = dict(
    name=dict(required=True, type='str'),
    sql=dict(required=True, type='str'),
)


def main():
    module = AnsibleModule(
        **SsbJob.module_spec(
            argument_spec=dict(
                state=dict(required=False, type='str', choices=['started', 'stopped', 'present', 'absent'],
                           default='started'),

                name=dict(required=False, type='str'),
                name_prefix=dict(required=False, type='str'),
                sql=dict(required=False, type='str', default=''),
                mv_name=dict(required=False, type='str'),
                mv_retention_secs=dict(required=False, type='int', default=300),
                mv_retention_rows=dict(required=False, type='int', default=0),
                mv_recreate=dict(required=False, type='bool', default=False),
                mv_key_column_name=dict(required=False, type='str'),
                mv_api_key=dict(required=False, type='str'),
                mv_ignore_nulls=dict(required=False, type='bool', default=True),
                mv_enabled=dict(required=False, type='bool', default=False),
                mv_batch_size=dict(required=False, type='int', default=0),

                execution_mode=dict(required=False, type='str', default='SESSION'),
                parallelism=dict(required=False, type='int', default=1),
                sample_interval=dict(required=False, type='int', default=1000),
                sample_count=dict(required=False, type='int', default=100),
                window_size=dict(required=False, type='int', default=100),
                start_with_savepoint=dict(required=False, type='bool', default=True),
                log4j_config=dict(required=False, type='str', default=''),
                execute_in_session=dict(required=False, type='bool', default=True),
                add_to_history=dict(required=False, type='bool', default=True),

                stop_savepoint=dict(required=False, type='bool', default=False),
                stop_savepoint_path=dict(required=False, type='str', default=''),
                stop_timeout_secs=dict(required=False, type='int', default=60),
            ),
            required_one_of=[
                ('name', 'name_prefix'),
            ],
            mutually_exclusive=[
                ('name', 'name_prefix'),
            ],
            required_if=[
                ('mv_enabled', 'true', ['mv_name']),
                ('state', 'stopped', ['name']),
                ('stop_savepoint', True, ['stop_savepoint_path']),
            ],
            supports_check_mode=True
        )
    )

    result = SsbJob(module)
    result.process()

    output = dict(
        changed=result.changed,
        job=result.job,
    )

    # if result.debug:
    #     output.update(
    #        sdk_out=result.log_out,
    #        sdk_out_lines=result.log_lines
    #     )

    module.exit_json(**output)


if __name__ == '__main__':
    main()
