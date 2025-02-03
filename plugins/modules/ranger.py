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
import copy
import logging

from ansible.module_utils.basic import AnsibleModule
from apache_ranger.client.ranger_client import RangerClient
from apache_ranger.model.ranger_service import RangerService
from apache_ranger.model.ranger_policy import RangerPolicy

logging.basicConfig(level=logging.INFO)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: ranger
short_description: Create, update, and delete Apache Ranger services and policies
description:
  - Create, update, and delete Apache Ranger services and policies.
author:
  - "Andre Araujo (@asdaraujo)"
requirements:
  - apache-ranger
options:
  endpoint:
    description: Ranger REST API endpoint.
    required: True
    type: str
    aliases: url
  username:
    description: Username for authentication with the REST API.
    required: True
    type: str
    aliases: user
  password:
    description: Password for authentication with the REST API.
    required: True
    type: str
  verify_tls:
    description:
      - If true, the server TLS certificate is verified. If false, it doesn't.
    required: False
    default: True
    type: str
  ca_cert_file:
    description:
      - Path of a file containing a TLS root certificate in PEM format.
      - If provided, the certificate will be used to validate Ranger's certificate.
    required: False
    type: str
  force_deletion:
    description:
      - After deleting all the policy items contained the specification passed to the module, if the policy still has
        other remaining items it will not be deleted if force_deletion==False. If force_deletion==True, the remaining
        items and the policy will be fully deleted.
    required: False
    type: bool
    default: False
  policies_only:
    description:
      - If policies_only==True, the module expects that the services will already be created. Services will not be
        created or updated in this case.
      - This option is ideal for adding items to the existing default service policies.
      - If the specification includes policies for a service that does not exist, an error will be thrown.
      - If the service exists, the policies will be added to it, but the service properties will not be updated.
    required: False
    type: bool
    default: False
  merge_policies:
    description:
      - If merge_policies==False, policies that already exist will be overridden by the spec passed to the module.
      - If merge_policies==True, policy items in the spec will be merged with the ones in existing policies.
    required: False
    type: bool
    default: True
  services:
    description:
    required: True
    type: list
    elements: dict
    options:
      name:
        description: Name of the Ranger service to be acted upon.
        required: True
        type: str
      type:
        description:
          - Ranger service's type
          - Examples: kafka, hive, schema-registry, etc...
        required: True
        type: str
      displayName:
        description: Ranger service's display name.
        required: False
        type: str
      description:
        description: Ranger service's description.
        required: False
        type: str
      tagService:
        description: Tag service associated with the Ranger service.
        required: False
        type: str
      configs:
        description: Configuration properties for the service.
        required: False
        type: dict
      policies:
        description: List of policies for the service.
        required: False
        type: list
        elements: dict
        options:
          name:
            description: Name of the Ranger policy to be acted upon.
            required: True
            type: str
          policyType:
            description:
              - Type of policy
              - Valid values are: 0=access, 1=masking, 2=row_level.
            required: False
            type: int
            choices: [0, 1, 2]
            default: 0
          policyPriority:
            description:
              - The value of this property determines if the policy is a normal policy (0) or an override policy (1).
            required: False
            type: int
            choices: [0, 1]
            default: 0
          policyLabels:
            description: List of labels to be attached to the policy.
            required: False
            type: list
            elements: str
          description:
            description: Policy description.
            required: False
            type: str
          isAuditEnabled:
            description:
              - Determines if auditing is enabled or not for the policy.
              - If audit is false, there must be at least one policy item specified.
            required: False
            type: bool
            default: True
          isDenyAllElse:
            description: Determines if the "Deny All Other Accesses" is enabled or not for the policy.
            required: False
            type: bool
            default: False
          resources:
            description: List of resources associated to the policy.
            required: False
            type: dict
            options: RESOURCES
          policyItems:
            description:
              - List of Allow policy items.
              - Applies to the Access policies.
            required: False
            type: list
            elements: dict
            options: POLICY_ITEM
          denyPolicyItems:
            description:
              - List of Deny policy items.
              - Applies to the Access policies.
              - Only accepted when isDenyAllElse=false
            required: False
            type: list
            elements: dict
            options: POLICY_ITEM
          allowExceptions:
            description:
              - List of exceptions to the Allow policy items.
              - Applies to the Access policies.
            required: False
            type: list
            elements: dict
            options: POLICY_ITEM
          denyExceptions:
            description:
              - List of exceptions to the Deny policy items.
              - Applies to the Access policies.
              - Only accepted when isDenyAllElse=false
            required: False
            type: list
            elements: dict
            options: POLICY_ITEM
          dataMaskPolicyItems:
            description:
              - Data masking policy items.
              - Applies to the Masking policies.
            required: False
            type: list
            elements: dict
            options: DATA_MASK_POLICY_ITEM
          rowFilterPolicyItems:
            description:
              - List of Row Filter policy items
              - Applies to the Row Level policies.
            required: False
            type: list
            elements: dict
            options: ROW_FILTER_POLICY_ITEM
          validitySchedules:
            description: List of validity schedules.
            required: False
            type: list
            elements: dict
            options: VALIDITY_SCHEDULE
  state:
    description:
      - The declarative state of the CustomFlow
    type: str
    required: False
    default: present
    choices:
      - present
      - absent
  debug:
    description:
      - Flag to capture and return the debugging log of the underlying CDP SDK.
      - If set, the log level will be set from ERROR to DEBUG.
    default: False
    type: bool
'''

EXAMPLES = r'''
# Create a new Ranger Service with policies
ranger:
  endpoint:
  username: alice
  password: supersecret
  state: present
  services:
    - name: Hive service sample
      type: hive
      displayName: Sample Hive Service
      description: This is a Hive Ranger service
      configs:
        username: hive
        password: hive
        jdbc.driverClassName: org.apache.hive.jdbc.HiveDriver
        jdbc.url: jdbc:hive2://ranger-hadoop:10000
        hadoop.security.authorization: true
      policies:
        - name: Sample Access policy
          policyType: 0 # 0=access, 1=masking, 2=row_level
          policyPriority: 1 # 0=normal, 1=override
          policyLabels: [abc,def]
          description: Sample access policy
          isAuditEnabled: true
          isDenyAllElse: false
          resources:
            database:
              values: [test_db]
              isExcludes: False
              isRecursive: False
            table:
              values: [test_tbl]
              isExcludes: False
              isRecursive: False
            column:
              values: ["*"]
              isExcludes: False
              isRecursive: False
          policyItems:
            - users: [admin]
              accesses:
                - type: select
              groups: [hdfs, hadoop]
              roles: [test_role]
              delegateAdmin: true
          allowExceptions:
            - users: [admin]
              accesses:
                - type: select
              groups: [hdfs, hadoop]
              roles: [test_role]
              delegateAdmin: true
          denyPolicyItems:
            - users: [admin]
              accesses:
                - type: select
              groups: [hdfs, hadoop]
              roles: [test_role]
              delegateAdmin: true
          denyExceptions:
            - users: [admin]
              accesses:
                - type: select
              groups: [hdfs, hadoop]
              roles: [test_role]
              delegateAdmin: true
        - name: Sample Masking policy
          policyType: 1 # 0=access, 1=masking, 2=row_level
          policyPriority: 0 # 0=normal, 1=override
          policyLabels: [abc,def]
          description: This is a sample Masking policy
          isAuditEnabled: true
          isDenyAllElse: false
          resources:
            database:
              values: [test_db]
              isExcludes: False
              isRecursive: False
            table:
              values: [test_tbl]
              isExcludes: False
              isRecursive: False
            column:
              values: ["*"]
              isExcludes: False
              isRecursive: False
          dataMaskPolicyItems:
            - users: [admin]
              accesses:
                - type: select
              groups: [hdfs, hadoop]
              roles: [test_role]
              delegateAdmin: true
              dataMaskInfo:
                dataMaskType: MASK_SHOW_FIRST_4
                valueExpr: null
            - users: [admin]
              accesses:
                - type: select
              groups: [hdfs, hadoop]
              roles: [test_role]
              delegateAdmin: true
              dataMaskInfo:
                dataMaskType: CUSTOM
                valueExpr: abcd
        - name: Sample Row Level policy
          policyType: 2 # 0=access, 1=masking, 2=row_level
          policyPriority: 0 # 0=normal, 1=override
          policyLabels: [abc,def]
          description: This is a sample Row Level policy
          isAuditEnabled: true
          isDenyAllElse: false
          resources:
            database:
              values: [test_db]
              isExcludes: False
              isRecursive: False
            table:
              values: [test_tbl]
              isExcludes: False
              isRecursive: False
          rowFilterPolicyItems:
            - users: [admin]
              accesses:
                - type: select
              groups: [hdfs, hadoop]
              roles: [test_role]
              rowFilterInfo:
                filterExpr: "1=1"
          validitySchedules:
            - startTime: 2022/03/24 00:00:00
              endTime: 2022/03/31 03:05:03
              timeZone: Africa/Accra
'''

RETURN = r'''
---
'''


def _call_api(func, *args, **kwargs):
    try:
        return func(*args, **kwargs)
    except Exception as err:
        if (hasattr(err, 'strerror') and err.strerror == 'Not found') or \
                (hasattr(err, 'strerror') and hasattr(err, 'errno')
                 and err.strerror == '' and err.errno == 'Expecting value'):  # this can be the result of a 404
            return None
        raise


class Ranger(AnsibleModule):
    def __init__(self, module):
        self.module = module

        self.endpoint = self._get_param('endpoint')
        self.username = self._get_param('username')
        self.password = self._get_param('password')
        self.verify_tls = self._get_param('verify_tls')
        self.ca_cert_file = self._get_param('ca_cert_file')

        self.services = remove_nulls(self._get_param('services'))
        for service in self.services:
            for policy in service['policies']:
                policy.update({'service': service['name'], 'serviceType': service['type']})

        self.force_deletion = self._get_param('force_deletion')
        self.policies_only = self._get_param('policies_only')
        self.merge_policies = self._get_param('merge_policies')
        self.state = self._get_param('state')

        # Set up the client
        self.ranger = RangerClient(self.endpoint, (self.username, self.password))
        if self.verify_tls:
            if self.ca_cert_file is None:
                self.ranger.session.verify = True
            else:
                self.ranger.session.verify = self._get_param('ca_cert_file')
        else:
            self.ranger.session.verify = False

        self.logger = logging.getLogger("ranger_module")
        if self._get_param('debug'):
            self.logger.setLevel(logging.DEBUG)

        # Initialize the return values
        self.policy = {}
        self.changed = False

    def process(self):
        for service in self.services:
            service_state = RangerService(service)
            service_state.type_coerce_attrs()
            if not service_state.name:
                self.module.fail_json(msg="Ranger service name must be specified.")

            existing_service = self._get_service(service_state.name)

            if existing_service and self.state == 'absent':
                # Delete policies
                for policy in service['policies']:
                    policy_state = RangerPolicy(policy)
                    policy_state.type_coerce_attrs()
                    existing_policy = self._get_policy(service_state.name, policy_state.name)
                    if not existing_policy:
                        self.logger.debug('No policy (%s, %s) to delete.', service_state.name, policy_state.name)
                    else:
                        # Ensure that policy is only deleted if it has no extra items (unless forced)
                        is_policy_empty = True
                        for attr in ['policyItems', 'denyPolicyItems', 'allowExceptions', 'denyExceptions',
                                     'dataMaskPolicyItems', 'rowFilterPolicyItems', 'validitySchedules']:
                            if list_difference(existing_policy[attr], policy_state[attr]):
                                is_policy_empty = False
                                break

                        if not is_policy_empty and not self.force_deletion:
                            self.logger.debug('Policy (%s, %s) will not be deleted because it has extra items. '
                                              'Specify force_deletion=true to force the deletion. ',
                                              service_state.name, policy_state.name)
                        else:
                            if not is_policy_empty:
                                self.logger.debug(
                                    'Policy (%s, %s) still have items in it but it will be deleted due to '
                                    'force_deletion=true.',
                                    service_state.name, policy_state.name)
                            self.changed = True
                            if not self.module.check_mode:
                                self.logger.debug('Delete policy (%s, %s).', service_state.name, policy_state.name)
                                self._delete_policy(policy_state.service, policy_state.name)

            if self.state == 'present':
                # Create service
                if existing_service is None:
                    if self.policies_only:
                        self.module.fail_json(
                            msg='Service ({}) does not exist and policies_only=true.'.format(service_state.name))

                    self.changed = True
                    if not self.module.check_mode:
                        self.logger.debug('Create service (%s).', service_state.name)
                        self.ranger.create_service(service_state)
                else:
                    if self.policies_only:
                        self.logger.debug('No changes applied to service (%s) since policies_only=true.',
                                          service_state.name)
                    else:
                        is_subset = is_subset_of(service, remove_nulls(existing_service))
                        if not is_subset:
                            self.changed = True
                            if not self.module.check_mode:
                                self.logger.debug('Update service(%s).', service_state.name)
                                self.ranger.update_service(service_state.name, service_state)
                        else:
                            self.logger.debug('No changes to service (%s).', service_state.name)

                # Create policies
                for policy in service['policies']:
                    policy_state = RangerPolicy(policy)
                    policy_state.type_coerce_attrs()
                    existing_policy = self._get_policy(service_state.name, policy_state.name)
                    if existing_policy is None:
                        self.changed = True
                        if not self.module.check_mode:
                            self.logger.debug('Create policy (%s, %s).', service_state.name, policy_state.name)
                            self.ranger.create_policy(policy_state)
                    else:
                        is_subset = is_subset_of(policy, remove_nulls(existing_policy))
                        if not is_subset:
                            if self.merge_policies:
                                policy_state = RangerPolicy(merge(existing_policy, policy_state))
                            self.changed = True
                            if not self.module.check_mode:
                                self.logger.debug('Update policy (%s, %s).', service_state.name, policy_state.name)
                                self.ranger.update_policy(service_state.name, policy_state.name, policy_state)
                        else:
                            self.logger.debug('No changes to policy (%s, %s).', service_state.name, policy_state.name)

            elif self.state == 'absent':
                if self.policies_only:
                    self.logger.debug('Skipping deletion of service (%s) since policies_only=true.', service_state.name)
                    return

                # Delete service
                if not existing_service:
                    self.logger.debug('No service (%s) to delete.', service_state.name)
                else:
                    # Ensure that service is only deleted if there are no more policies (unless forced)
                    remaining_policies = self.ranger.get_policies_in_service(service_state.name)
                    if remaining_policies and not self.force_deletion:
                        self.logger.debug('Service (%s) will not be deleted since there are still policies in it. '
                                          'Specify force_deletion=true to force the deletion. '
                                          'Remaining policies: [%s].',
                                          service_state.name, ', '.join([p.name for p in remaining_policies]))
                    else:
                        if remaining_policies:
                            self.logger.debug('Service (%s) still have policies in it but it will be deleted due to '
                                              'force_deletion=true. Remaining policies: [%s]. ',
                                              service_state.name, ', '.join([p.name for p in remaining_policies]))
                        self.changed = True
                        if not self.module.check_mode:
                            self.logger.debug('Delete service (%s).', service_state.name)
                            self._delete_service(service_state.name)

    def _get_service(self, service_name):
        return _call_api(self.ranger.get_service, service_name)

    def _get_policy(self, service_name, policy_name):
        return _call_api(self.ranger.get_policy, service_name, policy_name)

    def _delete_service(self, service_name):
        return _call_api(self.ranger.delete_service, service_name)

    def _delete_policy(self, service_name, policy_name):
        return _call_api(self.ranger.delete_policy, service_name, policy_name)

    def _get_param(self, param, default=None):
        """Fetches an Ansible Input Parameter if it exists, else returns optional default or None"""
        if self.module is not None and self.module.params is not None:
            return self.module.params.get(param, default)
        return default


def remove_nulls(a):
    if isinstance(a, list):
        return [remove_nulls(i) for i in a]
    elif isinstance(a, dict):
        output = {}
        for key, value in a.items():
            if value and value != []:
                output[key] = remove_nulls(value)
        return output
    else:
        return a


def is_subset_of(a, b):
    for key, value in a.items():
        if key in b:
            if isinstance(a[key], dict):
                if not is_subset_of(a[key], b[key]):
                    return False
            elif isinstance(value, bool) and isinstance(b[key], str):
                if value != bool(b[key]):
                    return False
            elif isinstance(value, str) and isinstance(b[key], bool):
                if bool(value) != b[key]:
                    return False
            elif value != b[key]:
                return False
        else:
            return False
    return True


def merge(a, b): # TODO Review usage of builtin Ansible dict merge function
    a = remove_nulls(a)
    b = remove_nulls(b)
    for key, value in b.items():
        if key in a:
            if isinstance(a[key], dict):
                assert isinstance(value, dict)
                a[key] = merge(a[key], value)
            elif isinstance(a[key], list):
                assert isinstance(value, list)
                for i in value:
                    if not i in a[key]:
                        a[key].append(copy.deepcopy(i))
            else:
                a[key] = copy.deepcopy(value)
        else:
            a[key] = copy.deepcopy(value)
    return a


def list_difference(la, lb):
    la = remove_nulls(la)
    lb = remove_nulls(lb)
    return [a for a in la if a not in lb]


VALIDITY_SCHEDULE = dict(
    startTime=dict(required=True, type='str'),
    endTime=dict(required=True, type='str'),
    timeZone=dict(required=True, type='str'),
)


DATA_MASK_INFO = dict(
    dataMaskType=dict(required=True, type='str'),
    valueExpr=dict(required=False, type='str', default=None),
)


ROW_FILTER_INFO = dict(
    filterExpr=dict(required=True, type='str'),
)


ACCESS = dict(
    type=dict(required=True, type='str'),
    isAllowed=dict(required=False, type='bool', default=True),
)


BASE_POLICY_ITEM = dict(
    accesses=dict(required=True, type='list', elements='dict', options=ACCESS),
    users=dict(required=False, type='list', elements='str', default=[]),
    groups=dict(required=False, type='list', elements='str', default=[]),
    roles=dict(required=False, type='list', elements='str', default=[]),
)


POLICY_ITEM = dict(
    BASE_POLICY_ITEM,
    delegateAdmin=dict(required=False, type='bool', elements=False),
)


DATA_MASK_POLICY_ITEM = dict(
    POLICY_ITEM,
    dataMaskInfo=dict(required=True, type='dict', options=DATA_MASK_INFO),
)


ROW_FILTER_POLICY_ITEM = dict(
    BASE_POLICY_ITEM,
    rowFilterInfo=dict(required=True, type='dict', options=ROW_FILTER_INFO),
)


RESOURCE = dict(
    values=dict(required=True, type='list', elements='str'),
    isExcludes=dict(required=False, type='bool', elements=False),
    isRecursive=dict(required=False, type='bool', elements=False),
)


HIVE_RESOURCES = dict(
    column=dict(required=False, type='dict', options=RESOURCE),
    database=dict(required=False, type='dict', options=RESOURCE),
    table=dict(required=False, type='dict', options=RESOURCE),
)


KAFKA_RESOURCES = dict(
    cluster=dict(required=False, type='dict', options=RESOURCE),
    consumergroup=dict(required=False, type='dict', options=RESOURCE),
    delegationtoken=dict(required=False, type='dict', options=RESOURCE),
    topic=dict(required=False, type='dict', options=RESOURCE),
    transactionalid=dict(required=False, type='dict', options=RESOURCE),
)


SCHEMA_REGISTRY_RESOURCES = {
    'registry-service': dict(required=False, type='dict', options=RESOURCE),
    'schema-group': dict(required=False, type='dict', options=RESOURCE),
    'serde': dict(required=False, type='dict', options=RESOURCE),
    'export-import': dict(required=False, type='dict', options=RESOURCE),
}


RESOURCES = dict(
    **HIVE_RESOURCES,
    **KAFKA_RESOURCES,
    **SCHEMA_REGISTRY_RESOURCES,
)


POLICY = dict(
    name=dict(required=True, type='str'),
    policyType=dict(required=False, type='int', choices=[0, 1, 2], default=0),  # 0=access, 1=masking, 2=row_level
    policyPriority=dict(required=False, type='int', choices=[0, 1], default=0),  # 0=normal, 1=override
    policyLabels=dict(required=False, type='list', elements='str'),
    description=dict(required=False, type='str'),
    isAuditEnabled=dict(required=False, type='bool', default=True),  # if audit is false there must be at least
                                                                     # one policy item specified
    isDenyAllElse=dict(required=False, type='bool', default=False),
    resources=dict(required=False, type='dict', options=RESOURCES),
    policyItems=dict(required=False, type='list', elements='dict', options=POLICY_ITEM),
    denyPolicyItems=dict(required=False, type='list', elements='dict', options=POLICY_ITEM),
    allowExceptions=dict(required=False, type='list', elements='dict', options=POLICY_ITEM),
    denyExceptions=dict(required=False, type='list', elements='dict', options=POLICY_ITEM),
    dataMaskPolicyItems=dict(required=False, type='list', elements='dict', options=DATA_MASK_POLICY_ITEM),
    rowFilterPolicyItems=dict(required=False, type='list', elements='dict', options=ROW_FILTER_POLICY_ITEM),
    validitySchedules=dict(required=False, type='list', elements='dict', options=VALIDITY_SCHEDULE),
)


SERVICE = dict(
    name=dict(required=True, type='str'),
    type=dict(required=True, type='str'),
    displayName=dict(required=False, type='str'),
    description=dict(required=False, type='str'),
    tagService=dict(required=False, type='str'),
    configs=dict(required=False, type='dict'),
    policies=dict(required=False, type='list', elements='dict', options=POLICY),
)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            services=dict(required=True, type='list', elements='dict', options=SERVICE),

            force_deletion=dict(required=False, type='bool', default=False),
            policies_only=dict(required=False, type='bool', default=False),
            merge_policies=dict(required=False, type='bool', default=True),
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),

            endpoint=dict(required=True, type='str', aliases=['url']),
            username=dict(required=True, type='str', aliases=['user']),
            password=dict(required=True, type='str', no_log=True),
            verify_tls=dict(required=False, type='bool', default=True, aliases=['tls']),
            ca_cert_file=dict(required=False, type='str', aliases=['cert', 'truststore']),
            debug=dict(required=False, type='bool', default=False)
        ),
        supports_check_mode=True
    )

    result = Ranger(module)
    result.process()

    output = dict(
        changed=result.changed,
        policy=result.policy,
    )

    module.exit_json(**output)


if __name__ == '__main__':
    main()
