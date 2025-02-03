# Ansible Collection - cloudera.runtime

Documentation for the collection.

# Action Plugins

## cm_api

Wraps the `uri` module to work with the Cloudera Manager REST endpoint. 

The action requires the following:

| Parameter | Description |
| --- | --- |
| `cloudera_manager_url` | Cloudera Manager service |
| `cloudera_manager_api_user` | Endpoint user |
| `cloudera_manager_api_password` | Endpoint user password |
| `cloudera_manager_tls_validate_certs` | If `true`, will fail if unable to validate the endpoint's TLS certificates |
| `endpoint` | The service path for the REST endpoint |

Optionally, you can use the following:

| Parameter | Description | Default |
| --- | --- | --- |
| `method` | The HTTP method | `GET` |
| `status_code` | The expected response | `200` |
| `body` | Body payload in JSON/YAML | |

The action will automatically poll the endpoint for completion if the response returns an active ApiCommand.

### Examples

```yaml
- name: Test the Cloudera Manager API Action plugin
  hosts: localhost
  connection: local
  vars:
    cloudera_manager_url: https://cm.example.com:7183
    cloudera_manager_api_user: admin
    cloudera_manager_api_password: admin
    cloudera_manager_tls_validate_certs: false
  tasks:
    - name: Get the version of Cloudera Manager
      cloudera.runtime.cm_api:
        endpoint: /cm/version
      register: cm_version_response
    - name: Debug the response
      debug:
        var: cm_version_response
```

The above returns:
```json
{
    "cm_version_response": {
        "cache_control": "no-cache, no-store, max-age=0, must-revalidate",
        "changed": false,
        "connection": "close",
        "content": "{\n  \"version\" : \"7.1.1\",\n  \"buildUser\" : \"jenkins\",\n  \"buildTimestamp\" : \"20200521-0113\",\n  \"gitHash\" : \"d29acfa5859a1099425944ed9783bbfd82a6b8dc\",\n  \"snapshot\" : false\n}",
        "content_type": "application/json;charset=utf-8",
        "cookies": {
            "SESSION": "15d5d707-653b-468d-9913-d22b3da78035"
        },
        "cookies_string": "SESSION=15d5d707-653b-468d-9913-d22b3da78035",
        "date": "Tue, 30 Jun 2020 21:59:48 GMT",
        "elapsed": 0,
        "expires": "Thu, 01 Jan 1970 00:00:00 GMT",
        "failed": false,
        "json": {
            "buildTimestamp": "20200521-0113",
            "buildUser": "jenkins",
            "gitHash": "d29acfa5859a1099425944ed9783bbfd82a6b8dc",
            "snapshot": false,
            "version": "7.1.1"
        },
        "msg": "OK (unknown bytes)",
        "pragma": "no-cache",
        "redirected": false,
        "set_cookie": "SESSION=15d5d707-653b-468d-9913-d22b3da78035;Path=/;Secure;HttpOnly",
        "status": 200,
        "strict_transport_security": "max-age=31536000 ; includeSubDomains",
        "url": "https://cm.example.com:7183/api/v41/cm/version",
        "x_content_type_options": "nosniff",
        "x_frame_options": "DENY",
        "x_xss_protection": "1; mode=block"
    }
}
```

An example of PUT'ing a payload (from the `cloudera.cdp_dc.cloudera_manager.config` role):

```yaml
- name: Update configuration (via Cloudera Manager API)
  cm_api:
    endpoint: "{{ api_config_endpoint }}"
    body: "{{ lookup('template', 'config.j2', convert_data=False) }}"
    method: PUT
  register: response
  when: api_configs is mapping
```

Or POST'ing a payload (from the `cloudera.cdp_dc.cloudera_manager.license` role):
```yaml
- name: Begin Cloudera Manager trial license
  cm_api:
    endpoint: /cm/trial/begin
    method: POST
    status_code: 200,204
  ignore_errors: True
```

## Getting Involved

See the [Contributing Document](./CONTRIBUTING.md).

## License and Copyright

Copyright 2021, Cloudera, Inc.

```
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```