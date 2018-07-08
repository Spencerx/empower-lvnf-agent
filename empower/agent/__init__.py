#!/usr/bin/env python3
#
# Copyright (c) 2016 Roberto Riggio
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.

"""EmPOWER Agent Package."""

PT_VERSION = 0

# ctrl to self
PT_BYE = "bye"
PT_REGISTER = "register"
PT_LVNF_JOIN = "lvnf_join"
PT_LVNF_LEAVE = "lvnf_leave"

# cpp to ctrl
PT_HELLO = "hello"
PT_CAPS_RESPONSE = "caps_response"
PT_ADD_LVNF_RESPONSE = "add_lvnf_response"
PT_DEL_LVNF_RESPONSE = "del_lvnf_response"
PT_LVNF_STATS_RESPONSE = "lvnf_stats_response"
PT_LVNF_GET_RESPONSE = "lvnf_get_response"
PT_LVNF_SET_RESPONSE = "lvnf_set_response"
PT_LVNF_STATUS_RESPONSE = "lvnf_status_response"

# ctrl to cpp
PT_CAPS_REQUEST = "caps_request"
PT_ADD_LVNF = "add_lvnf"
PT_DEL_LVNF = "del_lvnf"
PT_LVNF_STATS_REQUEST = "lvnf_stats_request"
PT_LVNF_GET_REQUEST = "lvnf_get_request"
PT_LVNF_SET_REQUEST = "lvnf_set_request"
PT_LVNF_STATUS_REQUEST = "lvnf_status_request"
