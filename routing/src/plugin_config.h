/*
  Copyright (c) 2015, Oracle and/or its affiliates. All rights reserved.

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef PLUGIN_CONFIG_ROUTING_INCLUDED
#define PLUGIN_CONFIG_ROUTING_INCLUDED

#include "utils.h"
#include "uri.h"
#include "mysqlrouter/datatypes.h"
#include "mysqlrouter/utils.h"
#include <mysqlrouter/routing.h>

#include <map>
#include <string>

#include "mysqlrouter/plugin_config.h"
#include "plugin.h"

using std::map;
using std::string;
using mysqlrouter::to_string;
using mysqlrouter::TCPAddress;

class RoutingPluginConfig final : public mysqlrouter::BasePluginConfig {
public:
  /** @brief Constructor
   *
   * @param section from configuration file provided as ConfigSection
   */
  RoutingPluginConfig(const ConfigSection *section)
      : BasePluginConfig(section),
        destinations(get_option_destinations(section, "destinations")),
        bind_port(get_option_tcp_port(section, "bind_port")),
        query_logfile_path(get_option_string(section, "query_logfile_path")),
        error_logfile_path(get_option_string(section, "error_logfile_path")),
        learn_file_path(get_option_string(section, "learn_file_path")),
        bind_address(get_option_tcp_address(section, "bind_address", false, bind_port)),
        connect_timeout(get_uint_option<uint16_t>(section, "connect_timeout", 1)),
        learn_mode(get_uint_option<uint16_t>(section, "learn_mode", 1)),
        blacklist_detection(get_uint_option<uint16_t>(section, "blacklist_detection", 1)),
        logging_query(get_uint_option<uint16_t>(section, "logging_query", 1)),
        blacklist_wordlist_path(get_option_string(section, "blacklist_wordlist_path")),
        fill_error_message(get_uint_option<uint16_t>(section, "fill_error_message", 1)),
        mode(get_option_mode(section, "mode")),
        max_connections(get_uint_option<uint16_t>(section, "max_connections", 1)) {
  }

  string get_default(const string &option);

  bool is_required(const string &option);

  /** @brief `destinations` option read from configuration section */
  const string destinations;
  /** @brief `bind_port` option read from configuration section */
  const int bind_port;
  /** @brief `bind_address` option read from configuration section */
  const TCPAddress bind_address;
  /** @brief `connect_timeout` option read from configuration section */
  const int connect_timeout;
  /** @brief `mode` option read from configuration section */
  const routing::AccessMode mode;
  /** @brief `max_connections` option read from configuration section */
  const int max_connections;

  string query_logfile_path;
  string error_logfile_path;
  string learn_file_path;
  string blacklist_wordlist_path;

  int learn_mode;
  int logging_query;
  int fill_error_message;
  int blacklist_detection;



protected:

private:
  routing::AccessMode get_option_mode(const ConfigSection *section, const string &option);
  string get_option_destinations(const ConfigSection *section, const string &option);
};

#endif // PLUGIN_CONFIG_ROUTING_INCLUDED
