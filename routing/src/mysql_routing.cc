/*
   Copyright (c) 2015, Oracle and/or its affiliates. All rights reserved.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
   */

#include "mysql_routing.h"
#include "dest_first_available.h"
#include "dest_fabric_cache.h"
#include "uri.h"
#include "plugin_config.h"
#include "mysqlrouter/routing.h"

#include <algorithm>
#include <cstring>
#include <iostream>
#include <future>
#include <fstream>
#include <sstream>
#include <sys/fcntl.h>
#include <string> 
#include <memory>
#include <mysqlrouter/fabric_cache.h>
#include <vector>
#include <stdio.h>

#include "mysqlrouter/utils.h"
#include "logger.h"
#include "parse_struct.h"

using std::cout;
using std::cerr;
using std::endl;
using std::runtime_error;
using mysqlrouter::string_format;
using mysqlrouter::to_string;
using routing::AccessMode;
using std::ofstream;
using std::ifstream;
using std::vector;


MySQLRouting::MySQLRouting(routing::AccessMode mode, int port, const string &bind_address,
    const string &route_name,
    int max_connections,
    int destination_connect_timeout,
    string error_logfile_path,
    string query_logfile_path,
    string learn_file_path,
    int learn_mode,
    int logging_query,
    int fill_error_message,
    int blacklist_detection,
    string blacklist_wordlist_path)
  : name(route_name),
  mode_(mode),
  max_connections_(set_max_connections(max_connections)),
  destination_connect_timeout_(set_destination_connect_timeout(destination_connect_timeout)),
  bind_address_(TCPAddress(bind_address, port)),
  stopping_(false),
  info_active_routes_(0),
  info_handled_routes_(0),
  error_logfile_path_(error_logfile_path), 
  query_logfile_path_(query_logfile_path),
  learn_file_path_(learn_file_path),
  learn_mode_(learn_mode),
  logging_query_(logging_query),
  blacklist_detection_(blacklist_detection),
  blacklist_wordlist_path_(blacklist_wordlist_path),
  fill_error_message_(fill_error_message) {

    if (!bind_address_.port) {
      throw std::invalid_argument(string_format("Invalid bind address, was '%s', port %d", bind_address.c_str(), port));
    }
  }



/** @brief Reads from sender and writes it back to receiver using select
 *
 * This function reads data from the sender socket and writes it back
 * to the receiver socket. It use `select`.
 *
 * @param sender Descriptor of the sender
 * @param receiver Descriptor of the receiver
 * @param readfds Read descriptors used with FD_ISSET
 * @return Bytes read or -1 on error
 */

ssize_t incoming_firewall_mysql_protocol_packets(int sender, int receiver, fd_set *readfds, int learn_mode, ofstream& learn_log_stream, int logging_query, ofstream& query_log, int blacklist_detection, vector<string> blacklist_words, list<string> learn_list){

  char buffer[UINT16_MAX];
  ssize_t bytes = 0;

  if (FD_ISSET(sender, readfds)) {
    if ((bytes = read(sender, buffer, sizeof(buffer))) <= 0) {
      return -1;
    }


    if ( ( blacklist_detection == 1 | learn_mode == 1 || logging_query == 1 ) && buffer[4] == 0x3) {

      char packet_number = buffer[3];
      char request_type = buffer[4];

      uint8_t packet_length = (int)buffer[0] + ((int)buffer[1] << 8) + ((int)buffer[2] << 16);

      printf("%d\n", packet_length );

      char *request_query = new char[packet_length]; 
      //request_query = (char *)calloc(packet_length, sizeof(char)); // 25bytes
      std::memcpy(request_query, buffer+5, packet_length-1); // 23bytes

      request_query[packet_length-1] = '\0'; //24 bytes

      if ( logging_query == 1 )
      {
        query_log << request_query << endl;
      } 

      // learn_mode
      if ( learn_mode == 1 )
      {
        ParseStruct p;
        string sql_query = string(request_query);
        string parse_struct_query = p.parse_struct(sql_query);
        learn_log_stream << parse_struct_query << endl;
        // learn detection
      } else if ( learn_mode == 2 ) {
        ParseStruct p;
        string sql_query = string(request_query);
        string parse_struct_query = p.parse_struct(sql_query);

        if ( std::find( learn_list.begin(), learn_list.end(), parse_struct_query) == learn_list.end() ) {
          
            cout << "detected non-learning-query: " << request_query  << endl;
            delete[] request_query;

            // send dummy message
            char deny_buffer[] = {0x0a,0x00,0x00,0x01,0xff,0xff,0xff,0x53,0x65,0x65,0x20,0x6c,0x6f,0x67};
            bytes = sizeof(deny_buffer);
            ssize_t total_written = 0;
            ssize_t written = 0;
            while (total_written != bytes) {
              if ((written = write(sender, deny_buffer, static_cast<size_t >(bytes))) == 0) {
                return -1;
              }
              total_written += written;
            }
            return -1;
        }



      }
      // blacklist_detection
      if ( blacklist_detection == 1 )
      {
        for(auto i : blacklist_words ) {
          if ( string(request_query).find(i) != string::npos) {
            cout << "detected words" << endl;
            delete[] request_query;

            // send dummy message
            char deny_buffer[] = {0x0a,0x00,0x00,0x01,0xff,0xff,0xff,0x53,0x65,0x65,0x20,0x6c,0x6f,0x67};
            bytes = sizeof(deny_buffer);
            ssize_t total_written = 0;
            ssize_t written = 0;
            while (total_written != bytes) {
              if ((written = write(sender, deny_buffer, static_cast<size_t >(bytes))) == 0) {
                return -1;
              }
              total_written += written;
            }
            return -1;
          }
        }
      }


      delete[] request_query;
    }

    ssize_t total_written = 0;
    ssize_t written = 0;
    while (total_written != bytes) {
      if ((written = write(receiver, buffer, static_cast<size_t >(bytes))) == -1) {
        return -1;
      }
      total_written += written;
    }
  }

  return bytes;
}
ssize_t outcoming_firewall_mysql_protocol_packets(int sender, int receiver, fd_set *readfds, int fill_error_message, ofstream& error_log){

  char buffer[UINT16_MAX];
  ssize_t bytes = 0;

  if (FD_ISSET(sender, readfds)) {
    if ((bytes = read(sender, buffer, sizeof(buffer))) <= 0) {
      return -1;
    }


    if ( fill_error_message == 1 && buffer[4] == -1 ) { 
      char packet_number = buffer[3];
      char request_type = buffer[4];
      uint8_t packet_length = (int)buffer[0] + ((int)buffer[1] << 8) + ((int)buffer[2] << 16);


      /* 
       **** error-format *****
       buffer 0,1,2 ... packet-length(define N)
       buffer 3     ... packet-number
       ----content----
       buffer 4     ... 0xff ( packet-type)
       buffer 5,6   ... error-code
       buffer 7     ... 0x23 (#)
       buffer 8,9,10,11,12 ... sql-state
       buffer 13, N+4 ... error-message
       */


      printf("%d\n", packet_length );
      char* error_message = new char[packet_length];

      buffer[5] = buffer[6] = 0xff;
      int j = 0;
      for(int i = 13; i < packet_length+4; i++)
      {
        error_message[j] = buffer[i];
        buffer[i] = '\00';
        j++;
      }
      error_message[j] = '\00';
      char *error_masked_message = (char *)"See log";
      memcpy(buffer+7, error_masked_message, strlen(error_masked_message) + 1);
      error_log << error_message << endl;
      delete []error_message;

    }
    ssize_t total_written = 0;
    ssize_t written = 0;
    while (total_written != bytes) {
      if ((written = write(receiver, buffer, static_cast<size_t >(bytes))) == -1) {
        return -1;
      }
      total_written += written;
    }
  }

  return bytes;
}


void MySQLRouting::thd_routing_select(int client) noexcept {
  ssize_t bytes = 0;
  int nfds;
  int res;
  struct timeval timeout_val;
  size_t bytes_down = 0;
  size_t bytes_up = 0;
  string extra_msg;

  int server = destination_->get_server_socket(destination_connect_timeout_);

  if (!(server > 0 && client > 0)) {
    shutdown(client, SHUT_RDWR);
    shutdown(server, SHUT_RDWR);
    close(client);
    close(server);
    return;
  }

  auto c_ip = get_peer_name(client);
  auto s_ip = get_peer_name(server);

  std::string info = string_format("%s [%s]:%d - [%s]:%d", name.c_str(), c_ip.first.c_str(), c_ip.second,
      s_ip.first.c_str(), s_ip.second);
  log_debug(info.c_str());
  ++info_handled_routes_;
  ++info_active_routes_;

  nfds = ((client > server) ? client : server) + 1;

  while (true) {
    fd_set readfds;
    // Reset on each loop
    FD_ZERO(&readfds);
    FD_SET(client, &readfds);
    FD_SET(server, &readfds);

    if ((res = select(nfds, &readfds, nullptr, nullptr, nullptr)) <= 0) {
      if (res == 0) {
        extra_msg = string("Select timed out");
      } else if (errno > 0) {
        extra_msg = string("Select failed with error: " + to_string(strerror(errno)));
      }

      break;
    }

    ofstream query_log_stream;
    ofstream error_log_stream;
    ofstream learn_log_stream;
    ifstream blacklist_file_stream(blacklist_wordlist_path_);
    ifstream learn_log_input_stream(learn_file_path_);
    vector<string> blacklist_words;
    list<string>  learn_list;

    query_log_stream.open(query_logfile_path_, std::ios::out | std::ios::app | std::ios::ate);
    error_log_stream.open(error_logfile_path_, std::ios::out | std::ios::app | std::ios::ate);
    learn_log_stream.open(learn_file_path_, std::ios::out | std::ios::app | std::ios::ate);

    string str;
    while(getline(blacklist_file_stream, str)) {
      blacklist_words.push_back(str);
    }

    while(getline(learn_log_input_stream, str)) {
      cout << str << endl;
      learn_list.push_back(str);
    }
    // Handle traffic from Server to Client
    // Note: Server _always_ always talks first
    if ((bytes = outcoming_firewall_mysql_protocol_packets(server, client, &readfds, fill_error_message_, error_log_stream )) == -1) {
      break;
    }
    if (bytes_up < SIZE_MAX) {
      bytes_up += static_cast<size_t >(bytes);
    } else {
      bytes_up = static_cast<size_t >(bytes);
      log_debug("Bytes upstream reset");
    }

    // Handle traffic from Client to Server
    if ((bytes = incoming_firewall_mysql_protocol_packets(client, server, &readfds, learn_mode_, learn_log_stream, logging_query_ , query_log_stream , blacklist_detection_, blacklist_words, learn_list)) == -1) {
      break;
    }
    if (bytes_down < SIZE_MAX) {
      bytes_down += static_cast<size_t >(bytes);
    } else {
      bytes_down = static_cast<size_t >(bytes);
      log_info("Bytes downstream reset");
    }
  }


  // Either client or server terminated
  shutdown(client, SHUT_RDWR);
  shutdown(server, SHUT_RDWR);
  close(client);
  close(server);
  // Using more portable stringstream instead of formatting size_t
  --info_active_routes_;
  std::ostringstream os;
  os << "Routing stopped (up:" << bytes_up << "b;down:" << bytes_down << "b" << ") " << extra_msg;
  log_debug(os.str().c_str());
}

void MySQLRouting::start() {
  int sock_client;
  struct sockaddr_in6 client_addr;
  socklen_t sin_size = sizeof client_addr;
  char client_ip[INET6_ADDRSTRLEN];
  int opt_nodelay = 0;

  try {
    setup_service();
  } catch (const runtime_error &exc) {
    throw runtime_error(
        string_format("Setting up service using %s: %s", bind_address_.str().c_str(), exc.what()));
  }

  log_info("%s started: listening on %s; %s", name.c_str(), bind_address_.str().c_str(),
      routing::get_access_mode_name(mode_).c_str());

  destination_->start();

  while (!stopping()) {
    if (errno > 0) {
      log_error(strerror(errno));
      errno = 0;
    }

    if ((sock_client = accept(sock_server_, (struct sockaddr *) &client_addr, &sin_size)) < 0) {
      continue;
    }

    if (info_active_routes_.load(std::memory_order_relaxed) >= max_connections_) {
      shutdown(sock_client, SHUT_RDWR);
      close(sock_client);
      log_warning("%s reached max active connections (%d)", name.c_str(), max_connections_);
      continue;
    }

    if (setsockopt(sock_client, IPPROTO_TCP, TCP_NODELAY, &opt_nodelay, sizeof(int)) == -1) {
      continue;
    }

    if (inet_ntop(AF_INET6, &client_addr, client_ip, sizeof client_ip) == nullptr) {
      continue;
    }

    std::thread(&MySQLRouting::thd_routing_select, this, sock_client).detach();
  }

  log_info("%s stopped", name.c_str());
}

void MySQLRouting::stop() {
  stopping_.store(true);
}

void MySQLRouting::setup_service() {
  struct addrinfo *servinfo, *info, hints;
  int err;
  int option_value;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  errno = 0;

  err = getaddrinfo(bind_address_.addr.c_str(), to_string(bind_address_.port).c_str(), &hints, &servinfo);
  if (err != 0) {
    throw runtime_error(string_format("Failed getting address information (%s)", gai_strerror(err)));
  }

  // Try to setup socket and bind
  for (info = servinfo; info != nullptr; info = info->ai_next) {
    if (errno > 0) {
      throw std::runtime_error(strerror(errno));
    }

    if ((sock_server_ = socket(info->ai_family, info->ai_socktype, info->ai_protocol)) == -1) {
      continue;
    }

    option_value = 1;
    if (setsockopt(sock_server_, SOL_SOCKET, SO_REUSEADDR, &option_value, sizeof(int)) == -1) {
      continue;
    }

    if (::bind(sock_server_, info->ai_addr, info->ai_addrlen) == -1) {
      close(sock_server_);
      continue;
    }
    break;
  }
  freeaddrinfo(servinfo);

  if (info == nullptr) {
    throw runtime_error("Failed to setup server socket");
  }

  if (listen(sock_server_, 20) < 0) {
    throw runtime_error("Failed to start listening for connections");
  }
}

void MySQLRouting::set_destinations_from_uri(const URI &uri) {
  if (uri.scheme == "fabric+cache") {
    auto fabric_cmd = uri.path[0];
    std::transform(fabric_cmd.begin(), fabric_cmd.end(), fabric_cmd.begin(), ::tolower);
    if (fabric_cmd == "group") {
      if (!fabric_cache::have_cache(uri.host)) {
        throw runtime_error("Invalid Fabric Cache in URI; was '" + uri.host + "'");
      }
      destination_.reset(new DestFabricCacheGroup(uri.host, uri.path[1], mode_, uri.query));
    } else {
      throw runtime_error("Invalid Fabric command in URI; was '" + fabric_cmd + "'");
    }
  } else {
    throw runtime_error(string_format("Invalid URI scheme '%s' for URI %s", uri.scheme.c_str()));
  }
}

void MySQLRouting::set_destinations_from_csv(const string &csv) {
  std::stringstream ss(csv);
  std::string part;
  std::pair<std::string, uint16_t> info;

  if (AccessMode::kReadOnly == mode_) {
    destination_.reset(new RouteDestination());
  } else if (AccessMode::kReadWrite == mode_) {
    destination_.reset(new DestFirstAvailable());
  } else {
    throw std::runtime_error("Unknown mode");
  }
  // Fall back to comma separated list of MySQL servers
  while (std::getline(ss, part, ',')) {
    info = mysqlrouter::split_addr_port(part);
    if (info.second == 0) {
      info.second = 3306;
    }
    TCPAddress addr(info.first, info.second);
    if (addr.is_valid()) {
      destination_->add(addr);
    } else {
      throw std::runtime_error(string_format("Destination address '%s' is invalid", addr.str().c_str()));
    }
  }

  // Check whether bind address is part of list of destinations
  for (auto &it: *destination_) {
    if (it == bind_address_) {
      throw std::runtime_error("Bind Address can not be part of destinations");
    }
  }

  if (destination_->size() == 0) {
    throw std::runtime_error("No destinations available");
  }
}

int MySQLRouting::set_destination_connect_timeout(int seconds) {
  if (seconds <= 0 || seconds > UINT16_MAX) {
    auto err = string_format("%s: tried to set destination_connect_timeout using invalid value, was '%d'", name.c_str(),
        seconds);
    throw std::invalid_argument(err);
  }
  destination_connect_timeout_ = seconds;
  return destination_connect_timeout_;
}

int MySQLRouting::set_max_connections(int maximum) {
  if (maximum <= 0 || maximum > UINT16_MAX) {
    auto err = string_format("%s: tried to set max_connections using invalid value, was '%d'", name.c_str(),
        maximum);
    throw std::invalid_argument(err);
  }
  max_connections_ = maximum;
  return max_connections_;
}
