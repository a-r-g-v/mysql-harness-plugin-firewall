#include "plugin.h"
#include "config_parser.h"


#include <algorithm>
#include <atomic>
#include <cassert>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <map>
#include <sstream>
#include <string>
#include <thread>
#include <iostream>

static int init(const AppInfo* info){
  std::cout << "Yo" << std::endl;
  
  if (info && info->config) {
    auto sections = info->config->get("test");
    if (sections.size() != 1) {
      throw std::invalid_argument("Section [test] can only appear once");
    }
}
  return 0;
}



Plugin firewall = {
  PLUGIN_ABI_VERSION,
  ARCHITECTURE_DESCRIPTOR,
  "MySQL Router firewall", 
  VERSION_NUMBER(0,0,1),
  0, NULL,                                      // Requires
  0, NULL,                                      // Conflicts
  init,
  NULL,
  NULL                                          // start
};
