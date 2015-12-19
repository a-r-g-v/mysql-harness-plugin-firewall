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
#include <list>
#include <regex>

#include <boost/algorithm/string.hpp>
#include <boost/foreach.hpp>

#include "parse_struct.h"


std::list<std::string> ParseStruct::parse_query(std::string sql_query) {
  std::list<std::string> sql_list;
  boost::split(sql_list, sql_query, boost::is_space());
  return sql_list;
}

std::string ParseStruct::classed_to_string(int classed){
  if (classed == 1)
    return "<d string>";
  else if (classed == 2)
    return "<s string>";
  else if (classed == 3)
    return "<integer>";
  else if (classed == 4)
    return "<function>";
  else if (classed == 5)
    return "<sub-query>";
  return "<unknown>";
}


int ParseStruct::classed_token(std::string token) {
  // string
  if ( token[0] == token[token.length() - 1] and token[0] == '\"') {
    return 1;
  }

  // string (ex 'a')
  if ( token[0] == token[token.length() - 1] and token[0] == '\'') {
    return 2;
  }

  // numeric
  std::regex integer("(\\+|-)?[[:digit:]]+");
  if ( std::regex_match(token, integer) ) {
    return 3;
  }


  // table name / row name
  return 0;
}

std::string ParseStruct::parse_struct(std::string sql_request){

  std::string result = "";
  std::list<std::string> sql_token_list = parse_query(sql_request);
  BOOST_FOREACH(std::string token, sql_token_list) {
    if (classed_token(token) == 0 ) {
      result +=  token + " ";
    }
    else {
     result += classed_to_string(classed_token(token)) + " ";
    }
  }
  return result;
}

