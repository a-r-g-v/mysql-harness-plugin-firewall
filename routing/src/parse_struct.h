#ifndef PARSE_STRUCT_INCLUDED
#define PARSE_STRUCT_INCLUDED

#include <string>
#include <list>

using std::string;
using std::list;
class ParseStruct {
  public:
    string parse_struct(std::string sql_query);
  private:
    list<string> parse_query(std::string sql_query);
    int classed_token(std::string);
    string classed_to_string(int);
};
#endif
