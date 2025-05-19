#include "db-general-request.hpp"

#include "../utils.hpp"
#include <chrono>
#include <sstream>

using namespace std;
namespace fwso::structs
{
    DbGeneralRequest::DbGeneralRequest(const optional<string>& whereClause,
            const std::optional<vector<string>>& selectColumns,
            const std::optional<vector<string>>& insertColumns,
            const std::optional<vector<string>>& insertValues,
            const std::optional<std::map<std::string,std::string>>& updateAssignments,
            const std::optional<int>& enforcerType) :
    WhereClause(whereClause), SelectColumns(selectColumns), InsertColumns(insertColumns),
    InsertValues(insertValues), UpdateAssignments(updateAssignments), EnforcerType(enforcerType){}

    string DbGeneralRequest::Serialize(Subject subject, Prototype prototype)
    {
        stringstream ss;
        string whereClause = WhereClause.value_or("null");
        string selectColumns = "null";
        string insertColumns = "null";
        string insertValues  = "null";
        string updateAssignments  = "null";
        string enforcerType = EnforcerType.has_value()? to_string(EnforcerType.value()) :"null";

        if (SelectColumns.has_value())
        {
            ss << "[";
            for (auto i=0; i < SelectColumns.value().size()-1; i++)
                ss << "\""
                   << SelectColumns.value()[i]
                   << "\",";
            ss << "\""
               << SelectColumns.value()[SelectColumns.value().size()-1]
               << "\"]";
            selectColumns = ss.str();
            ss.str("");
            ss.clear();
        }

        if (InsertColumns.has_value())
        {
            ss << "[";
            for (auto i=0; i < InsertColumns.value().size()-1; i++)
                ss << "\""
                   << InsertColumns.value()[i]
                   << "\",";
            ss << "\""
               << InsertColumns.value()[InsertColumns.value().size()-1]
               << "\"]";
            insertColumns = ss.str();
            ss.str("");
            ss.clear();
        }

        if (InsertValues.has_value())
        {
            ss << "[";
            for (auto i=0; i < InsertValues.value().size()-1; i++)
                ss << "\""
                   << InsertValues.value()[i]
                   << "\",";
            ss << "\""
               << InsertValues.value()[InsertValues.value().size()-1]
               << "\"]";
            insertValues = ss.str();
            ss.str("");
            ss.clear();
        }

        if (UpdateAssignments.has_value() && !UpdateAssignments->empty())
        {
            ss << "{";
            auto it = UpdateAssignments->begin();
            while (true) {
                ss << "\"" << it->first << "\":\"" << it->second << "\"";
                ++it;
                if (it == UpdateAssignments->end()) break;
                ss << ",";
            }
            ss << "}";
            updateAssignments = ss.str();
            ss.str("");
            ss.clear();
        }


        ss << "{\"WhereClause\":"
           <<  whereClause
           << ",\"SelectColumns\":"
           << selectColumns
           << ",\"InsertColumns\":"
           << insertColumns
           << ",\"InsertValues\":"
           << insertValues
           << ",\"UpdateAssignments\":"
           << updateAssignments
           << ",\"EnforcerType\":"
           << enforcerType
           << "}";

        string qArgs = ss.str();
        qArgs = utils::base64_encode(reinterpret_cast<const unsigned char*>(qArgs.c_str()),qArgs.length());
        ss.str("");
        ss.clear();
        ss << "{\"Prototype\":"
           << to_string(static_cast<const int>(prototype))
           << ",\"Subject\":"
           << to_string(static_cast<const int>(subject))
           << ",\"Arguments\":"
           << "\"" << qArgs << "\"}";
        string res = ss.str();
        res = utils::base64_encode(reinterpret_cast<const unsigned char*>(res.c_str()),res.length());
        return res;
    }
}

