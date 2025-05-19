#ifndef DB_GENERAL_REQUEST_HPP
#define DB_GENERAL_REQUEST_HPP

#include "enums.hpp"
#include <string>
#include <vector>
#include <optional>
#include <map>

namespace fwso::structs
{
    class DbGeneralRequest
    {
    private:
        std::optional<std::string> WhereClause;
        std::optional<std::vector<std::string>> SelectColumns;
        std::optional<std::vector<std::string>> InsertColumns;
        std::optional<std::vector<std::string>> InsertValues;
        std::optional<std::map<std::string, std::string>> UpdateAssignments;
        std::optional<int> EnforcerType;
    public:

        DbGeneralRequest(const std::optional<std::string>& whereClause,
            const std::optional<std::vector<std::string>>& selectColumns,
            const std::optional<std::vector<std::string>>& insertColumns,
            const std::optional<std::vector<std::string>>& insertValues,
            const std::optional<std::map<std::string,std::string>>& updateAssignments,
            const std::optional<int>& enforcerType);

        std::string Serialize(Subject subject, Prototype prototype);

    };
}


#endif //DB_GENERAL_REQUEST_HPP
