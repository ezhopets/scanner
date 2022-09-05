#include <iostream>
#include <atomic>
#include <fstream>
#include <string>
#include <thread>
#include <vector>
#include <boost/filesystem.hpp>
#include <boost/chrono.hpp>
#include <boost/format.hpp>
#include <mutex>


class ScanUtil {
public:
    ScanUtil(std::string&&);
    void Scan();

private:
    // Struct which contains info of suspicious file type
    // Maybe better to define it in another file
    struct SuspiciousType {
        const std::string Name;
        const std::vector<std::string> ExtList;
        const std::vector<std::string> SuspStringList;
        std::uint64_t CntFiles;
    };

    void CheckFileOnSuspicious(const boost::filesystem::directory_entry);
    void ScanFile(std::ifstream&, const boost::filesystem::directory_entry&);
    bool FindSuspiciousString(std::ifstream&, const SuspiciousType&) const;
    void PrintScanResults(std::ostream&) const;

private:
    const std::chrono::high_resolution_clock::time_point StartTime; // To get at the end execution time
    const std::string DirName;
    std::vector<SuspiciousType> SuspiciousTypeList; // List of all suspicious file types
    std::atomic_uint64_t CntErrors;
    std::atomic_uint64_t CntProcessedFiles;
};
