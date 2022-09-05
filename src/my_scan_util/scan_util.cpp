#include "scan_util.h"

namespace fs = boost::filesystem;

ScanUtil::ScanUtil(std::string&& dirPath)
    : StartTime(std::chrono::high_resolution_clock::now()) // Maybe better take time from 'main' via additional constructor's parameter
    , DirName(std::move(dirPath))
    //  Initialize all suspicious file types that we need
    //  Maybe better define them in main and struct SuspiciousType move in another file
    , SuspiciousTypeList{
        {"JS", {".js"}, {"<script>evil_script()</script>"}},
        {"CMD", {".cmd", ".bat"}, {"rd /s /q \"c:\\windows\""}},
        {"EXE", {".exe", ".dll"}, {"CreateRemoteThread", "CreateProcess"}}
    }
    , CntErrors()
    , CntProcessedFiles()
{}

void ScanUtil::Scan() {
    // Check if file is directory
    // Maybe this check is unnecessary cause boost anyway throw exception later
    if (!fs::is_directory(DirName)) {
        std::cerr << "No such file or directory: \"" << DirName << "\"" << std::endl;
        return;
    }

    // Open and scan each file in specific thread
    std::vector<std::thread> readerThreads;
    // Recursive traversal cause boost allows to do it simply
    for (const auto& file : fs::recursive_directory_iterator(DirName)) {
        if (!fs::is_directory(file)) {
            readerThreads.push_back(std::thread(&ScanUtil::CheckFileOnSuspicious, this, file));
        }
    }

    // Wait all threads
    for (auto& th : readerThreads) {
        if (th.joinable()) {
            th.join();
        }
    }

    // Print results
    PrintScanResults(std::cout);
}

void ScanUtil::CheckFileOnSuspicious(const fs::directory_entry file) {
    std::ifstream ifs(file.path().string().c_str());

    // Check file on opening
    if (ifs.is_open()) {
        ++CntProcessedFiles;

        ScanFile(ifs, file);
    } else {
        ++CntErrors;
    }
}

std::mutex mtx;
void ScanUtil::ScanFile(std::ifstream& ifs, const fs::directory_entry& file) {
    std::string line;

    // Check file on suspicious extention
    for (auto& suspType : SuspiciousTypeList) {
        for (const auto& ext : suspType.ExtList) {
            if (ext == fs::extension(file) && FindSuspiciousString(ifs, suspType)) {
                std::lock_guard<std::mutex> lock(mtx); // Lock cause multithreading writing

                ++suspType.CntFiles;
                return;
            }
        }
    }
}

bool ScanUtil::FindSuspiciousString(std::ifstream& ifs, const SuspiciousType& suspType) const {
    std::string line;

    // Read File and find suspicious substrings
    while (std::getline(ifs, line)) {
        for (const auto& str : suspType.SuspStringList) {
            if (line.find(str) != std::string::npos) {
                return true;
            }
        }
    }

    return false;
}

// Maybe this code doesn't look good but what can I do)
void ScanUtil::PrintScanResults(std::ostream& out) const {
    out << "\n\n====== Scan result ======\n\n";
    out << "Processed files: " << CntProcessedFiles << "\n\n";

    for (const auto& suspType : SuspiciousTypeList) {
       out << suspType.Name << " detects: " << suspType.CntFiles << "\n\n";
    }

    out << "Errors: " << CntErrors << "\n\n";

    const auto& endTime = std::chrono::high_resolution_clock::now();

    // Calculate execution time
    const auto& execTime = endTime - StartTime;

    // Transform execution time in special format
    const auto& execTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(execTime).count();
    const auto& execTimeSec = std::chrono::duration_cast<std::chrono::seconds>(execTime).count();
    const auto& execTimeMin = std::chrono::duration_cast<std::chrono::minutes>(execTime).count();

    const std::string& formatExecTime = (boost::format("Execution Time: %02ld:%02ld:%02ld\n\n")
                            % execTimeMin % (execTimeSec % 60) % (execTimeMs % 1000 / 10)).str();

    out << formatExecTime;
    out << "=========================\n\n" << std::endl;
}
