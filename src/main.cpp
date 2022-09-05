#include <iostream>
#include "my_scan_util/scan_util.h"

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Error!\n Please choose directory!" << std::endl;
        return 0;
    }

    // Take only second parameter (first after the program name)
    ScanUtil scanner(argv[1]);
    scanner.Scan();

    return 0;
}
