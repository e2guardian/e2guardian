#include "ListContainer.hpp"

#include <cstdio>
#include <fstream>
#include <iostream>

int main() {
    const char *filename = "phrase-list-escaped-greater-than-test.txt";
    {
        std::ofstream phrases(filename);
        phrases << "<Porn \\> Movies>\n";
        phrases << "<Porn Movies>\n";
    }

    ListContainer list;
    const bool read_ok = list.readPhraseList(filename, false);
    std::remove(filename);
    if (!read_ok) {
        std::cerr << "failed to read phrase-list fixture\n";
        return 1;
    }
    if (list.getListLength() != 2 || list.getItemAtInt(0) != "porn > movies" ||
        list.getItemAtInt(1) != "porn movies") {
        std::cerr << "escaped greater-than was not preserved as a phrase literal\n";
        return 1;
    }

    return 0;
}
