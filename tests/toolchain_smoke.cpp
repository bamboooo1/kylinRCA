#include <iostream> 
#include <optional>
#include <string>

int main()
{
    std::optional<std::string> message = "C++17 toolchain OK";

    if (message) {
        std::cout << *message << std::endl;
    }

    return 0;
}
