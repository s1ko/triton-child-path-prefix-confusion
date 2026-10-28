#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

namespace fs = std::filesystem;

struct Status {
  enum class Code { SUCCESS, INVALID_ARG };
  Status(Code code = Code::SUCCESS, std::string message = "")
      : code_(code), message_(std::move(message))
  {
  }
  static const Status Success;
  Code code_;
  std::string message_;
};
const Status Status::Success;

namespace vulnerable_r26_05 {
Status
IsChildPathEscapingParentPath(
    const std::string& child_path, const std::string& parent_path,
    bool* is_escaped)
{
  std::string absolute_child_path;
  std::string absolute_parent_path;
  try {
    absolute_child_path =
        std::filesystem::weakly_canonical(child_path).string();
  }
  catch (const std::exception& e) {
    return Status(
        Status::Code::INVALID_ARG,
        "Invalid path '" + child_path + "': " + e.what());
  }
  try {
    absolute_parent_path = std::filesystem::canonical(parent_path).string();
  }
  catch (const std::exception& e) {
    return Status(
        Status::Code::INVALID_ARG,
        "Nonexistent path '" + parent_path + "': " + e.what());
  }
  *is_escaped = absolute_child_path.rfind(absolute_parent_path, 0) != 0;
  return Status::Success;
}
}

namespace fixed_72f3d9b {
Status
IsChildPathEscapingParentPath(
    const std::string& child_path, const std::string& parent_path,
    bool* is_escaped)
{
  if (parent_path.empty() || child_path.empty()) {
    return Status(
        Status::Code::INVALID_ARG,
        "Parent path and child path must be non-empty");
  }
  std::string canonical_child_path;
  std::string canonical_parent_path;
  try {
    canonical_child_path = fs::weakly_canonical(child_path).string();
  }
  catch (const std::exception& ex) {
    return Status(
        Status::Code::INVALID_ARG,
        "Failed to canonicalize child path '" + child_path + "': " + ex.what());
  }
  try {
    canonical_parent_path = fs::canonical(parent_path).string();
  }
  catch (const std::exception& e) {
    return Status(
        Status::Code::INVALID_ARG, "Failed to canonicalize parent path '" +
                                       parent_path + "': " + e.what());
  }
  if (canonical_child_path.find(canonical_parent_path, 0) == 0 &&
      ((canonical_child_path.size() > canonical_parent_path.size() &&
        canonical_child_path[canonical_parent_path.size()] == '/') ||
       (canonical_child_path.size() == canonical_parent_path.size()))) {
    *is_escaped = false;
    return Status::Success;
  }
  *is_escaped = true;
  return Status::Success;
}
}

struct Row {
  std::string description;
  std::string child;
  bool expect_escaped;
};

template <typename F>
bool
Run(F fn, const std::string& child, const std::string& parent)
{
  bool escaped = false;
  fn(child, parent, &escaped);
  return escaped;
}

int
main()
{
  const fs::path root = fs::temp_directory_path() / "triton_child_path_diff";
  fs::remove_all(root);
  fs::create_directories(root / "models/foo/1");
  fs::create_directories(root / "models/foo_admin");
  fs::create_directories(root / "models/f");
  fs::create_directories(root / "models/bar");
  std::ofstream(root / "models/foo/labels.txt") << "cat\ndog\n";
  std::ofstream(root / "models/foo_admin/keys.txt") << "secret\n";

  const std::string parent = (root / "models/foo").string();
  const std::string base = parent + "/";

  const std::vector<Row> rows = {
      {"label inside model dir", base + "labels.txt", false},
      {"file in version subdirectory", base + "1/model.onnx", false},
      {"child equals parent", parent, false},
      {"sibling sharing the name prefix (foo_admin)",
       base + "../foo_admin/keys.txt", true},
      {"sibling with unrelated name (bar)", base + "../bar/keys.txt", true},
      {"parent of the model dir", base + "../", true},
      {"two levels up", base + "../../etc/passwd", true},
  };

  std::cout << "parent: " << parent << "\n\n";
  std::cout << "case                                           r26.05    "
               "72f3d9b   expected\n";
  int mismatches_vulnerable = 0;
  int mismatches_fixed = 0;
  for (const auto& row : rows) {
    const bool v = Run(vulnerable_r26_05::IsChildPathEscapingParentPath,
                       row.child, parent);
    const bool f = Run(fixed_72f3d9b::IsChildPathEscapingParentPath, row.child,
                       parent);
    mismatches_vulnerable += (v != row.expect_escaped);
    mismatches_fixed += (f != row.expect_escaped);
    std::string d = row.description;
    d.resize(46, ' ');
    std::cout << d << " " << (v ? "escaped " : "allowed ") << "  "
              << (f ? "escaped " : "allowed ") << "  "
              << (row.expect_escaped ? "escaped" : "allowed")
              << (v != row.expect_escaped ? "   <- r26.05 wrong" : "")
              << "\n";
  }
  std::cout << "\nmismatches r26.05: " << mismatches_vulnerable
            << ", mismatches 72f3d9b: " << mismatches_fixed << "\n";
  fs::remove_all(root);
  return mismatches_fixed == 0 ? 0 : 1;
}
