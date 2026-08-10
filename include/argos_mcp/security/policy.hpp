#pragma once

#include "argos_mcp/domain/types.hpp"

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace argos::security {

struct SecurityPolicy {
    bool allow_write{false};
    bool allow_foreign_user{false};
    std::size_t max_read_bytes{64U * 1024U};
    std::size_t max_write_bytes{4U * 1024U};
    std::size_t max_scan_bytes{32U * 1024U * 1024U};
    std::size_t max_scan_results{256U};
    std::size_t max_string_result_length{256U};
    std::size_t max_scan_session_candidates{262144U};
    std::size_t max_scan_sessions_per_session{4U};
    std::size_t max_pointer_chain_depth{8U};
    std::size_t max_pointer_chain_fanout{16U};
    bool allow_launch{false};
    std::vector<std::string> launch_allowed_dirs;
    std::size_t max_launched_processes{4U};
    std::size_t max_captured_output_bytes{1U * 1024U * 1024U};

    [[nodiscard]] static SecurityPolicy from_environment();

    [[nodiscard]] domain::Result<void> authorize_attach(
        bool user_acknowledged,
        domain::AccessMode access
    ) const;

    [[nodiscard]] domain::Result<void> authorize_read(std::size_t size) const;

    [[nodiscard]] domain::Result<void> authorize_write(
        std::size_t size,
        std::string_view confirmation
    ) const;

    [[nodiscard]] domain::Result<void> authorize_scan(
        std::size_t byte_budget,
        std::size_t result_limit
    ) const;

    [[nodiscard]] domain::Result<void> authorize_scan_session(
        std::size_t byte_budget,
        std::size_t result_limit
    ) const;

    [[nodiscard]] domain::Result<void> authorize_pointer_chain_scan(
        std::size_t byte_budget,
        std::size_t result_limit,
        std::size_t max_depth,
        std::size_t max_fanout
    ) const;

    [[nodiscard]] domain::Result<void> authorize_launch(
        bool user_acknowledged,
        std::string_view executable_path
    ) const;
};

}  // namespace argos::security
