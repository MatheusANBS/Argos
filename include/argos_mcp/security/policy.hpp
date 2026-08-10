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

    // Spec 0008 -- async scan jobs (AnalysisJobManager). Every limit here is a
    // hard cap the client cannot raise: a requested execution limit is only
    // ever reduced to fit inside these, never extended.
    std::size_t max_async_jobs_total{64U};
    std::size_t max_async_jobs_per_session{8U};
    std::size_t max_async_queue_depth{32U};
    std::size_t max_async_workers{2U};
    std::size_t max_async_job_byte_budget{256U * 1024U * 1024U};
    std::size_t max_async_job_deadline_ms{600'000U};
    std::size_t max_async_job_result_items{4096U};
    std::size_t max_async_results_retained_bytes{64U * 1024U * 1024U};
    std::size_t async_results_ttl_ms{300'000U};
    std::size_t async_tombstone_ttl_ms{60'000U};

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

    // Clamps a client-requested async job byte_budget/deadline down to the
    // server hard caps (never up) and rejects a zero/absent value. Does not
    // check queue/job-count backpressure -- AnalysisJobManager owns that
    // because it requires the current registry state, not just the policy.
    [[nodiscard]] domain::Result<std::size_t> clamp_async_byte_budget(
        std::optional<std::size_t> requested
    ) const;

    [[nodiscard]] domain::Result<std::size_t> clamp_async_deadline_ms(
        std::optional<std::size_t> requested
    ) const;
};

}  // namespace argos::security
