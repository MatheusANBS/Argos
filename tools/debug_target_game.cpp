#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include <atomic>
#include <mutex>
#include <algorithm>

struct Vec3 {
    float x, y, z;
};

struct Player {
    int32_t health;
    int32_t max_health;
    uint64_t score;
    Vec3 position;
    float rotation;
    bool is_alive;
    char name[32];
    int32_t level;
    float experience;
    uint32_t flags;
};

struct GameState {
    uint32_t magic;
    Player player;
    int32_t wave;
    int32_t enemies_killed;
    uint64_t session_id;
    bool paused;
    char map_name[64];
    Vec3 checkpoint;
    int32_t difficulty;
    float game_speed;
};

static GameState g_game_state;
static std::mutex g_state_mutex;
static std::atomic<bool> g_running{true};

constexpr uint32_t GAME_MAGIC = 0x47414D45;
constexpr const char* STATIC_PATTERN = "ARGOS-GAME-TARGET-2026!";

void initialize_game() {
    g_game_state.magic = GAME_MAGIC;
    g_game_state.player.health = 100;
    g_game_state.player.max_health = 100;
    g_game_state.player.score = 0;
    g_game_state.player.position = {0.0f, 0.0f, 0.0f};
    g_game_state.player.rotation = 0.0f;
    g_game_state.player.is_alive = true;
    strcpy_s(g_game_state.player.name, "DebugPlayer");
    g_game_state.player.level = 1;
    g_game_state.player.experience = 0.0f;
    g_game_state.player.flags = 0xDEADBEEF;
    
    g_game_state.wave = 1;
    g_game_state.enemies_killed = 0;
    g_game_state.session_id = 0xC0FFEE1234567890;
    g_game_state.paused = false;
    strcpy_s(g_game_state.map_name, "debug_arena");
    g_game_state.checkpoint = {100.0f, 50.0f, 25.0f};
    g_game_state.difficulty = 2;
    g_game_state.game_speed = 1.0f;
}

void print_memory_info() {
    std::cout << "========================================\n";
    std::cout << "ARGOS DEBUG TARGET GAME\n";
    std::cout << "========================================\n";
    std::cout << "PID: " << GetCurrentProcessId() << "\n";
    std::cout << "GameState address: 0x" << std::hex << reinterpret_cast<uintptr_t>(&g_game_state) << std::dec << "\n";
    std::cout << "Player address:    0x" << std::hex << reinterpret_cast<uintptr_t>(&g_game_state.player) << std::dec << "\n";
    std::cout << "Static pattern:    " << STATIC_PATTERN << "\n";
    std::cout << "Pattern address:   0x" << std::hex << reinterpret_cast<uintptr_t>(STATIC_PATTERN) << std::dec << "\n";
    std::cout << "Game Magic:        0x" << std::hex << GAME_MAGIC << std::dec << "\n";
    std::cout << "========================================\n";
    std::cout << "Attach with MCP server and use:\n";
    std::cout << "  memory_debug_attach --pid " << GetCurrentProcessId() << " --authorized true\n";
    std::cout << "  memory_debug_read --session-id <id> --address <Player address> --size 128\n";
    std::cout << "  memory_debug_scan_exact --session-id <id> --pattern-hex 4152474f532d47414d452d5441524745542d323032362100\n";
    std::cout << "========================================\n\n";
}

void print_status() {
    std::lock_guard<std::mutex> lock(g_state_mutex);
    std::cout << "\r[Wave " << g_game_state.wave 
              << "] HP: " << g_game_state.player.health << "/" << g_game_state.player.max_health
              << " | Score: " << g_game_state.player.score
              << " | Pos: (" << g_game_state.player.position.x 
              << ", " << g_game_state.player.position.y 
              << ", " << g_game_state.player.position.z << ")"
              << " | Kills: " << g_game_state.enemies_killed
              << " | Speed: " << g_game_state.game_speed << "x    " << std::flush;
}

void game_loop() {
    auto last_time = std::chrono::steady_clock::now();
    
    while (g_running) {
        auto now = std::chrono::steady_clock::now();
        float dt = std::chrono::duration<float>(now - last_time).count() * g_game_state.game_speed;
        last_time = now;
        
        {
            std::lock_guard<std::mutex> lock(g_state_mutex);
            if (!g_game_state.paused && g_game_state.player.is_alive) {
                g_game_state.player.position.x += 10.0f * dt;
                g_game_state.player.position.y = 50.0f + 10.0f * sinf(g_game_state.player.position.x * 0.1f);
                g_game_state.player.rotation += 45.0f * dt;
                if (g_game_state.player.rotation > 360.0f) g_game_state.player.rotation -= 360.0f;
                
                g_game_state.player.experience += 5.0f * dt;
                if (g_game_state.player.experience >= 100.0f) {
                    g_game_state.player.experience -= 100.0f;
                    g_game_state.player.level++;
                    g_game_state.player.max_health += 10;
                    g_game_state.player.health = g_game_state.player.max_health;
                }
                
                g_game_state.player.score += static_cast<uint64_t>(10 * dt);
                
                if (g_game_state.enemies_killed >= g_game_state.wave * 5) {
                    g_game_state.wave++;
                    g_game_state.enemies_killed = 0;
                    g_game_state.difficulty = std::min(5, g_game_state.difficulty + 1);
                }
                
                g_game_state.enemies_killed++;
            }
        }
        
        print_status();
        std::this_thread::sleep_for(std::chrono::milliseconds(16));
    }
}

void input_handler() {
    std::string cmd;
    while (g_running && std::getline(std::cin, cmd)) {
        std::lock_guard<std::mutex> lock(g_state_mutex);
        if (cmd == "quit" || cmd == "exit" || cmd == "q") {
            g_running = false;
        } else if (cmd == "pause" || cmd == "p") {
            g_game_state.paused = !g_game_state.paused;
            std::cout << "\nGame " << (g_game_state.paused ? "paused" : "resumed") << "\n";
        } else if (cmd == "hurt") {
            g_game_state.player.health = std::max(0, g_game_state.player.health - 10);
            if (g_game_state.player.health == 0) g_game_state.player.is_alive = false;
            std::cout << "\nPlayer hurt! HP: " << g_game_state.player.health << "\n";
        } else if (cmd == "heal") {
            g_game_state.player.health = g_game_state.player.max_health;
            g_game_state.player.is_alive = true;
            std::cout << "\nPlayer healed! HP: " << g_game_state.player.health << "\n";
        } else if (cmd == "kill") {
            g_game_state.enemies_killed += 5;
            std::cout << "\nEnemies killed!\n";
        } else if (cmd == "speed") {
            g_game_state.game_speed = (g_game_state.game_speed == 1.0f) ? 2.0f : 1.0f;
            std::cout << "\nGame speed: " << g_game_state.game_speed << "x\n";
        } else if (cmd == "tp") {
            g_game_state.player.position = g_game_state.checkpoint;
            std::cout << "\nTeleported to checkpoint\n";
        } else if (cmd == "help" || cmd == "h") {
            std::cout << "\nCommands: quit, pause, hurt, heal, kill, speed, tp, help\n";
        } else if (!cmd.empty()) {
            std::cout << "\nUnknown command. Type 'help' for list.\n";
        }
    }
}

int main() {
    SetConsoleOutputCP(CP_UTF8);
    initialize_game();
    print_memory_info();
    std::cout << "Commands: quit, pause, hurt, heal, kill, speed, tp, help\n\n";
    
    std::thread game_thread(game_loop);
    std::thread input_thread(input_handler);
    
    game_thread.join();
    input_thread.join();
    
    std::cout << "\nGame stopped.\n";
    return 0;
}