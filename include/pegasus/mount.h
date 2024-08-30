#pragma once
#include "pegasus/runtime.h"

namespace pegasus {
struct USwitchContext;
void init_mount(const std::shared_ptr<USwitchContext> &ucontext,
                const ProgramConfiguration &pc, int *terminal_fds);
}