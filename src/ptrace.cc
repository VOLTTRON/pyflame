// Copyright 2016 Uber Technologies, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "./ptrace.h"

#include <dirent.h>
#include <cassert>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <utility>
#include <vector>

#include <capstone/capstone.h>

#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "./exc.h"

namespace pyflame {

void PtraceAttach(pid_t pid) {
  if (ptrace(PTRACE_ATTACH, pid, 0, 0)) {
    std::ostringstream ss;
    ss << "Failed to attach to PID " << pid << ": " << strerror(errno);
    throw PtraceException(ss.str());
  }
  int status;
  if (waitpid(pid, &status, __WALL) != pid || !WIFSTOPPED(status)) {
    std::ostringstream ss;
    ss << "Failed to wait on PID " << pid << ": " << strerror(errno);
    throw PtraceException(ss.str());
  }
}

void PtraceDetach(pid_t pid) {
  if (ptrace(PTRACE_DETACH, pid, 0, 0)) {
    std::ostringstream ss;
    ss << "Failed to detach PID " << pid << ": " << strerror(errno);
    throw PtraceException(ss.str());
  }
}

struct user_regs_struct PtraceGetRegs(pid_t pid) {
  struct user_regs_struct regs;
  if (ptrace(PTRACE_GETREGS, pid, 0, &regs)) {
    std::ostringstream ss;
    ss << "Failed to PTRACE_GETREGS: " << strerror(errno);
    throw PtraceException(ss.str());
  }
  return regs;
}

void PtraceSetRegs(pid_t pid, struct user_regs_struct regs) {
  if (ptrace(PTRACE_SETREGS, pid, 0, &regs)) {
    std::ostringstream ss;
    ss << "Failed to PTRACE_SETREGS: " << strerror(errno);
    throw PtraceException(ss.str());
  }
}

void PtracePoke(pid_t pid, unsigned long addr, long data) {
  if (ptrace(PTRACE_POKEDATA, pid, addr, (void *)data)) {
    std::ostringstream ss;
    ss << "Failed to PTRACE_POKEDATA at " << reinterpret_cast<void *>(addr)
       << ": " << strerror(errno);
    throw PtraceException(ss.str());
  }
}

long PtracePeek(pid_t pid, unsigned long addr) {
  errno = 0;
  const long data = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
  if (data == -1 && errno != 0) {
    std::ostringstream ss;
    ss << "Failed to PTRACE_PEEKDATA at " << reinterpret_cast<void *>(addr)
       << ": " << strerror(errno);
    throw PtraceException(ss.str());
  }
  return data;
}

static void do_wait(pid_t pid) {
  int status;
  if (waitpid(pid, &status, 0) == -1) {
    std::ostringstream ss;
    ss << "Failed to waitpid(): " << strerror(errno);
    throw PtraceException(ss.str());
  }
  if (WIFSTOPPED(status)) {
    int signum = WSTOPSIG(status);
    if (signum != SIGTRAP) {
      std::ostringstream ss;
      ss << "Failed to waitpid(), unexpectedly got status: "
         << strsignal(signum);
      throw PtraceException(ss.str());
    }
  } else {
    std::ostringstream ss;
    ss << "Failed to waitpid(), unexpectedly got status: " << status;
    throw PtraceException(ss.str());
  }
}

void PtraceCont(pid_t pid) {
  if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) {
    std::ostringstream ss;
    ss << "Failed to PTRACE_CONT: " << strerror(errno);
    throw PtraceException(ss.str());
  }
  do_wait(pid);
}

void PtraceSingleStep(pid_t pid) {
  if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1) {
    std::ostringstream ss;
    ss << "Failed to PTRACE_SINGLESTEP: " << strerror(errno);
    throw PtraceException(ss.str());
  }
  do_wait(pid);
}

std::string PtracePeekString(pid_t pid, unsigned long addr) {
  std::ostringstream dump;
  unsigned long off = 0;
  while (true) {
    const long val = PtracePeek(pid, addr + off);

    // XXX: this can be micro-optimized, c.f.
    // https://graphics.stanford.edu/~seander/bithacks.html#ZeroInWord
    const std::string chunk(reinterpret_cast<const char *>(&val), sizeof(val));
    dump << chunk.c_str();
    if (chunk.find_first_of('\0') != std::string::npos) {
      break;
    }
    off += sizeof(val);
  }
  return dump.str();
}

std::unique_ptr<uint8_t[]> PtracePeekBytes(pid_t pid, unsigned long addr,
                                           size_t nbytes) {
  // align the buffer to a word size
  if (nbytes % sizeof(long)) {
    nbytes = (nbytes / sizeof(long) + 1) * sizeof(long);
  }
  std::unique_ptr<uint8_t[]> bytes(new uint8_t[nbytes]);

  size_t off = 0;
  while (off < nbytes) {
    const long val = PtracePeek(pid, addr + off);
    memmove(bytes.get() + off, &val, sizeof(val));
    off += sizeof(val);
  }
  return bytes;
}

#if defined(__amd64__) && ENABLE_THREADS
static csh capstone_handle = 0;
static cs_insn *insn = nullptr;

static int InitCapstone() {
  if (capstone_handle != 0) {
    return 0;
  }
  if (cs_open(CS_ARCH_X86, CS_MODE_64, &capstone_handle) != CS_ERR_OK) {
    return -1;
  }
  assert(cs_option(capstone_handle, CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK);
  insn = cs_malloc(capstone_handle);
  return 0;
}

static void FinalizeCapstone() {
  if (capstone_handle != 0) {
    cs_free(insn, 1);
    cs_close(&capstone_handle);
  }
}

long PtraceDecodeInterpHead(pid_t pid, unsigned long fn_addr) {
  assert(InitCapstone() == 0);

  uint64_t addr = fn_addr;
  size_t code_size = 16;
  const std::unique_ptr<uint8_t[]> bytes =
      PtracePeekBytes(pid, fn_addr, code_size);
  const uint8_t *bytes_loc = bytes.get();
  assert(cs_disasm_iter(capstone_handle, &bytes_loc, &code_size, &addr, insn));
  assert(insn->detail != nullptr);
  assert(strcmp(insn->mnemonic, "mov") == 0);
  const size_t mov_sz = insn->size;
  size_t disp = 0;
  for (size_t i = 0; i < insn->detail->x86.op_count; i++) {
    if (insn->detail->x86.operands[i].type == X86_OP_MEM) {
      disp = insn->detail->x86.operands[i].mem.disp;
      break;
    }
  }
  assert(disp);

  // sanity check that the next insn is a ret
  assert(cs_disasm_iter(capstone_handle, &bytes_loc, &code_size, &addr, insn));
  assert(strcmp(insn->mnemonic, "ret") == 0);

  return fn_addr + disp + mov_sz;
}
#endif

void PtraceCleanup(pid_t pid) {
  PtraceDetach(pid);
  FinalizeCapstone();
}

}  // namespace pyflame
