/**
 * ChatHistoryPlus - helpers with no Ashita dependency, so tests/chathistoryplus_test.cpp compiles them.
 *
 * ThreadFreeze / whenNoThreadIn: every other thread of the process suspended, and a check that none of them is inside
 * a span of code about to change. Same design as truefps's patch.h (2026-09-14): threads are walked with
 * NtGetNextThread (no allocation: a suspended thread may hold the heap lock) until a pass finds nothing new, and
 * anything that cannot be established makes the freeze incomplete, which counts as "a thread might be there".
 *
 * chp_fit: how many of a page's newest records fit the stock layout when the plugin hands the page back.
 */
#pragma once

#include <windows.h>
#include <cstdio>
#include <cstdint>

namespace chp
{
    // A span of code no other thread may be running while bytes in it change: [lo, hi).
    struct CodeRange { uintptr_t lo = 0, hi = 0; };

    class ThreadFreeze
    {
    public:
        ThreadFreeze()
        {
            using NextThreadFn = LONG(NTAPI*)(HANDLE, HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE);
            static const auto nextThread = reinterpret_cast<NextThreadFn>(
                GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtGetNextThread"));
            if (!nextThread) { complete_ = false; failStep_ = "NtGetNextThread missing"; return; }
            const DWORD self = GetCurrentThreadId();
            const ACCESS_MASK access = THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_LIMITED_INFORMATION;
            bool settled = false;
            for (int pass = 0; pass < kMaxPasses && complete_; pass++)
            {
                bool added = false;
                HANDLE current = nullptr;
                for (;;)
                {
                    HANDLE next = nullptr;
                    const LONG status = nextThread(GetCurrentProcess(), current, access, 0, 0, &next);
                    if (current) CloseHandle(current);
                    current = nullptr;
                    if (status == LONG(0x8000001A)) break;                  // STATUS_NO_MORE_ENTRIES
                    if (status < 0 || !next) { complete_ = false; failStep_ = "walk"; failErr_ = DWORD(status); break; }
                    const DWORD id = GetThreadId(next);
                    if (id == self || holds(id)) { current = next; continue; }
                    if (count_ == kMaxThreads) { current = next; complete_ = false; failStep_ = "too many threads"; break; }
                    // An exited thread whose object another handle keeps alive is still walked, and SuspendThread refuses it (access denied, measured in pol.exe 2026-09-14 by freezeprobe). It runs nothing: skip it.
                    { DWORD code = 0; if (GetExitCodeThread(next, &code) && code != STILL_ACTIVE) { current = next; continue; } }
                    if (SuspendThread(next) == DWORD(-1)) { DWORD code = 0; if (GetExitCodeThread(next, &code) && code != STILL_ACTIVE) { current = next; continue; } current = next; complete_ = false; failStep_ = "SuspendThread"; failTid_ = id; failErr_ = GetLastError(); break; }
                    Thread& t = threads_[count_++];
                    t.id = id;
                    t.handle = next;
                    CONTEXT context{};
                    context.ContextFlags = CONTEXT_CONTROL;                 // also waits for the suspension to take effect
                    t.ipKnown = GetThreadContext(next, &context) != FALSE;
                if (!t.ipKnown) { t.ctxErr = GetLastError(); ++unknown_; }
                    t.ip = t.ipKnown ? uintptr_t(context.Eip) : 0;
                    added = true;
                    if (!DuplicateHandle(GetCurrentProcess(), next, GetCurrentProcess(), &current, 0, FALSE, DUPLICATE_SAME_ACCESS))
                    { complete_ = false; failStep_ = "DuplicateHandle"; failErr_ = GetLastError(); break; }
                }
                if (current) CloseHandle(current);
                if (complete_ && !added) { settled = true; break; }
            }
            if (!settled) { complete_ = false; if (!failStep_) failStep_ = "not settled"; }
        passes_ = 0;
        }
        ~ThreadFreeze()
        {
            for (size_t i = 0; i < count_; i++) { ResumeThread(threads_[i].handle); CloseHandle(threads_[i].handle); }
        }
        ThreadFreeze(const ThreadFreeze&) = delete;
        ThreadFreeze& operator=(const ThreadFreeze&) = delete;

        // True if any suspended thread not in `skip` has its instruction pointer in one of `ranges`, or might (an
        // unread pointer, or an incomplete freeze). `skip` is for the plugin's own worker threads.
        bool anyInRanges(const CodeRange* ranges, size_t n, const DWORD* skip = nullptr, size_t skipCount = 0) const
        {
            if (!complete_) return true;
            for (size_t i = 0; i < count_; i++)
            {
                bool skipped = false;
                for (size_t k = 0; k < skipCount && !skipped; k++) skipped = skip[k] != 0 && skip[k] == threads_[i].id;
                if (skipped) continue;
                if (!threads_[i].ipKnown) return true;
                for (size_t r = 0; r < n; r++)
                    if (threads_[i].ip >= ranges[r].lo && threads_[i].ip < ranges[r].hi) return true;
            }
            return false;
        }
        bool complete() const { return complete_; }
        // Why the last check said "busy": for the log. No allocation.
        void describe(char* out, size_t size, const CodeRange* ranges, size_t n, const DWORD* skip = nullptr, size_t skipCount = 0) const
        {
            int len = _snprintf_s(out, size, _TRUNCATE, "freeze %s (%s tid %lu err %lu), %u threads, %u without a readable context; in range:",
                                  complete_ ? "complete" : "INCOMPLETE", failStep_ ? failStep_ : "-", static_cast<unsigned long>(failTid_),
                                  static_cast<unsigned long>(failErr_), unsigned(count_), unsigned(unknown_));
            for (size_t i = 0; i < count_ && len > 0 && size_t(len) < size; i++)
            {
                bool skipped = false;
                for (size_t k = 0; k < skipCount && !skipped; k++) skipped = skip[k] != 0 && skip[k] == threads_[i].id;
                if (skipped) continue;
                bool hit = !threads_[i].ipKnown;
                for (size_t r = 0; r < n && !hit; r++) hit = threads_[i].ip >= ranges[r].lo && threads_[i].ip < ranges[r].hi;
                if (!hit) continue;
                const int added = _snprintf_s(out + len, size - size_t(len), _TRUNCATE, " tid %lu ip %08X%s", static_cast<unsigned long>(threads_[i].id), unsigned(threads_[i].ip),
                                   threads_[i].ipKnown ? "" : " (context unreadable)");
                if (added < 0) break;   // truncated: stop, never move the cursor back
                len += added;
            }
        }

    private:
        static constexpr size_t kMaxThreads = 512;
        static constexpr int kMaxPasses = 8;
        struct Thread { DWORD id = 0; HANDLE handle = nullptr; uintptr_t ip = 0; bool ipKnown = false; DWORD ctxErr = 0; };
        bool holds(DWORD id) const
        {
            for (size_t i = 0; i < count_; i++) if (threads_[i].id == id) return true;
            return false;
        }
        Thread threads_[kMaxThreads];
        size_t count_ = 0;
        bool complete_ = true;
        const char* failStep_ = nullptr;
        DWORD failTid_ = 0, failErr_ = 0;
        size_t unknown_ = 0;
        int passes_ = 0;
    };

    // Runs `act` with every other thread suspended, at a moment when none of them (except `skip`) is in `ranges` and
    // `gate()` agrees: tries up to `attempts` times, 1 ms apart. `act` must not allocate or take a lock another
    // (suspended) thread may hold. Returns whether `act` ran.
    template <class Gate, class Act>
    bool whenNoThreadIn(const CodeRange* ranges, size_t n, const DWORD* skip, size_t skipCount, int attempts, Gate&& gate, Act&& act, char* why = nullptr, size_t whySize = 0)
    {
        for (int i = 0; i < attempts; i++)
        {
            {
                ThreadFreeze freeze;
                const bool busy = freeze.anyInRanges(ranges, n, skip, skipCount);
                if (!busy && gate()) { act(); return true; }
                if (why && whySize && i == attempts - 1)   // the last try: why it was busy
                {
                    if (busy) freeze.describe(why, whySize, ranges, n, skip, skipCount);
                    else _snprintf_s(why, whySize, _TRUNCATE, "no thread in the ranges, but the gate refused (detour calls in flight)");
                }
            }
            Sleep(1);
        }
        return false;
    }

    // The stock page: a 50-entry table of 16-bit offsets that the engine reads as SIGNED, so an offset (and the
    // page's size word) past 0x7FFF is not representable. Given the byte length of each of `live` records, oldest
    // first (a dead record counts 1 for its terminator), returns how many of the NEWEST fit: at most 50, and only as
    // many as keep every offset and the total under 0x8000. `firstOut` is the index of the oldest kept record.
    inline int fitRecords(const uint32_t* lengths, int live, int* firstOut)
    {
        const uint32_t limit = 0x7FFFu;
        int keep = 0;
        uint32_t total = 0;
        for (int i = live - 1; i >= 0 && keep < 50; --i)
        {
            const uint32_t need = lengths[i] + 1;           // the bytes plus the terminator
            if (total + need > limit) break;
            total += need;
            ++keep;
        }
        if (firstOut) *firstOut = live - keep;
        return keep;
    }
}
