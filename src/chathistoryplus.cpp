// ChatHistoryPlus page storage and client hooks.
#include "chathistoryplus.hpp"
#include "chp_util.h"
#include "plugin_log.h"

#include <cstdarg>
#include <ctime>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace
{
    enum Kind : uint8_t { K_SPLICE = 0, K_DIVISOR = 1, K_DATAREF = 2 };

    struct Sig
    {
        const char* name;
        const uint8_t* pat;
        const char* mask;
        size_t      len;
        Kind        kind;
        uint32_t    knownRva;      // reference RVA; scanning resolves the live address
        uint8_t     steal;         // K_SPLICE: bytes the detour takes
        int8_t      operandOff;    // K_DATAREF: offset of the absolute within the match
        uint32_t    off[2];        // K_DIVISOR: imm32 offsets from the match, 0xFFFFFFFF = unused
    };

    #define NOFF { 0xFFFFFFFFu, 0xFFFFFFFFu }

    const uint8_t s_ctor[] = { 0x8B,0xC1,0x8B,0x4C,0x24,0x04,0x89,0x88,0xDC,0x00,0x00,0x00 };
    const uint8_t s_dtor[] = { 0x81,0xEC,0x00,0x01,0x00,0x00,0x57,0x8B,0xF9,0xE8,0x00,0x00,0x00,0x00 };
    const uint8_t s_load[] = { 0x51,0x53,0x56,0x57,0x8B,0x3D,0x00,0x00,0x00,0x00 };
    const uint8_t s_save[] = { 0x81,0xEC,0x04,0x01,0x00,0x00,0x53,0x55,0x56,0x8B,0xD9 };
    const uint8_t s_append[] = { 0x51,0x53,0x55,0x56,0x8B,0x74,0x24,0x14,0x85,0xF6,0x57,0x8B,0xD9 };
    const uint8_t s_resolve[] = { 0x8B,0x44,0x24,0x04,0x85,0xC0,0x7C,0x2C,0x33,0xD2 };
    const uint8_t s_recount[] = { 0x53,0xC6,0x81,0xC8,0x00,0x00,0x00,0x00,0x33,0xD2 };
    const uint8_t s_freeblob[] = { 0x53,0x56,0x8B,0xF1,0x33,0xDB,0x8B,0x86,0xCC,0x00,0x00,0x00 };

    // Function anchors for records-per-page constants.
    const uint8_t d_a[] = { 0x81,0xEC,0x00,0x01,0x00,0x00,0x56,0x8B,0xF1,0x8A,0x4E,0x54 };
    const uint8_t d_b[] = { 0x56,0x8B,0xF1,0x57,0x8B,0x4E,0x0C,0x8A,0x41,0x60 };
    const uint8_t d_c[] = { 0x53,0x56,0x57,0x8B,0xF9,0x8B,0x4F,0x0C,0x8A,0x41,0x60 };
    const uint8_t d_d[] = { 0x56,0x57,0x8B,0xF9,0x8B,0x4F,0x0C,0x8A,0x41,0x60,0x84,0xC0,0x75,0x05 };

    const uint8_t s_mgr[] = { 0x0D,0x00,0x00,0x00,0x00,0x50,0xE8,0x00,0x00,0x00,0x00,0x66,0x83,0xBF,0x10,0x02,0x00,0x00 };

    // Index into k_sigs / g_res.
    enum SigIdx {
        SI_CTOR = 0, SI_DTOR, SI_LOAD, SI_SAVE, SI_APPEND, SI_RESOLVE, SI_RECOUNT,
        SI_FREEBLOB, SI_DIV_A, SI_DIV_B, SI_DIV_C, SI_DIV_D, SI_CHATMGR
    };

    const Sig k_sigs[] = {
      { "page_ctor",    s_ctor,    "xxxxxxxxxxxx",         sizeof(s_ctor),    K_SPLICE,  0x18DF30,  6, -1, NOFF },
      { "page_dtor",    s_dtor,    "xxxxxxxxxx????",       sizeof(s_dtor),    K_SPLICE,  0x18DF70,  6, -1, NOFF },
      { "page_load",    s_load,    "xxxxxx????",           sizeof(s_load),    K_SPLICE,  0x18E060, 10, -1, NOFF },
      { "page_save",    s_save,    "xxxxxxxxxxx",          sizeof(s_save),    K_SPLICE,  0x18E1A0,  6, -1, NOFF },
      { "page_append",  s_append,  "xxxxxxxxxxxxx",        sizeof(s_append),  K_SPLICE,  0x18E360,  8, -1, NOFF },
      { "page_resolve", s_resolve, "xxxxxxxxxx",           sizeof(s_resolve), K_SPLICE,  0x18E4B0,  6, -1, NOFF },
      { "page_recount", s_recount, "xxxxxxxxxx",           sizeof(s_recount), K_SPLICE,  0x18E530,  8, -1, NOFF },
      { "page_freeblob",s_freeblob,"xxxxxxxxxxxx",         sizeof(s_freeblob),K_SPLICE,  0x18E4F0,  6, -1, NOFF },

      { "div_a",        d_a,       "xxxxxxxxxxxx",         sizeof(d_a),       K_DIVISOR, 0x18E760,  0, -1, { 0x0C6u, 0xFFFFFFFFu } },
      { "div_b",        d_b,       "xxxxxxxxxx",           sizeof(d_b),       K_DIVISOR, 0x18EAA0,  0, -1, { 0x017u, 0xFFFFFFFFu } },
      { "div_c",        d_c,       "xxxxxxxxxxx",          sizeof(d_c),       K_DIVISOR, 0x18EAE0,  0, -1, { 0x02Bu, 0x067u } },
      { "div_d",        d_d,       "xxxxxxxxxxxxxx",       sizeof(d_d),       K_DIVISOR, 0x18EB70,  0, -1, { 0x025u, 0x05Fu } },

      { "chat_manager", s_mgr,     "x????xx????xxxxxxx",   sizeof(s_mgr),     K_DATAREF, 0x00257B,  0,  1, NOFF },
    };
    const size_t k_sigN = sizeof(k_sigs) / sizeof(k_sigs[0]);

    SigResult g_res[k_sigN];

    const uint8_t k_colInfo = 0x6A;
    const uint8_t k_colWarn = 0x68;
    const uint8_t k_colFail = 0x44;
    const uint8_t k_colCmd  = 0x02;
    const char HL_ON  = '\x11';
    const char HL_OFF = '\x12';

    // -- signature scanning

    bool scan_span(const uint8_t* lo, uint32_t span, const Sig& s, SigResult* r)
    {
        __try
        {
            for (uint32_t o = 0; o + s.len <= span; ++o)
            {
                size_t k = 0;
                for (; k < s.len; ++k)
                    if (s.mask[k] == 'x' && lo[o + k] != s.pat[k]) break;
                if (k != s.len) continue;
                if (r->hits == 0) r->at = reinterpret_cast<uintptr_t>(lo + o);
                ++r->hits;
            }
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    }

    bool probe_module(ModuleInfo& m)
    {
        memset(&m, 0, sizeof(m));
        m.base = reinterpret_cast<uintptr_t>(GetModuleHandleA("FFXiMain.dll"));
        if (m.base == 0) return false;
        const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(m.base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        const IMAGE_NT_HEADERS* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(m.base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
        m.sizeOfImage = nt->OptionalHeader.SizeOfImage;
        m.timeStamp   = nt->FileHeader.TimeDateStamp;
        m.sec         = IMAGE_FIRST_SECTION(nt);
        m.nsec        = nt->FileHeader.NumberOfSections;
        for (unsigned i = 0; i < m.nsec; ++i)
            if ((m.sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) ++m.nexec;
        return m.nexec != 0;
    }

    void scan_all(const ModuleInfo& m, const Sig& s, SigResult& out)
    {
        memset(&out, 0, sizeof(out));
        bool faulted = false;
        for (unsigned i = 0; i < m.nsec; ++i)
        {
            if ((m.sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) continue;
            const uint32_t vsize = (m.sec[i].Misc.VirtualSize != 0)
                                 ? m.sec[i].Misc.VirtualSize : m.sec[i].SizeOfRawData;
            if (vsize <= static_cast<uint32_t>(s.len)) continue;
            if (!scan_span(reinterpret_cast<const uint8_t*>(m.base + m.sec[i].VirtualAddress),
                           vsize, s, &out)) faulted = true;
        }
        out.code = faulted        ? SIG_FAULTED
                 : (out.hits == 0) ? SIG_NOT_FOUND
                 : (out.hits == 1) ? SIG_OK
                 :                   SIG_AMBIGUOUS;
        out.rva = (out.hits == 1) ? static_cast<uint32_t>(out.at - m.base) : 0;
    }

    // -- resolved addresses

    struct Addrs
    {
        uintptr_t ctor, dtor, load, save, append, resolve, recount;    // spliced
        uintptr_t freeblob;                                            // called
        uintptr_t isbusy, getsize, read, writed, opnew, opfree;        // called
        uintptr_t fmgr;                                                // file-manager global slot
        uintptr_t chatmgr;                                             // chat-manager global slot
        uintptr_t div[6];                                              // records-per-page immediates
        bool      ok;
    };
    Addrs g_a;

    // Page object fields.
    enum { PGF_COUNT = 0xC8, PGF_DATA = 0xCC, PGF_CAP = 0xD4, PGF_SIZE = 0xD8 };
    // One manager per chat window
    enum { MGR_STRIDE = 0x64068, ST_ITER = 0x64044,
           IT_LIVE = 0x04, IT_TOTAL = 0x08, IT_CONT = 0x0C,
           CT_PAGES = 0x54, CT_OVERFLOW = 0x58, CT_ARRAY = 0x04 };
    enum { CH_MAX_N = 200, CH_SHADOWS = 64, CH_BLOB_MAX = 0x20000, CH_MAX_PAGES = 20 };
    const uint32_t CH_DEAD = 0xFFFFFFFFu;   // shadow sentinel for a dead slot

    struct ChShadow { uintptr_t page; uint16_t n; uint32_t size; uint32_t off[CH_MAX_N]; };
    ChShadow  g_chSh[CH_SHADOWS];
    const int CH_DEFAULT_N = 140;
    int       g_chN  = 50;
    int       g_chDropped = 0;
    bool      g_chOn = false;
    void*     g_chTramp[8] = { nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr };
    uint8_t   g_chOrig[8][16];
    bool      g_chInst[8] = { false, false, false, false, false, false, false, false };
    uint32_t  g_chDivOrig[6];
    // 0 ctor, 1 dtor, 2 load, 3 save, 4 append, 5 resolve, 6 recount, 7 freeblob.
    static_assert(sizeof(g_chTramp) / sizeof(g_chTramp[0]) == 8, "splice arrays must agree");
    static_assert(sizeof(g_chInst)  / sizeof(g_chInst[0])  == 8, "splice arrays must agree");
    volatile uint32_t g_chHit[8];
    volatile uint32_t g_chFail[8];
    bool      g_chDivPoked[6] = { false, false, false, false, false, false };
    bool      g_chPinned = false;      // the DLL stays mapped until the game closes (set at unload, only when something stays)
    bool      g_chRetained = false;    // something could not be put back: stays in, pass-through, until the game closes
    volatile long g_chInflight = 0;    // threads between a detour's entry and its exit
    CRITICAL_SECTION g_chLock;         // recursive: every detour body, and Enable/Disable's data conversion
    bool      g_chLockInit = false;
    plog::FileLog g_chLog;             // logs\chathistoryplus\<Name>_<id>\chathistoryplus.log; nothing goes to Ashita's log

    void ch_lock_init(void)
    {
        if (g_chLockInit) return;
        InitializeCriticalSection(&g_chLock);
        g_chLockInit = true;
    }

    // Detours hold the lock and increment the in-flight count. While disabled, forward through
    // the trampoline so retained hooks preserve native behavior.
    struct DetourGuard
    {
        DetourGuard()  { InterlockedIncrement(&g_chInflight); EnterCriticalSection(&g_chLock); }
        ~DetourGuard() { LeaveCriticalSection(&g_chLock); InterlockedDecrement(&g_chInflight); }
        DetourGuard(const DetourGuard&) = delete;
        DetourGuard& operator=(const DetourGuard&) = delete;
    };

    inline uint8_t  ch_r8 (uintptr_t a) { return *reinterpret_cast<volatile uint8_t*>(a); }
    inline uint16_t ch_r16(uintptr_t a) { return *reinterpret_cast<volatile uint16_t*>(a); }
    inline uint32_t ch_r32(uintptr_t a) { return *reinterpret_cast<volatile uint32_t*>(a); }
    inline void     ch_w8 (uintptr_t a, uint8_t v)  { *reinterpret_cast<volatile uint8_t*>(a) = v; }
    inline void     ch_w16(uintptr_t a, uint16_t v) { *reinterpret_cast<volatile uint16_t*>(a) = v; }
    inline void     ch_w32(uintptr_t a, uint32_t v) { *reinterpret_cast<volatile uint32_t*>(a) = v; }

    bool safe_r32(uintptr_t a, uint32_t* out)
    {
        if (a < 0x10000) return false;
        __try { *out = *reinterpret_cast<volatile uint32_t*>(a); return true; }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    }
    bool safe_r16(uintptr_t a, uint16_t* out)
    {
        if (a < 0x10000) return false;
        __try { *out = *reinterpret_cast<volatile uint16_t*>(a); return true; }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    }
    bool safe_r8(uintptr_t a, uint8_t* out)
    {
        if (a < 0x10000) return false;
        __try { *out = *reinterpret_cast<volatile uint8_t*>(a); return true; }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    }

    ChShadow* ch_find(uintptr_t page)
    {
        for (int i = 0; i < CH_SHADOWS; ++i) if (g_chSh[i].page == page) return &g_chSh[i];
        return nullptr;
    }
    uint32_t ch_size(uintptr_t page, const ChShadow* s)
    {
        const uintptr_t data = ch_r32(page + PGF_DATA);
        const uint32_t  cap  = ch_r32(page + PGF_CAP);
        if (data < 0x10000 || cap == 0) return 0;
        const uint32_t v = (s != nullptr) ? s->size
                                          : static_cast<uint32_t>(ch_r16(page + PGF_SIZE));
        return (v > cap) ? cap : v;
    }
    void ch_setsize(uintptr_t page, ChShadow* s, uint32_t v)
    {
        if (s != nullptr) s->size = v;
        ch_w16(page + PGF_SIZE, static_cast<uint16_t>(v > 0xFFFFu ? 0xFFFFu : v));
    }


    ChShadow* ch_alloc(uintptr_t page)
    {
        ChShadow* s = ch_find(page);
        if (s != nullptr) return s;
        for (int i = 0; i < CH_SHADOWS; ++i)
            if (g_chSh[i].page == 0)
            {
                g_chSh[i].page = page;
                g_chSh[i].n    = static_cast<uint16_t>(g_chN);
                g_chSh[i].size = 0;
                for (int k = 0; k < CH_MAX_N; ++k) g_chSh[i].off[k] = CH_DEAD;
                return &g_chSh[i];
            }
        return nullptr;
    }

    ChShadow* ch_rebuild(uintptr_t page)
    {
        ChShadow* s = ch_alloc(page);
        if (s == nullptr) return nullptr;
        const uintptr_t data = ch_r32(page + PGF_DATA);
        const uint32_t  cap = ch_r32(page + PGF_CAP);
        const int       cnt = static_cast<int>(ch_r8(page + PGF_COUNT));
        s->n = static_cast<uint16_t>(g_chN);
        for (int k = 0; k < CH_MAX_N; ++k) s->off[k] = CH_DEAD;
        s->size = 0;
        if (data < 0x10000 || cap == 0) return s;
        uint32_t off = 0;
        int i = 0;
        while (off < cap && i < cnt && i < CH_MAX_N)
        {
            s->off[i++] = off;
            uint32_t len = 0;
            while (off + len < cap && ch_r8(data + off + len) != 0) ++len;
            off += len + 1;
        }
        s->size = off;
        return s;
    }

    typedef void* (__cdecl*   fn_new)(size_t);
    typedef void  (__cdecl*   fn_del)(void*);
    typedef char  (__fastcall* fn_busy)(void*, void*, void*);
    typedef int   (__fastcall* fn_size)(void*, void*, void*);
    typedef int   (__fastcall* fn_read)(void*, void*, void*, void*, int, int);
    typedef int   (__fastcall* fn_writ)(void*, void*, void*, const void*, int, int);
    typedef void  (__fastcall* fn_fblob)(void*, void*);

    inline void* ch_new(size_t n) { return reinterpret_cast<fn_new>(g_a.opnew)(n); }
    inline void  ch_del(void* p)  { reinterpret_cast<fn_del>(g_a.opfree)(p); }
    inline void* ch_mgr(void)     { return reinterpret_cast<void*>(ch_r32(g_a.fmgr)); }

    // Page-method replacements.

    void __fastcall ch_freeblob(void* self, void* edx)
    {
        DetourGuard guard;
        ++g_chHit[7];
        ChShadow* s = g_chOn ? ch_find(reinterpret_cast<uintptr_t>(self)) : nullptr;
        if (s != nullptr)
        {
            s->size = 0;
            for (int k = 0; k < CH_MAX_N; ++k) s->off[k] = CH_DEAD;
        }
        reinterpret_cast<void(__fastcall*)(void*, void*)>(g_chTramp[7])(self, edx);
    }

    void __fastcall ch_recount(void* self, void* edx)
    {
        DetourGuard guard;
        ++g_chHit[6];
        if (!g_chOn) { reinterpret_cast<void(__fastcall*)(void*, void*)>(g_chTramp[6])(self, edx); return; }
        const uintptr_t page = reinterpret_cast<uintptr_t>(self);
        ChShadow* s = ch_find(page);
        const uintptr_t data = ch_r32(page + PGF_DATA);
        const int size = static_cast<int>(ch_size(page, s));
        int cnt = 0;
        if (s == nullptr)   // no shadow -> revalidate the NATIVE table exactly as the engine would
        {
            for (int i = 0; i < 50; ++i)
            {
                const int off = static_cast<int16_t>(ch_r16(page + i * 2));
                const bool ok = (off >= 0) && (off < size) &&
                                (off == 0 || (data >= 0x10000 && ch_r8(data + off - 1) == 0));
                if (!ok) ch_w16(page + i * 2, 0xFFFF); else ++cnt;
            }
            ch_w8(page + PGF_COUNT, static_cast<uint8_t>(cnt));
            return;
        }
        for (int i = 0; i < s->n; ++i)
        {
            const uint32_t o = s->off[i];
            const bool ok = (o != CH_DEAD) && (o < static_cast<uint32_t>(size)) &&
                            (o == 0 || (data >= 0x10000 && ch_r8(data + o - 1) == 0));
            if (!ok) s->off[i] = CH_DEAD; else ++cnt;
        }
        ch_w8(page + PGF_COUNT, static_cast<uint8_t>(cnt > 255 ? 255 : cnt));
    }

    char* __fastcall ch_resolve(void* self, void* edx, int idx)
    {
        DetourGuard guard;
        ++g_chHit[5];
        if (!g_chOn) return reinterpret_cast<char*(__fastcall*)(void*, void*, int)>(g_chTramp[5])(self, edx, idx);
        const uintptr_t page = reinterpret_cast<uintptr_t>(self);
        const ChShadow* s = ch_find(page);
        if (idx < 0 || idx >= static_cast<int>(ch_r8(page + PGF_COUNT))) return nullptr;
        if (s == nullptr) s = ch_rebuild(page);
        if (s == nullptr) { ++g_chFail[5]; return nullptr; }
        const uint32_t off = s->off[idx];
        if (off == CH_DEAD || off >= ch_size(page, s)) { ++g_chFail[5]; return nullptr; }
        const uintptr_t data = ch_r32(page + PGF_DATA);
        if (data < 0x10000) { ++g_chFail[5]; return nullptr; }
        return reinterpret_cast<char*>(data + off);
    }

    int __fastcall ch_append(void* self, void* edx, const char* txt)
    {
        DetourGuard guard;
        ++g_chHit[4];
        if (!g_chOn) return reinterpret_cast<int(__fastcall*)(void*, void*, const char*)>(g_chTramp[4])(self, edx, txt);
        const uintptr_t page = reinterpret_cast<uintptr_t>(self);
        if (txt == nullptr) return 1;
        ChShadow* s = ch_find(page);
        if (s == nullptr) s = ch_rebuild(page);
        if (s == nullptr) { ++g_chFail[4]; return -1; }

        const int len = static_cast<int>(strlen(txt));
        const int cnt = static_cast<int>(ch_r8(page + PGF_COUNT));
        if (cnt >= s->n) return -1;
        const int size = static_cast<int>(ch_size(page, s));

        const int remaining_after = static_cast<int>(s->n) - cnt - 1;
        int wlen = len;
        if (size + wlen + 1 + remaining_after > CH_BLOB_MAX)
            wlen = CH_BLOB_MAX - remaining_after - 1 - size;
        if (wlen < 0) wlen = 0;

        int cap = static_cast<int>(ch_r32(page + PGF_CAP));
        uintptr_t data = ch_r32(page + PGF_DATA);
        if (data < 0x10000 || size + wlen + 1 >= cap)
        {
            const int ncap = cap + (((wlen + 1) < 0xC80) ? 0xC80 : (wlen + 1));   // native growth rule
            void* nb = ch_new(static_cast<size_t>(ncap));
            if (nb == nullptr) return -1;
            if (data >= 0x10000)
            {
                if (size > 0) memcpy(nb, reinterpret_cast<const void*>(data), static_cast<size_t>(size));
                ch_del(reinterpret_cast<void*>(data));
            }
            data = reinterpret_cast<uintptr_t>(nb);
            ch_w32(page + PGF_CAP, static_cast<uint32_t>(ncap));
            ch_w32(page + PGF_DATA, static_cast<uint32_t>(data));
        }
        if (wlen > 0) memcpy(reinterpret_cast<void*>(data + size), txt, static_cast<size_t>(wlen));
        *reinterpret_cast<volatile char*>(data + size + wlen) = 0;
        s->off[cnt] = static_cast<uint32_t>(size);
        ch_setsize(page, s, static_cast<uint32_t>(size + wlen + 1));
        ch_w8(page + PGF_COUNT, static_cast<uint8_t>(cnt + 1));
        return 1;
    }

    // Candidates: this build's 4-byte header, an older build's 2-byte header, and the stock 100.
    int ch_best_hdr(const uint8_t* buf, int fsz, int n)
    {
        const int cands[3] = { 4 * n, 2 * n, 100 };
        int bestH = -1, bestCnt = -1;
        for (int c = 0; c < 3; ++c)
        {
            const int H = cands[c];
            if (H <= 0 || fsz < H) continue;
            bool dup = false;
            for (int d = 0; d < c; ++d) if (cands[d] == H) dup = true;
            if (dup) continue;
            const int esz  = (c == 0) ? 4 : 2;
            const int dsz  = fsz - H;
            const uint8_t* data = buf + H;
            int cnt = 0;
            for (int i = 0; i < H / esz && i < CH_MAX_N; ++i)
            {
                uint32_t off;
                if (esz == 4) memcpy(&off, buf + i * 4, 4);
                else          off = static_cast<uint16_t>(buf[i * 2] | (buf[i * 2 + 1] << 8));
                if (off == CH_DEAD || off == 0xFFFFu) continue;
                if (off >= static_cast<uint32_t>(dsz)) continue;
                if (off > 0 && data[off - 1] != 0) continue;
                ++cnt;
            }
            if (cnt > bestCnt) { bestCnt = cnt; bestH = H; }
        }
        return bestH;
    }

    int __fastcall ch_load(void* self, void* edx, void* file)
    {
        DetourGuard guard;
        ++g_chHit[2];
        if (!g_chOn) return reinterpret_cast<int(__fastcall*)(void*, void*, void*)>(g_chTramp[2])(self, edx, file);
        const uintptr_t page = reinterpret_cast<uintptr_t>(self);
        ChShadow* s = ch_find(page);
        if (s == nullptr) s = ch_alloc(page);
        if (s == nullptr) return -1;

        void* mgr = ch_mgr();
        if (mgr == nullptr || file == nullptr) return -1;
        for (int guard = 0; guard <= 20; ++guard)
        {
            if (reinterpret_cast<fn_busy>(g_a.isbusy)(mgr, nullptr, file) == 0) break;
            Sleep(100);
        }
        const int fsz = reinterpret_cast<fn_size>(g_a.getsize)(mgr, nullptr, file);
        if (fsz < 100) { ++g_chFail[2]; return -1; }

        void* buf = ch_new(static_cast<size_t>(fsz));
        if (buf == nullptr) return -1;
        const int got = reinterpret_cast<fn_read>(g_a.read)(mgr, nullptr, file, buf, fsz, 0);
        if (got != fsz) { ch_del(buf); return -1; }

        const int hdr = ch_best_hdr(static_cast<const uint8_t*>(buf), fsz, s->n);
        if (hdr <= 0 || fsz < hdr) { ch_del(buf); ++g_chFail[2]; return -1; }
        const int dsz = fsz - hdr;
        if (dsz > CH_BLOB_MAX) { ch_del(buf); ++g_chFail[2]; return -1; }

        reinterpret_cast<fn_fblob>(g_a.freeblob)(self, nullptr);
        void* blob = ch_new(static_cast<size_t>(dsz > 0 ? dsz : 1));
        if (blob == nullptr) { ch_del(buf); return -1; }
        if (dsz > 0) memcpy(blob, static_cast<const char*>(buf) + hdr, static_cast<size_t>(dsz));
        const int esz  = (hdr == 2 * s->n || hdr == 100) ? 2 : 4;
        const int nEnt = (hdr / esz > CH_MAX_N) ? CH_MAX_N : hdr / esz;
        const uint8_t* hb = static_cast<const uint8_t*>(buf);
        for (int i = 0; i < nEnt; ++i)
        {
            uint32_t v;
            if (esz == 2)
            {
                const uint16_t w16 = static_cast<uint16_t>(hb[i * 2] | (hb[i * 2 + 1] << 8));
                v = (w16 == 0xFFFFu) ? CH_DEAD : w16;
            }
            else memcpy(&v, hb + i * 4, 4);
            s->off[i] = v;
        }
        for (int i = nEnt; i < CH_MAX_N; ++i) s->off[i] = CH_DEAD;
        ch_del(buf);

        ch_w32(page + PGF_DATA, reinterpret_cast<uint32_t>(blob));
        ch_w32(page + PGF_CAP, static_cast<uint32_t>(dsz));
        ch_setsize(page, s, static_cast<uint32_t>(dsz));
        ch_recount(self, nullptr);
        return 1;
    }

    int __fastcall ch_save(void* self, void* edx, void* file)
    {
        DetourGuard guard;
        ++g_chHit[3];
        if (!g_chOn) return reinterpret_cast<int(__fastcall*)(void*, void*, void*)>(g_chTramp[3])(self, edx, file);
        const uintptr_t page = reinterpret_cast<uintptr_t>(self);
        ChShadow* s = ch_find(page);
        if (s == nullptr) return -1;
        void* mgr = ch_mgr();
        if (mgr == nullptr || file == nullptr) return -1;
        ch_recount(self, nullptr);
        for (int guard = 0; guard <= 20; ++guard)
        {
            if (reinterpret_cast<fn_busy>(g_a.isbusy)(mgr, nullptr, file) == 0) break;
            Sleep(100);
        }
        // the engine's own direct-write branch: header then blob, no private copy
        const fn_writ w = reinterpret_cast<fn_writ>(g_a.writed);
        w(mgr, nullptr, file, s->off, 4 * s->n, 0);
        const uintptr_t data = ch_r32(page + PGF_DATA);
        if (data >= 0x10000) w(mgr, nullptr, file, reinterpret_cast<const void*>(data),
                               static_cast<int>(ch_size(page, s)), 1);
        return 1;
    }

    void* __fastcall ch_ctor(void* self, void* edx, uint32_t fidx)
    {
        DetourGuard guard;
        ++g_chHit[0];
        return reinterpret_cast<void*(__fastcall*)(void*, void*, uint32_t)>(g_chTramp[0])(self, edx, fidx);
    }
    void __fastcall ch_dtor(void* self, void* edx)
    {
        DetourGuard guard;
        ++g_chHit[1];
        ChShadow* s = g_chOn ? ch_find(reinterpret_cast<uintptr_t>(self)) : nullptr;
        if (s != nullptr) s->page = 0;
        reinterpret_cast<void(__fastcall*)(void*, void*)>(g_chTramp[1])(self, edx);
    }

    // -- splice mechanics

    bool ours(uintptr_t addr, int steal, const void* detour)
    {
        const uint8_t* t = reinterpret_cast<const uint8_t*>(addr);
        if (t[0] != 0xE9) return false;
        if (*reinterpret_cast<const int32_t*>(t + 1) !=
            static_cast<int32_t>(reinterpret_cast<uintptr_t>(detour) - (addr + 5))) return false;
        for (int j = 5; j < steal; ++j) if (t[j] != 0x90) return false;
        return true;
    }

    // Allocate trampolines before patching. Free only after quiet removal of every entry and detour.
    // Stolen instructions contain no calls, so no thread can retain a return into them.
    void* make_tramp(uintptr_t addr, int steal)
    {
        uint8_t* t = static_cast<uint8_t*>(VirtualAlloc(nullptr, 32, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if (t == nullptr) return nullptr;
        memcpy(t, reinterpret_cast<const void*>(addr), steal);
        t[steal] = 0xE9;
        *reinterpret_cast<int32_t*>(t + steal + 1) =
            static_cast<int32_t>((addr + steal) - (reinterpret_cast<uintptr_t>(t) + steal + 5));
        FlushInstructionCache(GetCurrentProcess(), t, 32);
        return t;
    }

    // Write and read back under a freeze; no allocation. The caller verifies ownership first.
    bool write_code(uintptr_t addr, const uint8_t* bytes, int n)
    {
        uint8_t* target = reinterpret_cast<uint8_t*>(addr);
        DWORD op = 0;
        if (!VirtualProtect(target, n, PAGE_EXECUTE_READWRITE, &op)) return false;
        memcpy(target, bytes, n);
        VirtualProtect(target, n, op, &op);
        FlushInstructionCache(GetCurrentProcess(), target, n);
        return memcmp(target, bytes, n) == 0;
    }
    void jump_bytes(uint8_t* out, uintptr_t addr, int steal, const void* detour)
    {
        out[0] = 0xE9;
        *reinterpret_cast<int32_t*>(out + 1) = static_cast<int32_t>(reinterpret_cast<uintptr_t>(detour) - (addr + 5));
        for (int j = 5; j < steal; ++j) out[j] = 0x90;
    }

    bool poke32(uintptr_t addr, uint32_t v)
    {
        DWORD op = 0;
        if (!VirtualProtect(reinterpret_cast<void*>(addr), 4, PAGE_EXECUTE_READWRITE, &op)) return false;
        *reinterpret_cast<volatile uint32_t*>(addr) = v;
        VirtualProtect(reinterpret_cast<void*>(addr), 4, op, &op);
        FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(addr), 4);
        return *reinterpret_cast<volatile uint32_t*>(addr) == v;
    }

    // The eight entries and what replaces them, in g_chTramp / g_chOrig / g_chInst order.
    struct Site { uintptr_t addr; int steal; void* det; };
    void ch_sites(Site* out)
    {
        const Site sites[8] = {
            { g_a.ctor,    k_sigs[SI_CTOR].steal,    reinterpret_cast<void*>(&ch_ctor)    },
            { g_a.dtor,    k_sigs[SI_DTOR].steal,    reinterpret_cast<void*>(&ch_dtor)    },
            { g_a.load,    k_sigs[SI_LOAD].steal,    reinterpret_cast<void*>(&ch_load)    },
            { g_a.save,    k_sigs[SI_SAVE].steal,    reinterpret_cast<void*>(&ch_save)    },
            { g_a.append,  k_sigs[SI_APPEND].steal,  reinterpret_cast<void*>(&ch_append)  },
            { g_a.resolve, k_sigs[SI_RESOLVE].steal, reinterpret_cast<void*>(&ch_resolve) },
            { g_a.recount, k_sigs[SI_RECOUNT].steal, reinterpret_cast<void*>(&ch_recount) },
            { g_a.freeblob, k_sigs[SI_FREEBLOB].steal, reinterpret_cast<void*>(&ch_freeblob) },
        };
        memcpy(out, sites, sizeof(sites));
    }

    // Freeze this DLL, eight entries, their trampolines and six divisor instructions.
    size_t ch_ranges(const Site* sites, chp::CodeRange* out)
    {
        size_t n = 0;
        HMODULE self = nullptr;
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               reinterpret_cast<LPCSTR>(&ch_append), &self) && self != nullptr)
        {
            const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(self);
            const IMAGE_NT_HEADERS* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(reinterpret_cast<uintptr_t>(self) + dos->e_lfanew);
            out[n++] = chp::CodeRange{ reinterpret_cast<uintptr_t>(self), reinterpret_cast<uintptr_t>(self) + nt->OptionalHeader.SizeOfImage };
        }
        else out[n++] = chp::CodeRange{ 0, UINTPTR_MAX };   // unknown: every thread counts as busy
        for (int i = 0; i < 8; ++i)
        {
            out[n++] = chp::CodeRange{ sites[i].addr, sites[i].addr + static_cast<uintptr_t>(sites[i].steal) };
            if (g_chTramp[i] != nullptr)
                out[n++] = chp::CodeRange{ reinterpret_cast<uintptr_t>(g_chTramp[i]), reinterpret_cast<uintptr_t>(g_chTramp[i]) + 32 };
        }
        for (int i = 0; i < 6; ++i) out[n++] = chp::CodeRange{ g_a.div[i] - 1, g_a.div[i] + 4 };
        return n;
    }

    // Discard incompatible stored pages and set the iterator total to the live-page count.
    int ch_drop_pages(const Store& st)
    {
        int cleared = 0;
        if (st.pages != 0) { ch_w8(st.cont + CT_PAGES, 0); cleared = st.pages; }
        if (st.iter >= 0x10000)
        {
            uint32_t total = 0;
            const uint32_t live = (st.live >= 0x10000) ? static_cast<uint32_t>(ch_r8(st.live + PGF_COUNT)) : 0u;
            if (safe_r32(st.iter + IT_TOTAL, &total) && total != live) ch_w32(st.iter + IT_TOTAL, live);
        }
        return cleared;
    }

    // Pin only when unload leaves hooks or a writer alive; a clean unload must allow a fresh DLL.
    bool ch_pin(void)
    {
        if (g_chPinned) return true;
        HMODULE self = nullptr;
        g_chPinned = GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                                        reinterpret_cast<LPCSTR>(&ch_append), &self) != FALSE && self != nullptr;
        return g_chPinned;
    }

    // Adopt native page indices on install; compact the newest fitting records on removal.
    int ch_adopt(const Store& st, bool adopt)
    {
        uintptr_t list[CH_MAX_PAGES + 1];
        int n_list = 0;
        if (st.live >= 0x10000) list[n_list++] = st.live;
        for (int i = 0; i < st.pages && n_list <= CH_MAX_PAGES; ++i)
        {
            uint32_t pg = 0;
            if (!safe_r32(st.cont + CT_ARRAY + i * 4, &pg)) continue;
            if (pg >= 0x10000 && pg != st.live) list[n_list++] = pg;
        }

        int touched = 0;
        for (int i = 0; i < n_list; ++i)
        {
            const uintptr_t page = list[i];
            if (adopt)
            {
                ChShadow* s = ch_alloc(page);
                if (s == nullptr) continue;
                for (int k = 0; k < 50; ++k)
                {
                    const uint16_t w16 = ch_r16(page + k * 2);
                    s->off[k] = (w16 == 0xFFFFu) ? CH_DEAD : w16;
                }
                for (int k = 50; k < CH_MAX_N; ++k) s->off[k] = CH_DEAD;
                s->n = static_cast<uint16_t>(g_chN);
                s->size = static_cast<uint32_t>(ch_r16(page + PGF_SIZE));
            }
            else
            {
                ChShadow* s = ch_find(page);
                if (s == nullptr) continue;
                int live = static_cast<int>(ch_r8(page + PGF_COUNT));
                if (live > CH_MAX_N) live = CH_MAX_N;
                const uintptr_t data = ch_r32(page + PGF_DATA);
                const uint32_t  osz  = ch_size(page, s);

                // Keep the newest records that fit 50 signed 16-bit offsets and a total size below 0x8000.
                uint32_t lens[CH_MAX_N];
                for (int k = 0; k < live; ++k)
                {
                    const uint32_t o = s->off[k];
                    uint32_t len = 0;
                    if (data >= 0x10000 && o != CH_DEAD && o < osz)
                        while (o + len < osz && ch_r8(data + o + len) != 0) ++len;
                    lens[k] = len;
                }
                int first = 0;
                int keep = (data >= 0x10000) ? chp::fitRecords(lens, live, &first) : 0;
                uint32_t nsz = 0;
                for (int k = 0; k < keep; ++k) nsz += lens[first + k] + 1;
                void* nb = (nsz > 0) ? ch_new(nsz) : nullptr;
                if (nb != nullptr && data >= 0x10000)
                {
                    uint8_t* w = static_cast<uint8_t*>(nb);
                    uint32_t at = 0;
                    uint32_t newoff[50] = { 0 };
                    for (int k = 0; k < keep; ++k)
                    {
                        const uint32_t o = s->off[first + k];
                        newoff[k] = at;
                        ch_w16(page + k * 2, static_cast<uint16_t>(at));
                        if (o == CH_DEAD || o >= osz) { w[at++] = 0; continue; }
                        uint32_t len = 0;
                        while (o + len < osz && ch_r8(data + o + len) != 0) ++len;
                        for (uint32_t j = 0; j < len; ++j) w[at + j] = ch_r8(data + o + j);
                        w[at + len] = 0;
                        at += len + 1;
                    }
                    reinterpret_cast<fn_fblob>(g_a.freeblob)(reinterpret_cast<void*>(page), nullptr);
                    ch_w32(page + PGF_DATA, reinterpret_cast<uint32_t>(nb));
                    ch_w32(page + PGF_CAP, nsz);
                    ch_w16(page + PGF_SIZE, static_cast<uint16_t>(nsz > 0xFFFFu ? 0xFFFFu : nsz));
                    s->size = nsz;
                    for (int k = 0; k < keep; ++k)        s->off[k] = newoff[k];
                    for (int k = keep; k < CH_MAX_N; ++k) s->off[k] = CH_DEAD;
                }
                else
                {
                    // If packing allocation fails, return an empty page with a zero size.
                    if (data >= 0x10000) reinterpret_cast<fn_fblob>(g_a.freeblob)(reinterpret_cast<void*>(page), nullptr);
                    ch_w32(page + PGF_DATA, 0);
                    ch_w32(page + PGF_CAP, 0);
                    ch_w16(page + PGF_SIZE, 0);
                    s->size = 0;
                    for (int k = 0; k < CH_MAX_N; ++k) s->off[k] = CH_DEAD;
                    keep = 0;
                }
                for (int k = keep; k < 50; ++k) ch_w16(page + k * 2, 0xFFFF);
                ch_w8(page + PGF_COUNT, static_cast<uint8_t>(keep));
                g_chDropped += live - keep;
            }
            ++touched;
        }
        return touched;
    }
}


chathistoryplus::chathistoryplus(void)
    : m_Core(nullptr), m_Id(0), m_Base(0), m_ImgStamp(0), m_Resolved(false), m_Want(0)
{
    // Do not reset globals here: a refused instance may share the pinned image with live detours.
}

void chathistoryplus::Print(uint8_t colour, const char* fmt, ...)
{
    if (fmt == nullptr) return;
    char raw[512];
    va_list ap; va_start(ap, fmt);
    _vsnprintf_s(raw, sizeof(raw), _TRUNCATE, fmt, ap);
    va_end(ap);

    if (colour == k_colFail && !m_Diag)
    {
        char named[512];
        _snprintf_s(named, sizeof(named), _TRUNCATE, "%s Details: " HL("%s") "%s", raw, LogShown().c_str(), LogNote());
        strcpy_s(raw, sizeof(raw), named);
    }

    if (m_Diag)
    {
        char flat[512]; size_t f = 0;
        for (size_t r = 0; raw[r] != '\0' && f + 1 < sizeof(flat); ++r)
            if (raw[r] != HL_ON && raw[r] != HL_OFF) flat[f++] = raw[r];
        flat[f] = '\0';
        m_DiagText += "      ";
        m_DiagText += flat;
        m_DiagText += '\n';
        return;
    }

    char body[512]; size_t w = 0;
    char plain[512]; size_t p = 0;
    for (size_t r = 0; raw[r] != '\0' && w + 3 < sizeof(body); ++r)
    {
        if (raw[r] == HL_ON)       { body[w++] = '\x1E'; body[w++] = static_cast<char>(k_colCmd); }
        else if (raw[r] == HL_OFF) { body[w++] = '\x1E'; body[w++] = static_cast<char>(colour); }
        else                       { body[w++] = raw[r]; plain[p++] = raw[r]; }
    }
    body[w] = '\0';
    plain[p] = '\0';

    Log(colour == k_colFail || colour == k_colWarn, "%s", plain);

    IChatManager* cm = (m_Core != nullptr) ? m_Core->GetChatManager() : nullptr;
    if (cm == nullptr) return;
    char out[600];
    _snprintf_s(out, sizeof(out), _TRUNCATE,
        "\x1E\x51" "[" "\x1E\x06" "ChatHistoryPlus" "\x1E\x51" "]" "\x1E\x01" " "
        "\x1E%c" "%s" "\x1E\x01", colour, body);
    cm->AddChatMessage(1, false, out);
}

void chathistoryplus::Refuse(const char* fmt, ...)
{
    char buf[512];
    va_list ap; va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    Log(true, "%s", buf);
    if (m_ToldWhy) return;
    m_ToldWhy = true;
    Print(k_colWarn, "Nothing was patched - this client build is not one ChatHistoryPlus knows. Details: " HL("%s") "%s", LogShown().c_str(), LogNote());
}

void chathistoryplus::Log(bool warn, const char* fmt, ...)
{
    if (fmt == nullptr) return;
    char buf[512];
    va_list ap; va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    if (m_Diag)
    {
        m_DiagText += warn ? "WARN  " : "      ";
        m_DiagText += buf;
        m_DiagText += '\n';
        return;
    }
    g_chLog.write(warn ? "warn" : "info", buf);
}

void chathistoryplus::Chat(uint8_t colour, const char* text)
{
    IChatManager* cm = (m_Core != nullptr) ? m_Core->GetChatManager() : nullptr;
    if (cm == nullptr || text == nullptr) return;
    char body[512];
    size_t w = 0;
    for (size_t r = 0; text[r] != '\0' && w + 3 < sizeof(body); ++r)
    {
        if (text[r] == HL_ON)       { body[w++] = '\x1E'; body[w++] = static_cast<char>(k_colCmd); }
        else if (text[r] == HL_OFF) { body[w++] = '\x1E'; body[w++] = static_cast<char>(colour); }
        else                        { body[w++] = text[r]; }
    }
    body[w] = '\0';
    char out[600];
    _snprintf_s(out, sizeof(out), _TRUNCATE,
        "\x1E\x51" "[" "\x1E\x06" "ChatHistoryPlus" "\x1E\x51" "]" "\x1E\x01" " " "\x1E%c" "%s" "\x1E\x01", colour, body);
    cm->AddChatMessage(1, false, out);
}

std::string chathistoryplus::LogShown(void) { return plog::underRoot(m_Root, g_chLog.path()); }
const char* chathistoryplus::LogNote(void) { return (!m_Refused && g_chLog.atStartupFile()) ? " (it moves into your character's log at login)" : ""; }

void chathistoryplus::DiagBegin(void)
{
    m_Diag = true;
    m_DiagText.clear();
}

void chathistoryplus::DiagEnd(void)
{
    m_Diag = false;
    char who[96];
    _snprintf_s(who, sizeof(who), _TRUNCATE, "ChatHistoryPlus %.1f build %08X", GetVersion(), plog::ownImageStamp(&g_chLog));
    g_chLog.writeDiag(who, m_DiagText);
    m_DiagText.clear();
    Print(k_colInfo, "Diagnostics written to " HL("%s") "%s.", LogShown().c_str(), LogNote());
}

void chathistoryplus::FollowCharacter(void)
{
    if (m_Core == nullptr) return;
    IMemoryManager* mm = m_Core->GetMemoryManager();
    IPlayer* player = mm != nullptr ? mm->GetPlayer() : nullptr;
    IParty* party = mm != nullptr ? mm->GetParty() : nullptr;
    if (player == nullptr || party == nullptr || player->GetLoginStatus() != 2) return;
    const char* name = party->GetMemberName(0);
    const uint32_t serverId = party->GetMemberServerId(0);
    if (name == nullptr || name[0] == '\0' || serverId == 0) return;
    const std::string key = plog::characterKey(name, serverId);
    if (key == m_CharKey) return;
    m_CharKey = key;
    g_chLog.moveToCharacter(plog::characterLogPath(m_Root, "chathistoryplus", key), name);
}

void chathistoryplus::Usage(bool verbose)
{
    Chat(k_colInfo, HL("/chathistoryplus") " [" HL("status") "|" HL("diag") "]   (or " HL("/chp") ")");
    if (!verbose) return;
    char line[200];
    _snprintf_s(line, sizeof(line), _TRUNCATE, "Keeps %d messages per chat window instead of 1000. Applies itself; if your "
                                               "log has already started filling, it waits for your next login.",
                CH_DEFAULT_N * CH_MAX_PAGES);
    Chat(k_colInfo, line);
}

bool chathistoryplus::Resolve(void)
{
    ModuleInfo m;
    if (!probe_module(m))
    {
        Print(k_colFail, "FFXiMain.dll is not loaded yet, so nothing could be resolved.");
        return false;
    }
    m_Base = m.base;
    m_ImgStamp = m.timeStamp;

    unsigned ok = 0;
    for (size_t i = 0; i < k_sigN; ++i)
    {
        scan_all(m, k_sigs[i], g_res[i]);
        if (g_res[i].code == SIG_OK) ++ok;
    }
    m_Resolved = (ok == k_sigN) && Derive();
    return m_Resolved;
}

bool chathistoryplus::Derive(void)
{
    memset(&g_a, 0, sizeof(g_a));
    for (size_t i = 0; i < k_sigN; ++i) if (g_res[i].code != SIG_OK) return false;

    const uintptr_t load = g_res[SI_LOAD].at;
    const uintptr_t save = g_res[SI_SAVE].at;

    g_a.ctor     = g_res[SI_CTOR].at;
    g_a.dtor     = g_res[SI_DTOR].at;
    g_a.load     = load;
    g_a.save     = save;
    g_a.append   = g_res[SI_APPEND].at;
    g_a.resolve  = g_res[SI_RESOLVE].at;
    g_a.recount  = g_res[SI_RECOUNT].at;
    {
        const uintptr_t site = g_res[SI_CHATMGR].at + k_sigs[SI_CHATMGR].operandOff;
        const uint8_t*  op   = reinterpret_cast<const uint8_t*>(site - 2);
        if (op[0] != 0x8B || op[1] != 0x0D)
        {
            Log(true, "derive: chat_manager operand site is not `mov ecx,[imm32]` (%02X %02X)",
                op[0], op[1]);
            return false;
        }
        g_a.chatmgr = *reinterpret_cast<const uint32_t*>(site);
    }

    struct CallSite { uintptr_t* dst; uintptr_t from; uint32_t off; const char* name; };
    const CallSite cs[7] = {
        { &g_a.isbusy,   load, 0x019, "isbusy"   },
        { &g_a.getsize,  load, 0x039, "getsize"  },
        { &g_a.read,     load, 0x094, "read"     },
        { &g_a.freeblob, load, 0x0A4, "freeblob" },
        { &g_a.opnew,    load, 0x0B3, "new"      },
        { &g_a.opfree,   save, 0x0E2, "free"     },
        { &g_a.writed,   save, 0x186, "write"    },
    };
    for (size_t i = 0; i < sizeof(cs) / sizeof(cs[0]); ++i)
    {
        const uintptr_t site = cs[i].from + cs[i].off;
        if (*reinterpret_cast<const uint8_t*>(site) != 0xE8)
        {
            Log(true, "derive: %s call site +0x%03X is not a CALL", cs[i].name, cs[i].off);
            return false;
        }
        *cs[i].dst = site + 5 + *reinterpret_cast<const int32_t*>(site + 1);
    }
    if (g_a.freeblob != g_res[SI_FREEBLOB].at)
    {
        Log(true, "derive: freeblob call site 0x%08X disagrees with its signature 0x%08X",
            g_a.freeblob, g_res[SI_FREEBLOB].at);
        return false;
    }

    const uintptr_t m1 = load + 0x012, m2 = load + 0x033;
    if (*reinterpret_cast<const uint16_t*>(m1) != 0x0D8B ||
        *reinterpret_cast<const uint16_t*>(m2) != 0x0D8B)
    {
        Log(true, "derive: file-manager load site is not `mov ecx,[abs]`");
        return false;
    }
    g_a.fmgr = *reinterpret_cast<const uint32_t*>(m1 + 2);
    if (g_a.fmgr != *reinterpret_cast<const uint32_t*>(m2 + 2))
    {
        Log(true, "derive: the two file-manager loads disagree");
        return false;
    }

    // Six `mov r32, 50` immediates under four function anchors.
    int d = 0;
    for (size_t i = SI_DIV_A; i <= SI_DIV_D; ++i)
        for (int k = 0; k < 2; ++k)
            if (k_sigs[i].off[k] != 0xFFFFFFFFu) g_a.div[d++] = g_res[i].at + k_sigs[i].off[k];
    if (d != 6) return false;

    g_a.ok = true;
    return true;
}

void chathistoryplus::Report(bool toLog)
{
    unsigned bad = 0;
    for (size_t i = 0; i < k_sigN; ++i) if (g_res[i].code != SIG_OK) ++bad;

    if (bad == 0 && g_a.ok)
        Log(false, "all %u signatures resolved on client build 0x%08X",
            static_cast<unsigned>(k_sigN), m_ImgStamp);
    else if (bad == 0)
        Refuse("signatures matched but the derived addresses did not check out");
    else
        Refuse("%u of %u signatures did not resolve on client build 0x%08X",
               bad, static_cast<unsigned>(k_sigN), m_ImgStamp);

    if (!toLog && bad == 0 && g_a.ok) return;   // the detail only when something failed, or in diag
    Log(false, "module FFXiMain.dll base 0x%08X  TimeDateStamp 0x%08X", m_Base, m_ImgStamp);
    for (size_t i = 0; i < k_sigN; ++i)
    {
        const SigResult& r = g_res[i];
        const char* verdict = (r.code == SIG_OK)        ? "OK"
                            : (r.code == SIG_NOT_FOUND) ? "NOT FOUND"
                            : (r.code == SIG_AMBIGUOUS) ? "AMBIGUOUS"
                            :                             "FAULTED";
        if (r.code == SIG_OK)
        {
            const int dl = static_cast<int>(r.rva) - static_cast<int>(k_sigs[i].knownRva);
            Log(false, "  %-13s %-9s rva 0x%06X  (reference 0x%06X, delta %c0x%X)",
                k_sigs[i].name, verdict, r.rva, k_sigs[i].knownRva,
                dl < 0 ? '-' : '+', dl < 0 ? -dl : dl);
        }
        else
            Log(true,  "  %-13s %-9s %u match(es)  (reference 0x%06X)",
                k_sigs[i].name, verdict, r.hits, k_sigs[i].knownRva);
    }
    if (!g_a.ok) { Log(true, "derived addresses: NOT VALID"); return; }
    Log(false, "derived from callers: isbusy 0x%06X getsize 0x%06X read 0x%06X writed 0x%06X "
               "new 0x%06X free 0x%06X freeblob 0x%06X",
        g_a.isbusy - m_Base, g_a.getsize - m_Base, g_a.read - m_Base, g_a.writed - m_Base,
        g_a.opnew - m_Base, g_a.opfree - m_Base, g_a.freeblob - m_Base);
    Log(false, "globals: file manager 0x%06X  chat manager 0x%06X",
        g_a.fmgr - m_Base, g_a.chatmgr - m_Base);
    for (int i = 0; i < 6; ++i)
        Log(false, "  divisor %d rva 0x%06X reads %u", i + 1, g_a.div[i] - m_Base,
            *reinterpret_cast<const uint32_t*>(g_a.div[i]));
}

int chathistoryplus::Stores(Store* out, int max)
{
    int n = 0;
    if (!g_a.ok || max <= 0) return 0;
    uint32_t mgr = 0;
    if (!safe_r32(g_a.chatmgr, &mgr) || mgr < 0x10000) return 0;

    uint32_t vt0 = 0;
    for (int c = 0; c < 2 && n < max; ++c)
    {
        Store st; memset(&st, 0, sizeof(st));
        uint32_t it = 0, ct = 0, live = 0, ovf = 0, vt = 0;
        uint8_t pages = 0, lcnt = 0;
        if (!safe_r32(mgr + c * MGR_STRIDE + ST_ITER, &it) || it < 0x10000) continue;
        if (!safe_r32(it + IT_CONT, &ct) || ct < 0x10000) continue;
        if (!safe_r32(ct, &vt) || vt < 0x10000) continue;
        if (c == 0) vt0 = vt; else if (vt != vt0) continue;   // not a container
        if (!safe_r8(ct + CT_PAGES, &pages) || pages > CH_MAX_PAGES) continue;
        if (!safe_r32(ct + CT_OVERFLOW, &ovf)) continue;
        if (!safe_r32(it + IT_LIVE, &live)) continue;
        if (live != 0 && live < 0x10000) continue;
        if (live >= 0x10000 && !safe_r8(live + PGF_COUNT, &lcnt)) continue;

        bool dup = false;
        for (int i = 0; i < n; ++i) if (out[i].cont == ct) dup = true;
        if (dup) continue;

        st.iter = it; st.cont = ct; st.live = live;
        st.pages = pages; st.overflow = static_cast<int>(ovf); st.liveCount = lcnt;
        out[n++] = st;
    }
    return n;
}

void chathistoryplus::Status(void)
{
    if (!m_Resolved && !Resolve()) { Report(false); return; }

    Store st[4];
    const int ns = Stores(st, 4);
    const int n  = g_chOn ? g_chN : 50;

    if (g_chOn)
        Print(k_colInfo, "Currently " HL("ON") " at %d records/page -- %d messages per window "
                         "(stock is 50 / %d).", n, n * CH_MAX_PAGES, 50 * CH_MAX_PAGES);
    else if (m_Want != 0)
        Print(k_colWarn, "Currently " HL("OFF") ". %d records/page is armed and will apply at the "
                         "next login, before the first page rotates.", m_Want);
    else
        Print(k_colWarn, "Currently " HL("OFF") " -- stock 50 records/page, %d messages per window.",
              50 * CH_MAX_PAGES);

    if (ns == 0) { Print(k_colWarn, "No chat store is reachable right now."); return; }

    // Collapse identical per-window counts; report both when filtering makes them differ.
    const int tot0 = st[0].pages * n + st[0].liveCount;
    const bool same = (ns == 2) && (st[1].pages * n + st[1].liveCount) == tot0;
    if (same)
    {
        Print(g_chOn ? k_colInfo : k_colWarn,
              "Holding %d message(s) -- %d stored page(s) + %d live.",
              tot0, st[0].pages, st[0].liveCount);

    }
    else
    {
        for (int i = 0; i < ns; ++i)
            Print(g_chOn ? k_colInfo : k_colWarn,
                  "Chat window %d: %d stored page(s) + %d live record(s) = %d message(s).",
                  i + 1, st[i].pages, st[i].liveCount, st[i].pages * n + st[i].liveCount);
        if (ns == 2)
            Print(k_colInfo, "The two differ because your chat windows are filtered differently.");
    }
    if (ns < 2)
    {
        Log(true, "only %d of 2 stores reachable; refusing - the size constant is shared code", ns);
        Print(k_colWarn, "Only one chat window's store is reachable, so nothing was changed.");
    }
}

// Read-only topology dump
void chathistoryplus::DumpWords(const char* tag, uintptr_t at, int words)
{
    char line[256];
    for (int row = 0; row < words; row += 4)
    {
        int w = _snprintf_s(line, sizeof(line), _TRUNCATE, "%s +0x%02X:", tag, row * 4);
        for (int i = row; i < row + 4 && i < words; ++i)
        {
            uint32_t v = 0;
            const bool ok = safe_r32(at + i * 4, &v);
            w += _snprintf_s(line + w, sizeof(line) - w, _TRUNCATE, ok ? " %08X" : " --------", v);
        }
        Log(false, "%s", line);
    }
}

void chathistoryplus::Probe(void)
{
    if (!m_Resolved && !Resolve()) { Report(false); return; }
    uint32_t mgr = 0;
    safe_r32(g_a.chatmgr, &mgr);
    Log(false, "probe: chat manager global 0x%08X -> 0x%08X", g_a.chatmgr, mgr);
    for (int c = 0; c < 2; ++c)
    {
        const uint32_t off = c * MGR_STRIDE + ST_ITER;
        uint32_t it = 0, ct = 0, live = 0, ovf = 0, vt = 0; uint8_t pages = 0, lcnt = 0;
        const bool a = safe_r32(mgr + off, &it);
        const bool b = a && safe_r32(it + IT_CONT, &ct) && safe_r32(ct, &vt);
        const bool d = b && safe_r8(ct + CT_PAGES, &pages) && safe_r32(ct + CT_OVERFLOW, &ovf);
        const bool e = a && safe_r32(it + IT_LIVE, &live) &&
                       (live < 0x10000 || safe_r8(live + PGF_COUNT, &lcnt));
        // Blob bytes, not just record count
        uint16_t lsz = 0; uint32_t lcap = 0;
        // The shadow holds the full buffer size.
        uint32_t ltrue = 0;
        if (e && live >= 0x10000)
        {
            safe_r16(live + PGF_SIZE, &lsz);
            safe_r32(live + PGF_CAP, &lcap);
            uint32_t d = 0;
            if (safe_r32(live + PGF_DATA, &d) && d >= 0x10000 && lcap > 0)
            {
                const ChShadow* sh = ch_find(live);
                ltrue = (sh != nullptr) ? ((sh->size > lcap) ? lcap : sh->size) : lsz;
            }
        }
        Log(false, "  mgr%d +0x%05X iter 0x%08X cont 0x%08X vtbl 0x%08X pages %u overflow %u "
                   "live 0x%08X count %u  blob %u/%u bytes (%u%% of ceiling, cap %u)%s",
            c + 1, off, it, ct, vt, pages, ovf, live, lcnt,
            ltrue, static_cast<unsigned>(CH_BLOB_MAX),
            static_cast<unsigned>(ltrue * 100u / CH_BLOB_MAX), lcap,
            (a && b && d && e) ? "" : "   <- did not validate");
        if (d)
            for (int i = 0; i < pages; ++i)
            {
                uint32_t pg = 0; uint8_t pc = 0;
                safe_r32(ct + CT_ARRAY + i * 4, &pg);
                if (pg >= 0x10000) safe_r8(pg + PGF_COUNT, &pc);
                Log(false, "      page[%02d] 0x%08X count %u", i, pg, pc);
            }
        if (a) DumpWords("    iter", it, 8);
        if (b) DumpWords("    cont", ct, 26);
        if (live >= 0x10000)
        {
            uint32_t cnt = 0, dat = 0, cap = 0, siz = 0;
            safe_r32(live + PGF_COUNT, &cnt);
            safe_r32(live + PGF_DATA, &dat);
            safe_r32(live + PGF_CAP, &cap);
            uint16_t s16 = 0;
            safe_r16(live + PGF_SIZE, &s16);
            const ChShadow* sh2 = ch_find(live);
            siz = (sh2 != nullptr && dat >= 0x10000 && cap > 0)
                    ? ((sh2->size > cap) ? cap : sh2->size) : s16;
            Log(false, "    live page: count %u data 0x%08X cap %u size %u (true)",
                cnt & 0xFF, dat, cap, siz);
            DumpWords("    live off[]", live, 6);
        }
    }
    for (size_t i = 0; i < sizeof(g_chHit) / sizeof(g_chHit[0]); ++i)
        Log(false, "  detour %u hits %u fails %u",
            static_cast<unsigned>(i), g_chHit[i], g_chFail[i]);
}

bool chathistoryplus::Enable(void)
{
    const int n = CH_DEFAULT_N;
    ch_lock_init();
    if (!m_Resolved && !Resolve()) { Report(false); return false; }
    if (!g_a.ok) { Refuse("addresses did not check out"); return false; }
    if (g_chOn)
    {
        Log(false, "already on at %d records/page", g_chN);
        return false;
    }
    if (g_chRetained)
    {
        Log(true, "not enabling: an earlier attempt left code in the client that could not be put back");
        return false;
    }

    Store st[4];
    const int ns = Stores(st, 4);
    if (ns < 2)
    {
        m_Want = n;
        Log(false, "waiting for the chat store (unreachable: Tick pre-checks this)");
        Log(false, "armed: only %d of 2 stores reachable, want %d records/page", ns, n);
        return false;
    }

    if (n > 50)
    {
        int worst = 0;
        for (int i = 0; i < ns; ++i) if (st[i].pages > worst) worst = st[i].pages;
        if (worst > 0)
        {
            m_Want = n;
            Log(false, "store already rotated (unreachable: Tick pre-checks this)");
            Log(false, "armed at %d: %d page(s) already closed at 50 records", n, worst);
            return false;
        }
    }

    // Verify each divisor site decodes as `mov r32, 50`
    for (int i = 0; i < 6; ++i)
    {
        const uint8_t op = *reinterpret_cast<const uint8_t*>(g_a.div[i] - 1);
        if (op < 0xB8 || op > 0xBF || *reinterpret_cast<const uint32_t*>(g_a.div[i]) != 50)
        {
            Refuse("divisor site %d does not decode as `mov r32, 50`", i + 1);
            return false;
        }
    }

    Site sites[8];
    ch_sites(sites);
    for (int i = 0; i < 8; ++i)
        if (g_chInst[i])
        {
            Log(true, "not enabling: entry %d is still spliced from an earlier attempt", i + 1);
            return false;
        }

    // Trampolines first (they allocate); the stolen bytes are recorded now and checked again under the freeze.
    for (int i = 0; i < 8; ++i)
    {
        if (g_chTramp[i] == nullptr) g_chTramp[i] = make_tramp(sites[i].addr, sites[i].steal);
        else memcpy(g_chTramp[i], reinterpret_cast<const void*>(sites[i].addr), sites[i].steal);   // a kept one from a refused attempt: refresh its copy
        if (g_chTramp[i] == nullptr)
        {
            Refuse("trampoline %d could not be allocated", i + 1);
            return false;
        }
        memcpy(g_chOrig[i], reinterpret_cast<const void*>(sites[i].addr), sites[i].steal);
    }

    memset(const_cast<uint32_t*>(g_chHit), 0, sizeof(g_chHit));
    memset(const_cast<uint32_t*>(g_chFail), 0, sizeof(g_chFail));

    // Under one quiet freeze, adopt live pages, install entries/divisors and enable detours.
    // Recheck ownership and roll back all writes on failure. No allocation.
    chp::CodeRange ranges[33];
    size_t nr = ch_ranges(sites, ranges);
    {
        // Also freeze the native page-method bodies to avoid losing an append after shadow adoption.
        // Calls already inside allocators or file I/O are outside these checked ranges.
        uintptr_t lo = sites[0].addr;
        for (int i = 1; i < 8; ++i) if (sites[i].addr < lo) lo = sites[i].addr;
        const uintptr_t hi = g_res[SI_DIV_A].at;
        if (hi > lo && hi - lo < 0x4000) ranges[nr++] = chp::CodeRange{ lo, hi };
    }
    const DWORD skip[1] = { g_chLog.threadId() };
    int failedSite = -1, adopted = 0;
    bool foreign = false;
    char why[600] = "";
    const bool ran = chp::whenNoThreadIn(ranges, nr, skip, 1, 1000, [] { return g_chInflight == 0; }, [&]
    {
        g_chN = n;
        for (int i = 0; i < CH_SHADOWS; ++i) g_chSh[i].page = 0;
        for (int i = 0; i < ns; ++i) adopted += ch_adopt(st[i], true);
        int written = 0;
        for (; written < 8; ++written)
        {
            // Recheck entry signatures so a later hook is not copied into an unrelocated trampoline.
            const Sig& sig = k_sigs[written];   // SI_CTOR..SI_FREEBLOB are the sites' order
            const uint8_t* live = reinterpret_cast<const uint8_t*>(sites[written].addr);
            bool matches = live[0] != 0xE9 && live[0] != 0xE8;
            for (size_t k = 0; k < sig.len && matches; ++k) if (sig.mask[k] == 'x' && live[k] != sig.pat[k]) matches = false;
            if (!matches || memcmp(live, g_chOrig[written], sites[written].steal) != 0) { foreign = true; break; }
            uint8_t jmp[16];
            jump_bytes(jmp, sites[written].addr, sites[written].steal, sites[written].det);
            if (!write_code(sites[written].addr, jmp, sites[written].steal)) break;
            g_chInst[written] = true;
        }
        int poked = 0;
        if (written == 8)
            for (; poked < 6; ++poked)
            {
                g_chDivOrig[poked] = *reinterpret_cast<const uint32_t*>(g_a.div[poked]);
                if (g_chDivOrig[poked] != 50 || !poke32(g_a.div[poked], static_cast<uint32_t>(n))) break;
                g_chDivPoked[poked] = true;
            }
        if (written == 8 && poked == 6) { g_chOn = true; return; }
        // Roll back what went in, in this same pass.
        failedSite = (written < 8) ? written : 8 + poked;
        for (int i = 0; i < poked; ++i) if (poke32(g_a.div[i], g_chDivOrig[i])) g_chDivPoked[i] = false;
        for (int i = written - 1; i >= 0; --i)
            if (write_code(sites[i].addr, g_chOrig[i], sites[i].steal)) g_chInst[i] = false;
        for (int i = 0; i < CH_SHADOWS; ++i) g_chSh[i].page = 0;
        g_chN = 50;
    }, why, sizeof why);

    if (!ran)
    {
        Log(true, "no moment without another thread near the chat page code came within a second; nothing was patched");
        Log(true, "  last try: %s", why);
        Print(k_colWarn, "Could not patch: the client never left the chat code alone. Nothing was changed.");
        return false;
    }
    if (!g_chOn)
    {
        bool left = false;
        for (int i = 0; i < 8; ++i) left = left || g_chInst[i];
        for (int i = 0; i < 6; ++i) left = left || g_chDivPoked[i];
        if (foreign) Refuse("entry %d no longer holds the client's own bytes (another tool patched it); nothing was changed", failedSite + 1);
        else Refuse("write %d failed - rolled back", failedSite + 1);
        if (left)
        {
            g_chRetained = true;
            Log(true, "the rollback could not put every byte back: the detours stay in as pass-through until the game closes");
            Print(k_colFail, "A patch could not be undone; ChatHistoryPlus stays loaded doing nothing until you close the game.");
        }
        return false;
    }
    m_Want = 0;
    Print(k_colInfo, "On at %d records/page -- %d messages per chat window. Adopted %d page(s) "
                     "across both windows.", n, n * CH_MAX_PAGES, adopted);
    return true;
}

// Convert pages under the detour lock, then restore code under a quiet freeze.
// After disabling, retained detours pass through; Release pins the DLL if any remain.
bool chathistoryplus::Disable(void)
{
    ch_lock_init();
    Site sites[8];
    bool anySplice = false, anyDiv = false;
    if (g_a.ok) ch_sites(sites);
    for (int i = 0; i < 8; ++i) anySplice = anySplice || g_chInst[i];
    for (int i = 0; i < 6; ++i) anyDiv = anyDiv || g_chDivPoked[i];
    if (!g_chOn && !anySplice && !anyDiv) return true;
    if (!g_a.ok) return false;   // cannot happen with something installed; nothing to address it by

    int back = 0, cleared = 0, was = g_chN;
    if (g_chOn)
    {
        // Do not convert pages under a foreign divisor; retain the active plugin.
        for (int i = 0; i < 6; ++i)
            if (g_chDivPoked[i] && *reinterpret_cast<const uint32_t*>(g_a.div[i]) != static_cast<uint32_t>(was))
            {
                Log(true, "divisor %d no longer reads %d (another tool changed it): staying on", i + 1, was);
                Print(k_colFail, "Could not turn off: another tool changed the page divisor. ChatHistoryPlus stays on.");
                return false;
            }
        EnterCriticalSection(&g_chLock);
        Store st[4];
        const int ns = Stores(st, 4);
        for (int i = 0; i < ns; ++i) back += ch_adopt(st[i], false);
        // Drop incompatible stored pages and update the total from the converted live page.
        if (g_chN > 50)
            for (int i = 0; i < ns; ++i) cleared += ch_drop_pages(st[i]);
        for (int i = 0; i < CH_SHADOWS; ++i) g_chSh[i].page = 0;
        g_chOn = false;
        g_chN = 50;
        LeaveCriticalSection(&g_chLock);
    }

    chp::CodeRange ranges[32];
    const size_t nr = ch_ranges(sites, ranges);
    const DWORD skip[1] = { g_chLog.threadId() };
    bool foreignSite[8] = {}, failedSite[8] = {}, foreignDiv[6] = {}, failedDiv[6] = {}, divisorsStuck = false;
    char whyOff[600] = "";
    const bool ran = chp::whenNoThreadIn(ranges, nr, skip, 1, 1000, [] { return g_chInflight == 0; }, [&]
    {
        for (int i = 0; i < 6; ++i)
        {
            if (!g_chDivPoked[i]) continue;
            const uint32_t now = *reinterpret_cast<const uint32_t*>(g_a.div[i]);
            if (now != static_cast<uint32_t>(was)) { foreignDiv[i] = true; divisorsStuck = true; continue; }
            if (poke32(g_a.div[i], g_chDivOrig[i])) g_chDivPoked[i] = false; else { failedDiv[i] = true; divisorsStuck = true; }
        }
        if (divisorsStuck)
        {
            // If removal fails, restore our divisors and re-enable detours before stock tables can be
            // misindexed.
            for (int i = 0; i < 6; ++i)
                if (!g_chDivPoked[i] && *reinterpret_cast<const uint32_t*>(g_a.div[i]) == g_chDivOrig[i] && poke32(g_a.div[i], static_cast<uint32_t>(was)))
                    g_chDivPoked[i] = true;
            return;
        }
        for (int i = 0; i < 8; ++i)
        {
            if (!g_chInst[i]) continue;
            if (!ours(sites[i].addr, sites[i].steal, sites[i].det)) { foreignSite[i] = true; continue; }
            if (write_code(sites[i].addr, g_chOrig[i], sites[i].steal)) g_chInst[i] = false; else failedSite[i] = true;
        }
    }, whyOff, sizeof whyOff);

    bool left = false;
    for (int i = 0; i < 8; ++i)
    {
        if (foreignSite[i]) Log(true, "entry %d holds code this plugin did not write and was left alone", i + 1);
        if (failedSite[i]) Log(true, "entry %d could not be written back", i + 1);
        left = left || g_chInst[i];
    }
    for (int i = 0; i < 6; ++i)
    {
        if (foreignDiv[i]) Log(true, "divisor %d no longer reads %d (another tool changed it) and was left alone", i + 1, was);
        if (failedDiv[i]) Log(true, "divisor %d could not be written back", i + 1);
        left = left || g_chDivPoked[i];
    }
    if (!ran) Log(true, "no moment without another thread near the chat page code came within a second (last try: %s)", whyOff);
    bool divisorMixed = false;
    if (divisorsStuck)
        for (int i = 0; i < 6; ++i)
            if (!g_chDivPoked[i] || *reinterpret_cast<const uint32_t*>(g_a.div[i]) != static_cast<uint32_t>(was))
            {
                divisorMixed = true;
                Log(true, "divisor %d is stuck at %u", i + 1, *reinterpret_cast<const uint32_t*>(g_a.div[i]));
            }
    if ((!ran || divisorsStuck) && was > 50)
    {
        // Re-adopt the converted stock-layout pages.
        EnterCriticalSection(&g_chLock);
        Store st[4];
        int ns = Stores(st, 4);
        // Discard any native page rotated into storage while detours passed through; our divisors cannot
        // index it.
        int rotated = 0;
        for (int i = 0; i < ns; ++i) rotated += ch_drop_pages(st[i]);
        if (rotated) ns = Stores(st, 4);
        g_chN = was;
        for (int i = 0; i < CH_SHADOWS; ++i) g_chSh[i].page = 0;
        for (int i = 0; i < ns; ++i) ch_adopt(st[i], true);
        g_chOn = true;
        LeaveCriticalSection(&g_chLock);
        if (rotated) Log(true, "%d page(s) rotated while the code was passing through were dropped before going back on", rotated);
        if (!ran)
        {
            Log(true, "no quiet moment to put the code back: staying on at %d records/page (the stored pages were dropped)", was);
            Print(k_colFail, "Could not turn off: the client never left the chat code alone, so ChatHistoryPlus stays on.");
        }
        else if (divisorMixed)
        {
            Log(true, "the divisors are mixed after a failed restore: scrollback indexing may be wrong until the game restarts");
            Print(k_colFail, "Could not turn off cleanly: a page divisor is stuck. Scrollback may index wrongly until you restart the game.");
        }
        else
        {
            Log(true, "a divisor could not be put back: staying on at %d records/page (the stored pages were dropped)", was);
            Print(k_colFail, "Could not turn off: a page divisor could not be put back, so ChatHistoryPlus stays on.");
        }
        return false;
    }
    g_chRetained = left;

    if (was > 50)
    {
        Print(k_colWarn, "Off -- %d page(s) written back to the native 50-record table across both "
                         "chat windows.", back);
        if (g_chDropped > 0)
            Print(k_colWarn, "Discarded %d of the oldest message(s) - the stock layout cannot hold them.",
                  g_chDropped);
        g_chDropped = 0;
        if (cleared > 0)
            Print(k_colWarn, "Dropped %d stored page(s) the stock engine cannot read. Relog for a clean "
                             "store.", cleared);
        Log(false, "dropped %d page(s) written at %d records/page", cleared, was);
    }
    if (left)
        Print(k_colFail, "Some of its changes could not be undone; they stay in (passing the client's calls straight "
                         "through) until you close the game.");
    else if (anySplice || anyDiv)
        Log(false, "every change to the client is undone");
    return !left;
}

void chathistoryplus::Tick(void)
{
    if (m_Want == 0 || g_chOn) return;
    static int throttle = 0;
    if (++throttle < 60) return;
    throttle = 0;
    Store st[4];
    const int ns = Stores(st, 4);
    if (ns < 2) return;
    for (int i = 0; i < ns; ++i)
        if (st[i].pages != 0)
        {
            // A stored 50-record page prevents enabling until next login. Report once.
            if (!m_ToldArmed)
            {
                m_ToldArmed = true;
                Print(k_colWarn, "Currently " HL("OFF") " -- your chat log has already started filling, so it turns on "
                                 "by itself at your next login.");
            }
            return;
        }
    if (!Enable())
        m_Want = 0;
}

void chathistoryplus::Direct3DPresent(const RECT*, const RECT*, HWND, const RGNDATA*)
{
    if (m_FrameDead) return;
    try
    {
        Tick();
        const ULONGLONG now = GetTickCount64();
        if (now < m_NextCharCheck) return;
        m_NextCharCheck = now + 1000;
        FollowCharacter();
        if (g_chLog.takeWriteWarning())
            Print(k_colWarn, "can't write its log (%s).", LogShown().c_str());
        if (g_chLog.takeTrimWarning())
            Print(k_colWarn, "its log is over 1.5 MB and cannot be trimmed (%s): is another program holding it open?", LogShown().c_str());
    }
    catch (...)
    {
        m_FrameDead = true;
        Log(true, "error: Direct3DPresent: an unexpected error; its per-frame work stops for this session");
        Print(k_colFail, "an unexpected error stopped its per-frame work.");
    }
}

bool chathistoryplus::Initialize(IAshitaCore* core, ILogManager* logger, uint32_t id)
{
    UNREFERENCED_PARAMETER(logger);
    m_Core = core; m_Id = id;
    m_Root = plog::ashitaRoot(&g_chLog);
    m_Run  = plog::thisRun();
    g_chLog.open(m_Root, plog::startupLogPath(m_Root, "chathistoryplus", m_Run));
    char ver[16], iface[16];
    _snprintf_s(ver, sizeof(ver), _TRUNCATE, "%.1f", GetVersion());
    _snprintf_s(iface, sizeof(iface), _TRUNCATE, "%.2f", GetInterfaceVersion());
    const std::string session = plog::sessionText("chathistoryplus", ver, plog::ownImageStamp(&g_chLog),
                                                  plog::imageStamp(GetModuleHandleA("FFXiMain.dll")), iface, m_Run);
    g_chLog.setSession(session, m_Run);
    g_chLog.write("info", session);
    g_chLog.start();
    // Keep the instance lock if unload retains client hooks. A clean unload permits a new DLL.
    const std::string name = "Local\\chathistoryplus-sole-instance-" + std::to_string(GetCurrentProcessId());
    m_SoleInstance = CreateMutexA(nullptr, TRUE, name.c_str());
    if (m_SoleInstance == nullptr || GetLastError() == ERROR_ALREADY_EXISTS)
    {
        if (m_SoleInstance != nullptr) { CloseHandle(m_SoleInstance); m_SoleInstance = nullptr; }
        m_Refused = true;
        FollowCharacter();
        Print(k_colFail, "ChatHistoryPlus is already loaded in this client, or an earlier load had to stay in memory "
                         "until the game closes; restart the game to load it again.");
        g_chLog.stop();
        m_Core = nullptr;
        return false;
    }
    ch_lock_init();
    memset(g_res, 0, sizeof(g_res));
    memset(&g_a, 0, sizeof(g_a));
    const std::string root = m_Root;
    const plog::Run run = m_Run;
    g_chLog.post([root, run]
    {
        plog::deleteFiles(root, { "logs\\chathistoryplus\\chathistoryplus.log", "logs\\chathistoryplus\\chathistoryplus.log.old",
                                  "logs\\chathistoryplus_diag.log" });
        plog::cleanupStartupFiles(root, "chathistoryplus", run);
    });
    Resolve();
    Report(false);
    Usage();
    m_Want = CH_DEFAULT_N;
    FollowCharacter();
    return true;
}

void chathistoryplus::Release(void)
{
    if (m_Refused) return;
    m_Want = 0;
    Disable();
    // Pin while any remaining entry, divisor or active detour can reach this DLL.
    bool left = g_chOn;
    for (int i = 0; i < 8; ++i) left = left || g_chInst[i];
    for (int i = 0; i < 6; ++i) left = left || g_chDivPoked[i];
    if (left && !ch_pin())
    {
        Log(true, "could not pin the DLL (error %lu) while some of its changes are still in the client", GetLastError());
        Print(k_colFail, "Could not keep itself in memory while some of its changes are still in the game; the game "
                         "may crash, so restart it.");
    }
    Log(false, "unloaded%s%s", left ? "; some of its changes stay in, so the DLL stays mapped until the game closes" : "",
        plog::runSuffix(m_Run).c_str());
    // Stop the writer last; pin if it exceeds the two-second timeout.
    if (!g_chLog.stop()) ch_pin();
    if (g_chPinned)
    {
        if (m_Core != nullptr)
            Chat(k_colInfo, "Unloaded; it stays in memory until the game closes, so restart the game to load "
                            "ChatHistoryPlus again.");
    }
    else
    {
        // Quiet removal leaves no references to trampolines or the lock; release them for a clean reload.
        for (int i = 0; i < 8; ++i)
            if (g_chTramp[i] != nullptr) { VirtualFree(g_chTramp[i], 0, MEM_RELEASE); g_chTramp[i] = nullptr; }
        if (g_chLockInit) { DeleteCriticalSection(&g_chLock); g_chLockInit = false; }
        if (m_SoleInstance != nullptr)
        {
            ReleaseMutex(m_SoleInstance);
            CloseHandle(m_SoleInstance);
            m_SoleInstance = nullptr;
        }
    }
    m_Core = nullptr;
}

bool chathistoryplus::Command(const char* command)
{
    if (command == nullptr) return false;

    std::vector<std::string> args;
    {
        std::string s(command), cur;
        for (size_t i = 0; i <= s.size(); ++i)
        {
            if (i == s.size() || s[i] == ' ') { if (!cur.empty()) { args.push_back(cur); cur.clear(); } }
            else cur += s[i];
        }
    }
    if (args.empty()) return false;
    if (_stricmp(args[0].c_str(), "/chathistoryplus") != 0 && _stricmp(args[0].c_str(), "/chp") != 0)
        return false;
    m_CmdOurs = true;

    const char* a = (args.size() > 1) ? args[1].c_str() : "status";

    if (_stricmp(a, "diag") == 0)
    {
        if (!g_chOn) Resolve();
        DiagBegin();
        Report(true);
        Probe();
        if (g_chOn)
        {
            unsigned spl = 0;
            for (size_t i = 0; i < k_sigN; ++i) if (k_sigs[i].kind == K_SPLICE) ++spl;
            Log(false, "(%u of the %u signatures sit under this plugin's own patches while enabled, "
                       "so they are reported from the cached scan rather than re-read)",
                spl, static_cast<unsigned>(k_sigN));
        }
        DiagEnd();
    }
    else if (_stricmp(a, "status") == 0) { Status(); if (args.size() <= 1) Usage(false); }
    else Usage(true);
    return true;
}

bool chathistoryplus::HandleCommand(int32_t mode, const char* command, bool injected)
{
    UNREFERENCED_PARAMETER(mode);
    UNREFERENCED_PARAMETER(injected);
    m_CmdOurs = false;
    try
    {
        return Command(command);
    }
    catch (...)
    {
        m_Diag = false;
        if (!m_CmdOurs) return false;   // it failed before it was known to be ours: leave it to its owner
        Log(true, "error: HandleCommand: an unexpected error");
        Print(k_colFail, "the command failed with an unexpected error.");
        return true;
    }
}

// Plugin entry points.
extern "C"
{
    __declspec(noinline) IPlugin* __stdcall expCreatePlugin(const char* args)
    {
        UNREFERENCED_PARAMETER(args);
        return new chathistoryplus();
    }
    __declspec(noinline) void __stdcall expDestroyPlugin(void* instance)
    {
        if (instance != nullptr) delete static_cast<chathistoryplus*>(instance);
    }
    __declspec(noinline) double __stdcall expGetInterfaceVersion(void)
    {
        return ASHITA_INTERFACE_VERSION;
    }
}
