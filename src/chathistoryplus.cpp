/**
 * ChatHistoryPlus - see chathistoryplus.hpp.
 */
#include "chathistoryplus.hpp"

#include <cstdarg>
#include <ctime>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace
{
    // kind: SPLICE = a function we will detour or call; DIVISOR = a function anchor holding imm32
    // records-per-page values at fixed offsets; DATAREF = the operand is the address of a global.
    enum Kind : uint8_t { K_SPLICE = 0, K_DIVISOR = 1, K_DATAREF = 2 };

    struct Sig
    {
        const char* name;
        const uint8_t* pat;
        const char* mask;
        size_t      len;
        Kind        kind;
        uint32_t    knownRva;      // where it matched in the reference image (documentation only)
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
    const uint8_t s_mtadd[] = { 0x8B,0x44,0x24,0x04,0x56,0x8B,0xF1,0x50,0x8B,0x4E,0x04 };

    // Anchored to the FUNCTION, not per-site
    const uint8_t d_a[] = { 0x81,0xEC,0x00,0x01,0x00,0x00,0x56,0x8B,0xF1,0x8A,0x4E,0x54 };
    const uint8_t d_b[] = { 0x56,0x8B,0xF1,0x57,0x8B,0x4E,0x0C,0x8A,0x41,0x60 };
    const uint8_t d_c[] = { 0x53,0x56,0x57,0x8B,0xF9,0x8B,0x4F,0x0C,0x8A,0x41,0x60 };
    const uint8_t d_d[] = { 0x56,0x57,0x8B,0xF9,0x8B,0x4F,0x0C,0x8A,0x41,0x60,0x84,0xC0,0x75,0x05 };

    const uint8_t s_mgr[] = { 0x0D,0x00,0x00,0x00,0x00,0x50,0xE8,0x00,0x00,0x00,0x00,0x66,0x83,0xBF,0x10,0x02,0x00,0x00 };

    // Index into k_sigs / g_res.
    enum SigIdx {
        SI_CTOR = 0, SI_DTOR, SI_LOAD, SI_SAVE, SI_APPEND, SI_RESOLVE, SI_RECOUNT,
        SI_FREEBLOB, SI_STOREADD, SI_DIV_A, SI_DIV_B, SI_DIV_C, SI_DIV_D, SI_CHATMGR
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
      { "store_append", s_mtadd,   "xxxxxxxxxxx",          sizeof(s_mtadd),   K_SPLICE,  0x18EC10,  8, -1, NOFF },

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

    // -- signature scanning -----------------------------------------------------------------------

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

    // -- resolved addresses -----------------------------------------------------------------------

    struct Addrs
    {
        uintptr_t ctor, dtor, load, save, append, resolve, recount;   // spliced
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
    enum { CH_MAX_N = 200, CH_SHADOWS = 64, CH_BLOB_MAX = 0x7F00, CH_MAX_PAGES = 20 };

    struct ChShadow { uintptr_t page; uint16_t n; uint16_t off[CH_MAX_N]; };
    ChShadow  g_chSh[CH_SHADOWS];
    const int CH_DEFAULT_N = 140;   // the size the plugin arms itself at; not selectable
    int       g_chN  = 50;      // records per page currently in force
    int       g_chDropped = 0;  // records the last teardown could not hand back (reported, not hidden)
    bool      g_chOn = false;
    void*     g_chTramp[7] = { nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr };
    uint8_t   g_chOrig[7][16];
    bool      g_chInst[7] = { false, false, false, false, false, false, false };
    uint32_t  g_chDivOrig[6];
    // 0 ctor, 1 dtor, 2 load, 3 save, 4 append, 5 resolve, 6 recount.
    volatile uint32_t g_chHit[7];
    volatile uint32_t g_chFail[7];

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
    ChShadow* ch_alloc(uintptr_t page)
    {
        ChShadow* s = ch_find(page);
        if (s != nullptr) return s;
        for (int i = 0; i < CH_SHADOWS; ++i)
            if (g_chSh[i].page == 0)
            {
                g_chSh[i].page = page;
                g_chSh[i].n = static_cast<uint16_t>(g_chN);
                for (int k = 0; k < CH_MAX_N; ++k) g_chSh[i].off[k] = 0xFFFF;
                return &g_chSh[i];
            }
        return nullptr;
    }

    // The blobs are allocated and freed by ENGINE code, so we must use the engine's allocator.
    // __fastcall with a dummy edx is how MSVC spells __thiscall for a function pointer.
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

    // -- the seven replacements -------------------------------------------------------------------

    void __fastcall ch_recount(void* self, void*)
    {
        ++g_chHit[6];
        const uintptr_t page = reinterpret_cast<uintptr_t>(self);
        ChShadow* s = ch_find(page);
        const uintptr_t data = ch_r32(page + PGF_DATA);
        const int size = static_cast<int>(ch_r16(page + PGF_SIZE));
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
        // The engine's own liveness rule: an offset is live iff it is in range and points just past
        // a NUL. Keep this, the native function and chatpage.py in lockstep.
        for (int i = 0; i < s->n; ++i)
        {
            const int off = static_cast<int16_t>(s->off[i]);
            const bool ok = (off >= 0) && (off < size) &&
                            (off == 0 || (data >= 0x10000 && ch_r8(data + off - 1) == 0));
            if (!ok) s->off[i] = 0xFFFF; else ++cnt;
        }
        ch_w8(page + PGF_COUNT, static_cast<uint8_t>(cnt > 255 ? 255 : cnt));
    }

    char* __fastcall ch_resolve(void* self, void*, int idx)
    {
        ++g_chHit[5];
        const uintptr_t page = reinterpret_cast<uintptr_t>(self);
        const ChShadow* s = ch_find(page);
        if (idx < 0 || idx >= static_cast<int>(ch_r8(page + PGF_COUNT))) return nullptr;
        if (s == nullptr)
        {
            if (idx >= 50) return nullptr;
            const int noff = static_cast<int16_t>(ch_r16(page + idx * 2));
            if (noff < 0 || noff >= static_cast<int>(ch_r16(page + PGF_SIZE))) { ++g_chFail[5]; return nullptr; }
            const uintptr_t nd = ch_r32(page + PGF_DATA);
            if (nd < 0x10000) { ++g_chFail[5]; return nullptr; }
            return reinterpret_cast<char*>(nd + noff);
        }
        const int off = static_cast<int16_t>(s->off[idx]);
        if (off < 0 || off >= static_cast<int>(ch_r16(page + PGF_SIZE))) { ++g_chFail[5]; return nullptr; }
        const uintptr_t data = ch_r32(page + PGF_DATA);
        if (data < 0x10000) { ++g_chFail[5]; return nullptr; }
        return reinterpret_cast<char*>(data + off);
    }

    int __fastcall ch_append(void* self, void*, const char* txt)
    {
        ++g_chHit[4];
        const uintptr_t page = reinterpret_cast<uintptr_t>(self);
        if (txt == nullptr) return 1;
        ChShadow* s = ch_find(page);
        if (s == nullptr) s = ch_alloc(page);
        if (s == nullptr) { ++g_chFail[4]; return -1; }

        const int len = static_cast<int>(strlen(txt));
        const int cnt = static_cast<int>(ch_r8(page + PGF_COUNT));
        if (cnt >= s->n) return -1;
        const int size = static_cast<int>(ch_r16(page + PGF_SIZE));

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
        s->off[cnt] = static_cast<uint16_t>(size);
        ch_w16(page + PGF_SIZE, static_cast<uint16_t>(size + wlen + 1));
        ch_w8(page + PGF_COUNT, static_cast<uint8_t>(cnt + 1));
        return 1;
    }

    int ch_best_hdr(const uint8_t* buf, int fsz, int n)
    {
        const int cands[2] = { 2 * n, 100 };
        int bestH = -1, bestCnt = -1;
        for (int c = 0; c < 2; ++c)
        {
            const int H = cands[c];
            if (H <= 0 || fsz < H) continue;
            if (c == 1 && cands[0] == cands[1]) continue;
            const int dsz = fsz - H;
            const uint8_t* data = buf + H;
            int cnt = 0;
            for (int i = 0; i < H / 2 && i < CH_MAX_N; ++i)
            {
                const int off = static_cast<int16_t>(
                    static_cast<uint16_t>(buf[i * 2] | (buf[i * 2 + 1] << 8)));
                if (off < 0 || off >= dsz) continue;
                if (off > 0 && data[off - 1] != 0) continue;
                ++cnt;
            }
            if (cnt > bestCnt) { bestCnt = cnt; bestH = H; }
        }
        return bestH;
    }

    int __fastcall ch_load(void* self, void*, void* file)
    {
        ++g_chHit[2];
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
        const int nEnt = (hdr / 2 > CH_MAX_N) ? CH_MAX_N : hdr / 2;
        memcpy(s->off, buf, static_cast<size_t>(nEnt * 2));
        for (int i = nEnt; i < CH_MAX_N; ++i) s->off[i] = 0xFFFF;
        ch_del(buf);

        ch_w32(page + PGF_DATA, reinterpret_cast<uint32_t>(blob));
        ch_w32(page + PGF_CAP, static_cast<uint32_t>(dsz));
        ch_w16(page + PGF_SIZE, static_cast<uint16_t>(dsz));
        ch_recount(self, nullptr);
        return 1;
    }

    int __fastcall ch_save(void* self, void*, void* file)
    {
        ++g_chHit[3];
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
        w(mgr, nullptr, file, s->off, 2 * s->n, 0);
        const uintptr_t data = ch_r32(page + PGF_DATA);
        if (data >= 0x10000) w(mgr, nullptr, file, reinterpret_cast<const void*>(data),
                               static_cast<int>(ch_r16(page + PGF_SIZE)), 1);
        return 1;
    }

    void* __fastcall ch_ctor(void* self, void* edx, uint32_t fidx)
    {
        ++g_chHit[0];
        return reinterpret_cast<void*(__fastcall*)(void*, void*, uint32_t)>(g_chTramp[0])(self, edx, fidx);
    }
    void __fastcall ch_dtor(void* self, void* edx)
    {
        ++g_chHit[1];
        ChShadow* s = ch_find(reinterpret_cast<uintptr_t>(self));
        if (s != nullptr) s->page = 0;
        reinterpret_cast<void(__fastcall*)(void*, void*)>(g_chTramp[1])(self, edx);
    }

    // -- splice mechanics --------------------------------------------------------------------------

    bool ours(uintptr_t addr, int steal, const void* detour)
    {
        const uint8_t* t = reinterpret_cast<const uint8_t*>(addr);
        if (t[0] != 0xE9) return false;
        if (*reinterpret_cast<const int32_t*>(t + 1) !=
            static_cast<int32_t>(reinterpret_cast<uintptr_t>(detour) - (addr + 5))) return false;
        for (int j = 5; j < steal; ++j) if (t[j] != 0x90) return false;
        return true;
    }

    bool splice(uintptr_t addr, int steal, void* detour, void** tramp, uint8_t* orig, bool* inst)
    {
        if (*inst) return true;
        uint8_t* target = reinterpret_cast<uint8_t*>(addr);
        uint8_t* t = static_cast<uint8_t*>(VirtualAlloc(nullptr, 32, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if (t == nullptr) return false;
        memcpy(orig, target, steal);
        memcpy(t, target, steal);
        t[steal] = 0xE9;
        *reinterpret_cast<int32_t*>(t + steal + 1) =
            static_cast<int32_t>((addr + steal) - (reinterpret_cast<uintptr_t>(t) + steal + 5));
        *tramp = t;
        DWORD op = 0;
        if (!VirtualProtect(target, steal, PAGE_EXECUTE_READWRITE, &op))
        { VirtualFree(t, 0, MEM_RELEASE); *tramp = nullptr; return false; }
        target[0] = 0xE9;
        *reinterpret_cast<int32_t*>(target + 1) =
            static_cast<int32_t>(reinterpret_cast<uintptr_t>(detour) - (addr + 5));
        for (int j = 5; j < steal; ++j) target[j] = 0x90;
        VirtualProtect(target, steal, op, &op);
        FlushInstructionCache(GetCurrentProcess(), target, steal);
        *inst = true;
        return true;
    }

    void unsplice(uintptr_t addr, int steal, const void* detour, void** tramp, uint8_t* orig, bool* inst)
    {
        if (!*inst) return;
        uint8_t* target = reinterpret_cast<uint8_t*>(addr);
        if (!ours(addr, steal, detour)) { *inst = false; return; }
        DWORD op = 0;
        if (!VirtualProtect(target, steal, PAGE_EXECUTE_READWRITE, &op)) return;
        memcpy(target, orig, steal);
        VirtualProtect(target, steal, op, &op);
        FlushInstructionCache(GetCurrentProcess(), target, steal);
        (void)tramp;
        *inst = false;
    }

    bool poke32(uintptr_t addr, uint32_t v)
    {
        DWORD op = 0;
        if (!VirtualProtect(reinterpret_cast<void*>(addr), 4, PAGE_EXECUTE_READWRITE, &op)) return false;
        *reinterpret_cast<volatile uint32_t*>(addr) = v;
        VirtualProtect(reinterpret_cast<void*>(addr), 4, op, &op);
        FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(addr), 4);
        return true;
    }

    // -- adoption ---------------------------------------------------------------------------------
    // adopt=true  : copy each live page's native 50-entry table into its shadow (install)
    // adopt=false : write the shadow's first 50 entries back and clamp the count (remove)
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
                for (int k = 0; k < 50; ++k) s->off[k] = ch_r16(page + k * 2);
                for (int k = 50; k < CH_MAX_N; ++k) s->off[k] = 0xFFFF;
                s->n = static_cast<uint16_t>(g_chN);
            }
            else
            {
                const ChShadow* s = ch_find(page);
                if (s == nullptr) continue;
                // Keep the newest 50
                int live = static_cast<int>(ch_r8(page + PGF_COUNT));
                if (live > CH_MAX_N) live = CH_MAX_N;
                const int first = (live > 50) ? (live - 50) : 0;   // index of the oldest kept record
                const int keep  = (live > 50) ? 50 : live;
                for (int k = 0; k < keep; ++k) ch_w16(page + k * 2, s->off[first + k]);
                for (int k = keep; k < 50; ++k) ch_w16(page + k * 2, 0xFFFF);   // unused slots empty
                if (live > 50) ch_w8(page + PGF_COUNT, 50);   // native tables hold 50
                g_chDropped += (live > 50) ? (live - 50) : 0;
            }
            ++touched;
        }
        return touched;
    }
}

// ------------------------------------------------------------------------------------------------

chathistoryplus::chathistoryplus(void)
    : m_Core(nullptr), m_Log(nullptr), m_Id(0), m_Base(0), m_ImgStamp(0), m_Resolved(false), m_Want(0)
{
    memset(g_res, 0, sizeof(g_res));
    memset(&g_a, 0, sizeof(g_a));
}

void chathistoryplus::Print(uint8_t colour, const char* fmt, ...)
{
    if (fmt == nullptr) return;
    char raw[512];
    va_list ap; va_start(ap, fmt);
    _vsnprintf_s(raw, sizeof(raw), _TRUNCATE, fmt, ap);
    va_end(ap);

    if (m_DiagFp != nullptr)
    {
        char flat[512]; size_t f = 0;
        for (size_t r = 0; raw[r] != '\0' && f + 1 < sizeof(flat); ++r)
            if (raw[r] != HL_ON && raw[r] != HL_OFF) flat[f++] = raw[r];
        flat[f] = '\0';
        fprintf(m_DiagFp, "      %s\n", flat);
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

    Log(colour == k_colFail, "%s", plain);

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
    Print(k_colWarn, "Nothing was patched - this client build is not one ChatHistoryPlus knows.");
}

void chathistoryplus::Log(bool warn, const char* fmt, ...)
{
    if (fmt == nullptr) return;
    char buf[512];
    va_list ap; va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    if (m_DiagFp != nullptr)
    {
        fprintf(m_DiagFp, "%s%s\n", warn ? "WARN  " : "      ", buf);
        return;
    }
    if (m_Log == nullptr) return;
    m_Log->Logf(static_cast<uint32_t>(warn ? Ashita::LogLevel::Warn : Ashita::LogLevel::Info),
                "ChatHistoryPlus", "%s", buf);
}

bool chathistoryplus::DiagOpen(char* pathOut, size_t n)
{
    if (m_Core == nullptr) return false;
    const char* inst = m_Core->GetInstallPath();
    if (inst == nullptr || inst[0] == '\0') return false;

    const size_t len = strlen(inst);
    const char* sep  = (len > 0 && (inst[len - 1] == '\\' || inst[len - 1] == '/')) ? "" : "\\";
    _snprintf_s(pathOut, n, _TRUNCATE, "%s%slogs\\chathistoryplus_diag.log", inst, sep);

    if (fopen_s(&m_DiagFp, pathOut, "a") != 0 || m_DiagFp == nullptr) { m_DiagFp = nullptr; return false; }

    char stamp[64] = "unknown time";
    __time64_t t = _time64(nullptr);
    struct tm lt;
    if (_localtime64_s(&lt, &t) == 0) strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &lt);
    fprintf(m_DiagFp, "\n===== ChatHistoryPlus diag  %s =====\n", stamp);
    return true;
}

void chathistoryplus::DiagClose(void)
{
    if (m_DiagFp == nullptr) return;
    fclose(m_DiagFp);
    m_DiagFp = nullptr;
}

void chathistoryplus::Usage(bool verbose)
{
    Print(k_colInfo, HL("/chathistoryplus") " [" HL("status") "|" HL("diag") "]   (or " HL("/chp") ")");
    if (!verbose) return;
    Print(k_colInfo, "Keeps %d messages per chat window instead of 1000. Applies itself; if your "
                     "log has already started filling, it waits for your next login.",
          CH_DEFAULT_N * CH_MAX_PAGES);
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
    for (int i = 0; i < 7; ++i)
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

    if (!toLog) return;
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

    // Each window keeps its own copy of the same history, so two identical rows read as a total.
    // Collapse them; print both only when they differ, which means the windows are filtered apart.
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
        Log(true, "only %d of 2 stores reachable; refusing - the size constant is shared code", ns);
        Print(k_colWarn, "Only one chat window's store is reachable, so nothing was changed.");
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
        Log(false, "  mgr%d +0x%05X iter 0x%08X cont 0x%08X vtbl 0x%08X pages %u overflow %u "
                   "live 0x%08X count %u%s",
            c + 1, off, it, ct, vt, pages, ovf, live, lcnt,
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
            safe_r32(live + PGF_SIZE, &siz);
            Log(false, "    live page: count %u data 0x%08X cap %u size %u",
                cnt & 0xFF, dat, cap, siz & 0xFFFF);
            DumpWords("    live off[]", live, 6);
        }
    }
    for (int i = 0; i < 7; ++i)
        Log(false, "  detour %d hits %u fails %u", i, g_chHit[i], g_chFail[i]);
}

bool chathistoryplus::Enable(void)
{
    const int n = CH_DEFAULT_N;
    if (!m_Resolved && !Resolve()) { Report(false); return false; }
    if (!g_a.ok) { Refuse("addresses did not check out"); return false; }
    if (g_chOn)
    {
        Log(false, "already on at %d records/page", g_chN);
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

    struct Site { uintptr_t addr; int steal; void* det; };
    const Site sites[7] = {
        { g_a.ctor,    k_sigs[SI_CTOR].steal,    reinterpret_cast<void*>(&ch_ctor)    },
        { g_a.dtor,    k_sigs[SI_DTOR].steal,    reinterpret_cast<void*>(&ch_dtor)    },
        { g_a.load,    k_sigs[SI_LOAD].steal,    reinterpret_cast<void*>(&ch_load)    },
        { g_a.save,    k_sigs[SI_SAVE].steal,    reinterpret_cast<void*>(&ch_save)    },
        { g_a.append,  k_sigs[SI_APPEND].steal,  reinterpret_cast<void*>(&ch_append)  },
        { g_a.resolve, k_sigs[SI_RESOLVE].steal, reinterpret_cast<void*>(&ch_resolve) },
        { g_a.recount, k_sigs[SI_RECOUNT].steal, reinterpret_cast<void*>(&ch_recount) },
    };

    g_chN = n;
    for (int i = 0; i < CH_SHADOWS; ++i) g_chSh[i].page = 0;
    memset(const_cast<uint32_t*>(g_chHit), 0, sizeof(g_chHit));
    memset(const_cast<uint32_t*>(g_chFail), 0, sizeof(g_chFail));

    int adopted = 0;   // adopt before splicing
    for (int i = 0; i < ns; ++i) adopted += ch_adopt(st[i], true);

    for (int i = 0; i < 7; ++i)
        if (!splice(sites[i].addr, sites[i].steal, sites[i].det,
                    &g_chTramp[i], g_chOrig[i], &g_chInst[i]))
        {
            Refuse("splice %d failed - rolling back", i + 1);
            for (int j = 0; j < 7; ++j)
                unsplice(sites[j].addr, sites[j].steal, sites[j].det,
                         &g_chTramp[j], g_chOrig[j], &g_chInst[j]);
            for (int j = 0; j < ns; ++j) ch_adopt(st[j], false);
            g_chN = 50;
            return false;
        }

    for (int i = 0; i < 6; ++i)
    {
        g_chDivOrig[i] = *reinterpret_cast<const uint32_t*>(g_a.div[i]);
        poke32(g_a.div[i], static_cast<uint32_t>(n));
    }
    g_chOn = true;
    m_Want = 0;
    Print(k_colInfo, "On at %d records/page -- %d messages per chat window. Adopted %d page(s) "
                     "across both windows.", n, n * CH_MAX_PAGES, adopted);
    return true;
}

bool chathistoryplus::Disable(void)
{
    if (!g_chOn) return true;

    Store st[4];
    const int ns = Stores(st, 4);

    // Restore the native tables while the detours are STILL LIVE
    int back = 0;
    for (int i = 0; i < ns; ++i) back += ch_adopt(st[i], false);

    int cleared = 0;
    if (g_chN > 50)
        for (int i = 0; i < ns; ++i)
        {
            if (st[i].pages == 0) continue;
            ch_w8(st[i].cont + CT_PAGES, 0);
            cleared += st[i].pages;
        }

    // iter+0x08 is the store's total record count
    if (g_chN > 50)
        for (int i = 0; i < ns; ++i)
        {
            if (st[i].iter < 0x10000) continue;
            uint32_t total = 0;
            if (!safe_r32(st[i].iter + IT_TOTAL, &total)) continue;
            const uint32_t live = (st[i].liveCount > 50) ? 50u : static_cast<uint32_t>(st[i].liveCount);
            if (total != live) ch_w32(st[i].iter + IT_TOTAL, live);
        }

    struct Site { uintptr_t addr; int steal; void* det; };
    const Site sites[7] = {
        { g_a.ctor,    k_sigs[SI_CTOR].steal,    reinterpret_cast<void*>(&ch_ctor)    },
        { g_a.dtor,    k_sigs[SI_DTOR].steal,    reinterpret_cast<void*>(&ch_dtor)    },
        { g_a.load,    k_sigs[SI_LOAD].steal,    reinterpret_cast<void*>(&ch_load)    },
        { g_a.save,    k_sigs[SI_SAVE].steal,    reinterpret_cast<void*>(&ch_save)    },
        { g_a.append,  k_sigs[SI_APPEND].steal,  reinterpret_cast<void*>(&ch_append)  },
        { g_a.resolve, k_sigs[SI_RESOLVE].steal, reinterpret_cast<void*>(&ch_resolve) },
        { g_a.recount, k_sigs[SI_RECOUNT].steal, reinterpret_cast<void*>(&ch_recount) },
    };
    for (int i = 0; i < 7; ++i)
        unsplice(sites[i].addr, sites[i].steal, sites[i].det,
                 &g_chTramp[i], g_chOrig[i], &g_chInst[i]);
    for (int i = 0; i < 6; ++i) poke32(g_a.div[i], g_chDivOrig[i]);
    for (int i = 0; i < CH_SHADOWS; ++i) g_chSh[i].page = 0;

    const int was = g_chN;
    g_chOn = false;
    g_chN = 50;
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
    return true;
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
    for (int i = 0; i < ns; ++i) if (st[i].pages != 0) return;
    if (!Enable())
        m_Want = 0;
}

void chathistoryplus::Direct3DPresent(const RECT*, const RECT*, HWND, const RGNDATA*)
{
    Tick();
}

bool chathistoryplus::Initialize(IAshitaCore* core, ILogManager* logger, uint32_t id)
{
    m_Core = core; m_Log = logger; m_Id = id;
    Resolve();
    Report(true);
    Usage();
    m_Want = CH_DEFAULT_N;
    return true;
}

void chathistoryplus::Release(void)
{
    Disable();
    Log(false, "released.");
}

bool chathistoryplus::HandleCommand(int32_t mode, const char* command, bool injected)
{
    UNREFERENCED_PARAMETER(mode);
    UNREFERENCED_PARAMETER(injected);
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

    const char* a = (args.size() > 1) ? args[1].c_str() : "status";

    if (_stricmp(a, "diag") == 0)
    {
        if (!g_chOn) Resolve();
        char path[MAX_PATH];
        const bool toFile = DiagOpen(path, sizeof(path));
        Report(true);
        Probe();
        if (g_chOn)
            Log(false, "(7 of the 14 signatures sit under this plugin's own patches while enabled, "
                       "so they are reported from the cached scan rather than re-read)");
        if (toFile)
        {
            DiagClose();
            Print(k_colInfo, "Diagnostics written to " HL("logs\\chathistoryplus_diag.log")
                             " in your Ashita folder.");
        }
        else Print(k_colWarn, "Could not open the diagnostic file - written to the Ashita log instead.");
    }
    else if (_stricmp(a, "status") == 0) { Status(); if (args.size() <= 1) Usage(false); }
    else Usage(true);
    return true;
}

// ------------------------------------------------------------------------------------------------
// Ashita plugin entry points (see src/exports.def).
// ------------------------------------------------------------------------------------------------
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
