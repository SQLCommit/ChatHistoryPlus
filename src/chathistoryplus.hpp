/**
 * ChatHistoryPlus - raises how much chat history FFXI keeps.
 *
 * Native: 50 records per page x 20 pages = 1000 messages per chat window. This raises the
 * records-per-page figure, which multiplies the whole store.
 */
#define HL(s) "\x11" s "\x12"

#ifndef CHATHISTORYPLUS_HPP_INCLUDED
#define CHATHISTORYPLUS_HPP_INCLUDED

#include "Ashita.h"

#include <cstdint>
#include <windows.h>

enum SigCode : uint8_t { SIG_OK = 0, SIG_NOT_FOUND, SIG_AMBIGUOUS, SIG_FAULTED };

struct SigResult
{
    SigCode   code;
    uint32_t  hits;        // total matches
    uintptr_t at;          // match address
    uint32_t  rva;
};

struct ModuleInfo
{
    uintptr_t base;
    uint32_t  sizeOfImage;
    uint32_t  timeStamp;
    const IMAGE_SECTION_HEADER* sec;
    unsigned  nsec;
    unsigned  nexec;
};

// One page store: the container the engine indexes as page = idx/N, slot = idx%N.
struct Store
{
    uintptr_t iter;        // holds the LIVE page at +0x04 and the container at +0x0C
    uintptr_t cont;
    uintptr_t live;
    int       pages;
    int       overflow;    // bumps only once the 20-slot array wraps, not once per page
    int       liveCount;
};

class chathistoryplus final : public IPlugin
{
    IAshitaCore* m_Core;
    ILogManager* m_Log;
    uint32_t     m_Id;

    uintptr_t m_Base;
    uint32_t  m_ImgStamp;
    bool      m_Resolved;      // all signatures unique AND every derived address sane

    int       m_Want;          // non-zero = enable pending; Tick applies it at the next safe moment

    bool Resolve(void);
    bool Derive(void);
    void Report(bool toLog);
    int  Stores(Store* out, int max);
    void Print(uint8_t colour, const char* fmt, ...);
    FILE* m_DiagFp = nullptr;
    bool  DiagOpen(char* pathOut, size_t n);
    void  DiagClose(void);

    bool m_ToldWhy = false;
    void Refuse(const char* fmt, ...);

    void Log(bool warn, const char* fmt, ...);
    void Usage(bool verbose = false);
    void Status(void);
    void Probe(void);
    void DumpWords(const char* tag, uintptr_t at, int words);
    bool Enable(void);   // always CH_DEFAULT_N as the size is not selectable
    bool Disable(void);
    void Tick(void);

public:
    chathistoryplus(void);
    ~chathistoryplus(void) = default;

    const char* GetName(void) const override { return "ChatHistoryPlus"; }
    const char* GetAuthor(void) const override { return "SQLCommit"; }
    const char* GetDescription(void) const override { return "Raises how much chat history FFXI keeps."; }
    const char* GetLink(void) const override { return ""; }
    double GetVersion(void) const override { return 1.0; }
    double GetInterfaceVersion(void) const override { return ASHITA_INTERFACE_VERSION; }
    int32_t GetPriority(void) const override { return 0; }
    uint32_t GetFlags(void) const override
    {
        return static_cast<uint32_t>(Ashita::PluginFlags::UseCommands)
             | static_cast<uint32_t>(Ashita::PluginFlags::UseDirect3D);
    }

    bool Initialize(IAshitaCore* core, ILogManager* logger, uint32_t id) override;
    void Release(void) override;
    bool HandleCommand(int32_t mode, const char* command, bool injected) override;
    bool Direct3DInitialize(IDirect3DDevice8*) override { return true; }
    void Direct3DPresent(const RECT*, const RECT*, HWND, const RGNDATA*) override;
};

#endif // CHATHISTORYPLUS_HPP_INCLUDED
