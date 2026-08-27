#pragma once

// Real ISO9660 filesystem reader over a mounted PS2 disc image (.iso, 2048
// byte/sector). Modeled directly on RecompOne's DiscFs.cs (the file-lookup
// layer behind the working SymphonyRecomp static-recompilation project) --
// see project memory 2026-08-27 for the full rationale: DQ8's file-open path
// has no real backing data source today, and every attempt to fake individual
// SIF-reply fields or BSS comparison flags has been unreliable at best. This
// class exists to serve REAL bytes for REAL requested files/paths instead.
//
// Validated standalone against the actual DQ8 disc image before integration:
// SLUS_212.07 read back byte-for-byte identical to the already-extracted
// known-good copy, SYSTEM.CNF read correctly, and MODULES/CDVDSTM.IRX located
// via directory traversal with the exact expected size (33521 bytes).

#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

class Ps2DiscFs
{
public:
    struct Entry
    {
        uint32_t lba = 0;
        uint32_t size = 0;
        bool isDir = false;
        std::string name;
    };

    // Returns nullptr if the file can't be opened or doesn't look like a
    // valid ISO9660 image (PVD signature check at sector 16).
    static std::unique_ptr<Ps2DiscFs> Open(const std::string &isoPath);

    ~Ps2DiscFs();
    Ps2DiscFs(const Ps2DiscFs &) = delete;
    Ps2DiscFs &operator=(const Ps2DiscFs &) = delete;

    // path uses '/' or '\\' as separators, e.g. "MODULES/CDVDSTM.IRX" or
    // "SLUS_212.07" for a root-level file. Case-insensitive; ";N" ISO9660
    // version suffixes are stripped automatically on both sides.
    bool Locate(const std::string &path, uint32_t &outLba, uint32_t &outSize) const;
    bool ReadFile(const std::string &path, std::vector<uint8_t> &outData) const;

    // Reads `size` bytes starting at sector `lba`, spanning as many 2048-byte
    // sectors as needed. Used once a caller already has an LBA (e.g. from a
    // prior Locate call), without repeating the path lookup.
    std::vector<uint8_t> ReadSectors(uint32_t lba, uint32_t size) const;

    void ListDir(const std::string &path, std::vector<Entry> &outEntries) const;

private:
    Ps2DiscFs() = default;

    bool readSector(uint32_t lba, uint8_t *buf) const;
    bool readRoot();
    static Entry parseEntry(const uint8_t *data, size_t off);
    std::vector<Entry> listEntries(const Entry &dir) const;
    bool findInDir(const Entry &dir, const std::string &name, bool wantDir, Entry &out) const;
    bool resolve(const std::string &path, Entry &out) const;
    static std::string stripVersion(const std::string &name);
    static std::string toUpper(const std::string &s);
    static std::vector<std::string> splitPath(const std::string &path);

    FILE *m_file = nullptr;
    Entry m_root{};
};
