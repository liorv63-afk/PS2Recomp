#include "ps2_disc_fs.h"

#include <algorithm>
#include <cctype>
#include <cstring>

std::unique_ptr<Ps2DiscFs> Ps2DiscFs::Open(const std::string &isoPath)
{
    FILE *f = nullptr;
#if defined(_WIN32)
    fopen_s(&f, isoPath.c_str(), "rb");
#else
    f = fopen(isoPath.c_str(), "rb");
#endif
    if (!f)
    {
        return nullptr;
    }
    std::unique_ptr<Ps2DiscFs> fs(new Ps2DiscFs());
    fs->m_file = f;
    if (!fs->readRoot())
    {
        return nullptr;
    }
    return fs;
}

Ps2DiscFs::~Ps2DiscFs()
{
    if (m_file)
    {
        fclose(m_file);
    }
}

bool Ps2DiscFs::Locate(const std::string &path, uint32_t &outLba, uint32_t &outSize) const
{
    Entry e;
    if (!resolve(path, e))
    {
        return false;
    }
    outLba = e.lba;
    outSize = e.size;
    return true;
}

bool Ps2DiscFs::ReadFile(const std::string &path, std::vector<uint8_t> &outData) const
{
    Entry e;
    if (!resolve(path, e))
    {
        return false;
    }
    outData = ReadSectors(e.lba, e.size);
    return true;
}

void Ps2DiscFs::ListDir(const std::string &path, std::vector<Entry> &outEntries) const
{
    Entry dir = m_root;
    if (!path.empty())
    {
        if (!resolve(path, dir) || !dir.isDir)
        {
            return;
        }
    }
    outEntries = listEntries(dir);
}

bool Ps2DiscFs::readSector(uint32_t lba, uint8_t *buf) const
{
    const long long offset = static_cast<long long>(lba) * 2048;
#if defined(_WIN32)
    if (_fseeki64(m_file, offset, SEEK_SET) != 0)
#else
    if (fseeko(m_file, static_cast<off_t>(offset), SEEK_SET) != 0)
#endif
    {
        return false;
    }
    return fread(buf, 1, 2048, m_file) == 2048;
}

Ps2DiscFs::Entry Ps2DiscFs::parseEntry(const uint8_t *data, size_t off)
{
    Entry e;
    e.lba = static_cast<uint32_t>(data[off + 2]) |
            (static_cast<uint32_t>(data[off + 3]) << 8) |
            (static_cast<uint32_t>(data[off + 4]) << 16) |
            (static_cast<uint32_t>(data[off + 5]) << 24);
    e.size = static_cast<uint32_t>(data[off + 10]) |
             (static_cast<uint32_t>(data[off + 11]) << 8) |
             (static_cast<uint32_t>(data[off + 12]) << 16) |
             (static_cast<uint32_t>(data[off + 13]) << 24);
    e.isDir = (data[off + 25] & 0x02) != 0;
    uint8_t nameLen = data[off + 32];
    std::string raw(reinterpret_cast<const char *>(data + off + 33), nameLen);
    e.name = stripVersion(raw);
    return e;
}

bool Ps2DiscFs::readRoot()
{
    uint8_t pvd[2048];
    if (!readSector(16, pvd))
    {
        return false;
    }
    if (pvd[0] != 1 || std::memcmp(pvd + 1, "CD001", 5) != 0)
    {
        return false;
    }
    m_root = parseEntry(pvd, 156);
    return true;
}

std::vector<uint8_t> Ps2DiscFs::ReadSectors(uint32_t lba, uint32_t size) const
{
    std::vector<uint8_t> result(size);
    uint32_t done = 0;
    uint32_t cur = lba;
    uint8_t sector[2048];
    while (done < size)
    {
        if (!readSector(cur++, sector))
        {
            result.resize(done);
            break;
        }
        uint32_t n = std::min<uint32_t>(2048, size - done);
        std::memcpy(result.data() + done, sector, n);
        done += n;
    }
    return result;
}

std::vector<Ps2DiscFs::Entry> Ps2DiscFs::listEntries(const Entry &dir) const
{
    std::vector<Entry> out;
    std::vector<uint8_t> data = ReadSectors(dir.lba, dir.size);
    size_t i = 0;
    while (i < data.size())
    {
        uint8_t len = data[i];
        if (len == 0)
        {
            i = ((i / 2048) + 1) * 2048;
            continue;
        }
        Entry e = parseEntry(data.data(), i);
        if (!(e.name.size() == 1 && (e.name[0] == '\x00' || e.name[0] == '\x01')))
        {
            out.push_back(e);
        }
        i += len;
    }
    return out;
}

bool Ps2DiscFs::findInDir(const Entry &dir, const std::string &name, bool wantDir, Entry &out) const
{
    std::string upper = toUpper(stripVersion(name));
    for (const Entry &e : listEntries(dir))
    {
        if (e.isDir == wantDir && toUpper(e.name) == upper)
        {
            out = e;
            return true;
        }
    }
    return false;
}

bool Ps2DiscFs::resolve(const std::string &path, Entry &out) const
{
    std::vector<std::string> parts = splitPath(path);
    if (parts.empty())
    {
        out = m_root;
        return true;
    }
    Entry dir = m_root;
    for (size_t i = 0; i + 1 < parts.size(); ++i)
    {
        if (!findInDir(dir, parts[i], true, dir))
        {
            return false;
        }
    }
    return findInDir(dir, parts.back(), false, out);
}

std::string Ps2DiscFs::stripVersion(const std::string &name)
{
    auto semi = name.find(';');
    return semi == std::string::npos ? name : name.substr(0, semi);
}

std::string Ps2DiscFs::toUpper(const std::string &s)
{
    std::string r = s;
    std::transform(r.begin(), r.end(), r.begin(), [](unsigned char c)
                   { return static_cast<char>(std::toupper(c)); });
    return r;
}

std::vector<std::string> Ps2DiscFs::splitPath(const std::string &path)
{
    std::vector<std::string> parts;
    std::string cur;
    for (char c : path)
    {
        if (c == '/' || c == '\\')
        {
            if (!cur.empty())
            {
                parts.push_back(cur);
                cur.clear();
            }
        }
        else
        {
            cur.push_back(c);
        }
    }
    if (!cur.empty())
    {
        parts.push_back(cur);
    }
    return parts;
}
