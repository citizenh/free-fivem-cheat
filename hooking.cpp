#include "hooking.h"

std::unique_ptr<c_hooking> g_hooking;

c_hooking::c_hooking() : m_initialized(false) {}

c_hooking::~c_hooking()
{
    shutdown();
}

bool c_hooking::initialize()
{
    if (m_initialized)
        return true;

    if (MH_Initialize() != MH_OK)
        return false;

    m_initialized = true;
    return true;
}

void c_hooking::shutdown()
{
    if (!m_initialized)
        return;

    disable_all();

    for (auto& hook : m_hooks)
        MH_RemoveHook(hook.second.target);

    m_hooks.clear();
    MH_Uninitialize();
    m_initialized = false;
}

bool c_hooking::create_hook(const char* name, void* target, void* detour)
{
    if (!m_initialized || !target || !detour)
        return false;

    if (m_hooks.find(name) != m_hooks.end())
        return false;


    auto* bytes = static_cast<uint8_t*>(target);

    if (bytes[0] == 0xE9 || bytes[0] == 0xEB || (bytes[0] == 0xFF && bytes[1] == 0x25))
        return false;

    void* original = nullptr;
    if (MH_CreateHook(target, detour, &original) != MH_OK)
        return false;

    if (MH_EnableHook(target) != MH_OK)
    {
        MH_RemoveHook(target);
        return false;
    }

    m_hooks[name] = { target, detour, original, name };
    return true;
}

bool c_hooking::enable_hook(const char* name)
{
    auto it = m_hooks.find(name);
    if (it == m_hooks.end())
        return false;

    return MH_EnableHook(it->second.target) == MH_OK;
}

bool c_hooking::disable_hook(const char* name)
{
    auto it = m_hooks.find(name);
    if (it == m_hooks.end())
        return false;

    return MH_DisableHook(it->second.target) == MH_OK;
}

bool c_hooking::enable_all()
{
    return MH_EnableHook(MH_ALL_HOOKS) == MH_OK;
}

bool c_hooking::disable_all()
{
    return MH_DisableHook(MH_ALL_HOOKS) == MH_OK;
}

bool c_hooking::hook_exists(const char* name) const
{
    return m_hooks.find(name) != m_hooks.end();
}

size_t c_hooking::hook_count() const
{
    return m_hooks.size();
}