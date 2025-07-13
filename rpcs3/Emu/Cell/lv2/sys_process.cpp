#include "stdafx.h"
#include "sys_process.h"
#include "Emu/Memory/vm_ptr.h"
#include "Emu/System.h"
#include "Emu/VFS.h"
#include "Emu/IdManager.h"
#include "Crypto/unedat.h"
#include "Emu/Cell/ErrorCodes.h"
#include "Emu/Cell/PPUThread.h"
#include "sys_lwmutex.h"
#include "sys_lwcond.h"
#include "sys_mutex.h"
#include "sys_cond.h"
#include "sys_event.h"
#include "sys_event_flag.h"
#include "sys_interrupt.h"
#include "sys_memory.h"
#include "sys_mmapper.h"
#include "sys_prx.h"
#include "sys_overlay.h"
#include "sys_rwlock.h"
#include "sys_semaphore.h"
#include "sys_timer.h"
#include "sys_fs.h"
#include "sys_vm.h"
#include "sys_spu.h"

LOG_CHANNEL(sys_process);

ps3_process_info_t g_ps3_process_info;

// Permission checks
bool ps3_process_info_t::debug_or_root() const
{
    return (ctrl_flags1 & (0xe << 28)) != 0;
}
bool ps3_process_info_t::has_root_perm() const
{
    return (ctrl_flags1 & (0xc << 28)) != 0;
}
bool ps3_process_info_t::has_debug_perm() const
{
    return (ctrl_flags1 & (0xa << 28)) != 0;
}
std::string_view ps3_process_info_t::get_cellos_appname() const
{
    if (!has_root_perm() || !Emu.GetTitleID().empty())
        return {};
    return std::string_view(Emu.GetBoot()).substr(Emu.GetBoot().find_last_of('/') + 1);
}

// Basic syscalls
s32 process_getpid() { return 1; }
s32 sys_process_getpid()
{
    sys_process.trace("sys_process_getpid() -> 1");
    return process_getpid();
}
s32 sys_process_getppid()
{
    sys_process.todo("sys_process_getppid() -> 0");
    return 0;
}

// Object counting helpers
template <typename T, typename Get>
u32 idm_get_count()
{
    return idm::select<T, Get>([&](u32, Get&) {});
}
error_code sys_process_get_number_of_object(u32 object, vm::ptr<u32> nump)
{
    sys_process.error("sys_process_get_number_of_object(object=0x%x, nump=*0x%x)", object, nump);
    switch(object)
    {
    case SYS_MEM_OBJECT: *nump = idm_get_count<lv2_obj, lv2_memory>(); break;
    case SYS_MUTEX_OBJECT: *nump = idm_get_count<lv2_obj, lv2_mutex>(); break;
    case SYS_COND_OBJECT: *nump = idm_get_count<lv2_obj, lv2_cond>(); break;
    case SYS_RWLOCK_OBJECT: *nump = idm_get_count<lv2_obj, lv2_rwlock>(); break;
    case SYS_INTR_TAG_OBJECT: *nump = idm_get_count<lv2_obj, lv2_int_tag>(); break;
    case SYS_INTR_SERVICE_HANDLE_OBJECT: *nump = idm_get_count<lv2_obj, lv2_int_serv>(); break;
    case SYS_EVENT_QUEUE_OBJECT: *nump = idm_get_count<lv2_obj, lv2_event_queue>(); break;
    case SYS_EVENT_PORT_OBJECT: *nump = idm_get_count<lv2_obj, lv2_event_port>(); break;
    case SYS_TRACE_OBJECT: sys_process.error("sys_process_get_number_of_object: object = SYS_TRACE_OBJECT"); *nump = 0; break;
    case SYS_SPUIMAGE_OBJECT: *nump = idm_get_count<lv2_obj, lv2_spu_image>(); break;
    case SYS_PRX_OBJECT: *nump = idm_get_count<lv2_obj, lv2_prx>(); break;
    case SYS_SPUPORT_OBJECT: sys_process.error("sys_process_get_number_of_object: object = SYS_SPUPORT_OBJECT"); *nump = 0; break;
    case SYS_OVERLAY_OBJECT: *nump = idm_get_count<lv2_obj, lv2_overlay>(); break;
    case SYS_LWMUTEX_OBJECT: *nump = idm_get_count<lv2_obj, lv2_lwmutex>(); break;
    case SYS_TIMER_OBJECT: *nump = idm_get_count<lv2_obj, lv2_timer>(); break;
    case SYS_SEMAPHORE_OBJECT: *nump = idm_get_count<lv2_obj, lv2_sema>(); break;
    case SYS_FS_FD_OBJECT: *nump = idm_get_count<lv2_fs_object, lv2_fs_object>(); break;
    case SYS_LWCOND_OBJECT: *nump = idm_get_count<lv2_obj, lv2_lwcond>(); break;
    case SYS_EVENT_FLAG_OBJECT: *nump = idm_get_count<lv2_obj, lv2_event_flag>(); break;
    default: return CELL_EINVAL;
    }
    return CELL_OK;
}

// ID retrieval helpers
#include <set>
template <typename T, typename Get>
void idm_get_set(std::set<u32>& out)
{
    idm::select<T, Get>([&](u32 id, Get&) { out.emplace(id); });
}
static error_code process_get_id(u32 object, vm::ptr<u32> buffer, u32 size, vm::ptr<u32> set_size)
{
    std::set<u32> objects;
    switch (object)
    {
    case SYS_MEM_OBJECT: idm_get_set<lv2_obj, lv2_memory>(objects); break;
    case SYS_MUTEX_OBJECT: idm_get_set<lv2_obj, lv2_mutex>(objects); break;
    case SYS_COND_OBJECT: idm_get_set<lv2_obj, lv2_cond>(objects); break;
    case SYS_RWLOCK_OBJECT: idm_get_set<lv2_obj, lv2_rwlock>(objects); break;
    case SYS_INTR_TAG_OBJECT: idm_get_set<lv2_obj, lv2_int_tag>(objects); break;
    case SYS_INTR_SERVICE_HANDLE_OBJECT: idm_get_set<lv2_obj, lv2_int_serv>(objects); break;
    case SYS_EVENT_QUEUE_OBJECT: idm_get_set<lv2_obj, lv2_event_queue>(objects); break;
    case SYS_EVENT_PORT_OBJECT: idm_get_set<lv2_obj, lv2_event_port>(objects); break;
    case SYS_TRACE_OBJECT: fmt::throw_exception("SYS_TRACE_OBJECT");
    case SYS_SPUIMAGE_OBJECT: idm_get_set<lv2_obj, lv2_spu_image>(objects); break;
    case SYS_PRX_OBJECT: idm_get_set<lv2_obj, lv2_prx>(objects); break;
    case SYS_OVERLAY_OBJECT: idm_get_set<lv2_obj, lv2_overlay>(objects); break;
    case SYS_LWMUTEX_OBJECT: idm_get_set<lv2_obj, lv2_lwmutex>(objects); break;
    case SYS_TIMER_OBJECT: idm_get_set<lv2_obj, lv2_timer>(objects); break;
    case SYS_SEMAPHORE_OBJECT: idm_get_set<lv2_obj, lv2_sema>(objects); break;
    case SYS_FS_FD_OBJECT: idm_get_set<lv2_fs_object, lv2_fs_object>(objects); break;
    case SYS_LWCOND_OBJECT: idm_get_set<lv2_obj, lv2_lwcond>(objects); break;
    case SYS_EVENT_FLAG_OBJECT: idm_get_set<lv2_obj, lv2_event_flag>(objects); break;
    case SYS_SPUPORT_OBJECT: fmt::throw_exception("SYS_SPUPORT_OBJECT");
    default: return CELL_EINVAL;
    }
    u32 i = 0;
    for (auto id = objects.begin(); i < std::max<s32>(size, 1) + 0u && id != objects.end(); id++, i++)
        buffer[i] = *id;
    *set_size = i;
    return CELL_OK;
}
error_code sys_process_get_id(u32 object, vm::ptr<u32> buffer, u32 size, vm::ptr<u32> set_size)
{
    sys_process.error("sys_process_get_id(object=0x%x, buffer=*0x%x, size=%d, set_size=*0x%x)", object, buffer, size, set_size);
    if (object == SYS_SPUPORT_OBJECT) return CELL_EINVAL;
    return process_get_id(object, buffer, size, set_size);
}
error_code sys_process_get_id2(u32 object, vm::ptr<u32> buffer, u32 size, vm::ptr<u32> set_size)
{
    sys_process.error("sys_process_get_id2(object=0x%x, buffer=*0x%x, size=%d, set_size=*0x%x)", object, buffer, size, set_size);
    if (!g_ps3_process_info.has_root_perm()) return CELL_ENOSYS;
    return process_get_id(object, buffer, size, set_size);
}

// SPU lock line reservation address logic
CellError process_is_spu_lock_line_reservation_address(u32 addr, u64 flags)
{
    if (!flags || flags & ~(SYS_MEMORY_ACCESS_RIGHT_SPU_THR | SYS_MEMORY_ACCESS_RIGHT_RAW_SPU))
        return CELL_EINVAL;
    switch (addr >> 28)
    {
    case 0x0: case 0x1: case 0x2: case 0xc: case 0xe: break;
    case 0xf:
        if (flags & SYS_MEMORY_ACCESS_RIGHT_RAW_SPU) return CELL_EPERM;
        break;
    case 0xd: return CELL_EPERM;
    default:
        if (auto vm0 = idm::get_unlocked<sys_vm_t>(sys_vm_t::find_id(addr)))
        {
            if (vm0->addr + vm0->size - 1 < addr) return CELL_EINVAL;
            return CELL_EPERM;
        }
        if (!vm::get(vm::any, addr & -0x1000'0000)) return CELL_EINVAL;
        break;
    }
    return {};
}
error_code sys_process_is_spu_lock_line_reservation_address(u32 addr, u64 flags)
{
    sys_process.warning("sys_process_is_spu_lock_line_reservation_address(addr=0x%x, flags=0x%llx)", addr, flags);
    if (auto err = process_is_spu_lock_line_reservation_address(addr, flags)) return err;
    return CELL_OK;
}

// Paramsfo retrieval
error_code _sys_process_get_paramsfo(vm::ptr<char> buffer)
{
    sys_process.warning("_sys_process_get_paramsfo(buffer=0x%x)", buffer);
    if (Emu.GetTitleID().empty()) return CELL_ENOENT;
    memset(buffer.get_ptr(), 0, 0x40);
    memcpy(buffer.get_ptr() + 1, Emu.GetTitleID().c_str(), std::min<usz>(Emu.GetTitleID().length(), 9));
    return CELL_OK;
}

// SDK version
s32 process_get_sdk_version(u32 /*pid*/, s32& ver)
{
    ver = g_ps3_process_info.sdk_ver;
    return CELL_OK;
}
error_code sys_process_get_sdk_version(u32 pid, vm::ptr<s32> version)
{
    sys_process.warning("sys_process_get_sdk_version(pid=0x%x, version=*0x%x)", pid, version);
    s32 sdk_ver;
    const s32 ret = process_get_sdk_version(pid, sdk_ver);
    if (ret != CELL_OK) return CellError{ret + 0u};
    *version = sdk_ver;
    return CELL_OK;
}

// Process kill/wait/detach stubs
error_code sys_process_kill(u32 pid)
{
    sys_process.todo("sys_process_kill(pid=0x%x)", pid);
    return CELL_OK;
}
error_code sys_process_wait_for_child(u32 pid, vm::ptr<u32> status, u64 unk)
{
    sys_process.todo("sys_process_wait_for_child(pid=0x%x, status=*0x%x, unk=0x%llx", pid, status, unk);
    return CELL_OK;
}
error_code sys_process_wait_for_child2(u64 unk1, u64 unk2, u64 unk3, u64 unk4, u64 unk5, u64 unk6)
{
    sys_process.todo("sys_process_wait_for_child2(unk1=0x%llx, unk2=0x%llx, unk3=0x%llx, unk4=0x%llx, unk5=0x%llx, unk6=0x%llx)",
        unk1, unk2, unk3, unk4, unk5, unk6);
    return CELL_OK;
}
error_code sys_process_get_status(u64 unk)
{
    sys_process.todo("sys_process_get_status(unk=0x%llx)", unk);
    return CELL_OK;
}
error_code sys_process_detach_child(u64 unk)
{
    sys_process.todo("sys_process_detach_child(unk=0x%llx)", unk);
    return CELL_OK;
}

// Exit and spawn logic, XMB boot support
extern void signal_system_cache_can_stay();

void _sys_process_exit(ppu_thread& ppu, s32 status, u32 arg2, u32 arg3)
{
    ppu.state += cpu_flag::wait;
    sys_process.warning("_sys_process_exit(status=%d, arg2=0x%x, arg3=0x%x)", status, arg2, arg3);
    Emu.CallFromMainThread([]()
    {
        sys_process.success("Process finished");
        signal_system_cache_can_stay();
        Emu.Kill();
    });
    while (auto state = +ppu.state)
    {
        if (is_stopped(state)) break;
        ppu.state.wait(state);
    }
}

void _sys_process_exit2(ppu_thread& ppu, s32 status, vm::ptr<sys_exit2_param> arg, u32 arg_size, u32 arg4)
{
    ppu.state += cpu_flag::wait;
    sys_process.warning("_sys_process_exit2(status=%d, arg=*0x%x, arg_size=0x%x, arg4=0x%x)", status, arg, arg_size, arg4);

    auto pstr = +arg->args;
    std::vector<std::string> argv, envp;
    while (auto ptr = *pstr++) { argv.emplace_back(ptr.get_ptr()); sys_process.notice(" *** arg: %s", ptr); }
    while (auto ptr = *pstr++) { envp.emplace_back(ptr.get_ptr()); sys_process.notice(" *** env: %s", ptr); }
    std::vector<u8> data;
    if (arg_size > 0x1030)
    {
        data.resize(0x1000);
        std::memcpy(data.data(), vm::base(arg.addr() + arg_size - 0x1000), 0x1000);
    }
    if (argv.empty())
        return _sys_process_exit(ppu, status, 0, 0);
    lv2_exitspawn(ppu, argv, envp, data);
}

void lv2_exitspawn(ppu_thread& ppu, std::vector<std::string>& argv, std::vector<std::string>& envp, std::vector<u8>& data)
{
    ppu.state += cpu_flag::wait;
    const bool is_real_reboot = (ppu.gpr[11] == 379);
    const bool is_another_game = (ppu.gpr[11] == 27);

    Emu.CallFromMainThread([is_real_reboot, is_another_game, argv = std::move(argv), envp = std::move(envp), data = std::move(data)]() mutable
    {
        sys_process.success("Process finished -> %s", argv[0]);
        std::string disc;
        if (Emu.GetCat() == "DG" || Emu.GetCat() == "GD")
            disc = vfs::get("/dev_bdvd/");
        if (disc.empty() && !Emu.GetTitleID().empty())
            disc = vfs::get(Emu.GetDir());
        std::string path = vfs::get(argv[0]);
        std::string hdd1 = vfs::get("/dev_hdd1/");
        const u128 klic = g_fxo->get<loaded_npdrm_keys>().last_key();

        using namespace id_manager;
        // Use serialization for memory container state
        shared_ptr<utils::serial> idm_capture = make_shared<utils::serial>();
        if (!is_real_reboot)
        {
            reader_lock rlock{g_mutex};
            g_fxo->get<id_map<lv2_memory_container>>().save(*idm_capture);
            stx::serial_breathe_and_tag(*idm_capture, "id_map<lv2_memory_container>", false);
        }
        idm_capture->set_reading_state();

        auto func = [is_real_reboot, old_size = g_fxo->get<lv2_memory_container>().size, idm_capture](u32 sdk_suggested_mem) mutable
        {
            if (is_real_reboot)
            {
                ensure(g_fxo->init<id_map<lv2_memory_container>>());
            }
            else
            {
                ensure(g_fxo->init<id_map<lv2_memory_container>>(*idm_capture));
            }
            u32 total_size = 0;
            idm::select<lv2_memory_container>([&](u32, lv2_memory_container& ctr)
            {
                ctr.used = 0;
                total_size += ctr.size;
            });
            ensure(g_fxo->init<lv2_memory_container>(std::min(old_size - total_size, sdk_suggested_mem) + total_size));
        };

        Emu.after_kill_callback = [is_another_game, func = std::move(func), argv = std::move(argv), envp = std::move(envp), data = std::move(data),
            disc = std::move(disc), path = std::move(path), hdd1 = std::move(hdd1), old_config = Emu.GetUsedConfig(), klic]() mutable
        {
            if (!is_another_game)
            {
                Emu.argv = std::move(argv);
                Emu.envp = std::move(envp);
                Emu.data = std::move(data);
                Emu.disc = std::move(disc);
                Emu.hdd1 = std::move(hdd1);
                Emu.init_mem_containers = std::move(func);
                if (klic)
                    Emu.klic.emplace_back(klic);
            }
            Emu.SetForceBoot(true);
            auto res = Emu.BootGame(path, "", true, is_another_game ? cfg_mode::custom : cfg_mode::continuous, is_another_game ? "" : old_config);
            if (res != game_boot_result::no_errors)
                sys_process.fatal("Failed to boot from exitspawn! (path=\"%s\", error=%s)", path, res);
        };

        signal_system_cache_can_stay();
        Emu.SetContinuousMode(true);
        Emu.Kill(false);
    });

    while (auto state = +ppu.state)
    {
        if (is_stopped(state)) break;
        ppu.state.wait(state);
    }
}

void sys_process_exit3(ppu_thread& ppu, s32 status)
{
    ppu.state += cpu_flag::wait;
    sys_process.warning("_sys_process_exit3(status=%d)", status);
    return _sys_process_exit(ppu, status, 0, 0);
}

// XMB boot support: spawns a new SELF/game from XMB
error_code sys_process_spawns_a_self2(ppu_thread& ppu, vm::ptr<u32> pid, u32 primary_prio, u64 flags, vm::ptr<spawn_self_stack> stack, u32 stack_size, u32 mem_id, vm::ptr<void> param_sfo, vm::ptr<void> dbg_data)
{
    ppu.state += cpu_flag::wait;
    sys_process.warning("sys_process_spawns_a_self2(pid=*0x%x, primary_prio=0x%x, flags=0x%llx, stack=*0x%x, stack_size=0x%x, mem_id=0x%x, param_sfo=*0x%x, dbg_data=*0x%x",
        pid, primary_prio, flags, stack, stack_size, mem_id, param_sfo, dbg_data);
    if (!g_ps3_process_info.debug_or_root())
        return CELL_ENOSYS;
    if (!pid || !stack || !param_sfo || !dbg_data)
        return CELL_EFAULT;
    if (stack_size < sizeof(spawn_self_stack))
        return CELL_EINVAL;

    std::string_view self_path{stack->self_path, sizeof(stack->self_path)};
    if (const auto trim_start = self_path.find_first_not_of('\0'); trim_start != umax)
        self_path.remove_prefix(trim_start);
    if (const auto trim_end = self_path.find_first_of('\0'); trim_end != umax)
        self_path.remove_suffix(self_path.size() - trim_end);
    sys_process.notice("SELF path: %s", self_path);

    if (self_path.ends_with("/USRDIR/EBOOT.BIN"sv))
    {
        std::vector<std::string> argv;
        std::vector<std::string> envp;
        std::vector<u8> data;
        argv.emplace_back(self_path);
        lv2_exitspawn(ppu, argv, envp, data);
    }
    return CELL_OK;
}
