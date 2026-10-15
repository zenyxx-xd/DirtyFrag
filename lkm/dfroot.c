#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/ptrace.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("DFRoot LKM");

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
typedef unsigned long (*module_kallsyms_lookup_name_t)(const char *name);
typedef void *(*umh_setup_t)(const char *path, char **argv, char **envp, gfp_t gfp,
                             void *init, void *cleanup, void *data);
typedef int (*umh_exec_t)(void *info, int wait);
typedef int  (*kern_path_t)(const char *, unsigned int, struct path *);
typedef int  (*invalidate_t)(struct address_space *);
typedef void (*path_put_t)(const struct path *);
typedef int  (*insn_patch_t)(void *addrs[], u32 insns[], int cnt);

static kern_path_t  kern_path_fn;
static invalidate_t invalidate_fn;
static path_put_t   path_put_fn;
static insn_patch_t insn_patch_text;

static void drop_path_cache(const char *path)
{
    struct path p;
    if (!kern_path_fn || !invalidate_fn || !path_put_fn) {
        pr_err("dfroot: drop_path_cache: symbols missing\n");
        return;
    }
    if (kern_path_fn(path, LOOKUP_FOLLOW, &p)) {
        pr_err("dfroot: drop_path_cache: kern_path failed for %s\n", path);
        return;
    }
    invalidate_fn(p.dentry->d_inode->i_mapping);
    path_put_fn(&p);
    pr_info("dfroot: cleared page cache for %s\n", path);
}

/* Обнуление возврата функции insn-патчем (PAC/BTI-aware). kprobe-хуки
 * несовместимы с soft reboot части форков KSU (v4.1, chisewaguri) —
 * патчим тело функции напрямую. */
static __nocfi void patch_fn_ret_zero(void *fn)
{
    u32  insn  = *(u32 *)fn;
    int  skip  = 0;
    bool pac_a = false, pac_b = false;
    void *addrs[2];
    u32   insns[2];

    while (skip < 2) {
        switch (insn) {
        case 0xD503233F: pac_a = true; goto skip_insn; /* PACIASP */
        case 0xD503237F: pac_b = true; goto skip_insn; /* PACIBSP */
        case 0xD503241F:                               /* BTI     */
        case 0xD503245F:                               /* BTI c   */
        case 0xD503249F:                               /* BTI j   */
        case 0xD50324DF:                               /* BTI jc  */
        skip_insn:
            insn = *(u32 *)((u8 *)fn + ++skip * 4);
            continue;
        }
        break;
    }

    addrs[0] = (u8 *)fn + skip * 4;
    addrs[1] = (u8 *)fn + skip * 4 + 4;
    insns[0] = 0xD2800000;
    insns[1] = pac_b ? 0xD65F0FFF :
               pac_a ? 0xD65F0BFF :
                       0xD65F03C0;

    if (insn_patch_text(addrs, insns, 2))
        pr_warn("dfroot: patch failed at %px\n", fn);
}

static int __nocfi __init dfroot_init(void)
{
    kallsyms_lookup_name_t get_addr;
    module_kallsyms_lookup_name_t mkln;
    umh_setup_t umh_setup;
    umh_exec_t  umh_exec;
    bool *selinux_state;
    struct kprobe kln_kp;
    void *oplus_exe_fn, *oplus_root_fn, *defex_enforce_fn, *defex_umh_fn;
    void *info;
    int ret;

    static const char sh[]        = "/system/bin/sh";
    static const char bootstrap[] = "/data/user_de/0/com.rootmyvivo/bootstrap";
    static char cmd[128];
    static char *envp[] = { "PATH=/system/bin", NULL };
    static char *argv[] = { (char *)sh, "-c", cmd, NULL };
    snprintf(cmd, sizeof(cmd), "touch /dev/dfm0; exec %s", bootstrap);

    kln_kp = (struct kprobe){ .symbol_name = "kallsyms_lookup_name" };
    if (register_kprobe(&kln_kp) < 0) {
        pr_err("dfroot: kallsyms_lookup_name not found\n");
        return -EINVAL;
    }
    get_addr = (kallsyms_lookup_name_t)kln_kp.addr;
    unregister_kprobe(&kln_kp);

    insn_patch_text = (insn_patch_t)get_addr("aarch64_insn_patch_text");
    if (!insn_patch_text) {
        pr_err("dfroot: aarch64_insn_patch_text not found\n");
        return -EINVAL;
    }

    mkln = (module_kallsyms_lookup_name_t)get_addr("module_kallsyms_lookup_name");

    kern_path_fn  = (kern_path_t) get_addr("kern_path");
    invalidate_fn = (invalidate_t)get_addr("invalidate_inode_pages2");
    path_put_fn   = (path_put_t)  get_addr("path_put");
    drop_path_cache("/apex/com.android.runtime/bin/crash_dump64");

    selinux_state = (bool *)get_addr("selinux_state");
    if (!selinux_state) {
        pr_err("dfroot: selinux_state not found\n");
        return -EINVAL;
    }
    WRITE_ONCE(*selinux_state, false);
    pr_info("dfroot: selinux_state permissive\n");

    // Oppo/OnePlus (v4.1: патч вместо rmmod — работает при locked bl)
    oplus_exe_fn = (void *)(mkln ? mkln("oplus_exe_block_ret_handler") : 0);
    if (!oplus_exe_fn)
        pr_err("dfroot: oplus_exe_block_ret_handler not found, skipping\n");
    else {
        patch_fn_ret_zero(oplus_exe_fn);
        pr_info("dfroot: oplus_exe_block_ret_handler patched\n");
    }

    oplus_root_fn = (void *)(mkln ? mkln("oplus_root_check_post_handler") : 0);
    if (!oplus_root_fn)
        pr_err("dfroot: oplus_root_check_post_handler not found, skipping\n");
    else {
        patch_fn_ret_zero(oplus_root_fn);
        pr_info("dfroot: oplus_root_check_post_handler patched\n");
    }

    // Samsung defex
    defex_enforce_fn = (void *)get_addr("task_defex_enforce");
    if (!defex_enforce_fn)
        pr_err("dfroot: task_defex_enforce not found, skipping\n");
    else {
        patch_fn_ret_zero(defex_enforce_fn);
        pr_info("dfroot: task_defex_enforce patched\n");
    }

    defex_umh_fn = (void *)get_addr("task_defex_user_exec");
    if (!defex_umh_fn)
        pr_err("dfroot: task_defex_user_exec not found, skipping\n");
    else {
        patch_fn_ret_zero(defex_umh_fn);
        pr_info("dfroot: task_defex_user_exec patched\n");
    }

    umh_setup = (umh_setup_t)get_addr("call_usermodehelper_setup");
    umh_exec  = (umh_exec_t)get_addr("call_usermodehelper_exec");
    if (!umh_setup || !umh_exec) {
        pr_err("dfroot: usermodehelper symbols missing (setup=%px exec=%px)\n",
               umh_setup, umh_exec);
        return -EINVAL;
    }

    info = umh_setup(sh, argv, envp, GFP_KERNEL, NULL, NULL, NULL);
    if (!info) {
        pr_err("dfroot: usermodehelper_setup: returned NULL\n");
        return -EINVAL;
    }
    /* bypass CONFIG_STATIC_USERMODEHELPER_PATH="" overriding path to "" */
    ((struct subprocess_info *)info)->path = sh;

    ret = umh_exec(info, UMH_WAIT_EXEC);
    pr_info("dfroot: usermodehelper_exec(%s) returned %d\n", bootstrap, ret);

    return -ENODEV; /* return any error to unload module */
}

/* no module_exit: we never unload; saves .exit sections */
module_init(dfroot_init);
