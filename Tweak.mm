#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <substrate.h>
#import <vector>
#import <mach/mach_vm.h>
#import <sys/stat.h>
#import <unistd.h>

static uint64_t slide;
static void *dyld_get_image_name_ptr;
static void *dyld_get_image_vmaddr_slide_ptr;
static void *dyld_get_image_header_ptr;
static void *dyld_register_func_for_add_image_ptr;
static void *stat_ptr;
static void *access_ptr;
static void *symlink_ptr;
static void *task_info_ptr;
static void *hooked_func_ptr;
static void *NSGetEnviron_ptr;
static const uint8_t mov_x0_NEGATIVE1[] = { 0x00, 0x00, 0x80, 0x92 };
static const uint8_t mov_x0_2[] = { 0x40, 0x00, 0x80, 0xD2 };
static const uint8_t mov_x0_0[] = { 0x00, 0x00, 0x80, 0xD2 };
static const uint8_t ret[] = { 0xC0, 0x03, 0x5F, 0xD6 };
static const uint8_t jmp_hook_102B04BB8[] = { 0x77, 0xE1, 0x04, 0x94 };
static const uint8_t jmp_hook_102BF9490[] = { 0x41, 0x0F, 0x01, 0x94 };
static const uint8_t jmp_hook_102BFA98C[] = { 0x02, 0x0A, 0x01, 0x94 };
static const uint8_t nop[] = { 0x1F, 0x20, 0x03, 0xD5 };
extern "C" { char *path1 = "/3cf2dc680d10f17a5499e9ebffb08a3e"; }

static uint64_t access_array[] = 
{
    0x1002334C0,
};

static uint64_t ptrace_array[] = 
{
    0x100233F10,
    0x100233F14,
    0x102C23A00,
    0x102C23A04,
};

static uint64_t stat_array[] = 
{
    0x102B04BB8,
    0x102BF9490,
    0x102BFA98C,
};

static uint64_t sysctl_array[] = 
{
    0x102AC4120,
    0x102AC4124,
    0x102BFBB7C,
    0x102BFBB80,
    0x102BFBC80,
    0x102BFBC84,
};

static uint64_t symlink_array[] =
{
    0x102BFCE88,
};

#define CHECKLIST() \
        CHECK1("/Applications/Cydia.app") \
        CHECK("/Applications/Flex.app") \
        CHECK("/Applications/Flex.app") \
        CHECK("/Applications/GameGemiOS.app") \
        CHECK("/Applications/Sileo.app") \
        CHECK("/Applications/Zebra.app") \
        CHECK("/Applications/iGameGuardian.app") \
        CHECK("/Applications/Sileo.app") \
        CHECK("/Applications/Zebra.app") \
        CHECK("/Applications/iGameGuardian.app") \
        CHECK("/Library/BreakThrough") \
        CHECK("/Library/Frameworks/CydiaSubstrate.framework") \
        CHECK("/Library/LaunchDaemons/com.apple.gg.daemon.plist") \
        CHECK("/Library/MobileSubstrate") \
        CHECK("/Library/PreferenceLoader/Preferences/LibertyPref.plist") \
        CHECK("/Library/PreferenceLoader/Preferences/NoSubstitute.plist") \
        CHECK("/Library/dpkg/info/xyz.willy.zebra.list") \
        CHECK("/User") \
        CHECK("/boot") \
        CHECK("/jb") \
        CHECK("/lib") \
        CHECK("/mnt") \
        CHECK("/private/etc/ssh") \
        CHECK("/private/var/containers/Bundle/iosbinpack64") \
        CHECK("/private/var/containers/Bundle/tweaksupport") \
        CHECK("/private/var/db/stash") \
        CHECK("/private/var/lib") \
        CHECK("/private/var/libexec") \
        CHECK("/private/var/mobile/Library/Caches/Snapshots/org.coolstar.SileoStore") \
        CHECK("/private/var/mobile/Library/Caches/com.saurik.Cydia") \
        CHECK("/private/var/mobile/Library/Flex3") \
        CHECK("/private/var/mobile/Library/Preferences/org.coolstar.SileoStore.plist") \
        CHECK("/private/var/mobile/Library/Preferences/xyz.willy.Zebra.plist") \
        CHECK("/private/var/mobile/Library/iGameGuardian") \
        CHECK("/usr/lib/TweakInject") \
        CHECK("/usr/lib/libsubstrate.dylib") \
        CHECK("/var/containers/Bundle/iosbinpack64") \
        CHECK("/var/containers/Bundle/tweaksupport") \
        CHECK("/var/libexec") \
        CHECK("/var/mobile/Library/Caches/com.saurik.Cydia") \
        CHECK("/var/mobile/Library/Caches/com.saurik.Cydia")

uint32_t num_bak;
#define BYTESWAP32(num) \
    do { \
        num_bak = num; \
        num = ((num_bak >> 0x18) &0xff); \
        num = num | ((num_bak << 0x8) &0xff0000); \
        num = num | ((num_bak >> 0x8) &0xff00); \
        num = num | ((num_bak << 0x18) &0xff000000); \
    } while(0)

%group Dyld_get_image_name

%hookf(const char *, dyld_get_image_name_ptr, int index)
{
    const char *orig = %orig;
    if(strstr(orig, "TweakInject") != 0) orig = "/A";
    if(strstr(orig, "libhooker") != 0) orig = "/A";
    if(strstr(orig, "libblackjack") != 0) orig = "/A";
    if(strstr(orig, "libsubstrate") != 0) orig = "/A";
    if(strstr(orig, "substrate") != 0) orig = "/A";
    if(strstr(orig, "Substrate") != 0) orig = "/A";
    NSLog(@"Fate Bypass: Runtime: dyld_get_image_name: ret: %s index: %d", orig, index);
    return orig;
}

%end

%group Dyld_get_image_vmaddr_slide

%hookf(uint64_t, dyld_get_image_vmaddr_slide_ptr, int index)
{
    uint64_t orig = %orig;
    NSLog(@"Fate Bypass: Runtime: dyld_get_image_vmaddr_slide: ret: 0x%llX index: %d new: 0x0", orig, index);
    orig = 0x0;
    return orig;
}

%end

%group Dyld_get_image_header

%hookf(const struct mach_header *, dyld_get_image_header_ptr, int index)
{
    const struct mach_header* orig = %orig;
    Dl_info dylib_info;
    dladdr(orig, &dylib_info);
    NSLog(@"Fate Bypass: Runtime: dyld_get_image_header: index: %d dli_fname: %s", index, dylib_info.dli_fname);
    return orig;
}

%end

%group Hooked_func

%hookf(void, hooked_func_ptr, const struct mach_header *mh, intptr_t vmaddr_slide)
{
    Dl_info dylib_info;
    dladdr(mh, &dylib_info);
    NSLog(@"Fate Bypass: Runtime: dyld_register_func_for_add_image: dylib_info.dli_fname: %s vmaddr_slide: 0x%llX", dylib_info.dli_fname, vmaddr_slide);
}

%end

%group Dyld_register_func_for_add_image

%hookf(void, dyld_register_func_for_add_image_ptr, void (*func)(const struct mach_header *mh, intptr_t vmaddr_slide))
{
    NSLog(@"Fate Bypass: Runtime: dyld_register_func_for_add_image called!");
    hooked_func_ptr = &func;
    %init(Hooked_func);
}

%end

%group Stat

%hookf(int, stat_ptr, const char *path, struct stat *buf)
{
    NSLog(@"Fate Bypass: Runtime: stat: path: %s", path);
    #define CHECK1(check_path) \
        if(strcmp(path, check_path) == 0) \
        { \
            NSLog(@"Fate Bypass: Runtime: stat: path: %s", path); \
            return %orig(path1, buf); \
        }
    #define CHECK(check_path) \
        else if(strcmp(path, check_path) == 0) \
        { \
            NSLog(@"Fate Bypass: Runtime: stat: path: %s", path); \
            return %orig(path1, buf); \
        }

    CHECKLIST()
    #undef CHECK1
    #undef CHECK
    else
    {
        int orig = %orig;
        NSLog(@"Fate Bypass: Runtime: stat: ret: %d path: %s", orig, path);
        return orig;
    }
}

%end

%group Access

%hookf(int, access_ptr, const char *path, int a2)
{
    NSLog(@"Fate Bypass: Runtime: access: path: %s", path);
    #define CHECK1(check_path) \
        if(strcmp(path, check_path) == 0) \
        { \
            NSLog(@"Fate Bypass: Runtime: access: path: %s a2: %d", path, a2); \
            return %orig(path1, a2); \
        }
    #define CHECK(check_path) \
        else if(strcmp(path, check_path) == 0) \
        { \
            NSLog(@"Fate Bypass: Runtime: access: path: %s a2: %d", path, a2); \
            return %orig(path1, a2); \
        }

    CHECKLIST()
    #undef CHECK1
    #undef CHECK
    else
    {
        int orig = %orig;
        NSLog(@"Fate Bypass: Runtime: access: ret: %d path: %s a2: %d", orig, path, a2);
        return orig;
    }
}

%end

%group Symlink

%hookf(int, symlink_ptr, const char *path, const char *link)
{
    NSLog(@"Fate Bypass: Runtime: symlink: path: %s link: %s", path, link);
    #define CHECK1(check_path) \
        if(strcmp(path, check_path) == 0 || strcmp(link, check_path) == 0) \
        { \
            NSLog(@"Fate Bypass: Runtime: symlink: path: %s link: %s", path, link); \
            return %orig(path1, link); \
        }
    #define CHECK(check_path) \
        else if(strcmp(path, check_path) == 0 || strcmp(link, check_path) == 0) \
        { \
            NSLog(@"Fate Bypass: Runtime: symlink: path: %s link: %s", path, link); \
            return %orig(path1, link); \
        }

    CHECKLIST()
    #undef CHECK1
    #undef CHECK
    else
    {
        int orig = %orig;
        NSLog(@"Fate Bypass: Runtime: symlink: ret: %d path: %s link: %s", orig, path, link);
        return orig;
    }
}

%end

%group Task_info

%hookf(kern_return_t, task_info_ptr, task_name_t target_task, task_flavor_t flavor, task_info_t task_info_out, mach_msg_type_number_t *task_info_outCnt)
{
    kern_return_t orig = %orig;
    task_info_out = NULL;
    task_info_outCnt = NULL;
    NSLog(@"Fate Bypass: Runtime: task_info: ret: 0x%X target_task: 0x%X mach_task_self: 0x%X flavor: 0x%X task_info_out: 0x%llX task_info_outCnt: 0x%llx", orig, target_task, mach_task_self(), flavor, task_info_out, task_info_outCnt);
    return KERN_MEMORY_FAILURE;
}

%end

%group NSGetEnviron

%hookf(char ***, NSGetEnviron_ptr)
{
    char ***orig = %orig;
    char **env = *orig;
    NSLog(@"Fate Bypass: Runtime: NSGetEnviron!");
    while(*env)
 {
        NSLog(@"Fate Bypass: Runtime: NSGetEnviron: env: %s", *env);
		env++;
	}
    return orig;
}

%end

extern "C"
{
    int stat_hook(const char *path, struct stat *buf)
    {
        uint64_t ret = 0x0;
        NSLog(@"Fate Bypass: syscall: stat: path: %s", path);

        #define CHECK1(check_path) \
            if(strcmp(path, check_path) == 0) \
            { \
                __asm__ volatile("mov x0, %0" : : "r" (path1) : ); \
                __asm__ volatile("mov x1, %0" : : "r" (buf) : ); \
                __asm__ volatile("mov x16, #0xbc"); \
                __asm__ volatile("svc #0x80"); \
                ret = 0x0; \
                asm volatile("mov %0, x0" : "=r" (ret)); \
                NSLog(@"Fate Bypass: syscall: stat: ret: 0x%llX errno: %d", ret, errno); \
            }
        #define CHECK(check_path) \
            else if(strcmp(path, check_path) == 0) \
            { \
                __asm__ volatile("mov x0, %0" : : "r" (path1) : ); \
                __asm__ volatile("mov x1, %0" : : "r" (buf) : ); \
                __asm__ volatile("mov x16, #0xbc"); \
                __asm__ volatile("svc #0x80"); \
                ret = 0x0; \
                asm volatile("mov %0, x0" : "=r" (ret)); \
                NSLog(@"Fate Bypass: syscall: stat: ret: 0x%llX errno: %d", ret, errno); \
            }
            CHECKLIST()
        #undef CHECK1
        #undef CHECK
        else
        {
            __asm__ volatile("mov x0, %0" : : "r" (path) : );
            __asm__ volatile("mov x1, %0" : : "r" (buf) : );
            __asm__ volatile("mov x16, #0xbc");
            __asm__ volatile("svc #0x80");
            ret = 0x0;
            asm volatile("mov %0, x0" : "=r" (ret));
            NSLog(@"Fate Bypass: syscall: stat: ret: 0x%llX errno: %d", ret, errno);
        }
    }

    int access_hook(const char *path, int a2)
    {
        uint64_t ret = 0x0;
        NSLog(@"Fate Bypass: syscall: access: path: %s a2: %d", path, a2);

        #define CHECK1(check_path) \
            if(strcmp(path, check_path) == 0) \
            { \
                __asm__ volatile("mov x0, %0" : : "r" (path1) : ); \
                __asm__ volatile("mov x1, %0" : : "r" (a2) : ); \
                __asm__ volatile("mov x16, #0x21"); \
                __asm__ volatile("svc #0x80"); \
                ret = 0x0; \
                asm volatile("mov %0, x0" : "=r" (ret)); \
                NSLog(@"Fate Bypass: syscall: access: ret: 0x%llX errno: %d", ret, errno); \
            }
        #define CHECK(check_path) \
            else if(strcmp(path, check_path) == 0) \
            { \
                __asm__ volatile("mov x0, %0" : : "r" (path1) : ); \
                __asm__ volatile("mov x1, %0" : : "r" (a2) : ); \
                __asm__ volatile("mov x16, #0x21"); \
                __asm__ volatile("svc #0x80"); \
                ret = 0x0; \
                asm volatile("mov %0, x0" : "=r" (ret)); \
                NSLog(@"Fate Bypass: syscall: access: ret: 0x%llX errno: %d", ret, errno); \
            }

        CHECKLIST()
        #undef CHECK1
        #undef CHECK
        else
        {
            __asm__ volatile("mov x0, %0" : : "r" (path) : );
            __asm__ volatile("mov x1, %0" : : "r" (a2) : );
            __asm__ volatile("mov x16, #0x21");
            __asm__ volatile("svc #0x80");
            ret = 0x0;
            asm volatile("mov %0, x0" : "=r" (ret));
            NSLog(@"Fate Bypass: syscall: access: ret: 0x%llX errno: %d", ret, errno);
        }
    }

    int symlink_hook(const char *path, const char *link)
    {
        uint64_t ret = 0x0;
        NSLog(@"Fate Bypass: syscall: symlink: path: %s link: %s", path, link);

        #define CHECK1(check_path) \
            if(strcmp(path, check_path) == 0 || strcmp(link, check_path) == 0) \
            { \
                __asm__ volatile("mov x0, %0" : : "r" (path1) : ); \
                __asm__ volatile("mov x1, %0" : : "r" (link) : ); \
                __asm__ volatile("mov x16, #0x39"); \
                __asm__ volatile("svc #0x80"); \
                ret = 0x0; \
                asm volatile("mov %0, x0" : "=r" (ret)); \
                NSLog(@"Fate Bypass: syscall: symlink: ret: 0x%llX errno: %d", ret, errno); \
            }
        #define CHECK(check_path) \
            else if(strcmp(path, check_path) || strcmp(link, check_path) == 0) \
            { \
                __asm__ volatile("mov x0, %0" : : "r" (path1) : ); \
                __asm__ volatile("mov x1, %0" : : "r" (link) : ); \
                __asm__ volatile("mov x16, #0x39"); \
                __asm__ volatile("svc #0x80"); \
                ret = 0x0; \
                asm volatile("mov %0, x0" : "=r" (ret)); \
                NSLog(@"Fate Bypass: syscall: symlink: ret: 0x%llX errno: %d", ret, errno); \
            }

        CHECKLIST()
        #undef CHECK1
        #undef CHECK
        else
        {
            __asm__ volatile("mov x0, %0" : : "r" (path) : );
            __asm__ volatile("mov x1, %0" : : "r" (link) : );
            __asm__ volatile("mov x16, #0x39");
            __asm__ volatile("svc #0x80");
            ret = 0x0;
            asm volatile("mov %0, x0" : "=r" (ret));
            NSLog(@"Fate Bypass: syscall: symlink: ret: 0x%llX errno: %d", ret, errno);
        }
    }
}

__attribute__((naked)) int stat_trampoline(const char *path, struct stat *buf)
{
    __asm__ volatile("stp x29, x30, [sp, #-0x10]!");
    __asm__ volatile("mov x29, sp");
    __asm__ volatile("bl _stat_hook");
    __asm__ volatile("ldp x29, x30, [sp], #0x10");
    __asm__ volatile("ret");
}

__attribute__((naked)) int access_trampoline(const char *path, int a2)
{
    __asm__ volatile("stp x29, x30, [sp, #-0x10]!");
    __asm__ volatile("mov x29, sp");
    __asm__ volatile("bl _access_hook");
    __asm__ volatile("ldp x29, x30, [sp], #0x10");
    __asm__ volatile("ret");
}

__attribute__((naked)) int symlink_trampoline(const char *path, const char *link)
{
    __asm__ volatile("stp x29, x30, [sp, #-0x10]!");
    __asm__ volatile("mov x29, sp");
    __asm__ volatile("bl _symlink_hook");
    __asm__ volatile("ldp x29, x30, [sp], #0x10");
    __asm__ volatile("ret");
}

#define PATCH(array, patch) \
    do { \
        for(int i = 0; i < sizeof(array) / sizeof(uint64_t); i++) MSHookMemory((void *)(array[i] + slide), (void *)&patch, sizeof(patch)); \
    } while(false)

uint32_t BL_MASK = 0x94;
uint32_t offset;
uint32_t BL_trampoline;

#define BL_PATCH(array, trampoline) \
    do { \
        for(int i = 0; i < sizeof(array) / sizeof(uint64_t); i++) \
        { \
            offset = (uint32_t)((uint64_t)&trampoline - (array[i] + slide)); \
            offset = offset >> 0x2; \
            BYTESWAP32(offset); \
            offset = offset | BL_MASK; \
            BL_trampoline = offset; \
            BYTESWAP32(BL_trampoline); \
            MSHookMemory((void *)(array[i] + slide), (void *)&BL_trampoline, sizeof(BL_trampoline)); \
        } \
    } while(false)

static void init()
{
    NSLog(@"Fate Bypass: initializing...");
    slide = _dyld_get_image_vmaddr_slide(0);
    NSLog(@"Fate Bypass: slide: 0x%llX", slide);
    void *libsystem = dlopen("/usr/lib/libSystem.B.dylib", RTLD_NOW | RTLD_GLOBAL);
    NSLog(@"Fate Bypass: dlerror: %s", dlerror());
    if(libsystem)
    {
        NSLog(@"Fate Bypass: got libsystem!");
        dyld_get_image_name_ptr = dlsym(libsystem, "_dyld_get_image_name");
        NSLog(@"Fate Bypass: dlerror: %s", dlerror());
        if(dyld_get_image_name_ptr)
        {
            NSLog(@"Fate Bypass: got dyld_get_image_name!");
            %init(Dyld_get_image_name);
        }
        dyld_get_image_vmaddr_slide_ptr = dlsym(libsystem, "_dyld_get_image_vmaddr_slide");
        NSLog(@"Fate Bypass: dlerror: %s", dlerror());
        if(dyld_get_image_name_ptr)
        {
            NSLog(@"Fate Bypass: got dyld_get_image_vmaddr_slide!");
            %init(Dyld_get_image_vmaddr_slide);
        }
        dyld_get_image_header_ptr = dlsym(libsystem, "_dyld_get_image_header");
        NSLog(@"Fate Bypass: dlerror: %s", dlerror());
        if(dyld_get_image_header_ptr)
        {
            NSLog(@"Fate Bypass: got dyld_get_image_header!");
            %init(Dyld_get_image_header);
        }
        dyld_register_func_for_add_image_ptr = dlsym(libsystem, "_dyld_register_func_for_add_image");
        NSLog(@"Fate Bypass: dlerror: %s", dlerror());
        if(dyld_register_func_for_add_image_ptr)
        {
            NSLog(@"Fate Bypass: got dyld_register_func_for_add_image!");
            %init(Dyld_register_func_for_add_image);
        }
        stat_ptr = dlsym(libsystem, "stat");
        NSLog(@"Fate Bypass: dlerror: %s", dlerror());
        if(stat_ptr)
        {
            NSLog(@"Fate Bypass: got stat!");
            %init(Stat);
        }
        access_ptr = dlsym(libsystem, "access");
        NSLog(@"Fate Bypass: dlerror: %s", dlerror());
        if(access_ptr)
        {
            NSLog(@"Fate Bypass: got access!");
            %init(Access);
        }
        symlink_ptr = dlsym(libsystem, "symlink");
        NSLog(@"Fate Bypass: dlerror: %s", dlerror());
        if(symlink_ptr)
        {
            NSLog(@"Fate Bypass: got symlink!");
            %init(Symlink);
        }
        task_info_ptr = dlsym(libsystem, "task_info");
        NSLog(@"Fate Bypass: dlerror: %s", dlerror());
        if(task_info_ptr)
        {
            NSLog(@"Fate Bypass: got task_info!");
            %init(Task_info);
        }
        NSGetEnviron_ptr = dlsym(libsystem, "_NSGetEnviron");
        NSLog(@"Fate Bypass: dlerror: %s", dlerror());
        if(NSGetEnviron_ptr)
        {
            NSLog(@"Fate Bypass: got NSGetEnviron!");
            %init(NSGetEnviron);
        }
    }
    unsetenv("CRANE_CONTAINER_IDENTIFIER");
    unsetenv("SHELL");
	extern char **environ;
	for(int i = 0; environ[i]; i++)
	{
        NSLog(@"Fate Bypass: Init: environ: %s", environ[i]);
    }
    NSLog(@"Fate Bypass: initializing done!");
}

static void hook()
{
    NSLog(@"Fate Bypass: patching syscalls...");
    // PATCH(ptrace_array, mov_x0_NEGATIVE1);
    // PATCH(stat1_array, nop);
    BL_PATCH(stat_array, stat_trampoline);
    BL_PATCH(access_array, access_trampoline);
    BL_PATCH(symlink_array, symlink_trampoline);
    // PATCH(sysctl_array, mov_x0_NEGATIVE1);
    // PATCH(access_array, mov_x0_NEGATIVE1);
    // PATCH(symlink_array, mov_x0_NEGATIVE1);
    NSLog(@"Fate Bypass: patching syscalls done!");
}

%ctor
{
    NSLog(@"Fate Bypass: ctor!");
    init();
    hook();
}
