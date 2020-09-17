#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <substrate.h>
#import <vector>

static uint64_t slide;
static void *dyld_get_image_name_ptr;
static void *dyld_get_image_vmaddr_slide_ptr;
static void *dyld_get_image_header_ptr;
static void *NSGetEnviron_ptr;
static const uint8_t mov_x0_NEGATIVE1[] = { 0x00, 0x00, 0x80, 0x92 };
static const uint8_t mov_x0_2[] = { 0x40, 0x00, 0x80, 0xD2 };
static const uint8_t mov_x0_0[] = { 0x00, 0x00, 0x80, 0xD2 };
static const uint8_t ret[] = { 0xC0, 0x03, 0x5F, 0xD6 };

static uint64_t access_array[] = 
{
    0x100233F48,
    0x100233F4C,
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
    0x102B04BB4,
    0x102B04BB8,
    0x102BF948C,
    0x102BF9490,
    0x102BFA988,
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

%group Dyld_get_image_name

%hookf(const char *, dyld_get_image_name_ptr, int index)
{
    const char *orig = %orig;
    if(strstr(orig, "TweakInject") != NULL) orig = "/A";
    if(strstr(orig, "libhooker") != NULL) orig = "/A";
    if(strstr(orig, "libblackjack") != NULL) orig = "/A";
    if(strstr(orig, "libsubstrate") != NULL) orig = "/A";
    if(strstr(orig, "substrate") != NULL) orig = "/A";
    if(strstr(orig, "Substrate") != NULL) orig = "/A";
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
        NSLog(@"Fate Bypass: Init: eniron: %s", environ[i]);
    }
    NSLog(@"Fate Bypass: initializing done!");
}

#define PATCH(array, patch) \
    do { \
        for(int i = 0; i < sizeof(array) / sizeof(uint64_t); i++) MSHookMemory((void *)(array[i] + slide), (void *)&patch, sizeof(patch)); \
    } while(false)

static void hook()
{
    NSLog(@"Fate Bypass: patching syscalls...");
    PATCH(ptrace_array, mov_x0_NEGATIVE1);
    PATCH(stat_array, mov_x0_NEGATIVE1);
    PATCH(sysctl_array, mov_x0_NEGATIVE1);
    PATCH(access_array, mov_x0_NEGATIVE1);
    NSLog(@"Fate Bypass: patching syscalls done!");
}

%ctor
{
    NSLog(@"Fate Bypass: ctor!");
    init();
    hook();
}
