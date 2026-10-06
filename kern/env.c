/* See COPYRIGHT for copyright information. */

#include <inc/x86.h>
#include <inc/mmu.h>
#include <inc/error.h>
#include <inc/string.h>
#include <inc/assert.h>
#include <inc/elf.h>

#include <kern/env.h>
#include <kern/monitor.h>
#include <kern/sched.h>
#include <kern/kdebug.h>
#include <kern/macro.h>
#include <kern/traceopt.h>

/* Currently active environment */
struct Env *curenv = NULL;

#ifdef CONFIG_KSPACE
/* All environments */
struct Env env_array[NENV];
struct Env *envs = env_array;
#else
/* All environments */
struct Env *envs = NULL;
#endif

/* Free environment list
 * (linked by Env->env_link) */
static struct Env *env_free_list;


/* NOTE: Should be at least LOGNENV */
#define ENVGENSHIFT 12

/* Converts an envid to an env pointer.
 * If checkperm is set, the specified environment must be either the
 * current environment or an immediate child of the current environment.
 *
 * RETURNS
 *     0 on success, -E_BAD_ENV on error.
 *   On success, sets *env_store to the environment.
 *   On error, sets *env_store to NULL. */
int
envid2env(envid_t envid, struct Env **env_store, bool need_check_perm) {
    struct Env *env;

    /* If envid is zero, return the current environment. */
    if (!envid) {
        *env_store = curenv;
        return 0;
    }

    /* Look up the Env structure via the index part of the envid,
     * then check the env_id field in that struct Env
     * to ensure that the envid is not stale
     * (i.e., does not refer to a _previous_ environment
     * that used the same slot in the envs[] array). */
    env = &envs[ENVX(envid)];
    if (env->env_status == ENV_FREE || env->env_id != envid) {
        *env_store = NULL;
        return -E_BAD_ENV;
    }

    /* Check that the calling environment has legitimate permission
     * to manipulate the specified environment.
     * If checkperm is set, the specified environment
     * must be either the current environment
     * or an immediate child of the current environment. */
    if (need_check_perm && env != curenv && env->env_parent_id != curenv->env_id) {
        *env_store = NULL;
        return -E_BAD_ENV;
    }

    *env_store = env;
    return 0;
}

/* Mark all environments in 'envs' as free, set their env_ids to 0,
 * and insert them into the env_free_list.
 * Make sure the environments are in the free list in the same order
 * they are in the envs array (i.e., so that the first call to
 * env_alloc() returns envs[0]).
 */
void
env_init(void) {

    /* Set up envs array */

    // LAB 3: Your code here
    env_free_list = &envs[0];
    for (size_t i = 0; i < NENV - 1; i++) {
        envs[i].env_id = 0;
        envs[i].env_link = &envs[i + 1];
    }
    envs[NENV - 1].env_link = NULL;

}

/* Allocates and initializes a new environment.
 * On success, the new environment is stored in *newenv_store.
 *
 * Returns
 *     0 on success, < 0 on failure.
 * Errors
 *    -E_NO_FREE_ENV if all NENVS environments are allocated
 *    -E_NO_MEM on memory exhaustion
 */
int
env_alloc(struct Env **newenv_store, envid_t parent_id, enum EnvType type) {

    struct Env *env;
    if (!(env = env_free_list))
        return -E_NO_FREE_ENV;

    /* Generate an env_id for this environment */
    int32_t generation = (env->env_id + (1 << ENVGENSHIFT)) & ~(NENV - 1);
    /* Don't create a negative env_id */
    if (generation <= 0) generation = 1 << ENVGENSHIFT;
    env->env_id = generation | (env - envs);

    /* Set the basic status variables */
    env->env_parent_id = parent_id;
#ifdef CONFIG_KSPACE
    env->env_type = ENV_TYPE_KERNEL;
#else
    env->env_type = type;
#endif
    env->env_status = ENV_RUNNABLE;
    env->env_runs = 0;

    /* Clear out all the saved register state,
     * to prevent the register values
     * of a prior environment inhabiting this Env structure
     * from "leaking" into our new environment */
    memset(&env->env_tf, 0, sizeof(env->env_tf));

    /* Set up appropriate initial values for the segment registers.
     * GD_UD is the user data (KD - kernel data) segment selector in the GDT, and
     * GD_UT is the user text (KT - kernel text) segment selector (see inc/memlayout.h).
     * The low 2 bits of each segment register contains the
     * Requestor Privilege Level (RPL); 3 means user mode, 0 - kernel mode.  When
     * we switch privilege levels, the hardware does various
     * checks involving the RPL and the Descriptor Privilege Level
     * (DPL) stored in the descriptors themselves */

#ifdef CONFIG_KSPACE
    env->env_tf.tf_ds = GD_KD;
    env->env_tf.tf_es = GD_KD;
    env->env_tf.tf_ss = GD_KD;
    env->env_tf.tf_cs = GD_KT;

    // LAB 3: Your code here:
    
    static uintptr_t stack_top = 0x2000000;
    env->env_tf.tf_rsp = stack_top - 2 * PAGE_SIZE * (env - envs);
#else
    env->env_tf.tf_ds = GD_UD | 3;
    env->env_tf.tf_es = GD_UD | 3;
    env->env_tf.tf_ss = GD_UD | 3;
    env->env_tf.tf_cs = GD_UT | 3;
    env->env_tf.tf_rsp = USER_STACK_TOP;
#endif

    /* For now init trapframe with IF set */
    env->env_tf.tf_rflags = FL_IF;

    /* Commit the allocation */
    env_free_list = env->env_link;
    *newenv_store = env;

    if (trace_envs) cprintf("[%08x] new env %08x\n", curenv ? curenv->env_id : 0, env->env_id);
    return 0;
}

/* Pass the original ELF image to binary/size and bind all the symbols within
 * its loaded address space specified by image_start/image_end.
 * Make sure you understand why you need to check that each binding
 * must be performed within the image_start/image_end range.
 */

static int 
elf_region_check(const uint8_t *binary, size_t size, uint64_t off, uint64_t len, size_t align) {
    if (off > size) 
        return -1;                          /* начало внутри файла */
    if (len > size - off) 
        return -1;                          /* конец внутри файла, без переполнения */
    if (((uintptr_t)binary + off) % align) 
        return -1;                          /* выравнивание */
    
    return 0;
}
/* вписать в переменные программы адреса реальных функций ядра.*/
static int
bind_functions(struct Env *env, uint8_t *binary, size_t size, uintptr_t image_start, uintptr_t image_end) {
    // LAB 3: Your code here:

    /* NOTE: find_function from kdebug.c should be used */

    /* Заголовок ELF уже проверен в load_icode */
    struct Elf *elf = (struct Elf *)binary;

    /* размер записи в таблице заголовков секций совпадает с размером структуры*/
    if (elf->e_shentsize != sizeof(struct Secthdr)) 
        return -E_INVALID_EXE;
    /*таблица в файле и выровнена*/
    /*e_shoff смещение от начала файла таблицы секций, e_shnum сколько в ней записей*/
    if (elf_region_check(binary, size, elf->e_shoff,
                       (uint64_t)elf->e_shnum * sizeof(struct Secthdr),
                       _Alignof(struct Secthdr))<0)
        return -E_INVALID_EXE;
    /*указатель на массив записей section headers.*/
    struct Secthdr *sh = (struct Secthdr *)(binary + elf->e_shoff); /*указатель на тыблицу секций*/
    /*роходим по всем записям таблицы секций*/
    for (size_t i = 0; i < elf->e_shnum; i++) {
        /*пропускаем все что не таблица символов*/
        if (sh[i].sh_type != ELF_SHT_SYMTAB)    
            continue;

        /* Таблица символов */
        /*размер записей совпадает и размер секции делится на размер записи*/
        if (sh[i].sh_entsize != sizeof(struct Elf64_Sym) ||
            sh[i].sh_size % sizeof(struct Elf64_Sym))
            return -E_INVALID_EXE;
        /*вся таблица символов лежит внутри файла*/
        if (elf_region_check(binary, size, sh[i].sh_offset, sh[i].sh_size,
                           _Alignof(struct Elf64_Sym))<0)
            return -E_INVALID_EXE;

        /* Связанная с ней таблица строк и ее индекс не выходит за пределы таблицы секций*/
        if (sh[i].sh_link >= elf->e_shnum)
            return -E_INVALID_EXE;
        /*описание таблицы строк*/
        struct Secthdr *str_sh = &sh[sh[i].sh_link];
        /*SHT_STRTAB — иначе это не таблица строк,  и не пустая желательно*/
        if (str_sh->sh_type != ELF_SHT_STRTAB || str_sh->sh_size == 0)
            return -E_INVALID_EXE;
        /*вся таблица строк лежит внутри файла*/
        if (elf_region_check(binary, size, str_sh->sh_offset, str_sh->sh_size, 1)<0)
            return -E_INVALID_EXE;
        /* туказательна на таблицу строк переводим в в чар чтобы потом читать  посимвольно*/
        const char *strtab = (const char *)(binary + str_sh->sh_offset);    
        /* Последний байт — ноль, значит любая строка внутри таблицы заканчивается внутри неё */
        if (strtab[str_sh->sh_size - 1] != '\0')
            return -E_INVALID_EXE;
         /*binary +(сsh[i].sh_offset-смещение таблицы символов) - адрес первого байта таблицы символов*/
        struct Elf64_Sym *syms = (struct Elf64_Sym *)(binary + sh[i].sh_offset);   
        /*колличество символов в таблице*/
        size_t nsyms = sh[i].sh_size / sizeof(struct Elf64_Sym);    /*сколько записей*/

        for (size_t j = 0; j < nsyms; j++) {
            /*st_info — это один байт, младшие 4 вид, старшие видимость*/
            if (ELF64_ST_BIND(syms[j].st_info) != STB_GLOBAL ||
                ELF64_ST_TYPE(syms[j].st_info) != STT_OBJECT)
                continue;
            /*смещение таблицы строк может выходить за пределы таблицы*/
            if (syms[j].st_name >= str_sh->sh_size)
                continue;

            const char *name = strtab + syms[j].st_name;
            /*ищет в таблице символов ядра функцию с заданным именем и возвращает её адрес.*/
            uintptr_t addr = find_function(name);
            if (!addr)
                continue;
            /*st_value — это адрес переменной в образе программы.*/
            uintptr_t var_addr = syms[j].st_value;

            /*(void (*)(void)) — это тип «указатель на функцию, принимающую ничего (void) 
            *и возвращающую ничего (void)*/
            /* Получили именно указатель на функцию */
            void (*func)(void) = (void (*)(void))addr;

            /* Проверяем только, что запись лежит внутри образа */
            if (var_addr < image_start ||
                var_addr >= image_end ||
                image_end - var_addr < sizeof(func))
                return -E_INVALID_EXE;

            /* Копируем сам указатель на функцию */
            memcpy((void *)var_addr, &func, sizeof(func));
        }
    }
    return 0;
}

/* Set up the initial program binary, stack, and processor flags
 * for a user process.
 * This function is ONLY called during kernel initialization,
 * before running the first environment.
 *
 * This function loads all loadable segments from the ELF binary image
 * into the environment's user memory, starting at the appropriate
 * virtual addresses indicated in the ELF program header.
 * At the same time it clears to zero any portions of these segments
 * that are marked in the program header as being mapped
 * but not actually present in the ELF file - i.e., the program's bss section.
 *
 * All this is very similar to what our boot loader does, except the boot
 * loader also needs to read the code from disk.  Take a look at
 * LoaderPkg/Loader/Bootloader.c to get ideas.
 *
 * Finally, this function maps one page for the program's initial stack.
 *
 * load_icode returns -E_INVALID_EXE if it encounters problems.
 *  - How might load_icode fail?  What might be wrong with the given input?
 *
 * Hints:
 *   Load each program segment into memory
 *   at the address specified in the ELF section header.
 *   You should only load segments with ph->p_type == ELF_PROG_LOAD.
 *   Each segment's address can be found in ph->p_va
 *   and its size in memory can be found in ph->p_memsz.
 *   The ph->p_filesz bytes from the ELF binary, starting at
 *   'binary + ph->p_offset', should be copied to address
 *   ph->p_va.  Any remaining memory bytes should be cleared to zero.
 *   (The ELF header should have ph->p_filesz <= ph->p_memsz.)
 *
 *   All page protection bits should be user read/write for now.
 *   ELF segments are not necessarily page-aligned, but you can
 *   assume for this function that no two segments will touch
 *   the same page.
 *
 *   You must also do something with the program's entry point,
 *   to make sure that the environment starts executing there.
 *   What?  (See env_run() and env_pop_tf() below.) */

/*Функция берёт binary, разбирает ELF-файл, 
 * копирует код и данные программы по нужным адресам и записывает в env_tf.tf_rip точку входа e_entry, 
 * чтобы процесс знал, откуда начинать.*/
static int
load_icode(struct Env *env, uint8_t *binary, size_t size) {
    // LAB 3: Your code here
    /* проверка elf- заголовка */
     if (binary == NULL) 
        return -E_INVALID_EXE;

    /* проверяем, что заголовок ELF целиком помещается в буфер и выровнен */        
    if (elf_region_check(binary, size, 0, sizeof(struct Elf), _Alignof(struct Elf))<0)
        return -E_INVALID_EXE;

    /*чтобы обращаться как к заголовоку а не через смещение*/
    struct Elf *elf = (struct Elf *)binary; 
    /*проверка на elf*/
    if (elf->e_magic != ELF_MAGIC)  
        return -E_INVALID_EXE;

    /* проверяем, что файл 64-битный */
    if (elf->e_elf[EI_CLASS] != ELFCLASS64)
        return -E_INVALID_EXE;

     /* проверяем, что данные в little-endian (x86 — little-endian) */
    if (elf->e_elf[EI_DATA] != ELFDATA2LSB)
        return -E_INVALID_EXE;

    /* проверяем версию ELF: и в e_ident, и в e_version — обе должны быть EV_CURRENT */
    if ((elf->e_elf[EI_VERSION] != EV_CURRENT) ||
        (elf->e_version != EV_CURRENT))
        return -E_INVALID_EXE;
    
    /* проверяем тип: JOS загружает только ET_EXEC (готовый к запуску) */
    if (elf->e_type != ET_EXEC)
        return -E_INVALID_EXE;

     /* проверяем архитектуру: должна быть x86-64 */
    if (elf->e_machine != EM_X86_64)
        return -E_INVALID_EXE;

     /* проверяем, что размер заголовка совпадает с sizeof(struct Elf) */
    if (elf->e_ehsize != sizeof(struct Elf))
        return -E_INVALID_EXE;



                            /* Proghdr check */

    /* проверяем, что размер одной записи program header совпадает с sizeof(struct Proghdr) */
    if (elf->e_phentsize != sizeof(struct Proghdr))
        return -E_INVALID_EXE;

    /* проверяем, что таблица program headers не перекрывается с ELF-заголовком */
    if (elf->e_phoff < elf->e_ehsize)
        return -E_INVALID_EXE;

    /*Таблица сегментов начинается с e_phoff, e_phnum количество сегментов*/
    if (elf_region_check(binary, size, elf->e_phoff,
                       (uint64_t)elf->e_phnum * sizeof(struct Proghdr),
                       _Alignof(struct Proghdr))<0)   /*проверка границ и выравнивание*/
        return -E_INVALID_EXE;
    /*указатель массив записей в таблице смещений*/
    struct Proghdr *ph = (struct Proghdr *)(binary + elf->e_phoff); 
    /*инициализация границ образа-потом проверим что адрес переменной в этих границах*/
    uintptr_t image_start = UINTPTR_MAX, image_end = 0;

    for (size_t i = 0; i < elf->e_phnum; i++) {
        if (ph[i].p_type != ELF_PROG_LOAD)
            continue;
        /*данных в файле не более чем в памяти*/
        if (ph[i].p_filesz > ph[i].p_memsz)
            return -E_INVALID_EXE;

        /* проверяем, что p_align — степень двойки */
        if ((ph[i].p_align & (ph[i].p_align - 1)) != 0)
            return -E_INVALID_EXE;

        /* проверяем, что offset и vaddr согласованы по модулю p_align (требование ELF) */
        if (ph[i].p_offset % ph[i].p_align != ph[i].p_va % ph[i].p_align)
            return -E_INVALID_EXE;


        /* Данные сегмента целиком внутри файла */
        /*p_offset	смещение сегмента в файле, p_filesz	размер сегмента в файле*/
        if (elf_region_check(binary, size, ph[i].p_offset, ph[i].p_filesz, 1)<0)
            return -E_INVALID_EXE;

        // Check for valid virtual address
        if (ph[i].p_va > MAX_USER_READABLE)
            return -E_INVALID_EXE;

        /* p_va + p_memsz не переполняется */
        /*p_memsz	размер сегмента в памяти, p_va	адрес в памяти, куда положить сегмент*/
        if (ph[i].p_memsz > UINTPTR_MAX - ph[i].p_va)
            return -E_INVALID_EXE;
        /*кладем сегмент в память, зануляем хвост сегмента*/
        memcpy((void *)ph[i].p_va, binary + ph[i].p_offset, ph[i].p_filesz);
        memset((void *)(ph[i].p_va + ph[i].p_filesz), 0, ph[i].p_memsz - ph[i].p_filesz);

        /* обновляем минимальный и максимальный адрес среди наших сегментов*/
        if (ph[i].p_va < image_start) image_start = ph[i].p_va;
        if (ph[i].p_va + ph[i].p_memsz > image_end) image_end = ph[i].p_va + ph[i].p_memsz;
    }

    /* Должен быть хотя бы один загружаемый сегмент,
     * и точка входа должна указывать внутрь загруженной программы */
    if (image_start >= image_end)
        return -E_INVALID_EXE;
    if (elf->e_entry < image_start || elf->e_entry >= image_end)
        return -E_INVALID_EXE;
    /* записываем точку входа в trapframe щкружение*/
    env->env_tf.tf_rip = elf->e_entry;

    return bind_functions(env, binary, size, image_start, image_end);
}

/* Allocates a new env with env_alloc, loads the named elf
 * binary into it with load_icode, and sets its env_type.
 * This function is ONLY called during kernel initialization,
 * before running the first user-mode environment.
 * The new env's parent ID is set to 0.
 */
void
env_create(uint8_t *binary, size_t size, enum EnvType type) {
    // LAB 3: Your code here
    struct Env *env;
    int status = env_alloc(&env, 0, type);
    if (status < 0)
        panic("Error. Can't allocate new environment : %i", status);

    status = load_icode(env, binary, size);
    if (status < 0)
        panic("Error. Could not load executable : %i", status);

    env->binary = binary;
}


/* Frees env and all memory it uses */
void
env_free(struct Env *env) {

    /* Note the environment's demise. */
    if (trace_envs) cprintf("[%08x] free env %08x\n", curenv ? curenv->env_id : 0, env->env_id);

    /* Return the environment to the free list */
    env->env_status = ENV_FREE;
    env->env_link = env_free_list;
    env_free_list = env;
}

/* Frees environment env
 *
 * If env was the current one, then runs a new environment
 * (and does not return to the caller)
 */
void
env_destroy(struct Env *env) {
    env->env_status = ENV_DYING;
    env_free(env);

    if (env == curenv)
        sched_yield();
}


#ifdef CONFIG_KSPACE
void
csys_exit(void) {
    if (!curenv) panic("curenv = NULL");
    env_destroy(curenv);
}

void
csys_yield(struct Trapframe *tf) {
    memcpy(&curenv->env_tf, tf, sizeof(struct Trapframe));
    sched_yield();
}
#endif

/* Restores the register values in the Trapframe with the 'ret' instruction.
 * This exits the kernel and starts executing some environment's code.
 *
 * This function does not return.
 */

_Noreturn void
env_pop_tf(struct Trapframe *tf) {

    /* Push RIP on program stack */
    tf->tf_rsp -= sizeof(uintptr_t);
    *((uintptr_t *)tf->tf_rsp) = tf->tf_rip;
    /* Push RFLAGS on program stack */
    tf->tf_rsp -= sizeof(uintptr_t);
    *((uintptr_t *)tf->tf_rsp) = tf->tf_rflags;

    asm volatile(
            "movq %0, %%rsp\n"
            "movq 0(%%rsp), %%r15\n"
            "movq 8(%%rsp), %%r14\n"
            "movq 16(%%rsp), %%r13\n"
            "movq 24(%%rsp), %%r12\n"
            "movq 32(%%rsp), %%r11\n"
            "movq 40(%%rsp), %%r10\n"
            "movq 48(%%rsp), %%r9\n"
            "movq 56(%%rsp), %%r8\n"
            "movq 64(%%rsp), %%rsi\n"
            "movq 72(%%rsp), %%rdi\n"
            "movq 80(%%rsp), %%rbp\n"
            "movq 88(%%rsp), %%rdx\n"
            "movq 96(%%rsp), %%rcx\n"
            "movq 104(%%rsp), %%rbx\n"
            "movq 112(%%rsp), %%rax\n"
            "movq (128+48)(%%rsp), %%rsp\n"
            "popfq; ret" ::"g"(tf)
            : "memory");

    /* Mostly to placate the compiler */
    panic("Reached unrecheble\n");
}

/* Context switch from curenv to env.
 * This function does not return.
 *
 * Step 1: If this is a context switch (a new environment is running):
 *       1. Set the current environment (if any) back to
 *          ENV_RUNNABLE if it is ENV_RUNNING (think about
 *          what other states it can be in),
 *       2. Set 'curenv' to the new environment,
 *       3. Set its status to ENV_RUNNING,
 *       4. Update its 'env_runs' counter,
 * Step 2: Use env_pop_tf() to restore the environment's
 *       registers and starting execution of process.

 * Hints:
 *    If this is the first call to env_run, curenv is NULL.
 *
 *    This function loads the new environment's state from
 *    env->env_tf.  Go back through the code you wrote above
 *    and make sure you have set the relevant parts of
 *    env->env_tf to sensible values.
 */
_Noreturn void
env_run(struct Env *env) {
    assert(env);

    if (trace_envs_more) {
        const char *state[] = {"FREE", "DYING", "RUNNABLE", "RUNNING", "NOT_RUNNABLE"};
        if (curenv) cprintf("[%08X] env stopped: %s\n", curenv->env_id, state[curenv->env_status]);
        cprintf("[%08X] env started: %s\n", env->env_id, state[env->env_status]);
    }

    // LAB 3: Your code here
    if (curenv) {
        if (curenv->env_status == ENV_RUNNING)
            curenv->env_status = ENV_RUNNABLE;
    }

    if (env->env_status != ENV_RUNNABLE)
        panic("Scheduled process is not runnable");

    curenv = env;
    curenv->env_status = ENV_RUNNING;
    curenv->env_runs++;


    env_pop_tf(&curenv->env_tf);
    
    while (1)
        ;
}
