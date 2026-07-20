#ifndef DOLPHIN_OS_PPC_EABI_INIT_H_
#define DOLPHIN_OS_PPC_EABI_INIT_H_

#ifdef __cplusplus
extern "C" {
#endif

void __init_user(void);
void _ExitProcess(void);
__declspec(section ".init") asm void __init_hardware(void);
__declspec(section ".init") asm void __flush_cache(void* address, unsigned int size);

#ifdef __cplusplus
}
#endif

#endif /* DOLPHIN_OS_PPC_EABI_INIT_H_ */
