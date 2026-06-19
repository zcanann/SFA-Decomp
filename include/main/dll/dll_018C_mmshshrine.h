#ifndef MAIN_DLL_LASER19F_H_
#define MAIN_DLL_LASER19F_H_

#include "ghidra_import.h"

typedef struct MMSHShrineSequenceState {
  u8 pad00[0x56];
  u8 activeCommand;
  u8 pad57[0x70 - 0x57];
  s16 targetObject;
  u8 pad72[0x81 - 0x72];
  u8 commands[10];
  u8 commandCount;
} MMSHShrineSequenceState;

int MMSH_Shrine_SeqFn(int obj, u32 unused, MMSHShrineSequenceState *seq);
int mmsh_shrine_getExtraSize(void);
int mmsh_shrine_getObjectTypeId(void);
void mmsh_shrine_free(int param_1);
void mmsh_shrine_render(int obj, u32 a2, u32 a3, u32 a4, u32 a5,
                        char flag);
void mmsh_shrine_hitDetect(void);
void mmsh_shrine_update(int param_1);

#endif /* MAIN_DLL_LASER19F_H_ */
