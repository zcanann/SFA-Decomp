#ifndef MAIN_UNKNOWN_AUTOS_PLACEHOLDER_80284BAC_H_
#define MAIN_UNKNOWN_AUTOS_PLACEHOLDER_80284BAC_H_

#include "ghidra_import.h"

typedef struct ReverbParams {
  int p0;
  int p4;
  int p8;
} ReverbParams;

typedef struct ReverbState {
  u8 unk0[0x13c];
  u8 enabled;
  u8 unk13D[3];
  f32 a;
  f32 c;
  f32 b;
  f32 d;
  f32 e;
} ReverbState;

void salFree(void *ptr);
void sndAuxCallbackReverbSTD(u8 mode, ReverbParams *params, ReverbState *state);
void sndAuxCallbackUpdateSettingsReverbSTD(ReverbState *state);

#endif /* MAIN_UNKNOWN_AUTOS_PLACEHOLDER_80284BAC_H_ */
