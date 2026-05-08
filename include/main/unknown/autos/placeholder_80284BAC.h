#ifndef MAIN_UNKNOWN_AUTOS_PLACEHOLDER_80284BAC_H_
#define MAIN_UNKNOWN_AUTOS_PLACEHOLDER_80284BAC_H_

#include "ghidra_import.h"

typedef struct ReverbParams ReverbParams;
typedef struct ReverbState ReverbState;

void salFree(void *ptr);
void sndAuxCallbackReverbSTD(u8 mode, ReverbParams *params, ReverbState *state);
void sndAuxCallbackUpdateSettingsReverbSTD(ReverbState *state);

#endif /* MAIN_UNKNOWN_AUTOS_PLACEHOLDER_80284BAC_H_ */
