#ifndef MAIN_DLL_CRATE2_H_
#define MAIN_DLL_CRATE2_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

void dfpstatue1_updateState(int obj);

extern char sDfperchwitchInitNoLongerSupported[];
extern ObjectDescriptor gDfpstatue1ObjDescriptor;
extern ObjectDescriptor gDfperchwitchObjDescriptor;

int dfperchwitch_getExtraSize(void);
int dfperchwitch_func08(void);
void dfperchwitch_free(void);
void dfperchwitch_render(void);
void dfperchwitch_hitDetect(void);
void dfperchwitch_update(void);
void dfperchwitch_init(void);
void dfperchwitch_release(void);
void dfperchwitch_initialise(void);

int dfpstatue1_getExtraSize(void);
int dfpstatue1_func08(void);
void dfpstatue1_free(void);
void dfpstatue1_render(void);
void dfpstatue1_hitDetect(void);
void dfpstatue1_update(int obj);
void dfpstatue1_init(undefined2 *obj, int mapData);
void dfpstatue1_release(void);
void dfpstatue1_initialise(void);

#endif /* MAIN_DLL_CRATE2_H_ */
