#ifndef MAIN_DLL_DF_DLL_022E_DFPDOORSWITCH_H_
#define MAIN_DLL_DF_DLL_022E_DFPDOORSWITCH_H_

#include "main/object_descriptor.h"

extern char sDoorswitchInitNoLongerSupported[];
extern ObjectDescriptor gDFP_seqpointObjDescriptor;
extern ObjectDescriptor gDFP_TorchObjDescriptor;

int doorswitch_getExtraSize(void);
int doorswitch_getObjectTypeId(void);
void doorswitch_free(void);
void doorswitch_render(void);
void doorswitch_hitDetect(void);
void doorswitch_update(void);
void doorswitch_init(void);
void doorswitch_release(void);
void doorswitch_initialise(void);

#endif /* MAIN_DLL_DF_DLL_022E_DFPDOORSWITCH_H_ */
