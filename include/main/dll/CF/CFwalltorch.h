#ifndef MAIN_DLL_CF_CFWALLTORCH_H_
#define MAIN_DLL_CF_CFWALLTORCH_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor gTransporterObjDescriptor;
extern ObjectDescriptor gCflightwallObjDescriptor;
extern ObjectDescriptor gBarrelPadObjDescriptor;
extern ObjectDescriptor gCF_DoorLightObjDescriptor;

void FUN_80190bd4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,int param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);
int transporter_getExtraSize(void);
void transporter_render(void);
void transporter_hitDetect(int obj);
void transporter_update(int obj);
void transporter_init(void);

int cflightwall_getExtraSize(void);
int cflightwall_func08(void);
void cflightwall_free(void);
void cflightwall_render(void);
void cflightwall_hitDetect(void);
void cflightwall_update(void);
void cflightwall_init(void);
void cflightwall_release(void);
void cflightwall_initialise(void);

int barrelpad_getExtraSize(void);
int barrelpad_func08(void);
void barrelpad_free(void);
void barrelpad_render(void);
void barrelpad_hitDetect(void);
void barrelpad_update(void);
void barrelpad_init(void);
void barrelpad_release(void);
void barrelpad_initialise(void);

int cf_doorlight_getExtraSize(void);
int cf_doorlight_func08(void);
void cf_doorlight_free(void);
void cf_doorlight_render(void);
void cf_doorlight_hitDetect(void);
void cf_doorlight_update(void);
void cf_doorlight_init(void);
void cf_doorlight_release(void);
void cf_doorlight_initialise(void);

#endif /* MAIN_DLL_CF_CFWALLTORCH_H_ */
