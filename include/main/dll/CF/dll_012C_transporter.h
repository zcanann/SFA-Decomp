#ifndef MAIN_DLL_CF_CFWALLTORCH_H_
#define MAIN_DLL_CF_CFWALLTORCH_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"
#include "main/objanim_update.h"

extern ObjectDescriptor gTransporterObjDescriptor;
extern ObjectDescriptor gCflightwallObjDescriptor;
extern ObjectDescriptor gBarrelPadObjDescriptor;
extern ObjectDescriptor gCF_DoorLightObjDescriptor;

int Transporter_SeqFn(int *obj, int p2, ObjAnimUpdateState *animUpdate);
int transporter_getExtraSize(void);
void transporter_render(void);
void transporter_hitDetect(int obj);
void transporter_update(int obj);
void transporter_init(int obj, u8 *params);

int cflightwall_getExtraSize(void);
int cflightwall_getObjectTypeId(void);
void cflightwall_free(void);
void cflightwall_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void cflightwall_hitDetect(void);
void cflightwall_update(void);
void cflightwall_init(s16 *obj, u8 *def);
void cflightwall_release(void);
void cflightwall_initialise(void);

int barrelpad_getExtraSize(void);
int barrelpad_getObjectTypeId(void);
void barrelpad_free(void);
void barrelpad_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void barrelpad_hitDetect(void);
void barrelpad_update(s16 *obj);
void barrelpad_init(s16 *obj, u8 *def);
void barrelpad_release(void);
void barrelpad_initialise(void);

int cf_doorlight_getExtraSize(void);
int cf_doorlight_getObjectTypeId(void);
void cf_doorlight_free(void);
void cf_doorlight_render(void);
void cf_doorlight_hitDetect(void);
void cf_doorlight_update(int obj);
void cf_doorlight_init(int *obj, s8 *def);
void cf_doorlight_release(void);
void cf_doorlight_initialise(void);

#endif /* MAIN_DLL_CF_CFWALLTORCH_H_ */
