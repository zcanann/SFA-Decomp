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
int Transporter_getExtraSize(void);
void Transporter_render(void);
void Transporter_hitDetect(int obj);
void Transporter_update(int obj);
void Transporter_init(int obj, u8 *params);

int CFLightWall_getExtraSize(void);
int CFLightWall_getObjectTypeId(void);
void CFLightWall_free(void);
void CFLightWall_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void CFLightWall_hitDetect(void);
void CFLightWall_update(void);
void CFLightWall_init(s16 *obj, u8 *def);
void CFLightWall_release(void);
void CFLightWall_initialise(void);

int BarrelPad_getExtraSize(void);
int BarrelPad_getObjectTypeId(void);
void BarrelPad_free(void);
void BarrelPad_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void BarrelPad_hitDetect(void);
void BarrelPad_update(s16 *obj);
void BarrelPad_init(s16 *obj, u8 *def);
void BarrelPad_release(void);
void BarrelPad_initialise(void);

int CF_DoorLight_getExtraSize(void);
int CF_DoorLight_getObjectTypeId(void);
void CF_DoorLight_free(void);
void CF_DoorLight_render(void);
void CF_DoorLight_hitDetect(void);
void CF_DoorLight_update(int obj);
void CF_DoorLight_init(int *obj, s8 *def);
void CF_DoorLight_release(void);
void CF_DoorLight_initialise(void);

#endif /* MAIN_DLL_CF_CFWALLTORCH_H_ */
