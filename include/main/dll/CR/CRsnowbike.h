#ifndef MAIN_DLL_CR_CRSNOWBIKE_H_
#define MAIN_DLL_CR_CRSNOWBIKE_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"
#include "main/objanim_update.h"

extern ObjectDescriptor12 gSC_levelcontrolObjDescriptor;
extern ObjectDescriptor gSC_MusicTreeObjDescriptor;

void sh_emptytumblew_init(s16 *p1, int p2);
void FUN_801db57c(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u16 *param_9,int param_10);
void FUN_801db580(u32 param_1);
void FUN_801db5b8(short *param_1,int param_2);
u32 sc_levelcontrol_processAnimEvents(int param_1,u32 param_2,ObjAnimUpdateState *animUpdate);
void sc_levelcontrol_setAnimEventState(int param_1,u8 param_2);
void FUN_801db8c4(void);
void FUN_801db924(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801db94c(u64 param_1,double param_2,double param_3,double param_4,double param_5,
                 u64 param_6,u64 param_7,u64 param_8,int param_9);

u8 sc_levelcontrol_getAnimEventState(int *obj);
int sc_levelcontrol_processAnimEventsCallback(int obj, int unused, ObjAnimUpdateState *animUpdate);
void sc_levelcontrol_applyAnimEventState(int obj, u8 scale);
int sc_levelcontrol_getExtraSize(void);
int sc_levelcontrol_getObjectTypeId(void);
void sc_levelcontrol_free(int obj);
void sc_levelcontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void sc_levelcontrol_hitDetect(void);
void sc_levelcontrol_update(int obj);
void sc_levelcontrol_init(int obj);
void sc_levelcontrol_release(void);
void sc_levelcontrol_initialise(void);

void sc_musictree_spawnAmbientEffect(int obj, int p2, int p3, s8 idx);
void sc_musictree_handleHitObject(int obj, int p2, int effectType);
int sc_musictree_getExtraSize(void);
int sc_musictree_getObjectTypeId(void);
void sc_musictree_free(void);
void sc_musictree_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void sc_musictree_hitDetect(void);
void sc_musictree_update(int obj);
/* sc_musictree_init is defined in DRcloudrunner.c with a private setup type;
 * declared there. Not referenced here, so no prototype is carried (a (void)
 * drift prototype collides with the real def when the TUs merge). */
void sc_musictree_release(void);
void sc_musictree_initialise(void);

#endif /* MAIN_DLL_CR_CRSNOWBIKE_H_ */
