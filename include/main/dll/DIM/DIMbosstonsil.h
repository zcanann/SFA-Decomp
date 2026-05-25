#ifndef MAIN_DLL_DIM_DIMBOSSTONSIL_H_
#define MAIN_DLL_DIM_DIMBOSSTONSIL_H_

#include "ghidra_import.h"
#include "main/objanim_update.h"

#define DIMBOSSTONSIL_OBJECT_TYPE 0x4b
#define DIMBOSSTONSIL_STATE_SIZE 0x410
#define DIMBOSSTONSIL_SCALE_OFFSET 0x274
#define DIMBOSSTONSIL_HEALTH_PHASE_OFFSET 0x354
#define DIMBOSSTONSIL_FIELD270_OFFSET 0x270
#define DIMBOSSTONSIL_EVENT_GAMEBIT_OFFSET 0x3f6
#define DIMBOSSTONSIL_STATE_FLAGS_OFFSET 0x400
#define DIMBOSSTONSIL_HIT_REACT_MODE_OFFSET 0x405

#define DIMBOSSTONSIL_ANIM_EVENT_START_STEAM 1
#define DIMBOSSTONSIL_ANIM_EVENT_ENABLE_AREA 2
#define DIMBOSSTONSIL_ANIM_EVENT_DISABLE_AREA 3
#define DIMBOSSTONSIL_ANIM_EVENT_ENABLE_LIGHT 4
#define DIMBOSSTONSIL_ANIM_EVENT_DISABLE_LIGHT 5

#define DIMBOSSTONSIL_MAP_DIR 0x1c
#define DIMBOSSTONSIL_MAP_AREA 1
#define DIMBOSSTONSIL_STEAM_ENVFX 0xd8
#define DIMBOSSTONSIL_STEAM_MUSIC 0xee
#define DIMBOSSTONSIL_RUMBLE_SFX 0x189
#define DIMBOSSTONSIL_STATE_FLAG_START_MOVE 2

extern void *gDIMbosstonsilLight;
extern s8 gDIMbosstonsilRoutePhase;

int dll_DIM_BossGutSpik_update(void *obj,undefined4 param_2,ObjAnimUpdateState *animUpdate);
void DIMbosstonsil_func0B(void);
int DIMbosstonsil_setScale(int obj);
int DIMbosstonsil_getExtraSize(void);
int DIMbosstonsil_getObjectTypeId(void);
void DIMbosstonsil_free(void *obj);
int DIMbosstonsil_func08(void);
void DIMbosstonsil_render(void *obj,undefined4 p2,undefined4 p3,undefined4 p4,undefined4 p5,
                          char visible);
void DIMbosstonsil_hitDetect(void *obj);
void DIMbosstonsil_update(void *obj);
void DIMbosstonsil_init(int obj,undefined4 param_2,int isAltVariant);
void DIMbosstonsil_release(void);
void DIMbosstonsil_initialise(void);

#endif /* MAIN_DLL_DIM_DIMBOSSTONSIL_H_ */
