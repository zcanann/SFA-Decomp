#ifndef MAIN_DLL_MMP_MMP_LEVELCONTROL_H_
#define MAIN_DLL_MMP_MMP_LEVELCONTROL_H_

#include "main/game_object.h"
#include "ghidra_import.h"

#define WALLANIMATOR_DONE_TIMER          3000
#define WALLANIMATOR_GROUP_PRIMARY       0x23
#define WALLANIMATOR_GROUP_SECONDARY     0x31
#define WALLANIMATOR_NEARBY_GROUP        5
#define WALLANIMATOR_RUNTIME_ACTIVE_FLAG 0x80
#define WALLANIMATOR_COMPLETE_SFX        0x109

struct WallanimatorPlacement;
f32 wallanimator_setScale(GameObject* obj, int desc);
void fn_80194964(int obj, int state, int block);
void fn_80194C40(u32 def, int state, int block);
u8 wallanimator_modelMtxFn(int* obj);
u8 wallanimator_func0B(int* obj);
int wallanimator_getExtraSize(void);
void wallanimator_free(int obj);
void wallanimator_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void wallanimator_update(GameObject* obj);
void wallanimator_init(int obj, struct WallanimatorPlacement* desc);
int XyzAnimator_getExtraSize(void);
void XyzAnimator_free(GameObject* obj, int param_2);

#endif /* MAIN_DLL_MMP_MMP_LEVELCONTROL_H_ */
