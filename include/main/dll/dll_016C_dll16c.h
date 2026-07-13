#ifndef MAIN_DLL_DLL_016C_DLL16C_H_
#define MAIN_DLL_DLL_016C_DLL16C_H_

#include "main/game_object.h"
#include "ghidra_import.h"
#include "main/object_descriptor.h"
#include "main/objanim_update.h"

typedef struct Dll16CState
{
    GameObject* linkedObj; /* group-10 object matched by type (364/367) */
    f32 unk04; /* set on anim event 2 */
    f32 snapX; /* path point snapshot taken on anim event 2 */
    f32 snapY;
    f32 snapZ;
    f32 pathPointX; /* path point 1 world position, refreshed in render */
    f32 pathPointY;
    f32 pathPointZ;
    u8 opacity; /* distance fade; 0xFF when unlinked */
    s8 subObjIndex; /* lbl_802C2308 id selector; -1 = clear (anim event 3) */
    s8 subObjIndexApplied;
    u8 pad23;
} Dll16CState;

int dll_16C_getExtraSize(void);
int dll_16C_getObjectTypeId(void);
void dll_16C_free(GameObject* obj);
void dll_16C_render(GameObject* obj, int p1, int p2, int p3, int p4, s8 visible);
void dll_16C_hitDetect(GameObject* obj);
void dll_16C_update(GameObject* obj);
void dll_16C_init(GameObject* obj, void* arg2);
int dll_16C_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
void dll_16C_release(void);
void dll_16C_initialise(void);
void dll_16C_syncSubObjectTransform(GameObject* dst, GameObject* src, int p1, int p2, int p3, int p4, int visible,
                                    int opacity, int copyTransform);

#endif /* MAIN_DLL_DLL_016C_DLL16C_H_ */
