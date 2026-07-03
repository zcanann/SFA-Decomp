/*
 * dll3f (DLL 0x3F) - title-screen DLL boilerplate.
 *
 * Owns gTitleScreenObjDescriptor, a 10-slot ObjectDescriptor wiring the
 * titlescreen_* object callbacks (init/update/hitDetect/render/free/...).
 * dll_3F_initialise loads texture asset 0x47A into lbl_803DD960 and
 * dll_3F_release frees it. dll_3F_frameStart_ret_0 / dll_3F_frameEnd_nop
 * are the per-frame hook leaves.
 *
 * fn_80133F70 formats a countdown into a stack buffer: it runs the game
 * timer (if active), finds the nearest object of group 9 within
 * lbl_803E22A0, queries it through vtable slot 21 for three counters,
 * derives a clamped remaining value, and sprintf's it via the
 * lbl_803DBBF0 format string.
 */
#include "main/texture.h"
#include "main/dll/ppcwgpipe_struct.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/gameplay_runtime.h"
#include "main/sfa_extern_decls.h"
#include "main/dll/dll_02C0_front.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/printf.h"
extern int ObjGroup_FindNearestObject();
extern u8 gameTimerIsRunning(void);
extern void gameTimerRun(void* obj);

extern f32 lbl_803E22A0;
extern void* lbl_803DD960;
__declspec(section ".sdata") extern char lbl_803DBBF0[];





void dll_3F_frameEnd_nop(void)
{
}

int dll_3F_frameStart_ret_0(void) { return 0; }

ObjectDescriptor10WithPadding gTitleScreenObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
        (ObjectDescriptorCallback)titlescreen_initialise,
        (ObjectDescriptorCallback)titlescreen_release,
        0,
        (ObjectDescriptorCallback)titlescreen_init,
        (ObjectDescriptorCallback)titlescreen_update,
        (ObjectDescriptorCallback)titlescreen_hitDetect,
        (ObjectDescriptorCallback)titlescreen_render,
        (ObjectDescriptorCallback)titlescreen_free,
        (ObjectDescriptorCallback)titlescreen_getObjectTypeId,
        titlescreen_getExtraSize,
    },
    0,
};

#pragma scheduling off
#pragma peephole off
void fn_80133F70(void* obj)
{
    char buf[12];
    f32 maxDist;
    int start;
    int elapsed;
    int total;
    void* player;
    void* nearest;

    maxDist = lbl_803E22A0;
    start = 0;
    elapsed = 0;
    total = 0;
    if (gameTimerIsRunning())
    {
        gameTimerRun(obj);
    }
    player = Obj_GetPlayerObject();
    nearest = (void*)ObjGroup_FindNearestObject(9, player, &maxDist);
    if (nearest != NULL)
    {
        ((void (*)(void*, int*, int*, int*))(*(void***)((GameObject*)nearest)->anim.dll)[21])(nearest, &start, &elapsed, &total);
    }
    elapsed = total - (elapsed - start);
    if (elapsed < 0)
    {
        elapsed = 0;
    }
    sprintf(buf, lbl_803DBBF0, elapsed);
}

#pragma scheduling on
#pragma peephole on
void dll_3F_release(void)
{
    textureFree(lbl_803DD960);
}

#pragma scheduling off /* intentional: last fn in TU */
void dll_3F_initialise(void)
{
    lbl_803DD960 = textureLoadAsset(0x47A);
}

PPCWGPipe GXWGFifo : (0xCC008000);
