#include "main/obj_placement.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/DF/rope.h"
#include "main/dll/mmsh_waterspike.h"

typedef struct DimbosscrackparPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    u8 pad1C[0x1E - 0x1C];
    s16 unk1E;
} DimbosscrackparPlacement;












extern EffectInterface** gPartfxInterface;

/*
 * --INFO--
 *
 * Function: dimbossgut2_updateTracking
 * EN v1.0 Address: 0x801BF048
 * EN v1.0 Size: 652b
 * EN v1.1 Address: 0x801BF5FC
 * EN v1.1 Size: 680b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: dimbossgut2_free
 * EN v1.0 Address: 0x801BF2F0
 * EN v1.0 Size: 140b
 * EN v1.1 Address: 0x801BF8A4
 * EN v1.1 Size: 140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: dimbossgut2_render
 * EN v1.0 Address: 0x801BF37C
 * EN v1.0 Size: 104b
 * EN v1.1 Address: 0x801BF930
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: dimbossgut2_update
 * EN v1.0 Address: 0x801BF3E8
 * EN v1.0 Size: 716b
 * EN v1.1 Address: 0x801BF99C
 * EN v1.1 Size: 716b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: dimbossgut2_init
 * EN v1.0 Address: 0x801BF6B4
 * EN v1.0 Size: 540b
 * EN v1.1 Address: 0x801BFC68
 * EN v1.1 Size: 540b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: DIMbossspit_updateBurst
 * EN v1.0 Address: 0x801BF8D8
 * EN v1.0 Size: 648b
 * EN v1.1 Address: 0x801BFE8C
 * EN v1.1 Size: 664b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: DIMbossspit_free
 * EN v1.0 Address: 0x801BFB70
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x801C0124
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: DIMbossspit_render
 * EN v1.0 Address: 0x801BFBC4
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x801C0178
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: DIMbossspit_update
 * EN v1.0 Address: 0x801BFC2C
 * EN v1.0 Size: 648b
 * EN v1.1 Address: 0x801C01E0
 * EN v1.1 Size: 648b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: DIMbossspit_init
 * EN v1.0 Address: 0x801BFEB4
 * EN v1.0 Size: 312b
 * EN v1.1 Address: 0x801C0468
 * EN v1.1 Size: 312b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */



/* Trivial 4b 0-arg blr leaves. */












void dimbosscrackpar_hitDetect(void)
{
}

void dimbosscrackpar_release(void)
{
}

void dimbosscrackpar_initialise(void)
{
}

/*
 * --INFO--
 *
 * Function: magicmaker_update
 * EN v1.0 Address: 0x801C0080
 * EN v1.0 Size: 624b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern u8 Obj_IsLoadingLocked(void);

void magicmaker_update(int obj);

extern f32 lbl_803E4D98;

int dimbosscrackpar_SeqFn(int* obj)
{
    int* side = *(int**)&((GameObject*)obj)->anim.placementData;
    if ((u32)GameBit_Get(((DimbosscrackparPlacement*)side)->unk1E) == 0u)
    {
        return 0;
    }
    (*gPartfxInterface)->spawnObject(
        obj, ((DimbosscrackparPlacement*)side)->unk1A + 1222, NULL, 2, -1, NULL);
    (*gPartfxInterface)->spawnObject(obj, 1224, NULL, 2, -1, NULL);
    return 0;
}

void dimbosscrackpar_update(int* obj)
{
    int* side = *(int**)&((GameObject*)obj)->anim.placementData;
    if ((u32)GameBit_Get(((DimbosscrackparPlacement*)side)->unk1E) != 0u)
    {
        (*gPartfxInterface)->spawnObject(
            obj, ((DimbosscrackparPlacement*)side)->unk1A + 1222, NULL, 2, -1, NULL);
        (*gPartfxInterface)->spawnObject(obj, 1224, NULL, 2, -1, NULL);
    }
}

void dimbosscrackpar_free(int* obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void dimbosscrackpar_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }

void dimbosscrackpar_init(s16* obj, s8* def)
{
    ((GameObject*)obj)->anim.rotX = 0;
    ((GameObject*)obj)->anim.rootMotionScale = lbl_803E4D98;
    ((GameObject*)obj)->animEventCallback = (void*)dimbosscrackpar_SeqFn;
    ((GameObject*)obj)->anim.rotX = (s16)((s32)def[0x24] << 8);
    ((GameObject*)obj)->anim.rotY = (s16)((s32)def[0x23] << 8);
    ((GameObject*)obj)->anim.rotZ = (s16)((s32)def[0x22] << 8);
}

void dimbossfire_hitDetect(void);

/*
 * --INFO--
 *
 * Function: dimbossfire_free
 * EN v1.0 Address: 0x801C04C8
 * EN v1.0 Size: 100b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/* 8b "li r3, N; blr" returners. */
int dimbosscrackpar_getExtraSize(void) { return 0x0; }
int dimbosscrackpar_getObjectTypeId(void) { return 0x0; }
int dimbossfire_getExtraSize(void);

/* render-with-objRenderFn_8003b8f4 pattern. */
