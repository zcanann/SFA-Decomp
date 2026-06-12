/* DLL 0x194 — GP/SH scene controller [801C70F0-801C7724) */
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"
#include "main/dll/mmshrine/shrine1C2.h"
#include "main/objseq.h"
#include "main/screen_transition.h"





/*
 * --INFO--
 *
 * Function: ecsh_shrine_update
 * EN v1.0 Address: 0x801C60B8
 * EN v1.0 Size: 3360b
 * EN v1.1 Address: 0x801C666C
 * EN v1.1 Size: 3104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */



#pragma opt_strength_reduction off
#pragma opt_strength_reduction reset


/*
 * --INFO--
 *
 * Function: FUN_801c6e04
 * EN v1.0 Address: 0x801C6E04
 * EN v1.0 Size: 704b
 * EN v1.1 Address: 0x801C7408
 * EN v1.1 Size: 668b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/* Trivial 4b 0-arg blr leaves. */







/* 8b "li r3, N; blr" returners. */

extern void objRenderFn_8003b8f4(f32);



/* render-with-objRenderFn_8003b8f4 pattern. */











#include "main/audio/sfx_ids.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/dll/creator1C4.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/screen_transition.h"









/*
 * --INFO--
 *
 * Function: gpsh_shrine_update
 * EN v1.0 Address: 0x801C7724
 * EN v1.0 Size: 2520b
 * EN v1.1 Address: 0x801C7CD8
 * EN v1.1 Size: 2124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */





/* Trivial 4b 0-arg blr leaves. */








void gpsh_scene_free(void)
{
}

void gpsh_scene_hitDetect(void)
{
}

void gpsh_scene_update(void)
{
}

void gpsh_scene_release(void)
{
}

void gpsh_scene_initialise(void)
{
}

void ecsh_cup_hitDetect(void);

/* 8b "li r3, N; blr" returners. */
int gpsh_scene_getExtraSize(void) { return 0x0; }
int gpsh_scene_getObjectTypeId(void) { return 0x0; }
int ecsh_cup_getExtraSize(void);

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E5058;


void gpsh_scene_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E5058);
}

void ecsh_cup_render(int p1, int p2, int p3, int p4, int p5, s8 visible);


void gpsh_scene_init(int* obj, int* def)
{
    *(s16*)obj = (s16)((s32) * (s8*)((char*)def + 0x18) << 8);
    ((GameObject*)obj)->anim.worldPosX = ((GameObject*)obj)->anim.localPosX;
    ((GameObject*)obj)->anim.worldPosY = ((GameObject*)obj)->anim.localPosY;
    ((GameObject*)obj)->anim.worldPosZ = ((GameObject*)obj)->anim.localPosZ;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 8);
}

void gpsh_objcreator_init(int* obj, int* def);
