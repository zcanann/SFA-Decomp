/* DLL 0x010F — mmpbridge (MoonMountain Pass bridge object). TU: 0x8017BB80–0x8017BCF8. */
#include "main/game_object.h"

/*
 * --INFO--
 *
 * Function: pressureswitchfb_updateStateMode
 * EN v1.0 Address: 0x8017AC2C
 * EN v1.0 Size: 348b
 * EN v1.1 Address: 0x8017AC40
 * EN v1.1 Size: 388b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: pressureswitchfb_getExtraSize
 * EN v1.0 Address: 0x8017AD88
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8017ADC4
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: pressureswitchfb_free
 * EN v1.0 Address: 0x8017AD90
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x8017ADCC
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

#include "main/dll/cfguardian_state.h"
#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/cfguardian.h"
#include "main/game_object.h"
#include "main/objseq.h"

typedef struct MmpBridgePlacement
{
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 unk5;
    u8 unk6;
    u8 pad7[0x18 - 0x7];
    s8 unk18;
    u8 pad19[0x1E - 0x19];
    s16 unk1E;
} MmpBridgePlacement;

extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();

extern f32 timeDelta;

/*
 * --INFO--
 *
 * Function: pressureswitchfb_update
 * EN v1.0 Address: 0x8017ADB4
 * EN v1.0 Size: 1540b
 * EN v1.1 Address: 0x8017B2F8
 * EN v1.1 Size: 1604b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

extern int* objFindTexture(int* obj, int a, int b);
extern u32 GameBit_Get(int eventId);

/*
 * --INFO--
 *
 * Function: FUN_8017b3bc
 * EN v1.0 Address: 0x8017B3BC
 * EN v1.0 Size: 768b
 * EN v1.1 Address: 0x8017BB20
 * EN v1.1 Size: 796b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_8017b6bc
 * EN v1.0 Address: 0x8017B6BC
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x8017BE3C
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_8017b6dc
 * EN v1.0 Address: 0x8017B6DC
 * EN v1.0 Size: 204b
 * EN v1.1 Address: 0x8017BE60
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_8017b7a8
 * EN v1.0 Address: 0x8017B7A8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8017BF24
 * EN v1.1 Size: 464b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_8017b7ac
 * EN v1.0 Address: 0x8017B7AC
 * EN v1.0 Size: 172b
 * EN v1.1 Address: 0x8017C0F4
 * EN v1.1 Size: 192b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/* Trivial 4b 0-arg blr leaves. */
void mmp_bridge_free(void)
{
}

void mmp_bridge_render(void)
{
}

void mmp_bridge_hitDetect(void)
{
}

void mmp_bridge_release(void)
{
}

void mmp_bridge_initialise(void)
{
}

extern f32 lbl_803E3778;
__declspec(section ".sdata") extern char lbl_803DBD90[];
extern void fn_80137948(char* fmt, ...);

/* 8b "li r3, N; blr" returners. */
int mmp_bridge_getExtraSize(void) { return 0x0; }
int mmp_bridge_getObjectTypeId(void) { return 0x0; }
int doorlock_getExtraSize(void);

/* render-with-fn(lbl) (no visibility check). */

/* ObjGroup_RemoveObject(x, N) wrappers. */

void mmp_bridge_init(int* obj)
{
    int* state = *(int**)&((GameObject*)obj)->anim.placementData;
    int* tex = objFindTexture(obj, 0, 0);
    if (tex != NULL)
    {
        *(s16*)((char*)tex + 8) = 0x800;
    }
    *(s16*)obj = (s16)(((MmpBridgePlacement*)state)->unk18 << 8);
    ((GameObject*)obj)->objectFlags |= 0x6000;
    ObjHits_DisableObject((int)obj);
    if (GameBit_Get(((MmpBridgePlacement*)state)->unk1E) != 0)
    {
        ObjHits_EnableObject((int)obj);
    }
}

extern f32 lbl_803E3798;

void mmp_bridge_update(int* obj)
{
    int* tex;
    int frame;

    if (GameBit_Get(*(s16*)((char*)obj[0x4c / 4] + 0x1e)) != 0)
    {
        tex = objFindTexture(obj, 0, 0);
        if (tex != NULL)
        {
            frame = *(s16*)((char*)tex + 8) + ((int)timeDelta << 3);
            *(s16*)((char*)tex + 8) = (s16)frame;
            frame = *(s16*)((char*)tex + 8) + ((int)timeDelta << 3);
            if (frame >= 0x131f)
            {
                *(s16*)((char*)tex + 8) = 0x131f;
            }
            fn_80137948(lbl_803DBD90, (int)*(s16*)((char*)tex + 8));
        }
        ObjHits_EnableObject((int)obj);
    }
}

extern int Sfx_IsPlayingFromObject(int obj, int sfxId);

/*
 * --INFO--
 *
 * Function: Door_SeqFn
 * EN v1.0 Address: 0x8017B5C8
 * EN v1.0 Size: 788b
 */

/*
 * --INFO--
 *
 * Function: Lock_DoorLock_SeqFn
 * EN v1.0 Address: 0x8017BCF8
 * EN v1.0 Size: 180b
 */

/*
 * --INFO--
 *
 * Function: doorlock_update
 * EN v1.0 Address: 0x8017BE28
 * EN v1.0 Size: 848b
 */

/* segment pragma-stack balance (re-split): */

#include "main/dll/alphaanim.h"
#include "main/game_object.h"
#include "main/objanim_internal.h"
#include "main/objseq.h"

extern uint GameBit_Get(int eventId);

/*
 * --INFO--
 *
 * Function: doorlock_init
 * EN v1.0 Address: 0x8017C178
 * EN v1.0 Size: 184b
 * EN v1.1 Address: 0x8017C250
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_8017c5c4
 * EN v1.0 Address: 0x8017C5C4
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x8017C7EC
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_8017c608
 * EN v1.0 Address: 0x8017C608
 * EN v1.0 Size: 456b
 * EN v1.1 Address: 0x8017C82C
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: seqObject_free
 * EN v1.0 Address: 0x8017C7D0
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x8017C960
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: seqObject_render
 * EN v1.0 Address: 0x8017C7F4
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8017C984
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: seqObject_update
 * EN v1.0 Address: 0x8017C81C
 * EN v1.0 Size: 548b
 * EN v1.1 Address: 0x8017C9B4
 * EN v1.1 Size: 592b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: seqObject_init
 * EN v1.0 Address: 0x8017CA40
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8017CC04
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: seqObj2_free
 * EN v1.0 Address: 0x8017CAF4
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x8017CDE4
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: seqObj2_update
 * EN v1.0 Address: 0x8017CB18
 * EN v1.0 Size: 460b
 * EN v1.1 Address: 0x8017CE10
 * EN v1.1 Size: 596b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: seqObj2_init
 * EN v1.0 Address: 0x8017CCE4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8017D064
 * EN v1.1 Size: 200b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/* Trivial 4b 0-arg blr leaves. */

/* 8b "li r3, N; blr" returners. */

/* render-with-objRenderFn_8003b8f4 pattern. */

/* ObjGroup_RemoveObject(x, N) wrappers. */

/* Drift-recovery: add new fns with v1.0 names. */

/* immultiseq_SeqFn: seqobj2 advance-state predicate. If obj has a trigger id
 * (-1 sentinel skips), peek at the next state slot in def[0x20+n*2], read
 * its GameBit, compare against the def[0x30] mask bit for that slot, and
 * if the polarity flips (GameBit != mask bit) end the current sequence.
 * Always latches state[1] bit 0 before returning 0. */
