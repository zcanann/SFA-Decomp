#include "main/dll/DR/DRearthwalk.h"
#include "main/dll/sclevelcontrolprocessanimeventsstate_struct.h"
#include "main/dll/sclevelcontrolstate_types.h"
#include "main/audio/sfx_ids.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/objhits.h"
#include "main/dll/CR/CRsnowbike.h"
#include "main/mapEventTypes.h"
#include "main/screen_transition.h"
#include "global.h"

extern f32 lbl_803DDC00;

STATIC_ASSERT(sizeof(ScLevelControlState) == 0x24);
extern undefined4 FUN_800067c0();
extern undefined4 FUN_80006824();
extern byte FUN_80006b44();
extern undefined4 FUN_80006b4c();
extern undefined4 FUN_80006b50();
extern undefined4 FUN_80006b54();
extern uint FUN_80017690();
extern undefined8 FUN_80017698();
extern int FUN_80017a98();
extern undefined4 ObjHitbox_SetCapsuleBounds();
extern f32 lbl_803E61E8;
extern f32 lbl_803E5540;
extern f32 lbl_803E5544;
extern f32 lbl_803E5548;

void sh_emptytumblew_update(int obj)
{
    ObjHits_PollPriorityHitEffectWithCooldown(obj, 8, 0xff, 0xff, 0x78, 0x280,
                                              &lbl_803DDC00);
}

/* TODO stubs to align function set with v1.0 asm. Bodies are large
 * state-machine and animation logic; filling them is a follow-up task. */

void sh_emptytumblew_init(s16* p1, int p2)
{
    f32 fv;

    ((GameObject*)p1)->anim.rotZ = (*(u8*)(p2 + 0x18) - 0x7f) * 0x80;
    ((GameObject*)p1)->anim.rotY = (*(u8*)(p2 + 0x19) - 0x7f) * 0x80;
    ((GameObject*)p1)->anim.rotX = *(u8*)(p2 + 0x1a) << 8;
    ((GameObject*)p1)->anim.rootMotionScale = *(f32*)(p2 + 0x1c);
    fv = ((GameObject*)p1)->anim.rootMotionScale;
    ObjHitbox_SetCapsuleBounds(p1, (int)(lbl_803E5540 * fv), (int)(lbl_803E5544 * fv), (int)(lbl_803E5548 * fv));
    ((GameObject*)p1)->objectFlags |= 0x4000;
}

#pragma scheduling on
#pragma peephole on
undefined4 sc_levelcontrol_processAnimEvents(int obj, undefined4 arg2, ObjAnimUpdateState* animUpdate)
{
    byte bval;
    byte eventId;
    uint bitVal;
    int i;
    int state;

    state = *(int*)&((GameObject*)obj)->extra;
    animUpdate->sequenceEventActive = 0;
    for (i = 0; i < (int)(uint)animUpdate->eventCount; i = i + 1)
    {
        eventId = animUpdate->eventIds[i];
        if (eventId == 2)
        {
            sc_levelcontrol_setAnimEventState(obj, 5);
        }
        else if (eventId < 2)
        {
            if (eventId != 0)
            {
                sc_levelcontrol_setAnimEventState(obj, 7);
            }
        }
        else if (eventId < 4)
        {
            ((ScLevelControlState*)state)->flags1F = ((ScLevelControlState*)state)->flags1F | 2;
        }
    }
    ((ScLevelControlState*)state)->flags1F = ((ScLevelControlState*)state)->flags1F | 1;
    FUN_80017698(0x60f, 0);
    i = *(int*)&((GameObject*)obj)->extra;
    FUN_80017a98();
    if (((ScLevelcontrolProcessAnimEventsState*)i)->unk1D == '\x05')
    {
        FUN_80017698(0x60f, 1);
        bval = FUN_80006b44();
        if (bval != 0)
        {
            bitVal = FUN_80017690(0x7a);
            if (bitVal != 0)
            {
                FUN_80017698(0x85, 1);
            }
            ((ScLevelControlState*)i)->timer10 = lbl_803E61E8;
            ((ScLevelControlState*)i)->mode = 0;
            FUN_80006824(0, SFXsp_skeep_mumb1);
            FUN_800067c0((int*)0xef, 0);
        }
    }
    return 0;
}

void sc_levelcontrol_setAnimEventState(int obj, undefined value)
{
    char mode;
    int state;

    state = *(int*)&((GameObject*)obj)->extra;
    ((ScLevelControlState*)state)->mode = value;
    mode = *(char*)&((ScLevelControlState*)state)->mode;
    if (mode == '\x02')
    {
        ((ScLevelControlState*)state)->mode = 0;
    }
    else if (mode == '\x05')
    {
        FUN_80017698(0x2b8, 1);
        FUN_80017698(0x4bd, 0);
        FUN_80017698(0x85, 0);
        FUN_80006b54(0x1d, 0x96);
        FUN_800067c0((int*)0xef, 1);
        FUN_80006b50();
    }
    else if (mode == '\x03')
    {
        FUN_80006b54(0x1d, 0x3c);
        ((ScLevelControlState*)state)->mode = 0;
        FUN_800067c0((int*)0xc7, 1);
        FUN_80006b50();
    }
    else if (mode == '\x06')
    {
        FUN_800067c0((int*)0xef, 0);
        ((ScLevelControlState*)state)->mode = 0;
        ((ScLevelControlState*)state)->fadeTimer = lbl_803E61E8;
        FUN_80006b4c();
    }
    else if (mode == '\x04')
    {
        ((ScLevelControlState*)state)->mode = 0;
        FUN_800067c0((int*)0xc7, 0);
        FUN_80006b4c();
    }
    return;
}

void sc_levelcontrol_hitDetect(void);

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset

/* EN v1.0 0x801DB3A8  size: 2732b  SnowBike Race level controller per-frame
 * driver: replays the env-fx set on map (re)entry, latches the race
 * GameBits, runs the two race countdown timers, eases the heavy fog level,
 * tracks the totem combo code (bits 0x7d..0x7f), and keeps the area music
 * in sync with the Thorntail animation state. */
