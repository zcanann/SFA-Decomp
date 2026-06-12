#include "main/dll/paymentkiosk.h"
#include "main/dll/DB/DBrockfall.h"
#include "main/dll/VF/platform1.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"
#include "main/objanim_internal.h"
#include "main/objseq.h"

extern uint FUN_80006c00();
extern undefined4 FUN_80006c88();
extern undefined8 FUN_80017484();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern int FUN_80017a98();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_800400b0();
extern undefined4 FUN_80080eec();
extern undefined4 FUN_8011e800();
extern int FUN_80286838();
extern undefined4 FUN_80286884();
extern int FUN_80294d20();
extern undefined4 FUN_80294d28();
extern uint countLeadingZeros();

extern undefined4 DAT_80328730;
extern undefined4 DAT_80328734;
extern ObjectTriggerInterface** gObjectTriggerInterface;
extern MapEventInterface** gMapEventInterface;
extern undefined4 DAT_803de890;
extern f32 lbl_803E6310;
extern EffectInterface** gPartfxInterface;
extern f32 lbl_803E56B0;
extern f32 lbl_803E56B4;

/*
 * --INFO--
 *
 * Function: paymentkiosk_init
 * EN v1.0 Address: 0x801DF43C
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x801DF458
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void paymentkiosk_init(int obj, PaymentKioskMapData* initData);

typedef struct FEseqobjectEffectParams
{
    s16 xRot;
    s16 yRot;
    s16 variant;
    s16 pad06;
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} FEseqobjectEffectParams;

#pragma scheduling on
#pragma peephole on
static void FEseqobject_spawnEffect(int obj, FEseqobjectEffectParams* params)
{
    (*gPartfxInterface)->spawnObject((void*)obj, 0x85, params, 1, -1, NULL);
}

static int FEseqobject_findControlObject(void)
{
    int count;
    int i;
    int found;
    int* objects;

    objects = (int*)ObjGroup_GetObjects(3, &count);
    found = 0;
    for (i = 0; i < count; i++)
    {
        int obj = objects[i];
        if (((GameObject*)obj)->anim.seqId == 0xf7)
        {
            found = obj;
            i = count;
        }
    }
    return found;
}

#pragma scheduling off
#pragma peephole off
int FEseqobject_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    FEseqobjectEffectParams effect;
    register int self = obj;
    int i;
    int msg;
    uint sender;
    uint param;
    int controlObj;
    f32 zero;
    f32 one;

    zero = lbl_803E56B0;
    one = lbl_803E56B4;
    controlObj = 0;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        effect.x = zero;
        effect.y = zero;
        effect.z = zero;
        effect.scale = one;
        effect.yRot = 0;
        effect.xRot = 0;
        effect.variant = 0;

        switch (animUpdate->eventIds[i])
        {
        case 1:
            GameBit_Set(0x75, 1);
            break;
        case 2:
            effect.variant = 0;
            FEseqobject_spawnEffect(self, &effect);
            break;
        case 3:
            effect.variant = 1;
            FEseqobject_spawnEffect(self, &effect);
            break;
        case 4:
            effect.variant = 2;
            FEseqobject_spawnEffect(self, &effect);
            break;
        case 5:
            effect.variant = 3;
            FEseqobject_spawnEffect(self, &effect);
            break;
        case 6:
            effect.variant = 4;
            FEseqobject_spawnEffect(self, &effect);
            break;
        }
    }

    while (ObjMsg_Pop((void*)self, (uint*)&msg, &sender, &param) != 0)
    {
        if ((((u8*)animUpdate)[0x90] & 0x80) == 0)
        {
            if (msg == 0xf000b)
            {
                controlObj = FEseqobject_findControlObject();
                if (controlObj != 0)
                {
                    ObjMsg_SendToObject((void*)controlObj, 0x130001, (void*)self, 0);
                }
            }
            else if (msg == 0xf000c)
            {
                controlObj = FEseqobject_findControlObject();
                if (controlObj != 0)
                {
                    ObjMsg_SendToObject((void*)controlObj, 0x130002, (void*)self, 0);
                }
            }
            else if (msg == 0xf000d)
            {
                controlObj = FEseqobject_findControlObject();
                if (controlObj != 0)
                {
                    ObjMsg_SendToObject((void*)controlObj, 0x130003, (void*)self, 0);
                }
            }
        }
    }
    animUpdate->sequenceEventActive = 0;
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801df45c
 * EN v1.0 Address: 0x801DF45C
 * EN v1.0 Size: 576b
 * EN v1.1 Address: 0x801DF480
 * EN v1.1 Size: 640b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801df784
 * EN v1.0 Address: 0x801DF784
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801DF7DC
 * EN v1.1 Size: 316b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801df788
 * EN v1.0 Address: 0x801DF788
 * EN v1.0 Size: 252b
 * EN v1.1 Address: 0x801DF918
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/* Trivial 4b 0-arg blr leaves. */
#pragma scheduling off
#pragma peephole off
void paymentkiosk_release(void);

void paymentkiosk_initialise(void);

void FEseqobject_free(void)
{
}

void FEseqobject_hitDetect(void)
{
}

void FEseqobject_release(void)
{
}

void FEseqobject_initialise(void)
{
}

void FElevControl_free(void)
{
}

void FElevControl_hitDetect(void)
{
}

void FElevControl_update(void)
{
}

void FElevControl_release(void)
{
}

void FElevControl_initialise(void)
{
}

void dll_144_free(void)
{
}

void dll_144_hitDetect(void)
{
}

void dll_144_update(void)
{
}

void dll_144_release(void)
{
}

void dll_144_initialise(void)
{
}

/* 8b "li r3, N; blr" returners. */
int FEseqobject_getExtraSize(void) { return 0x1; }
int FEseqobject_getObjectTypeId(void) { return 0x0; }
int FElevControl_getExtraSize(void) { return 0x0; }
int FElevControl_getObjectTypeId(void) { return 0x0; }
int dll_144_getExtraSize(void) { return 0x0; }
int dll_144_getObjectTypeId(void) { return 0x0; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E56B8;
extern f32 lbl_803E56C0;

void FEseqobject_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E56B4);
}

void FElevControl_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E56B8);
}

void dll_144_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E56C0);
}

/* call(x, N) wrappers. */
void FElevControl_init(int x) { ObjMsg_AllocQueue(x, 0x2); }

/*
 * Function: FEseqobject_init
 * EN v1.0 Address: 0x801DF8F4
 * EN v1.0 Size: 56b
 */
void FEseqobject_init(int obj)
{
    *(short*)obj = 0;
    ((GameObject*)obj)->animEventCallback = (void*)FEseqobject_SeqFn;
    ObjMsg_AllocQueue((void*)obj, 0xa);
}

/*
 * Function: FEseqobject_update
 * EN v1.0 Address: 0x801DF894
 * EN v1.0 Size: 96b
 */
void FEseqobject_update(int obj)
{
    register int self = obj;
    *(short*)self = 0x2000;
    if (GameBit_Get(0x75) == 0)
    {
        (*gObjectTriggerInterface)->runSequence(0, (void*)self, -1);
    }
}

/*
 * Function: dll_144_SeqFn
 * EN v1.0 Address: 0x801DF9AC
 * EN v1.0 Size: 16b
 */
int dll_144_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    animUpdate->sequenceEventActive = 0;
    return 0;
}

/*
 * Function: dll_144_init
 * EN v1.0 Address: 0x801DFA08
 * EN v1.0 Size: 24b
 */
void dll_144_init(int obj)
{
    *(short*)obj = 0;
    ((GameObject*)obj)->animEventCallback = (void*)dll_144_SeqFn;
}

ObjectDescriptor gFElevControlObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)FElevControl_initialise,
    (ObjectDescriptorCallback)FElevControl_release,
    0,
    (ObjectDescriptorCallback)FElevControl_init,
    (ObjectDescriptorCallback)FElevControl_update,
    (ObjectDescriptorCallback)FElevControl_hitDetect,
    (ObjectDescriptorCallback)FElevControl_render,
    (ObjectDescriptorCallback)FElevControl_free,
    (ObjectDescriptorCallback)FElevControl_getObjectTypeId,
    FElevControl_getExtraSize,
};
