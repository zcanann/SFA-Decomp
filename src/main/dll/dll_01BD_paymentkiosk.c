#include "main/dll/paymentkiosk.h"
#include "main/dll/feseqobjecteffectparams_struct.h"
#include "main/game_object.h"
#include "main/dll/VF/platform1.h"
#include "main/objseq.h"

extern u8* Obj_GetPlayerObject(void);

void paymentkiosk_free(void)
{
}

void paymentkiosk_hitDetect(void)
{
}

int sc_totemstrength_getExtraSize(void);
int paymentkiosk_getExtraSize(void) { return 0x3; }
int paymentkiosk_getObjectTypeId(void) { return 0x1; }

void paymentkiosk_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }

void sc_totemstrength_init(int* obj);

extern u32 GameBit_Get(int eventId);
extern u32 getButtonsJustPressed(int pad);
extern int playerGetMoney(int player);
extern void playerAddMoney(int player, int amount);
extern void gameTextSetColor(int r, int g, int b, int a);
extern void gameTextShow(int id);
extern void objRenderFn_80041018(int obj);

typedef struct KioskTextPair
{
    int approachText;
    int poorText;
} KioskTextPair;

extern KioskTextPair lbl_80327AF0[];

/* EN v1.0 0x801DF110  size: 220b  PaymentKiosk_testEvent. */
u32 PaymentKiosk_testEvent(int obj, int p2, int ev)
{
    PaymentKioskMapData* setup = (PaymentKioskMapData*)((GameObject*)obj)->anim.placementData;
    PaymentKioskState* st = ((GameObject*)obj)->extra;
    int player;
    u32 r;

    player = (int)Obj_GetPlayerObject();
    r = getButtonsJustPressed(0);
    if ((r & 0x100) == 0)
    {
        r = 0;
    }
    else
    {
        st->promptState = 0;
        if (playerGetMoney(player) >= setup->price)
        {
            r = 1;
            st->promptState = 0;
        }
        else
        {
            r = 0;
            st->promptState = 2;
        }
        switch (ev)
        {
        case 0x14:
            r = !(1 - r);
            break;
        case 0x15:
            r = !r;
            break;
        default:
            r = 0;
            break;
        }
    }
    return r;
}

/* EN v1.0 0x801DF1EC  size: 280b  PaymentKiosk_SeqFn. */
int PaymentKiosk_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    extern void GameBit_Set(int eventId, int value);
    PaymentKioskState* st = ((GameObject*)obj)->extra;
    PaymentKioskMapData* setup = (PaymentKioskMapData*)((GameObject*)obj)->anim.placementData;
    int player;
    int i;
    u8 ev;
    player = (int)Obj_GetPlayerObject();
    animUpdate->conditionCallback = (ObjAnimSequenceConditionCallback)PaymentKiosk_testEvent;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        ev = animUpdate->eventIds[i];
        switch (ev)
        {
        case 2:
            GameBit_Set(setup->gameBit, 1);
            playerAddMoney(player, -setup->price);
            st->payState = 2;
            break;
        case 1:
            st->promptState = 1;
            break;
        }
    }
    gameTextSetColor(0xff, 0xff, 0xff, 0xff);
    if (st->promptState == 1)
    {
        gameTextShow(lbl_80327AF0[st->textVariant].approachText);
    }
    else if (st->promptState == 2)
    {
        gameTextShow(lbl_80327AF0[st->textVariant].poorText);
    }
    return 0;
}

/* EN v1.0 0x801DF328  size: 276b  paymentkiosk_update. */
void paymentkiosk_update(int obj)
{
    PaymentKioskState* st = ((GameObject*)obj)->extra;
    PaymentKioskMapData* setup = (PaymentKioskMapData*)((GameObject*)obj)->anim.placementData;
    u8 b = st->payState;

    switch (b)
    {
    case 0:
        if (setup->gameBit != -1 && GameBit_Get(setup->gameBit) != 0)
        {
            st->payState = 2;
        }
        else
        {
            st->payState = 1;
        }
        break;
    case 1:
        if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 1) != 0)
        {
            (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
        }
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~8);
        break;
    case 2:
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 8);
        break;
    }
    st->promptState = 0;
    if ((((ObjAnimComponent*)obj)->modelInstance->flags & 1) != 0 &&
        ((ObjAnimComponent*)obj)->hitVolumeTransforms != NULL)
    {
        objRenderFn_80041018(obj);
    }
}

#include "main/dll/paymentkiosk.h"
#include "main/dll/DB/DBrockfall.h"
#include "main/dll/VF/platform1.h"
#include "main/game_object.h"
#include "main/objseq.h"

extern uint GameBit_Get(int eventId);

void paymentkiosk_init(int obj, PaymentKioskMapData* initData)
{
    register int self = obj;
    register PaymentKioskMapData* setup = initData;
    register PaymentKioskState* state = ((GameObject*)self)->extra;
    u32 secondaryFlag;

    ((GameObject*)self)->animEventCallback = (void*)PaymentKiosk_SeqFn;
    *(short*)self = (short)((int)setup->facingByte << 8);
    state->payState = 0;
    ((GameObject*)self)->objectFlags = (u16)(((GameObject*)self)->objectFlags | 0x6000);
    *(u8*)&((GameObject*)self)->anim.resetHitboxMode =
        (u8)(*(u8*)&((GameObject*)self)->anim.resetHitboxMode | 0x8);
    secondaryFlag = (((GameObject*)self)->anim.seqId == PAYMENT_KIOSK_WELL_TEXT_SEQ_ID) ? 1 : 0;
    state->textVariant = (u8)secondaryFlag;
}

static void FEseqobject_spawnEffect(int obj, FEseqobjectEffectParams* params);

static int FEseqobject_findControlObject(void);

void paymentkiosk_release(void)
{
}

void paymentkiosk_initialise(void)
{
}

void dll_144_free(void);

/*
 * Function: FEseqobject_init
 * EN v1.0 Address: 0x801DF8F4
 * EN v1.0 Size: 56b
 */

/*
 * Function: FEseqobject_update
 * EN v1.0 Address: 0x801DF894
 * EN v1.0 Size: 96b
 */

/*
 * Function: dll_144_SeqFn
 * EN v1.0 Address: 0x801DF9AC
 * EN v1.0 Size: 16b
 */

/*
 * Function: dll_144_init
 * EN v1.0 Address: 0x801DFA08
 * EN v1.0 Size: 24b
 */

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
