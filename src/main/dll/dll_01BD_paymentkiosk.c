/*
 * paymentkiosk (DLL 0x1BD) - a "pay to proceed" kiosk object.
 *
 * The kiosk gates a sequence (and its game bit) behind the player having
 * enough money. On interact (A-button / button 0x100) the test-event
 * callback checks playerGetMoney against the placement price; condition
 * events 0x14/0x15 select the affordable/unaffordable branch. When the
 * sequence pays out it sets the placement game bit, deducts the price,
 * and latches payState to "paid" (2). gameTextShow displays approach
 * (promptState 1) or "cannot afford" (promptState 2) text from
 * lbl_80327AF0, indexed by textVariant (set to 1 for the "well" text
 * sequence, seq id 0x476).
 *
 * The TU also defines gFElevControlObjDescriptor for the FElevControl
 * (front-end elevator control) object, whose callbacks live in DBrockfall.
 */
#include "main/dll/DB/DBrockfall.h"
#include "main/game_object.h"
#include "main/objseq.h"
#include "main/gamebits.h"
#include "main/pad.h"
#include "main/sfa_shared_decls.h"

#define PAD_BUTTON_A 0x100

extern int Obj_GetPlayerObject(void);
extern int playerGetMoney(int player);
extern void playerAddMoney(int obj, int amount);
extern void gameTextSetColor(u8 r, u8 g, u8 b, u8 a);

extern void objRenderFn_80041018(int obj);

typedef struct KioskTextPair
{
    int approachText;
    int poorText;
} KioskTextPair;

extern KioskTextPair lbl_80327AF0[];

/* condition-event opcodes resolved by PaymentKiosk_testEvent */
enum
{
    PAYMENT_KIOSK_COND_CAN_AFFORD = 0x14,
    PAYMENT_KIOSK_COND_CANNOT_AFFORD = 0x15
};

/* sequence-event opcodes consumed by PaymentKiosk_SeqFn */
enum
{
    PAYMENT_KIOSK_SEQEV_SHOW_PROMPT = 1,
    PAYMENT_KIOSK_SEQEV_PAY = 2
};

void paymentkiosk_free(void)
{
}

void paymentkiosk_hitDetect(void)
{
}

int paymentkiosk_getExtraSize(void) { return sizeof(PaymentKioskState); }
int paymentkiosk_getObjectTypeId(void) { return 0x1; }

void paymentkiosk_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible == 0)
    {
        return;
    }
}

/* EN v1.0 0x801DF110  size: 220b  PaymentKiosk_testEvent. */
u32 PaymentKiosk_testEvent(int obj, int p2, int ev)
{
    PaymentKioskMapData* setup = (PaymentKioskMapData*)((GameObject*)obj)->anim.placementData;
    PaymentKioskState* st = ((GameObject*)obj)->extra;
    int player;
    u32 r;

    player = Obj_GetPlayerObject();
    r = getButtonsJustPressed(0);
    if ((r & PAD_BUTTON_A) == 0)
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
        case PAYMENT_KIOSK_COND_CAN_AFFORD:
            r = !(1 - r);
            break;
        case PAYMENT_KIOSK_COND_CANNOT_AFFORD:
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
    PaymentKioskState* st = ((GameObject*)obj)->extra;
    PaymentKioskMapData* setup = (PaymentKioskMapData*)((GameObject*)obj)->anim.placementData;
    int player;
    int i;
    u8 ev;
    player = Obj_GetPlayerObject();
    animUpdate->conditionCallback = (ObjAnimSequenceConditionCallback)PaymentKiosk_testEvent;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        ev = animUpdate->eventIds[i];
        switch (ev)
        {
        case PAYMENT_KIOSK_SEQEV_PAY:
            GameBit_Set(setup->gameBit, 1);
            playerAddMoney(player, -setup->price);
            st->payState = PAYMENT_KIOSK_STATE_PAID;
            break;
        case PAYMENT_KIOSK_SEQEV_SHOW_PROMPT:
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
    u8 payState = st->payState;

    switch (payState)
    {
    case PAYMENT_KIOSK_STATE_RESOLVE:
        if (setup->gameBit != -1 && GameBit_Get(setup->gameBit) != 0)
        {
            st->payState = PAYMENT_KIOSK_STATE_PAID;
        }
        else
        {
            st->payState = PAYMENT_KIOSK_STATE_ACTIVE;
        }
        break;
    case PAYMENT_KIOSK_STATE_ACTIVE:
        if ((((GameObject*)obj)->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0)
        {
            (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
        }
        ((GameObject*)obj)->anim.resetHitboxFlags = (u8)(((GameObject*)obj)->anim.resetHitboxFlags & ~INTERACT_FLAG_DISABLED);
        break;
    case PAYMENT_KIOSK_STATE_PAID:
        ((GameObject*)obj)->anim.resetHitboxFlags = (u8)(((GameObject*)obj)->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED);
        break;
    }
    st->promptState = 0;
    if ((((GameObject*)obj)->anim.modelInstance->flags & 1) != 0 &&
        ((GameObject*)obj)->anim.hitVolumeTransforms != NULL)
    {
        objRenderFn_80041018(obj);
    }
}

void paymentkiosk_init(int obj, PaymentKioskMapData* initData)
{
    int self = obj;
    PaymentKioskMapData* setup = initData;
    PaymentKioskState* state = ((GameObject*)self)->extra;
    u32 secondaryFlag;

    ((GameObject*)self)->animEventCallback = PaymentKiosk_SeqFn;
    *(short*)self = (short)((int)setup->facingByte << 8);
    state->payState = PAYMENT_KIOSK_STATE_RESOLVE;
    ((GameObject*)self)->objectFlags = (u16)(((GameObject*)self)->objectFlags | 0x6000);
    ((GameObject*)self)->anim.resetHitboxFlags =
        (u8)(((GameObject*)self)->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED);
    secondaryFlag = (((GameObject*)self)->anim.seqId == PAYMENT_KIOSK_WELL_TEXT_SEQ_ID) ? 1 : 0;
    state->textVariant = secondaryFlag;
}

void paymentkiosk_release(void)
{
}

void paymentkiosk_initialise(void)
{
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
