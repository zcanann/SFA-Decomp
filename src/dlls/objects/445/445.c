/*
 * DLL 445 (0x1BD) - the shared SC_paypoint and SPWell payment-kiosk
 * implementation.
 *
 * The kiosk gates a sequence (and its game bit) behind the player having
 * enough money. On interact (A-button / button 0x100) the test-event
 * callback checks playerGetMoney against the placement price; condition
 * events 0x14/0x15 select the affordable/unaffordable branch. When the
 * sequence pays out it sets the placement game bit, deducts the price,
 * and latches payState to "paid" (2). gameTextShow displays approach
 * (promptState 1) or "cannot afford" (promptState 2) text from the unit's
 * two-row text table. Sequence id 0x476 selects the SPWell row.
 */
#include "dlls/objects/445.h"

#include "dolphin/pad.h"
#include "main/gamebits_api.h"
#include "main/objseq.h"
#include "sys/objects.h"
#include "main/dll/player_api.h"
#include "main/gametext_color_api.h"
#include "main/gametext_show_api.h"
#include "main/objprint_render_api.h"
#include "main/pad.h"

typedef struct PaymentKioskTextPair {
    int approachTextId;
    int cannotAffordTextId;
} PaymentKioskTextPair;

STATIC_ASSERT(offsetof(PaymentKioskTextPair, approachTextId) == 0x00);
STATIC_ASSERT(offsetof(PaymentKioskTextPair, cannotAffordTextId) == 0x04);
STATIC_ASSERT(sizeof(PaymentKioskTextPair) == 0x08);

#define PAYMENT_KIOSK_TEXT_VARIANT_COUNT 2

#define PAYMENT_KIOSK_PAYPOINT_APPROACH_TEXT_ID      0x312
#define PAYMENT_KIOSK_PAYPOINT_CANNOT_AFFORD_TEXT_ID 0x34A
#define PAYMENT_KIOSK_SP_WELL_APPROACH_TEXT_ID       0x527
#define PAYMENT_KIOSK_TEXT_ID_NONE                   -1

/* condition-event opcodes resolved by PaymentKiosk_testEvent */
enum {
    PAYMENT_KIOSK_COND_CAN_AFFORD = 0x14,
    PAYMENT_KIOSK_COND_CANNOT_AFFORD = 0x15
};

/* sequence-event opcodes consumed by PaymentKiosk_SeqFn */
enum {
    PAYMENT_KIOSK_SEQEV_SHOW_PROMPT = 1,
    PAYMENT_KIOSK_SEQEV_PAY = 2
};

enum {
    PAYMENT_KIOSK_STATE_RESOLVE,
    PAYMENT_KIOSK_STATE_ACTIVE,
    PAYMENT_KIOSK_STATE_PAID
};

enum {
    PAYMENT_KIOSK_TEXT_VARIANT_PAYPOINT,
    PAYMENT_KIOSK_TEXT_VARIANT_SP_WELL
};

enum {
    PAYMENT_KIOSK_PROMPT_NONE,
    PAYMENT_KIOSK_PROMPT_APPROACH,
    PAYMENT_KIOSK_PROMPT_CANNOT_AFFORD
};

#define PAYMENT_KIOSK_SP_WELL_SEQUENCE_ID 0x476
#define PAYMENT_KIOSK_OBJECT_TYPE_ID      1
#define PAYMENT_KIOSK_NO_GAME_BIT         -1

PaymentKioskTextPair gPaymentKioskTextPairs[PAYMENT_KIOSK_TEXT_VARIANT_COUNT] = {
    {PAYMENT_KIOSK_PAYPOINT_APPROACH_TEXT_ID, PAYMENT_KIOSK_PAYPOINT_CANNOT_AFFORD_TEXT_ID},
    {PAYMENT_KIOSK_SP_WELL_APPROACH_TEXT_ID, PAYMENT_KIOSK_TEXT_ID_NONE},
};

STATIC_ASSERT(sizeof(gPaymentKioskTextPairs) == 0x10);

u32 PaymentKiosk_testEvent(GameObject* obj, int unused, int eventId) {
    const PaymentKioskPlacement* placement = (const PaymentKioskPlacement*)obj->anim.placementData;
    PaymentKioskState* state = obj->extra;
    GameObject* player;
    u32 result;

    (void)unused;

    player = Obj_GetPlayerObject();
    result = getButtonsJustPressed(0);
    if ((result & PAD_BUTTON_A) == 0) {
        result = 0;
    } else {
        state->promptState = PAYMENT_KIOSK_PROMPT_NONE;
        if (playerGetMoney(player) >= placement->price) {
            result = 1;
            state->promptState = PAYMENT_KIOSK_PROMPT_NONE;
        } else {
            result = 0;
            state->promptState = PAYMENT_KIOSK_PROMPT_CANNOT_AFFORD;
        }
        switch (eventId) {
        case PAYMENT_KIOSK_COND_CAN_AFFORD:
            result = !(1 - result);
            break;
        case PAYMENT_KIOSK_COND_CANNOT_AFFORD:
            result = !result;
            break;
        default:
            result = 0;
            break;
        }
    }
    return result;
}

int PaymentKiosk_SeqFn(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    PaymentKioskState* state = obj->extra;
    const PaymentKioskPlacement* placement = (const PaymentKioskPlacement*)obj->anim.placementData;
    GameObject* player;
    int eventIndex;
    u8 eventId;

    (void)unused;

    player = Obj_GetPlayerObject();
    animUpdate->conditionCallback = (ObjAnimSequenceConditionCallback)PaymentKiosk_testEvent;
    for (eventIndex = 0; eventIndex < animUpdate->eventCount; eventIndex++) {
        eventId = animUpdate->eventIds[eventIndex];
        switch (eventId) {
        case PAYMENT_KIOSK_SEQEV_PAY:
            mainSetBits(placement->gameBit, 1);
            playerAddMoney(player, -placement->price);
            state->payState = PAYMENT_KIOSK_STATE_PAID;
            break;
        case PAYMENT_KIOSK_SEQEV_SHOW_PROMPT:
            state->promptState = PAYMENT_KIOSK_PROMPT_APPROACH;
            break;
        }
    }
    gameTextSetColor(0xff, 0xff, 0xff, 0xff);
    if (state->promptState == PAYMENT_KIOSK_PROMPT_APPROACH) {
        gameTextShow(gPaymentKioskTextPairs[state->textVariant].approachTextId);
    } else if (state->promptState == PAYMENT_KIOSK_PROMPT_CANNOT_AFFORD) {
        gameTextShow(gPaymentKioskTextPairs[state->textVariant].cannotAffordTextId);
    }
    return 0;
}

int PaymentKiosk_getExtraSize(void) {
    return sizeof(PaymentKioskState);
}

int PaymentKiosk_getObjectTypeId(void) {
    return PAYMENT_KIOSK_OBJECT_TYPE_ID;
}

void PaymentKiosk_free(void) {
}

void PaymentKiosk_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    (void)obj;
    (void)renderArg2;
    (void)renderArg3;
    (void)renderArg4;
    (void)renderArg5;

    if (visible == 0) {
        return;
    }
}

void PaymentKiosk_hitDetect(void) {
}

void PaymentKiosk_update(GameObject* obj) {
    PaymentKioskState* state = obj->extra;
    const PaymentKioskPlacement* placement = (const PaymentKioskPlacement*)obj->anim.placementData;
    u8 payState = state->payState;

    switch (payState) {
    case PAYMENT_KIOSK_STATE_RESOLVE:
        if (placement->gameBit != PAYMENT_KIOSK_NO_GAME_BIT && mainGetBit(placement->gameBit) != 0) {
            state->payState = PAYMENT_KIOSK_STATE_PAID;
        } else {
            state->payState = PAYMENT_KIOSK_STATE_ACTIVE;
        }
        break;
    case PAYMENT_KIOSK_STATE_ACTIVE:
        if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0) {
            (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
        }
        obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
        break;
    case PAYMENT_KIOSK_STATE_PAID:
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        break;
    }
    state->promptState = PAYMENT_KIOSK_PROMPT_NONE;
    if ((obj->anim.modelInstance->flags & OBJDEF_FLAG_HAS_MODELS) != 0 && obj->anim.hitVolumeTransforms != NULL) {
        objUpdateHitVolumeTransforms(obj);
    }
}

void PaymentKiosk_init(GameObject* obj, const PaymentKioskPlacement* placement) {
    GameObject* self = obj;
    const PaymentKioskPlacement* setup = placement;
    PaymentKioskState* state = self->extra;
    u32 textVariant;

    self->animEventCallback = PaymentKiosk_SeqFn;
    self->anim.rotX = (s16)((s32)setup->rotXByte << 8);
    state->payState = PAYMENT_KIOSK_STATE_RESOLVE;
    self->objectFlags = (u16)(self->objectFlags | (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED));
    self->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    textVariant = (self->anim.romDefNo == PAYMENT_KIOSK_SP_WELL_SEQUENCE_ID) ? PAYMENT_KIOSK_TEXT_VARIANT_SP_WELL
                                                                          : PAYMENT_KIOSK_TEXT_VARIANT_PAYPOINT;
    state->textVariant = textVariant;
}

void PaymentKiosk_release(void) {
}

void PaymentKiosk_initialise(void) {
}

ObjectDescriptor gPaymentKioskObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)PaymentKiosk_initialise,
    (ObjectDescriptorCallback)PaymentKiosk_release,
    0,
    (ObjectDescriptorCallback)PaymentKiosk_init,
    (ObjectDescriptorCallback)PaymentKiosk_update,
    (ObjectDescriptorCallback)PaymentKiosk_hitDetect,
    (ObjectDescriptorCallback)PaymentKiosk_render,
    (ObjectDescriptorCallback)PaymentKiosk_free,
    (ObjectDescriptorCallback)PaymentKiosk_getObjectTypeId,
    PaymentKiosk_getExtraSize,
};
