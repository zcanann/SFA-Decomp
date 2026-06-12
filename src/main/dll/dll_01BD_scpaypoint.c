#include "main/dll/paymentkiosk.h"
#include "main/camera_interface.h"
#include "main/game_object.h"
#include "main/dll/VF/platform1.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/screen_transition.h"

extern undefined4 Sfx_SetObjectSfxVolume();
extern undefined4 Sfx_PlayFromObject();
extern undefined4 Sfx_KeepAliveLoopedObjectSound();
extern uint randomGetRange();
extern int ObjList_GetObjects();
extern undefined4 setAButtonIcon();
extern u8* Obj_GetPlayerObject(void);


#define PLATFORM1_ANCHOR_SEQ_ID 0x3ff
#define PLATFORM1_PEER_SEQ_ID 0x282
#define PLATFORM1_PLAYER_PULL_MOVE_ID 0x401
#define PLATFORM1_IDLE_PULL_MOVE_ID 0

#define PLATFORM1_LOOP_SFX_ID 0x3af
#define PLATFORM1_PLAYER_SFX_ID 0x13a
#define PLATFORM1_PLATFORM_SFX_ID 0x4a3

/*
 * --INFO--
 *
 * Function: platform1_control
 * EN v1.0 Address: 0x801DE430
 * EN v1.0 Size: 3368b
 * EN v1.1 Address: 0x801DEA20
 * EN v1.1 Size: 2596b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern u32 getButtonsJustPressedIfNotBusy(int pad);
extern int isGameTimerDisabled(void);
extern f64 fn_8001461C(void);
extern void fn_801DE320(void* dst, int val);
extern int ObjSeq_takeXrotChanged(int index);
extern void hudFn_8011f38c(int n);
extern ObjectTriggerInterface** gObjectTriggerInterface;
extern ScreenTransitionInterface** gScreenTransitionInterface;
extern int lbl_803DDC10;
extern int lbl_803DC070;
extern u8 framesThisStep;
extern f32 timeDelta;
extern f32 lbl_803E5668;
extern f32 lbl_803E566C;
extern f32 lbl_803E5670;
extern f32 lbl_803E5674;
extern f32 lbl_803E5678;
extern f32 lbl_803E567C;
extern f32 lbl_803E5680;
extern f32 lbl_803E5684;
extern f32 lbl_803E5688;
extern f32 lbl_803E568C;
extern f32 lbl_803E5690;
extern f32 lbl_803E5694;
extern f32 lbl_803E5698;
extern f32 lbl_803E569C;
extern f32 lbl_803E56A0;
extern f32 lbl_803E56A4;

/* EN v1.0 0x801DE430  size: 2596b  platform1_control: tug-of-war rope
 * minigame. Resolves the anchor object, applies sequence events, then per
 * frame works the rope position from A-press mashing, runs both pull anims
 * and grunt/creak sfx, and ends the game through the screen transition
 * when either side wins. */
int platform1_control(int obj, int unused, ObjAnimUpdateState* animUpdate);


/* Trivial 4b 0-arg blr leaves. */
void sc_totemstrength_free(void);

void sc_totemstrength_hitDetect(void);

void sc_totemstrength_release(void);

void sc_totemstrength_initialise(void);

void paymentkiosk_free(void)
{
}

void paymentkiosk_hitDetect(void)
{
}

/* 8b "li r3, N; blr" returners. */
int sc_totemstrength_getExtraSize(void);
int sc_totemstrength_getObjectTypeId(void);
int paymentkiosk_getExtraSize(void) { return 0x3; }
int paymentkiosk_getObjectTypeId(void) { return 0x1; }

/* render-with-fn(lbl) (no visibility check). */
extern void objRenderFn_8003b8f4(f32);
void sc_totemstrength_render(void);
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

/* EN v1.0 0x801DEE90  size: 548b  sc_totemstrength_update: drive the
 * tug-of-war intro/outro sequencing once map event 0xe reaches state 6. */
void sc_totemstrength_update(u8* obj);

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
    if ((((ObjAnimComponent*)obj)->modelInstance->flags & 1) != 0 && *(void**)(obj + 0x74) != NULL)
    {
        objRenderFn_80041018(obj);
    }
}

/* === moved from main/dll/DB/DBrockfall.c [801DF43C-801DF4AC) (TU re-split, docs/boundary_audit.md) === */
#include "main/dll/paymentkiosk.h"
#include "main/dll/DB/DBrockfall.h"
#include "main/dll/VF/platform1.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"
#include "main/objanim_internal.h"
#include "main/objseq.h"

extern uint FUN_80006c00();
extern uint GameBit_Get(int eventId);


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
static void FEseqobject_spawnEffect(int obj, FEseqobjectEffectParams* params);

static int FEseqobject_findControlObject(void);

#pragma scheduling off
#pragma peephole off

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
void paymentkiosk_release(void)
{
}

void paymentkiosk_initialise(void)
{
}










void dll_144_free(void);





/* 8b "li r3, N; blr" returners. */

/* render-with-objRenderFn_8003b8f4 pattern. */




/* call(x, N) wrappers. */

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
