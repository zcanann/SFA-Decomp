/*
 * SPShopKeepe (DLL 646) - the SnowHorn shopkeeper vendor character.
 *
 * The TU contains the shopkeeper's state handlers, its object-sequence
 * callbacks, and the shopkeeper object implementation.
 */
#include "main/audio/sfx_play_api.h"
#include "main/dll/baddie_state.h"
#include "main/dll/player_api.h"
#include "main/dll/tricky_api.h"
#include "main/gametext_show_api.h"
#include "main/track_dolphin_api.h"
#include "main/dll/dll_0004_dummy04.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/boneparticleeffect_interface.h"
#include "main/dll/shopkeeperstate_struct.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/mapEvent.h"
#include "main/model_engine.h"
#include "main/objanim.h"
#include "main/objhits.h"
#include "main/objprint_character_api.h"
#include "main/obj_trigger.h"
#include "game/objects/object_setup.h"
#include "main/dll/dll_002E_moveLib.h"
#include "sys/objects/lifecycle.h"
#include "sys/objects.h"
#include "main/objseq.h"
#include "main/objtexture.h"
#include "main/pad.h"
#include "main/player_control_interface.h"
#include "main/rcp_dolphin.h"
#include "main/screen_transition.h"
#include "main/objtype.h"
#include "main/vecmath.h"
#include "main/dll/SP/dll_0285_spshop.h"
#include "main/dll/SP/dll_0286_spshopkeeper.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.h"
#include "main/object_render.h"
#include "dlls/object_descriptor.h"
#include "main/game_timer_control_api.h"
#include "main/mapEventTypes.h"
#include "main/rcp_dolphin_api.h"

#define SHOPKEEPER_GAMEBIT_HAS_MONEY        0x61D
#define SHOPKEEPER_GAMEBIT_SCARAB_GAME_WON  0x624
#define SHOPKEEPER_GAMEBIT_SCARAB_GAME_LOST 0x625

#define SHOPKEEPER_ANIM_IDLE     0
#define SHOPKEEPER_ANIM_TRACKING 0x11
#define SHOPKEEPER_ANIM_ALERT    0x12

#define SHOPKEEPER_STATE_PUSH_IDLE       1
#define SHOPKEEPER_STATE_VENDOR_SEQUENCE 2
#define SHOPKEEPER_STATE_PUSH_TRACKING   4
#define SHOPKEEPER_STATE_SHOP_OPEN       6
#define SHOPKEEPER_STATE_CONTINUE        7
#define SHOPKEEPER_STATE_CURVE_A         1
#define SHOPKEEPER_STATE_CURVE_B         2

#define SHOPKEEPER_SFX_IDLE_ANIM   0x40D
#define SHOPKEEPER_SFX_PROMPT_TICK 0xF3

#define SHOPKEEPER_BUTTON_ACCEPT 0x100
#define SHOPKEEPER_BUTTON_CANCEL 0x200

#define SHOPKEEPER_PROMPT_ADJUST_PRICE   0x14
#define SHOPKEEPER_PROMPT_OFFER_ACCEPTED 0x15
#define SHOPKEEPER_PROMPT_OFFER_REFUSED  0x16
#define SHOPKEEPER_PROMPT_ADJUST_AMOUNT  0x17

#define SHOPKEEPER_ONES_TEXTURE_SLOT     8
#define SHOPKEEPER_TENS_TEXTURE_SLOT     7
#define SHOPKEEPER_HUNDREDS_TEXTURE_SLOT 6
#define SHOPKEEPER_DIGIT_TEXTURE_SHIFT   8
#define SHOPKEEPER_MAX_DIGIT             9
#define SHOPKEEPER_MAX_AMOUNT            10
#define SHOPKEEPER_MIN_AMOUNT            1
#define SHOPKEEPER_MAX_HAGGLE_COUNT      2

#define SHOPKEEPER_CURVE_NODE_TYPE_A 0xC

#define SHOPKEEPER_OBJFLAG_RENDERED           0x800
#define SHOPKEEPER_OBJFLAG_HITDETECT_DISABLED 0x2000

#define SHOPKEEPER_VENDOR_OBJGROUP 9

/* object type id of the scarab coins the shopkeeper scatters (DLL 0x287) */
#define OBJTYPE_SPSCARAB 1151

/* ShopkeeperState.flags9D4 bits */
enum
{
    SHOPKEEPER_FLAG_PURCHASED = 0x02, /* purchase event fired */
    SHOPKEEPER_FLAG_FACING = 0x04,    /* turn to face the player */
    SHOPKEEPER_FLAG_IDLE_ANIM = 0x08, /* a randomised idle animation is playing */
    SHOPKEEPER_FLAG_LEAVING = 0x10,   /* leaving / screen transition */
    SHOPKEEPER_FLAG_TICK = 0x20       /* per-frame tick effect this frame */
};

typedef struct RomCurveSearchPair
{
    u32 a;
    u32 b;
} RomCurveSearchPair;

/* rom-curve node record returned by gRomCurveInterface->getById; only the
 * fields touched here are named (full layout in dll_0015_curves.h, which this
 * TU can't include without an extern conflict). */
typedef struct ShopKeeperCurveNode
{
    u8 pad00[0x8];
    f32 x; /* 0x08 */
    f32 y; /* 0x0C */
    f32 z; /* 0x10 */
    u8 pad14[0x19 - 0x14];
    u8 type; /* 0x19 */
    u8 pad1A[0x2C - 0x1A];
    s8 rotZ; /* 0x2C (placement extension) */
} ShopKeeperCurveNode;
STATIC_ASSERT(offsetof(ShopKeeperCurveNode, x) == 0x8);
STATIC_ASSERT(offsetof(ShopKeeperCurveNode, y) == 0xc);
STATIC_ASSERT(offsetof(ShopKeeperCurveNode, z) == 0x10);
STATIC_ASSERT(offsetof(ShopKeeperCurveNode, type) == 0x19);
STATIC_ASSERT(offsetof(ShopKeeperCurveNode, rotZ) == 0x2c);

void ShopKeeper_spawnScarabs(GameObject* obj, ShopkeeperState* state, int count);
int ShopKeeper_getExtraSize(void);
int ShopKeeper_getObjectTypeId(void);
void ShopKeeper_free(GameObject* obj);
void ShopKeeper_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void ShopKeeper_hitDetect(void);
void ShopKeeper_update(GameObject* obj);
void ShopKeeper_init(GameObject* obj);
void ShopKeeper_release(void);
void ShopKeeper_initialise(void);

ObjectDescriptor gShopKeeperObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)ShopKeeper_initialise,
    (ObjectDescriptorCallback)ShopKeeper_release,
    0,
    (ObjectDescriptorCallback)ShopKeeper_init,
    (ObjectDescriptorCallback)ShopKeeper_update,
    (ObjectDescriptorCallback)ShopKeeper_hitDetect,
    (ObjectDescriptorCallback)ShopKeeper_render,
    (ObjectDescriptorCallback)ShopKeeper_free,
    (ObjectDescriptorCallback)ShopKeeper_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)ShopKeeper_getExtraSize,
};

const RomCurveSearchPair gShopKeeperCurveSearchKinds = {0xC, 0x1C};

void* gShopKeeperStateHandlers[8];

s16 gShopKeeperIdleAnimMoves[2] = {0x13, 0x11};
f32 gShopKeeperIdleAnimStepScales[2] = {0.01f, 0.0125f};

int ShopKeeper_defaultStateHandler(void)
{
    return 0;
}

int ShopKeeper_state7Handler(void)
{
    return 0;
}

int ShopKeeper_popQueuedState(GameObject* objHandle, BaddieState* baddie)
{
    GameObject* obj = objHandle;
    ShopkeeperState* state;
    f32 spawnParam;
    RingBufferQueue* stk;
    int nextState;

    state = obj->extra;
    spawnParam = 1.0f;

    if (baddie->moveJustStartedA != 0)
    {
        if ((obj->objectFlags & SHOPKEEPER_OBJFLAG_RENDERED) != 0)
        {
            (*gBoneParticleEffectInterface)->spawnEffect((void*)obj, 2031, &spawnParam, 80, NULL);
        }
    }

    state->opacity = 0;
    baddie->animSpeedA = 0.0f;
    if (state->opacity == 0)
    {
        stk = state->msgStack;
        nextState = 0;
        if (Stack_IsEmpty(stk) == 0)
        {
            Stack_Pop(stk, &nextState);
        }
        return nextState + 1;
    }
    return 0;
}

int ShopKeeper_moveToCurvePoint(GameObject* obj, BaddieState* baddie)
{
    ShopkeeperState* state;
    GameObject* playerObj;
    RingBufferQueue* stackHandle;
    ShopKeeperCurveNode* node;
    u32 head[2];
    int pushKindA;
    int pushKindB;
    int popOut;

    *(RomCurveSearchPair*)head = gShopKeeperCurveSearchKinds;
    playerObj = Obj_GetPlayerObject();
    state = obj->extra;

    if (baddie->moveJustStartedA != 0)
    {
        if (Stack_IsEmpty(state->msgStack) != 0)
        {
            RomCurveFindFn findFn = (*gRomCurveInterface)->find;
            int found = findFn(playerObj->anim.localPosX, playerObj->anim.localPosY,
                               playerObj->anim.localPosZ, (int*)head, 2, -1);

            if (found != -1)
            {
                node = (ShopKeeperCurveNode*)(*gRomCurveInterface)->getById(found);
                obj->anim.localPosX = node->x;
                obj->anim.localPosY = 6.0f + node->y;
                obj->anim.localPosZ = node->z;
                obj->anim.rotX = (s16)((s32)node->rotZ << 8);
                state->bobBaseY = 6.0f + node->y;
                state->bobPhase = 0;
                state->curveNodeType = node->type;
            }

            if ((s8)node->type == SHOPKEEPER_CURVE_NODE_TYPE_A)
            {
                pushKindA = SHOPKEEPER_STATE_CURVE_A;
                stackHandle = state->msgStack;
                if (Stack_IsFull(stackHandle) == 0)
                {
                    Stack_Push(stackHandle, &pushKindA);
                }
            }
            else
            {
                pushKindB = SHOPKEEPER_STATE_CURVE_B;
                stackHandle = state->msgStack;
                if (Stack_IsFull(stackHandle) == 0)
                {
                    Stack_Push(stackHandle, &pushKindB);
                }
            }

            baddie->animSpeedA = 0.0f;
            state->flags9D4 = (u8)(state->flags9D4 | SHOPKEEPER_FLAG_TICK);
        }
    }

    state->opacity = 0xff;
    if (state->opacity == 0xff)
    {
        stackHandle = state->msgStack;
        popOut = 0;
        if (Stack_IsEmpty(stackHandle) == 0)
        {
            Stack_Pop(stackHandle, &popOut);
        }
        return popOut + 1;
    }
    return 0;
}

int ShopKeeper_waitForShopOpen(void)
{
    if (mainGetBit(GAMEBIT_SHOP_Unk0617) != 0)
    {
        return SHOPKEEPER_STATE_SHOP_OPEN;
    }
    return 0;
}

int ShopKeeper_updateScarabGame(GameObject* obj)
{
    ShopkeeperState* state;
    int elapsed;
    int now;
    int limit;

    state = obj->extra;
    obj->anim.resetHitboxFlags = (u8)(obj->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED);
    state->opacity = 0;
    ObjHits_DisableObject(obj);

    SHOP_INTERFACE(state->vendorObj)->func17(state->vendorObj, &elapsed, &now, &limit);

    now -= elapsed;

    if (isGameTimerDisabled() != 0 || now >= limit || elapsed != 0)
    {
        gameTimerStop();
        setTrickyHudShowNearestInfo(0);
        mainSetBits(GAMEBIT_SHOP_ScarabGameRunning, 0);

        if (now >= limit)
        {
            mainSetBits(SHOPKEEPER_GAMEBIT_SCARAB_GAME_WON, 1);
        }
        else
        {
            mainSetBits(SHOPKEEPER_GAMEBIT_SCARAB_GAME_LOST, 1);
        }

        setHudForceShowMask(2);

        (*gMapEventInterface)->setObjGroupStatus((s32)obj->anim.mapEventSlot, 6, 0);

        gTitleMenuControlInterfaceCopy->vtable->func04(NULL, 0xf3, 0, 0, 0);
    }

    return 0;
}

int ShopKeeper_updateIdle(GameObject* obj, BaddieState* baddie)
{
    void* playerObj;
    ShopkeeperState* state;
    RingBufferQueue* stack;
    int pushState;
    int sum;
    int rng;

    playerObj = Obj_GetPlayerObject();
    state = obj->extra;
    state->opacity = 0xff;
    baddie->moveSpeed = 0.007f;
    if (obj->anim.currentMove != 0)
    {
        ObjAnim_SetCurrentMove(obj, SHOPKEEPER_ANIM_IDLE, 0.0f, 0);
    }
    ObjHits_EnableObject(obj);
    obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
    if (mainGetBit(GAMEBIT_SHOP_Unk0617) == 0)
    {
        pushState = SHOPKEEPER_STATE_PUSH_IDLE;
        stack = state->msgStack;
        if (Stack_IsFull(stack) == 0)
        {
            Stack_Push(stack, &pushState);
        }
        return SHOPKEEPER_STATE_CONTINUE;
    }
    ShopKeeper_turnTowardPlayer(obj, playerObj, 0);
    obj->anim.localPosY = state->bobAmplitude *
                 mathSinf((double)(3.1415927f * (float)(u32)state->bobPhase / 32768.0f)) +
             state->bobBaseY;
    sum = state->bobPhase + framesThisStep * 0x100;
    if (sum > 0xffff)
    {
        float rngf;
        rng = randomGetRange(0xf, 0x23);
        rngf = (float)rng;
        rngf = 0.1f * rngf;
        state->bobAmplitude = rngf;
    }
    state->bobPhase = sum;
    if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0)
    {
        if (playerGetMoney(playerObj) >= 1)
        {
            mainSetBits(SHOPKEEPER_GAMEBIT_HAS_MONEY, 1);
            buttonDisable(0, SHOPKEEPER_BUTTON_ACCEPT);
        }
        else
        {
            rng = randomGetRange(0, 2);
            (*gObjectTriggerInterface)->runSequence(rng, obj, -1);
            buttonDisable(0, SHOPKEEPER_BUTTON_ACCEPT);
        }
    }
    return 0;
}

int ShopKeeper_updateTracking(GameObject* obj, BaddieState* baddie)
{
    void* playerObj;
    ShopkeeperState* state;
    RingBufferQueue* stack;
    TrackGroundHit** arr;
    int pushState;
    int sum;
    int rng;
    float dist;
    float minDist;
    int count;
    int idx;
    f32 t;
    float rate;
    float target;
    float d;

    playerObj = Obj_GetPlayerObject();
    state = obj->extra;
    if (baddie->moveJustStartedA != 0)
    {
        rng = randomGetRange(0x1f4, 0x3e8);
        state->actionTimer = rng;
        state->flags9D4 &= ~SHOPKEEPER_FLAG_IDLE_ANIM;
    }
    if ((state->flags9D4 & SHOPKEEPER_FLAG_IDLE_ANIM) != 0)
    {
        if (baddie->moveDone != 0)
        {
            if (obj->anim.currentMove == SHOPKEEPER_ANIM_TRACKING && baddie->moveSpeed > 0.0f)
            {
                ObjAnim_SetCurrentMove(obj, SHOPKEEPER_ANIM_ALERT, 0.0f, 0);
            }
            else if (obj->anim.currentMove != 0)
            {
                ObjAnim_SetCurrentMove(obj, SHOPKEEPER_ANIM_IDLE, 0.0f, 0);
            }
            baddie->moveSpeed = 0.007f;
            state->flags9D4 &= ~SHOPKEEPER_FLAG_IDLE_ANIM;
            rng = randomGetRange(0x1f4, 0x3e8);
            state->actionTimer = rng;
        }
    }
    else
    {
        if (obj->anim.currentMove != SHOPKEEPER_ANIM_ALERT && obj->anim.currentMove != 0)
        {
            ObjAnim_SetCurrentMove(obj, SHOPKEEPER_ANIM_IDLE, 0.0f, 0);
            baddie->moveSpeed = 0.007f;
        }
    }
    state->actionTimer -= timeDelta;
    if (state->actionTimer <= 0.0f && (state->flags9D4 & SHOPKEEPER_FLAG_IDLE_ANIM) == 0)
    {
        Sfx_PlayFromObject(obj, SHOPKEEPER_SFX_IDLE_ANIM);
        if (obj->anim.currentMove == SHOPKEEPER_ANIM_ALERT)
        {
            ObjAnim_SetCurrentMove(obj, SHOPKEEPER_ANIM_TRACKING, 0.99f, 0);
            baddie->moveSpeed = -0.0125f;
        }
        else
        {
            rng = randomGetRange(0, 1);
            ObjAnim_SetCurrentMove(obj, gShopKeeperIdleAnimMoves[rng], 0.0f, 0);
            baddie->moveSpeed = gShopKeeperIdleAnimStepScales[rng];
        }
        state->flags9D4 |= SHOPKEEPER_FLAG_IDLE_ANIM;
    }
    if (mainGetBit(GAMEBIT_SHOP_Unk0617) == 0)
    {
        pushState = SHOPKEEPER_STATE_PUSH_TRACKING;
        stack = state->msgStack;
        if (Stack_IsFull(stack) == 0)
        {
            Stack_Push(stack, &pushState);
        }
        return SHOPKEEPER_STATE_CONTINUE;
    }
    t = ShopKeeper_turnTowardPlayer(obj, playerObj, 0);
    rate = 0.02f;
    if (t > 80.0f)
    {
        target = -0.9f;
    }
    else
    {
        target = 0.0f;
    }
    d = rate * (target - baddie->animSpeedA);
    baddie->animSpeedA += d * timeDelta;
    if (baddie->animSpeedA > -0.002f)
    {
        baddie->animSpeedA = 0.0f;
    }
    baddie->animSpeedA = 0.0f;
    count = trackGetHeight(obj, obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &arr, 0, 0);
    minDist = 10000.0f;
    for (idx = 0; idx < count; idx++)
    {
        dist = arr[idx]->height - obj->anim.localPosY;
        if (dist < 0.0f)
        {
            dist = -dist;
        }
        if (dist < minDist)
        {
            state->bobBaseY = 6.0f + arr[idx]->height;
            minDist = dist;
        }
    }
    obj->anim.localPosY = state->bobAmplitude *
                 mathSinf((double)(3.1415927f * (float)(u32)state->bobPhase / 32768.0f)) +
             state->bobBaseY;
    sum = state->bobPhase + framesThisStep * 0x100;
    if (sum > 0xffff)
    {
        float rngf;
        rng = randomGetRange(0xf, 0x23);
        rngf = (float)rng;
        rngf = 0.1f * rngf;
        state->bobAmplitude = rngf;
    }
    state->bobPhase = sum;
    if (ObjTrigger_IsSet(obj) != 0)
    {
        rng = randomGetRange(0, 2);
        (*gObjectTriggerInterface)->runSequence(rng, obj, -1);
    }
    return 0;
}

int ShopKeeper_startVendorSequence(GameObject* obj)
{
    ShopkeeperState* state;

    state = obj->extra;
    if (mainGetBit(GAMEBIT_SHOP_Unk0CEF) == 0)
    {
        return 0;
    }
    if ((int)mainGetBit(GAMEBIT_SHOP_Unk0AD3) == 0)
    {
        GameObject* target;
        mainSetBits(GAMEBIT_SHOP_Unk0AD3, 1);
        target = state->vendorObj;
        SHOP_INTERFACE(target)->playSequence(target, 1, 2);
    }
    return SHOPKEEPER_STATE_VENDOR_SEQUENCE;
}

int ShopKeeper_handlePromptChoice(GameObject* obj, void* param2, int dispatch)
{
    ShopkeeperState* state;
    s8 stickHi;
    s8 stickLo;
    int btn;
    int cv;
    char nudge;
    ObjTextureRuntimeSlot* texture;

    state = obj->extra;
    if (dispatch == SHOPKEEPER_PROMPT_ADJUST_PRICE)
    {
        padGetAnalogInput(0, &stickHi, &stickLo);
        if (stickLo < 0)
        {
            state->priceShown--;
            Sfx_PlayFromObject(0, SHOPKEEPER_SFX_PROMPT_TICK);
        }
        else if (stickLo > 0)
        {
            state->priceShown++;
            Sfx_PlayFromObject(0, SHOPKEEPER_SFX_PROMPT_TICK);
        }
        if (state->priceShown > state->playerMoney)
        {
            state->priceShown = state->playerMoney;
        }
        if (state->priceShown > state->price << 1)
        {
            state->priceShown = (s16)(state->price << 1);
        }
        else if (state->priceShown < state->price >> 1)
        {
            state->priceShown = (s16)(state->price >> 1);
        }
        cv = state->priceShown;
        texture = objFindTexture((GameObject*)(obj), SHOPKEEPER_ONES_TEXTURE_SLOT, 0);
        texture->textureId = (cv % 10) << SHOPKEEPER_DIGIT_TEXTURE_SHIFT;
        texture = objFindTexture((GameObject*)(obj), SHOPKEEPER_TENS_TEXTURE_SLOT, 0);
        texture->textureId = ((cv / 10) % 10) << SHOPKEEPER_DIGIT_TEXTURE_SHIFT;
        cv /= 100;
        if (cv > SHOPKEEPER_MAX_DIGIT)
            cv = SHOPKEEPER_MAX_DIGIT;
        texture = objFindTexture((GameObject*)(obj), SHOPKEEPER_HUNDREDS_TEXTURE_SLOT, 0);
        texture->textureId = cv << SHOPKEEPER_DIGIT_TEXTURE_SHIFT;
    }
    else if (dispatch == SHOPKEEPER_PROMPT_ADJUST_AMOUNT)
    {
        padGetAnalogInput(0, &stickHi, &stickLo);
        if (stickLo < 0)
        {
            state->amount--;
            Sfx_PlayFromObject(0, SHOPKEEPER_SFX_PROMPT_TICK);
        }
        else if (stickLo > 0)
        {
            state->amount++;
            Sfx_PlayFromObject(0, SHOPKEEPER_SFX_PROMPT_TICK);
        }
        if (state->amount > state->playerMoney)
        {
            state->amount = state->playerMoney;
        }
        if (state->amount > SHOPKEEPER_MAX_AMOUNT)
        {
            state->amount = SHOPKEEPER_MAX_AMOUNT;
        }
        else if (state->amount < SHOPKEEPER_MIN_AMOUNT)
        {
            state->amount = SHOPKEEPER_MIN_AMOUNT;
        }
        {
            cv = state->amount;
            texture = objFindTexture((GameObject*)(obj), SHOPKEEPER_ONES_TEXTURE_SLOT, 0);
            texture->textureId = (cv % 10) << SHOPKEEPER_DIGIT_TEXTURE_SHIFT;
            texture = objFindTexture((GameObject*)(obj), SHOPKEEPER_TENS_TEXTURE_SLOT, 0);
            texture->textureId = ((cv / 10) % 10) << SHOPKEEPER_DIGIT_TEXTURE_SHIFT;
            cv /= 100;
            if (cv > SHOPKEEPER_MAX_DIGIT)
                cv = SHOPKEEPER_MAX_DIGIT;
            texture = objFindTexture((GameObject*)(obj), SHOPKEEPER_HUNDREDS_TEXTURE_SLOT, 0);
            texture->textureId = cv << SHOPKEEPER_DIGIT_TEXTURE_SHIFT;
        }
        btn = getButtonsJustPressed(0);
        if ((btn & SHOPKEEPER_BUTTON_CANCEL) != 0u)
        {
            state->flags9D4 |= SHOPKEEPER_FLAG_LEAVING;
            (*gScreenTransitionInterface)->start(0x1e, SCREEN_TRANSITION_BLACK);
            return 1;
        }
    }
    btn = getButtonsJustPressed(0);
    if ((btn & SHOPKEEPER_BUTTON_ACCEPT) == 0u)
    {
        return 0;
    }
    cv = state->priceShown;
    if (cv < state->minPrice)
    {
        nudge = (state->haggleCount < SHOPKEEPER_MAX_HAGGLE_COUNT) ? 0 : 2;
    }
    else
    {
        nudge = 1;
    }
    switch (dispatch)
    {
    case SHOPKEEPER_PROMPT_ADJUST_PRICE:
        if ((s8)nudge == 0)
        {
            state->haggleCount++;
        }
        return nudge == 0;
    case SHOPKEEPER_PROMPT_OFFER_ACCEPTED:
        if ((s8)nudge == 1)
        {
            GameObject* target = state->vendorObj;
            SHOP_INTERFACE(target)->buyItem(target, cv);
        }
        return nudge == 1;
    case SHOPKEEPER_PROMPT_OFFER_REFUSED:
        return nudge == 2;
    }
    return 0;
}

void ShopKeeper_startScarabGame(GameObject* obj)
{
    ShopkeeperState* state;

    state = obj->extra;
    if ((state->flags9D4 & SHOPKEEPER_FLAG_PURCHASED) != 0)
    {
        GameObject* target;
        gameTimerInit(0x11, 0x1e);
        timerSetToCountUp();
        setTrickyHudShowNearestInfo(1);
        mainSetBits(GAMEBIT_SHOP_ScarabGameRunning, 1);
        target = state->vendorObj;
        SHOP_INTERFACE(target)->func15(target, state->amount);
        gTitleMenuControlInterfaceCopy->vtable->func04(NULL, 0xf5, 0, 0, 0);
    }
    else
    {
        setHudForceShowMask(0);
    }
    state->flags9D4 = 0;
}

STATIC_ASSERT(sizeof(ShopkeeperState) == 0x9D8);
STATIC_ASSERT(offsetof(ShopkeeperState, msgStack) == 0x9B0);

/* Obj_AllocObjectSetup(36,...) buffer composed in ShopKeeper_spawnScarabs. Head is the
 * common ObjPlacement; ident slot (0x14) is repurposed as an int (vendorObj),
 * tail (0x18..0x1B) is file-local. */
typedef struct ShopkeeperSpawnSetup
{
    ObjPlacement base; /* 0x00..0x17 */
    s8 rotXByte;       /* 0x18: scarab spawn rotX (1/256 turns) */
    u8 kind;           /* 0x19: scarab variant (see SpscarabPlacement.kind) */
    s16 groundY;       /* 0x1A: scarab ground-height delta (see SpscarabState.groundY) */
    u8 pad1C[0x24 - 0x1C];
} ShopkeeperSpawnSetup;

STATIC_ASSERT(offsetof(ShopkeeperSpawnSetup, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(ShopkeeperSpawnSetup, kind) == 0x19);
STATIC_ASSERT(offsetof(ShopkeeperSpawnSetup, groundY) == 0x1A);
STATIC_ASSERT(sizeof(ShopkeeperSpawnSetup) == 0x24);

void* gShopKeeperDefaultStateHandler;

int ShopKeeper_SeqFn(GameObject* obj, int unused, ObjSeqState* seq, s8 advance)
{
    ShopkeeperState* state;
    int digit;
    int slot;
    int i;
    ShopkeeperState* state2;
    GameObject* player;
    int hundreds;
    ObjTextureRuntimeSlot* tex;
    UiDllVTable** uiDll;
    f32 range;
    f32 speed;

    state = (ShopkeeperState*)*(int*)&obj->extra;
    /* second copy of the extra pointer */
    state2 = (ShopkeeperState*)(long)*(int*)&obj->extra;
    player = Obj_GetPlayerObject();
    range = 1.0f;
    state->flags9D4 &= ~SHOPKEEPER_FLAG_TICK;
    if (state->flags9D4 & SHOPKEEPER_FLAG_LEAVING)
    {
        if ((*gScreenTransitionInterface)->isFinished() != 0)
        {
            (*gScreenTransitionInterface)->step(0x1E, SCREEN_TRANSITION_BLACK);
            (*gObjectTriggerInterface)->endSequence(seq->slot);
        }
        return 0;
    }
    if (dll_2E_updateSequenceTurn(obj, seq, &state->moveLib, 0, 0) != 0)
    {
        return 1;
    }
    seq->freeCallback = (ObjAnimSequenceFreeCallback)ShopKeeper_startScarabGame;
    seq->flags &= ~0x20;
    speed = 0.0f;
    state2->baddie.animSpeedA = speed;
    state->flags9D4 |= SHOPKEEPER_FLAG_FACING;
    if (advance != 0)
    {
        ObjAnim_AdvanceCurrentMove(obj, speed, timeDelta, NULL);
    }
    if (obj->seqIndex == -1) {
        if (seq->movementState != 0)
        {
            slot = SHOP_INTERFACE(state->vendorObj)
                       ->getItemIndex((GameObject*)state->vendorObj);
            if (slot != -1)
            {
                state->price =
                    (s16)SHOP_INTERFACE(state->vendorObj)
                        ->getItemPrice((GameObject*)state->vendorObj, slot);
                state->minPrice =
                    (s16)SHOP_INTERFACE(state->vendorObj)
                        ->getItemMinPrice((GameObject*)state->vendorObj, slot);
                state->priceShown = state->price;
                state->haggleCount = 0;
                digit = state->price;
                tex = objFindTexture(obj, 8, 0);
                tex->textureId = (digit % 10) * 0x100;
                tex = objFindTexture(obj, 7, 0);
                tex->textureId = ((digit / 10) % 10) * 0x100;
                hundreds = digit / 100;
                if (hundreds > 9)
                {
                    hundreds = 9;
                }
                tex = objFindTexture(obj, 6, 0);
                tex->textureId = hundreds << 8;
            }
            seq->movementState = 0;
            seq->conditionCallback = (ObjAnimSequenceConditionCallback)ShopKeeper_handlePromptChoice;
        }
        if (SHOP_INTERFACE(state->vendorObj)
                ->getItemIndex((GameObject*)state->vendorObj) != -1)
        {
            setAButtonIcon(0x12);
            setBButtonIcon(0xA);
        }
    }
    for (i = 0; i < seq->eventCount; i++)
    {
        switch (seq->eventIds[i])
        {
        case 1:
            ShopKeeper_spawnScarabs(obj, (ShopkeeperState*)state, state->amount);
            state->flags9D4 |= SHOPKEEPER_FLAG_PURCHASED;
            break;
        case 2:
            (*gPlayerInterface)->setState((void*)obj, (void*)state2, 3);
            (*gBoneParticleEffectInterface)->spawnEffect((void*)obj, 0x7EF, &range, 0x50, NULL);
            state->opacity = 0;
            break;
        case 3:
            (*gPlayerInterface)->setState((void*)obj, (void*)state2, 2);
            state->flags9D4 |= SHOPKEEPER_FLAG_TICK;
            state->opacity = 0xFF;
            break;
        case 4:
            if (player->anim.romDefNo == 0)
            {
                warpToMap(0xF, 0);
            }
            else
            {
                warpToMap(0xE, 0);
            }
            break;
        case 5:
            if (getCurUiDll() == 0x10)
            {
                uiDll = getCurUiDllInterface();
                (*uiDll)->setState(0);
            }
            break;
        case 6:
            if (getCurUiDll() == 0x10)
            {
                uiDll = getCurUiDllInterface();
                (*uiDll)->setState(2);
            }
            break;
        case 7:
            if (getCurUiDll() == 0x10)
            {
                uiDll = getCurUiDllInterface();
                (*uiDll)->setState(4);
            }
            break;
        case 9:
            playerAddMoney(player, state->amount);
            break;
        case 10:
            playerAddMoney(player, -(int)state->amount);
            break;
        case 0xB:
            (*gBoneParticleEffectInterface)->spawnEffect((void*)obj, 0x7EF, &range, 0x50, NULL);
            break;
        case 0xC:
            state->amount = 1;
            digit = state->amount;
            tex = objFindTexture(obj, 8, 0);
            tex->textureId = (digit % 10) * 0x100;
            tex = objFindTexture(obj, 7, 0);
            tex->textureId = ((digit / 10) % 10) * 0x100;
            digit /= 100;
            if (digit > 9)
            {
                digit = 9;
            }
            tex = objFindTexture(obj, 6, 0);
            tex->textureId = digit << 8;
            break;
        }
    }
    obj->anim.alpha = state->opacity;
    return 0;
}

f32 ShopKeeper_turnTowardPlayer(GameObject* obj, GameObject* player, int snap)
{
    f32 dist;
    f32 dx;
    f32 dz;
    int angleDelta;

    dx = player->anim.localPosX - obj->anim.localPosX;
    dz = player->anim.localPosZ - obj->anim.localPosZ;
    dist = sqrtf(dx * dx + dz * dz);
    if (dist)
    {
        dx /= dist;
        dz /= dist;
    }
    if (dist > 10.0f)
    {
        angleDelta = getAngle(dx, dz) & 0xffff;
        if (snap != 0)
        {
            obj->anim.rotX = angleDelta;
        }
        else
        {
            angleDelta = angleDelta - (u16)obj->anim.rotX;
            if (angleDelta > 0x8000)
            {
                angleDelta -= 0xFFFF;
            }
            if (angleDelta < -0x8000)
            {
                angleDelta += 0xFFFF;
            }
            if (angleDelta > 0x2000)
            {
                angleDelta -= 0x2000;
            }
            else if (angleDelta < -0x2000)
            {
                angleDelta += 0x2000;
            }
            else
            {
                angleDelta = 0;
            }
            obj->anim.rotX = (s16)((f32)(angleDelta >> 3) * timeDelta + (f32) * (s16*)obj);
        }
    }
    return dist;
}

void ShopKeeper_spawnScarabs(GameObject* obj, ShopkeeperState* state, int count)
{
    int i;
    f32 groundHeight;
    ShopkeeperSpawnSetup* setup;
    u8 canSetupObject;

    canSetupObject = Obj_CanSetupObject();
    if (canSetupObject == 0)
        return;

    (*gMapEventInterface)->setObjGroupStatus((s32)obj->anim.mapEventSlot, 6, 1);

    trackGetNearestGroundOffset(obj, obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &groundHeight, 0);

    for (i = 0; i < count; i++)
    {
        setup = (ShopkeeperSpawnSetup*)Obj_AllocObjectSetup(0x24, OBJTYPE_SPSCARAB);
        setup->base.posX = obj->anim.localPosX;
        setup->base.posY = obj->anim.localPosY;
        setup->base.posZ = obj->anim.localPosZ;
        setup->rotXByte = randomGetRange(-128, 127);
        setup->groundY = obj->anim.localPosY - groundHeight;
        setup->base.color[1] = 1;
        setup->base.color[3] = 255;
        setup->base.color[0] = 16;
        setup->base.color[2] = 6;
        setup->base.ident = (int)state->vendorObj;
        objSetupObject((ObjPlacement*)setup, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
    }

    for (i = 0; i < count; i++)
    {
        setup = (ShopkeeperSpawnSetup*)Obj_AllocObjectSetup(0x24, OBJTYPE_SPSCARAB);
        setup->base.posX = obj->anim.localPosX;
        setup->base.posY = obj->anim.localPosY;
        setup->base.posZ = obj->anim.localPosZ;
        setup->rotXByte = randomGetRange(-128, 127);
        setup->groundY = obj->anim.localPosY - groundHeight;
        setup->base.color[1] = 1;
        setup->base.color[3] = 255;
        setup->base.color[0] = 16;
        setup->base.color[2] = 6;
        setup->kind = 1;
        setup->base.ident = (int)state->vendorObj;
        objSetupObject((ObjPlacement*)setup, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
    }
}

int ShopKeeper_getExtraSize(void)
{
    return sizeof(ShopkeeperState);
}

int ShopKeeper_getObjectTypeId(void)
{
    return 0x0;
}

void ShopKeeper_free(GameObject* obj)
{
    Stack_Free(((ShopkeeperState*)obj->extra)->msgStack);
    return;
}

void ShopKeeper_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    ShopkeeperState* state = obj->extra;
    f32 fxParams[4];
    fxParams[0] = 1.0f;
    if (state->baddie.controlMode != 7 && visible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
        dll_2E_setTargetFromPathPoint(obj, &state->moveLib, 0);
    }
    if ((state->flags9D4 & SHOPKEEPER_FLAG_TICK) != 0)
    {
        (*gBoneParticleEffectInterface)->spawnEffect((void*)obj, 0x7ef, fxParams, 0x50, NULL);
    }
}

void ShopKeeper_hitDetect(void)
{
}

void ShopKeeper_update(GameObject* obj)
{
    void* player;
    ShopkeeperState* state;
    f32 dist;
    player = Obj_GetPlayerObject();
    state = obj->extra;
    dist = 10000.0f;
    state->flags9D4 &= ~SHOPKEEPER_FLAG_TICK;
    if (state->textTimer > 0.0f)
    {
        gameTextShow(0x433);
        state->textTimer -= timeDelta;
        if (state->textTimer < 0.0f)
        {
            state->textTimer = 0.0f;
        }
    }
    if ((state->flags9D4 & SHOPKEEPER_FLAG_FACING) != 0)
    {
        ShopKeeper_turnTowardPlayer(obj, player, 1);
    }
    obj->anim.rootMotionScale = obj->anim.modelInstance->rootMotionScaleBase;
    if (state->vendorObj == NULL)
    {
        state->vendorObj =
            objGetNearestTypeTo(SHOPKEEPER_VENDOR_OBJGROUP, obj, &dist);
    }
    state->playerMoney = playerGetMoney(player);
    (*gPlayerInterface)->update((void*)obj, (void*)state, timeDelta, timeDelta, gShopKeeperStateHandlers, &gShopKeeperDefaultStateHandler);
    dll_2E_updateLookAt(obj, &state->moveLib);
    characterDoEyeAnims(obj, &state->eyeAnimState);
    obj->anim.alpha = state->opacity;
}

void ShopKeeper_init(GameObject* obj)
{
    ShopkeeperState* state = obj->extra;
    obj->objectFlags |= SHOPKEEPER_OBJFLAG_HITDETECT_DISABLED;
    obj->animEventCallback = ShopKeeper_SeqFn;
    obj->anim.modelState->flags |= 0x810;
    state->bobAmplitude = 0.1f * (f32)(s32)randomGetRange(0xF, 0x23);
    state->msgStack = Queue_Alloc(4, 4);
    state->opacity = 0xFF;
    state->textTimer = 300.0f;
    dll_2E_initState(obj, &state->moveLib, -0x1C71, 0x3555, 2);
    state->moveLib.modeBits |= 0x12;
}

void ShopKeeper_release(void)
{
}

void ShopKeeper_initialise(void)
{
    gShopKeeperStateHandlers[0] = ShopKeeper_startVendorSequence;
    gShopKeeperStateHandlers[1] = ShopKeeper_updateTracking;
    gShopKeeperStateHandlers[2] = ShopKeeper_updateIdle;
    gShopKeeperStateHandlers[3] = ShopKeeper_updateScarabGame;
    gShopKeeperStateHandlers[4] = ShopKeeper_waitForShopOpen;
    gShopKeeperStateHandlers[5] = ShopKeeper_moveToCurvePoint;
    gShopKeeperStateHandlers[6] = ShopKeeper_popQueuedState;
    gShopKeeperStateHandlers[7] = ShopKeeper_state7Handler;
    gShopKeeperDefaultStateHandler = ShopKeeper_defaultStateHandler;
}
