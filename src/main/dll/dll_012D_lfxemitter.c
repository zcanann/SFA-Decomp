#include "main/asset_load.h"
#include "main/dll/CF/CFchuckobj.h"
#include "main/dll/rom_curve_interface.h"
#include "main/effect_interfaces.h"
#include "main/gamebits.h"
#include "main/gameplay_runtime.h"
#include "main/objlib.h"
#include "main/mm.h"
#include "main/dll/objfsa.h"
extern void Obj_FreeObject(int obj);

extern u8 framesThisStep;
extern f32 timeDelta;
extern f32 FLOAT_803e4b00;
extern f32 lbl_803E3E78;
extern f32 lbl_803E3E7C;
extern f32 lbl_803E3E80;
extern f32 lbl_803E3E84;
extern f32 lbl_803E3E88;

#pragma scheduling on
#pragma peephole on
extern u8 lbl_803AC7B0[];

#pragma scheduling off
#pragma peephole off
void lfxemitter_init(LfxEmitterObject* obj, LfxEmitterPlacement* setup)
{
    LfxEmitterState* state;
    int curveFlags;

    state = obj->state;
    curveFlags = 0x21;
    obj->objAnim.rootMotionScale = lbl_803E3E80 * obj->objAnim.modelInstance->rootMotionScaleBase;

    state->configIndex = setup->configIndex;
    state->lifeTimer = setup->lifeTimer;
    state->unk114 = -2;
    state->enableBit = setup->enableBit;
    state->spinRoll = setup->spinRoll;
    state->spinPitch = setup->spinPitch;
    state->spinYaw = setup->spinYaw;
    obj->objAnim.localPosX = setup->initialX;
    obj->objAnim.localPosY = setup->initialY;
    obj->objAnim.localPosZ = setup->initialZ;

    if (state->lifeTimer != 0)
    {
        state->hasLifeTimer = 1;
    }
    else
    {
        state->hasLifeTimer = 0;
    }

    if (setup->followCurve != 0)
    {
        state->flags = state->flags | LFXEMITTER_FLAG_FOLLOW_CURVE;
        state->curveSpeed = setup->curveSpeed / lbl_803E3E84;
        (*gRomCurveInterface)->initCurve(&state->curve, obj, lbl_803E3E88, &curveFlags, -1);
    }
    ObjGroup_AddObject((int)obj, LFXEMITTER_OBJ_GROUP);
}

int lfxemitter_setScale(void) { return -1; }

void lfxemitter_initialise(void)
{
    *(s16*)(lbl_803AC7B0 + 0xe) = 10000;
}

int lfxemitter_func0B(LfxEmitterObject* obj)
{
    LfxEmitterState* state = obj->state;
    int v = (int)state->config;
    return (u32)(-v | v) >> 31;
}

void fn_8018FF48(u16* src, u16* dst)
{
    *dst = *src;
    dst[1] = src[1];
    ((s16*)dst)[2] = ((s16*)src)[2];
    ((s16*)dst)[3] = ((s16*)src)[3];
    ((s16*)dst)[4] = ((s16*)src)[4];
    ((s16*)dst)[5] = ((s16*)src)[5];
    ((s16*)dst)[6] = ((s16*)src)[6];
    dst[7] = src[7];
    *(u8*)(dst + 9) = *(u8*)(src + 9);
    *(u8*)((int)dst + 0x13) = *(u8*)((int)src + 0x13);
    *(u8*)((int)dst + 0x1b) = *(u8*)((int)src + 0x1b);
    *(u8*)(dst + 0xe) = *(u8*)(src + 0xe);
    *(u8*)((int)dst + 0x1d) = *(u8*)((int)src + 0x1d);
    *(u8*)(dst + 0xf) = *(u8*)(src + 0xf);
    *(u8*)((int)dst + 0x1f) = *(u8*)((int)src + 0x1f);
    *(u8*)(dst + 0x10) = *(u8*)(src + 0x10);
    *(u8*)((int)dst + 0x21) = *(u8*)((int)src + 0x21);
    *(u8*)(dst + 0x11) = *(u8*)(src + 0x11);
    *(u8*)((int)dst + 0x15) = *(u8*)((int)src + 0x15);
    *(u8*)((int)dst + 0x23) = *(u8*)((int)src + 0x23);
    *(u8*)(dst + 0xb) = *(u8*)(src + 0xb);
    *(u8*)(dst + 0x12) = *(u8*)(src + 0x12);
    *(u8*)((int)dst + 0x17) = *(u8*)((int)src + 0x17);
    *(u8*)((int)dst + 0x25) = *(u8*)((int)src + 0x25);
    *(u8*)(dst + 0xc) = *(u8*)(src + 0xc);
    *(u8*)(dst + 0x13) = *(u8*)(src + 0x13);
    *(u8*)((int)dst + 0x19) = *(u8*)((int)src + 0x19);
    *(u8*)((int)dst + 0x27) = *(u8*)((int)src + 0x27);
    *(u8*)(dst + 0xd) = *(u8*)(src + 0xd);
    *(u8*)(dst + 0x14) = *(u8*)(src + 0x14);
}

void lfxemitter_update(LfxEmitterObject* obj)
{
    LfxEmitterState* state;
    ObjAnimComponent* player;

    state = obj->state;
    player = (ObjAnimComponent*)Obj_GetPlayerObject();

    obj->objAnim.rotX += state->spinYaw;
    obj->objAnim.rotZ += state->spinRoll;
    obj->objAnim.rotY += state->spinPitch;

    if ((state->flags & LFXEMITTER_FLAG_FOLLOW_CURVE) != 0)
    {
        if ((Curve_AdvanceAlongPath(&state->curve, state->curveSpeed) != 0) ||
            (state->curve.atSegmentEnd != 0))
        {
            (*gRomCurveInterface)->goNextPoint(&state->curve);
        }
        obj->objAnim.localPosX = state->curve.posX;
        obj->objAnim.localPosY = state->curve.posY;
        obj->objAnim.localPosZ = state->curve.posZ;
    }
    else
    {
        obj->objAnim.localPosX = obj->objAnim.velocityX * timeDelta + obj->objAnim.localPosX;
        obj->objAnim.localPosY = obj->objAnim.velocityY * timeDelta + obj->objAnim.localPosY;
        obj->objAnim.localPosZ = obj->objAnim.velocityZ * timeDelta + obj->objAnim.localPosZ;
        if (((state->flags & LFXEMITTER_FLAG_DAMP_Y_VELOCITY) != 0) && (obj->objAnim.velocityY > lbl_803E3E78))
        {
            obj->objAnim.velocityY = lbl_803E3E7C * timeDelta + obj->objAnim.velocityY;
        }
    }

    if ((player != NULL) &&
        ((state->enableBit == -1) || (GameBit_Get(state->enableBit) != 0)))
    {
        if (state->hasLifeTimer != 0)
        {
            state->lifeTimer -= framesThisStep;
            if (state->lifeTimer <= 0)
            {
                Obj_FreeObject((int)obj);
                return;
            }
        }
        if (state->configLoaded == 0)
        {
            if ((state != NULL) && (state->configIndex == (*(u16*)(lbl_803AC7B0 + 0xe) - 1)))
            {
                state->config = mmAlloc(LFXEMITTER_CONFIG_BYTES, 0x12, 0);
                if (state->config != NULL)
                {
                    fn_8018FF48((u16*)lbl_803AC7B0, state->config);
                }
            }
            else
            {
                state->config = mmAlloc(LFXEMITTER_CONFIG_BYTES, 0x12, 0);
                getTabEntry(state->config, 0xc, state->configIndex * LFXEMITTER_CONFIG_BYTES, LFXEMITTER_CONFIG_BYTES);
                if (state->config != NULL)
                {
                    fn_8018FF48((u16*)state->config, (u16*)lbl_803AC7B0);
                }
            }
            state->configLoaded = 1;
        }
    }
}

void lfxemitter_free(LfxEmitterObject* obj)
{
    LfxEmitterState* state = obj->state;
    int* ptr = state->config;
    if (ptr != NULL)
    {
        mm_free(ptr);
    }
    ObjGroup_RemoveObject((int)obj, LFXEMITTER_OBJ_GROUP);
}


void lfxemitter_render(void)
{
}

void lfxemitter_hitDetect(void)
{
}

void lfxemitter_release(void)
{
}

int lfxemitter_getExtraSize(void) { return 0x124; }
int lfxemitter_getObjectTypeId(void) { return 0x0; }
