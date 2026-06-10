#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/game_object.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/gfxemit_state.h"
#include "main/dll/gfxEmit.h"
#include "main/objanim_internal.h"
#include "main/objhits_types.h"

extern undefined4 FUN_80006824();
extern uint FUN_80017690();
extern undefined8 FUN_80017698();
extern undefined4 FUN_80017710();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017a88();
extern int FUN_80017a98();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjMsg_SendToObject();
extern int ObjTrigger_IsSet();
extern undefined4 FUN_8003b56c();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_800810f4();
extern undefined4 FUN_80081118();
extern undefined4 FUN_801713ac();
extern int FUN_80286840();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern uint FUN_80294c78();
extern int FUN_80294dbc();
extern uint countLeadingZeros();

extern undefined4 DAT_803dc070;
extern EffectInterface **gPartfxInterface;
extern f64 DOUBLE_803e40e0;
extern f64 DOUBLE_803e4108;
extern f32 lbl_803DC074;
extern f32 lbl_803E40EC;
extern f32 lbl_803E40F0;
extern f32 lbl_803E40F4;
extern f32 lbl_803E40F8;
extern f32 lbl_803E40FC;
extern f32 lbl_803E4100;
extern f32 lbl_803E4104;
extern f32 lbl_803E4110;
extern f32 lbl_803E4114;
extern f32 lbl_803E4118;
extern f32 lbl_803E411C;
extern f32 lbl_803E4124;
extern f32 lbl_803E4128;

/*
 * --INFO--
 *
 * Function: FUN_801723dc
 * EN v1.0 Address: 0x801723DC
 * EN v1.0 Size: 720b
 * EN v1.1 Address: 0x801725F0
 * EN v1.1 Size: 664b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801723dc(int param_1)
{
  float fVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  
  GfxEmitState *state = ((GameObject *)param_1)->extra;
  iVar4 = (int)state;
  if (((GameObject *)param_1)->anim.seqId == 0x6a6) {
    FUN_80017a88((double)lbl_803E40F4,
                 (double)(((GameObject *)param_1)->anim.velocityY *
                         (float)((double)CONCAT44(0x43300000,(uint)DAT_803dc070) - DOUBLE_803e4108))
                 ,(double)lbl_803E40F4,param_1);
  }
  else {
    uVar3 = (uint)DAT_803dc070;
    FUN_80017a88((double)(((GameObject *)param_1)->anim.velocityX *
                         (float)((double)CONCAT44(0x43300000,uVar3) - DOUBLE_803e4108)),
                 (double)(((GameObject *)param_1)->anim.velocityY *
                         (float)((double)CONCAT44(0x43300000,uVar3) - DOUBLE_803e4108)),
                 (double)(((GameObject *)param_1)->anim.velocityZ *
                         (float)((double)CONCAT44(0x43300000,uVar3) - DOUBLE_803e4108)),param_1);
  }
  (*gPathControlInterface)->update((void *)param_1, state->pathState, lbl_803DC074);
  (*gPathControlInterface)->apply((void *)param_1, state->pathState);
  (*gPathControlInterface)->advance((void *)param_1, state->pathState, lbl_803DC074);
  if (*(char *)&((GfxEmitState *)iVar4)->unk2B1 == '\0') {
    ((GameObject *)param_1)->anim.velocityY = ((GameObject *)param_1)->anim.velocityY * lbl_803E4100;
    ((GameObject *)param_1)->anim.velocityY = -(lbl_803E4104 * lbl_803DC074 - ((GameObject *)param_1)->anim.velocityY);
  }
  else {
    dVar8 = -(double)((GameObject *)param_1)->anim.velocityX;
    dVar7 = -(double)((GameObject *)param_1)->anim.velocityY;
    dVar9 = -(double)((GameObject *)param_1)->anim.velocityZ;
    dVar6 = FUN_80293900((double)(float)(dVar9 * dVar9 +
                                        (double)(float)(dVar8 * dVar8 +
                                                       (double)(float)(dVar7 * dVar7))));
    if ((double)lbl_803E40F4 != dVar6) {
      dVar5 = (double)(float)((double)lbl_803E40EC / dVar6);
      dVar8 = (double)(float)(dVar8 * dVar5);
      dVar7 = (double)(float)(dVar7 * dVar5);
      dVar9 = (double)(float)(dVar9 * dVar5);
    }
    fVar1 = *(float *)(iVar4 + 0xbc);
    fVar2 = *(float *)(iVar4 + 0xc0);
    dVar5 = (double)(lbl_803E40F8 *
                    (float)(dVar9 * (double)fVar2 +
                           (double)(float)(dVar8 * (double)*(float *)(iVar4 + 0xb8) +
                                          (double)(float)(dVar7 * (double)fVar1))));
    ((GameObject *)param_1)->anim.velocityX = (float)((double)*(float *)(iVar4 + 0xb8) * dVar5);
    ((GameObject *)param_1)->anim.velocityY = (float)((double)fVar1 * dVar5);
    ((GameObject *)param_1)->anim.velocityZ = (float)((double)fVar2 * dVar5);
    ((GameObject *)param_1)->anim.velocityX = (float)((double)((GameObject *)param_1)->anim.velocityX - dVar8);
    ((GameObject *)param_1)->anim.velocityY = (float)((double)((GameObject *)param_1)->anim.velocityY - dVar7);
    ((GameObject *)param_1)->anim.velocityZ = (float)((double)((GameObject *)param_1)->anim.velocityZ - dVar9);
    ((GameObject *)param_1)->anim.velocityY = (float)((double)((GameObject *)param_1)->anim.velocityY * dVar6);
    ((GameObject *)param_1)->anim.velocityY = ((GameObject *)param_1)->anim.velocityY * lbl_803E40FC;
    ((GameObject *)param_1)->anim.velocityX = (float)((double)((GameObject *)param_1)->anim.velocityX * dVar6);
    ((GameObject *)param_1)->anim.velocityZ = (float)((double)((GameObject *)param_1)->anim.velocityZ * dVar6);
    *(char *)&((GfxEmitState *)iVar4)->unk1D = *(char *)&((GfxEmitState *)iVar4)->unk1D + -1;
    if (*(char *)&((GfxEmitState *)iVar4)->unk1D == '\0') {
      ((GfxEmitState *)iVar4)->unk1D = 0;
      fVar1 = lbl_803E40F4;
      ((GameObject *)param_1)->anim.velocityX = lbl_803E40F4;
      ((GameObject *)param_1)->anim.velocityY = fVar1;
      ((GameObject *)param_1)->anim.velocityZ = fVar1;
    }
  }
  return;
}


/*
 * --INFO--
 *
 * Function: collectible_free
 * EN v1.0 Address: 0x80173040
 * EN v1.0 Size: 76b
 * EN v1.1 Address: 0x80172F80
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void collectible_free(int obj)
{
  (*gExpgfxInterface)->freeSource2((u32)obj);
  ObjGroup_RemoveObject(obj,4);
  return;
}
#pragma scheduling reset


/*
 * --INFO--
 *
 * Function: collectible_getExtraSize
 * EN v1.0 Address: 0x80172E34
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80172D70
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int collectible_getExtraSize(void)
{
  return 0x2b8;
}

/*
 * --INFO--
 *
 * Function: collectible_getObjectTypeId
 * EN v1.0 Address: 0x80172E3C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80172D78
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int collectible_getObjectTypeId(void)
{
  return 0x13;
}

/*
 * --INFO--
 *
 * Function: collectible_hitDetect
 * EN v1.0 Address: 0x80172F90
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80172ECC
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void collectible_hitDetect(void)
{
}

extern uint GameBit_Get(int);
extern f32 mathCosf(f32 x);
extern f32 mathSinf(f32 x);
extern void objfx_spawnDirectionalBurst(int obj, int a, f32 fa, int b, int c, int d, f32 fb, int e, int f);
extern f32 lbl_803E3454;
extern f32 lbl_803E3458;
extern f32 lbl_803E345C;
extern f32 lbl_803E3460;
extern f32 lbl_803E3484;
extern f32 lbl_803E3488;
extern f32 lbl_803E348C;

#pragma scheduling off
#pragma peephole off
int collectible_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate)
{
    int* state = ((GameObject *)obj)->extra;
    f32 buf[6];
    int j;
    int i;
    f32 s_val;
    f32 c_val;
    f32 vy;

    if (((GfxEmitState *)state)->enableGameBit != -1) {
        ((GfxEmitState *)state)->enableGameBitClear = (u8)(GameBit_Get((s32)((GfxEmitState *)state)->enableGameBit) == 0);
    }
    if (((GfxEmitState *)state)->enableGameBitClear == 0) {
        switch (((GameObject *)obj)->anim.seqId) {
        case 0x6a6:
            objfx_spawnDirectionalBurst(obj, 5, lbl_803E3454, 6, 1, 0x14, lbl_803E3458, 0, 0);
            break;
        }
    }

    animUpdate->sequenceEventActive = 0;
    for (i = 0; i < (s32)animUpdate->eventCount; i++) {
        u8 cmd = animUpdate->eventIds[i];
        if (cmd == 1) {
            s_val = lbl_803E3484 * mathCosf(lbl_803E3488);
            c_val = lbl_803E3484 * mathSinf(lbl_803E3488);
            *(u8*)((char*)((GameObject *)obj)->extra + 0x1d) = 8;
            ((GameObject *)obj)->anim.velocityX = c_val;
            ((GameObject *)obj)->anim.velocityY = (vy = lbl_803E3460);
            ((GameObject *)obj)->anim.velocityZ = s_val;
            *(u8*)((char*)((GameObject *)obj)->extra + 0x1d) = 8;
            ((GameObject *)obj)->anim.velocityX = lbl_803E348C;
            ((GameObject *)obj)->anim.velocityY = vy;
            ((GameObject *)obj)->anim.velocityZ = lbl_803E345C;
        } else if (cmd == 2) {
            *(u8*)((char*)state + 0x3e) = 1;
        } else if (cmd == 3) {
            f32 z;
            j = 0;
            z = lbl_803E345C;
            for (; j < 10; j++) {
                buf[3] = z;
                buf[4] = z;
                buf[5] = z;
                (*gPartfxInterface)->spawnObject((void *)obj, 0x7ef, buf, 1,
                                                                    -1, NULL);
            }
        }
    }
    return 0;
}

extern void fn_8003B608(s16 a, s16 b, s16 c);
extern void objRenderFn_8003b8f4(int obj, int a, int b, int c, int d, f32 e);
extern u8 *Obj_GetPlayerObject(void);
extern u8 *fn_802972A8(void);
extern f32 Vec_xzDistance(f32 *a, f32 *b);
extern int fn_8029622C(u8 *player);
extern void fn_80171E5C(int obj);
extern void GameBit_Set(int bit, int value);
extern f32 lbl_803E3490;

void fn_80172824(int obj, u8 *state)
{
    u8 *player;
    s16 *attach;
    u8 *focus;
    f32 dist;
    f32 dy;

    attach = ((GameObject *)obj)->anim.placementData;
    player = Obj_GetPlayerObject();
    if (player == NULL) {
        return;
    }
    if ((state[0x37] & 1) != 0) {
        return;
    }
    focus = fn_802972A8();
    if (focus == NULL) {
        focus = player;
    }
    dist = Vec_xzDistance(&((GameObject *)obj)->anim.worldPosX, (f32 *)(focus + 0x18));
    dy = *(f32 *)(focus + 0x1c) - ((GameObject *)obj)->anim.worldPosY;
    if (dy < lbl_803E345C) {
        dy = -dy;
    }
    if (dy < lbl_803E3490 && dist < *(f32 *)(state + 4) && fn_8029622C(player) != 0) {
        ((GfxEmitState *)state)->unk48 = -1;
        switch (((GameObject *)obj)->anim.seqId) {
        case 0xb:
            if (GameBit_Get(0x90e) == 0) {
                ObjMsg_SendToObject(player, 0x7000a, obj, state + 0x48);
                GameBit_Set(0x90e, 1);
            } else {
                fn_80171E5C(obj);
            }
            state[0x37] |= 1;
            break;
        case 0x319:
            fn_80171E5C(obj);
            state[0x37] |= 1;
            break;
        case 0x49:
        case 0x2da:
        case 0x3cd:
            if (GameBit_Get(0x90f) == 0) {
                ObjMsg_SendToObject(player, 0x7000a, obj, state + 0x48);
                GameBit_Set(0x90f, 1);
            } else {
                fn_80171E5C(obj);
            }
            state[0x37] |= 1;
            break;
        case 0x6a6:
            if (GameBit_Get(0x9a8) == 0) {
                ObjMsg_SendToObject(player, 0x7000a, obj, state + 0x48);
                GameBit_Set(0x9a8, 1);
            } else {
                fn_80171E5C(obj);
            }
            state[0x37] |= 1;
            break;
        default:
            if (ObjTrigger_IsSet(obj) != 0) {
                GameBit_Set(0xa7b, 1);
                ((GfxEmitState *)state)->unk48 = attach[0xf];
                ObjMsg_SendToObject(player, 0x7000a, obj, state + 0x48);
                state[0x37] |= 1;
                if (((GameObject *)obj)->anim.modelState != NULL) {
                    ((GameObject *)obj)->anim.modelState->flags = OBJ_MODEL_STATE_SHADOW_FADE_OUT;
                }
            }
            break;
        }
    }
    *(f32 *)state = dist;
}

extern void Sfx_PlayFromObject(int obj, int sfx);
extern void itemPickupDoParticleFx(int obj, f32 scale, int a, int b);
extern u8 framesThisStep;
extern f32 timeDelta;
extern f32 lbl_803E3478;
extern f32 lbl_803E347C;
extern f32 lbl_803E3480;

extern void fn_801723DC(int obj);


extern void ObjHits_DisableObject(int obj);
extern void Obj_FreeObject(int obj);
extern int ObjMsg_Pop(int obj, int *outMessage, int *outParam, int *outSender);
extern void fn_80172144(int obj);
extern f32 lbl_803E3450;

void collectible_update(int obj)
{
    u8 *state = ((GameObject *)obj)->extra;
    int msgParam;
    int msg;
    int t;
    f32 timer;
    f32 zero;

    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
    timer = ((GfxEmitState *)state)->delayTimer;
    zero = lbl_803E345C;
    if (timer != zero) {
        ((GfxEmitState *)state)->delayTimer = timer - timeDelta;
        if (((GfxEmitState *)state)->delayTimer <= zero) {
            ((GfxEmitState *)state)->delayTimer = zero;
            ObjHits_DisableObject(obj);
            if ((((GameObject *)obj)->anim.flags & 0x2000) != 0) {
                Obj_FreeObject(obj);
            }
        }
        return;
    }
    if (((GfxEmitState *)state)->enableGameBit != -1) {
        state[0x1e] = (u8)(GameBit_Get((s32)((GfxEmitState *)state)->enableGameBit) == 0);
    }
    if (state[0x1e] != 0 || state[0xf] != 0) {
        return;
    }
    switch (((GameObject *)obj)->anim.seqId) {
    case 0x6a6:
        objfx_spawnDirectionalBurst(obj, 5, lbl_803E3454, 6, 1, 0x14, lbl_803E3458, 0, 0);
        break;
    }
    timer = ((GfxEmitState *)state)->intervalTimer;
    zero = lbl_803E345C;
    if (timer != zero) {
        ((GfxEmitState *)state)->intervalTimer = timer - timeDelta;
        if (((GfxEmitState *)state)->intervalTimer <= zero) {
            if ((((GameObject *)obj)->anim.flags & 0x2000) != 0) {
                ((GfxEmitState *)state)->delayTimer = lbl_803E3450;
                if (((GameObject *)obj)->anim.modelState != NULL) {
                    ((GameObject *)obj)->anim.modelState->flags = OBJ_MODEL_STATE_SHADOW_FADE_OUT;
                }
                itemPickupDoParticleFx(obj, lbl_803E3454, 255, 40);
            }
            ((GfxEmitState *)state)->intervalTimer = lbl_803E345C;
            return;
        }
    }
    while (ObjMsg_Pop(obj, &msg, &msgParam, NULL) != 0) {
        switch (msg) {
        case 0x7000b:
            fn_80171E5C(obj);
            break;
        }
    }
    switch (((GameObject *)obj)->anim.seqId) {
    case 0x319:
        t = ((GfxEmitState *)state)->hideFrames;
        if (t != 0) {
            ((GfxEmitState *)state)->hideFrames -= framesThisStep;
            if (((GfxEmitState *)state)->hideFrames <= 0) {
                ((GfxEmitState *)state)->hideFrames = 0;
                state[0x37] &= ~1;
                ((GameObject *)obj)->anim.alpha = 255;
                ((GameObject *)obj)->countF4 = 0;
            }
        }
        break;
    }
    if (((GameObject *)obj)->countF4 != 0) {
        if (((GameObject *)obj)->anim.hitReactState != NULL) {
            (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->flags |= 0x100;
        }
        ObjHits_DisableObject(obj);
        if (((GfxEmitState *)state)->hideGameBit != -1 && GameBit_Get((s32)((GfxEmitState *)state)->hideGameBit) == 0) {
            ((GameObject *)obj)->countF4 = 0;
        }
    } else {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~8;
        fn_801723DC(obj);
        if (state[0x1d] != 0) {
            fn_80172144(obj);
        }
        if (state[0x3e] != 0) {
            state[0x3e]--;
            if (state[0x3e] == 0) {
                ((GfxEmitState *)state)->unk48 = -1;
                ObjMsg_SendToObject(Obj_GetPlayerObject(), 0x7000a, obj, state + 0x48);
            }
        } else {
            fn_80172824(obj, state);
        }
    }
}

void collectible_render(int obj, int a, int b, int c, int d, s8 visible)
{
    int state = *(int *)&((GameObject *)obj)->extra;
    if (visible != 0 && ((GfxEmitState *)state)->delayTimer == lbl_803E345C && ((GameObject *)obj)->countF4 == 0
        && (((GameObject *)obj)->anim.seqId == 0x156 || ((GfxEmitState *)state)->enableGameBitClear == 0)) {
        if ((((ObjAnimComponent *)obj)->modelInstance->flags & 0x10000) != 0 && ((GfxEmitState *)state)->useColor != 0) {
            fn_8003B608(((GfxEmitState *)state)->colorR, ((GfxEmitState *)state)->colorG, ((GfxEmitState *)state)->colorB);
        }
        objRenderFn_8003b8f4(obj, a, b, c, d, lbl_803E3454);
        if (((GameObject *)obj)->anim.seqId == 0xa8) {
            objfx_spawnDirectionalBurst(obj, 7, lbl_803E3454, 5, 1, 10, lbl_803E348C, 0, 0x20000000);
        }
    }
}

void fn_801723DC(int obj)
{
    u8 *state = ((GameObject *)obj)->extra;

    switch (((GameObject *)obj)->anim.seqId) {
    case 0xb:
        if ((((GfxEmitState *)state)->spinTimer -= framesThisStep) <= 0) {
            ((GfxEmitState *)state)->spinSpeed = (f32)(int)randomGetRange(600, 800);
            ((GfxEmitState *)state)->spinTimer = (s16)randomGetRange(180, 240);
            Sfx_PlayFromObject(obj, SFXwp_whiz3_c);
        }
        ((GameObject *)obj)->anim.rotY = ((GfxEmitState *)state)->spinSpeed;
        ((GfxEmitState *)state)->spinSpeed *= lbl_803E3478;
        if (((GameObject *)obj)->anim.rotY < 10 && ((GameObject *)obj)->anim.rotY > -10) {
            ((GameObject *)obj)->anim.rotY = 0;
        }
        break;
    case 0x12d:
    case 0x135:
    case 0x137:
    case 0x156:
    case 0x246:
        *(s16 *)obj = lbl_803E347C * timeDelta + (f32)*(s16 *)obj;
        break;
    case 0x22:
        *(s16 *)obj = lbl_803E347C * timeDelta + (f32)*(s16 *)obj;
        itemPickupDoParticleFx(obj, lbl_803E3454, 10, 1);
        break;
    case 0x27f:
        if (*(f32 *)state < lbl_803E347C) {
            if ((int)randomGetRange(0, 10) == 0) {
                (*gPartfxInterface)->spawnObject((void *)obj, 0x423, NULL, 2,
                                                                    -1, NULL);
            }
            *(s16 *)obj += (s16)(lbl_803E3480 * timeDelta);
        }
        break;
    case 0x5e8:
        *(s16 *)obj = lbl_803E347C * timeDelta + (f32)*(s16 *)obj;
        itemPickupDoParticleFx(obj, lbl_803E3454, 9, 1);
        break;
    }
}
