#include "main/dll/dll_80220608_shared.h"
#include "main/obj_placement.h"
#include "main/game_object.h"

#define RING_EXTRA_SIZE 0x24

#define RING_OBJ_ARW_GOLD 0x060b
#define RING_OBJ_ARW_SILVER 0x060c
#define RING_OBJ_WC_SUN 0x07fb
#define RING_OBJ_WC_MOON 0x07fc
#define RING_OBJ_AND_SILVER 0x0819

#define RING_MODE_SILVER 0
#define RING_MODE_GOLD 2
#define RING_MODE_WC_MOON 3
#define RING_MODE_WC_SUN 4

#define RING_ROUTE_STATIONARY_SHOT 2
#define RING_ROUTE_MOVING_SHOT_A 3
#define RING_ROUTE_MOVING_AXIS_A 4
#define RING_ROUTE_MOVING_SHOT_B 5

#define RING_PHASE_HIDDEN 0
#define RING_PHASE_ACTIVE 1
#define RING_PHASE_PULL_TO_ARWING 2
#define RING_PHASE_COLLECTED 3

#define RING_SETUP_MODE_FLAG_OFFSET 0x18
#define RING_SETUP_ROUTE_OFFSET 0x19
#define RING_SETUP_LINK_ID_OFFSET 0x1a
#define RING_SETUP_PULL_HEIGHT_OFFSET 0x1c
#define RING_SETUP_ACTIVATE_BIT_OFFSET 0x20

#define RING_STATE_MODE 0x00
#define RING_STATE_ROUTE 0x01
#define RING_STATE_LINK_ID 0x02
#define RING_STATE_PULL_HEIGHT 0x04
#define RING_STATE_ORIG_X 0x08
#define RING_STATE_ORIG_Y 0x0c
#define RING_STATE_ARWING_Y_OFFSET 0x10
#define RING_STATE_FLAGS 0x14
#define RING_STATE_PHASE 0x15
#define RING_STATE_PULL_TIMER 0x18
#define RING_STATE_LIGHT 0x20

#define RING_ALPHA_OPAQUE 0xff
#define RING_SCORE_VALUE 0xf
#define RING_SHOT_TYPE_A 0x604
#define RING_SHOT_TYPE_B 0x605
#define RING_PARTFX_FLAGS 0x200001
#define RING_MODEL_DEFAULT 0
#define RING_MODEL_ALT 1
#define RING_OBJFLAG_HIDDEN 0x4000

#define RING_MODE(state) (*(u8 *)((state) + RING_STATE_MODE))
#define RING_ROUTE(state) (*(u8 *)((state) + RING_STATE_ROUTE))
#define RING_LINK_ID(state) (*(u16 *)((state) + RING_STATE_LINK_ID))
#define RING_PULL_HEIGHT(state) (*(f32 *)((state) + RING_STATE_PULL_HEIGHT))
#define RING_ORIG_X(state) (*(f32 *)((state) + RING_STATE_ORIG_X))
#define RING_ORIG_Y(state) (*(f32 *)((state) + RING_STATE_ORIG_Y))
#define RING_ARWING_Y_OFFSET(state) (*(f32 *)((state) + RING_STATE_ARWING_Y_OFFSET))
#define RING_FLAGS_BYTE(state) (*(u8 *)((state) + RING_STATE_FLAGS))
#define RING_PHASE(state) (*(u8 *)((state) + RING_STATE_PHASE))
#define RING_PULL_TIMER(state) (*(f32 *)((state) + RING_STATE_PULL_TIMER))
#define RING_LIGHT(state) (*(void **)((state) + RING_STATE_LIGHT))

#pragma peephole on
#pragma scheduling on
int ring_getExtraSize(void) { return RING_EXTRA_SIZE; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int ring_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void ring_free(int obj)
{
    int state = *(int *)(obj + 0xb8);
    if (RING_LIGHT(state) != NULL) {
        ModelLightStruct_free(RING_LIGHT(state));
        RING_LIGHT(state) = NULL;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void ring_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void ring_render(int obj, int p2, int p3, int p4, int p5, f32 scale)
{
    int state = *(int *)(obj + 0xb8);
    if (RING_LIGHT(state) != NULL && modelLightStruct_getActiveState(RING_LIGHT(state)) != 0) {
        queueGlowRender(RING_LIGHT(state));
    }
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E70B0);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void ring_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void ring_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void ring_init(int obj, int setup) {
    int state = *(int *)(obj + 0xb8);
    RingFlags *f = (RingFlags *)(state + RING_STATE_FLAGS);
    s16 type = ((GameObject *)obj)->anim.seqId;
    if (type == RING_OBJ_ARW_SILVER) {
        RING_MODE(state) = RING_MODE_SILVER;
    } else if (type == RING_OBJ_AND_SILVER) {
        RING_MODE(state) = RING_MODE_SILVER;
        f->bit10 = 1;
    } else if (type == RING_OBJ_ARW_GOLD) {
        RING_MODE(state) = RING_MODE_GOLD;
    } else if (type == RING_OBJ_WC_MOON) {
        RING_MODE(state) = RING_MODE_WC_MOON;
    } else if (type == RING_OBJ_WC_SUN) {
        RING_MODE(state) = RING_MODE_WC_SUN;
    } else {
        RING_MODE(state) = RING_MODE_GOLD;
    }
    RING_ROUTE(state) = *(u8 *)(setup + RING_SETUP_ROUTE_OFFSET);
    if (RING_ROUTE(state) == RING_ROUTE_STATIONARY_SHOT || RING_ROUTE(state) == RING_ROUTE_MOVING_SHOT_A ||
        RING_ROUTE(state) == RING_ROUTE_MOVING_SHOT_B) {
        f->bit80 = 0;
        Obj_SetActiveModelIndex(obj, RING_MODEL_ALT);
    } else {
        f->bit80 = 1;
        ObjHits_DisableObject(obj);
    }
    RING_LINK_ID(state) = *(s16 *)(setup + RING_SETUP_LINK_ID_OFFSET);
    RING_PULL_HEIGHT(state) = (f32)*(s16 *)(setup + RING_SETUP_PULL_HEIGHT_OFFSET) / lbl_803E70C4;
    RING_ORIG_X(state) = ((GameObject *)obj)->anim.localPosX;
    RING_ORIG_Y(state) = ((GameObject *)obj)->anim.localPosY;
    if (*(s8 *)(setup + RING_SETUP_MODE_FLAG_OFFSET) != 0)
        f->bit20 = 1;
    else
        f->bit20 = 0;
    *(s16 *)obj = -32768;
    if (RING_MODE(state) == RING_MODE_WC_MOON || RING_MODE(state) == RING_MODE_WC_SUN) {
        f->bit10 = 1;
        RING_ARWING_Y_OFFSET(state) = lbl_803E70D8;
    } else {
        ((GameObject *)obj)->anim.flags |= RING_OBJFLAG_HIDDEN;
        *(u8 *)(obj + 0x36) = 0;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma scheduling off
void ring_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int arwing;
    int setup = *(int *)(obj + 0x4c);
    int bit;
    int r;
    int hitA;
    int hitB;
    int hit;
    int ang;
    f32 dir[3];
    f32 spawnBuf[6];
    f32 mtx[12];

    arwing = getArwing();
    if (arwing == 0)
        arwing = Obj_GetPlayerObject();

    switch (RING_PHASE(state)) {
    case RING_PHASE_HIDDEN:
        r = (int)((f32)(u32) * (u8 *)(obj + 0x36) - lbl_803E70B4 * timeDelta);
        if (r < 0) {
            r = 0;
            ((GameObject *)obj)->anim.flags = (s16)(((GameObject *)obj)->anim.flags | RING_OBJFLAG_HIDDEN);
        }
        *(u8 *)(obj + 0x36) = (u8)r;
        bit = *(s16 *)(setup + RING_SETUP_ACTIVATE_BIT_OFFSET);
        if (bit > -1) {
            if (GameBit_Get(bit) != 0) {
                ((GameObject *)obj)->anim.flags = (s16)(((GameObject *)obj)->anim.flags & ~RING_OBJFLAG_HIDDEN);
                RING_PHASE(state) = RING_PHASE_ACTIVE;
            }
        } else {
            if (getArwing() != 0) {
                ((GameObject *)obj)->anim.flags = (s16)(((GameObject *)obj)->anim.flags & ~RING_OBJFLAG_HIDDEN);
                RING_PHASE(state) = RING_PHASE_ACTIVE;
            }
        }
        return;
    case RING_PHASE_ACTIVE:
        r = (int)((f32)(u32) * (u8 *)(obj + 0x36) + lbl_803E70B4 * timeDelta);
        if (r > RING_ALPHA_OPAQUE) r = RING_ALPHA_OPAQUE;
        *(u8 *)(obj + 0x36) = (u8)r;
        bit = *(s16 *)(setup + RING_SETUP_ACTIVATE_BIT_OFFSET);
        if (bit > -1) {
            if (GameBit_Get(bit) == 0)
                RING_PHASE(state) = RING_PHASE_ACTIVE;
        }
        switch (RING_ROUTE(state)) {
        case RING_ROUTE_MOVING_SHOT_A:
        case RING_ROUTE_MOVING_SHOT_B:
            if (ObjHits_GetPriorityHit(obj, &hitA, 0, 0) != 0 && (hit = hitA) != 0 &&
                (*(s16 *)(hit + 0x46) == RING_SHOT_TYPE_A || *(s16 *)(hit + 0x46) == RING_SHOT_TYPE_B)) {
                getArwing();
                arwarwing_addScore(getArwing(), RING_SCORE_VALUE);
                ((GameObject *)obj)->anim.rootMotionScale = *(f32 *)(*(int *)(obj + 0x50) + 4);
                Obj_SetActiveModelIndex(obj, RING_MODEL_DEFAULT);
                ObjHits_DisableObject(obj);
                RING_FLAGS_BYTE(state) |= 0x80;
                if (RING_LIGHT(state) != NULL) {
                    ModelLightStruct_free(RING_LIGHT(state));
                    *(int *)(state + RING_STATE_LIGHT) = 0;
                }
            }
            arwbombcoll_updateMovingAxis(obj, state);
            break;
        case RING_ROUTE_STATIONARY_SHOT:
            if (ObjHits_GetPriorityHit(obj, &hitB, 0, 0) != 0 && (hit = hitB) != 0 &&
                (*(s16 *)(hit + 0x46) == RING_SHOT_TYPE_A || *(s16 *)(hit + 0x46) == RING_SHOT_TYPE_B)) {
                getArwing();
                arwarwing_addScore(getArwing(), RING_SCORE_VALUE);
                ((GameObject *)obj)->anim.rootMotionScale = *(f32 *)(*(int *)(obj + 0x50) + 4);
                Obj_SetActiveModelIndex(obj, RING_MODEL_DEFAULT);
                ObjHits_DisableObject(obj);
                RING_FLAGS_BYTE(state) |= 0x80;
                if (RING_LIGHT(state) != NULL) {
                    ModelLightStruct_free(RING_LIGHT(state));
                    *(int *)(state + RING_STATE_LIGHT) = 0;
                }
            }
            break;
        case 1:
        case RING_ROUTE_MOVING_AXIS_A:
            arwbombcoll_updateMovingAxis(obj, state);
            break;
        }
        if ((RING_FLAGS_BYTE(state) & 0x80) != 0) {
            if (fn_8022D750(arwing) == 0 && fn_8022D710(arwing) == 0 &&
                arwbombcoll_checkArwingCollision(obj, state, arwing) != 0) {
                arwbombcoll_handleArwingHit(obj, state, arwing);
            }
        }
        *(s16 *)(obj + 0) =
            (s16)(int)((f32)(int) * (s16 *)(obj + 0) + lbl_803E70B8 * timeDelta);
        break;
    case RING_PHASE_PULL_TO_ARWING:
        if (RING_PULL_TIMER(state) > lbl_803E70A0) {
            if (arwing != 0) {
                *(f32 *)(obj + 0x24) =
                    oneOverTimeDelta * (*(f32 *)(arwing + 0xc) - ((GameObject *)obj)->anim.localPosX);
                ((GameObject *)obj)->anim.velocityY =
                    oneOverTimeDelta *
                    (RING_ARWING_Y_OFFSET(state) + (*(f32 *)(arwing + 0x10) - ((GameObject *)obj)->anim.localPosY));
                ((GameObject *)obj)->anim.velocityZ =
                    oneOverTimeDelta * (*(f32 *)(arwing + 0x14) - ((GameObject *)obj)->anim.localPosZ);
                objMove(obj, *(f32 *)(obj + 0x24) * timeDelta, ((GameObject *)obj)->anim.velocityY * timeDelta,
                        ((GameObject *)obj)->anim.velocityZ * timeDelta);
            }
            if (RING_PULL_TIMER(state) > lbl_803E70BC) {
                *(s16 *)(obj + 0) =
                    (s16)(*(s16 *)(obj + 0) + lbl_8032B720[RING_MODE(state)].f10);
                ((GameObject *)obj)->anim.rootMotionScale = (RING_PULL_TIMER(state) - lbl_803E70BC) / lbl_803E70BC *
                                    *(f32 *)(*(int *)(obj + 0x50) + 4);
                if (lbl_803E70C0 != RING_PULL_TIMER(state)) {
                    Obj_BuildWorldTransformMatrix(obj, mtx, 0);
                    for (ang = -0x7fff; ang < 0x7fff;
                         ang += lbl_8032B720[RING_MODE(state)].f8) {
                        dir[0] = lbl_803E70C4 *
                                 sin(lbl_803E70C8 *
                                     (f32)(ang +
                                           (int)(RING_PULL_TIMER(state) *
                                                 lbl_8032B720[RING_MODE(state)].f14)) /
                                     lbl_803E70CC);
                        dir[1] = lbl_803E70C4 *
                                 fn_80293E80(lbl_803E70C8 *
                                             (f32)(ang +
                                                   (int)(RING_PULL_TIMER(state) *
                                                         lbl_8032B720[RING_MODE(state)].f14)) /
                                             lbl_803E70CC);
                        dir[2] = lbl_803E70A0;
                        PSMTXMultVecSR(mtx, dir, dir);
                        spawnBuf[3] = dir[0] + ((GameObject *)obj)->anim.localPosX;
                        spawnBuf[4] = dir[1] + ((GameObject *)obj)->anim.localPosY;
                        spawnBuf[5] = dir[2] + ((GameObject *)obj)->anim.localPosZ;
                        (*(void (**)(int, int, f32 *, int, int, int))(*gPartfxInterface + 8))(
                            obj, lbl_8032B720[RING_MODE(state)].f0, spawnBuf, RING_PARTFX_FLAGS, -1,
                            obj + 0x24);
                        (*(void (**)(int, int, f32 *, int, int, int))(*gPartfxInterface + 8))(
                            obj, lbl_8032B720[RING_MODE(state)].f0, spawnBuf, RING_PARTFX_FLAGS, -1,
                            obj + 0x24);
                    }
                }
                RING_FLAGS_BYTE(state) |= 0x40;
            } else {
                if ((RING_FLAGS_BYTE(state) & 0x40) != 0) {
                    for (ang = 0; ang < lbl_8032B720[RING_MODE(state)].fc; ang++) {
                        (*(void (**)(int, int, int, int, int, int))(*gPartfxInterface + 8))(
                            obj, lbl_8032B720[RING_MODE(state)].f4, 0, 2, -1, 0);
                    }
                }
                RING_FLAGS_BYTE(state) &= ~0x40;
                *(u8 *)(obj + 0x36) = 0;
            }
            RING_PULL_TIMER(state) -= timeDelta;
            if (RING_PULL_TIMER(state) <= lbl_803E70A0) {
                RING_PULL_TIMER(state) = lbl_803E70A0;
                ((GameObject *)obj)->anim.localPosX = ((ObjPlacement *)setup)->posX;
                ((GameObject *)obj)->anim.localPosY = ((ObjPlacement *)setup)->posY;
                ((GameObject *)obj)->anim.localPosZ = ((ObjPlacement *)setup)->posZ;
                *(s16 *)(obj + 0) = 0;
                *(u8 *)(obj + 0x36) = RING_ALPHA_OPAQUE;
                ((GameObject *)obj)->anim.rootMotionScale = *(f32 *)(*(int *)(obj + 0x50) + 4);
                *(f32 *)(obj + 0x24) = lbl_803E70A0;
                ((GameObject *)obj)->anim.velocityY = lbl_803E70A0;
                ((GameObject *)obj)->anim.velocityZ = lbl_803E70A0;
                RING_PHASE(state) = RING_PHASE_COLLECTED;
                ((GameObject *)obj)->anim.flags = (s16)(((GameObject *)obj)->anim.flags | RING_OBJFLAG_HIDDEN);
            }
        } else {
            RING_PULL_TIMER(state) = lbl_803E70C0;
        }
        break;
    }

    if (RING_LIGHT(state) != NULL && modelLightStruct_getActiveState(RING_LIGHT(state)) != 0) {
        modelLightStruct_updateGlowAlpha(RING_LIGHT(state));
    }
}
#pragma scheduling reset
