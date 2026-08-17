/*
 * BaddieInterestP object (DLL slot 222).
 *
 * Triggers a nearby matching baddie's reaction when its game-bit and
 * time-of-day conditions are satisfied.
 */
#include "dlls/objects/222_BaddieInterestP.h"
#include "main/dll/wispbaddieseq_ext.h"
#include "main/gamebits.h"
#include "main/objtype.h"
#include "main/object_render.h"
#include "main/sky_interface.h"
#include "main/vecmath.h"

#define BADDIE_INTEREST_OBJECT_GROUP              3
#define BADDIE_INTEREST_RANGE_SQUARED             1600.0f
#define BADDIE_INTEREST_PROBABILITY_MIN           1
#define BADDIE_INTEREST_PROBABILITY_MAX           100
#define BADDIE_INTEREST_SUN_MODE_MASK             0x30
#define BADDIE_INTEREST_SUN_MODE_SHIFT            4
#define BADDIE_INTEREST_REACTION_KIND_MASK        0xf
#define BADDIE_INTEREST_SUN_MODE_UNCONDITIONAL    0
#define BADDIE_INTEREST_SUN_MODE_POSITION_ZERO    1
#define BADDIE_INTEREST_SUN_MODE_POSITION_NONZERO 2
#define BADDIE_INTEREST_GAME_BIT_NONE             -1

ObjectDescriptor gBaddieInterestPObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)BaddieInterestP_initialise,
    (ObjectDescriptorCallback)BaddieInterestP_release,
    0,
    (ObjectDescriptorCallback)BaddieInterestP_init,
    (ObjectDescriptorCallback)BaddieInterestP_update,
    (ObjectDescriptorCallback)BaddieInterestP_hitDetect,
    (ObjectDescriptorCallback)BaddieInterestP_render,
    (ObjectDescriptorCallback)BaddieInterestP_free,
    (ObjectDescriptorCallback)BaddieInterestP_getObjectTypeId,
    BaddieInterestP_getExtraSize,
};

int BaddieInterestP_getExtraSize(void) {
    return 0;
}

int BaddieInterestP_getObjectTypeId(void) {
    return 0;
}

void BaddieInterestP_free(GameObject* obj) {
    (void)obj;
}

void BaddieInterestP_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 visible) {
    s32 visible32 = visible;
    if (visible32 != 0) {
        objRenderModelAndHitVolumes(obj, fwdArg2, fwdArg3, fwdArg4, fwdArg5, 1.0f);
    }
}

void BaddieInterestP_hitDetect(GameObject* obj) {
    (void)obj;
}

void BaddieInterestP_update(GameObject* obj) {
    BaddieInterestPPlacement* placement = (BaddieInterestPPlacement*)obj->anim.placementData;

    if (((int)placement->enableGameBit == BADDIE_INTEREST_GAME_BIT_NONE ||
         mainGetBit((int)placement->enableGameBit) != 0) &&
        ((int)placement->doneGameBit == BADDIE_INTEREST_GAME_BIT_NONE ||
         mainGetBit((int)placement->doneGameBit) == 0)) {
        int objectCount;
        GameObject** objects = objGetAllOfType(BADDIE_INTEREST_OBJECT_GROUP, &objectCount);
        if (objectCount > 0) {
            u32 targetLinkId = (u32)(u16)placement->targetLinkIdHi << 16;
            GameObject* candidate;
            u16 objectIndex;
            u8 foundTarget;
            targetLinkId |= (u16)placement->targetLinkIdLo;
            for (objectIndex = 0; objectIndex < objectCount; objectIndex++) {
                BaddieInterestPPlacement* candidatePlacement;
                candidate = (GameObject*)objects[objectIndex];
                candidatePlacement = (BaddieInterestPPlacement*)candidate->anim.placementData;
                if (candidatePlacement != NULL) {
                    foundTarget = 0;
                    if (targetLinkId == candidatePlacement->base.ident || targetLinkId == 0) {
                        foundTarget = 1;
                    }
                } else {
                    foundTarget = 1;
                }
                if (foundTarget != 0) {
                    foundTarget = 0;
                    if (vec3f_distanceSquared(&obj->anim.worldPosX, &candidate->anim.worldPosX) <
                        BADDIE_INTEREST_RANGE_SQUARED) {
                        if (obj->userData1 == 0) {
                            if (randomGetRange(BADDIE_INTEREST_PROBABILITY_MIN, BADDIE_INTEREST_PROBABILITY_MAX) <=
                                placement->triggerProbability) {
                                f32 sunTime;
                                GameObject* target;
                                int kind;
                                int modeKind = placement->modeKind;
                                switch ((modeKind & BADDIE_INTEREST_SUN_MODE_MASK) >> BADDIE_INTEREST_SUN_MODE_SHIFT) {
                                case BADDIE_INTEREST_SUN_MODE_UNCONDITIONAL: {
                                    kind = modeKind & BADDIE_INTEREST_REACTION_KIND_MASK;
                                    target = (GameObject*)objects[objectIndex];
                                    if ((int)placement->doneGameBit != BADDIE_INTEREST_GAME_BIT_NONE) {
                                        mainSetBits((int)placement->doneGameBit, 1);
                                    }
                                    switch (target->anim.romDefNo) {
                                    case 0x11:
                                    case 0x13a:
                                    case 0x5b7:
                                    case 0x5b8:
                                    case 0x5b9:
                                    case 0x5e1:
                                        wispBaddieQueueNextEvent((int)target, kind);
                                        break;
                                    }
                                    break;
                                }
                                case BADDIE_INTEREST_SUN_MODE_POSITION_ZERO:
                                    if ((*gSkyInterface)->getSunPosition(&sunTime) == 0) {
                                        GameObject* target;
                                        int kind;
                                        u8 modeKind = (u8)placement->modeKind;
                                        kind = modeKind & BADDIE_INTEREST_REACTION_KIND_MASK;
                                        target = (GameObject*)objects[objectIndex];
                                        if ((int)placement->doneGameBit != BADDIE_INTEREST_GAME_BIT_NONE) {
                                            mainSetBits((int)placement->doneGameBit, 1);
                                        }
                                        switch (target->anim.romDefNo) {
                                        case 0x11:
                                        case 0x13a:
                                        case 0x5b7:
                                        case 0x5b8:
                                        case 0x5b9:
                                        case 0x5e1:
                                            wispBaddieQueueNextEvent((int)target, kind);
                                            break;
                                        }
                                    }
                                    break;
                                case BADDIE_INTEREST_SUN_MODE_POSITION_NONZERO:
                                    if ((*gSkyInterface)->getSunPosition(&sunTime) != 0) {
                                        GameObject* target;
                                        int kind;
                                        u8 modeKind = (u8)placement->modeKind;
                                        kind = modeKind & BADDIE_INTEREST_REACTION_KIND_MASK;
                                        target = (GameObject*)objects[objectIndex];
                                        if ((int)placement->doneGameBit != BADDIE_INTEREST_GAME_BIT_NONE) {
                                            mainSetBits((int)placement->doneGameBit, 1);
                                        }
                                        switch (target->anim.romDefNo) {
                                        case 0x11:
                                        case 0x13a:
                                        case 0x5b7:
                                        case 0x5b8:
                                        case 0x5b9:
                                        case 0x5e1:
                                            wispBaddieQueueNextEvent((int)target, kind);
                                            break;
                                        }
                                    }
                                    break;
                                }
                            }
                            obj->userData1 = 1;
                        }
                        foundTarget = 1;
                    }
                    objectIndex = (u16)objectCount;
                }
            }
            if (foundTarget == 0) {
                obj->userData1 = 0;
            }
        }
    }
}

void BaddieInterestP_init(GameObject* obj) {
    (void)obj;
}

void BaddieInterestP_release(void) {
}

void BaddieInterestP_initialise(void) {
}
