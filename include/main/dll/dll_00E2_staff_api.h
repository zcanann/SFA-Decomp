#ifndef MAIN_DLL_DLL_00E2_STAFF_API_H_
#define MAIN_DLL_DLL_00E2_STAFF_API_H_

#include "game/objects/object.h"
#include "dlls/object_descriptor.h"

extern ObjectDescriptor23 gStaffObjDescriptor;

typedef struct SwipeVertex {
    f32 x;
    f32 y;
    f32 z;
    f32 life;
    s16 alpha;
    s16 pad12;
} SwipeVertex;

typedef struct StaffSwipeSlot {
    SwipeVertex* vertexData;
    f32 start;
    f32 lengthScale;
    u16 startIndex;
    u16 endIndex;
    s16 idx;
    s16 vertexCount;
    u8 flags;
    u8 pad15[3];
} StaffSwipeSlot;

typedef struct StaffState {
    StaffSwipeSlot slots[3];
    StaffSwipeSlot* activeSlot;
    u8 pad4C[4];
    f32 moveSpeed;
    f32 geometryPointAX[2];
    f32 geometryPointAY[2];
    f32 geometryPointAZ[2];
    f32 geometryPointBX[2];
    f32 geometryPointBY[2];
    f32 geometryPointBZ[2];
    u8 pad84[4];
    s16 hitReactValue;
    u8 pad8A[2];
    f32 anchorX;
    f32 anchorY;
    f32 anchorZ;
    f32 progress;
    u8 pad9C[14];
    u8 unkAA;
    u8 padAB[5];
    s16 unkB0;
    s16 fieldB2;
    u8 padB4[5];
    s8 swipeTextureIndex;
    u8 glowEnable;
    u8 glowAttackType;
    u8 hudSuppressed;
} StaffState;

typedef struct StaffQuakeSpellState {
    f32 posX;
    f32 posY;
    f32 posZ;
    f32 scale;
    f32 radius;
    f32 heightScale;
    f32 fade;
    GameObject* object;
    u8 active;
    u8 pad21[7];
} StaffQuakeSpellState;

STATIC_ASSERT(sizeof(SwipeVertex) == 0x14);
STATIC_ASSERT(sizeof(StaffSwipeSlot) == 0x18);
STATIC_ASSERT(offsetof(StaffSwipeSlot, start) == 0x04);
STATIC_ASSERT(offsetof(StaffSwipeSlot, flags) == 0x14);
STATIC_ASSERT(sizeof(StaffState) == 0xC0);
STATIC_ASSERT(offsetof(StaffState, activeSlot) == 0x48);
STATIC_ASSERT(offsetof(StaffState, moveSpeed) == 0x50);
STATIC_ASSERT(offsetof(StaffState, hitReactValue) == 0x88);
STATIC_ASSERT(offsetof(StaffState, anchorX) == 0x8C);
STATIC_ASSERT(offsetof(StaffState, progress) == 0x98);
STATIC_ASSERT(offsetof(StaffState, swipeTextureIndex) == 0xB9);
STATIC_ASSERT(offsetof(StaffState, hudSuppressed) == 0xBC);
STATIC_ASSERT(sizeof(StaffQuakeSpellState) == 0x28);
STATIC_ASSERT(offsetof(StaffQuakeSpellState, object) == 0x1C);
STATIC_ASSERT(offsetof(StaffQuakeSpellState, active) == 0x20);

/* gStaffObjDescriptor from slot02 onwards: the export table other objects
   reach through the player's staff child object (childObjs[0])->anim.dll. */
typedef struct StaffInterface {
    void* pad00[8];
    void (*func0A)(void);
    void (*func0B)(void);
    void (*updateSwipe)(GameObject* staff, GameObject* player, void* context);
    void (*hitDetectGeometry)(GameObject* staff);
    void (*func0E)(void);
    void (*func0F)(void);
    void (*func10)(GameObject* staff, s32 value);
    void (*setHitReactValue)(GameObject* staff, s32 value);
    void (*addHitReactValue)(GameObject* staff, s32 delta);
    int (*getHitReactValue)(GameObject* staff);
    void (*getHitGeometryPoints)(GameObject* staff, f32* outA, f32* outB);
    void (*startSwipe)(GameObject* staff, s16 index, f32 start, f32 lengthScale);
    s32 (*getSwipeTextureIndex)(GameObject* staff);
} StaffInterface;

#define STAFF_INTERFACE(staff) ((StaffInterface*)*((GameObject*)(staff))->anim.dll)

STATIC_ASSERT(offsetof(StaffInterface, updateSwipe) == 0x28);
STATIC_ASSERT(offsetof(StaffInterface, hitDetectGeometry) == 0x2C);
STATIC_ASSERT(offsetof(StaffInterface, func10) == 0x38);
STATIC_ASSERT(offsetof(StaffInterface, setHitReactValue) == 0x3C);
STATIC_ASSERT(offsetof(StaffInterface, addHitReactValue) == 0x40);
STATIC_ASSERT(offsetof(StaffInterface, getHitReactValue) == 0x44);
STATIC_ASSERT(offsetof(StaffInterface, getHitGeometryPoints) == 0x48);
STATIC_ASSERT(offsetof(StaffInterface, startSwipe) == 0x4C);
STATIC_ASSERT(offsetof(StaffInterface, getSwipeTextureIndex) == 0x50);
STATIC_ASSERT(sizeof(StaffInterface) == 0x54);

void objSetAnimField48to0(GameObject* obj);
void staffUpdateWhileTimeStopped(GameObject* obj);
void staffUpdateAttackEffects(GameObject* obj, GameObject* player);
void staffDrawQuakeSpellRing(void);
void staff_addHitReactValue(GameObject* obj, s32 delta);
void staffDoGrowShrinkAnim(GameObject* obj, u8 grow, u8 alternateRate, int unused);
void staff_free(GameObject* obj);
void staff_func0B(void);
void staff_func0E(void);
void staff_func0F(void);
void staff_func10(GameObject* obj, s32 value);
int staff_getExtraSize(void);
void staff_getHitGeometryPoints(GameObject* obj, f32* outA, f32* outB);
s16 staff_getHitReactValue(GameObject* obj);
int staff_getObjectTypeId(void);
s32 staff_getSwipeTextureIndex(GameObject* obj);
void staff_hitDetect(void);
void staff_hitDetectGeometry(GameObject* obj);
void staff_init(GameObject* obj);
void staff_initialise(void);
void staff_updateSwipe(GameObject* staff, GameObject* player, int context);
void staff_release(void);
void staff_render(void);
void staffSetGlow(GameObject* obj, u8 attackType, u8 enable);
void staff_func0A(void);
void staff_setHitReactValue(GameObject* obj, s32 value);
void staff_setupSwipe(int staff, StaffState* state, int context, int player);
void staff_startSwipe(GameObject* obj, s16 index, f32 start, f32 lengthScale);
void staff_update(GameObject* obj);
void staffStartQuakeSpell(f32* position);

#endif /* MAIN_DLL_DLL_00E2_STAFF_API_H_ */
