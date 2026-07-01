#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

#define WCBLOCK_GRID_OBJECT_OFFSET 0x268
#define WCBLOCK_CELL_X_OFFSET 0x27e
#define WCBLOCK_CELL_Z_OFFSET 0x280
#define WCBLOCK_TILE_INDEX_OFFSET 0x283
#define WCBLOCK_VARIANT_A 1

#define WCBLOCK_GRID_IFACE(state) (*(WCBlockGridInterface **)(*(int *)((state)->controller + 0x68)))

typedef struct WCBlockGridInterface
{
    char pad0[0x20];
    void (*getCellWorldA)(int obj, s16 cellX, s16 cellZ, f32* worldX, f32* worldZ, struct WCBlockGridInterface* self);
    char pad24[0x0c];
    void (*getCellXYA)(u8 tileIndex, s16* cellX, s16* cellZ, struct WCBlockGridInterface* self);
    char pad34[0x08];
    void (*getCellWorldB)(int obj, s16 cellX, s16 cellZ, f32* worldX, f32* worldZ, struct WCBlockGridInterface* self);
    char pad40[0x0c];
    void (*getCellXYB)(u8 tileIndex, s16* cellX, s16* cellZ, struct WCBlockGridInterface* self);
} WCBlockGridInterface;

typedef struct WCBlockState
{
    u8 pad00[WCBLOCK_GRID_OBJECT_OFFSET];
    int controller;
    u8 pad26C[WCBLOCK_CELL_X_OFFSET - (WCBLOCK_GRID_OBJECT_OFFSET + 4)];
    s16 cellX;
    s16 cellZ;
    u8 pad282[WCBLOCK_TILE_INDEX_OFFSET - (WCBLOCK_CELL_Z_OFFSET + 2)];
    u8 tileIndex;
} WCBlockState;

STATIC_ASSERT(offsetof(WCBlockState, controller) == WCBLOCK_GRID_OBJECT_OFFSET);
STATIC_ASSERT(offsetof(WCBlockState, cellX) == WCBLOCK_CELL_X_OFFSET);
STATIC_ASSERT(offsetof(WCBlockState, cellZ) == WCBLOCK_CELL_Z_OFFSET);
STATIC_ASSERT(offsetof(WCBlockState, tileIndex) == WCBLOCK_TILE_INDEX_OFFSET);

#define WBOUNCY_EXTRA_SIZE 0xc
#define WBOUNCY_STATE_HOME_Y 0x00
#define WBOUNCY_STATE_COOLDOWN 0x08
#define WBOUNCY_STATE_FLAGS 0x0a
#define WBOUNCY_STATE_BOUNCE_COUNT 0x0b
#define WBOUNCY_FLAG_ACTIVE 1
#define WBOUNCY_TRIGGER_GROUP 3
#define WBOUNCY_RESET_COOLDOWN 0x28
#define WBOUNCY_MAX_BOUNCES 0xa

typedef struct WCBouncyCrateState
{
    f32 homeY;
    u8 pad04[0x08 - 0x04];
    s16 cooldown;
    u8 flags;
    u8 bounceCount;
} WCBouncyCrateState;

STATIC_ASSERT(sizeof(WCBouncyCrateState) == WBOUNCY_EXTRA_SIZE);
STATIC_ASSERT(offsetof(WCBouncyCrateState, homeY) == WBOUNCY_STATE_HOME_Y);
STATIC_ASSERT(offsetof(WCBouncyCrateState, cooldown) == WBOUNCY_STATE_COOLDOWN);
STATIC_ASSERT(offsetof(WCBouncyCrateState, flags) == WBOUNCY_STATE_FLAGS);
STATIC_ASSERT(offsetof(WCBouncyCrateState, bounceCount) == WBOUNCY_STATE_BOUNCE_COUNT);

int wcbouncycra_getExtraSize(void) { return WBOUNCY_EXTRA_SIZE; }

int wcbouncycra_getObjectTypeId(void) { return 0; }

void wcbouncycra_free(void)
{
}

void wcbouncycra_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6D38);
    }
}

void wcbouncycra_hitDetect(void)
{
}

#pragma scheduling off
void wcbouncycra_update(int obj)
{
    WCBouncyCrateState* state = ((GameObject*)obj)->extra;

    if ((state->flags & WBOUNCY_FLAG_ACTIVE) == 0)
    {
        s16 n = (s16)((f32)state->cooldown - timeDelta);
        state->cooldown = n;
        if (n <= 0)
        {
            f32 dist;
            f32 v = gBouncyCrateTriggerSearchRadius;

            if ((void*)ObjGroup_FindNearestObject(WBOUNCY_TRIGGER_GROUP, obj, &v) == NULL)
            {
                dist = lbl_803E6D24;
            }
            else
            {
                f32 vv = v;
                dist = gBouncyCrateNearDistance;
                if (vv < dist)
                {
                    dist = lbl_803E6D2C;
                }
                else if (vv > gBouncyCrateFarDistance)
                {
                    dist = lbl_803E6D24;
                }
                else
                {
                    dist = (vv - dist) / lbl_803E6D34;
                    dist = lbl_803E6D38 - dist;
                    dist = dist * lbl_803E6D2C;
                }
            }
            ((GameObject*)obj)->anim.velocityY = dist;
            state->flags |= WBOUNCY_FLAG_ACTIVE;
            state->bounceCount = 0;
        }
    }
    else
    {
        ((GameObject*)obj)->anim.velocityY = gBouncyCrateGravity * timeDelta + ((GameObject*)obj)->anim.velocityY;
        ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.velocityY * timeDelta + ((GameObject*)obj)->anim.
            localPosY;
        if (((GameObject*)obj)->anim.localPosY <= state->homeY)
        {
            ((GameObject*)obj)->anim.localPosY =
                ((GameObject*)obj)->anim.localPosY + (state->homeY - ((GameObject*)obj)->anim.localPosY);
            ((GameObject*)obj)->anim.velocityY = gBouncyCrateRestitution * -((GameObject*)obj)->anim.velocityY;
            state->bounceCount += 1;
            if (state->bounceCount > WBOUNCY_MAX_BOUNCES)
            {
                state->flags &= ~WBOUNCY_FLAG_ACTIVE;
                state->cooldown = WBOUNCY_RESET_COOLDOWN;
                ((GameObject*)obj)->anim.localPosY = state->homeY;
                ((GameObject*)obj)->anim.velocityY = lbl_803E6D24;
            }
        }
    }
}

#pragma scheduling reset
void wcbouncycra_init(int obj, int setup)
{
    WCBouncyCrateState* state = ((GameObject*)obj)->extra;

    state->homeY = ((ObjPlacement*)setup)->posY;
    state->cooldown = WBOUNCY_RESET_COOLDOWN;
}

void wcbouncycra_release(void)
{
}

void wcbouncycra_initialise(void)
{
}

#pragma scheduling off
int wcblock_isPlayerAwayFromStoredCell(int obj, int stateArg, int player)
{
    WCBlockState* state = (WCBlockState*)stateArg;
    ObjAnimComponent* objAnim;
    GameObject* playerObj;
    f32 cellX;
    f32 cellZ;
    f32 pos;
    f32 min;
    f32 max;
    WCBlockGridInterface* iface;

    objAnim = (ObjAnimComponent*)obj;
    if (objAnim->bankIndex == WCBLOCK_VARIANT_A)
    {
        iface->getCellXYA(
            state->tileIndex, &state->cellX, &state->cellZ, (iface = WCBLOCK_GRID_IFACE(state)));
        iface->getCellWorldA(
            obj, state->cellX, state->cellZ, &cellX, &cellZ, (iface = WCBLOCK_GRID_IFACE(state)));
    }
    else
    {
        iface->getCellXYB(
            state->tileIndex, &state->cellX, &state->cellZ, (iface = WCBLOCK_GRID_IFACE(state)));
        iface->getCellWorldB(
            obj, state->cellX, state->cellZ, &cellX, &cellZ, (iface = WCBLOCK_GRID_IFACE(state)));
    }

    min = cellX - WCBLOCK_PLAYER_CELL_MARGIN;
    playerObj = (GameObject*)player;
    pos = playerObj->anim.localPosX;
    max = WCBLOCK_PLAYER_CELL_MARGIN + cellX;
    if (pos > max || pos < min)
    {
        return 1;
    }

    {
        f32 posZ;
        f32 minZ;
        f32 maxZ;

        minZ = cellZ - WCBLOCK_PLAYER_CELL_MARGIN;
        posZ = playerObj->anim.localPosZ;
        maxZ = WCBLOCK_PLAYER_CELL_MARGIN + cellZ;
        if (posZ > maxZ || posZ < minZ)
        {
            return 1;
        }
    }

    return 0;
}

#undef WCBLOCK_GRID_IFACE
