#ifndef MAIN_DLL_WC_DLL_028D_WCLEVELCONT_H_
#define MAIN_DLL_WC_DLL_028D_WCLEVELCONT_H_

#include "global.h"
#include "main/dll/SC/SCtotemlogpuz.h"
#include "main/game_object.h"
#include "main/objanim_update.h"

typedef struct WCLevelContInterface WCLevelContInterface;

struct WCLevelContInterface
{
    u8 pad00[0x20];
    void (*tileAToWorldPos)(GameObject* obj, int tileX, int tileY, f32* outX, f32* outZ,
                            WCLevelContInterface* iface);
    void (*worldPosToTileA)(GameObject* obj, f32 x, f32 z, s16* outTileX, s16* outTileY,
                            WCLevelContInterface* iface);
    void (*setTileA)(int value, int tileX, int tileY, WCLevelContInterface* iface);
    int (*getTileA)(int tileX, int tileY, WCLevelContInterface* iface);
    void (*getInitialTileXYA)(int value, s16* outTileX, s16* outTileY, WCLevelContInterface* iface);
    void (*getSolvedTileXYA)(int value, s16* outTileX, s16* outTileY, WCLevelContInterface* iface);
    u8 (*traceMoveA)(GameObject* obj, int tileX, int tileY, f32* outX, f32* outZ, int dx, int dy,
                     WCLevelContInterface* iface);
    void (*tileBToWorldPos)(GameObject* obj, int tileX, int tileY, f32* outX, f32* outZ,
                            WCLevelContInterface* iface);
    void (*worldPosToTileB)(GameObject* obj, f32 x, f32 z, s16* outTileX, s16* outTileY,
                            WCLevelContInterface* iface);
    void (*setTileB)(int value, int tileX, int tileY, WCLevelContInterface* iface);
    int (*getTileB)(int tileX, int tileY, WCLevelContInterface* iface);
    void (*getInitialTileXYB)(int value, s16* outTileX, s16* outTileY, WCLevelContInterface* iface);
    void (*getSolvedTileXYB)(int value, s16* outTileX, s16* outTileY, WCLevelContInterface* iface);
    u8 (*traceMoveB)(GameObject* obj, int tileX, int tileY, f32* outX, f32* outZ, int dx, int dy,
                     WCLevelContInterface* iface);
};

#define WC_LEVEL_CONT_INTERFACE(controller) (*(WCLevelContInterface**)((controller)->anim.dll))

STATIC_ASSERT(offsetof(WCLevelContInterface, tileAToWorldPos) == 0x20);
STATIC_ASSERT(offsetof(WCLevelContInterface, worldPosToTileA) == 0x24);
STATIC_ASSERT(offsetof(WCLevelContInterface, setTileA) == 0x28);
STATIC_ASSERT(offsetof(WCLevelContInterface, getTileA) == 0x2C);
STATIC_ASSERT(offsetof(WCLevelContInterface, getInitialTileXYA) == 0x30);
STATIC_ASSERT(offsetof(WCLevelContInterface, getSolvedTileXYA) == 0x34);
STATIC_ASSERT(offsetof(WCLevelContInterface, traceMoveA) == 0x38);
STATIC_ASSERT(offsetof(WCLevelContInterface, tileBToWorldPos) == 0x3C);
STATIC_ASSERT(offsetof(WCLevelContInterface, worldPosToTileB) == 0x40);
STATIC_ASSERT(offsetof(WCLevelContInterface, setTileB) == 0x44);
STATIC_ASSERT(offsetof(WCLevelContInterface, getTileB) == 0x48);
STATIC_ASSERT(offsetof(WCLevelContInterface, getInitialTileXYB) == 0x4C);
STATIC_ASSERT(offsetof(WCLevelContInterface, getSolvedTileXYB) == 0x50);
STATIC_ASSERT(offsetof(WCLevelContInterface, traceMoveB) == 0x54);

typedef struct WclevelcontFlags
{
    u8 b80 : 1;
    u8 b40 : 1;
    u8 b20 : 1;
    u8 b18 : 2;
    u8 b07 : 3;
} WclevelcontFlags;

#define WCLEVELCTL_FLAG_TRIGGERED    0x1
#define WCLEVELCTL_FLAG_EVENT_ACTIVE 0x2
#define WCLEVELCTL_FLAG_PUZZLE_A     0x4
#define WCLEVELCTL_FLAG_PUZZLE_B     0x8
#define WCLEVELCTL_FLAG_TILE_A       0x10
#define WCLEVELCTL_FLAG_TILE_B       0x20
#define WCLEVELCTL_FLAG_TREX         0x40
#define WCLEVELCTL_FLAG_SWITCHES     0x80
#define WCLEVELCTL_FLAG_FINAL        0x100
#define WCLEVELCTL_FLAG_EXTRA        0x200

#define WCLEVELCTL_MODE_IDLE        0
#define WCLEVELCTL_MODE_PUZZLE_A    1
#define WCLEVELCTL_MODE_PUZZLE_B    2
#define WCLEVELCTL_MODE_SEQUENCE    3
#define WCLEVELCTL_MODE_TREX_ACTIVE 4
#define WCLEVELCTL_MODE_TREX_INIT   6
#define WCLEVELCTL_MODE_DONE        7

typedef struct WcLevelControlState
{
    f32 eventTimer;
    f32 tileBResetTimer;
    f32 tileAResetTimer;
    u8 mode;
    u8 previousMode;
    u8 pad0E[0x10 - 0x0E];
    SCGameBitLatchState gameBitLatch;
    WclevelcontFlags dialogueFlags;
    u8 pad15;
    u16 thorntailMusicId;
    u16 ambientMusicId;
    u16 completionFlags;
} WcLevelControlState;

STATIC_ASSERT(sizeof(WclevelcontFlags) == 1);
STATIC_ASSERT(sizeof(WcLevelControlState) == 0x1C);
STATIC_ASSERT(offsetof(WcLevelControlState, eventTimer) == 0x00);
STATIC_ASSERT(offsetof(WcLevelControlState, tileBResetTimer) == 0x04);
STATIC_ASSERT(offsetof(WcLevelControlState, tileAResetTimer) == 0x08);
STATIC_ASSERT(offsetof(WcLevelControlState, mode) == 0x0C);
STATIC_ASSERT(offsetof(WcLevelControlState, previousMode) == 0x0D);
STATIC_ASSERT(offsetof(WcLevelControlState, gameBitLatch) == 0x10);
STATIC_ASSERT(offsetof(WcLevelControlState, dialogueFlags) == 0x14);
STATIC_ASSERT(offsetof(WcLevelControlState, thorntailMusicId) == 0x16);
STATIC_ASSERT(offsetof(WcLevelControlState, ambientMusicId) == 0x18);
STATIC_ASSERT(offsetof(WcLevelControlState, completionFlags) == 0x1A);

extern u8 lbl_8032B0C8[][8];
extern u8 lbl_8032B088[][8];
extern u8 lbl_8032B048[][8];
extern u8 lbl_8032B008[][8];
extern u8 lbl_803AD298[][8];
extern u8 lbl_803AD2D8[][8];
extern f32 gWcPushBlockTileResetTime;

void wclevelcont_getSolvedTileXYB(s16 value, s16* outRow, s16* outCol);
void wclevelcont_getInitialTileXYB(s16 value, s16* outRow, s16* outCol);
int wclevelcont_getTileB(s16 i, s16 j);
void wclevelcont_setTileB(int value, s16 i, s16 j);
void wclevelcont_worldPosToTileB(GameObject* obj, f32 px, f32 pz, s16* outRow, s16* outCol);
void wclevelcont_tileBToWorldPos(GameObject* obj, s16 col, s16 row, f32* outX, f32* outZ);
void wclevelcont_getSolvedTileXYA(s16 value, s16* outRow, s16* outCol);
void wclevelcont_getInitialTileXYA(s16 value, s16* outRow, s16* outCol);
int wclevelcont_getTileA(s16 i, s16 j);
void wclevelcont_setTileA(int value, s16 i, s16 j);
void wclevelcont_worldPosToTileA(GameObject* obj, f32 px, f32 pz, s16* outRow, s16* outCol);
void wclevelcont_tileAToWorldPos(GameObject* obj, s16 col, s16 row, f32* outX, f32* outZ);
int wclevelcont_getExtraSize(void);
int wclevelcont_getObjectTypeId(void);
void wclevelcont_free(GameObject* obj);
void wclevelcont_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void wclevelcont_hitDetect(void);
void wclevelcont_syncProgressBits(WcLevelControlState* state);
void wclevelcont_update(GameObject* obj);
void fn_802251B4(GameObject* obj, WcLevelControlState* state);
int wclevelcont_traceMoveA(GameObject* obj, s16 x, s16 y, f32* outX, f32* outZ, int dx, int dy);
void wcpushblock_updateLevelControlState(GameObject* obj, WcLevelControlState* state);
int wclevelcont_seqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int wclevelcont_traceMoveB(GameObject* obj, s16 x, s16 y, f32* outX, f32* outZ, int dx, int dy);
void wclevelcont_init(GameObject* obj);
void wclevelcont_release(void);
void wclevelcont_initialise(void);

#endif /* MAIN_DLL_WC_DLL_028D_WCLEVELCONT_H_ */
