#include "dlls/objects/202.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "game/objects/object.h"
#include "game/objects/object_setup.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/camera.h"
#include "main/camera_shake_api.h"
#include "main/dll/baddie_control_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "main/mapEventTypes.h"
#include "main/object_render.h"
#include "main/objtype.h"
#include "main/obj_message.h"
#include "main/obj_path.h"
#include "main/objanim.h"
#include "main/objhits.h"
#include "main/objprint_api.h"
#include "main/objseq.h"
#include "main/player_control_interface.h"
#include "main/vecmath.h"
#include "main/voxmaps.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/dll/baddie_state.h"
#include "main/dll/dll_00C9_enemy.h"
#include "main/dll/wispbaddie_baddie.h"
#include "main/audio/sfx_position_api.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/baddie_setmove.h"
#include "main/pad_api.h"
#include "main/dll/seqobj11d_ext.h"
#include "main/dll/wispbaddieseq_ext.h"
#include "main/gameloop_api.h"
#include "main/audio/sfx.h"
#include "main/dll/curve_walker.h"
#include "main/dll/rom_curve_interface.h"
#include "main/gamebits.h"
#include "main/dll/objfsa.h"
#include "main/gamebit_ids.h"
#include "main/dll/newseqobj_baddie.h"
#include "main/dll/baddie_frozen.h"
#include "main/game_ui_interface.h"
#include "main/dll/tricky_api.h"
#include "main/model.h"
#include "main/object_transform.h"
#include "main/dll/player_target.h"
#include "main/dll/player_api.h"
#include "dlls/objects/225_WispBaddie.h"
#include "main/trig_float_helpers.h"
#include "main/obj_link.h"
#include "main/objfx.h"
#include "main/objtexture.h"
#include "main/dll/seqObj11E.h"
#include "main/dll/groundbaddiepush_ext.h"
#include "main/dll/dll_00C9_enemy_ext.h"
#include "dlls/objects/336_GCRobotLigh.h"
#include "dolphin/mtx.h"
#include "main/dll/mikaladon.h"
#include "main/dll/magicPlant.h"
#include "main/dll/kooshy.h"
#include "main/dll/weevil.h"
#include "main/trig.h"
#include "main/dll/waterfx_interface.h"
#include "main/dll/fall_ladders.h"
#include "main/dll/fireflyLantern.h"
#include "main/dll/duster_api.h"
#include "main/track_bbox_api.h"
#include "main/sky_interface.h"
#include "main/dll/duster.h"
#include "dlls/objects/216_PinPonSpike.h"
#include "main/dll/duster_wb.h"
#include "main/obj_query.h"
#include "main/dll/hoodedzyck.h"
#include "main/camera_interface.h"
#include "main/model_light.h"
#include "main/dll/firecrawler.h"
#include "main/dll/dll_0273_firepipe.h"
#include "main/dll/hagabon_mk2.h"
#include "main/dll/snowworm.h"
#include "main/dll/baddiewhirlpool.h"

/* Baddie-family animation data shared with the sequence-driver TUs. */

/* baddie-AI tables referenced via extern by firecrawler.c; owned here by link order */

static inline int hoodedZyck_getAngleDelta(GameObject* obj, GameObject* target)
{
    f32 d = (f32)(int)((u16)getAngle(obj->anim.localPosX - target->anim.localPosX,
                                     obj->anim.localPosZ - target->anim.localPosZ) -
                       (u16)obj->anim.rotX);
    if (d > 32768.0f)
    {
        d = -65535.0f + d;
    }
    if (d < -32768.0f)
    {
        d = 65535.0f + d;
    }
    return d;
}

#define FIRECRAWLER_OBJFLAG_RENDERED     0x800
#define FIRECRAWLER_OBJFLAG_PARENT_SLACK 0x1000
#define FIREHOLE_OBJ_ID                  0x710 /* FireHole child spawned by firecrawler (firepipe DLL 0x273) */

#define FIRECRAWLER_PROJECTILE_OBJ       0x869 /* retail "FireCrawler..." (DLL 0xD7 kaldachomspit) */

/* crawler-family enemy anim.romDefNos (docblock table: romDefNo -> enemy name) */

#define FIRECRAWLER_SEQID_FIRECRAWLER  0x6a2 /* FireCrawler */

#define FIRECRAWLER_SEQID_REDEYE       0x6a3 /* RedEye */

/* attacker romDefNo this creature is immune to (retail OBJECTS.bin). */

#define FIRECRAWLER_ATTACKER_SEQID_FLAMETHROWER 0x1b5 /* "FlameThrowe" (DLL 0xE4) */

#define FIRECRAWLER_SEQID_SHADOWHUNTER 0x6a4 /* ShadowHunter */

/* movement dust spawned on the move-loop event: turning (turnDelta != 0) */

typedef struct
{
    f32 speeds[3][3];
    f32 unused;
} CrawlerSpeedThresholdTable;

typedef struct
{
    f32 spd;   /* 0x0 */
    u32 mask;  /* 0x4 */
    u8 moveId; /* 0x8 */
    u8 next9;  /* 0x9 */
    u8 nextA;  /* 0xa */
    u8 pad;
    int flagC; /* 0xc */
} CrawlerSeq16;

typedef struct
{
    CrawlerSeq12* tbl0; // 0x0  anim move ids
    CrawlerSeq12* tbl4;  // 0x4  chained move table
    CrawlerSeq12* tbl8;  // 0x8  random move table
    CrawlerSeq12* tblC;  // 0xc  octant move table
    CrawlerSeq12* tbl10; // 0x10 single move entry
    CrawlerSeq16* seq;   // 0x14
    CrawlerSeq12* tbl18; // 0x18 anim-id loop table
    u8 pad1C[4];
} CrawlerDescriptor;

/* Nearby-object scan. Asks enemy_findNearbyEnemies for up to 40 objects
 * within 640.0f, walks the result array of (obj, ?) pairs, and if
 * any entry's modelType is 0x6a3 with state[0x2dc] bit 0x20000000 set
 * AND bits 0x1800 clear, latches "found" and exits. If nothing matched,
 * loads the default triggered camera action. */

void crawler_checkNearbyActive(GameObject* obj, u8* state);

void firecrawler_spawnFireHole(GameObject* obj, u8* state);

void firecrawler_spawnProjectile(GameObject* obj, u8* state);

void crawlerPlayMoveEventFx(GameObject* obj, u8* state);

void crawler_updateC(GameObject* obj, u8* state);

void crawler_updateB(GameObject* obj, u8* state);

void crawler_update(GameObject* obj, u8* state);

/* crawler_initModelVariant: crawler-family variant init. Dispatches on obj->modelType
 * (offset 0x46): values 0x6a2/0x6a3/0x6a4 each pick a different float +
 * byte tuple to seed state[0x2a8..0x322]. The trailing block sets
 * shared state floats and computes obj->anim.rootMotionScale from params->unk28. */

void crawler_initModelVariant(GameObject* obj, u8* state);

u8 gRedEyeLocomotionMoves[0x30] = {
    0x40, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x0E, 0x00, 0x03, 0x00, 0x40, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x3F, 0xC0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x01, 0x00, 0x03, 0x00, 0x3F, 0xC0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0x00, 0x03, 0x00,
};

u8 gRedEyeRandomMoves[0x54] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x40, 0x40, 0x00, 0x00, 0x00,
    0x0F, 0x00, 0x00, 0x12, 0x00, 0x08, 0x00, 0x40, 0x40, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x14, 0x00,
    0x08, 0x00, 0x40, 0x40, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x14, 0x00, 0x08, 0x00, 0x40, 0xA0, 0x00,
    0x00, 0x00, 0x0F, 0x00, 0x00, 0x13, 0x00, 0x03, 0x00, 0x3F, 0xA6, 0x66, 0x66, 0x00, 0x0F, 0x00, 0x00,
    0x10, 0x00, 0x08, 0x00, 0x3F, 0xA6, 0x66, 0x66, 0x00, 0x0F, 0x00, 0x00, 0x11, 0x00, 0x08, 0x00,
};

u8 gRedEyeDefaultMoveChain[0x48] = {
    0x3F, 0xC0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x0D, 0x01, 0x03, 0x00, 0x3F, 0xC0, 0x00, 0x00, 0x00, 0x0F,
    0x00, 0x00, 0x0F, 0x02, 0x03, 0x00, 0x3F, 0xC0, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x0F, 0x03, 0x03, 0x00,
    0x40, 0x60, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x14, 0x04, 0x08, 0x00, 0x3F, 0xC0, 0x00, 0x00, 0x00, 0x0F,
    0x00, 0x00, 0x0F, 0x05, 0x03, 0x00, 0x40, 0xC0, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x13, 0x01, 0x03, 0x00,
};

u8 gRedEyeMoveChain[0x60] = {
    0x40, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x14, 0x01, 0x08, 0x00, 0x3F, 0x80, 0x00, 0x00,
    0x00, 0x0F, 0x00, 0x00, 0x02, 0x02, 0x03, 0x00, 0x3F, 0xC0, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00,
    0x04, 0x03, 0x03, 0x00, 0x3F, 0x80, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x02, 0x04, 0x03, 0x00,
    0x3F, 0xC0, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x05, 0x05, 0x03, 0x00, 0x3F, 0xC0, 0x00, 0x00,
    0x00, 0x0F, 0x00, 0x00, 0x03, 0x06, 0x03, 0x00, 0x3F, 0xC0, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00,
    0x06, 0x07, 0x03, 0x00, 0x3F, 0xC0, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x04, 0x00, 0x03, 0x00,
};

u8 gRedEyeOctantMoves[0x60] = {
    0x3F, 0xA6, 0x66, 0x66, 0x00, 0x0F, 0x00, 0x00, 0x12, 0x00, 0x08, 0x00, 0x3F, 0xA6, 0x66, 0x66,
    0x00, 0x0F, 0x00, 0x00, 0x10, 0x00, 0x08, 0x00, 0x3F, 0xA6, 0x66, 0x66, 0x00, 0x0F, 0x00, 0x00,
    0x10, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3F, 0xA6, 0x66, 0x66,
    0x00, 0x0F, 0x00, 0x00, 0x11, 0x00, 0x08, 0x00, 0x3F, 0xA6, 0x66, 0x66, 0x00, 0x0F, 0x00, 0x00,
    0x11, 0x00, 0x08, 0x00, 0x3F, 0xA6, 0x66, 0x66, 0x00, 0x0F, 0x00, 0x00, 0x12, 0x00, 0x08, 0x00,
};

u8 gRedEyeMoveHitVolumes[0xC0] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x18, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x01, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x18, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x04, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x18, 0x06, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x07, 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x0D, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x18, 0x0F, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x10, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x11, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x18, 0x12, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x13, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x15, 0x01, 0x00, 0x00,
};

u8 gRedEyeHitReactionSeq[0x70] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x0B, 0x07, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x06, 0x3E, 0xCC, 0xCC, 0xCD, 0x00, 0x00,
    0x00, 0x0B, 0x0A, 0x06, 0x06, 0x00, 0x00, 0x00, 0x00, 0x02, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0B, 0x08,
    0x03, 0x05, 0x00, 0x00, 0x00, 0x00, 0x03, 0x3F, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0B, 0x0B, 0x03, 0x05, 0x00,
    0x00, 0x00, 0x00, 0x03, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0B, 0x09, 0x06, 0x06, 0x00, 0x00, 0x00, 0x00,
    0x06, 0x3F, 0x33, 0x33, 0x33, 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

u8 gCrawlerDefaultMoveEventFx[0x9C] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xA0, 0x03, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x03, 0xA0, 0x04, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x9C, 0x05, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x9D, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x90, 0x08, 0x00, 0x00, 0x20,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x41, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x9E, 0x0B, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x9F, 0x0C, 0x00, 0x00, 0x00,
};

u8 gFireCrawlerLocomotionMoves[0x30] = {
    0x40, 0x40, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x3F, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x02, 0x00, 0x03, 0x00, 0x3F, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x03, 0x00, 0x03, 0x00, 0x3F, 0x19, 0x99, 0x9A, 0x00, 0x01, 0x00, 0x00, 0x04, 0x00, 0x03, 0x00,
};

u8 gFireCrawlerOctantMoves[0x60] = {
    0x40, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x08, 0x00, 0x08, 0x00, 0x3F, 0x99, 0x99, 0x9A,
    0x00, 0x0F, 0x00, 0x00, 0x06, 0x00, 0x08, 0x00, 0x3F, 0x99, 0x99, 0x9A, 0x00, 0x0F, 0x00, 0x00,
    0x06, 0x00, 0x08, 0x00, 0x3F, 0x99, 0x99, 0x9A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x3F, 0x99, 0x99, 0x9A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3F, 0x99, 0x99, 0x9A,
    0x00, 0x0F, 0x00, 0x00, 0x07, 0x00, 0x08, 0x00, 0x3F, 0x99, 0x99, 0x9A, 0x00, 0x0F, 0x00, 0x00,
    0x07, 0x00, 0x08, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x08, 0x00, 0x08, 0x00,
};

u8 gFireCrawlerRandomMoves[0x24] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x40, 0x40, 0x00, 0x00, 0x00, 0x0F,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x40, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
};

u8 gFireCrawlerMoveChain[0x24] = {
    0x40, 0x19, 0x99, 0x9A, 0x00, 0x0F, 0x00, 0x00, 0x05, 0x01, 0x03, 0x00, 0x3F, 0xB3, 0x33, 0x33, 0x00, 0x0F,
    0x00, 0x00, 0x09, 0x02, 0x03, 0x00, 0x40, 0x80, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x0A, 0x00, 0x03, 0x00,
};

u8 gFireCrawlerMoveHitVolumes[0x9C] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x09, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x03, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x09, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x06, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x07, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x09, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x09, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x0A, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x1F, 0x0B, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1F, 0x0C, 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1F, 0x0D, 0x02, 0x00, 0x00,
};

u8 gFireCrawlerHitReactionSeq[0x50] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x3F, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0B, 0x0B, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x06,
    0x3F, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0B, 0x0C, 0x04, 0x03, 0x00, 0x00, 0x00, 0x00, 0x02,
    0x3F, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0B, 0x0D, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
    0x3F, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0B, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
};

u8 gFireCrawlerMoveEventFx[0x9C] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0xAB, 0x01, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0xAB, 0x02, 0x00, 0x00, 0x08,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00,
};

u8 gShadowHunterLocomotionMoves[0x30] = {
    0x40, 0x80, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x3F, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x03, 0x00, 0x03, 0x00, 0x3F, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x04, 0x00, 0x03, 0x00, 0x3F, 0x19, 0x99, 0x9A, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x03, 0x00,
};

u8 gShadowHunterOctantMoves[0x60] = {
    0x40, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x08, 0x00, 0x08, 0x00, 0x3F, 0xC0, 0x00, 0x00,
    0x00, 0x0F, 0x00, 0x00, 0x06, 0x00, 0x08, 0x00, 0x3F, 0xC0, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00,
    0x06, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3F, 0xC0, 0x00, 0x00,
    0x00, 0x0F, 0x00, 0x00, 0x07, 0x00, 0x08, 0x00, 0x3F, 0xC0, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00,
    0x07, 0x00, 0x08, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x08, 0x00, 0x08, 0x00,
};

u8 gShadowHunterRandomMoves[0x30] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x40, 0x80, 0x00, 0x00,
    0x00, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x40, 0x80, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00,
    0x01, 0x00, 0x08, 0x00, 0x40, 0x80, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x02, 0x00, 0x08, 0x00,
};

u8 gShadowHunterMoveChain[0x24] = {
    0x3F, 0xC0, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x05, 0x01, 0x03, 0x00, 0x3F, 0xC0, 0x00, 0x00, 0x00, 0x0F,
    0x00, 0x00, 0x05, 0x02, 0x03, 0x00, 0x3F, 0xC0, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x05, 0x00, 0x03, 0x00,
};

u8 gShadowHunterDefaultMoveChain[0x3C] = {
    0x3F, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x09, 0x01, 0x03, 0x02, 0x3F, 0x80, 0x00,
    0x00, 0x00, 0x0F, 0x00, 0x00, 0x0A, 0x00, 0x03, 0x00, 0x3F, 0x80, 0x00, 0x00, 0x00, 0x0F,
    0x00, 0x00, 0x0B, 0x03, 0x03, 0x03, 0x3F, 0x80, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x0C,
    0x04, 0x03, 0x04, 0x3F, 0x80, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x0D, 0x00, 0x03, 0x00,
};

u8 gShadowHunterMoveHitVolumes[0x30] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x0A, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
    0x0A, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x0D, 0x01, 0x00, 0x00,
};

u8 gShadowHunterHitReactionSeq[0x40] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x3F, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0B, 0x0E, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x06,
    0x3F, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0B, 0x0F, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x06,
    0x3F, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0B, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

int gCrawlerCurveInitData[2] = {2, 3};

EnemyTargetSearchResult gCrawlerNearbyObjectBuffer[16];

f32 gCrawlerHitSfxTimer;

void* gCrawlerDescriptorTable[24] = {
    gRedEyeLocomotionMoves, gRedEyeMoveChain, gRedEyeRandomMoves, gRedEyeOctantMoves, gRedEyeDefaultMoveChain, gRedEyeHitReactionSeq, gRedEyeMoveHitVolumes, gCrawlerDefaultMoveEventFx,
    gFireCrawlerLocomotionMoves, gFireCrawlerMoveChain, gFireCrawlerRandomMoves, gFireCrawlerOctantMoves, gFireCrawlerMoveChain, gFireCrawlerHitReactionSeq, gFireCrawlerMoveHitVolumes, gFireCrawlerMoveEventFx,
    gShadowHunterLocomotionMoves, gShadowHunterMoveChain, gShadowHunterRandomMoves, gShadowHunterOctantMoves, gShadowHunterDefaultMoveChain, gShadowHunterHitReactionSeq, gShadowHunterMoveHitVolumes, gCrawlerDefaultMoveEventFx,
};

CrawlerSpeedThresholdTable gCrawlerSpeedThresholds = {
    {{1.2f, 0.8f, 1e-04f}, {1.2f, 0.8f, 1e-04f}, {1.2f, 0.8f, 1e-04f}},
    0.0f,
};

void crawler_checkNearbyActive(GameObject* obj, u8* state)
{
    u8 count = enemy_findNearbyEnemies(obj, 640.0f, 0, 0x28, gCrawlerNearbyObjectBuffer);
    u8 noMatch = 1;
    if (count >= 1)
    {
        u8 i;
        for (i = 0; i < count; i++)
        {
            u32 objectIndex = i;
            GameObject* e = gCrawlerNearbyObjectBuffer[objectIndex].obj;
            if (e->anim.romDefNo == FIRECRAWLER_SEQID_REDEYE)
            {
                u32 flags = ((EnemyState*)e->extra)->controlFlags;
                if ((flags & 0x20000000) != 0 && (flags & 0x1800) == 0)
                {
                    i = count;
                    noMatch = 0;
                }
            }
        }
    }
    if (noMatch != 0)
    {
        (*gCameraInterface)->loadTriggeredCamAction(0, 0, 0);
    }
}

void firecrawler_spawnFireHole(GameObject* obj, u8* state)
{
    FirePipeMapData* setup;
    GameObject* child;
    (void)state;
    if (Obj_IsLoadingLocked() != 0)
    {
        setup = (FirePipeMapData*)Obj_AllocObjectSetup(0x24, FIREHOLE_OBJ_ID);
        ObjPath_GetPointWorldPosition(obj, 0, &setup->base.posX, &setup->base.posY, &setup->base.posZ, 0);
        setup->base.color[0] = 1;
        setup->base.color[1] = 4;
        setup->base.color[2] = 0xff;
        setup->base.color[3] = 0xff;
        setup->rotX = 0;
        setup->rotY = 0;
        setup->cycleTime = 0;
        setup->scale = 0xa;
        setup->gameBit = 0;
        setup->startOffset = 0;
        setup->flags = 3;
        setup->pad23 = 0;
        child = objSetupObject(&setup->base, 5, -1, -1, 0);
        if (child != NULL)
        {
            ObjLink_AttachChild(obj, child, 0);
            firepipe_setLinkedUpdateFlag(child);
            child->anim.flags = (s16)(child->anim.flags | OBJANIM_FLAG_HIDDEN);
        }
    }
}

void firecrawler_spawnProjectile(GameObject* obj, u8* state)
{
    u8 locked = Obj_IsLoadingLocked();
    if (locked != 0)
    {
        GameObject* child;
        ObjPlacement* setup = Obj_AllocObjectSetup(0x24, FIRECRAWLER_PROJECTILE_OBJ);
        ObjPath_GetPointWorldPosition(obj, 0, (f32*)((u8*)setup + 8), (f32*)((u8*)setup + 0xc), (f32*)((u8*)setup + 0x10),
                                      0);
        setup->color[0] = 1;
        setup->color[1] = 4;
        setup->color[2] = 0xff;
        setup->color[3] = 0xff;
        child = (GameObject*)((int)objSetupObject((ObjPlacement*)setup, 5, -1, -1, 0));
        if ((u32)child != 0)
        {
            f32 dur = 60.0f * ((f32)((EnemyState*)state)->targetDist / ((EnemyState*)state)->aggroRange);
            child->anim.velocityX = (((GameObject*)((EnemyState*)state)->trackedObj)->anim.localPosX -
                                                    setup->posX) /
                                                   dur;
            child->anim.velocityY =
                ((30.0f + ((GameObject*)((EnemyState*)state)->trackedObj)->anim.localPosY +
                  (f32)(int)randomGetRange(-10, 10)) -
                 setup->posY) /
                dur;
            child->anim.velocityZ = (((GameObject*)((EnemyState*)state)->trackedObj)->anim.localPosZ -
                                                    setup->posZ) /
                                                   dur;
        }
        Sfx_PlayFromObject(obj, SFXTRIG_en_cvdrip1c_4ae);
    }
}

void crawlerPlayMoveEventFx(GameObject* obj, u8* state)
{
    typedef struct
    {
        u8 pad[4];
        u32 sfxId; /* 0x4 */
        u8 pad2;
        u8 shakeAmt;  /* 0x9 */
        u8 rumbleAmt; /* 0xa */
        u8 flags;     /* 0xb */
    } CrawlerSubDesc;
    typedef struct
    {
        u8 pad[0x1c];
        CrawlerSubDesc* p;
    } CrawlerDescE;
    CrawlerDescE* d = (CrawlerDescE*)gCrawlerDescriptorTable;
    CrawlerSubDesc* sub;
    CrawlerSubDesc* entry = d[((EnemyState*)state)->userData2].p;
    u8 i;

    gCrawlerHitSfxTimer = gCrawlerHitSfxTimer - timeDelta;

    for (i = 0; i <= 12; i++)
    {
        if ((((EnemyState*)state)->animEventMask & (1 << i)) != 0)
        {
            sub = &entry[i];
            if (sub->sfxId != 0)
            {
                Sfx_PlayFromObject(obj, sub->sfxId);
            }
            if (sub->shakeAmt != 0)
            {
                CameraShake_ApplyRadial(obj->anim.localPosX, obj->anim.localPosY,
                                        obj->anim.localPosZ, 160.0f, (f32)(u32)sub->shakeAmt);
            }
            if (sub->rumbleAmt != 0)
            {
                GameObject* player = Obj_GetPlayerObject();
                if ((player->objectFlags & FIRECRAWLER_OBJFLAG_PARENT_SLACK) == 0)
                {
                    f32 dist =
                        Vec_distance(&obj->anim.worldPosX, &player->anim.worldPosX);
                    if (dist <= 640.0f)
                    {
                        f32 amt = 1.0f - dist / 640.0f;
                        doRumble(amt * (f32)(u32)sub->rumbleAmt);
                    }
                }
            }
            if (sub->flags != 0)
            {
                if ((sub->flags & 1) != 0)
                {
                    ((EnemyState*)state)->familyData.crawler.flagsD = (u8)(((EnemyState*)state)->familyData.crawler.flagsD ^ 0x40);
                    if ((((EnemyState*)state)->familyData.crawler.flagsD & 0x40) != 0)
                    {
                        if (obj->childObjs[0] == NULL)
                        {
                            firecrawler_spawnFireHole(obj, state);
                        }
                        else
                        {
                            firepipe_setLinkedUpdateFlag(obj->childObjs[0]);
                        }
                    }
                    else if (obj->childObjs[0] != NULL)
                    {
                        firepipe_clearLinkedUpdateFlag(obj->childObjs[0]);
                    }
                }
                if ((sub->flags & 2) != 0)
                {
                    firecrawler_spawnProjectile(obj, state);
                }
            }
        }
    }
}

void crawler_onHit(GameObject* obj, u8* state, GameObject* attacker, int cmd, int p5, int damage, Vec* wpad0, int wpad1)
{
    typedef struct
    {
        u8 pad[0x14];
        CrawlerSeq16* seq; // 0x14
        u8 pad2[8];
    } CrawlerDesc;
    u8 idx;
    CrawlerDesc* d = (CrawlerDesc*)gCrawlerDescriptorTable;
    CrawlerSeq16* tbl = d[(idx = ((EnemyState*)state)->userData2)].seq;

    if (cmd == 0xe)
    {
        damage = damage << 3;
    }
    if (idx == 0 && cmd == 5)
    {
        damage = damage << 2;
    }
    if (idx == 1 &&
        (attacker->anim.romDefNo == FIRECRAWLER_ATTACKER_SEQID_FLAMETHROWER || attacker->anim.classId == 0x1c || cmd == 0x1f))
    {
        return;
    }
    if ((((EnemyState*)state)->familyData.crawler.flagsC & 4) != 0 || (idx == 0 && (((EnemyState*)state)->flags2F1 & 0x40) != 0))
    {
        if (cmd == 0x11)
        {
            return;
        }
        if ((obj)->anim.romDefNo == FIRECRAWLER_SEQID_FIRECRAWLER)
        {
            if (gCrawlerHitSfxTimer <= 0.0f && attacker != NULL)
            {
                switch (attacker->anim.romDefNo)
                {
                case 0x416:
                    Sfx_PlayFromObject(obj, SFXTRIG_snort);
                    break;
                case 0:
                case 0x69:
                    Sfx_PlayFromObject(obj, SFXTRIG_stftest);
                    break;
                }
                gCrawlerHitSfxTimer = 100.0f;
            }
        }
        else
        {
            Sfx_PlayFromObject(obj, SFXTRIG_swd_var);
        }
        ((EnemyState*)state)->flags2E8 = ((EnemyState*)state)->flags2E8 | 0x10;
        return;
    }

    if (idx == 1 && (obj)->childObjs[0] != NULL)
    {
        firepipe_clearLinkedUpdateFlag((obj)->childObjs[0]);
    }
    ((EnemyState*)state)->familyData.crawler.flagsD = ((EnemyState*)state)->familyData.crawler.flagsD & ~0x40;
    ((EnemyState*)state)->flags2E8 = ((EnemyState*)state)->flags2E8 & ~0x40LL;
    if (cmd == 0x10 && ((EnemyState*)state)->userData2 != 0)
    {
        ((EnemyState*)state)->flags2E8 = ((EnemyState*)state)->flags2E8 | 0x20;
        return;
    }

    if (((EnemyState*)state)->familyData.crawler.reactStep != 0)
    {
        u8 step;
        if (((EnemyState*)state)->userData2 == 0)
        {
            step = 4;
        }
        else
        {
            step = 3;
        }
        baddieSetMove(obj, (int)state, tbl[step].moveId, tbl[step].spd, 0, tbl[step].mask & 0xff);
        ((EnemyState*)state)->familyData.crawler.flagsC = tbl[step].flagC;
        (obj)->hitVolumeIndex = ((EnemyState*)state)->familyData.crawler.flagsC & 1;
        ((EnemyState*)state)->familyData.crawler.reactStep = tbl[step].next9;
        ((EnemyState*)state)->flags2E8 = ((EnemyState*)state)->flags2E8 | 8;
        if ((obj)->anim.romDefNo == FIRECRAWLER_SEQID_FIRECRAWLER)
        {
            if (gCrawlerHitSfxTimer <= 0.0f && attacker != NULL)
            {
                switch (attacker->anim.romDefNo)
                {
                case 0x416:
                    Sfx_PlayFromObject(obj, SFXTRIG_snort);
                    break;
                case 0:
                case 0x69:
                    Sfx_PlayFromObject(obj, SFXTRIG_stftest);
                    break;
                }
                Sfx_PlayFromObject(obj, SFXTRIG_baddie_var);
                gCrawlerHitSfxTimer = 100.0f;
            }
        }
        else
        {
            Sfx_PlayFromObject(obj, SFXTRIG_stftest_var);
        }
        if (damage > ((EnemyState*)state)->current)
        {
            ((EnemyState*)state)->current = 0;
        }
        else
        {
            ((EnemyState*)state)->current = ((EnemyState*)state)->current - damage;
        }
        if (((EnemyState*)state)->current == 0 && ((EnemyState*)state)->userData2 == 0)
        {
            crawler_checkNearbyActive(obj, state);
        }
        return;
    }

    if ((((EnemyState*)state)->userData2 == 0 && cmd == 0x11 &&
         mainGetBit(GAMEBIT_STAFF_ABILITY_SUPER_QUAKE) != 0) ||
        ((EnemyState*)state)->userData2 == 1)
    {
        u8 v;
        baddieSetMove(obj, (int)state, tbl[1].moveId, tbl[1].spd, 0, tbl[1].mask & 0xff);
        ((EnemyState*)state)->familyData.crawler.flagsC = tbl[1].flagC;
        (obj)->hitVolumeIndex = ((EnemyState*)state)->familyData.crawler.flagsC & 1;
        ((EnemyState*)state)->familyData.crawler.reactStep = tbl[1].next9;
        v = ((EnemyState*)state)->userData2;
        if (v == 0)
        {
            ((EnemyState*)state)->crawler.emergeTimer = 6.0f * (f32)((EnemyState*)state)->hitStunFrames;
            ((EnemyState*)state)->flags2E8 = ((EnemyState*)state)->flags2E8 | 8;
            if ((obj)->anim.romDefNo == FIRECRAWLER_SEQID_FIRECRAWLER)
            {
                if (gCrawlerHitSfxTimer <= 0.0f && attacker != NULL)
                {
                    switch (attacker->anim.romDefNo)
                    {
                    case 0x416:
                        Sfx_PlayFromObject(obj, SFXTRIG_snort);
                        break;
                    case 0:
                    case 0x69:
                        Sfx_PlayFromObject(obj, SFXTRIG_stftest);
                        break;
                    }
                    Sfx_PlayFromObject(obj, SFXTRIG_baddie_var);
                    gCrawlerHitSfxTimer = 100.0f;
                }
            }
            else
            {
                Sfx_PlayFromObject(obj, SFXTRIG_stftest_var);
            }
            return;
        }
        if (v == 1)
        {
            ((EnemyState*)state)->crawler.emergeTimer = 2.0f * (f32)((EnemyState*)state)->hitStunFrames;
            if ((obj)->anim.romDefNo == FIRECRAWLER_SEQID_FIRECRAWLER)
            {
                if (gCrawlerHitSfxTimer <= 0.0f && attacker != NULL)
                {
                    switch (attacker->anim.romDefNo)
                    {
                    case 0x416:
                        Sfx_PlayFromObject(obj, SFXTRIG_snort);
                        break;
                    case 0:
                    case 0x69:
                        Sfx_PlayFromObject(obj, SFXTRIG_stftest);
                        break;
                    }
                    Sfx_PlayFromObject(obj, SFXTRIG_baddie_var);
                    gCrawlerHitSfxTimer = 100.0f;
                }
            }
            else
            {
                Sfx_PlayFromObject(obj, SFXTRIG_swd_var);
            }
            ((EnemyState*)state)->flags2E8 = ((EnemyState*)state)->flags2E8 | 0x10;
        }
        return;
    }

    if (cmd != 0x11)
    {
        if ((obj)->anim.romDefNo == FIRECRAWLER_SEQID_FIRECRAWLER)
        {
            if (gCrawlerHitSfxTimer <= 0.0f && attacker != NULL)
            {
                switch (attacker->anim.romDefNo)
                {
                case 0x416:
                    Sfx_PlayFromObject(obj, SFXTRIG_snort);
                    break;
                case 0:
                case 0x69:
                    Sfx_PlayFromObject(obj, SFXTRIG_stftest);
                    break;
                }
                Sfx_PlayFromObject(obj, SFXTRIG_baddie_var);
                gCrawlerHitSfxTimer = 100.0f;
            }
        }
        else
        {
            Sfx_PlayFromObject(obj, SFXTRIG_swd_var);
        }
    }
    ((EnemyState*)state)->flags2E8 = ((EnemyState*)state)->flags2E8 | 0x10;
}

void crawler_updateC(GameObject* obj, u8* state)
{
    CrawlerDescriptor* d = (CrawlerDescriptor*)gCrawlerDescriptorTable;
    CrawlerSeq12* t8 = d[((EnemyState*)state)->userData2].tbl8;
    CrawlerSeq12* t0 = d[((EnemyState*)state)->userData2].tbl0;
    CrawlerSeq16* seq = d[((EnemyState*)state)->userData2].seq;
    CrawlerSeq12* tC = d[((EnemyState*)state)->userData2].tblC;
    RomCurveWalker* base = *(RomCurveWalker**)state;
    f32 scale = 1.0f;
    f32 cap;
    int i;
    f32 dv[3];

    ((EnemyState*)state)->flags2E8 = ((EnemyState*)state)->flags2E8 & ~0x40LL;
    if (obj->childObjs[0] != NULL)
    {
        firepipe_clearLinkedUpdateFlag(obj->childObjs[0]);
    }

    if ((((EnemyState*)state)->controlFlags & BADDIE_CONTROL_JUST_TRIGGERED) != 0)
    {
        ((EnemyState*)state)->familyData.crawler.flagsD = ((EnemyState*)state)->familyData.crawler.flagsD | 8;
        if ((*gRomCurveInterface)->initCurve(*(RomCurveWalker**)state, obj, 0.0f, (int*)&gCrawlerCurveInitData, -1) != 0)
        {
            ((EnemyState*)state)->controlFlags =
                ((EnemyState*)state)->controlFlags & ~(u64)BADDIE_CONTROL_PATH_FOLLOW;
        }
        if (((EnemyState*)state)->userData2 == 0)
        {
            crawler_checkNearbyActive(obj, state);
        }
        ((EnemyState*)state)->userData1 = 0;
    }

    cap = 0.0f;
    if (((EnemyState*)state)->crawler.emergeTimer != cap && ((EnemyState*)state)->familyData.crawler.reactStep != 0)
    {
        ((EnemyState*)state)->crawler.emergeTimer = ((EnemyState*)state)->crawler.emergeTimer - timeDelta;
        if (((EnemyState*)state)->crawler.emergeTimer <= cap)
        {
            ((EnemyState*)state)->crawler.emergeTimer = cap;
            ((EnemyState*)state)->controlFlags |= (u64)BADDIE_CONTROL_SEQUENCE_DRIVEN;
            ((EnemyState*)state)->familyData.crawler.flagsC = seq[((EnemyState*)state)->familyData.crawler.reactStep].flagC;
            obj->hitVolumeIndex = ((EnemyState*)state)->familyData.crawler.flagsC & 1;
            ((EnemyState*)state)->familyData.crawler.reactStep = seq[((EnemyState*)state)->familyData.crawler.reactStep].nextA;
        }
        if ((((EnemyState*)state)->controlFlags & (BADDIE_CONTROL_JUST_TRIGGERED | BADDIE_CONTROL_SEQUENCE_DRIVEN)) ==
            0)
        {
            return;
        }
    }

    {
        u32 flags = ((EnemyState*)state)->controlFlags;
        if ((flags & BADDIE_CONTROL_PATH_FOLLOW) != 0)
        {
            int count = enemy_findNearbyEnemies(obj, 250.0f, 1, 0x28, gCrawlerNearbyObjectBuffer);
            if (count >= 1 && (f32)gCrawlerNearbyObjectBuffer[0].dist <= 250.0f)
            {
                f32* dp = dv;
                int rel;
                u16 oct;
                dp[0] = obj->anim.worldPosX - gCrawlerNearbyObjectBuffer[0].obj->anim.worldPosX;
                dp[1] = obj->anim.worldPosY - gCrawlerNearbyObjectBuffer[0].obj->anim.worldPosY;
                dp[2] = obj->anim.worldPosZ - gCrawlerNearbyObjectBuffer[0].obj->anim.worldPosZ;
                rel = (getAngle(-dp[0], -dp[2]) & 0xffff) - ((int)*(s16*)obj & 0xffffu);
                if (rel > 0x8000)
                {
                    rel = rel - 0xffff;
                }
                if (rel < -0x8000)
                {
                    rel = rel + 0xffff;
                }
                oct = ((u32)rel & 0xffff) >> 13;
                if (oct == 3 || oct == 4)
                {
                    scale = (f32)gCrawlerNearbyObjectBuffer[0].dist / 250.0f;
                }
                else if (oct == 0 || oct == 7)
                {
                    scale = 2.0f * (1.0f - (f32)gCrawlerNearbyObjectBuffer[0].dist / 250.0f) + 1.0f;
                }
            }
            {
                f32 dx = base->posX - obj->anim.localPosX;
                f32 dz = base->posZ - obj->anim.localPosZ;
                f32 dist = sqrtf(dx * dx + dz * dz);
                if (dist > 160.0f)
                {
                    dist = 160.0f;
                }
                {
                    f32 ratio = (160.0f - dist) / 160.0f;
                    ((EnemyState*)state)->pathSpeed = scale * (ratio * ((EnemyState*)state)->pathStep);
                }
                if (((EnemyState*)state)->pathSpeed < 0.25f)
                {
                    ((EnemyState*)state)->pathSpeed = 0.25f;
                }
            }
            if ((Curve_AdvanceAlongPath(&base->curve, ((EnemyState*)state)->pathSpeed) != 0 ||
                 base->atSegmentEnd != 0) &&
                (*gRomCurveInterface)->goNextPoint(base) != 0 &&
                (*gRomCurveInterface)
                        ->initCurve(*(RomCurveWalker**)state, obj, 700.0f, (int*)&gCrawlerCurveInitData, -1) != 0)
            {
                ((EnemyState*)state)->controlFlags =
                    ((EnemyState*)state)->controlFlags & ~(u64)BADDIE_CONTROL_PATH_FOLLOW;
            }
            if ((((EnemyState*)state)->familyData.crawler.flagsD & 0xa) == 0)
            {
                f32 t;
                f32 diff;
                f32 a;
                diff = (f32)(int)(((getAngle(base->tangentX, base->tangentZ) & 0xffff) + 0x8000) -
                                  ((int)*(s16*)obj & 0xffffu));
                if (diff > 32768.0f)
                {
                    diff = -65535.0f + diff;
                }
                if (diff < -32768.0f)
                {
                    diff = 65535.0f + diff;
                }
                t = (((EnemyState*)state)->pathStep * scale - ((EnemyState*)state)->pathSpeed) / 60.0f;
                a = diff >= 0.0f ? diff : -diff;
                /* 0x308 = EnemyState.animPlaySpeed; kept raw here - the typed
                 * member spelling shifts bytes off the u8* state param. */
                *(f32*)(state + 0x308) = t * (1.0f - a / 65535.0f);
                if (*(f32*)(state + 0x308) < 0.005f)
                {
                    *(f32*)(state + 0x308) = 0.005f;
                }
                else if (*(f32*)(state + 0x308) > 0.05f)
                {
                    *(f32*)(state + 0x308) = 0.05f;
                }
            }
            if ((((EnemyState*)state)->controlFlags &
                 (BADDIE_CONTROL_JUST_TRIGGERED | BADDIE_CONTROL_SEQUENCE_DRIVEN)) != 0)
            {
                ((EnemyState*)state)->familyData.crawler.flagsD = ((EnemyState*)state)->familyData.crawler.flagsD & ~0x20;
                if (((EnemyState*)state)->familyData.crawler.reactStep != 0)
                {
                    baddieSetMove(obj, (int)state, seq[((EnemyState*)state)->familyData.crawler.reactStep].moveId,
                                   seq[((EnemyState*)state)->familyData.crawler.reactStep].spd, 0,
                                   seq[((EnemyState*)state)->familyData.crawler.reactStep].mask & 0xff);
                    ((EnemyState*)state)->familyData.crawler.flagsC = seq[((EnemyState*)state)->familyData.crawler.reactStep].flagC;
                    obj->hitVolumeIndex = ((EnemyState*)state)->familyData.crawler.flagsC & 1;
                    ((EnemyState*)state)->familyData.crawler.reactStep = seq[((EnemyState*)state)->familyData.crawler.reactStep].next9;
                }
                else
                {
                    f32* dp2 = dv;
                    int rel2;
                    u16 oct2;
                    u8 mv;
                    dp2[0] = obj->anim.worldPosX - base->posX;
                    dp2[1] = obj->anim.worldPosY - base->posY;
                    dp2[2] = obj->anim.worldPosZ - base->posZ;
                    rel2 = (getAngle(-dp2[0], -dp2[2]) & 0xffff) - ((int)*(s16*)obj & 0xffffu);
                    if (rel2 > 0x8000)
                    {
                        rel2 = rel2 - 0xffff;
                    }
                    if (rel2 < -0x8000)
                    {
                        rel2 = rel2 + 0xffff;
                    }
                    oct2 = ((u32)rel2 & 0xffff) >> 13;
                    i = oct2;
                    mv = tC[i].moveId;
                    if (mv == 0)
                    {
                        ((EnemyState*)state)->familyData.crawler.flagsD = ((EnemyState*)state)->familyData.crawler.flagsD & ~0x18;
                        {
                            f32 v = ((EnemyState*)state)->pathSpeed;
                            int j = ((EnemyState*)state)->userData2;
                            if (v > gCrawlerSpeedThresholds.speeds[j][0])
                            {
                                ((EnemyState*)state)->rootMotionFlags = 1;
                                ObjAnim_SetCurrentMove(obj, t0[3].moveId, 0.0f, 0);
                            }
                            else if (v > gCrawlerSpeedThresholds.speeds[j][1])
                            {
                                ((EnemyState*)state)->rootMotionFlags = 1;
                                ObjAnim_SetCurrentMove(obj, t0[2].moveId, 0.0f, 0);
                            }
                            else if (v > gCrawlerSpeedThresholds.speeds[j][2])
                            {
                                ((EnemyState*)state)->rootMotionFlags = 1;
                                ObjAnim_SetCurrentMove(obj, t0[1].moveId, 0.0f, 0);
                            }
                            else
                            {
                                ((EnemyState*)state)->rootMotionFlags = 1;
                                *(f32*)(state + 0x308) = 0.01f;
                                ObjAnim_SetCurrentMove(obj, t0[0].moveId, 0.0f, 0);
                                ((EnemyState*)state)->pathSpeed = 0.0f;
                            }
                        }
                    }
                    else
                    {
                        baddieSetMove(obj, (int)state, mv, tC[i].spd, 0, tC[i].mode);
                        ((EnemyState*)state)->familyData.crawler.flagsD = ((EnemyState*)state)->familyData.crawler.flagsD | 8;
                    }
                }
            }
            if ((((EnemyState*)state)->rootMotionFlags & 8) == 0 && (((EnemyState*)state)->familyData.crawler.flagsD & 0x10) == 0)
            {
                baddieTurnTowardPoint(obj, (int)state, base->posX, base->posZ, 0xf, 0);
            }
        }
        else if ((flags & 0xc0000000) != 0)
        {
            i = randomGetRange(1, t8[0].moveId) & 0xff;
            baddieSetMove(obj, (int)state, t8[i].moveId, t8[i].spd, 0, t8[i].mode);
        }
    }
    crawlerPlayMoveEventFx(obj, state);
}

void crawler_updateB(GameObject* obj, u8* state)
{
    CrawlerDescriptor* d = (CrawlerDescriptor*)gCrawlerDescriptorTable;
    CrawlerSeq12* t10 = d[((EnemyState*)state)->userData2].tbl10;
    CrawlerSeq12* t8 = d[((EnemyState*)state)->userData2].tbl8;
    CrawlerSeq12* tC = d[((EnemyState*)state)->userData2].tblC;
    CrawlerSeq16* seq = d[((EnemyState*)state)->userData2].seq;
    CrawlerSeq12* t4 = d[((EnemyState*)state)->userData2].tbl4;
    CrawlerSeq12* t18 = d[((EnemyState*)state)->userData2].tbl18;
    f32 cap;
    int count;
    int i;
    f32 dv[3];

    if (((EnemyState*)state)->trackedObj != NULL &&
        ((GameObject*)((EnemyState*)state)->trackedObj)->anim.classId == 1)
    {
        requestGalleonBattleMusic();
    }

    if ((((EnemyState*)state)->controlFlags & BADDIE_CONTROL_JUST_TRIGGERED) != 0)
    {
        if (((EnemyState*)state)->userData2 == 0)
        {
            (*gCameraInterface)->loadTriggeredCamAction(0, 0x6c, 0);
        }
        ((EnemyState*)state)->familyData.crawler.flagsD = ((EnemyState*)state)->familyData.crawler.flagsD | 0x10;
        ((EnemyState*)state)->userData1 = 0;
        if (obj->anim.romDefNo == FIRECRAWLER_SEQID_FIRECRAWLER)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_baddie_eggsnatch_var);
            if (obj->childObjs[0] != NULL)
            {
                firepipe_clearLinkedUpdateFlag(obj->childObjs[0]);
            }
        }
    }

    cap = 0.0f;
    if (((EnemyState*)state)->crawler.emergeTimer != cap && ((EnemyState*)state)->familyData.crawler.reactStep != 0)
    {
        ((EnemyState*)state)->crawler.emergeTimer = ((EnemyState*)state)->crawler.emergeTimer - timeDelta;
        if (((EnemyState*)state)->crawler.emergeTimer <= cap)
        {
            ((EnemyState*)state)->crawler.emergeTimer = cap;
            ((EnemyState*)state)->controlFlags |= (u64)BADDIE_CONTROL_SEQUENCE_DRIVEN;
            ((EnemyState*)state)->familyData.crawler.flagsC = seq[((EnemyState*)state)->familyData.crawler.reactStep].flagC;
            obj->hitVolumeIndex = ((EnemyState*)state)->familyData.crawler.flagsC & 1;
            ((EnemyState*)state)->familyData.crawler.reactStep = seq[((EnemyState*)state)->familyData.crawler.reactStep].nextA;
        }
    }

    count = enemy_findNearbyEnemies(obj, 180.0f, 1, 0x28, gCrawlerNearbyObjectBuffer);
    if (count >= 1)
    {
        if ((((EnemyState*)state)->familyData.crawler.flagsD & 0x20) == 0 ||
            (((EnemyState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
        {
            if (((EnemyState*)state)->familyData.crawler.reactStep != 0)
            {
                baddieSetMove(obj, (int)state, seq[((EnemyState*)state)->familyData.crawler.reactStep].moveId,
                               seq[((EnemyState*)state)->familyData.crawler.reactStep].spd, 0, seq[((EnemyState*)state)->familyData.crawler.reactStep].mask & 0xff);
                ((EnemyState*)state)->familyData.crawler.flagsC = seq[((EnemyState*)state)->familyData.crawler.reactStep].flagC;
                obj->hitVolumeIndex = ((EnemyState*)state)->familyData.crawler.flagsC & 1;
                ((EnemyState*)state)->familyData.crawler.reactStep = seq[((EnemyState*)state)->familyData.crawler.reactStep].next9;
            }
            else
            {
                f32* dp = dv;
                int rel;
                u16 oct;
                dp[0] = obj->anim.worldPosX - gCrawlerNearbyObjectBuffer[0].obj->anim.worldPosX;
                dp[1] = obj->anim.worldPosY - gCrawlerNearbyObjectBuffer[0].obj->anim.worldPosY;
                dp[2] = obj->anim.worldPosZ - gCrawlerNearbyObjectBuffer[0].obj->anim.worldPosZ;
                rel = (getAngle(-dp[0], -dp[2]) & 0xffff) - ((int)*(s16*)obj & 0xffffu);
                if (rel > 0x8000)
                {
                    rel = rel - 0xffff;
                }
                if (rel < -0x8000)
                {
                    rel = rel + 0xffff;
                }
                oct = ((u32)rel & 0xffff) >> 13;
                if (oct != 0 && oct < 7)
                {
                    if (oct < 3 || oct > 4)
                    {
                        u8 mv;
                        i = ((EnemyState*)state)->turnOctant;
                        mv = tC[i].moveId;
                        if (mv == 0)
                        {
                            int i2 = ((EnemyState*)state)->familyData.crawler.moveChainIndex;

                            baddieSetMove(obj, (int)state, t4[i2].moveId, t4[i2].spd, 0, t4[i2].mode);
                            ((EnemyState*)state)->familyData.crawler.moveChainIndex = t4[((EnemyState*)state)->familyData.crawler.moveChainIndex].next;
                        }
                        else
                        {
                            baddieSetMove(obj, (int)state, mv, tC[i].spd, 0, tC[i].mode);
                        }
                    }
                    else
                    {
                        i = randomGetRange(1, t8[0].moveId) & 0xff;
                        baddieSetMove(obj, (int)state, t8[i].moveId, t8[i].spd, 0, t8[i].mode);
                    }
                }
                else
                {
                    baddieSetMove(obj, (int)state, t10[0].moveId, t10[0].spd, 0, t10[0].mode);
                }
                ((EnemyState*)state)->familyData.crawler.flagsD = ((EnemyState*)state)->familyData.crawler.flagsD | 0x20;
                ((EnemyState*)state)->familyData.crawler.flagsD = ((EnemyState*)state)->familyData.crawler.flagsD & ~0x10;
            }
        }
    }
    else
    {
        if ((((EnemyState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
        {
            ((EnemyState*)state)->familyData.crawler.flagsD = ((EnemyState*)state)->familyData.crawler.flagsD & ~0x30;
            if (obj->anim.romDefNo == FIRECRAWLER_SEQID_FIRECRAWLER &&
                obj->childObjs[0] != NULL)
            {
                firepipe_clearLinkedUpdateFlag(obj->childObjs[0]);
            }
            if (((EnemyState*)state)->familyData.crawler.reactStep != 0)
            {
                baddieSetMove(obj, (int)state, seq[((EnemyState*)state)->familyData.crawler.reactStep].moveId,
                               seq[((EnemyState*)state)->familyData.crawler.reactStep].spd, 0, seq[((EnemyState*)state)->familyData.crawler.reactStep].mask & 0xff);
                ((EnemyState*)state)->familyData.crawler.flagsC = seq[((EnemyState*)state)->familyData.crawler.reactStep].flagC;
                obj->hitVolumeIndex = ((EnemyState*)state)->familyData.crawler.flagsC & 1;
                ((EnemyState*)state)->familyData.crawler.reactStep = seq[((EnemyState*)state)->familyData.crawler.reactStep].next9;
            }
            else
            {
                int i2;
                CrawlerSeq12* q;
                if ((((EnemyState*)state)->controlFlags &
                     (q = &t4[i2 = ((EnemyState*)state)->familyData.crawler.moveChainIndex])->mask) != 0)
                {
                    u8 mv;
                    i = ((EnemyState*)state)->turnOctant;
                    mv = tC[i].moveId;
                    if (mv == 0)
                    {
                        baddieSetMove(obj, (int)state, q->moveId, t4[i2].spd, 0, q->mode);
                    }
                    else
                    {
                        baddieSetMove(obj, (int)state, mv, tC[i].spd, 0, tC[i].mode);
                    }
                }
                else
                {
                    u8 mv;
                    i = ((EnemyState*)state)->turnOctant;
                    mv = tC[i].moveId;
                    if (mv == 0)
                    {
                        int i4 = randomGetRange(1, t8[0].moveId) & 0xff;
                        baddieSetMove(obj, (int)state, t8[i4].moveId, t8[i4].spd, 0, t8[i4].mode);
                    }
                    else
                    {
                        baddieSetMove(obj, (int)state, mv, tC[i].spd, 0, tC[i].mode);
                    }
                }
                {
                    ((EnemyState*)state)->familyData.crawler.moveChainIndex = t4[((EnemyState*)state)->familyData.crawler.moveChainIndex].next;
                }
            }
        }
    }

    ((ObjHitsPriorityState*)obj->anim.hitReactState)->hitVolumePriority = 0;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->hitVolumeId = 0;
    {
        int j = 1;
        CrawlerSeq12* p = t18 + 1;
        int c;
        for (c = t18->moveId; c >= 1; c--)
        {
            if (obj->anim.currentMove == p->moveId)
            {
                p = t18 + j;
                ((ObjHitsPriorityState*)obj->anim.hitReactState)->hitVolumePriority = (s8)p->mask;
                ((ObjHitsPriorityState*)obj->anim.hitReactState)->hitVolumeId = (s8)p->next;
                if (((ObjHitsPriorityState*)obj->anim.hitReactState)->hitVolumePriority == 0x1f)
                {
                    ((EnemyState*)state)->flags2E8 = ((EnemyState*)state)->flags2E8 | 0x40;
                }
                else
                {
                    ((EnemyState*)state)->flags2E8 = ((EnemyState*)state)->flags2E8 & ~0x40LL;
                }
                break;
            }
            p++;
            j += 1;
        }
    }

    if ((((EnemyState*)state)->rootMotionFlags & 8) == 0 && (((EnemyState*)state)->familyData.crawler.flagsD & 0x10) == 0)
    {
        baddieTurnTowardPoint(obj, (int)state,
                    ((GameObject*)((EnemyState*)state)->trackedObj)->anim.localPosX,
                    ((GameObject*)((EnemyState*)state)->trackedObj)->anim.localPosZ, 0x1e, 0);
    }
    crawlerPlayMoveEventFx(obj, state);
}

void crawler_update(GameObject* obj, u8* state)
{
    typedef struct
    {
        u8 pad[0xc];
        CrawlerSeq12* tC;
        CrawlerSeq12* t10;
        CrawlerSeq16* t14;
        CrawlerSeq12* t18;
        u8 pad2[4];
    } CrawlerDescL;
    CrawlerDescL* d = (CrawlerDescL*)gCrawlerDescriptorTable;
    CrawlerSeq12* t9 = d[((EnemyState*)state)->userData2].t10;
    CrawlerSeq12* t8 = d[((EnemyState*)state)->userData2].t18;
    CrawlerSeq12* t7 = d[((EnemyState*)state)->userData2].tC;
    CrawlerSeq16* t6 = d[((EnemyState*)state)->userData2].t14;
    f32 cap;
    int i;
    CrawlerSeq12* p;
    int j;
    int n;

    if (((EnemyState*)state)->trackedObj != NULL &&
        ((GameObject*)((EnemyState*)state)->trackedObj)->anim.classId == 1)
    {
        requestGalleonBattleMusic();
    }

    if ((((EnemyState*)state)->controlFlags & BADDIE_CONTROL_JUST_TRIGGERED) != 0)
    {
        if (((EnemyState*)state)->userData2 == 0)
        {
            (*gCameraInterface)->loadTriggeredCamAction(0, 0x6c, 0);
        }
        if (obj->anim.romDefNo == FIRECRAWLER_SEQID_FIRECRAWLER && obj->childObjs[0] != NULL)
        {
            firepipe_clearLinkedUpdateFlag(obj->childObjs[0]);
        }
        ((EnemyState*)state)->familyData.crawler.flagsD = ((EnemyState*)state)->familyData.crawler.flagsD | 0x10;
    }

    cap = 0.0f;
    if (((EnemyState*)state)->crawler.emergeTimer != cap && ((EnemyState*)state)->familyData.crawler.reactStep != 0)
    {
        ((EnemyState*)state)->crawler.emergeTimer -= timeDelta;
        if (((EnemyState*)state)->crawler.emergeTimer <= cap)
        {
            ((EnemyState*)state)->crawler.emergeTimer = cap;
            ((EnemyState*)state)->controlFlags |= (u64)BADDIE_CONTROL_SEQUENCE_DRIVEN;
            ((EnemyState*)state)->familyData.crawler.flagsC = t6[((EnemyState*)state)->familyData.crawler.reactStep].flagC;
            obj->hitVolumeIndex = ((EnemyState*)state)->familyData.crawler.flagsC & 1;
            ((EnemyState*)state)->familyData.crawler.reactStep = t6[((EnemyState*)state)->familyData.crawler.reactStep].nextA;
        }
    }

    if ((((EnemyState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
    {
        ((EnemyState*)state)->familyData.crawler.flagsD = ((EnemyState*)state)->familyData.crawler.flagsD & ~0x30;
        if (obj->anim.romDefNo == FIRECRAWLER_SEQID_FIRECRAWLER && obj->childObjs[0] != NULL)
        {
            firepipe_clearLinkedUpdateFlag(obj->childObjs[0]);
        }
        if (((EnemyState*)state)->familyData.crawler.reactStep != 0)
        {
            baddieSetMove(obj, (int)state, t6[((EnemyState*)state)->familyData.crawler.reactStep].moveId, t6[((EnemyState*)state)->familyData.crawler.reactStep].spd, 0,
                           t6[((EnemyState*)state)->familyData.crawler.reactStep].mask & 0xff);
            ((EnemyState*)state)->familyData.crawler.flagsC = t6[((EnemyState*)state)->familyData.crawler.reactStep].flagC;
            obj->hitVolumeIndex = ((EnemyState*)state)->familyData.crawler.flagsC & 1;
            ((EnemyState*)state)->familyData.crawler.reactStep = t6[((EnemyState*)state)->familyData.crawler.reactStep].next9;
        }
        else
        {
            i = ((EnemyState*)state)->turnOctant;
            if (t7[i].moveId == 0)
            {
                if (((EnemyState*)state)->targetDist >= 0x50)
                {
                    ((EnemyState*)state)->userData1 = 0;
                }
                enemy_findNearbyEnemies(obj, 250.0f, 6, 0x28, gCrawlerNearbyObjectBuffer);
                if ((((EnemyState*)state)->controlFlags & t9[((EnemyState*)state)->userData1].mask) == 0 &&
                    t9[((EnemyState*)state)->userData1].next != 0)
                {
                    ((EnemyState*)state)->userData1 = t9[((EnemyState*)state)->userData1].next;
                }
                baddieSetMove(obj, (int)state, t9[((EnemyState*)state)->userData1].moveId,
                               t9[((EnemyState*)state)->userData1].spd, 0,
                               t9[((EnemyState*)state)->userData1].mode);
                ((EnemyState*)state)->userData1 = t9[((EnemyState*)state)->userData1].next;
            }
            else
            {
                baddieSetMove(obj, (int)state, t7[i].moveId, t7[i].spd, 0, t7[i].mode);
            }
        }
    }

    ((ObjHitsPriorityState*)obj->anim.hitReactState)->hitVolumePriority = 0;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->hitVolumeId = 0;
    j = 1;
    p = t8 + 1;
    n = t8->moveId;
    for (; j <= n; j++)
    {
        if (obj->anim.currentMove == p->moveId)
        {
            ((ObjHitsPriorityState*)obj->anim.hitReactState)->hitVolumePriority =
                (s8)t8[j].mask;
            ((ObjHitsPriorityState*)obj->anim.hitReactState)->hitVolumeId =
                (s8)t8[j].next;
            if (((ObjHitsPriorityState*)obj->anim.hitReactState)->hitVolumePriority == 0x1f)
            {
                ((EnemyState*)state)->flags2E8 = ((EnemyState*)state)->flags2E8 | 0x40;
            }
            else
            {
                ((EnemyState*)state)->flags2E8 = ((EnemyState*)state)->flags2E8 & ~0x40LL;
            }
            break;
        }
        p++;
    }

    if ((((EnemyState*)state)->rootMotionFlags & 8) == 0 && (((EnemyState*)state)->familyData.crawler.flagsD & 0x10) == 0)
    {
        baddieTurnTowardPoint(obj, (int)state,
                    ((GameObject*)((EnemyState*)state)->trackedObj)->anim.localPosX,
                    ((GameObject*)((EnemyState*)state)->trackedObj)->anim.localPosZ, 0x1e, 0);
    }
    crawlerPlayMoveEventFx(obj, state);
}

void crawler_initModelVariant(GameObject* obj, u8* state)
{
    GroundBaddiePlacement* params = (GroundBaddiePlacement*)obj->anim.placementData;
    ((EnemyState*)state)->flags2E4 = 0xb;
    ((EnemyState*)state)->flags2E4 |= 0x400b0LL;
    ((EnemyState*)state)->flags2E4 |= 0x40001040LL;
    switch (obj->anim.romDefNo)
    {
    case FIRECRAWLER_SEQID_REDEYE:
        ((EnemyState*)state)->sightRange = 150.0f;
        ((EnemyState*)state)->aggroRange = 250.0f;
        ((EnemyState*)state)->current = 0x1e;
        ((EnemyState*)state)->userData2 = 0;
        ((EnemyState*)state)->moveId0 = 9;
        ((EnemyState*)state)->moveSpeedScale0 = 3.0f;
        ((EnemyState*)state)->moveId1 = 0xc;
        ((EnemyState*)state)->moveSpeedScale1 = 1.25f;
        ((EnemyState*)state)->moveId2 = 9;
        ((EnemyState*)state)->moveSpeedScale2 = 3.0f;
        ((EnemyState*)state)->flags2E4 |= 0x400;
        break;
    case FIRECRAWLER_SEQID_FIRECRAWLER:
        ((EnemyState*)state)->sightRange = 130.0f;
        ((EnemyState*)state)->aggroRange = 250.0f;
        ((EnemyState*)state)->current = 0x32;
        ((EnemyState*)state)->userData2 = 1;
        ((EnemyState*)state)->moveId0 = 0xe;
        ((EnemyState*)state)->moveSpeedScale0 = 3.0f;
        ((EnemyState*)state)->moveId1 = 0xd;
        ((EnemyState*)state)->moveSpeedScale1 = 1.25f;
        ((EnemyState*)state)->moveId2 = 0xe;
        ((EnemyState*)state)->moveSpeedScale2 = 3.0f;
        ((EnemyState*)state)->flags2E4 |= 0xc00;
        break;
    case FIRECRAWLER_SEQID_SHADOWHUNTER:
        ((EnemyState*)state)->sightRange = 120.0f;
        ((EnemyState*)state)->aggroRange = 240.0f;
        ((EnemyState*)state)->current = 0xf;
        ((EnemyState*)state)->userData2 = 2;
        ((EnemyState*)state)->moveId0 = 0xd;
        ((EnemyState*)state)->moveSpeedScale0 = 3.0f;
        ((EnemyState*)state)->moveId1 = 0x10;
        ((EnemyState*)state)->moveSpeedScale1 = 1.25f;
        ((EnemyState*)state)->moveId2 = 0xd;
        ((EnemyState*)state)->moveSpeedScale2 = 3.0f;
        ((EnemyState*)state)->flags2E4 |= 0xc00;
        break;
    }
    ((EnemyState*)state)->animPlaySpeed = 0.005f;
    ((EnemyState*)state)->gravity = 0.17f;
    ((EnemyState*)state)->drag = 0.97f;
    ((EnemyState*)state)->pathStep *= 10.0f;
    if (params->sequenceId != -1)
    {
        ((EnemyState*)state)->controlFlags |= 1;
    }
    obj->anim.rootMotionScale = 0.5f + ((f32)(s32)(s8)params->unk28 / 127.0f);
}
