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

typedef struct FamilyTable
{
    u8* tbl0;
    u8* tbl4;
    u8* tbl8;
    u8* tblC;
    u8* tbl10;
    u8* tbl14;
    u8* tbl18;
    u8* tbl1c;
    u8* tbl20;
    u8* tbl24;
} FamilyTable;

#define WISPBADDIE_OBJFLAG_PARENT_SLACK 0x1000


typedef struct WispEventRow
{
    f32 blend; /* +0x0 */
    u32 flags; /* +0x4 (low byte = move flags) */
    u8 moveId; /* +0x8 */
    u8 pad9[3];
} WispEventRow;

STATIC_ASSERT(sizeof(WispEventRow) == 0xc);

STATIC_ASSERT(offsetof(WispEventRow, moveId) == 0x8);

/* explosive-barrel attackers; a hit from one skips the sword/impact sfx.
   retail OBJECTS.bin names "GunPowderBa" and "MetalBarrel" (both DLL 0x158) */

#define NEWSEQOBJ_ATTACKER_GUNPOWDERBARREL 0x6d
#define NEWSEQOBJ_ATTACKER_METALBARREL     0x754

/* per-family anim-table row: speed + flags + anim ids and chain links */

typedef struct
{
    f32 speed; /* 0x0 */
    u32 flags; /* 0x4 */
    u8 anim;   /* 0x8 */
    u8 next;   /* 0x9 */
    u8 alt;    /* 0xa */
    u8 padB;   /* 0xb */
    u32 extra; /* 0xc */
} SeqRow16;

typedef struct
{
    f32 speed; /* 0x0 */
    u32 flags; /* 0x4 */
    u8 anim;   /* 0x8 */
    u8 next;   /* 0x9 */
    u16 padA;  /* 0xa */
} IdleRow;

/* sidekick-toy main update: timer-driven 16-stride anim chain, curve chase
 * with speed/turn shaping, idle anims. */

/* sidekick-toy anim-chain advance: timer-driven 16-stride SeqRow16 chain +
 * curve-follow speed shaping, called from the sharpClawUpdateIdle update path. */

typedef struct GroundBaddieModelChainDescriptor
{
    void* entries;
    s32 count;
} GroundBaddieModelChainDescriptor;

STATIC_ASSERT(sizeof(GroundBaddieModelChainDescriptor) == 8);

typedef struct
{
    f32 speed;
    u32 mask;
    u8 anim;
    u8 pad9;
    u8 r;
    u8 g;
    u8 b;
    u8 pad13[3];
} SeqEntry;

typedef struct
{
    u8 pad00[0x14];
    u8* hitEntries;
    u8 pad18[4];
    u8* sequenceEntries;
    u8 pad20[8];
} GroundBaddieSequenceTable;

/* Routines live in sibling baddie/seq TUs (fn_8014*, getAngle, math*,
   player*, hud, ObjModelChain). DAT_/lbl_/PTR_ are shared .data/.sdata
   tables and FP constants. */

void groundBaddiePickIdleMove(GameObject* obj, u8* state);

void sharpClawUpdateAttack(GameObject* obj, u8* state);

void sharpClawInit(GameObject* obj, u8* state);

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

u8 gBaddieMoveProgressTable[288] = {
    0,   0,   0,  0,   0,   0,   0,  0,   0,   0,   0,  0,  0,  0,   0,  0, 0, 0,  0,   0,   0,  0, 0, 0, 0, 0,  0,
    0,   0,   0,  0,   0,   0,   0,  0,   0,   0,   0,  0,  0,  0,   0,  0, 0, 0,  0,   0,   0,  0, 0, 0, 0, 0,  0,
    0,   0,   0,  0,   0,   0,   0,  0,   0,   0,   0,  0,  0,  0,   0,  0, 0, 0,  0,   0,   0,  0, 0, 0, 0, 0,  0,
    0,   0,   0,  0,   0,   0,   0,  0,   0,   0,   0,  0,  0,  0,   0,  0, 0, 0,  0,   0,   0,  0, 0, 0, 0, 0,  0,
    0,   0,   0,  0,   0,   0,   0,  0,   0,   0,   0,  0,  0,  0,   0,  0, 0, 0,  0,   0,   0,  0, 0, 0, 0, 0,  0,
    0,   0,   0,  0,   0,   0,   0,  0,   0,   0,   0,  0,  0,  0,   0,  0, 0, 61, 163, 215, 10, 0, 0, 0, 0, 61, 163,
    215, 10,  61, 204, 204, 205, 61, 204, 204, 205, 0,  0,  0,  0,   0,  0, 0, 0,  0,   0,   0,  0, 0, 0, 0, 0,  61,
    163, 215, 10, 61,  163, 215, 10, 61,  35,  215, 10, 61, 35, 215, 10, 0, 0, 0,  0,   0,   0,  0, 0, 0, 0, 0,  0,
    0,   0,   0,  0,   0,   0,   0,  0,   0,   0,   0,  0,  0,  0,   0,  0, 0, 0,  0,   0,   0,  0, 0, 0, 0, 0,  0,
    0,   0,   0,  0,   0,   0,   0,  0,   0,   0,   0,  0,  0,  0,   0,  0, 0, 0,  0,   0,   0,  0, 0, 0, 0, 0,  0,
    0,   0,   0,  0,   0,   0,   0,  0,   0,   0,   0,  0,  0,  0,   0,  0, 0, 0};

u8 gSharpClawLocomotionMoves[48] = {60, 35, 215, 10, 0, 0, 0, 0, 0,  0, 0, 0, 60, 35, 215, 10, 0, 0, 0, 0, 11, 0, 0, 0,
                       60, 35, 215, 10, 0, 0, 0, 0, 15, 0, 0, 0, 60, 35, 215, 10, 0, 0, 0, 0, 12, 0, 0, 0};

u8 gSharpClawIdleMoveTable[324] = {
    0,  0,  0,  0,  0, 0, 0,  0,  13, 0,  0, 0, 64, 64,  0,  0,  0, 0, 0,  0,  0,  0,  0, 0, 64, 64,  0,  0,  0, 0,
    0,  0,  0,  0,  0, 0, 64, 64, 0,  0,  0, 0, 0,  0,   0,  0,  0, 0, 64, 64, 0,  0,  0, 0, 0,  0,   0,  0,  0, 0,
    64, 64, 0,  0,  0, 0, 0,  0,  0,  0,  0, 0, 64, 64,  0,  0,  0, 0, 0,  0,  0,  0,  0, 0, 64, 64,  0,  0,  0, 0,
    0,  0,  0,  0,  0, 0, 64, 64, 0,  0,  0, 0, 0,  0,   0,  0,  0, 0, 64, 64, 0,  0,  0, 0, 0,  0,   3,  0,  0, 0,
    64, 64, 0,  0,  0, 0, 0,  0,  3,  0,  0, 0, 64, 64,  0,  0,  0, 0, 0,  0,  6,  0,  0, 0, 64, 64,  0,  0,  0, 0,
    0,  0,  4,  0,  0, 0, 64, 64, 0,  0,  0, 0, 0,  0,   5,  0,  0, 0, 64, 64, 0,  0,  0, 0, 0,  0,   22, 25, 0, 0,
    64, 64, 0,  0,  0, 0, 0,  0,  6,  25, 0, 0, 63, 192, 0,  0,  0, 0, 0,  0,  24, 25, 0, 0, 63, 192, 0,  0,  0, 0,
    0,  0,  45, 25, 0, 0, 64, 64, 0,  0,  0, 0, 0,  0,   27, 26, 0, 0, 64, 64, 0,  0,  0, 0, 0,  0,   3,  25, 0, 0,
    64, 64, 0,  0,  0, 0, 0,  0,  7,  25, 0, 0, 64, 160, 0,  0,  0, 0, 0,  0,  26, 25, 0, 0, 64, 64,  0,  0,  0, 0,
    0,  0,  8,  25, 0, 0, 64, 0,  0,  0,  0, 0, 0,  0,   23, 25, 0, 0, 64, 64, 0,  0,  0, 0, 0,  0,   3,  25, 0, 0,
    64, 0,  0,  0,  0, 0, 0,  1,  11, 0,  0, 0, 64, 128, 0,  0,  0, 0, 0,  0,  30, 25, 0, 0};

u8 gSharpClawAnimEventMoves[300] = {
    63, 128, 0,  0, 0, 0, 0,  11,  64, 0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  60, 0, 0, 0, 63, 128, 0,  0, 0, 0,
    0,  11,  61, 0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  61, 0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  62, 0, 0, 0,
    63, 128, 0,  0, 0, 0, 0,  11,  62, 0, 0, 0, 0,  0,   0,  0, 0, 0, 0,  0,   0,  0, 0, 0, 0,  0,   0,  0, 0, 0,
    0,  0,   0,  0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  64, 0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  63, 0, 0, 0,
    63, 128, 0,  0, 0, 0, 0,  11,  61, 0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  61, 0, 0, 0, 63, 128, 0,  0, 0, 0,
    0,  11,  62, 0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  62, 0, 0, 0, 0,  0,   0,  0, 0, 0, 0,  0,   0,  0, 0, 0,
    0,  0,   0,  0, 0, 0, 0,  0,   0,  0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  64, 0, 0, 0, 63, 128, 0,  0, 0, 0,
    0,  11,  60, 0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  61, 0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  61, 0, 0, 0,
    63, 128, 0,  0, 0, 0, 0,  11,  62, 0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  62, 0, 0, 0, 0,  0,   0,  0, 0, 0,
    0,  11,  0,  0, 0, 0, 0,  0,   0,  0, 0, 0, 0,  0,   0,  0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  64, 0, 0, 0};

u8 gSharpClawBlockReactionMoves[300] = {62, 148, 122, 225, 0, 0, 0, 11, 69, 2, 2, 0, 62, 148, 122, 225, 0, 0, 0, 11, 65, 2, 2, 0,
                        62, 148, 122, 225, 0, 0, 0, 11, 66, 2, 2, 0, 62, 148, 122, 225, 0, 0, 0, 11, 66, 2, 2, 0,
                        62, 148, 122, 225, 0, 0, 0, 11, 67, 2, 2, 0, 62, 148, 122, 225, 0, 0, 0, 11, 67, 2, 2, 0,
                        0,  0,   0,   0,   0, 0, 0, 0,  0,  0, 0, 0, 0,  0,   0,   0,   0, 0, 0, 0,  0,  0, 0, 0,
                        62, 148, 122, 225, 0, 0, 0, 11, 69, 2, 0, 0, 62, 148, 122, 225, 0, 0, 0, 11, 68, 2, 0, 0,
                        62, 148, 122, 225, 0, 0, 0, 11, 66, 2, 0, 0, 62, 148, 122, 225, 0, 0, 0, 11, 66, 2, 0, 0,
                        62, 148, 122, 225, 0, 0, 0, 11, 67, 2, 0, 0, 62, 148, 122, 225, 0, 0, 0, 11, 67, 2, 0, 0,
                        0,  0,   0,   0,   0, 0, 0, 0,  0,  0, 0, 0, 0,  0,   0,   0,   0, 0, 0, 0,  0,  0, 0, 0,
                        62, 148, 122, 225, 0, 0, 0, 11, 69, 2, 0, 0, 62, 148, 122, 225, 0, 0, 0, 11, 65, 2, 0, 0,
                        62, 148, 122, 225, 0, 0, 0, 11, 66, 2, 0, 0, 62, 148, 122, 225, 0, 0, 0, 11, 66, 2, 0, 0,
                        62, 148, 122, 225, 0, 0, 0, 11, 67, 2, 0, 0, 62, 148, 122, 225, 0, 0, 0, 11, 67, 2, 0, 0,
                        0,  0,   0,   0,   0, 0, 0, 0,  0,  0, 0, 0, 0,  0,   0,   0,   0, 0, 0, 0,  0,  0, 0, 0,
                        62, 148, 122, 225, 0, 0, 0, 11, 69, 2, 0, 0};

u8 gSharpClawAttackHitVolumes[36] = {0, 0,  0,  0, 0, 0, 0, 11, 24, 1, 0, 0, 0, 0,  0,  0, 0, 0,
                       0, 12, 25, 1, 0, 0, 0, 0,  0,  0, 0, 0, 0, 10, 16, 1, 0, 0};

u8 gSharpClawModeIdleMoves[96] = {63, 128, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 63, 128, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0,
                       63, 0,   0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 0,  0,   0, 0, 0, 0, 0, 0, 0,  0, 0, 0,
                       0,  0,   0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 63, 0,   0, 0, 0, 0, 0, 0, 21, 0, 0, 0,
                       63, 128, 0, 0, 0, 0, 0, 0, 21, 0, 0, 0, 63, 128, 0, 0, 0, 0, 0, 0, 21, 0, 0, 0};

u8 gSharpClawHitReactionMoves[300] = {63, 0,   0,   0,   0, 0, 0, 0,  40, 0, 0, 0, 63, 0,   0,   0,   0, 0, 0, 0, 38, 0, 0, 0,
                        63, 76,  204, 205, 0, 0, 0, 1,  53, 0, 0, 0, 63, 0,   0,   0,   0, 0, 0, 0, 47, 0, 0, 0,
                        63, 76,  204, 205, 0, 0, 0, 1,  54, 0, 0, 0, 63, 0,   0,   0,   0, 0, 0, 0, 48, 0, 0, 0,
                        0,  0,   0,   0,   0, 0, 0, 0,  0,  0, 0, 0, 0,  0,   0,   0,   0, 0, 0, 0, 0,  0, 0, 0,
                        63, 192, 0,   0,   0, 0, 0, 0,  57, 7, 0, 0, 63, 0,   0,   0,   0, 0, 0, 0, 38, 9, 0, 0,
                        64, 0,   0,   0,   0, 0, 0, 1,  32, 0, 0, 0, 63, 0,   0,   0,   0, 0, 0, 0, 49, 9, 0, 0,
                        63, 0,   0,   0,   0, 0, 0, 0,  57, 7, 0, 0, 63, 0,   0,   0,   0, 0, 0, 0, 50, 9, 0, 0,
                        0,  0,   0,   0,   0, 0, 0, 0,  0,  0, 0, 0, 0,  0,   0,   0,   0, 0, 0, 0, 0,  0, 0, 0,
                        63, 76,  204, 205, 0, 0, 0, 0,  39, 3, 0, 0, 63, 0,   0,   0,   0, 0, 0, 0, 57, 7, 0, 0,
                        63, 153, 153, 154, 0, 0, 0, 0,  42, 1, 0, 0, 63, 153, 153, 154, 0, 0, 0, 0, 42, 1, 0, 0,
                        63, 153, 153, 154, 0, 0, 0, 0,  41, 2, 0, 0, 63, 153, 153, 154, 0, 0, 0, 0, 41, 2, 0, 0,
                        0,  0,   0,   0,   0, 0, 0, 0,  0,  0, 0, 0, 0,  0,   0,   0,   0, 0, 0, 0, 0,  0, 0, 0,
                        63, 192, 0,   0,   0, 0, 0, 11, 28, 3, 0, 0};

u8 gSharpClawReactionMoveChain[208] = {
    0,  0,   0,  0,  0, 0, 0, 0,  0,  0, 0, 0,  0, 0, 0, 0,  63, 192, 0,  0,  0, 0, 0, 11, 56, 1, 5, 10, 0, 0, 0, 64,
    63, 192, 0,  0,  0, 0, 0, 11, 55, 2, 6, 11, 0, 0, 0, 64, 63, 192, 0,  0,  0, 0, 0, 11, 29, 0, 0, 0,  0, 0, 0, 0,
    63, 192, 0,  0,  0, 0, 0, 3,  46, 0, 0, 0,  0, 0, 0, 0,  63, 192, 0,  0,  0, 0, 0, 11, 51, 0, 0, 0,  0, 0, 0, 0,
    63, 192, 0,  0,  0, 0, 0, 11, 52, 0, 0, 0,  0, 0, 0, 0,  63, 192, 0,  0,  0, 0, 0, 11, 59, 7, 8, 12, 0, 0, 0, 64,
    63, 64,  0,  0,  0, 0, 0, 11, 58, 0, 0, 0,  0, 0, 0, 0,  63, 128, 0,  0,  0, 0, 0, 11, 36, 0, 0, 0,  0, 0, 0, 0,
    63, 51,  51, 51, 0, 0, 0, 11, 70, 0, 0, 0,  0, 0, 0, 0,  63, 51,  51, 51, 0, 0, 0, 11, 70, 0, 0, 0,  0, 0, 0, 0,
    63, 51,  51, 51, 0, 0, 0, 11, 71, 0, 0, 0,  0, 0, 0, 0};

u8 gSharpClawMoveSelectTable[432] = {
    0,  0,   0,   0,   0, 0, 0, 0, 21, 0, 0, 0,   0, 0, 0, 0, 63, 128, 0,   0,   0, 0, 0, 0, 36, 0, 0,  0,   0, 0, 0, 0,
    63, 128, 0,   0,   0, 0, 0, 0, 24, 0, 5, 230, 1, 0, 0, 0, 63, 166, 102, 102, 0, 0, 0, 0, 25, 0, 9,  230, 1, 0, 0, 0,
    63, 128, 0,   0,   0, 0, 0, 0, 36, 0, 0, 0,   0, 0, 0, 0, 63, 166, 102, 102, 0, 0, 0, 0, 25, 0, 9,  230, 1, 0, 0, 0,
    64, 0,   0,   0,   0, 0, 0, 0, 7,  0, 0, 0,   0, 0, 0, 0, 63, 128, 0,   0,   0, 0, 0, 0, 36, 0, 0,  0,   0, 0, 0, 0,
    63, 128, 0,   0,   0, 0, 0, 0, 24, 0, 5, 230, 1, 0, 0, 0, 63, 128, 0,   0,   0, 0, 0, 0, 24, 0, 5,  230, 1, 0, 0, 0,
    63, 38,  102, 102, 0, 4, 0, 0, 17, 0, 0, 0,   0, 0, 0, 0, 63, 38,  102, 102, 0, 2, 0, 0, 18, 0, 0,  0,   0, 0, 0, 0,
    63, 38,  102, 102, 0, 2, 0, 0, 18, 0, 0, 0,   0, 0, 0, 0, 63, 128, 0,   0,   0, 0, 0, 0, 2,  0, 0,  0,   0, 0, 0, 0,
    63, 166, 102, 102, 0, 0, 0, 0, 25, 0, 9, 230, 1, 0, 0, 0, 63, 128, 0,   0,   0, 0, 0, 0, 24, 0, 5,  230, 1, 0, 0, 0,
    63, 38,  102, 102, 0, 8, 0, 0, 19, 0, 0, 0,   0, 0, 0, 0, 63, 128, 0,   0,   0, 1, 0, 0, 16, 0, 33, 230, 2, 0, 0, 0,
    63, 38,  102, 102, 0, 8, 0, 0, 19, 0, 0, 0,   0, 0, 0, 0, 63, 166, 102, 102, 0, 0, 0, 0, 25, 0, 9,  230, 1, 0, 0, 0,
    63, 128, 0,   0,   0, 0, 0, 0, 24, 0, 5, 230, 1, 0, 0, 0, 63, 38,  102, 102, 0, 2, 0, 0, 18, 0, 0,  0,   0, 0, 0, 0,
    63, 38,  102, 102, 0, 4, 0, 0, 17, 0, 0, 0,   0, 0, 0, 0, 63, 140, 204, 205, 0, 1, 0, 0, 16, 0, 33, 230, 2, 0, 0, 0,
    63, 12,  204, 205, 0, 1, 0, 0, 12, 0, 0, 0,   0, 0, 0, 0, 63, 38,  102, 102, 0, 8, 0, 0, 19, 0, 0,  0,   0, 0, 0, 0,
    63, 38,  102, 102, 0, 2, 0, 0, 18, 0, 0, 0,   0, 0, 0, 0};

u8 gSharpClawDeflectHitboxFlags[24] = {0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0};

u8 gSharpClawSoMoveSelectTable[432] = {0,  0,   0,   0,   0, 0, 0, 0, 21, 0,   0,   0,   0, 0, 0, 0, 63, 128, 0,   0,   0, 0, 0, 0,
                        36, 0,   0,   0,   0, 0, 0, 0, 63, 128, 0,   0,   0, 0, 0, 0, 24, 0,   5,   230, 1, 0, 0, 0,
                        63, 166, 102, 102, 0, 0, 0, 0, 25, 0,   9,   230, 1, 0, 0, 0, 63, 128, 0,   0,   0, 1, 0, 0,
                        16, 0,   33,  230, 2, 0, 0, 0, 63, 166, 102, 102, 0, 0, 0, 0, 25, 0,   9,   230, 1, 0, 0, 0,
                        63, 128, 0,   0,   0, 1, 0, 0, 16, 0,   33,  230, 2, 0, 0, 0, 63, 128, 0,   0,   0, 0, 0, 0,
                        36, 0,   0,   0,   0, 0, 0, 0, 63, 128, 0,   0,   0, 0, 0, 0, 24, 0,   5,   230, 1, 0, 0, 0,
                        63, 128, 0,   0,   0, 0, 0, 0, 24, 0,   5,   230, 1, 0, 0, 0, 63, 38,  102, 102, 0, 4, 0, 0,
                        17, 0,   0,   0,   0, 0, 0, 0, 63, 166, 102, 102, 0, 0, 0, 0, 25, 0,   9,   230, 1, 0, 0, 0,
                        63, 38,  102, 102, 0, 2, 0, 0, 18, 0,   0,   0,   0, 0, 0, 0, 63, 128, 0,   0,   0, 0, 0, 0,
                        2,  0,   0,   0,   0, 0, 0, 0, 63, 166, 102, 102, 0, 0, 0, 0, 25, 0,   9,   230, 1, 0, 0, 0,
                        63, 128, 0,   0,   0, 0, 0, 0, 24, 0,   5,   230, 1, 0, 0, 0, 63, 38,  102, 102, 0, 8, 0, 0,
                        19, 0,   0,   0,   0, 0, 0, 0, 63, 128, 0,   0,   0, 1, 0, 0, 16, 0,   33,  230, 2, 0, 0, 0,
                        63, 38,  102, 102, 0, 8, 0, 0, 19, 0,   0,   0,   0, 0, 0, 0, 63, 166, 102, 102, 0, 0, 0, 0,
                        25, 0,   9,   230, 1, 0, 0, 0, 63, 128, 0,   0,   0, 0, 0, 0, 24, 0,   5,   230, 1, 0, 0, 0,
                        63, 38,  102, 102, 0, 2, 0, 0, 18, 0,   0,   0,   0, 0, 0, 0, 63, 38,  102, 102, 0, 4, 0, 0,
                        17, 0,   0,   0,   0, 0, 0, 0, 63, 140, 204, 205, 0, 1, 0, 0, 16, 0,   33,  230, 2, 0, 0, 0,
                        63, 12,  204, 205, 0, 1, 0, 0, 12, 0,   0,   0,   0, 0, 0, 0, 63, 38,  102, 102, 0, 8, 0, 0,
                        19, 0,   0,   0,   0, 0, 0, 0, 63, 38,  102, 102, 0, 2, 0, 0, 18, 0,   0,   0,   0, 0, 0, 0};

u8 gSharpClawSoDeflectHitboxFlags[24] = {0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0};

u8 gSharpClawCoAttackHitVolumes[36] = {0, 0,  0,  0, 0, 0, 0, 11, 24, 2, 0, 0, 0, 0,  0,  0, 0, 0,
                       0, 10, 25, 2, 0, 0, 0, 0,  0,  0, 0, 0, 0, 24, 16, 4, 0, 0};

u8 gSharpClawCoMoveSelectTable[432] = {0,  0,   0,   0,   0, 0, 0, 0, 21, 0,   0,   0,   0, 0, 0, 0, 63, 128, 0,   0,   0, 0, 0, 0,
                        36, 0,   0,   0,   0, 0, 0, 0, 63, 128, 0,   0,   0, 0, 0, 0, 24, 0,   5,   230, 1, 0, 0, 0,
                        63, 102, 102, 102, 0, 0, 0, 0, 25, 0,   9,   230, 1, 0, 0, 0, 63, 128, 0,   0,   0, 1, 0, 0,
                        16, 0,   33,  230, 2, 0, 0, 0, 63, 102, 102, 102, 0, 0, 0, 0, 25, 0,   9,   230, 1, 0, 0, 0,
                        63, 128, 0,   0,   0, 1, 0, 0, 16, 0,   33,  230, 2, 0, 0, 0, 63, 128, 0,   0,   0, 0, 0, 0,
                        36, 0,   0,   0,   0, 0, 0, 0, 63, 128, 0,   0,   0, 0, 0, 0, 24, 0,   5,   230, 1, 0, 0, 0,
                        63, 128, 0,   0,   0, 0, 0, 0, 24, 0,   5,   230, 1, 0, 0, 0, 63, 38,  102, 102, 0, 4, 0, 0,
                        17, 0,   0,   0,   0, 0, 0, 0, 63, 102, 102, 102, 0, 0, 0, 0, 25, 0,   9,   230, 1, 0, 0, 0,
                        63, 38,  102, 102, 0, 2, 0, 0, 18, 0,   0,   0,   0, 0, 0, 0, 63, 128, 0,   0,   0, 0, 0, 0,
                        2,  0,   0,   0,   0, 0, 0, 0, 63, 102, 102, 102, 0, 0, 0, 0, 25, 0,   9,   230, 1, 0, 0, 0,
                        63, 128, 0,   0,   0, 0, 0, 0, 24, 0,   5,   230, 1, 0, 0, 0, 63, 38,  102, 102, 0, 8, 0, 0,
                        19, 0,   0,   0,   0, 0, 0, 0, 63, 128, 0,   0,   0, 1, 0, 0, 16, 0,   33,  230, 2, 0, 0, 0,
                        63, 38,  102, 102, 0, 8, 0, 0, 19, 0,   0,   0,   0, 0, 0, 0, 63, 102, 102, 102, 0, 0, 0, 0,
                        25, 0,   9,   230, 1, 0, 0, 0, 63, 128, 0,   0,   0, 0, 0, 0, 24, 0,   5,   230, 1, 0, 0, 0,
                        63, 38,  102, 102, 0, 2, 0, 0, 18, 0,   0,   0,   0, 0, 0, 0, 63, 38,  102, 102, 0, 4, 0, 0,
                        17, 0,   0,   0,   0, 0, 0, 0, 63, 140, 204, 205, 0, 1, 0, 0, 16, 0,   33,  230, 2, 0, 0, 0,
                        63, 12,  204, 205, 0, 1, 0, 0, 12, 0,   0,   0,   0, 0, 0, 0, 63, 38,  102, 102, 0, 8, 0, 0,
                        19, 0,   0,   0,   0, 0, 0, 0, 63, 38,  102, 102, 0, 2, 0, 0, 18, 0,   0,   0,   0, 0, 0, 0};

u8 gSharpClawCoDeflectHitboxFlags[24] = {1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0};

u8 gSharpClawAsMoveSelectTable[468] = {0,  0,   0,   0,   0, 0, 0, 0,  21, 0,   0,   0,   0, 0, 0, 0, 63, 128, 0,   0,   0,  0, 0, 0,
                        36, 0,   0,   0,   0, 0, 0, 0,  63, 128, 0,   0,   0, 0, 0, 0, 24, 0,   5,   230, 1,  0, 0, 0,
                        63, 166, 102, 102, 0, 0, 0, 0,  25, 0,   9,   230, 1, 0, 0, 0, 63, 128, 0,   0,   0,  1, 0, 0,
                        16, 0,   33,  230, 2, 0, 0, 0,  63, 166, 102, 102, 0, 0, 0, 0, 25, 0,   9,   230, 1,  0, 0, 0,
                        63, 128, 0,   0,   0, 1, 0, 0,  16, 0,   33,  230, 2, 0, 0, 0, 63, 38,  102, 102, 0,  8, 0, 0,
                        19, 0,   0,   0,   0, 0, 0, 0,  63, 128, 0,   0,   0, 0, 0, 0, 24, 0,   5,   230, 1,  0, 0, 0,
                        63, 128, 0,   0,   0, 0, 0, 0,  24, 0,   5,   230, 1, 0, 0, 0, 63, 38,  102, 102, 0,  4, 0, 0,
                        17, 0,   0,   0,   0, 0, 0, 0,  63, 166, 102, 102, 0, 0, 0, 0, 25, 0,   9,   230, 1,  0, 0, 0,
                        63, 38,  102, 102, 0, 2, 0, 0,  18, 0,   0,   0,   0, 0, 0, 0, 63, 128, 0,   0,   0,  0, 0, 0,
                        2,  0,   0,   0,   0, 0, 0, 0,  63, 166, 102, 102, 0, 0, 0, 0, 25, 0,   9,   230, 1,  0, 0, 0,
                        63, 128, 0,   0,   0, 1, 0, 0,  16, 0,   33,  230, 2, 0, 0, 0, 63, 128, 0,   0,   0,  0, 0, 0,
                        24, 0,   5,   230, 1, 0, 0, 0,  63, 128, 0,   0,   0, 1, 0, 0, 16, 0,   33,  230, 2,  0, 0, 0,
                        63, 38,  102, 102, 0, 8, 0, 0,  19, 0,   0,   0,   0, 0, 0, 0, 63, 166, 102, 102, 0,  0, 0, 0,
                        25, 0,   9,   230, 1, 0, 0, 0,  63, 128, 0,   0,   0, 0, 0, 0, 24, 0,   5,   230, 1,  0, 0, 0,
                        63, 38,  102, 102, 0, 2, 0, 0,  18, 0,   0,   0,   0, 0, 0, 0, 63, 38,  102, 102, 0,  4, 0, 0,
                        17, 0,   0,   0,   0, 0, 0, 0,  63, 140, 204, 205, 0, 1, 0, 0, 16, 0,   33,  230, 2,  0, 0, 0,
                        63, 12,  204, 205, 0, 1, 0, 0,  12, 0,   0,   0,   0, 0, 0, 0, 63, 38,  102, 102, 0,  8, 0, 0,
                        19, 0,   0,   0,   0, 0, 0, 0,  63, 38,  102, 102, 0, 2, 0, 0, 18, 0,   0,   0,   0,  0, 0, 0,
                        0,  0,   0,   0,   0, 0, 0, 11, 24, 1,   0,   0,   0, 0, 0, 0, 0,  0,   0,   12,  25, 1, 0, 0,
                        0,  0,   0,   0,   0, 0, 0, 10, 16, 2,   0,   0};

u8 gSharpClawAsDeflectHitboxFlags[24] = {0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0};

u8 gBossGeneralLocomotionMoves[48] = {60, 35, 215, 10, 0, 0, 0, 0, 0, 0, 0, 0, 60, 35, 215, 10, 0, 0, 0, 0, 1, 0, 0, 0,
                       60, 35, 215, 10, 0, 0, 0, 0, 2, 0, 0, 0, 60, 35, 215, 10, 0, 0, 0, 0, 1, 0, 0, 0};

u8 gBossGeneralIdleMoveTable[24] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 64, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

u8 gBossGeneralAnimEventMoves[300] = {
    63, 128, 0,  0, 0, 0, 0,  11,  20, 0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  16, 0, 0, 0, 63, 128, 0,  0, 0, 0,
    0,  11,  18, 0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  18, 0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  19, 0, 0, 0,
    63, 128, 0,  0, 0, 0, 0,  11,  19, 0, 0, 0, 0,  0,   0,  0, 0, 0, 0,  0,   0,  0, 0, 0, 0,  0,   0,  0, 0, 0,
    0,  0,   0,  0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  20, 0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  17, 0, 0, 0,
    63, 128, 0,  0, 0, 0, 0,  11,  18, 0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  18, 0, 0, 0, 63, 128, 0,  0, 0, 0,
    0,  11,  19, 0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  19, 0, 0, 0, 0,  0,   0,  0, 0, 0, 0,  0,   0,  0, 0, 0,
    0,  0,   0,  0, 0, 0, 0,  0,   0,  0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  20, 0, 0, 0, 63, 128, 0,  0, 0, 0,
    0,  11,  16, 0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  18, 0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  18, 0, 0, 0,
    63, 128, 0,  0, 0, 0, 0,  11,  19, 0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  19, 0, 0, 0, 0,  0,   0,  0, 0, 0,
    0,  11,  0,  0, 0, 0, 0,  0,   0,  0, 0, 0, 0,  0,   0,  0, 0, 0, 63, 128, 0,  0, 0, 0, 0,  11,  20, 0, 0, 0};

u8 gBossGeneralBlockReactionMoves[300] = {62, 148, 122, 225, 0, 0, 0, 11, 20, 2, 0, 0, 62, 148, 122, 225, 0, 0, 0, 11, 16, 2, 0, 0,
                        62, 148, 122, 225, 0, 0, 0, 11, 18, 2, 0, 0, 62, 148, 122, 225, 0, 0, 0, 11, 18, 2, 0, 0,
                        62, 148, 122, 225, 0, 0, 0, 11, 19, 2, 0, 0, 62, 148, 122, 225, 0, 0, 0, 11, 19, 2, 0, 0,
                        0,  0,   0,   0,   0, 0, 0, 0,  0,  0, 0, 0, 0,  0,   0,   0,   0, 0, 0, 0,  0,  0, 0, 0,
                        62, 148, 122, 225, 0, 0, 0, 11, 20, 2, 0, 0, 62, 148, 122, 225, 0, 0, 0, 11, 17, 2, 0, 0,
                        62, 148, 122, 225, 0, 0, 0, 11, 18, 2, 0, 0, 62, 148, 122, 225, 0, 0, 0, 11, 18, 2, 0, 0,
                        62, 148, 122, 225, 0, 0, 0, 11, 19, 2, 0, 0, 62, 148, 122, 225, 0, 0, 0, 11, 19, 2, 0, 0,
                        0,  0,   0,   0,   0, 0, 0, 0,  0,  0, 0, 0, 0,  0,   0,   0,   0, 0, 0, 0,  0,  0, 0, 0,
                        62, 148, 122, 225, 0, 0, 0, 11, 20, 2, 0, 0, 62, 148, 122, 225, 0, 0, 0, 11, 16, 2, 0, 0,
                        62, 148, 122, 225, 0, 0, 0, 11, 18, 2, 0, 0, 62, 148, 122, 225, 0, 0, 0, 11, 18, 2, 0, 0,
                        62, 148, 122, 225, 0, 0, 0, 11, 19, 2, 0, 0, 62, 148, 122, 225, 0, 0, 0, 11, 19, 2, 0, 0,
                        0,  0,   0,   0,   0, 0, 0, 0,  0,  0, 0, 0, 0,  0,   0,   0,   0, 0, 0, 0,  0,  0, 0, 0,
                        62, 148, 122, 225, 0, 0, 0, 11, 20, 2, 0, 0};

u8 gBossGeneralAttackHitVolumes[36] = {0, 0,  0, 0, 0, 0, 0, 11, 0, 1, 0, 0, 0, 0,  0, 0, 0, 0,
                       0, 12, 0, 1, 0, 0, 0, 0,  0, 0, 0, 0, 0, 10, 0, 1, 0, 0};

u8 gBossGeneralModeIdleMoves[96] = {63, 128, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 63, 128, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0,
                       63, 0,   0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0,  0,   0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                       0,  0,   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 63, 0,   0, 0, 0, 0, 0, 0, 7, 0, 0, 0,
                       63, 128, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 63, 128, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0};

u8 gBossGeneralHitReactionMoves[300] = {63, 0,   0,   0,   0, 0, 0, 0, 15, 0, 0, 0, 63, 0,   0,   0,   0, 0, 0, 0, 12, 0, 0, 0,
                        63, 76,  204, 205, 0, 0, 0, 0, 14, 0, 0, 0, 63, 0,   0,   0,   0, 0, 0, 0, 14, 0, 0, 0,
                        63, 76,  204, 205, 0, 0, 0, 0, 13, 0, 0, 0, 63, 0,   0,   0,   0, 0, 0, 0, 13, 0, 0, 0,
                        0,  0,   0,   0,   0, 0, 0, 0, 0,  0, 0, 0, 0,  0,   0,   0,   0, 0, 0, 0, 0,  0, 0, 0,
                        63, 192, 0,   0,   0, 0, 0, 0, 15, 0, 0, 0, 63, 0,   0,   0,   0, 0, 0, 0, 12, 0, 0, 0,
                        64, 0,   0,   0,   0, 0, 0, 0, 14, 0, 0, 0, 63, 0,   0,   0,   0, 0, 0, 0, 14, 0, 0, 0,
                        63, 0,   0,   0,   0, 0, 0, 0, 13, 0, 0, 0, 63, 0,   0,   0,   0, 0, 0, 0, 13, 0, 0, 0,
                        0,  0,   0,   0,   0, 0, 0, 0, 0,  0, 0, 0, 0,  0,   0,   0,   0, 0, 0, 0, 0,  0, 0, 0,
                        63, 76,  204, 205, 0, 0, 0, 0, 15, 0, 0, 0, 63, 0,   0,   0,   0, 0, 0, 0, 12, 0, 0, 0,
                        63, 153, 153, 154, 0, 0, 0, 0, 14, 0, 0, 0, 63, 153, 153, 154, 0, 0, 0, 0, 14, 0, 0, 0,
                        63, 153, 153, 154, 0, 0, 0, 0, 13, 0, 0, 0, 63, 153, 153, 154, 0, 0, 0, 0, 13, 0, 0, 0,
                        0,  0,   0,   0,   0, 0, 0, 0, 0,  0, 0, 0, 0,  0,   0,   0,   0, 0, 0, 0, 0,  0, 0, 0,
                        63, 192, 0,   0,   0, 0, 0, 0, 15, 0, 0, 0};

u8 gBossGeneralNullMoveChain[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

u8 gBossGeneralMoveSelectTable[240] = {
    0,  0,   0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 64, 0,   0, 0, 0, 0, 0, 0, 0, 0, 0,  0,   0, 0, 0, 0,
    63, 128, 0, 0, 0, 8, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 63, 128, 0, 0, 0, 1, 0, 0, 1, 0, 0,  0,   0, 0, 0, 0,
    64, 0,   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 63, 128, 0, 0, 0, 4, 0, 0, 3, 0, 0,  0,   0, 0, 0, 0,
    63, 128, 0, 0, 0, 2, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 63, 128, 0, 0, 0, 8, 0, 0, 5, 0, 0,  0,   0, 0, 0, 0,
    64, 0,   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 63, 128, 0, 0, 0, 2, 0, 0, 6, 0, 0,  0,   0, 0, 0, 0,
    63, 128, 0, 0, 0, 4, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 63, 128, 0, 0, 0, 1, 0, 0, 1, 0, 33, 230, 2, 0, 0, 0,
    63, 128, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 63, 128, 0, 0, 0, 8, 0, 0, 5, 0, 0,  0,   0, 0, 0, 0,
    63, 128, 0, 0, 0, 2, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0};

u8 gBossGeneralDeflectHitboxFlags[24] = {0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0};

FamilyTable gBaddieFamilyTables[6] = {
    {gSharpClawLocomotionMoves, gSharpClawIdleMoveTable, gSharpClawAnimEventMoves, gSharpClawMoveSelectTable, gSharpClawHitReactionMoves, gSharpClawAttackHitVolumes, gSharpClawModeIdleMoves, gSharpClawReactionMoveChain,
     gSharpClawDeflectHitboxFlags, gSharpClawBlockReactionMoves},
    {gSharpClawLocomotionMoves, gSharpClawIdleMoveTable, gSharpClawAnimEventMoves, gSharpClawMoveSelectTable, gSharpClawHitReactionMoves, gSharpClawAttackHitVolumes, gSharpClawModeIdleMoves, gSharpClawReactionMoveChain,
     gSharpClawDeflectHitboxFlags, gSharpClawBlockReactionMoves},
    {gSharpClawLocomotionMoves, gSharpClawIdleMoveTable, gSharpClawAnimEventMoves, gSharpClawSoMoveSelectTable, gSharpClawHitReactionMoves, gSharpClawAttackHitVolumes, gSharpClawModeIdleMoves, gSharpClawReactionMoveChain,
     gSharpClawSoDeflectHitboxFlags, gSharpClawBlockReactionMoves},
    {gSharpClawLocomotionMoves, gSharpClawIdleMoveTable, gSharpClawAnimEventMoves, gSharpClawCoMoveSelectTable, gSharpClawHitReactionMoves, gSharpClawCoAttackHitVolumes, gSharpClawModeIdleMoves, gSharpClawReactionMoveChain,
     gSharpClawCoDeflectHitboxFlags, gSharpClawBlockReactionMoves},
    {gSharpClawLocomotionMoves, gSharpClawIdleMoveTable, gSharpClawAnimEventMoves, gSharpClawAsMoveSelectTable, gSharpClawHitReactionMoves, gSharpClawAttackHitVolumes, gSharpClawModeIdleMoves, gSharpClawReactionMoveChain,
     gSharpClawAsDeflectHitboxFlags, gSharpClawBlockReactionMoves},
    {gBossGeneralLocomotionMoves, gBossGeneralIdleMoveTable, gBossGeneralAnimEventMoves, gBossGeneralMoveSelectTable, gBossGeneralHitReactionMoves, gBossGeneralAttackHitVolumes, gBossGeneralModeIdleMoves, gBossGeneralNullMoveChain,
     gBossGeneralDeflectHitboxFlags, gBossGeneralBlockReactionMoves},
};

u8 gBaddieEventDelayRanges[6][2] = {{15, 60}, {10, 50}, {7, 20}, {5, 20}, {3, 15}, {3, 15}};

f32 gBaddieFamilySpeedScales[6] = {0.5f, 0.5f, 0.7f, 0.6f, 1.5f, 1.5f};

u32 gGroundBaddieModelChainIds[4] = {6, 7, 8, 9};

u32 wispBaddieProcessAnimEvent(GameObject* obj, u8* state, u32 allowNewEvent)
{
    u8* base = gBaddieMoveProgressTable;
    u8* sequenceBase;
    WispEventRow* eventRows;
    u8 eventIndex;
    int ei;
    int flag20;
    u8 eventFlags;
    u32 stateFlags;
    u32 sequenceIndex;
    f32 blendScale;
    f32 blendTimer;
    int eventTableIndex;
    WispEventRow* row;
    u32 sf2;

    sequenceIndex = ((EnemyState*)state)->userData2;
    sequenceBase = base + sequenceIndex * 0x28;
    eventRows = *(WispEventRow**)(sequenceBase + 0x1444);
    stateFlags = ((EnemyState*)state)->controlFlags;
    if ((stateFlags & 0x4000) != 0)
    {
        return 0;
    }
    if (((EnemyState*)state)->sharpClaw.seqTimer && ((EnemyState*)state)->phaseAngle != 0)
    {
        return 0;
    }
    eventFlags = ((EnemyState*)state)->flags2F1;
    ei = eventFlags & 0x1f;
    eventIndex = ei;
    if ((ei & 0x10) != 0)
    {
        eventIndex = ei & ~0x8;
    }
    if (eventIndex > 0x18)
    {
        eventIndex = 0;
    }
    flag20 = eventFlags & 0x20;
    if (flag20 != 0)
    {
        blendScale = 3.0f;
        eventIndex = 0;
    }
    else
    {
        blendScale = 1.0f;
    }
    if ((u8)allowNewEvent != 0)
    {
        if ((eventFlags != 0 || ((EnemyState*)state)->sharpClaw.eventDelayTimer) &&
            (stateFlags & 0x40) == 0 && flag20 == 0)
        {
            if (((EnemyState*)state)->sharpClaw.eventDelayTimer)
            {
                ((EnemyState*)state)->sharpClaw.eventDelayTimer = ((EnemyState*)state)->sharpClaw.eventDelayTimer - timeDelta;
                if (((EnemyState*)state)->sharpClaw.eventDelayTimer <= 0.0f)
                {
                    ((EnemyState*)state)->sharpClaw.eventDelayTimer = 0.0f;
                }
                else
                {
                    return 0;
                }
            }
            else
            {
                eventTableIndex = sequenceIndex * 2;
                ((EnemyState*)state)->sharpClaw.eventDelayTimer =
                    ((EnemyState*)state)->intervalTimer +
                    (f32)(int)randomGetRange(base[eventTableIndex + 0x152c], base[eventTableIndex + 0x152d]);
                ((EnemyState*)state)->intervalTimer = 0.0f;
                return 0;
            }
        }
    }
    if ((((u8)allowNewEvent != 0 && ((EnemyState*)state)->flags2F1 != 0 && eventRows[eventIndex].moveId != 0) ||
         (((EnemyState*)state)->flags2F1 & 0x20) != 0) &&
        !(((EnemyState*)state)->familyData.sharpClaw.activeEventIndex == eventIndex && ((EnemyState*)state)->sharpClaw.moveHoldTimer != 0.0f))
    {
        sf2 = ((EnemyState*)state)->controlFlags;
        if ((sf2 & 0x800080) != 0 || (((EnemyState*)state)->flags2F1 & 0x20) != 0)
        {
            blendTimer = 60.0f * (blendScale * (row = &eventRows[eventIndex])->blend);
            ((EnemyState*)state)->sharpClaw.moveHoldDuration = blendTimer;
            ((EnemyState*)state)->sharpClaw.moveHoldTimer = blendTimer;
            ((EnemyState*)state)->controlFlags = ((EnemyState*)state)->controlFlags | 0x40;
            ((EnemyState*)state)->curveIndex = ((EnemyState*)state)->curveIndex | 0x80;
            ((EnemyState*)state)->curveParamA = 0;
            ((EnemyState*)state)->curveParamB = 0;
            Baddie_SetMove(obj, state, row->moveId, blendScale * row->blend, 0, row->flags & 0xff);
            ObjAnim_SetMoveProgress(&obj->anim, *(f32*)(base + row->moveId * 4));
            ((EnemyState*)state)->familyData.sharpClaw.activeEventIndex = eventIndex;
            return 1;
        }
        if ((sf2 & 0x40000000) != 0)
        {
            groundBaddiePickNextMove(obj, state);
        }
        return 0;
    }
    if (((EnemyState*)state)->sharpClaw.moveHoldTimer)
    {
        GameObject* pos = (GameObject*)((EnemyState*)state)->trackedObj;
        baddieTurnTowardPoint(obj, state, pos->anim.localPosX, pos->anim.localPosZ, 0xf, 0);
        if (((EnemyState*)state)->animPlaySpeed > 0.0166f)
        {
            ((EnemyState*)state)->animPlaySpeed = ((EnemyState*)state)->animPlaySpeed - 0.005f;
        }
        if ((((EnemyState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
        {
            eventTableIndex = ((EnemyState*)state)->familyData.sharpClaw.activeEventIndex;
            Baddie_SetMove(obj, state, eventRows[eventTableIndex].moveId,
                           eventRows[((EnemyState*)state)->familyData.sharpClaw.activeEventIndex].blend, 0,
                           eventRows[eventTableIndex].flags & 0xff);
            ObjAnim_SetMoveProgress(
                &obj->anim, *(f32*)(base + eventRows[((EnemyState*)state)->familyData.sharpClaw.activeEventIndex].moveId * 4));
        }
        ((EnemyState*)state)->sharpClaw.moveHoldTimer = ((EnemyState*)state)->sharpClaw.moveHoldTimer - timeDelta;
        if (((EnemyState*)state)->sharpClaw.moveHoldTimer <= 0.0f)
        {
            ((EnemyState*)state)->sharpClaw.moveHoldTimer = 0.0f;
            ((EnemyState*)state)->controlFlags = ((EnemyState*)state)->controlFlags & ~0x40LL;
            ((EnemyState*)state)->controlFlags =
                ((EnemyState*)state)->controlFlags | (u64)BADDIE_CONTROL_SEQUENCE_DRIVEN;
            ((EnemyState*)state)->curveIndex = ((EnemyState*)state)->curveIndex & ~0x80;
            ((EnemyState*)state)->familyData.sharpClaw.activeEventIndex = 0;
            return 0;
        }
        else
        {
            return 1;
        }
    }
    return 0;
}

void wispBaddiePlayMoveEventSfx(GameObject* obj, void* animState)
{
    GameObject* player;
    f32 distance;
    f32 rumbleFalloff;

    if ((((EnemyState*)animState)->animEventMask & 0x200) != 0)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_sml_trex_snap3);
        player = Obj_GetPlayerObject();
        if ((player->objectFlags & WISPBADDIE_OBJFLAG_PARENT_SLACK) == 0)
        {
            distance = Vec_distance(&(obj)->anim.worldPosX, &player->anim.worldPosX);
            if (distance <= 640.0f)
            {
                rumbleFalloff = 1.0f - distance / 640.0f;
                rumbleFalloff = 3.0f * rumbleFalloff;
                doRumble(rumbleFalloff);
            }
            CameraShake_ApplyRadial((obj)->anim.localPosX, (obj)->anim.localPosY, (obj)->anim.localPosZ, 640.0f,
                                    4.0f);
        }
    }
    if ((((EnemyState*)animState)->animEventMask & 0x40) != 0)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_spotfox01);
    }
    if ((((EnemyState*)animState)->animEventMask & 0x1000) != 0)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_scream1);
    }
    if ((((EnemyState*)animState)->animEventMask & 1) != 0)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_pullup2);
    }
    if ((((EnemyState*)animState)->animEventMask & 0x80) != 0)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_death01);
    }
}

void wispBaddieQueueNextEvent(GameObject* obj, int delta)
{
    u8* inner = ((GameObject*)obj)->extra;
    u8* ptr = gBaddieFamilyTables[inner[0x33b]].tbl4;
    inner[0x33d] = (u8)(delta + (u32)ptr[8] + 1);
    inner[0x33e] = 1;
}

u8 sharpClawHandleHitMessage(GameObject* obj, u8* state, GameObject* attacker, int msgId, int arrIdx, int damage,
                                Vec* hitPos, int sector, f32 hDist, f32 vDist)
{
    u8* animRows;
    u8* rowsC;
    u8* rowsB;
    u8* trig;
    u8 ret;

    animRows = gBaddieFamilyTables[((EnemyState*)state)->userData2].tbl10;
    rowsC = gBaddieFamilyTables[((EnemyState*)state)->userData2].tbl24;
    rowsB = gBaddieFamilyTables[((EnemyState*)state)->userData2].tbl1c;
    trig = gBaddieFamilyTables[((EnemyState*)state)->userData2].tbl20;
    ret = 0;

    if (((EnemyState*)state)->userData2 == 5)
    {
        ((EnemyState*)state)->flags2E8 |= 0x10;
        return 0;
    }
    if (msgId == 0xe)
    {
        damage = damage * 0xa;
    }
    if (obj->anim.currentMove == animRows[0x128])
    {
        return 0;
    }
    if (msgId == 0x10)
    {
        ((EnemyState*)state)->flags2E8 |= 0x28;
        return 0;
    }
    if ((((EnemyState*)state)->controlFlags & 0x40) != 0 ||
        (trig[arrIdx] != 0 && ((u32)(msgId - 0xe) <= 1 || msgId == 0x13)))
    {
        if (msgId != 0x11)
        {
            f32 z;
            if (msgId != 0x1a && attacker->anim.romDefNo != NEWSEQOBJ_ATTACKER_GUNPOWDERBARREL && attacker->anim.romDefNo != NEWSEQOBJ_ATTACKER_METALBARREL)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_swdout1);
                Sfx_PlayFromObject(obj, SFXTRIG_gethit02);
            }
            ((EnemyState*)state)->flags2E8 |= 0x10;
            {
                IdleRow* rows = (IdleRow*)rowsC;
                Baddie_SetMove(obj, state, rows[state[0x33c]].anim, *(f32*)(rowsC + state[0x33c] * 12), 0,
                               (u8)rows[state[0x33c]].flags);
            }
            ObjAnim_SetMoveProgress(&obj->anim,
                                    *(f32*)(gBaddieMoveProgressTable + rowsC[state[0x33c] * 12 + 8] * 4));
            if (rowsC[state[0x33c] * 12 + 0xa] != 0)
            {
                state[0x33a] = rowsC[state[0x33c] * 12 + 0xa];
            }
            ret = rowsC[((EnemyState*)state)->familyData.sharpClaw.activeEventIndex * 12 + 9];
            ((EnemyState*)state)->sharpClaw.moveHoldTimer = ((EnemyState*)state)->sharpClaw.moveHoldDuration;
            z = 0.0f;
            ((EnemyState*)state)->sharpClaw.eventDelayTimer = z;
            ((EnemyState*)state)->intervalTimer = z;
        }
    }
    else
    {
        u32 amount;
        f32 z;

        if (msgId == 0x11)
        {
            amount = 0x18;
        }
        else
        {
            amount = ((EnemyState*)state)->flags2F1 & 0x1f;
            if ((u32)(((EnemyState*)state)->flags2F1 & 0x1f) > 0x18)
            {
                amount = 0;
            }
        }
        z = 0.0f;
        ((EnemyState*)state)->sharpClaw.eventDelayTimer = z;
        if (state[0x2f1] & 0x18)
        {
            if (state[0x2f1] & 1)
            {
                ((EnemyState*)state)->intervalTimer = 50.0f;
            }
            else
            {
                ((EnemyState*)state)->intervalTimer = 30.0f;
            }
        }
        else
        {
            ((EnemyState*)state)->intervalTimer = z;
        }
        if (((EnemyState*)state)->sharpClaw.seqTimer && ((EnemyState*)state)->phaseAngle != 0)
        {
            {
                SeqRow16* rows = (SeqRow16*)rowsB;
                Baddie_SetMove(obj, state, rows[rowsB[((EnemyState*)state)->phaseAngle * 16 + 0xb]].anim,
                               *(f32*)(rowsB + rowsB[((EnemyState*)state)->phaseAngle * 16 + 0xb] * 16), 0,
                               (u8)rows[rowsB[((EnemyState*)state)->phaseAngle * 16 + 0xb]].flags);
            }
            ObjAnim_SetMoveProgress(
                &obj->anim,
                *(f32*)(gBaddieMoveProgressTable +
                        rowsB[rowsB[((EnemyState*)state)->phaseAngle * 16 + 0xb] * 16 + 8] * 4));
        }
        else
        {
            int off = (u8)amount * 12;
            IdleRow* rows = (IdleRow*)animRows;

            Baddie_SetMove(obj, state, rows[(u8)amount].anim, *(f32*)(animRows + (u8)amount * 12), 0,
                           (u8)rows[(u8)amount].flags);
            ObjAnim_SetMoveProgress(&obj->anim,
                                    *(f32*)(gBaddieMoveProgressTable + rows[(u8)amount].anim * 4));
            ((EnemyState*)state)->phaseAngle = animRows[off + 9];
            ((EnemyState*)state)->sharpClaw.seqTimer = (f32)(u32)((EnemyState*)state)->hitStunFrames;
        }
        ((EnemyState*)state)->flags2E8 |= 8;
        if (attacker->anim.classId == 0x1c)
        {
            return 0;
        }
        {
            GameObject* other = attacker->ownerObj;
            if (other != 0 && other->anim.classId == 0x1c)
            {
                return 0;
            }
        }
        if (((EnemyState*)state)->flags2F1 & 0x10)
        {
            damage = 0x14;
        }
        else
        {
            ((EnemyState*)state)->spawnBits = 0;
        }
        if (damage > ((EnemyState*)state)->current)
        {
            ((EnemyState*)state)->current = 0;
        }
        else
        {
            ((EnemyState*)state)->current = ((EnemyState*)state)->current - damage;
        }
        if (((EnemyState*)state)->current == 0)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_land);
        }
        else
        {
            Sfx_PlayFromObject(obj, SFXTRIG_attack);
        }
        if (msgId != 0x1a && msgId != 0x1f && attacker->anim.romDefNo != NEWSEQOBJ_ATTACKER_GUNPOWDERBARREL && attacker->anim.romDefNo != NEWSEQOBJ_ATTACKER_METALBARREL)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_stftest);
        }
    }
    return ret;
}

void sharpClawUpdateIdle(GameObject* obj, u8* state)
{
    RomCurveWalker* path = *(RomCurveWalker**)state;
    u8* tbl4;
    u8* tbl0;
    u8* tbl1c;
    u32 flags;

    tbl4 = gBaddieFamilyTables[((EnemyState*)state)->userData2].tbl4;
    tbl0 = gBaddieFamilyTables[((EnemyState*)state)->userData2].tbl0;
    tbl1c = gBaddieFamilyTables[((EnemyState*)state)->userData2].tbl1c;

    if (((EnemyState*)state)->userData2 == 5 && (((EnemyState*)state)->controlFlags & 0x800000))
    {
        mainSetBits(GAMEBIT_BaddieRelated1C8, 1);
    }
    wispBaddiePlayMoveEventSfx(obj, state);
    {
        f32 t = ((EnemyState*)state)->sharpClaw.seqTimer;
        f32 z = 0.0f;
        if (t != z && ((EnemyState*)state)->phaseAngle != 0)
        {
            ((EnemyState*)state)->sharpClaw.seqTimer = t - timeDelta;
            if (((EnemyState*)state)->sharpClaw.seqTimer <= z)
            {
                ((EnemyState*)state)->sharpClaw.seqTimer = z;
                ((EnemyState*)state)->controlFlags |= (u64)BADDIE_CONTROL_SEQUENCE_DRIVEN;
                ((EnemyState*)state)->phaseAngle = tbl1c[((EnemyState*)state)->phaseAngle * 16 + 0xa];
            }
        }
    }
    if ((u8)wispBaddieProcessAnimEvent(obj, state, 0) != 0)
    {
        return;
    }
    if (((EnemyState*)state)->familyData.sharpClaw.idleRow != 0)
    {
        if (((EnemyState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN)
        {
            f32 z = 0.0f;
            (obj)->anim.velocityZ = z;
            (obj)->anim.velocityY = z;
            (obj)->anim.velocityX = z;
            {
                IdleRow* idleRows = (IdleRow*)tbl4;
                Baddie_SetMove(obj, state, idleRows[((EnemyState*)state)->familyData.sharpClaw.idleRow].anim, *(f32*)(tbl4 + ((EnemyState*)state)->familyData.sharpClaw.idleRow * 12), 0,
                               (u8)idleRows[((EnemyState*)state)->familyData.sharpClaw.idleRow].flags);
            }
            ObjAnim_SetMoveProgress(&obj->anim,
                                    *(f32*)(gBaddieMoveProgressTable + tbl4[((EnemyState*)state)->familyData.sharpClaw.idleRow * 12 + 8] * 4));
            ((EnemyState*)state)->familyData.sharpClaw.idleRow = tbl4[((EnemyState*)state)->familyData.sharpClaw.idleRow * 12 + 9];
            ((EnemyState*)state)->familyData.sharpClaw.idleRowStarted = 0;
        }
        if (((EnemyState*)state)->familyData.sharpClaw.idleRowStarted == 0)
        {
            return;
        }
    }
    if ((((EnemyState*)state)->controlFlags & BADDIE_CONTROL_JUST_TRIGGERED) && ((EnemyState*)state)->familyData.sharpClaw.idleRow == 0)
    {
        sidekickToy_updateCurveTargetLatch(obj);
    }
    flags = ((EnemyState*)state)->controlFlags;
    if (flags & BADDIE_CONTROL_PATH_FOLLOW)
    {
        f32 dist;
        f32 delta;

        {
            f32 dx = path->posX - (obj)->anim.localPosX;
            f32 dz = path->posZ - (obj)->anim.localPosZ;
            dist = sqrtf(dx * dx + dz * dz);
        }
        if (dist > 64.0f)
        {
            dist = 64.0f;
        }
        {
            f32 diff = 64.0f - dist;
            f32 spd = diff / 64.0f;
            ((EnemyState*)state)->pathSpeed = spd * ((EnemyState*)state)->pathStep;
        }
        if (((EnemyState*)state)->pathSpeed < 0.25f)
        {
            ((EnemyState*)state)->pathSpeed = 0.25f;
        }
        if (Curve_AdvanceAlongPath(&path->curve, ((EnemyState*)state)->pathSpeed) != 0 || path->atSegmentEnd != 0)
        {
            if ((*gRomCurveInterface)->goNextPoint(path) != 0)
            {
                sidekickToy_updateCurveTargetLatch(obj);
            }
        }
        delta = (f32)(int)((u16)getAngle(path->tangentX, path->tangentZ) + 0x8000 - (u16)(obj)->anim.rotX);
        if (delta > 32768.0f)
        {
            delta = -65535.0f + delta;
        }
        if (delta < -32768.0f)
        {
            delta = 65535.0f + delta;
        }
        ((EnemyState*)state)->animPlaySpeed =
            (((EnemyState*)state)->pathStep - ((EnemyState*)state)->pathSpeed) / 60.0f *
            (1.0f - ((delta >= 0.0f) ? delta : -delta) / 65535.0f);
        if (*(f32*)(state + 0x308) < 0.005f)
        {
            *(f32*)(state + 0x308) = 0.005f;
        }
        if ((((EnemyState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) && ((EnemyState*)state)->familyData.sharpClaw.idleRow == 0)
        {
            if (((EnemyState*)state)->phaseAngle != 0)
            {
                SeqRow16* seqRow16 = (SeqRow16*)tbl1c;
                Baddie_SetMove(obj, state, seqRow16[((EnemyState*)state)->phaseAngle].anim,
                               *(f32*)(tbl1c + ((EnemyState*)state)->phaseAngle * 16), 0,
                               (u8)seqRow16[((EnemyState*)state)->phaseAngle].flags);
                ObjAnim_SetMoveProgress(
                    &obj->anim,
                    *(f32*)(gBaddieMoveProgressTable + tbl1c[((EnemyState*)state)->phaseAngle * 16 + 8] * 4));
                ((EnemyState*)state)->phaseAngle = tbl1c[((EnemyState*)state)->phaseAngle * 16 + 9];
            }
            else if (((EnemyState*)state)->pathSpeed > 0.0001f)
            {
                ((EnemyState*)state)->curveIndex = 0;
                ((EnemyState*)state)->curveParamA = 0;
                ((EnemyState*)state)->curveParamB = 0;
                if (((EnemyState*)state)->pathSpeed > 1.2f)
                {
                    ((EnemyState*)state)->rootMotionFlags = 1;
                    ObjAnim_SetCurrentMove(obj, tbl0[0x20], 0.0f, 0);
                }
                else
                {
                    ((EnemyState*)state)->rootMotionFlags = 1;
                    ObjAnim_SetCurrentMove(obj, tbl0[0x14], 0.0f, 0);
                }
            }
            else
            {
                ((EnemyState*)state)->curveIndex = 0;
                ((EnemyState*)state)->curveParamA = 0;
                ((EnemyState*)state)->curveParamB = 0;
                ((EnemyState*)state)->rootMotionFlags = 1;
                *(f32*)(state + 0x308) = 0.01f;
                ObjAnim_SetCurrentMove(obj, tbl0[8], 0.0f, 0);
                ((EnemyState*)state)->pathSpeed = 0.0f;
            }
        }
        baddieTurnTowardPoint(obj, state, path->posX, path->posZ, 0xf, 0);
    }
    else
    {
        if (((EnemyState*)state)->familyData.sharpClaw.idleRow == 0 && (flags & BADDIE_CONTROL_SEQUENCE_DRIVEN))
        {
            u8 r = randomGetRange(1, tbl4[8]);
            if (((EnemyState*)state)->phaseAngle != 0)
            {
                {
                    SeqRow16* seqRow16 = (SeqRow16*)tbl1c;
                    ((EnemyState*)state)->curveIndex = (u8)seqRow16[((EnemyState*)state)->phaseAngle].extra;
                    Baddie_SetMove(obj, state, seqRow16[((EnemyState*)state)->phaseAngle].anim,
                                   *(f32*)(tbl1c + ((EnemyState*)state)->phaseAngle * 16), 0,
                                   (u8)seqRow16[((EnemyState*)state)->phaseAngle].flags);
                }
                ObjAnim_SetMoveProgress(
                    &obj->anim,
                    *(f32*)(gBaddieMoveProgressTable + tbl1c[((EnemyState*)state)->phaseAngle * 16 + 8] * 4));
                ((EnemyState*)state)->phaseAngle = tbl1c[((EnemyState*)state)->phaseAngle * 16 + 9];
            }
            else
            {
                int off;
                IdleRow* row;
                if ((obj)->anim.currentMove != (r = (row = (IdleRow*)(tbl4 + (off = r * 12)))->anim) ||
                    r != 0)
                {
                    ((EnemyState*)state)->curveIndex = 0;
                    ((EnemyState*)state)->curveParamA = 0;
                    ((EnemyState*)state)->curveParamB = 0;
                    Baddie_SetMove(obj, state, row->anim, *(f32*)(tbl4 + off), 0, 3);
                    ObjAnim_SetMoveProgress(&obj->anim,
                                            *(f32*)(gBaddieMoveProgressTable + row->anim * 4));
                }
            }
        }
    }
}

void sharpClawUpdateApproach(GameObject* obj, void* state)
{
    u8* table = gBaddieMoveProgressTable;
    u8 idx = ((EnemyState*)state)->userData2;
    void* animCtrl = *(void**)(table + idx * 0x28 + 0x143c);
    IdleRow* idleSrc = (IdleRow*)(*(void**)(table + idx * 0x28 + 0x1454));
    u8* seqRows = *(u8**)(table + idx * 0x28 + 0x1458);

    if (idx == 5 && (((EnemyState*)state)->controlFlags & 0x800000) != 0)
    {
        mainSetBits(GAMEBIT_BaddieRelated1C8, 1);
    }

    if (((EnemyState*)state)->trackedObj != NULL &&
        ((GameObject*)((EnemyState*)state)->trackedObj)->anim.classId == 1)
    {
        requestKrazoaShrineMusic();
    }

    wispBaddiePlayMoveEventSfx(obj, state);

    {
        if (((EnemyState*)state)->sharpClaw.seqTimer && ((EnemyState*)state)->phaseAngle != 0)
        {
            f32 zero = 0.0f;
            ((EnemyState*)state)->sharpClaw.seqTimer = ((EnemyState*)state)->sharpClaw.seqTimer - timeDelta;
            if (((EnemyState*)state)->sharpClaw.seqTimer <= zero)
            {
                ((EnemyState*)state)->sharpClaw.seqTimer = zero;
                ((EnemyState*)state)->controlFlags |= (u64)BADDIE_CONTROL_SEQUENCE_DRIVEN;
                {
                    SeqRow16* seqRow16 = (SeqRow16*)seqRows;
                    ((EnemyState*)state)->phaseAngle = seqRow16[((EnemyState*)state)->phaseAngle].alt;
                }
            }
        }
    }

    if ((u8)wispBaddieProcessAnimEvent(obj, state, 0) != 0)
    {
        return;
    }

    if ((((EnemyState*)state)->controlFlags & 0x20000000) != 0 && (((EnemyState*)state)->prevControlFlags & 0x20000000) == 0)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_sc_mumble02);
        ((EnemyState*)state)->controlFlags |= (u64)BADDIE_CONTROL_SEQUENCE_DRIVEN;
    }

    if ((((EnemyState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
    {
        SeqRow16* seqRow16 = (SeqRow16*)seqRows;
        if (((EnemyState*)state)->phaseAngle != 0)
        {
            ((EnemyState*)state)->curveIndex = seqRow16[((EnemyState*)state)->phaseAngle].extra;
            Baddie_SetMove(obj, state, seqRow16[((EnemyState*)state)->phaseAngle].anim,
                           *(f32*)(seqRows + (((EnemyState*)state)->phaseAngle << 4)), 0,
                           (u8)seqRow16[((EnemyState*)state)->phaseAngle].flags);
            ObjAnim_SetMoveProgress(
                &obj->anim, *(f32*)(table + (seqRow16[((EnemyState*)state)->phaseAngle].anim << 2)));
            ((EnemyState*)state)->phaseAngle = seqRow16[((EnemyState*)state)->phaseAngle].next;
        }
        else
        {
            IdleRow* idleRows = idleSrc;
            u8 idleAnim;
            ((EnemyState*)state)->curveIndex = 0;
            ((EnemyState*)state)->curveParamA = 0;
            ((EnemyState*)state)->curveParamB = 0;
            idleAnim = idleRows[((EnemyState*)state)->turnOctant].anim;
            if (idleAnim == 0)
            {
                ((EnemyState*)state)->rootMotionFlags = 3;
                ObjAnim_SetCurrentMove(obj, *(u8*)((u8*)animCtrl + 0x2c), 0.0f, 0);
            }
            else
            {
                Baddie_SetMove(obj, state, idleAnim, idleRows[((EnemyState*)state)->turnOctant].speed, 0, 0xb);
                ObjAnim_SetMoveProgress(
                    &obj->anim, *(f32*)(table + (idleRows[((EnemyState*)state)->turnOctant].anim << 2)));
            }
        }
    }

    if ((s32)(obj)->anim.currentMove == *(u8*)((u8*)animCtrl + 0x2c))
    {
        ((EnemyState*)state)->animPlaySpeed =
            ((EnemyState*)state)->pathStep *
            (((f32)(u32)((EnemyState*)state)->targetDist / ((EnemyState*)state)->aggroRange / 60.0f) *
             ((f32*)(table + 0x1538))[((EnemyState*)state)->userData2]);
        if (((EnemyState*)state)->animPlaySpeed < 0.03f)
        {
            ((EnemyState*)state)->animPlaySpeed = 0.03f;
        }
    }

    if ((((EnemyState*)state)->rootMotionFlags & 8) == 0)
    {
        GameObject* tracked = (GameObject*)(((EnemyState*)state)->trackedObj);
        baddieTurnTowardPoint(obj, state, tracked->anim.localPosX,
                    tracked->anim.localPosZ, 0xf, 0);
    }
}

u8 gGroundBaddieAngleSectorOffsets[8] = {1, 4, 4, 3, 3, 5, 5, 1};

GroundBaddieModelChainDescriptor gGroundBaddieModelChainIdsDesc = {gGroundBaddieModelChainIds, 4};

GroundBaddieModelChainDescriptor gGroundBaddieModelChainDesc = {&gGroundBaddieModelChainIdsDesc, 0};

u16 gGroundBaddieTriggerResponseSeq[4] = {0x4FD, 0x4FE, 0x4FF, 0};

EnemyTargetSearchResult gGroundBaddieTargetSearchResult[16];

void groundBaddiePickIdleMove(GameObject* obj, u8* state)
{
    SeqEntry* entry;
    u32 idx;
    u8 wrapIdx;
    entry = (SeqEntry*)gBaddieFamilyTables[((EnemyState*)state)->userData2].tblC;
    if ((f32)((EnemyState*)state)->targetDist > 0.6f * ((EnemyState*)state)->sightRange)
    {
        if ((f32)((EnemyState*)state)->targetDist > 0.8f * ((EnemyState*)state)->sightRange)
        {
            ((EnemyState*)state)->userData1 = (u8)(entry[0].anim + 2);
        }
        else
        {
            ((EnemyState*)state)->userData1 = (u8)(entry[0].anim + 3);
        }
    }
    wrapIdx = 1;
    while (entry[idx = ((EnemyState*)state)->userData1].mask != 0 &&
           (((EnemyState*)state)->controlFlags & entry[idx].mask) == 0)
    {
        (((EnemyState*)state)->userData1)++;
        if (((EnemyState*)state)->userData1 > entry[0].anim)
        {
            ((EnemyState*)state)->userData1 = wrapIdx;
        }
    }
    ((EnemyState*)state)->curveIndex = entry[((EnemyState*)state)->userData1].r;
    ((EnemyState*)state)->curveParamA = entry[((EnemyState*)state)->userData1].g;
    ((EnemyState*)state)->curveParamB = entry[((EnemyState*)state)->userData1].b;
    baddieSetMove(obj, state, entry[((EnemyState*)state)->userData1].anim, entry[((EnemyState*)state)->userData1].speed, 0, 3);
    ObjAnim_SetMoveProgress(&obj->anim,
                            *(f32*)(gBaddieMoveProgressTable + entry[((EnemyState*)state)->userData1].anim * 4));
    (((EnemyState*)state)->userData1)++;
    if (((EnemyState*)state)->userData1 > entry[0].anim)
    {
        ((EnemyState*)state)->userData1 = 1;
    }
}

void groundBaddiePickNextMove(GameObject* obj, u8* state)
{
    SeqEntry* entry;
    u32 idx;
    s16 d;
    entry = (SeqEntry*)gBaddieFamilyTables[((EnemyState*)state)->userData2].tblC;
    if (enemy_findNearbyEnemies(obj, 100.0f, 1, 16, gGroundBaddieTargetSearchResult) >= 1)
    {
        if (gGroundBaddieTargetSearchResult[0].dist <= 40 && ((EnemyState*)state)->turnOctant != 3 &&
            ((EnemyState*)state)->turnOctant != 4)
        {
            d = getAngle(obj->anim.localPosX - gGroundBaddieTargetSearchResult[0].obj->anim.localPosX,
                         obj->anim.localPosZ - gGroundBaddieTargetSearchResult[0].obj->anim.localPosZ) -
                (u16)(obj)->anim.rotX;
            if (d > 0x8000)
            {
                d = (d - 0x10000) + 1;
            }
            if (d < -0x8000)
            {
                d = (d + 0x10000) - 1;
            }
            d = (s16)((u32)(u16)d >> 13);
            ((EnemyState*)state)->userData1 = (u8)(entry[0].anim + gGroundBaddieAngleSectorOffsets[d]);
        }
        else if (gGroundBaddieTargetSearchResult[0].dist <= 70)
        {
            while ((entry[((EnemyState*)state)->userData1].r & 1) != 0)
            {
                (((EnemyState*)state)->userData1)++;
                if (((EnemyState*)state)->userData1 > entry[0].anim)
                {
                    ((EnemyState*)state)->userData1 = 1;
                }
            }
        }
    }
    if ((f32)((EnemyState*)state)->targetDist < 0.8f * ((EnemyState*)state)->sightRange)
    {
        ((EnemyState*)state)->userData1 = (u8)(entry[0].anim + 1);
    }
    while (entry[idx = ((EnemyState*)state)->userData1].mask != 0 &&
           (((EnemyState*)state)->controlFlags & entry[idx].mask) == 0)
    {
        (((EnemyState*)state)->userData1)++;
        if (((EnemyState*)state)->userData1 > entry[0].anim)
        {
            ((EnemyState*)state)->userData1 = 1;
        }
    }
    ((EnemyState*)state)->curveIndex = entry[((EnemyState*)state)->userData1].r;
    ((EnemyState*)state)->curveParamA = entry[((EnemyState*)state)->userData1].g;
    ((EnemyState*)state)->curveParamB = entry[((EnemyState*)state)->userData1].b;
    baddieSetMove(obj, state, entry[((EnemyState*)state)->userData1].anim, entry[((EnemyState*)state)->userData1].speed, 0, 3);
    ObjAnim_SetMoveProgress(&obj->anim,
                            *(f32*)(gBaddieMoveProgressTable + entry[((EnemyState*)state)->userData1].anim * 4));
    (((EnemyState*)state)->userData1)++;
    if (((EnemyState*)state)->userData1 > entry[0].anim)
    {
        ((EnemyState*)state)->userData1 = 1;
    }
}

void sharpClawUpdateAttack(GameObject* obj, u8* state)
{
    GameObject* player;
    u8* p20;
    u8* p28;
    u8 tableIdx;
    f32 tv;
    f32 fz;
    GroundBaddieSequenceTable* table;

    table = (GroundBaddieSequenceTable*)gBaddieFamilyTables;
    tableIdx = ((EnemyState*)state)->userData2;
    p20 = table[tableIdx].hitEntries;
    p28 = table[tableIdx].sequenceEntries;
    if (tableIdx == 5 && (((EnemyState*)state)->controlFlags & 0x800000) != 0)
    {
        mainSetBits(GAMEBIT_BaddieRelated1C8, 1);
    }
    if (((EnemyState*)state)->trackedObj != NULL &&
        ((GameObject*)((EnemyState*)state)->trackedObj)->anim.classId == 1)
    {
        requestKrazoaShrineMusic();
    }
    wispBaddiePlayMoveEventSfx(obj, state);
    tv = ((EnemyState*)state)->sharpClaw.seqTimer;
    fz = 0.0f;
    if (tv != fz && ((EnemyState*)state)->phaseAngle != 0)
    {
        ((EnemyState*)state)->sharpClaw.seqTimer = tv - timeDelta;
        if (((EnemyState*)state)->sharpClaw.seqTimer <= fz)
        {
            ((EnemyState*)state)->sharpClaw.seqTimer = fz;
            ((EnemyState*)state)->controlFlags |= (u64)BADDIE_CONTROL_SEQUENCE_DRIVEN;
            ((EnemyState*)state)->phaseAngle = (p28 + ((EnemyState*)state)->phaseAngle * 16)[10];
        }
    }
    if ((u8)wispBaddieProcessAnimEvent(obj, state, 1) == 0)
    {
        if ((((EnemyState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
        {
            player = Obj_GetPlayerObject();
            enemy_findNearbyEnemies(obj, 100.0f, 3, 16, gGroundBaddieTargetSearchResult);
            if (((EnemyState*)state)->phaseAngle != 0)
            {
                {
                    u8* p28c = p28 + 12;
                    ((EnemyState*)state)->curveIndex = (u8) * (u32*)(p28c + ((EnemyState*)state)->phaseAngle * 16);
                }
                baddieSetMove(obj, state, (p28 + ((EnemyState*)state)->phaseAngle * 16)[8],
                            ((SeqEntry*)(p28 + ((EnemyState*)state)->phaseAngle * 16))->speed, 0,
                            (u8) * (u32*)(&p28[((EnemyState*)state)->phaseAngle * 16 + 4]));
                ObjAnim_SetMoveProgress(
                    &obj->anim,
                    *(f32*)(gBaddieMoveProgressTable + (p28 + ((EnemyState*)state)->phaseAngle * 16)[8] * 4));
                ((EnemyState*)state)->phaseAngle = (p28 + ((EnemyState*)state)->phaseAngle * 16)[9];
            }
            else
            {
                if (player != NULL && ((((EnemyState*)state)->controlFlags & 0x800080) != 0 ||
                                       (void*)Player_GetTargetObject((int)player) == NULL))
                {
                    groundBaddiePickIdleMove(obj, state);
                }
                else
                {
                    groundBaddiePickNextMove(obj, state);
                }
            }
        }
        ((ObjHitsPriorityState*)(obj)->anim.hitReactState)->hitVolumePriority = 0;
        ((ObjHitsPriorityState*)(obj)->anim.hitReactState)->hitVolumeId = 0;
        if ((obj)->anim.currentMove == p20[8])
        {
            ((ObjHitsPriorityState*)(obj)->anim.hitReactState)->hitVolumePriority = (s8) * (int*)(p20 + 4);
            ((ObjHitsPriorityState*)(obj)->anim.hitReactState)->hitVolumeId = p20[9];
        }
        if ((obj)->anim.currentMove == p20[0x14])
        {
            ((ObjHitsPriorityState*)(obj)->anim.hitReactState)->hitVolumePriority = (s8) * (int*)(p20 + 0x10);
            ((ObjHitsPriorityState*)(obj)->anim.hitReactState)->hitVolumeId = p20[0x15];
        }
        if ((obj)->anim.currentMove == p20[0x20])
        {
            ((ObjHitsPriorityState*)(obj)->anim.hitReactState)->hitVolumePriority = (s8) * (int*)(p20 + 0x1c);
            ((ObjHitsPriorityState*)(obj)->anim.hitReactState)->hitVolumeId = p20[0x21];
        }
        if ((((EnemyState*)state)->rootMotionFlags & 8) == 0)
        {
            baddieTurnTowardPoint(obj, state,
                        ((GameObject*)((EnemyState*)state)->trackedObj)->anim.localPosX,
                        ((GameObject*)((EnemyState*)state)->trackedObj)->anim.localPosZ, 10, 0);
        }
    }
}

void sharpClawInit(GameObject* obj, u8* state)
{
    GroundBaddiePlacement* setup = (GroundBaddiePlacement*)((GameObject*)obj)->anim.placementData;
    f32 fz;
    f32 fz2;
    int z;

    ((EnemyState*)state)->flags2E4 = 11;
    ((EnemyState*)state)->flags2E4 |= 0x402B0LL;
    ((EnemyState*)state)->flags2E4 |= 0x3040;
    ((EnemyState*)state)->flags2E4 |= 0x40300000LL;
    ((EnemyState*)state)->flags2E4 |= 0xC00;
    ((EnemyState*)state)->animPlaySpeed = 0.005f;
    ((EnemyState*)state)->gravity = 0.17f;
    ((EnemyState*)state)->drag = 0.97f;
    ((EnemyState*)state)->moveId0 = 35;
    fz = 1.0f;
    ((EnemyState*)state)->moveSpeedScale0 = fz;
    ((EnemyState*)state)->moveId1 = 34;
    ((EnemyState*)state)->moveSpeedScale1 = 1.25f;
    ((EnemyState*)state)->moveId2 = 6;
    ((EnemyState*)state)->moveSpeedScale2 = fz;
    ((EnemyState*)state)->pathStep *= 10.0f;
    switch (((GameObject*)obj)->anim.romDefNo)
    {
    case 314:
        if ((s8)setup->initialWeaponId != 0)
        {
            ((EnemyState*)state)->weaponRomDefNo = 51;
        }
        ((EnemyState*)state)->sightRange = 110.0f;
        ((EnemyState*)state)->current = 40;
        ((EnemyState*)state)->userData2 = 0;
        break;
    case 17:
        if ((s8)setup->initialWeaponId != 0)
        {
            ((EnemyState*)state)->weaponRomDefNo = 51;
        }
        ((EnemyState*)state)->sightRange = 110.0f;
        ((EnemyState*)state)->current = 40;
        ((EnemyState*)state)->userData2 = 1;
        break;
    case 1505:
        if ((s8)setup->initialWeaponId != 0)
        {
            ((EnemyState*)state)->weaponRomDefNo = 1529;
        }
        ((EnemyState*)state)->sightRange = 110.0f;
        ((EnemyState*)state)->current = 50;
        ((EnemyState*)state)->userData2 = 2;
        break;
    case 1463:
        if ((s8)setup->initialWeaponId != 0)
        {
            ((EnemyState*)state)->weaponRomDefNo = 1530;
        }
        ((EnemyState*)state)->sightRange = 120.0f;
        ((EnemyState*)state)->current = 50;
        ((EnemyState*)state)->userData2 = 3;
        break;
    case 1464:
        if ((s8)setup->initialWeaponId != 0)
        {
            ((EnemyState*)state)->weaponRomDefNo = 1534;
        }
        ((EnemyState*)state)->sightRange = 110.0f;
        ((EnemyState*)state)->current = 60;
        ((EnemyState*)state)->userData2 = 4;
        break;
    case 1465:
        if ((s8)setup->initialWeaponId != 0)
        {
            ((EnemyState*)state)->weaponRomDefNo = 51;
        }
        ((EnemyState*)state)->sightRange = 110.0f;
        ((EnemyState*)state)->current = 1;
        ((EnemyState*)state)->userData2 = 1;
        break;
    case 1958:
        if ((s8)setup->initialWeaponId != 0)
        {
            ((EnemyState*)state)->weaponRomDefNo = 1957;
        }
        ((EnemyState*)state)->sightRange = 110.0f;
        ((EnemyState*)state)->current = 160;
        ((EnemyState*)state)->userData2 = 5;
        z = 0;
        ((EnemyState*)state)->moveId0 = z;
        fz2 = 1.0f;
        ((EnemyState*)state)->moveSpeedScale0 = fz2;
        ((EnemyState*)state)->moveId1 = 21;
        ((EnemyState*)state)->moveSpeedScale1 = 1.25f;
        ((EnemyState*)state)->moveId2 = z;
        ((EnemyState*)state)->moveSpeedScale2 = fz2;
        ((EnemyState*)state)->tailSimHandle = ObjModelChain_Alloc(&gGroundBaddieModelChainDesc, 1);
        ObjModelChain_SetOrigin(((EnemyState*)state)->tailSimHandle, 0.15f, 0.75f, -0.05f);
        ((GameObject*)obj)->afterBonesCallback = baddieAfterUpdateBonesCb;
        ObjModelChain_SetEnabled(((EnemyState*)state)->tailSimHandle, 1);
        break;
    }
    if (setup->sequenceId != -1)
    {
        ((EnemyState*)state)->controlFlags |= 1;
    }
}

void groundBaddieHandlePaidTrigger(GameObject* obj, u8* state)
{
    GameObject* player;
    GroundBaddiePlacement* setup;

    player = Obj_GetPlayerObject();
    setup = (GroundBaddiePlacement*)((GameObject*)obj)->anim.placementData;
    if ((*gGameUIInterface)->isItemBeingUsed(446) != 0)
    {
        if (player != NULL && playerGetMoney(player) >= 25)
        {
            playerAddMoney(player, -25);
            mainSetBits(setup->gameBitD, 1);
            ((EnemyState*)state)->phaseAngle = gGroundBaddieTriggerResponseSeq[2];
            ((GameObject*)obj)->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
            setHudForceShowMask(2);
            (*gObjectTriggerInterface)->runSequence(2, (void*)obj, -1);
        }
        else
        {
            setHudForceShowMask(2);
            ((EnemyState*)state)->phaseAngle = gGroundBaddieTriggerResponseSeq[1];
            (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
        }
    }
    else
    {
        setHudForceShowMask(2);
        ((EnemyState*)state)->phaseAngle = gGroundBaddieTriggerResponseSeq[0];
        (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
    }
}
