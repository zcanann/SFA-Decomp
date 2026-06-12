/* === moved from main/dll/SH/SHkillermushroom.c [801D3378-801D383C) (TU re-split, docs/boundary_audit.md) === */
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/dll/SH/dll_01A9_bombplant.h"
#include "main/objseq.h"

typedef struct BombplantsporeStartDriftBurstPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    s16 unk1C;
    u8 pad1E[0x20 - 0x1E];
} BombplantsporeStartDriftBurstPlacement;


typedef struct BombplantsporeUpdateDriftPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    s16 unk1C;
    u8 pad1E[0x20 - 0x1E];
} BombplantsporeUpdateDriftPlacement;




extern void ModelLightStruct_free(void* light);
extern int randomGetRange(int min, int max);
extern u32 GameBit_Get(int eventId);
extern void* Obj_GetPlayerObject(void);
extern void Sfx_PlayFromObject(void* obj, int sndId);
extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);


extern EffectInterface** gPartfxInterface;
extern ObjectTriggerInterface** gObjectTriggerInterface;

extern u8 framesThisStep;
extern f32 timeDelta;
extern f32 lbl_803E5390;
extern f32 lbl_803E5394;
extern f32 lbl_803E5398;
extern f32 lbl_803E539C;
extern f32 lbl_803E53A8;
extern f32 lbl_803E53AC;
extern f32 lbl_803E53B0;
extern f32 lbl_803E53B4;

/*
 * --INFO--
 *
 * Function: bombplantspore_getExtraSize
 * EN v1.0 Address: 0x801D3378
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int bombplantspore_getExtraSize(void);

/*
 * --INFO--
 *
 * Function: bombplantspore_free
 * EN v1.0 Address: 0x801D3380
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x801D3970
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void bombplantspore_free(void* obj);

/*
 * --INFO--
 *
 * Function: bombplantspore_startDriftBurst
 * EN v1.0 Address: 0x801D33D4
 * EN v1.0 Size: 456b
 * EN v1.1 Address: 0x801D39C4
 * EN v1.1 Size: 456b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
/* Keep the cross-TU bl: these two drift helpers' only callers
 * (bombplantspore_update/init) live in the BombPlantSpore TU
 * (SHrocketmushroom.c). Once they land there, dont_inline stops MWCC
 * auto-inlining them into bombplantspore_update. */
#pragma dont_inline on
void bombplantspore_startDriftBurst(void* obj, void* state);

/*
 * --INFO--
 *
 * Function: bombplantspore_updateDrift
 * EN v1.0 Address: 0x801D359C
 * EN v1.0 Size: 672b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void bombplantspore_updateDrift(void* obj, void* state);
#pragma dont_inline reset

/*
 * --INFO--
 *
 * Function: bombplant_init
 * EN v1.0 Address: 0x801D3238
 * EN v1.0 Size: 320b
 */
void bombplant_init(void* obj, void* param, int flag);

/*
 * --INFO--
 *
 * Function: bombplant_update
 * EN v1.0 Address: 0x801D2C54
 * EN v1.0 Size: 1508b
 */

#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/dll/path_control_interface.h"
#include "main/objseq.h"
#include "main/dll/SH/SHrocketmushroom.h"
#include "main/dll/SH/dll_01AC_shqueenearthwalker.h"


extern uint GameBit_Get(int bit);
extern int gameBitDecrement(int bit);
extern int gameBitIncrement(int bit);
extern void Sfx_PlayFromObject(void* obj, int id);
extern void* ObjHits_GetPriorityHit(void* obj, void* pos, int p3, int p4);
extern int ObjMsg_Pop(void* obj, u32* outMessage, u32* outSender, u32* outParam);
extern int ObjTrigger_IsSetById(void* obj, int triggerId);
extern void objRenderFn_80041018(void* obj);
extern void Sfx_StopObjectChannel(void* obj, int channel);
extern void Obj_FreeObject(void* obj);
extern void objMove(f32 x, f32 y, f32 z, void* obj);
extern int fn_8003B500(void* obj, void* p2, f32 f1);
extern int fn_8003B228(void* obj, void* p2);
extern int characterDoEyeAnims(void* obj, void* p2);
extern void* objCreateLight(void* obj, int arg);
extern void modelLightStruct_setEnabled(void* light, int enabled, f32 scale);
extern void modelLightStruct_setLightKind(void* light, int value);
extern void modelLightStruct_setDiffuseColor(void* light, int r, int g, int b, int a);
extern void lightSetFieldBC_8001db14(void* light, int value);
extern void modelLightStruct_setDistanceAttenuation(void* light, f32 min, f32 max);
extern void ObjMsg_AllocQueue(void* obj, int count);
extern void ObjMsg_SendToObject(void* dst, int msg, void* src, void* payload);
extern void objfx_spawnDirectionalBurst(void* obj, u8 idx, u8 kind, u8 mode, u8 chance, void* origin,
                                        int flags, f32 f8val, f32 mult);

extern u8 lbl_80326D98[];
extern u8 lbl_803DBFC0;
extern f32 lbl_803E5388;
extern f32 lbl_803E538C;
extern f32 lbl_803E53B8;
extern f32 lbl_803E53BC;
extern f32 lbl_803E53C0;
extern f32 lbl_803E53C4;
extern f32 lbl_803E53C8;
extern f64 lbl_803E53D0;
extern f64 lbl_803E53D8;
extern f32 lbl_803E53E0;
extern f32 lbl_803E53E4;
extern f32 lbl_803E53E8;
extern f32 lbl_803E53EC;
extern f32 lbl_803E53F8;
extern f32 lbl_803E53F0;
extern f32 lbl_803E53F4;

#define BOMBPLANT_GAME_BIT_AVAILABLE_SPORES 0x66c
#define BOMBPLANT_GAME_BIT_FIRST_SPOT_TRIGGER 0x196
#define BOMBPLANTSPORE_MSG_DETONATE 0x7000b
#define BOMBPLANTSPORE_MSG_HIT_PLAYER 0x7000a
#define BOMBPLANTSPORE_PLAYER_DAMAGE_TYPE 0x18e
#define BOMBPLANTSPORE_STATE_FLAG_WAITING_FOR_DETONATE_ACK 0x40
#define BOMBPLANTSPORE_STATE_FLAG_HIT_SURFACE 0x80
#define BOMBPLANTSPORE_EXPLOSION_PARTICLE_COUNT 10
#define BOMBPLANTINGSPOT_MODEL_HIDDEN_FLAG 0x08
#define BOMBPLANTINGSPOT_READY_FLAG 0x10

void bombplantspore_update(void* obj);

void bombplantspore_init(void* obj, void* param2);

void bombplantingspot_update(void* obj)
{
    extern int GameBit_Set(int bit, int value); /* #57 */
    BombPlantingSpotMapData* mapData = *(BombPlantingSpotMapData**)&((GameObject*)obj)->anim.placementData;
    s32 trigBit;

    *(s16*)obj = (s16)(mapData->yawByte << 8);

    trigBit = mapData->requiredGameBit;
    if (trigBit != -1 && GameBit_Get(trigBit) == 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= BOMBPLANTINGSPOT_MODEL_HIDDEN_FLAG;
        return;
    }

    if (GameBit_Get(BOMBPLANT_GAME_BIT_AVAILABLE_SPORES) == 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= BOMBPLANTINGSPOT_READY_FLAG;
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~BOMBPLANTINGSPOT_READY_FLAG;
    }

    if (ObjTrigger_IsSetById(obj, BOMBPLANT_GAME_BIT_AVAILABLE_SPORES) != 0)
    {
        gameBitDecrement(BOMBPLANT_GAME_BIT_AVAILABLE_SPORES);
        GameBit_Set(mapData->plantedGameBit, 1);
        (*gObjectTriggerInterface)->runSequence(1, obj, -1);
    }
    else if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 0x4) != 0 &&
        GameBit_Get(BOMBPLANT_GAME_BIT_FIRST_SPOT_TRIGGER) == 0)
    {
        (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        GameBit_Set(BOMBPLANT_GAME_BIT_FIRST_SPOT_TRIGGER, 1);
    }

    if (GameBit_Get(mapData->plantedGameBit) == 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~BOMBPLANTINGSPOT_MODEL_HIDDEN_FLAG;
        objRenderFn_80041018(obj);
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= BOMBPLANTINGSPOT_MODEL_HIDDEN_FLAG;
    }
}

void bombplantingspot_init(void* obj, BombPlantingSpotMapData* mapData)
{
    ((GameObject*)obj)->objectFlags |= 0x4000;
    *(s16*)obj = (s16)(mapData->yawByte << 8);
}

int sh_queenearthwalker_processAnimEvents(void* obj, void* unused, ObjAnimUpdateState* animUpdate);
