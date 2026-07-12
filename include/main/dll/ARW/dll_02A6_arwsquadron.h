#ifndef MAIN_DLL_ARW_DLL_02A6_ARWSQUADRON_H
#define MAIN_DLL_ARW_DLL_02A6_ARWSQUADRON_H

#include "global.h"
#include "main/game_object.h"
#include "main/dll/curve_walker.h"

typedef struct SquadFlags
{
    u8 b80 : 1;
    u8 b40 : 1;
    u8 b20 : 1;
    u8 b10 : 1;
} SquadFlags;

typedef struct SquadCmdFlags
{
    u8 f80 : 1;
    u8 f40 : 1;
    u8 f20 : 1;
    u8 f10 : 1;
    u8 f08 : 1;
    u8 : 3;
} SquadCmdFlags;

typedef struct SquadPfx
{
    s16 s0;
    s16 s2;
    s16 s4;
    s16 s6;
    f32 f8;
    f32 fx;
    f32 fy;
    f32 fz;
} SquadPfx;

typedef struct ArwSquadronSetup
{
    s16 objectId;
    u8 pad02[0x16];
    u8 rotX;
    u8 rotY;
    u8 rotZ;
    u8 rotXSpeed;
    u8 rotYSpeed;
    u8 rotZSpeed;
    s8 leaderOffsetZ;
    u8 pad1F;
    int leaderObjectId;
    u16 exitDistance;
    s8 leaderOffsetX;
    s8 leaderOffsetY;
    u8 pad28[2];
    u16 volleyAngleSpread;
    u8 volleyCooldown;
    u8 shotInterval;
    u8 shotsPerVolley;
    u8 pathMode;
    u8 pathSpeed;
    u8 dialogueVariant;
    s16 gameBit;
} ArwSquadronSetup;

typedef struct ArwSquadronProjectileSetup
{
    s16 objectId;
    u8 pad02[2];
    u8 field04;
    u8 field05;
    u8 pad06[2];
    f32 posX;
    f32 posY;
    f32 posZ;
    u8 pad14[4];
    u8 rotX;
    u8 rotY;
    u8 rotZ;
} ArwSquadronProjectileSetup;

STATIC_ASSERT(offsetof(ArwSquadronProjectileSetup, field04) == 0x04);
STATIC_ASSERT(offsetof(ArwSquadronProjectileSetup, field05) == 0x05);
STATIC_ASSERT(offsetof(ArwSquadronProjectileSetup, posX) == 0x08);
STATIC_ASSERT(offsetof(ArwSquadronProjectileSetup, posY) == 0x0c);
STATIC_ASSERT(offsetof(ArwSquadronProjectileSetup, posZ) == 0x10);
STATIC_ASSERT(offsetof(ArwSquadronProjectileSetup, rotX) == 0x18);
STATIC_ASSERT(offsetof(ArwSquadronProjectileSetup, rotY) == 0x19);
STATIC_ASSERT(offsetof(ArwSquadronProjectileSetup, rotZ) == 0x1a);

typedef struct ArwSquadronPathCommand
{
    u8 pad00[0x18];
    u8 primaryCommand;
    s8 signature;
    s8 primaryValue;
    u8 pad1B[0x14];
    u8 secondaryCommand;
    u8 secondaryValue;
} ArwSquadronPathCommand;

typedef struct ArwSquadronState
{
    RomCurveWalker curve;
    f32 pathSpeed;
    f32 targetPathSpeed;
    f32 hitFlashTimer;
    f32 muzzleLightRadius;
    f32 muzzleLightIntensity;
    f32 damageSmokeScale;
    f32 fireFxScale;
    f32 volleyCooldownTimer;
    f32 shotIntervalTimer;
    f32 deathTimer;
    f32 activationDistance;
    f32 exitDistance;
    f32 rollAmplitude;
    GameObject* leaderObj;
    s16 rotXSpeed;
    s16 rotYSpeed;
    s16 rotZSpeed;
    u16 swayPhaseX;
    u16 swayPhaseY;
    u16 swaySpeedX;
    u16 swaySpeedY;
    s16 volleyAngle;
    s16 hitFadeRed;
    s16 hitFadeGreen;
    u8 hitFlashActive;
    u8 volleyShotsRemaining;
    u8 hitVolumeMode;
    u8 deathScore;
    u8 hitScore;
    u8 phase;
    u8 muzzleCount;
    u8 projectilePathCount;
    u8 variant;
    u8 dialogueVariant;
    u8 health;
    u8 fxFrameCounter;
    union
    {
        SquadFlags init;
        SquadCmdFlags cmd;
    } flags;
    u8 pad161[3];
} ArwSquadronState;

STATIC_ASSERT(sizeof(ArwSquadronState) == 0x164);
STATIC_ASSERT(offsetof(ArwSquadronState, curve) == 0x00);
STATIC_ASSERT(offsetof(ArwSquadronState, pathSpeed) == 0x108);
STATIC_ASSERT(offsetof(ArwSquadronState, volleyCooldownTimer) == 0x124);
STATIC_ASSERT(offsetof(ArwSquadronState, leaderObj) == 0x13c);
STATIC_ASSERT(offsetof(ArwSquadronState, flags) == 0x160);

extern int lbl_803E7160;
extern f32 lbl_803E7164;
extern f32 lbl_803E7168;
extern f32 lbl_803E716C;
extern f32 lbl_803E7170;
extern f32 lbl_803E7188;
extern f32 lbl_803E719C;
extern f32 lbl_803E71A0;
extern f32 lbl_803E71A4;
extern f32 lbl_803E71A8;
extern f32 lbl_803E71AC;
extern f32 lbl_803E71B0;
extern f32 lbl_803E71B4;
extern f32 lbl_803E71B8;
extern f32 lbl_803E71BC;
extern f32 lbl_803E71C0;
extern f32 lbl_803E71C4;
extern f32 lbl_803E71C8;
extern f32 lbl_803E71CC;
extern f32 lbl_803E71D0;
extern f32 lbl_803E71D4;
extern f32 gArwingSquadronPi;
extern f32 gArwingSquadronSwayPhaseToAngleDiv;

int ARWSquadron_getExtraSize(void);
int ARWSquadron_getObjectTypeId(void);
void ARWSquadron_free(void);
void ARWSquadron_render(int obj, int p2, int p3, int p4, int p5);
void ARWSquadron_hitDetect(void);
void ARWSquadron_init(GameObject* obj, ArwSquadronSetup* setup);
void ARWSquadron_update(int obj);

void arwsquadron_spawnProjectile(GameObject* obj, int pathIdx, int angle, int flag);
void arwsquadron_applyCommandParams(GameObject* obj, ArwSquadronState* state);
void arwsquadron_followPath(GameObject* obj, ArwSquadronState* state);
void arwsquadron_updateVolley(GameObject* obj, ArwSquadronState* state, ArwSquadronSetup* setup);
void arwsquadron_emitEffects(GameObject* obj, ArwSquadronState* state);
void arwsquadron_handleDamage(GameObject* obj, ArwSquadronState* state);
void arwsquadron_followLeader(GameObject* obj, ArwSquadronState* state);

#endif
