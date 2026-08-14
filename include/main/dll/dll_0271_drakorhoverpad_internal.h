#ifndef MAIN_DLL_DLL_0271_DRAKORHOVERPAD_INTERNAL_H_
#define MAIN_DLL_DLL_0271_DRAKORHOVERPAD_INTERNAL_H_

#include "game/objects/object.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/rom_curve_def.h"
#include "main/dll/dll_0271_drakorhoverpad.h"

extern const f32 gDrakorHoverpadSpeedStep;
extern f32 gDrakorHoverpadSteerMaxSpeed;
extern s16 lbl_803DC2FC;
extern f32 lbl_803DC300;
extern f32 lbl_803DC304;

typedef struct DrakorHoverpadUpdateMainPlacement
{
    s16 subtype;
    u8 pad02[0x18 - 0x02];
    s8 rotXByte;
    u8 pad19[0x1a - 0x19];
    s16 unk1a;
    u8 pad1c[0x20 - 0x1c];
    s16 activateGameBit;
    u8 pad22[0x28 - 0x22];
} DrakorHoverpadUpdateMainPlacement;

typedef struct DrakorHoverpadState
{
    f32 commandSpeed;
    RomCurveWalker curve; /* 0x004 */
    u8 pad10C[4];
    f32 speed;       /* 0x110 */
    f32 targetSpeed; /* 0x114 */
    f32 unk118;
    f32 unk11C;
    f32 unk120;
    u8 pad124[0x30];
    f32 particleEmitAX; /* 0x154 */
    f32 particleEmitAY; /* 0x158 */
    f32 particleEmitAZ; /* 0x15c */
    f32 particleEmitBX; /* 0x160 */
    f32 particleEmitBY; /* 0x164 */
    f32 particleEmitBZ; /* 0x168 */
    u8 pad16C[4];
    int unk170;
    s16 anglePhase;
    s16 frameCounter;
    DrakorHoverpadFlags flags;         /* 0x178 */
    DrakorHoverpadPathFlags pathFlags; /* 0x179 */
    u8 pad17A[2];
} DrakorHoverpadState;

STATIC_ASSERT(sizeof(DrakorHoverpadState) == 0x17c);

/* placement subtype id (desc[0]) selecting the pad behaviour mode */
#define DRAKORHOVERPAD_SUBTYPE_TRACKING   1812 /* tracks/yaws toward a nearby object */
#define DRAKORHOVERPAD_SUBTYPE_FREE       1048 /* free curve-follow, no tracking */
#define DRAKORHOVERPAD_OBJGROUP           0x46
#define DRAKORHOVERPAD_OBJGROUP_SECONDARY 0xa
#define DRAKORHOVERPAD_HIT_VOLUME_SLOT    8
/* group owned by another DLL, queried here */
#define BOSSDRAKOR_OBJGROUP 0x45 /* DLL 0x24D bossdrakor */

int drakorhoverpad_canMount(GameObject* obj);
int drakorhoverpad_canDismount(GameObject* obj);
void drakorhoverpad_getPlayerAnim(int obj, f32* outFloat, int* outFlag);
void drakorhoverpad_getRiderPosition(GameObject* obj, f32* ox, f32* oy, f32* oz);
f32 drakorhoverpad_func13(int obj, f32* out);
void drakorhoverpad_free(GameObject* obj);
void drakorhoverpad_func17(GameObject* obj, int sel, int* out);
void drakorhoverpad_getCameraPosition(GameObject* obj, f32* ox, f32* oy, f32* oz);
void drakorhoverpad_handleRiderScale(GameObject* obj, f32 scale);
int drakorhoverpad_getExtraSize(void);
int drakorhoverpad_getObjectTypeId(void);
void drakorhoverpad_free(GameObject* obj);
void drakorhoverpad_render(GameObject* obj, int p2, int p3, int p4, int p5, char visible);
void drakorhoverpad_hitDetect(void);
void drakorhoverpad_updateMain(GameObject* obj);
void drakorhoverpad_initMain(GameObject* obj, void* desc);
void drakorhoverpad_release(void);
void drakorhoverpad_initialise(void);
int drakorhoverpad_init(GameObject* obj);

#endif /* MAIN_DLL_DLL_0271_DRAKORHOVERPAD_INTERNAL_H_ */
