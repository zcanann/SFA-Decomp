#ifndef MAIN_DLL_LGT_DLL_02AA_LGTDIRECTIONALLIGHT_H_
#define MAIN_DLL_LGT_DLL_02AA_LGTDIRECTIONALLIGHT_H_

#include "main/game_object.h"
#include "main/dll/dll_80220608_shared.h"

typedef struct DirectionalLightSetup
{
    ObjPlacement base;
    u8 rotX;
    u8 rotY;
    u8 diffuseR;
    u8 diffuseG;
    u8 diffuseB;
    u8 eventName;
    s16 enableBit;
    u8 pad20[0x26 - 0x20];
    u8 colorFadeSpeed;
    u8 targetR;
    u8 targetG;
    u8 targetB;
    u8 flags;
    u8 pad2B;
    u8 selectionPriority;
    u8 pad2D;
    s16 colorFadeFrames;
    u8 enabled;
    u8 pad31;
    s16 rotXSpeed;
    s16 rotYSpeed;
} DirectionalLightSetup;

typedef struct DirectionalLightState
{
    u8 diffuseR;
    u8 diffuseG;
    u8 diffuseB;
    u8 pad03;
    u8 targetR;
    u8 targetG;
    u8 targetB;
    u8 pad07;
    ModelLight* light;
    u8 debugEditing;
    s8 debugField;
    u8 enabled;
    u8 pad0F;
} DirectionalLightState;

STATIC_ASSERT(sizeof(DirectionalLightState) == 0x10);
STATIC_ASSERT(offsetof(DirectionalLightState, light) == 0x08);
STATIC_ASSERT(offsetof(DirectionalLightState, debugEditing) == 0x0C);
STATIC_ASSERT(offsetof(DirectionalLightState, debugField) == 0x0D);
STATIC_ASSERT(offsetof(DirectionalLightState, enabled) == 0x0E);
STATIC_ASSERT(offsetof(DirectionalLightSetup, rotX) == 0x18);
STATIC_ASSERT(offsetof(DirectionalLightSetup, rotY) == 0x19);
STATIC_ASSERT(offsetof(DirectionalLightSetup, diffuseR) == 0x1A);
STATIC_ASSERT(offsetof(DirectionalLightSetup, eventName) == 0x1D);
STATIC_ASSERT(offsetof(DirectionalLightSetup, enableBit) == 0x1E);
STATIC_ASSERT(offsetof(DirectionalLightSetup, flags) == 0x2A);
STATIC_ASSERT(offsetof(DirectionalLightSetup, selectionPriority) == 0x2C);
STATIC_ASSERT(offsetof(DirectionalLightSetup, colorFadeFrames) == 0x2E);
STATIC_ASSERT(offsetof(DirectionalLightSetup, enabled) == 0x30);
STATIC_ASSERT(offsetof(DirectionalLightSetup, rotXSpeed) == 0x32);
STATIC_ASSERT(offsetof(DirectionalLightSetup, rotYSpeed) == 0x34);
STATIC_ASSERT(sizeof(DirectionalLightSetup) == 0x38);

struct DirectionalLightObjDescriptorLayout
{
    u32 reserved0;
    u32 reserved1;
    u32 reserved2;
    u32 slotCountAndFlags;
    void (*callbacks[10])(void);
    char debugStrings[0xE0];
};

void directionallight_debugEdit(GameObject* obj, int statePtr);
int directionallight_getExtraSize(void);
int directionallight_getObjectTypeId(void);
void directionallight_free(GameObject* obj);
void directionallight_render(int obj, int p2, int p3, int p4, int p5, f32 scale);
void directionallight_hitDetect(void);
void directionallight_update(GameObject* obj);
void directionallight_init(GameObject* obj, int setup);
void directionallight_release(void);
void directionallight_initialise(void);

#endif /* MAIN_DLL_LGT_DLL_02AA_LGTDIRECTIONALLIGHT_H_ */
