#include "main/dll/dll_80220608_shared.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"

#define WCTREXSTATU_CALLBACK_COMMANDS_OFFSET 0x81
#define WCTREXSTATU_CALLBACK_COMMAND_COUNT_OFFSET 0x8b
#define WCTREXSTATU_CALLBACK_TRIGGER 1

#define WCTREXSTATU_SETUP_TYPE_OFFSET 0x18
#define WCTREXSTATU_SETUP_MODEL_INDEX_OFFSET 0x19
#define WCTREXSTATU_SETUP_RAISED_BIT_OFFSET 0x1e

#define WCTREXSTATU_RENDER_TYPE_BASE 0x400
#define WCTREXSTATU_RENDER_TYPE_SHIFT 0xb
#define WCTREXSTATU_TEXTURE_TRIGGERED 0x100
#define WCTREXSTATU_TRIGGERED_FLAG_OFFSET 0xf4

#define WCTREXSTATU_PARTFX_VARIANT_0 0x73f
#define WCTREXSTATU_PARTFX_VARIANT_1 0x740
#define WCTREXSTATU_PARTFX_CHANCE 5
#define WCTREXSTATU_PARTFX_KIND 2
#define WCTREXSTATU_PARTFX_INVALID_HANDLE -1

#define WCTREXSTATU_MAPEVENT_RAISED 2

#pragma scheduling off
#pragma opt_strength_reduction off
int wctrexstatu_interactCallback(int obj, int unused, int callbackData)
{
    int i;

    for (i = 0; i < *(u8 *)(callbackData + WCTREXSTATU_CALLBACK_COMMAND_COUNT_OFFSET); i++) {
        if (((u8 *)callbackData)[i + WCTREXSTATU_CALLBACK_COMMANDS_OFFSET] == WCTREXSTATU_CALLBACK_TRIGGER) {
            int *texture = objFindTexture(obj, 0, 0);

            if (texture != NULL) {
                *texture = WCTREXSTATU_TEXTURE_TRIGGERED;
            }
            *(int *)(obj + WCTREXSTATU_TRIGGERED_FLAG_OFFSET) = 1;
        }
    }

    return 0;
}
#pragma opt_strength_reduction reset
#pragma scheduling reset

#pragma scheduling on
int wctrexstatu_getExtraSize(void) { return 0; }
#pragma scheduling reset

#pragma peephole on
#pragma scheduling off
int wctrexstatu_getObjectTypeId(int obj)
{
    ObjAnimComponent *objAnim = (ObjAnimComponent *)obj;
    int modelIndex = *(s8 *)(*(int *)&((GameObject *)obj)->anim.placementData + WCTREXSTATU_SETUP_MODEL_INDEX_OFFSET);
    int modelCount = objAnim->modelInstance->modelCount;

    if (modelIndex >= modelCount) {
        modelIndex = 0;
    }
    return (modelIndex << WCTREXSTATU_RENDER_TYPE_SHIFT) | WCTREXSTATU_RENDER_TYPE_BASE;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wctrexstatu_free(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling on
void wctrexstatu_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6E10);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wctrexstatu_hitDetect(u8 *obj)
{
    ObjAnimComponent *objAnim = (ObjAnimComponent *)obj;

    if (*(int *)(obj + WCTREXSTATU_TRIGGERED_FLAG_OFFSET) != 0 && randomGetRange(0, WCTREXSTATU_PARTFX_CHANCE) == 0) {
        if (objAnim->bankIndex == 0) {
            (*gPartfxInterface)->spawnObject(obj, WCTREXSTATU_PARTFX_VARIANT_0, NULL,
                                             WCTREXSTATU_PARTFX_KIND,
                                             WCTREXSTATU_PARTFX_INVALID_HANDLE, obj);
        } else {
            (*gPartfxInterface)->spawnObject(obj, WCTREXSTATU_PARTFX_VARIANT_1, NULL,
                                             WCTREXSTATU_PARTFX_KIND,
                                             WCTREXSTATU_PARTFX_INVALID_HANDLE, obj);
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wctrexstatu_update(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma scheduling off
void wctrexstatu_init(int obj, int setup, int fromLoad)
{
    ObjAnimComponent *objAnim = (ObjAnimComponent *)obj;
    ((GameObject *)obj)->animEventCallback = wctrexstatu_interactCallback;
    objAnim->bankIndex = *(u8 *)(setup + WCTREXSTATU_SETUP_MODEL_INDEX_OFFSET);
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount) {
        objAnim->bankIndex = 0;
    }

    *(s16 *)obj = (s16)((s8)*(u8 *)(setup + WCTREXSTATU_SETUP_TYPE_OFFSET) << 8);
    if (fromLoad == 0) {
        if ((*gMapEventInterface)->getMode(*(s8 *)(obj + 0xac)) == WCTREXSTATU_MAPEVENT_RAISED) {
            ((GameObject *)obj)->anim.localPosY = ((GameObject *)obj)->anim.localPosY + lbl_803E6E14;
        }
    }

    if ((u32)GameBit_Get(*(s16 *)(setup + WCTREXSTATU_SETUP_RAISED_BIT_OFFSET)) != 0) {
        int *texture = objFindTexture(obj, 0, 0);

        if (texture != NULL) {
            *texture = WCTREXSTATU_TEXTURE_TRIGGERED;
        }
        *(int *)(obj + WCTREXSTATU_TRIGGERED_FLAG_OFFSET) = 1;
    }
}
#pragma scheduling reset

#pragma peephole on
#pragma scheduling on
void wctrexstatu_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wctrexstatu_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset
