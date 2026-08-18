/* WM_Galleon (DLL 0x01F8) - the World Map galleon. */
#include "dlls/objects/504_WM_Galleon.h"

#include "main/dll/dll_0011_screens.h"
#include "main/frame_timing.h"
#include "main/gameloop_internal.h"
#include "main/mapEventTypes.h"
#include "main/object_render.h"
#include "main/objseq.h"
#include "sys/objects.h"
#include "main/dll/player_api.h"
#include "main/render_lactions_api.h"
#include "main/resource.h"
#include "main/track_dolphin_api.h"

u32 gWmGalleonFrameStep = 3;

#define WM_GALLEON_GAMEBIT_CLEAR_DOOR       0xD1
#define WM_GALLEON_SEQUENCE_ATTACHED        0x188
#define WM_GALLEON_COMMAND_OPENED           1
#define WM_GALLEON_COMMAND_CLEAR_LACTIONS   2
#define WM_GALLEON_COMMAND_SCREEN_FADE      3
#define WM_GALLEON_COMMAND_ACTION_12        4
#define WM_GALLEON_COMMAND_ACTION_13        5
#define WM_GALLEON_COMMAND_CLEAR_MAP_EVENTS 6
#define WM_GALLEON_COMMAND_SHOW_MODEL       7
#define WM_GALLEON_COMMAND_HIDE_MODEL       8
#define WM_GALLEON_COMMAND_ACTION_11        9
#define WM_GALLEON_ACTION_INITIAL           9
#define WM_GALLEON_ACTION_OPENED            10
#define WM_GALLEON_ACTION_11                11
#define WM_GALLEON_ACTION_12                12
#define WM_GALLEON_ACTION_13                13
#define WM_GALLEON_TRANSITION_ATTACHED      1
#define WM_GALLEON_TRANSITION_RESTORED      2
#define WM_GALLEON_ATTACHED_ALPHA           0x80
#define WM_GALLEON_OBJECT_SLOT              0x5A
#define WM_GALLEON_MAP_EVENT_GROUP_COUNT    5

void* gWmGalleonResource;
s8 gWMGalleonShowScreen;

ObjectDescriptor gWM_GalleonObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    WM_Galleon_initialise,
    WM_Galleon_release,
    0,
    (ObjectDescriptorCallback)WM_Galleon_init,
    (ObjectDescriptorCallback)WM_Galleon_update,
    WM_Galleon_hitDetect,
    (ObjectDescriptorCallback)WM_Galleon_render,
    (ObjectDescriptorCallback)WM_Galleon_free,
    (ObjectDescriptorCallback)WM_Galleon_getObjectTypeId,
    WM_Galleon_getExtraSize,
};

int WM_Galleon_SeqFn(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    int eventIndex;

    (void)unused;
    gWmGalleonFrameStep = framesThisStep;
    animUpdate->flags = -1;
    animUpdate->movementState = 0;
    for (eventIndex = 0; eventIndex < animUpdate->eventCount; eventIndex++) {
        switch (animUpdate->eventIds[eventIndex]) {
        case WM_GALLEON_COMMAND_OPENED:
            obj->userData1 = WM_GALLEON_ACTION_OPENED;
            break;
        case WM_GALLEON_COMMAND_ACTION_11:
            obj->userData1 = WM_GALLEON_ACTION_11;
            break;
        case WM_GALLEON_COMMAND_ACTION_12:
            obj->userData1 = WM_GALLEON_ACTION_12;
            break;
        case WM_GALLEON_COMMAND_ACTION_13:
            obj->userData1 = WM_GALLEON_ACTION_13;
            break;
        case WM_GALLEON_COMMAND_CLEAR_MAP_EVENTS:
            (*gMapEventInterface)->setObjGroupStatus(obj->anim.hostedMapSlot, 1, 0);
            (*gMapEventInterface)->setObjGroupStatus(obj->anim.hostedMapSlot, 2, 0);
            (*gMapEventInterface)->setObjGroupStatus(obj->anim.hostedMapSlot, 4, 0);
            mainSetBits(WM_GALLEON_GAMEBIT_CLEAR_DOOR, 0);
            break;
        case WM_GALLEON_COMMAND_CLEAR_LACTIONS:
            getLActions(obj, obj, 0x77, 0, 0, 0);
            getLActions(obj, obj, 0x78, 0, 0, 0);
            getLActions(obj, obj, 0x80, 0, 0, 0);
            break;
        case WM_GALLEON_COMMAND_SCREEN_FADE:
            ((void (*)(int, int, int))(*(void***)gDll12Interface)[5])(0, 0x1e, 0x50);
            break;
        case WM_GALLEON_COMMAND_SHOW_MODEL:
            gWMGalleonShowScreen = 1;
            break;
        case WM_GALLEON_COMMAND_HIDE_MODEL:
            gWMGalleonShowScreen = 0;
            break;
        }
    }

    if (mainGetBit(GAMEBIT_WM_GalleonRelated429) != 0) {
        if ((u8)(*gMapEventInterface)->getObjGroupStatus(obj->anim.hostedMapSlot, 2) != 0) {
            (*gMapEventInterface)->setObjGroupStatus(obj->anim.hostedMapSlot, 1, 0);
            (*gMapEventInterface)->setObjGroupStatus(obj->anim.hostedMapSlot, 2, 0);
        }
    }
    return 0;
}

int WM_Galleon_getExtraSize(void) {
    return sizeof(WMGalleonState);
}

int WM_Galleon_getObjectTypeId(void) {
    return 0;
}

void WM_Galleon_free(GameObject* obj, int leavingMap) {
    if (obj->anim.romDefNo != WM_GALLEON_SEQUENCE_ATTACHED) {
        WMGalleonState* state = obj->extra;
        if (state->mapEventsLatched != 0 && leavingMap == 0) {
            state->mapEventsLatched = 0;
        }
        if (gWmGalleonResource != NULL) {
            Resource_Release(gWmGalleonResource);
            gWmGalleonResource = NULL;
        }
    }
}

void WM_Galleon_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    if (mainGetBit(GAMEBIT_WM_Galleon_despawn) != 0) {
        return;
    }
    if (visible == 0) {
        return;
    }
    if (obj->anim.romDefNo == WM_GALLEON_SEQUENCE_ATTACHED && ((GameObject*)obj->anim.parent)->userData1 >= 7) {
        return;
    }

    objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);

    if (gWMGalleonShowScreen != 0) {
        gScreensInterface->vtable->show(1);
    }
}

void WM_Galleon_hitDetect(void) {
}

void WM_Galleon_update(GameObject* obj) {
    GameObject* player;
    WMGalleonState* state;
    int gameBitA4;

    if (mainGetBit(GAMEBIT_WM_Galleon_despawn) != 0) {
        return;
    }

    if (obj->anim.romDefNo == WM_GALLEON_SEQUENCE_ATTACHED) {
        obj->anim.alpha = WM_GALLEON_ATTACHED_ALPHA;
        return;
    }

    player = Obj_GetPlayerObject();
    state = obj->extra;

    if (mainGetBit(GAMEBIT_WM_GalleonRelated429) != 0) {
        if ((u8)(*gMapEventInterface)->getObjGroupStatus(obj->anim.hostedMapSlot, 2) != 0) {
            (*gMapEventInterface)->setObjGroupStatus(obj->anim.hostedMapSlot, 1, 0);
            (*gMapEventInterface)->setObjGroupStatus(obj->anim.hostedMapSlot, 2, 0);
        }
    } else if (mainGetBit(GAMEBIT_WM_GalleonRelated00D0) == 0 &&
               (u8)(*gMapEventInterface)->getObjGroupStatus(obj->anim.hostedMapSlot, 2) == 0) {
        (*gMapEventInterface)->setObjGroupStatus(obj->anim.hostedMapSlot, 1, 1);
        (*gMapEventInterface)->setObjGroupStatus(obj->anim.hostedMapSlot, 2, 1);
    }

    if (mainGetBit(GAMEBIT_WM_GalleonRelated00D0) == 0) {
        if (state->mapEventsLatched == 0 && mainGetBit(GAMEBIT_WM_GalleonRelated429) == 0) {
            (*gMapEventInterface)->setObjGroupStatus(obj->anim.hostedMapSlot, 1, 1);
            (*gMapEventInterface)->setObjGroupStatus(obj->anim.hostedMapSlot, 2, 1);
            state->mapEventsLatched = 1;
        }
    } else {
        if ((u8)(*gMapEventInterface)->getObjGroupStatus(obj->anim.hostedMapSlot, 4) == 0) {
            (*gMapEventInterface)->setObjGroupStatus(obj->anim.hostedMapSlot, 4, 1);
        }
        if (state->mapEventsLatched != 0) {
            state->mapEventsLatched = 0;
        }
    }

    gameBitA4 = mainGetBit(GAMEBIT_WM_GalleonRelated00A4);
    if (gameBitA4 != 0) {
        obj->userData1 = WM_GALLEON_ACTION_OPENED;
    }
    if (gameBitA4 == 0) {
        player->anim.localPosX = -121.0f;
        player->anim.localPosY = 116.0f;
        player->anim.localPosZ = 5.0f;
        Obj_SetParent(player, obj, 0);
        playerDisableHitDetect(player);
        obj->userData2 = WM_GALLEON_TRANSITION_ATTACHED;
    } else if (obj->userData2 == WM_GALLEON_TRANSITION_ATTACHED) {
        obj->anim.localPosX = state->savedX;
        obj->anim.localPosY = state->savedY;
        obj->anim.localPosZ = state->savedZ;
        obj->anim.rotX = state->savedRotationX;
        (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        obj->userData2 = WM_GALLEON_TRANSITION_RESTORED;
    }
}

void WM_Galleon_init(GameObject* obj, const WMGalleonSetup* setup) {
    WMGalleonState* state = obj->extra;
    int groupIndex;

    if (mainGetBit(GAMEBIT_WM_Galleon_despawn) != 0) {
        return;
    }
    if (obj->anim.romDefNo == WM_GALLEON_SEQUENCE_ATTACHED) {
        return;
    }
    objSetSlot(obj, WM_GALLEON_OBJECT_SLOT);
    obj->animEventCallback = WM_Galleon_SeqFn;
    obj->anim.rotX = (s16)(setup->rotationXByte << 8);
    obj->userData1 = WM_GALLEON_ACTION_INITIAL;
    state->savedX = obj->anim.localPosX;
    state->savedY = obj->anim.localPosY;
    state->savedZ = obj->anim.localPosZ;
    state->savedRotationX = obj->anim.rotX;
    trackSetLinesEnabledByParam(0, obj, 0);
    for (groupIndex = 0; groupIndex < WM_GALLEON_MAP_EVENT_GROUP_COUNT; groupIndex++) {
        (*gMapEventInterface)->setObjGroupStatus(obj->anim.hostedMapSlot, groupIndex, 0);
    }
    mainSetBits(GAMEBIT_WM_GalleonRelated00A4, 1);
}

void WM_Galleon_release(void) {
}

void WM_Galleon_initialise(void) {
}
