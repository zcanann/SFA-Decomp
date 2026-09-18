#include "main/asset_load.h"
#include "main/gameloop_api.h"
#include "main/pi_dolphin.h"
#include "main/rcp_dolphin_api.h"
#include "main/model.h"
#include "main/resource.h"
#include "sys/objects.h"

typedef enum AssetLoadType {
    ASSET_LOAD_FILE = 0,
    ASSET_LOAD_FILE_BUFFER = 1,
    ASSET_LOAD_FILE_RANGE = 2,
    ASSET_LOAD_TEXTURE = 3,
    ASSET_LOAD_OBJECT = 4,
    ASSET_LOAD_RESOURCE = 5,
    ASSET_LOAD_MODEL = 6,
    ASSET_LOAD_ANIMATION = 7
} AssetLoadType;

typedef struct AssetLoadRequest {
    u8 pending;
    u8 type;
    u8 reserved[2];
    int resourceId;
    void* destination;
    union {
        struct {
            int size;
            int offset;
        } file;
        struct {
            int argument;
        } resource;
        struct {
            int argument;
        } model;
        struct {
            u8 unused[8];
            GameObject* parent;
            ObjPlacement* placement;
            int flags;
            int objectIndex;
            int mapLayer;
            int unusedArgument;
        } object;
        struct {
            int moveIndex;
            u8 unused[16];
            ObjAnimCachedMove* cache;
            ObjAnimDef* definition;
        } animation;
    } args;
} AssetLoadRequest;

STATIC_ASSERT(sizeof(AssetLoadRequest) == 0x2c);
STATIC_ASSERT(offsetof(AssetLoadRequest, pending) == 0);
STATIC_ASSERT(offsetof(AssetLoadRequest, type) == 1);
STATIC_ASSERT(offsetof(AssetLoadRequest, resourceId) == 4);
STATIC_ASSERT(offsetof(AssetLoadRequest, destination) == 8);
STATIC_ASSERT(offsetof(AssetLoadRequest, args.file.size) == 0x0c);
STATIC_ASSERT(offsetof(AssetLoadRequest, args.file.offset) == 0x10);
STATIC_ASSERT(offsetof(AssetLoadRequest, args.resource.argument) == 0x0c);
STATIC_ASSERT(offsetof(AssetLoadRequest, args.model.argument) == 0x0c);
STATIC_ASSERT(offsetof(AssetLoadRequest, args.object.parent) == 0x14);
STATIC_ASSERT(offsetof(AssetLoadRequest, args.object.placement) == 0x18);
STATIC_ASSERT(offsetof(AssetLoadRequest, args.object.flags) == 0x1c);
STATIC_ASSERT(offsetof(AssetLoadRequest, args.object.objectIndex) == 0x20);
STATIC_ASSERT(offsetof(AssetLoadRequest, args.object.mapLayer) == 0x24);
STATIC_ASSERT(offsetof(AssetLoadRequest, args.object.unusedArgument) == 0x28);
STATIC_ASSERT(offsetof(AssetLoadRequest, args.animation.moveIndex) == 0x0c);
STATIC_ASSERT(offsetof(AssetLoadRequest, args.animation.cache) == 0x20);
STATIC_ASSERT(offsetof(AssetLoadRequest, args.animation.definition) == 0x24);

static void loadAsset(AssetLoadRequest* req) {
    u8 modelScratch[0x10];

    switch (req->type) {
    case ASSET_LOAD_FILE:
        *(void**)req->destination = fileLoad(req->resourceId, 0);
        break;
    case ASSET_LOAD_FILE_BUFFER:
        fileLoadToBuffer(req->resourceId, req->destination);
        break;
    case ASSET_LOAD_FILE_RANGE:
        fileLoadToBufferOffset(req->resourceId, req->destination, req->args.file.offset, req->args.file.size);
        break;
    case ASSET_LOAD_OBJECT:
        *(void**)req->destination =
            loadCharacter(req->args.object.placement, req->args.object.flags, req->args.object.mapLayer,
                          req->args.object.objectIndex, req->args.object.parent, req->args.object.unusedArgument);
        break;
    case ASSET_LOAD_TEXTURE:
        *(void**)req->destination = (void*)textureLoad(req->resourceId, 0);
        break;
    case ASSET_LOAD_RESOURCE:
        *(void**)req->destination = Resource_Acquire(req->resourceId & 0xffff, req->args.resource.argument & 0xffff);
        break;
    case ASSET_LOAD_MODEL:
        *(void**)req->destination = loadModelInstance(req->resourceId, req->args.model.argument, modelScratch);
        break;
    case ASSET_LOAD_ANIMATION:
        *(void**)req->destination = loadAnimation(req->args.animation.definition, req->resourceId,
                                                  (s16)req->args.animation.moveIndex, req->args.animation.cache);
        break;
    }
}

void nop_onUnloadMap(int wpad0, int wpad1) {
}
void doNothing_startOfFrame(void) {
}
AssetLoadRequest gGameLoopAssetReq;

void animationLoad(void** out, int animId, int moveIndex, ObjAnimCachedMove* cache, ObjAnimDef* animDef) {
    gGameLoopAssetReq.pending = 1;
    gGameLoopAssetReq.type = ASSET_LOAD_ANIMATION;
    gGameLoopAssetReq.resourceId = (s16)animId;
    gGameLoopAssetReq.destination = out;
    gGameLoopAssetReq.args.animation.moveIndex = (s16)moveIndex;
    gGameLoopAssetReq.args.animation.cache = cache;
    gGameLoopAssetReq.args.animation.definition = animDef;
    loadAsset(&gGameLoopAssetReq);
}

void loadTextureFile(void** out, int assetId) {
    gGameLoopAssetReq.pending = 1;
    gGameLoopAssetReq.type = ASSET_LOAD_TEXTURE;
    gGameLoopAssetReq.resourceId = assetId;
    gGameLoopAssetReq.destination = out;
    loadAsset(&gGameLoopAssetReq);
}

void getTabEntry(void* dst, int fileId, int offset, int size) {
    gGameLoopAssetReq.pending = 1;
    gGameLoopAssetReq.type = ASSET_LOAD_FILE_RANGE;
    gGameLoopAssetReq.resourceId = fileId;
    gGameLoopAssetReq.destination = dst;
    gGameLoopAssetReq.args.file.offset = offset;
    gGameLoopAssetReq.args.file.size = size;
    loadAsset(&gGameLoopAssetReq);
}

void loadAssetFileById(void* out, int fileId) {
    gGameLoopAssetReq.pending = 1;
    gGameLoopAssetReq.type = ASSET_LOAD_FILE;
    gGameLoopAssetReq.resourceId = fileId;
    gGameLoopAssetReq.destination = out;
    loadAsset(&gGameLoopAssetReq);
}
