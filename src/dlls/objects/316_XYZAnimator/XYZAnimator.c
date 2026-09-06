/* Applies a game-bit-controlled XYZ offset to map-block polygons and display-list bounds. */
#include "dlls/objects/316_XYZAnimator.h"

#include "dolphin/os/OSCache.h"
#include "main/audio/sfx_keep_alive_api.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/lightmap_api.h"
#include "main/map_block.h"
#include "main/mm.h"
#include "main/object_render.h"
#include "main/objtype.h"
#include "main/pi_dolphin_api.h"
#include "main/track_dolphin_api.h"

f32 XyzAnimator_getCoordinate(GameObject* obj, u8 coordinate) {
    XyzAnimatorState* state;

    if (obj == NULL || (state = (XyzAnimatorState*)obj->extra, state == NULL)) {
        return 0.0f;
    }
    switch (coordinate) {
    case XYZ_ANIMATOR_COORD_WORLD_X:
        return obj->anim.localPosX + state->offsetX;
    case XYZ_ANIMATOR_COORD_OFFSET_X:
        return state->offsetX;
    case XYZ_ANIMATOR_COORD_WORLD_Y:
        return obj->anim.localPosY + state->offsetY;
    case XYZ_ANIMATOR_COORD_OFFSET_Y:
        return state->offsetY;
    case XYZ_ANIMATOR_COORD_WORLD_Z:
        return obj->anim.localPosZ + state->offsetZ;
    case XYZ_ANIMATOR_COORD_OFFSET_Z:
        return state->offsetZ;
    }
    return 0.0f;
}

void XyzAnimator_captureGeometry(XyzAnimatorPlacement* placement, XyzAnimatorState* state, MapBlockData* blockAddress) {
    Vec3s* vertex;
    int vertexDataOffset[1];
    int groupDataOffset[1];
    int triangleDataOffset[1];
    int blockIndex;
    int triangle;
    int triangleEnd;
    u16* mapEntry;
    int t;
    int dataOffset;
    int index;
    int boundsBufferOffset[1];
    int displayListIndex[1];
    MapBlockData* blockData = blockAddress;

    vertexDataOffset[0] = 0;
    boundsBufferOffset[0] = 0;
    blockIndex = 0;
    groupDataOffset[0] = 0;
    triangleDataOffset[0] = groupDataOffset[0];
    for (; blockIndex < (int)(u32)blockData->polyGroupCount; blockIndex++) {
        mapEntry = (u16*)mapBlockGetPolygonGroup(blockAddress, blockIndex);
        t = mapBlockGetPolygonGroupType(mapEntry);
        if ((int)placement->blockLayer == t) {
            *(s16*)(state->posABuffer + groupDataOffset[0]) = ((MapTriGroup*)mapEntry)->minY;
            *(s16*)(state->posBBuffer + groupDataOffset[0]) = ((MapTriGroup*)mapEntry)->maxY;
            groupDataOffset[0] += 2;
            triangleEnd = mapEntry[10];
            triangle = *mapEntry;
            vertexDataOffset[0] = triangleDataOffset[0];
            for (; triangle < triangleEnd; triangle++) {
                mapEntry = mapBlockGetPolygon(blockAddress, triangle);
                dataOffset = vertexDataOffset[0];
                for (index = 0; index != 3; index++) {
                    vertex = &((Vec3s*)blockData->vertices)[mapEntry[index]];
                    ((Vec3s*)(state->geometryBuffer + dataOffset))->x = vertex->x;
                    ((Vec3s*)(state->geometryBuffer + dataOffset))->y = vertex->y;
                    ((Vec3s*)(state->geometryBuffer + dataOffset))->z = vertex->z;
                    dataOffset += 6;
                }
                vertexDataOffset[0] += 0x12;
                triangleDataOffset[0] += 0x12;
            }
        }
    }
    displayListIndex[0] = 0;
    boundsBufferOffset[0] = displayListIndex[0];
    for (; displayListIndex[0] < (int)(u32)blockData->displayListCount; displayListIndex[0]++) {
        blockIndex = (int)mapBlockGetDisplayListBounds(blockAddress, displayListIndex[0]);
        *(s16*)(state->minXBuffer + boundsBufferOffset[0]) = ((MapBlockBoundsRec*)blockIndex)->minX;
        *(s16*)(state->maxXBuffer + boundsBufferOffset[0]) = ((MapBlockBoundsRec*)blockIndex)->maxX;
        *(s16*)(state->minYBuffer + boundsBufferOffset[0]) = ((MapBlockBoundsRec*)blockIndex)->minY;
        *(s16*)(state->maxYBuffer + boundsBufferOffset[0]) = ((MapBlockBoundsRec*)blockIndex)->maxY;
        *(s16*)(state->minZBuffer + boundsBufferOffset[0]) = ((MapBlockBoundsRec*)blockIndex)->minZ;
        *(s16*)(state->maxZBuffer + boundsBufferOffset[0]) = ((MapBlockBoundsRec*)blockIndex)->maxZ;
        boundsBufferOffset[0] += 2;
    }
}

int XyzAnimator_getExtraSize(void) {
    return sizeof(XyzAnimatorState);
}

void XyzAnimator_free(GameObject* obj, int flags) {
    int blockAddress;
    XyzAnimatorState* state;
    XyzAnimatorPlacement* placement;
    f32 zeroOffset;

    state = (XyzAnimatorState*)obj->extra;
    placement = (XyzAnimatorPlacement*)obj->anim.placementData;
    zeroOffset = 0.0f;
    state->offsetX = zeroOffset;
    state->offsetY = zeroOffset;
    state->offsetZ = zeroOffset;
    if (flags == 0) {
        blockAddress =
            objPosToMapBlockIdx((double)obj->anim.localPosX, (double)obj->anim.localPosY, (double)obj->anim.localPosZ);
        blockAddress = (int)mapGetBlock(blockAddress);
        if (((void*)blockAddress != NULL) && (state->vertexCount != 0)) {
            XyzAnimator_applyToMapBlock(placement, state, (MapBlockData*)blockAddress);
        }
    }
    if ((void*)state->geometryBuffer != NULL) {
        mm_free((void*)state->geometryBuffer);
    }
    objFreeObjectType(obj, XYZ_ANIMATOR_OBJECT_GROUP);
}

void XyzAnimator_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    s32 isVisible = visible;

    if (isVisible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void XyzAnimator_applyToMapBlock(XyzAnimatorPlacement* placement, XyzAnimatorState* state, MapBlockData* blockAddress) {
    Vec3s* vertex;
    MapBlockData* blockData = blockAddress;
    int vertexOffset[1];
    int vertexIndex;
    int polygonGroupIndex;
    int polygonGroupType;
    int dataOffset;
    u16* mapEntry;
    f32 scale;
    int triangle;
    int triangleEnd;
    int index;
    int groupDataOffset[1];
    void* shaderLayer;

    polygonGroupIndex = 0;
    groupDataOffset[0] = 0;
    vertexOffset[0] = groupDataOffset[0];
    for (; polygonGroupIndex < (int)(u32)blockData->polyGroupCount; polygonGroupIndex++) {
        mapEntry = (u16*)mapBlockGetPolygonGroup(blockAddress, polygonGroupIndex);
        polygonGroupType = mapBlockGetPolygonGroupType(mapEntry);
        if ((int)placement->blockLayer == polygonGroupType) {
            ((MapTriGroup*)mapEntry)->minY =
                (s16)(state->offsetY + (f32) * (s16*)(state->posABuffer + groupDataOffset[0]));
            ((MapTriGroup*)mapEntry)->maxY =
                (s16)(state->offsetY + (f32) * (s16*)(state->posBBuffer + groupDataOffset[0]));
            groupDataOffset[0] += 2;
            triangleEnd = mapEntry[10];
            triangle = *mapEntry;
            vertexIndex = vertexOffset[0];
            scale = 8.0f;
            for (; triangle < triangleEnd; triangle++) {
                mapEntry = mapBlockGetPolygon(blockAddress, triangle);
                dataOffset = vertexIndex;
                for (index = 0; index != 3; index++) {
                    vertex = &((Vec3s*)blockData->vertices)[mapEntry[index]];
                    vertex->x = (s16)(scale * state->offsetX + (f32)((Vec3s*)(state->geometryBuffer + dataOffset))->x);
                    vertex->y = (s16)(scale * state->offsetY + (f32)((Vec3s*)(state->geometryBuffer + dataOffset))->y);
                    vertex->z = (s16)(scale * state->offsetZ + (f32)((Vec3s*)(state->geometryBuffer + dataOffset))->z);
                    dataOffset += 6;
                    vertexIndex += 6;
                    vertexOffset[0] += 6;
                }
            }
        }
    }
    DCStoreRange((void*)blockData->vertices, (u32)blockData->vertexCount * 6);
    index = 0;
    dataOffset = index;
    for (; index < (int)(u32)blockData->displayListCount; index++) {
        vertexOffset[0] = (int)mapBlockGetDisplayListBounds(blockAddress, index);
        shaderLayer = mapBlockGetShader(blockAddress, *(u8*)(vertexOffset[0] + 0x13));
        shaderLayer = Shader_getLayer(shaderLayer, 0);
        if ((int)*(u8*)((int)shaderLayer + 5) == placement->blockLayer) {
            scale = 8.0f;
            ((MapBlockBoundsRec*)vertexOffset[0])->minX =
                (s16)(scale * state->offsetX + (f32) * (s16*)(state->minXBuffer + dataOffset));
            ((MapBlockBoundsRec*)vertexOffset[0])->maxX =
                (s16)(scale * state->offsetX + (f32) * (s16*)(state->maxXBuffer + dataOffset));
            ((MapBlockBoundsRec*)vertexOffset[0])->minY =
                (s16)(scale * state->offsetY + (f32) * (s16*)(state->minYBuffer + dataOffset));
            ((MapBlockBoundsRec*)vertexOffset[0])->maxY =
                (s16)(scale * state->offsetY + (f32) * (s16*)(state->maxYBuffer + dataOffset));
            ((MapBlockBoundsRec*)vertexOffset[0])->minZ =
                (s16)(scale * state->offsetZ + (f32) * (s16*)(state->minZBuffer + dataOffset));
            ((MapBlockBoundsRec*)vertexOffset[0])->maxZ =
                (s16)(scale * state->offsetZ + (f32) * (s16*)(state->maxZBuffer + dataOffset));
        }
        dataOffset += 2;
    }
    blockAddress->unused00 = mapBlockGetUnused00Value(blockAddress);
}

void XyzAnimator_update(GameObject* obj) {
    XyzAnimatorPlacement* placement = (XyzAnimatorPlacement*)obj->anim.placementData;
    XyzAnimatorState* state = (XyzAnimatorState*)obj->extra;
    MapBlockData* blockAddress;
    MapTriGroup* polygonGroup;
    int polygonGroupIndex;
    int completedAxes;
    u8* bufferAddress;
    int streamSize;
    int value;

    blockAddress =
        (MapBlockData*)mapGetBlock(objPosToMapBlockIdx(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ));
    if (blockAddress == NULL) {
        state->passCount = 0;
        return;
    }
    if ((blockAddress->flags4 & MAP_BLOCK_FLAG_LOADED) == 0) {
        return;
    }
    if (state->vertexCount == 0) {
        for (polygonGroupIndex = 0; polygonGroupIndex < blockAddress->polyGroupCount; polygonGroupIndex++) {
            polygonGroup = mapBlockGetPolygonGroup((void*)blockAddress, polygonGroupIndex);
            value = mapBlockGetPolygonGroupType(polygonGroup);
            if (placement->blockLayer == value) {
                state->polygonGroupCount++;
                state->vertexCount += ((MapTriGroup*)polygonGroup)[1].firstTri - polygonGroup->firstTri;
            }
        }
        if (state->vertexCount == 0) {
            return;
        }
        state->vertexCount *= 3;
        if (placement->triggerGameBit == -1) {
            state->triggerBitValue = 1;
        } else {
            state->triggerBitValue = mainGetBit(placement->triggerGameBit);
        }
        state->displayListCount = blockAddress->displayListCount;
        state->offsetX = (f32)placement->startX;
        state->offsetY = (f32)placement->startY;
        state->offsetZ = (f32)placement->startZ;
        if (placement->completionGameBit != -1 && mainGetBit(placement->completionGameBit) != 0) {
            state->offsetX = (f32)placement->targetX;
            state->offsetY = (f32)placement->targetY;
            state->offsetZ = (f32)placement->targetZ;
            state->triggerBitValue = 1;
        }
        value = state->vertexCount * 6 + state->polygonGroupCount * 0xc;
        value = value + state->displayListCount * 0xc;
        bufferAddress = mmAlloc(value, 5, 0);
        state->geometryBuffer = bufferAddress;
        streamSize = state->polygonGroupCount * 2;
        bufferAddress = bufferAddress + state->vertexCount * 6;
        state->polygonBuffer0 = bufferAddress;
        bufferAddress = bufferAddress + streamSize;
        state->polygonBuffer1 = bufferAddress;
        bufferAddress = bufferAddress + streamSize;
        state->posABuffer = bufferAddress;
        bufferAddress = bufferAddress + streamSize;
        state->posBBuffer = bufferAddress;
        bufferAddress = bufferAddress + streamSize;
        state->polygonBuffer4 = bufferAddress;
        bufferAddress = bufferAddress + streamSize;
        state->polygonBuffer5 = bufferAddress;
        bufferAddress = bufferAddress + streamSize;
        streamSize = state->displayListCount * 2;
        state->minXBuffer = bufferAddress;
        bufferAddress = bufferAddress + streamSize;
        state->maxXBuffer = bufferAddress;
        bufferAddress = bufferAddress + streamSize;
        state->minYBuffer = bufferAddress;
        bufferAddress = bufferAddress + streamSize;
        state->maxYBuffer = bufferAddress;
        bufferAddress = bufferAddress + streamSize;
        state->minZBuffer = bufferAddress;
        bufferAddress = bufferAddress + streamSize;
        state->maxZBuffer = bufferAddress;
        XyzAnimator_captureGeometry(placement, state, (MapBlockData*)blockAddress);
        if (placement->mode != XYZ_ANIMATOR_MODE_DEFERRED_ONESHOT) {
            XyzAnimator_applyToMapBlock(placement, state, (MapBlockData*)blockAddress);
            blockAddress->flags4 = blockAddress->flags4 ^ 1;
            XyzAnimator_applyToMapBlock(placement, state, (MapBlockData*)blockAddress);
            blockAddress->flags4 = blockAddress->flags4 ^ 1;
        }
    }
    if (placement->mode == XYZ_ANIMATOR_MODE_GATED) {
        value = mainGetBit(placement->triggerGameBit);
        if (state->triggerBitValue != value) {
            state->triggerBitValue = value;
            if (value == 0) {
                if (placement->completionGameBit > -1) {
                    mainSetBits(placement->completionGameBit, 0);
                }
            }
            if (state->passCount > 2) {
                state->passCount = 0;
            }
        }
        if (state->passCount > 2) {
            return;
        }
        if (state->loopSfxId != 0) {
            Sfx_KeepAliveLoopedObjectSound(obj, state->loopSfxId);
        }
    } else {
        if (state->passCount > 2) {
            return;
        }
        if (state->triggerBitValue == 0) {
            state->triggerBitValue = mainGetBit(placement->triggerGameBit);
            if (state->triggerBitValue == 0) {
                return;
            }
        }
    }
    switch (placement->mode) {
    case XYZ_ANIMATOR_MODE_ONESHOT:
    case XYZ_ANIMATOR_MODE_DEFERRED_ONESHOT:
        completedAxes = 0;
        if (placement->startX > placement->targetX) {
            state->offsetX = -(0.1f * ((f32)(int)placement->speedX * timeDelta) - state->offsetX);
            if (state->offsetX <= (f32)placement->targetX) {
                state->offsetX = (f32)placement->targetX;
                completedAxes = 1;
            }
        } else {
            state->offsetX = 0.1f * ((f32)(int)placement->speedX * timeDelta) + state->offsetX;
            if (state->offsetX >= (f32)placement->targetX) {
                state->offsetX = (f32)placement->targetX;
                completedAxes = 1;
            }
        }
        if (placement->startY > placement->targetY) {
            state->offsetY = -(0.1f * ((f32)(int)placement->speedY * timeDelta) - state->offsetY);
            if (state->offsetY <= (f32)placement->targetY) {
                state->offsetY = (f32)placement->targetY;
                completedAxes += 1;
            }
        } else {
            state->offsetY = 0.1f * ((f32)(int)placement->speedY * timeDelta) + state->offsetY;
            if (state->offsetY >= (f32)placement->targetY) {
                state->offsetY = (f32)placement->targetY;
                completedAxes += 1;
            }
        }
        if (placement->startZ > placement->targetZ) {
            state->offsetZ = -(0.1f * ((f32)(int)placement->speedZ * timeDelta) - state->offsetZ);
            if (state->offsetZ <= (f32)placement->targetZ) {
                state->offsetZ = (f32)placement->targetZ;
                completedAxes += 1;
            }
        } else {
            state->offsetZ = 0.1f * ((f32)(int)placement->speedZ * timeDelta) + state->offsetZ;
            if (state->offsetZ >= (f32)placement->targetZ) {
                state->offsetZ = (f32)placement->targetZ;
                completedAxes += 1;
            }
        }
        if (completedAxes == 3) {
            if (placement->completionGameBit != -1) {
                mainSetBits(placement->completionGameBit, 1);
            }
            state->passCount += 1;
        }
        break;
    case XYZ_ANIMATOR_MODE_LOOP:
        if (placement->startX > placement->targetX) {
            state->offsetX = -(0.1f * ((f32)(int)placement->speedX * timeDelta) - state->offsetX);
            if (state->offsetX < (f32)placement->targetX) {
                state->offsetX = (f32)(placement->startX - (int)((f32)placement->targetX - state->offsetX));
            }
        } else {
            state->offsetX = 0.1f * ((f32)(int)placement->speedX * timeDelta) + state->offsetX;
            if (state->offsetX > (f32)placement->startX) {
                state->offsetX = (f32)(placement->targetX + (int)(state->offsetX - (f32)placement->targetX));
            }
        }
        if (placement->startY > placement->targetY) {
            state->offsetY = -(0.1f * ((f32)(int)placement->speedY * timeDelta) - state->offsetY);
            if (state->offsetY < (f32)placement->targetY) {
                state->offsetY =
                    -(0.1f * (f32)(int)((f32)placement->targetY - state->offsetY) - (f32)placement->startY);
            }
        } else {
            state->offsetY = 0.1f * ((f32)(int)placement->speedY * timeDelta) + state->offsetY;
            if (state->offsetY > (f32)placement->startY) {
                state->offsetY = (f32)(placement->targetY + (int)(state->offsetY - (f32)placement->targetY));
            }
        }
        if (placement->startZ > placement->targetZ) {
            state->offsetZ = -(0.1f * ((f32)(int)placement->speedZ * timeDelta) - state->offsetZ);
            if (state->offsetZ < (f32)placement->targetZ) {
                state->offsetZ = (f32)(placement->startZ - (int)((f32)placement->targetZ - state->offsetZ));
            }
        } else {
            state->offsetZ = 0.1f * ((f32)(int)placement->speedZ * timeDelta) + state->offsetZ;
            if (state->offsetZ > (f32)placement->startZ) {
                state->offsetZ = (f32)(placement->targetZ + (int)(state->offsetZ - (f32)placement->targetZ));
            }
        }
        break;
    case XYZ_ANIMATOR_MODE_GATED:
        completedAxes = 0;
        if (state->triggerBitValue != 0) {
            if (placement->startX > placement->targetX) {
                state->offsetX = -(0.1f * ((f32)(int)placement->speedX * timeDelta) - state->offsetX);
                if (state->offsetX <= (f32)placement->targetX) {
                    state->offsetX = (f32)placement->targetX;
                    completedAxes = 1;
                }
            } else {
                state->offsetX = 0.1f * ((f32)(int)placement->speedX * timeDelta) + state->offsetX;
                if (state->offsetX >= (f32)placement->targetX) {
                    state->offsetX = (f32)placement->targetX;
                    completedAxes = 1;
                }
            }
            if (placement->startY > placement->targetY) {
                state->offsetY = -(0.1f * ((f32)(int)placement->speedY * timeDelta) - state->offsetY);
                if (state->offsetY <= (f32)placement->targetY) {
                    state->offsetY = (f32)placement->targetY;
                    completedAxes += 1;
                }
            } else {
                state->offsetY = 0.1f * ((f32)(int)placement->speedY * timeDelta) + state->offsetY;
                if (state->offsetY >= (f32)placement->targetY) {
                    state->offsetY = (f32)placement->targetY;
                    completedAxes += 1;
                }
            }
            if (placement->startZ > placement->targetZ) {
                state->offsetZ = -(0.1f * ((f32)(int)placement->speedZ * timeDelta) - state->offsetZ);
                if (state->offsetZ <= (f32)placement->targetZ) {
                    state->offsetZ = (f32)placement->targetZ;
                    completedAxes += 1;
                }
            } else {
                state->offsetZ = 0.1f * ((f32)(int)placement->speedZ * timeDelta) + state->offsetZ;
                if (state->offsetZ >= (f32)placement->targetZ) {
                    state->offsetZ = (f32)placement->targetZ;
                    completedAxes += 1;
                }
            }
            if (completedAxes == 3) {
                if (placement->completionGameBit != -1) {
                    mainSetBits(placement->completionGameBit, 1);
                }
                state->passCount += 1;
            }
        } else {
            if (placement->startX > placement->targetX) {
                state->offsetX = 0.1f * ((f32)(int)placement->speedX * timeDelta) + state->offsetX;
                if (state->offsetX >= (f32)placement->startX) {
                    state->offsetX = (f32)placement->startX;
                    completedAxes = 1;
                }
            } else {
                state->offsetX = -(0.1f * ((f32)(int)placement->speedX * timeDelta) - state->offsetX);
                if (state->offsetX <= (f32)placement->startX) {
                    state->offsetX = (f32)placement->startX;
                    completedAxes = 1;
                }
            }
            if (placement->startY > placement->targetY) {
                state->offsetY = 0.1f * ((f32)(int)placement->speedY * timeDelta) + state->offsetY;
                if (state->offsetY >= (f32)placement->startY) {
                    state->offsetY = (f32)placement->startY;
                    completedAxes += 1;
                }
            } else {
                state->offsetY = -(0.1f * ((f32)(int)placement->speedY * timeDelta) - state->offsetY);
                if (state->offsetY <= (f32)placement->startY) {
                    state->offsetY = (f32)placement->startY;
                    completedAxes += 1;
                }
            }
            if (placement->startZ > placement->targetZ) {
                state->offsetZ = 0.1f * ((f32)(int)placement->speedZ * timeDelta) + state->offsetZ;
                if (state->offsetZ >= (f32)placement->startZ) {
                    state->offsetZ = (f32)placement->startZ;
                    completedAxes += 1;
                }
            } else {
                state->offsetZ = -(0.1f * ((f32)(int)placement->speedZ * timeDelta) - state->offsetZ);
                if (state->offsetZ <= (f32)placement->startZ) {
                    state->offsetZ = (f32)placement->startZ;
                    completedAxes += 1;
                }
            }
            if (completedAxes == 3) {
                state->passCount += 1;
            }
        }
        break;
    }
    XyzAnimator_applyToMapBlock(placement, state, (MapBlockData*)blockAddress);
    return;
}

void XyzAnimator_init(GameObject* obj) {
    XyzAnimatorState* state = (XyzAnimatorState*)obj->extra;
    int mapId;

    objAddObjectType(obj, XYZ_ANIMATOR_OBJECT_GROUP);
    mapId = obj->anim.placement->ident;
    switch (mapId) {
    case XYZ_ANIMATOR_DRAGON_ROCK_FIREPIPE_IDENT:
    case 0x4BAB1:
        state->loopSfxId = 0x7D;
        break;
    case 0x49275:
    case 0x49CB7:
    case 0x4C797:
        state->loopSfxId = 0x4B7;
        break;
    }
}

ObjectDescriptor gXYZAnimatorObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)XyzAnimator_init,
    (ObjectDescriptorCallback)XyzAnimator_update,
    0,
    (ObjectDescriptorCallback)XyzAnimator_render,
    (ObjectDescriptorCallback)XyzAnimator_free,
    0,
    XyzAnimator_getExtraSize,
};
