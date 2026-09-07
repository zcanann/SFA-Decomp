/*
 * DFropenode (DLL 0x175) implements the Dragon Rock rope/cradle system.
 * It owns the rope mesh builder, spring simulation, construction helpers,
 * object callbacks, and rendering code.
 */
#include "dlls/objects/373_DFropenode.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/mtx/vec.h"
#include "game/objects/object.h"
#include "main/audio/sfx_keep_alive_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/camera.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "main/lightmap_api.h"
#include "main/mm.h"
#include "main/obj_list.h"
#include "main/objtype.h"
#include "main/sky.h"
#include "main/texture.h"
#include "main/vecmath.h"
#include "main/audio/sfx_play_api.h"
#include "string.h"
#include "track/intersect_api.h"
#include "track/intersect_render_setup_api.h"

#define DFROPENODE_SEGMENT_VERTEX_COUNT   6
#define DFROPENODE_SEGMENT_TRIANGLE_COUNT 6
#define DFROPENODE_ROPE_TEXTURE_ASSET_ID  0x3CA
#define DFROPENODE_WATER_TEXTURE_ASSET_ID 0x5DD

/* Resource and simulation settings indexed by DFropenodeStyle. */
int gDFropenodeTextureAssetIds[DFROPENODE_STYLE_COUNT] = {DFROPENODE_ROPE_TEXTURE_ASSET_ID,
                                                          DFROPENODE_WATER_TEXTURE_ASSET_ID};
Texture* gDFropenodeTextures[DFROPENODE_STYLE_COUNT] = {0};
f32 gDFropenodeNodeMasses[DFROPENODE_STYLE_COUNT] = {0.1f, 0.13f};
u8 gDFropenodeStyleUsesTransparency[DFROPENODE_STYLE_COUNT] = {0, 1};

LightmapVertex gDFropenodeRopeSegmentVertices[DFROPENODE_SEGMENT_VERTEX_COUNT] = {
    {0, 100, 0, 0, 256, 0, 255, 255, 255, 255},     {-200, -100, 0, 0, 0, 0, 255, 255, 255, 255},
    {200, -100, 0, 0, 512, 0, 255, 255, 255, 255},  {0, 1, 0, 0, 256, 512, 255, 255, 255, 255},
    {-200, -100, 0, 0, 0, 512, 255, 255, 255, 255}, {200, -100, 0, 0, 512, 512, 255, 255, 255, 255},
};

LightmapVertex gDFropenodeWaterSegmentVertices[DFROPENODE_SEGMENT_VERTEX_COUNT] = {
    {0, 200, 0, 0, 128, 0, 255, 255, 255, 128},     {-400, -200, 0, 0, 0, 0, 255, 255, 255, 128},
    {400, -200, 0, 0, 256, 0, 255, 255, 255, 128},  {0, 200, 0, 0, 128, 256, 255, 255, 255, 128},
    {-400, -200, 0, 0, 0, 256, 255, 255, 255, 128}, {400, -200, 0, 0, 256, 256, 255, 255, 255, 128},
};

const LightmapTriangle gDFropenodeSegmentTriangles[DFROPENODE_SEGMENT_TRIANGLE_COUNT] = {
    {0, {0, 1, 3}, {{0}}}, {0, {1, 4, 3}, {{0}}}, {0, {0, 3, 2}, {{0}}},
    {0, {2, 3, 5}, {{0}}}, {0, {1, 2, 4}, {{0}}}, {0, {2, 5, 4}, {{0}}},
};

/*
 * Build the six-vertex mesh for one rope segment. The template is rotated
 * around the Y axis and its two end caps are translated onto the link nodes.
 */
void DFropenode_buildRopeSegmentMesh(const LightmapVertex* templateVertices, int angle, const Vec* startNode,
                                     const Vec* endNode, LightmapVertex* out) {
    s16 startX = 100.0f * startNode->x;
    s16 startY = 100.0f * startNode->y;
    s16 startZ = 100.0f * startNode->z;
    s16 endX = 100.0f * endNode->x;
    s16 endY = 100.0f * endNode->y;
    s16 endZ = 100.0f * endNode->z;
    LightmapVertex* vertex;
    int i;
    float angleRadians;
    f32 vertexX;

    memcpy(out, templateVertices, DFROPENODE_SEGMENT_VERTEX_COUNT * sizeof(LightmapVertex));

    i = 0;
    vertex = out;
    angleRadians = 3.1415927f * (float)(short)angle / 32768.0f;
    for (; i < DFROPENODE_SEGMENT_VERTEX_COUNT; i++) {
        vertexX = (float)(int)vertex->x;
        vertex->x = vertexX * mathCosf(angleRadians);
        vertex->z = -vertexX * mathSinf(angleRadians);
        vertex++;
    }

    out[0].x += startX;
    out[0].y += startY;
    out[0].z += startZ;
    out[3].x += endX;
    out[3].y += endY;
    out[3].z += endZ;
    out[1].x += startX;
    out[1].y += startY;
    out[1].z += startZ;
    out[4].x += endX;
    out[4].y += endY;
    out[4].z += endZ;
    out[2].x += startX;
    out[2].y += startY;
    out[2].z += startZ;
    out[5].x += endX;
    out[5].y += endY;
    out[5].z += endZ;
}

const f32 gDFropenodeOneHundredth[] = {0.01f};

static inline void DFropenode_applyRopeSway(DFropenodeRope* rope) {
    DFropenodeRopeNode* nodes = rope->nodes;
    int i;

    if (rope->sway < -50) {
        rope->direction = 1;
    }
    if (rope->sway > 50) {
        rope->direction = 2;
    }
    if (rope->direction == 2) {
        rope->sway--;
    } else {
        rope->sway++;
    }

    for (i = 1; i < rope->count - 1; i++) {
        nodes[i].force.x += gDFropenodeOneHundredth[0] * rope->sway;
    }
}

/*
 * Integrate the spring forces attached to every unlocked rope node.
 */
void DFropenode_integrateRopeNodes(DFropenodeRope* rope) {
    DFropenodeRopeNode* part;
    int j;
    int i;
    Vec accel;
    Vec velscaled;
    Vec scaled;
    f32 mag;

    part = rope->nodes;
    i = 0;
    for (; i < rope->count; i++, part++) {
        accel.z = 0.0f;
        accel.y = 0.0f;
        accel.x = 0.0f;

        if (part->locked == 0) {
            for (j = 0; j < part->linkCount; j++) {
                DFropenodeRopeLink* link = part->links[j];
                if (part == link->a) {
                    PSVECAdd(&accel, &link->force, &accel);
                } else {
                    PSVECSubtract(&accel, &link->force, &accel);
                }
            }
            mag = PSVECMag(&accel);
            if (mag > rope->maxForce) {
                PSVECScale(&accel, &accel, rope->maxForce / mag);
            }
            PSVECScale(&accel, &accel, rope->stepOverMass);
            PSVECAdd(&accel, &part->force, &accel);
            PSVECAdd(&part->velocity, &accel, &part->velocity);
            PSVECScale(&part->velocity, &velscaled, rope->damping);
            PSVECSubtract(&part->velocity, &velscaled, &part->velocity);
            part->velocity.y = rope->timeStep * rope->gravityOverMass + part->velocity.y;
            PSVECScale(&part->velocity, &scaled, rope->timeStep);
            PSVECAdd(&part->pos, &scaled, &part->pos);
        }
    }
}

static inline void DFropenode_solveRopeLinks(DFropenodeRope* rope) {
    DFropenodeRopeLink* links = rope->links;
    int i;

    for (i = 0; i < rope->count - 1; i++, links++) {
        Vec tmp;
        PSVECSubtract(&links->a->pos, &links->b->pos, &tmp);
        links->length = PSVECMag(&tmp);

        if (links->length > links->maxLength) {
            links->restLength = 0.0f;
        }

        if (links->restLength == 0.0f) {
            links->force.z = 0.0f;
            links->force.y = 0.0f;
            links->force.x = 0.0f;
        } else {
            PSVECScale(&tmp, &links->force, -links->stiffness * (links->length - links->restLength));
        }
    }
}

static inline s16 DFropenode_calculateRopeYaw(f32 dx, f32 dz) {
    s16 angle = getAngle(dx, dz);

    if (angle > 0x8000) {
        angle = angle - 0xffff;
    }
    if (angle < -0x8000) {
        angle += 0xffff;
    }

    return angle;
}

/*
 * Apply rope sway, solve each spring link, integrate the nodes, and clear
 * accumulated forces for the next tick.
 */
void DFropenode_updateRopeSimulation(DFropenodeRope* rope) {
    int i;
    int solverIteration;
    DFropenodeRopeNode* node = rope->nodes;

    DFropenode_applyRopeSway(rope);

    for (solverIteration = 0; solverIteration < rope->solverIterations; solverIteration++) {
        DFropenode_solveRopeLinks(rope);
        DFropenode_integrateRopeNodes(rope);
    }

    for (i = 0; i < rope->count; i++, node++) {
        node->force.x = 0.0f;
        node->force.y = 0.0f;
        node->force.z = 0.0f;
    }
}

void DFropenode_attachRopeLink(DFropenodeRopeLink* linkSelf, DFropenodeRopeNode* firstNode,
                               DFropenodeRopeNode* secondNode);
void DFropenode_attachRopeLink(DFropenodeRopeLink* linkSelf, DFropenodeRopeNode* firstNode,
                               DFropenodeRopeNode* secondNode) {
    int firstLinkIndex;
    int secondLinkIndex;

    firstLinkIndex = 0;
    secondLinkIndex = 0;
    while (firstNode->links[firstLinkIndex] != NULL) {
        firstLinkIndex++;
    }
    while (secondNode->links[secondLinkIndex] != NULL) {
        secondLinkIndex++;
    }
    if (firstLinkIndex > firstNode->linkCount || secondLinkIndex > secondNode->linkCount) {
        return;
    }
    firstNode->links[firstLinkIndex] = linkSelf;
    secondNode->links[secondLinkIndex] = linkSelf;
    linkSelf->a = firstNode;
    linkSelf->b = secondNode;
}

/*
 * Allocate a rope, seed evenly-spaced nodes between its endpoints, pin the
 * ends, and attach each spring link to its node pair.
 */
DFropenodeRope* DFropenode_createRope(f32 startX, f32 startY, f32 startZ, f32 endX, f32 endY, f32 endZ, f32 length,
                                      s32 count, f32 nodeMass);
DFropenodeRope* DFropenode_createRope(f32 startX, f32 startY, f32 startZ, f32 endX, f32 endY, f32 endZ, f32 length,
                                      s32 count, f32 nodeMass) {
    s32 linkCount;
    DFropenodeRope* rope;
    DFropenodeRopeNode* nodes;
    DFropenodeRopeNode* node;
    DFropenodeRopeLink* link;
    DFropenodeRopeNode* linkNode;
    s32 nodesSize;
    s32 allocSize;
    u8* base;
    s32 i;
    s32 linkIndex;
    f32 dx;
    f32 dy;
    f32 dz;

    dx = endX - startX;
    dy = endY - startY;
    dz = endZ - startZ;
    length = sqrtf(dz * dz + (dx * dx + dy * dy));

    dx /= count - 1;
    dy /= count - 1;
    dz /= count - 1;

    nodesSize = count * sizeof(DFropenodeRopeNode);
    allocSize = sizeof(DFropenodeRope) + nodesSize + (count - 1) * sizeof(DFropenodeRopeLink);
    base = mmAlloc(allocSize, 0xFF, 0);
    rope = (DFropenodeRope*)base;
    rope->nodes = (DFropenodeRopeNode*)(base + sizeof(DFropenodeRope));
    rope->links = (DFropenodeRopeLink*)(base + nodesSize + sizeof(DFropenodeRope));
    rope->count = count;
    rope->totalLength = length;
    rope->start.x = startX;
    rope->start.y = startY;
    rope->start.z = startZ;
    rope->end.x = endX;
    rope->end.y = endY;
    rope->end.z = endZ;
    rope->sway = 0;
    rope->direction = 1;
    rope->damping = 0.025f;
    rope->solverIterations = 1;
    rope->timeStep = gDFropenodeOneHundredth[0];
    if (rope->timeStep * length > 5.0f) {
        rope->timeStep = 5.0f / length;
    }
    rope->maxForce = 5000.0f;
    rope->stepOverMass = rope->timeStep / nodeMass;
    rope->gravityOverMass = -9.81f / nodeMass;

    nodes = rope->nodes;
    for (i = 0, node = nodes; i < count; node++, i++) {
        node->pos.x = i * dx + rope->start.x;
        node->pos.y = i * dy + rope->start.y;
        node->pos.z = i * dz + rope->start.z;
        node->velocity.z = 0.0f;
        node->velocity.y = 0.0f;
        node->velocity.x = 0.0f;
        node->force.z = 0.0f;
        node->force.y = 0.0f;
        node->force.x = 0.0f;
        node->locked = 0;
        if (i == 0 || i == count - 1) {
            node->linkCount = 1;
        } else if (i == 1 || i == count - 2) {
            node->linkCount = 2;
        } else {
            node->linkCount = 2;
        }
        {
            s32 j;
            for (j = 0; j < node->linkCount; j++) {
                node->links[j] = NULL;
            }
        }
    }

    nodes[count - 1].locked = 1;
    nodes[0].locked = 1;

    linkIndex = 0;
    link = rope->links;
    linkNode = nodes;
    linkCount = count - 1;

    for (; linkIndex < linkCount; link++, linkNode++, linkIndex++) {
        link->restLength = rope->totalLength / linkCount;
        link->stiffness = 10.0f;
        link->force.z = 0.0f;
        link->force.y = 0.0f;
        link->force.x = 0.0f;
        link->maxLength = 1000.0f * link->restLength;
        DFropenode_attachRopeLink(link, linkNode, &nodes[linkIndex + 1]);
    }

    return rope;
}

void DFropenode_setMinY(GameObject* obj, f32 value) {
    DFropenodeState* state = obj->extra;
    state->minimumY = value;
}

s16 DFropenode_isVisible(GameObject* obj) {
    DFropenodeState* state = obj->extra;
    return state->hidden == 0;
}

void DFropenode_setVisible(GameObject* obj, int value) {
    GameObject* linkedNode;
    DFropenodeState* state = obj->extra;
    state->hidden = value == 0;

    if ((linkedNode = state->linkedNode) != NULL) {
        state = linkedNode->extra;
        state->hidden = value == 0;
    }
}

s16 DFropenode_getAngle(GameObject* obj) {
    DFropenodeState* state = obj->extra;
    return state->ropeYaw;
}

void DFropenode_clearLinkedObj(GameObject* obj) {
    DFropenodeState* state = obj->extra;
    state->linkedNode = NULL;
}

f32 DFropenode_projectPointOntoSegment(f32* x, f32* y, f32* z, f32 startX, f32 startY, f32 startZ, f32 endX, f32 endY,
                                       f32 endZ);
f32 DFropenode_projectPointOntoSegment(f32* x, f32* y, f32* z, f32 startX, f32 startY, f32 startZ, f32 endX, f32 endY,
                                       f32 endZ) {
    f32 dx = endX - startX;
    f32 dy = endY - startY;
    f32 dz = endZ - startZ;
    f32 t;

    if (dx == 0.0f && dz == 0.0f) {
        t = 0.0f;
    } else {
        t = (dx * (*x - startX) + dz * (*z - startZ)) / (dx * dx + dz * dz);
    }

    if (t < 0.0f) {
        *x = startX;
        *y = startY;
        *z = startZ;
    } else if (t >= 1.0f) {
        *x = endX;
        *y = endY;
        *z = endZ;
    } else {
        *x = t * dx + startX;
        *y = t * dy + startY;
        *z = t * dz + startZ;
    }

    return t;
}

int DFropenode_findNearestRopePoint(GameObject* obj, f32 worldX, f32 worldY, f32 worldZ, f32* distanceOut,
                                    f32* phaseOut, u8* sideOut) {
    int i;
    DFropenodeState* state = obj->extra;
    DFropenodePlacement* placement = (DFropenodePlacement*)obj->anim.placementData;

    int result;

    if ((placement->nodeId & 1) == 0) {
        return 0;
    }

    if (state->linkedNode == NULL) {
        return 0;
    }

    if (worldX < state->boundsMinX || worldX > state->boundsMaxX || worldZ < state->boundsMinZ ||
        worldZ > state->boundsMaxZ) {
        return 0;
    }

    *distanceOut = 10000.0f;
    worldX -= obj->anim.localPosX;
    worldY -= obj->anim.localPosY;
    worldZ -= obj->anim.localPosZ;

    for (i = 0, result = 0; i < state->rope->count - 1; i++) {
        f32 x = worldX;
        f32 y = worldY;
        f32 z = worldZ;
        DFropenodeRopeNode* node = &state->rope->nodes[i];
        f32 phase = DFropenode_projectPointOntoSegment(&x, &y, &z, node->pos.x, node->pos.y, node->pos.z, node[1].pos.x,
                                                       node[1].pos.y, node[1].pos.z);
        if (phase >= 0.0f && phase < 1.0f) {
            f32 dx = x - worldX;
            f32 dy = y - worldY;
            f32 dz = z - worldZ;
            f32 distance = sqrtf(dx * dx + dy * dy + dz * dz);

            if (distance < *distanceOut) {
                result = i + 1;
                *distanceOut = distance;
                *phaseOut = i + phase;
            }
        }
    }

    if (result != 0) {
        if (result - 1 <= state->rope->count >> 1) {
            *sideOut = 0;
        } else {
            *sideOut = 1;
        }
    }

    return result;
}

void DFropenode_applyForceAtPhase(f32 phase, f32 force, GameObject* obj) {
    DFropenodeState* state = obj->extra;
    s8 idx;
    f32 fraction;
    phase -= (f32)(s8)phase;
    idx = (s8)phase;
    fraction = phase - (f32)idx;
    state->rope->nodes[idx].force.y += force * fraction;
    state->rope->nodes[idx].force.y += force * (1.0f - fraction);
}

void DFropenode_advancePhaseByDistance(GameObject* obj, f32* phase, f32 distance) {
    DFropenodeState* state = obj->extra;
    s8 idx = (s8)*phase;
    DFropenodeRopeNode* nodes;
    f32 dx;
    f32 dz;
    *phase -= idx;
    nodes = state->rope->nodes;
    dx = nodes[idx].pos.x - nodes[idx + 1].pos.x;
    dz = nodes[idx].pos.z - nodes[idx + 1].pos.z;
    distance /= sqrtf(dx * dx + dz * dz);
    *phase += distance;
    *phase += idx;
}

void DFropenode_getWorldPosAtPhase(f32 phase, GameObject* obj, f32* xOut, f32* yOut, f32* zOut) {
    DFropenodeState* state = obj->extra;
    s8 idx = phase;
    f32 dx, dy, dz;
    f32 fraction = phase - idx;
    dy = state->rope->nodes[idx + 1].pos.y - state->rope->nodes[idx].pos.y;
    dz = state->rope->nodes[idx + 1].pos.z - state->rope->nodes[idx].pos.z;
    dx = state->rope->nodes[idx + 1].pos.x - state->rope->nodes[idx].pos.x;
    *xOut = dx * fraction + (obj->anim.localPosX + state->rope->nodes[idx].pos.x);
    *yOut = dy * fraction + (obj->anim.localPosY + state->rope->nodes[idx].pos.y);
    *zOut = dz * fraction + (obj->anim.localPosZ + state->rope->nodes[idx].pos.z);
}

void DFropenode_getPlaneEquation(GameObject* obj, DFropenodePlaneEquation* out) {
    DFropenodeState* state = obj->extra;
    out->normal.x = state->plane.normal.x;
    out->normal.y = state->plane.normal.y;
    out->normal.z = state->plane.normal.z;
    out->distance = state->plane.distance;
}

int DFropenode_syncRopeToEndpoints(GameObject* obj) {
    DFropenodeState* state;
    GameObject* endObj;
    int i;
    DFropenodeRopeLink* link;
    int isStartNode;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 length;
    f32 clampY;

    isStartNode = ((DFropenodePlacement*)obj->anim.placementData)->nodeId & 1;
    if (isStartNode != 0) {
        state = obj->extra;
        endObj = state->linkedNode;
    } else {
        endObj = obj;
        obj = ((DFropenodeState*)obj->extra)->linkedNode;
        if (obj == NULL) {
            return 0;
        }
        state = obj->extra;
    }

    if (state->rope == NULL || endObj == NULL) {
        return 0;
    }

    dx = endObj->anim.localPosX - obj->anim.localPosX;
    dy = endObj->anim.localPosY - obj->anim.localPosY;
    dz = endObj->anim.localPosZ - obj->anim.localPosZ;

    state->ropeYaw = DFropenode_calculateRopeYaw(dx, dz);

    length = sqrtf(dx * dx + dy * dy + dz * dz) / (state->rope->count - 1);
    link = state->rope->links;
    state->rope->damping = 0.1f;
    for (i = 0; i < state->rope->count - 1; i++, link++) {
        link->restLength = length;
    }

    i = state->rope->count - 1;
    state->rope->nodes[i].pos.x = dx;
    state->rope->nodes[i].pos.y = dy;
    state->rope->nodes[i].pos.z = dz;
    state->boundsMinX = obj->anim.localPosX;
    state->boundsMinZ = obj->anim.localPosZ;
    state->boundsMaxX = endObj->anim.localPosX;
    state->boundsMaxZ = endObj->anim.localPosZ;

    if (state->boundsMinX > state->boundsMaxX) {
        f32 temp = state->boundsMinX;
        state->boundsMinX = state->boundsMaxX;
        state->boundsMaxX = temp;
    }
    if (state->boundsMinZ > state->boundsMaxZ) {
        f32 temp = state->boundsMinZ;
        state->boundsMinZ = state->boundsMaxZ;
        state->boundsMaxZ = temp;
    }

    clampY = state->minimumY;
    if (clampY) {
        clampY -= obj->anim.localPosY;
        for (i = 0; i < state->rope->count - 1; i++) {
            if (state->rope->nodes[i].pos.y < clampY) {
                state->rope->nodes[i].pos.y = clampY;
            }
        }
    }

    state->boundsMinX -= 25.0f;
    state->boundsMinZ -= 25.0f;
    state->boundsMaxX += 25.0f;
    state->boundsMaxZ += 25.0f;
    return 0;
}

int DFropenode_getExtraSize(void) {
    return sizeof(DFropenodeState);
}

int DFropenode_getObjectTypeId(void) {
    return 0;
}

void DFropenode_free(GameObject* obj) {
    GameObject* linkedNode;
    DFropenodeState* state = obj->extra;
    int i;
    int objCount;
    GameObject** objs;

    objFreeObjectType(obj, DFROPENODE_OBJECT_GROUP);
    if (state->rope != NULL && state->rope != NULL) { //what?
        mm_free(state->rope);
    }
    linkedNode = state->linkedNode;
    if (linkedNode == NULL) {
        return;
    }

    objs = objGetAllOfType(DFROPENODE_OBJECT_GROUP, &objCount);
    for (i = 0; i < objCount; i++) {
        if (objs[i] != linkedNode) {
            continue;
        }

        ((DFropenodeInterface*)*linkedNode->anim.dll)->clearLinkedObj(linkedNode);
    }
}

void DFropenode_render(GameObject* obj, int gdl, int mtxs) {
    ObjAnimComponent* objAnim = &obj->anim;
    DFropenodeState* state = obj->extra;
    DFropenodePlacement* placement = (DFropenodePlacement*)objAnim->placementData;

    if (placement->fadeGameBit != 0 && mainGetBit(placement->fadeGameBit) != 0) {
        u32 oldAlpha = objAnim->alpha;
        int fadeAlpha;
        if (oldAlpha == 70) {
            Sfx_PlayFromObject(obj, SFXTRIG_ocean_beamlp);
        }
        fadeAlpha = oldAlpha - framesThisStep;
        if (fadeAlpha <= 0) {
            objAnim->alpha = 0;
            return;
        }
        objAnim->alpha = fadeAlpha;
    } else {
        if (objAnim->alpha == 0) {
            Sfx_PlayFromObject(obj, SFXTRIG_tile_buzzlp);
        }

        if (objAnim->alpha < 70) {
            objAnim->alpha += framesThisStep;
        } else {
            objAnim->alpha = 70;
        }
    }

    if ((placement->nodeId & 1) != 0 && state->linkedNode != NULL && state->rope != NULL) {
        DFropenodeRopeNode* node;
        s16 segment;
        DFropenodeRenderState renderState;
        LightmapVertex segmentVerts[DFROPENODE_SEGMENT_VERTEX_COUNT];
        int alpha;
        f32 tmp = obj->anim.rootMotionScale;
        obj->anim.rootMotionScale = gDFropenodeOneHundredth[0];
        Camera_LoadModelViewMatrix(0, mtxs, (MatrixTransform*)obj, 1.0f, 0.0f, NULL);
        obj->anim.rootMotionScale = tmp;

        gxTevResetStages();
        gxTevTextureTimesColor1Stage();
        gxTevCommitStages();

        if (placement->style == DFROPENODE_STYLE_WATER) {
            renderState.red = 255;
            renderState.green = 255;
            renderState.blue = 255;
        } else {
            objAnim->alpha = 255;
            skyGetSunColor(0, &renderState.blue, &renderState.green, &renderState.red);
            renderState.green = renderState.green * 200 >> 8;
            renderState.red = renderState.red * 170 >> 8;
        }

        if (objAnim->alpha > 70) {
            gxSetOpaqueZWriteMode();
            alpha = 255;
        } else {
            gxSetAlphaBlendZTest();
            alpha = (objAnim->alpha + objAnim->alpha) >> 1; // what?
        }

        selectTexture(gDFropenodeTextures[placement->style], 0);
        setTextColor(&gdl, renderState.blue, renderState.green, renderState.red, (u8)alpha);
        node = state->rope->nodes;
        for (segment = 0; segment < state->rope->count - 1; segment++) {
            node++;
            DFropenode_buildRopeSegmentMesh(gDFropenodeRopeSegmentVertices, state->ropeYaw, &node[-1].pos, &node->pos,
                                            segmentVerts);
            lightmapDrawTriangleList(segmentVerts, (u8*)gDFropenodeSegmentTriangles, DFROPENODE_SEGMENT_TRIANGLE_COUNT);
        }

        if (placement->style != DFROPENODE_STYLE_WATER) {
            return;
        }

        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_waterblock_wave);
        gxSetAlphaBlendZTest();
        alpha = (u8)(objAnim->alpha + randomGetRange(0, objAnim->alpha));
        setTextColor(&gdl, renderState.blue, renderState.green, renderState.red, alpha);
        node = state->rope->nodes;
        for (segment = 0; segment < state->rope->count - 1; segment++) {
            node++;
            DFropenode_buildRopeSegmentMesh(gDFropenodeWaterSegmentVertices, state->ropeYaw, &(node - 1)->pos,
                                            &node->pos, segmentVerts);
            lightmapDrawTriangleList(segmentVerts, (u8*)gDFropenodeSegmentTriangles, DFROPENODE_SEGMENT_TRIANGLE_COUNT);
        }
    }
}

void DFropenode_hitDetect(void) {
}

void DFropenode_update(GameObject* obj) {
    DFropenodeState* state;
    DFropenodePlacement* placement;
    GameObject* linkedObj;
    int objectCount;
    int objectIndex;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 length;
    f32 baseX;
    f32 baseY;
    f32 baseZ;
    f32 linkedX;
    f32 linkedY;
    f32 linkedZ;
    f32 liftedY;
    f32 normalX;
    f32 normalY;
    f32 normalZ;
    f32 normalLength;

    placement = (DFropenodePlacement*)obj->anim.placementData;
    state = obj->extra;
    if ((placement->nodeId & 1) == 0) {
        return;
    }

    linkedObj = state->linkedNode;
    if (linkedObj == NULL) {
        GameObject** objects = ObjList_GetObjects(&objectIndex, &objectCount);
        objectIndex = 0;
        while (objectIndex < objectCount && linkedObj == NULL) {
            GameObject* candidateObj = *objects;
            if (candidateObj->anim.classId == 0x36 &&
                (s32)placement->nodeId == ((DFropenodePlacement*)candidateObj->anim.placementData)->nodeId - 1) {
                linkedObj = candidateObj;
            }
            objects++;
            objectIndex++;
        }

        if (linkedObj == NULL) {
            return;
        }

        ((DFropenodeState*)linkedObj->extra)->linkedNode = obj;
        state = obj->extra;
        state->linkedNode = linkedObj;

        dx = linkedObj->anim.localPosX - obj->anim.localPosX;
        dy = linkedObj->anim.localPosY - obj->anim.localPosY;
        dz = linkedObj->anim.localPosZ - obj->anim.localPosZ;
        length = sqrtf(dz * dz + (dx * dx + dy * dy));
        state->ropeYaw = DFropenode_calculateRopeYaw(dx, dz);
        state->rope =
            DFropenode_createRope(0.0f, 0.0f, 0.0f, dx, dy, dz, length, 16, gDFropenodeNodeMasses[placement->style]);
        state->boundsMinX = obj->anim.localPosX;
        state->boundsMinZ = obj->anim.localPosZ;
        state->boundsMaxX = linkedObj->anim.localPosX;
        state->boundsMaxZ = linkedObj->anim.localPosZ;

        if (state->boundsMinX > state->boundsMaxX) {
            f32 temp = state->boundsMinX;
            state->boundsMinX = state->boundsMaxX;
            state->boundsMaxX = temp;
        }
        if (state->boundsMinZ > state->boundsMaxZ) {
            f32 temp = state->boundsMinZ;
            state->boundsMinZ = state->boundsMaxZ;
            state->boundsMaxZ = temp;
        }

        state->boundsMinX -= 25.0f;
        state->boundsMinZ -= 25.0f;
        state->boundsMaxX += 25.0f;
        state->boundsMaxZ += 25.0f;

        baseX = obj->anim.localPosX;
        baseY = obj->anim.localPosY;
        baseZ = obj->anim.localPosZ;
        linkedX = linkedObj->anim.localPosX;
        linkedY = linkedObj->anim.localPosY;
        linkedZ = linkedObj->anim.localPosZ;
        liftedY = baseY + 20.0f;
        normalX = liftedY * (baseZ - linkedZ) + (baseY * (linkedZ - baseZ) + (linkedY * (baseZ - baseZ)));
        normalY = baseZ * (baseX - linkedX) + (baseZ * (linkedX - baseX) + (linkedZ * (baseX - baseX)));
        normalZ = baseX * (baseY - linkedY) + (baseX * (linkedY - liftedY) + (linkedX * (liftedY - baseY)));
        normalLength = sqrtf(normalZ * normalZ + (normalX * normalX + normalY * normalY));
        if (normalLength > 0.0f) {
            normalX /= normalLength;
            normalY /= normalLength;
            normalZ /= normalLength;
        }
        state->plane.normal.x = normalX;
        state->plane.normal.y = normalY;
        state->plane.normal.z = normalZ;
        state->plane.distance = -(baseZ * normalZ + (baseX * normalX + baseY * normalY));
    }

    DFropenode_updateRopeSimulation(state->rope);
}

void DFropenode_init(GameObject* obj, DFropenodePlacement* placement) {
    DFropenodeState* state = obj->extra;

    if (gDFropenodeStyleUsesTransparency[placement->style] == 0) {
        obj->anim.flags &= ~0x80;
    }

    objAddObjectType(obj, DFROPENODE_OBJECT_GROUP);
    obj->animEventCallback = DFropenode_syncRopeToEndpoints;
    state->rope = NULL;
    state->linkedNode = NULL;
    obj->anim.alpha = 0x46;
}

void DFropenode_release(void) {
    int i;

    for (i = 0; i < DFROPENODE_STYLE_COUNT; i++) {
        textureFree(gDFropenodeTextures[i]);
    }
}

void DFropenode_initialise(void) {
    int i;

    for (i = 0; i < DFROPENODE_STYLE_COUNT; i++) {
        gDFropenodeTextures[i] = textureLoadAsset(gDFropenodeTextureAssetIds[i]);
    }
}

ObjectDescriptor20 gDFropenodeObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_20_SLOTS,
    (ObjectDescriptorCallback)DFropenode_initialise,
    (ObjectDescriptorCallback)DFropenode_release,
    0,
    (ObjectDescriptorCallback)DFropenode_init,
    (ObjectDescriptorCallback)DFropenode_update,
    (ObjectDescriptorCallback)DFropenode_hitDetect,
    (ObjectDescriptorCallback)DFropenode_render,
    (ObjectDescriptorCallback)DFropenode_free,
    (ObjectDescriptorCallback)DFropenode_getObjectTypeId,
    DFropenode_getExtraSize,
    (ObjectDescriptorCallback)DFropenode_getPlaneEquation,
    (ObjectDescriptorCallback)DFropenode_getWorldPosAtPhase,
    (ObjectDescriptorCallback)DFropenode_advancePhaseByDistance,
    (ObjectDescriptorCallback)DFropenode_applyForceAtPhase,
    (ObjectDescriptorCallback)DFropenode_findNearestRopePoint,
    (ObjectDescriptorCallback)DFropenode_getAngle,
    (ObjectDescriptorCallback)DFropenode_setVisible,
    (ObjectDescriptorCallback)DFropenode_isVisible,
    (ObjectDescriptorCallback)DFropenode_setMinY,
    (ObjectDescriptorCallback)DFropenode_clearLinkedObj,
};
