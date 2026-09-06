#include "dlls/object_descriptor.h"
#include "main/checkpoint_route.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/curve.h"
#include "main/vecmath.h"
#include "game/objects/object.h"

CheckpointSlot gCheckpointRouteTable[0x640 / sizeof(CheckpointSlot)];

void* gCheckpointRankItemsPending;
void* gCheckpointRankItems;
s16 gCheckpointRankItemPendingCount;
s16 gCheckpointRankItemCount;
s32 gCheckpointRouteCount;

s32 Checkpoint_buildControlPoints(CheckpointRouteEntry* checkpoint, s32 linkIndex, f32* outX, f32* outY, f32* outZ,
                                  u8 mode, f32 lateralOffset, f32 verticalOffset);
void Checkpoint_getRandomLinkedVector(s32 key, f32* out_vec, u8* flag_byte);
int Checkpoint_func09_ret_1(void);
void Checkpoint_onGameLoop(void);
u32 Checkpoint_getRouteRankItems(s32* p);
void Checkpoint_rewindRoute(CheckpointRouteState* o);
void Checkpoint_queueRouteRankItem(u32 v);
void Checkpoint_Remove(CheckpointRouteEntry* obj);
void Checkpoint_Add(CheckpointRouteEntry* entry);
void Checkpoint_reset(void);
void Checkpoint_release(void);
void Checkpoint_initialise(void);

CheckpointRouteEntry* Checkpoint_find(s32 key, s32* idx_out) {
    s32 high;
    s32 low;
    s32 mid;
    *idx_out = -1;
    if (key < 0) {
        return NULL;
    }
    high = gCheckpointRouteCount - 1;
    low = 0;
    while (high >= low) {
        mid = (high + low) >> 1;
        if ((u32)key > gCheckpointRouteTable[mid].key) {
            low = mid + 1;
        } else if ((u32)key < gCheckpointRouteTable[mid].key) {
            high = mid - 1;
        } else {
            *idx_out = mid;
            return gCheckpointRouteTable[mid].entry;
        }
    }
    *idx_out = -1;
    return NULL;
}
typedef struct CheckpointCursor {
    s16 headingAngle; /* 0x00 */
    s16 pitchAngle;   /* 0x02 */
    u8 pad04[0x08];
    f32 posX; /* 0x0C */
    f32 posY; /* 0x10 */
    f32 posZ; /* 0x14 */
} CheckpointCursor;
typedef struct CheckpointNavState {
    CheckpointRouteState route; /* 0x00 */
    u8 pad24[0x0C];
    u8 branchFlag; /* 0x30 */
} CheckpointNavState;

s32 Checkpoint_advanceRoute(CheckpointCursor* out, CheckpointNavState* o, f32 dist, s32 p3, u8 flag, int unused);

s32 Checkpoint_buildControlPoints(CheckpointRouteEntry* checkpoint, s32 linkIndex, f32* outX, f32* outY, f32* outZ,
                                  u8 mode, f32 lateralOffset, f32 verticalOffset) {
    f32 startSideX;
    f32 endSideX;
    f32 startSideZ;
    f32 endNegSin;
    f32 endSideZ;
    s32 routeIndex;
    f32* zPoints;
    f32* xPoints;
    f32* yPoints;
    f32 startNegSin;
    f32 startNegCos;
    CheckpointRouteEntry* nextCheckpoint;
    f32 endNegCos;
    f32 startWidthScale;
    f32 endWidthScale;
    s32 pointIndex;
    s32 result;
    s32 outputCount;

    result = 1;
    if (checkpoint == NULL) {
        return 0;
    }
    nextCheckpoint = Checkpoint_find(checkpoint->forwardLinkIds[linkIndex], &routeIndex);
    if (nextCheckpoint == NULL) {
        nextCheckpoint = Checkpoint_find(checkpoint->forwardLinkIds[1 - linkIndex], &routeIndex);
        result = 2;
    }
    if (nextCheckpoint == NULL) {
        return 0;
    }

    startNegSin = -mathSinf(3.1415927f * (checkpoint->heading << 8) / 32768.0f);
    startNegCos = -mathCosf(3.1415927f * (checkpoint->heading << 8) / 32768.0f);
    endNegSin = -mathSinf(3.1415927f * (nextCheckpoint->heading << 8) / 32768.0f);
    endNegCos = -mathCosf(3.1415927f * (nextCheckpoint->heading << 8) / 32768.0f);
    startWidthScale = 0.011111111f * checkpoint->width;
    endWidthScale = 0.011111111f * nextCheckpoint->width;

    /* Each axis stores two endpoints followed by their Hermite tangents. */
    if (mode == 1) {
        outputCount = 0;
        pointIndex = 0;
        xPoints = outX;
        yPoints = outY;
        zPoints = outZ;
        startSideX = startWidthScale * startNegCos;
        endSideX = endWidthScale * endNegCos;
        startSideZ = startWidthScale * -startNegSin;
        endSideZ = endWidthScale * -endNegSin;
        while (outputCount < 0x10) {
            xPoints[0] = checkpoint->sideOffsets[pointIndex] * startSideX + checkpoint->posX;
            xPoints[1] = nextCheckpoint->sideOffsets[pointIndex] * endSideX + nextCheckpoint->posX;
            xPoints[2] =
                2.0f * (checkpoint->tangentScale * mathSinf(3.1415927f * (checkpoint->tangentHeading << 8) / 32768.0f));
            xPoints[3] = 2.0f * (nextCheckpoint->tangentScale *
                                 mathSinf(3.1415927f * (nextCheckpoint->tangentHeading << 8) / 32768.0f));
            yPoints[0] = startWidthScale * checkpoint->heightOffsets[pointIndex] + checkpoint->posY;
            yPoints[1] = endWidthScale * nextCheckpoint->heightOffsets[pointIndex] + nextCheckpoint->posY;
            yPoints[2] = 0.0f;
            yPoints[3] = 0.0f;
            zPoints[0] = checkpoint->sideOffsets[pointIndex] * startSideZ + checkpoint->posZ;
            zPoints[1] = nextCheckpoint->sideOffsets[pointIndex] * endSideZ + nextCheckpoint->posZ;
            zPoints[2] =
                2.0f * (checkpoint->tangentScale * mathCosf(3.1415927f * (checkpoint->tangentHeading << 8) / 32768.0f));
            zPoints[3] = 2.0f * (nextCheckpoint->tangentScale *
                                 mathCosf(3.1415927f * (nextCheckpoint->tangentHeading << 8) / 32768.0f));
            pointIndex += 1;
            xPoints += 4;
            yPoints += 4;
            zPoints += 4;
            outputCount += 4;
        }
    } else if (mode == 0) {
        outX[0] = lateralOffset * (startWidthScale * startNegCos) + checkpoint->posX;
        outX[1] = lateralOffset * (endWidthScale * endNegCos) + nextCheckpoint->posX;
        outX[2] =
            2.0f * (checkpoint->tangentScale * mathSinf(3.1415927f * (checkpoint->tangentHeading << 8) / 32768.0f));
        outX[3] = 2.0f * (nextCheckpoint->tangentScale *
                          mathSinf(3.1415927f * (nextCheckpoint->tangentHeading << 8) / 32768.0f));
        outY[0] = startWidthScale * verticalOffset + checkpoint->posY;
        outY[1] = endWidthScale * verticalOffset + nextCheckpoint->posY;
        {
            f32 zero = 0.0f;
            outY[2] = zero;
            outY[3] = zero;
        }
        outZ[0] = lateralOffset * (startWidthScale * -startNegSin) + checkpoint->posZ;
        outZ[1] = lateralOffset * (endWidthScale * -endNegSin) + nextCheckpoint->posZ;
        outZ[2] =
            2.0f * (checkpoint->tangentScale * mathCosf(3.1415927f * (checkpoint->tangentHeading << 8) / 32768.0f));
        outZ[3] = 2.0f * (nextCheckpoint->tangentScale *
                          mathCosf(3.1415927f * (nextCheckpoint->tangentHeading << 8) / 32768.0f));
    } else {
        pointIndex = mode - 2;
        outX[0] = checkpoint->sideOffsets[pointIndex] * (startWidthScale * startNegCos) + checkpoint->posX;
        outX[1] = nextCheckpoint->sideOffsets[pointIndex] * (endWidthScale * endNegCos) + nextCheckpoint->posX;
        outX[2] =
            2.0f * (checkpoint->tangentScale * mathSinf(3.1415927f * (checkpoint->tangentHeading << 8) / 32768.0f));
        outX[3] = 2.0f * (nextCheckpoint->tangentScale *
                          mathSinf(3.1415927f * (nextCheckpoint->tangentHeading << 8) / 32768.0f));
        outY[0] = startWidthScale * checkpoint->heightOffsets[pointIndex] + checkpoint->posY;
        outY[1] = endWidthScale * nextCheckpoint->heightOffsets[pointIndex] + nextCheckpoint->posY;
        {
            f32 zero = 0.0f;
            outY[2] = zero;
            outY[3] = zero;
        }
        outZ[0] = checkpoint->sideOffsets[pointIndex] * (startWidthScale * -startNegSin) + checkpoint->posZ;
        outZ[1] = nextCheckpoint->sideOffsets[pointIndex] * (endWidthScale * -endNegSin) + nextCheckpoint->posZ;
        outZ[2] =
            2.0f * (checkpoint->tangentScale * mathCosf(3.1415927f * (checkpoint->tangentHeading << 8) / 32768.0f));
        outZ[3] = 2.0f * (nextCheckpoint->tangentScale *
                          mathCosf(3.1415927f * (nextCheckpoint->tangentHeading << 8) / 32768.0f));
    }
    return result;
}

/* Look up a checkpoint by key and emit a random local offset, then pick the
 * forward or back link to advance along depending on the flag byte. */
void Checkpoint_getRandomLinkedVector(s32 key, f32* out_vec, u8* flag_byte) {
    s32 local_idx;
    CheckpointRouteEntry* n;
    s32 alt_found;
    n = Checkpoint_find(key, &local_idx);
    if (n == 0) {
        return;
    }
    out_vec[0] = (f32)(s32)randomGetRange(-0x63, 0x63) / 100.0f;
    out_vec[1] = (f32)(s32)randomGetRange(-0x63, 0x63) / 100.0f;
    out_vec[2] = (f32)(s32)randomGetRange(0, 0x63) / 100.0f;
    alt_found = 0;
    {
        s32 forwardLink = n->forwardLink0;
        if (forwardLink != 0) {
            CheckpointRouteEntry* m = Checkpoint_find(forwardLink, &local_idx);
            if (m->forwardLink0 > -1) {
                alt_found = 1;
            }
        }
    }
    if ((s8)*flag_byte == 0) {
        if (alt_found != 0) {
            *(s32*)(out_vec + 4) = n->forwardLink0;
        } else {
            s32 backLink = n->backLink0;
            if (backLink > -1) {
                *(s32*)(out_vec + 4) = backLink;
                *flag_byte = 1;
            }
        }
    } else {
        s32 backLink = n->backLink0;
        if (backLink != 0) {
            *(s32*)(out_vec + 4) = backLink;
        } else if (alt_found != 0) {
            *(s32*)(out_vec + 4) = n->forwardLink0;
            *flag_byte = 0;
        }
    }
}

/* Rank object p against array at gCheckpointRankItems by (priority, distSq) descending. */
typedef struct PartFxItem {
    u8 pad00[0xc];
    f32 distSq;
    u8 pad10[0xc];
    s32 priority;
} PartFxItem;

s32 Checkpoint_getRouteRank(PartFxItem* p);
PartFxItem* Checkpoint_getRouteRankItem(s32 target_rank);

int Checkpoint_func09_ret_1(void) {
    return 0x1;
}

/* Advance along the route by arc-length `dist`, sampling the Hermite curve and
 * clamping t to [0,1]; crossing a segment end hands off to the next checkpoint. */
s32 Checkpoint_advanceRoute(CheckpointCursor* out, CheckpointNavState* o, f32 dist, s32 p3, u8 flag, int unused) {
    f32 v1[4];
    f32 v2[4];
    f32 v3[4];
    f32 outX;
    f32 outY;
    f32 outZ;
    s32 local_idx;
    s32 mode;
    s32 alt;
    CheckpointRouteEntry* n;
    s32 i;
    s8 clamp;
    s32 ang1;
    s32 ang2; /* only written and read under `flag != 0`; never read uninitialized */
    f32 kMax;
    f32 kMin;
    f32 t;
    f32 seg;
    f32 x;
    f32 y;
    f32 z;
    f32 len;

    i = 0;
    mode = p3 + 2;
    kMin = 0.0f;
    kMax = 1.0f;
    do {
        if (o->route.startCheckpointId < 0) {
            return 1;
        }
        n = Checkpoint_find(o->route.startCheckpointId, &local_idx);
        if (n == NULL) {
            return 1;
        }
        if (n->forwardLink0 < 0) {
            o->route.startCheckpointId = -1;
            return 1;
        }
        alt = 0;
        if (n->forwardLink1 > -1 && o->branchFlag != 0) {
            alt = 1;
        }
        if (Checkpoint_buildControlPoints(n, alt, v1, v2, v3, mode, 0.0f, 0.0f) == 0) {
            return 1;
        }
        len = sqrtf((v3[0] - v3[1]) * (v3[0] - v3[1]) +
                    ((v1[0] - v1[1]) * (v1[0] - v1[1]) + (v2[0] - v2[1]) * (v2[0] - v2[1])));
        t = o->route.pathT + dist / len;
        clamp = 0;
        if (t < kMin) {
            t = kMin;
            clamp = -1;
        }
        if (t > kMax) {
            t = kMax;
            clamp = 1;
        }
        x = Curve_EvalHermite(v1, t, &outX);
        y = Curve_EvalHermite(v2, t, &outY);
        z = Curve_EvalHermite(v3, t, &outZ);
        ang1 = (u16)getAngle(outX, outZ) + 0x8000;
        if (flag != 0) {
            f32 xd;
            f32 zd;
            ang2 = (u16)getAngle(sqrtf(outX * outX + outZ * outZ), outY) - 0x4000;
            xd = x - out->posX;
            zd = z - out->posZ;
            seg = sqrtf(xd * xd + zd * zd);
        } else {
            f32 xd;
            f32 zd;
            xd = x - out->posX;
            zd = z - out->posZ;
            seg = sqrtf(xd * xd + zd * zd);
        }
        if (dist < kMin) {
            seg = -seg;
        }
        if (clamp == -1 && seg < dist) {
            o->route.startCheckpointId = n->backLinkIds[alt];
            o->route.pathT = 0.9999f;
            if (alt != 0 && o->route.startCheckpointId < 0) {
                o->route.startCheckpointId = n->backLink0;
            }
        } else if (clamp == 1 && seg < dist) {
            o->route.startCheckpointId = n->forwardLinkIds[alt];
            o->route.pathT = 0.0f;
            if (alt != 0 && o->route.startCheckpointId < 0) {
                o->route.startCheckpointId = n->forwardLink0;
            }
        } else {
            o->route.pathT = t;
        }
        dist -= seg;
        out->posX = x;
        if (flag != 0) {
            out->posY = y;
        }
        out->posZ = z;
        i += 1;
    } while (i < 3);
    out->headingAngle = ang1;
    if (flag != 0) {
        out->pitchAngle = ang2;
    }
    return 0;
}

s32 Checkpoint_getRouteRank(PartFxItem* p) {
    PartFxItem* q;
    s32 rank = 1;
    PartFxItem** arr = (PartFxItem**)gCheckpointRankItems;
    s32 i;
    for (i = 0; i < gCheckpointRankItemCount; i++) {
        q = arr[i];
        if (q != p) {
            if (q->priority > p->priority) {
                rank++;
            } else if (q->priority == p->priority) {
                if (q->distSq > p->distSq) {
                    rank++;
                }
            }
        }
    }
    return rank;
}

PartFxItem* Checkpoint_getRouteRankItem(s32 target_rank) {
    s32 i;
    for (i = 0; i < gCheckpointRankItemCount; i++) {
        s32 j;
        s32 rank;
        PartFxItem* cur;
        PartFxItem* q;
        PartFxItem** arr;
        cur = ((PartFxItem**)gCheckpointRankItems)[i];
        rank = 1;
        arr = (PartFxItem**)gCheckpointRankItems;
        for (j = 0; j < gCheckpointRankItemCount; j++) {
            q = arr[j];
            if (q != cur) {
                if (q->priority > cur->priority) {
                    rank++;
                } else if (q->priority == cur->priority) {
                    if (q->distSq > cur->distSq) {
                        rank++;
                    }
                }
            }
        }
        if (rank == target_rank) {
            return cur;
        }
    }
    return NULL;
}

void Checkpoint_onGameLoop(void) {
    void* tmp = gCheckpointRankItems;
    gCheckpointRankItems = gCheckpointRankItemsPending;
    gCheckpointRankItemsPending = tmp;
    gCheckpointRankItemCount = gCheckpointRankItemPendingCount;
    gCheckpointRankItemPendingCount = 0;
}

u32 Checkpoint_getRouteRankItems(s32* p) {
    *p = gCheckpointRankItemCount;
    return (u32)gCheckpointRankItems;
}

/* Object cursor written back by Checkpoint_advanceRoute: the sampled heading/pitch
 * angles at the front and the interpolated world position (x/y/z) mid-block. */
STATIC_ASSERT(offsetof(CheckpointCursor, posX) == 0x0C);
STATIC_ASSERT(offsetof(CheckpointCursor, posZ) == 0x14);

/* Route navigation state passed as `o`: embeds CheckpointRouteState at the
 * front, with a route-branch flag byte further into the object. */
STATIC_ASSERT(offsetof(CheckpointNavState, branchFlag) == 0x30);

void Checkpoint_rewindRoute(CheckpointRouteState* o) {
    s32 local_idx;
    CheckpointRouteEntry* ret;
    s32 nxt;
    ret = Checkpoint_find(o->startCheckpointId, &local_idx);
    if (ret == 0) {
        o->currentCheckpointId = 0;
        o->routeProgress = 0.0f;
    } else {
        while ((nxt = ret->backLink0) > -1) {
            ret = Checkpoint_find(nxt, &local_idx);
            o->linkDepth = o->linkDepth + 1;
        }
        o->currentCheckpointId = o->startCheckpointId;
        o->routeProgress = 0.0f;
    }
}

void Checkpoint_queueRouteRankItem(u32 v) {
    if (gCheckpointRankItemPendingCount >= 10) {
        return;
    }
    ((u32*)gCheckpointRankItemsPending)[gCheckpointRankItemPendingCount++] = v;
}

int Checkpoint_getRouteHeading(GameObject* obj, CheckpointRouteState* state);
void Checkpoint_findRouteForObject(GameObject* obj, CheckpointRouteState* state, int filter);

/* Project the object onto the current checkpoint segment, stepping the route
 * cursor forward or back and returning the segment heading. */
int Checkpoint_getRouteHeading(GameObject* obj, CheckpointRouteState* state) {
    s32 slotC;
    s32 slot8;
    CheckpointRouteEntry* cp;
    CheckpointRouteEntry* cp2;
    short ang;
    f32 zero, cpX, sin2, cos2;
    f32 dist, dist2, nx, nz, offs, dx;
    f32 cpZ, distA, distB, dz, dy, len, q, proj, offs2, t0, sum, frac;
    f32 cosv, sinv, proj2, cp2X, cp2Z;

    if (state->currentCheckpointId < 0) {
        state->linkDepth = 0;
        state->routeProgress = 0.0f;
        if (state->startCheckpointId < 0) {
            return 0;
        }
        state->currentCheckpointId = state->startCheckpointId;
    }
    cp = Checkpoint_find(state->currentCheckpointId, &slot8);
    if (cp == NULL) {
        state->currentCheckpointId = -1;
        return 0;
    }
    cosv = mathSinf((3.1415927f * (f32)(cp->heading << 8)) / 32768.0f);
    sinv = mathCosf((3.1415927f * (f32)(cp->heading << 8)) / 32768.0f);
    offs = -(cp->posX * cosv + cp->posZ * sinv);
    dist = offs + (cosv * obj->anim.localPosX + sinv * obj->anim.localPosZ);
    if (cp->backLink0 > -1 && dist >= 0.0f) {
        state->currentCheckpointId = cp->backLink0;
        state->routeProgress = 0.99f;
        state->linkDepth = state->linkDepth - 1;
        return cp->heading;
    }
    if (cp->forwardLink0 < 0) {
        return cp->heading;
    }
    cp2 = Checkpoint_find(cp->forwardLink0, &slotC);
    ang = getAngle(cp2->posX - cp->posX, cp2->posZ - cp->posZ);
    sin2 = mathSinf((3.1415927f * (f32)(cp2->heading << 8)) / 32768.0f);
    cos2 = mathCosf((3.1415927f * (f32)(cp2->heading << 8)) / 32768.0f);
    offs2 = -(cp2->posX * sin2 + cp2->posZ * cos2);
    dist2 = offs2 + (sin2 * obj->anim.localPosX + cos2 * obj->anim.localPosZ);
    zero = 0.0f;
    if (dist2 < zero) {
        state->currentCheckpointId = cp->forwardLink0;
        state->routeProgress = zero;
        state->linkDepth = state->linkDepth + 1;
        return ang;
    }
    cp2Z = cp2->posZ;
    cp2X = cp2->posX;
    distA = offs + (cosv * cp2X + sinv * cp2Z);
    cpX = cp->posX;
    cpZ = cp->posZ;
    distB = offs2 + (sin2 * cpX + cos2 * cpZ);
    if (((distA < zero && dist < zero) || (distA >= 0.0f && dist >= 0.0f)) &&
        ((distB <= 0.0f && dist2 <= 0.0f) || (distB > 0.0f && dist2 > 0.0f))) {
        dx = cpX - cp2X;
        dy = cp->posY - cp2->posY;
        dz = cpZ - cp2Z;
        len = sqrtf(dz * dz + (dx * dx + dy * dy));
        if (len > 0.0f) {
            q = 1.0f / len;
            nx = dx * q;
            nz = dz * q;
        }
        proj = cosv * nx + sinv * nz;
        if (proj > -0.01f && proj < 0.01f) {
            return ang;
        }
        t0 = -dist / proj;
        proj2 = sin2 * nx + cos2 * nz;
        if (proj2 > -0.01f && proj2 < 0.01f) {
            return ang;
        }
        sum = dist2 / proj2;
        frac = 0.0f;
        sum = t0 + sum;
        if (sum != 0.0f) {
            frac = t0 / sum;
        }
        state->routeProgress = frac;
        if (state->routeProgress < 0.0f) {
            state->routeProgress = 0.0f;
        }
        if (state->routeProgress >= 0.999f) {
            state->routeProgress = 0.999f;
        }
    }
    return ang;
}

/* Flood-search the route graph (filtered by group) for the segment the object
 * lies within, recording the matched checkpoint and local coordinates. */
void Checkpoint_findRouteForObject(GameObject* obj, CheckpointRouteState* state, int filter) {
    int stack[64];
    char visited[200];
    s32 cur;
    s32 slot;
    CheckpointRouteEntry* cp;
    int count, k, i, j;
    CheckpointRouteEntry* n;
    CheckpointRouteEntry* e;
    f32 distA, cos1, sin2, cos2;
    f32 dist1, dist2, nx, nz, outX, sum;
    f32 offs2, sin1, distB, dx, dy, len, q, t0, dz, offs1, b1;
    f32 px, py, pz, width, frac, outY;
    f32 ddy;

    count = 0;
    for (i = 0; i < (int)gCheckpointRouteCount; i++) {
        visited[i] = 0;
    }
    cp = Checkpoint_find(state->startCheckpointId, &cur);
    if (cp != NULL) {
        stack[count++] = cur;
    } else {
        for (i = 0; i < gCheckpointRouteCount; i++) {
            e = gCheckpointRouteTable[i].entry;
            if (visited[i] == 0 && (filter == -1 || e->group == filter)) {
                nx = e->posX - obj->anim.localPosX;
                ddy = e->posY - obj->anim.localPosY;
                nz = e->posZ - obj->anim.localPosZ;
                if (nz * nz + (nx * nx + ddy * ddy) < 409600.0f) {
                    stack[count++] = i;
                    for (j = i; j < gCheckpointRouteCount; j++) {
                        if (filter == gCheckpointRouteTable[j].entry->group) {
                            visited[j] = 1;
                        }
                    }
                }
            }
        }
    }
    for (i = 0; i < (int)gCheckpointRouteCount; i++) {
        visited[i] = 0;
    }
    for (;;) {
        if (count > 0) {
            count--;
            cur = stack[count];
            cp = gCheckpointRouteTable[cur].entry;
        } else {
            state->startCheckpointId = -1;
            return;
        }
        if (cp == NULL) {
            return;
        }
        for (k = 0; k < 2; k++) {
            n = Checkpoint_find(cp->forwardLinkIds[k], &slot);
            if (n != NULL) {
                sin1 = mathSinf((3.1415927f * (f32)(cp->heading << 8)) / 32768.0f);
                cos1 = mathCosf((3.1415927f * (f32)(cp->heading << 8)) / 32768.0f);
                offs1 = -(cp->posX * sin1 + cp->posZ * cos1);
                sin2 = mathSinf((3.1415927f * (f32)(n->heading << 8)) / 32768.0f);
                cos2 = mathCosf((3.1415927f * (f32)(n->heading << 8)) / 32768.0f);
                offs2 = -(n->posX * sin2 + n->posZ * cos2);
                dist1 = offs1 + (sin1 * obj->anim.localPosX + cos1 * obj->anim.localPosZ);
                dist2 = offs2 + (sin2 * obj->anim.localPosX + cos2 * obj->anim.localPosZ);
                distA = offs1 + (sin1 * n->posX + cos1 * n->posZ);
                distB = offs2 + (sin2 * cp->posX + cos2 * cp->posZ);
                if (((distA <= 0.0f && dist1 <= 0.0f) || (distA > 0.0f && dist1 > 0.0f)) &&
                    ((distB <= 0.0f && dist2 <= 0.0f) || (distB > 0.0f && dist2 > 0.0f))) {
                    dx = cp->posX - n->posX;
                    dy = cp->posY - n->posY;
                    dz = cp->posZ - n->posZ;
                    len = sqrtf(dz * dz + (dx * dx + dy * dy));
                    if (len > 0.0) {
                        q = 1.0f / len;
                        nx = dx * q;
                        nz = dz * q;
                    }
                    q = sin1 * nx + cos1 * nz;
                    sin1 = sin2 * nx + cos2 * nz;
                    t0 = -dist1 / q;
                    sum = t0 + dist2 / sin1;
                    if (sum > 0.1f || sum < -0.1f) {
                        frac = t0 / sum;
                    } else {
                        frac = 0.0f;
                    }
                    if (frac < 0.0f) {
                        frac = 0.0f;
                    }
                    if (frac >= 0.999f) {
                        frac = 0.999f;
                    }
                    b1 = cp->width;
                    width = frac * ((f32)n->width - b1) + b1;
                    px = -(dx * frac - cp->posX);
                    py = -(dy * frac - cp->posY);
                    pz = -(dz * frac - cp->posZ);
                    dy = obj->anim.localPosY;
                    outY = (dy - py) / width;
                    dx = obj->anim.localPosX;
                    dz = obj->anim.localPosZ;
                    b1 = -(px * nz - pz * nx);
                    b1 += dx * nz - dz * nx;
                    outX = b1 / width;
                    if (outX < -8.0f || outX > 8.0f || outY < -4.0f || outY > 8.0f) {
                    } else {
                        state->startCheckpointId = cp->checkpointId;
                        state->matchedCheckpointId = cp->checkpointId;
                        state->localX = outX;
                        state->localY = outY;
                        state->pathT = frac;
                        state->group = cp->group;
                        return;
                    }
                }
            }
        }
        if (visited[cur] == 0) {
            for (j = 1; j >= 0; j--) {
                n = Checkpoint_find(cp->backLinkIds[j], &slot);
                if (n != NULL && visited[slot] == 0 && count < 0x3c) {
                    stack[count++] = slot;
                }
                n = Checkpoint_find(cp->forwardLinkIds[j], &slot);
                if (n != NULL && visited[slot] == 0 && count < 0x3c) {
                    stack[count++] = slot;
                }
            }
            visited[cur] = 1;
        }
    }
}
void Checkpoint_Remove(CheckpointRouteEntry* obj) {
    int count;
    int i = 0;
    CheckpointSlot* p = gCheckpointRouteTable;
    CheckpointSlot* e;

    while (i < (count = gCheckpointRouteCount) && obj->sortKey != p[i].key) {
        i++;
    }
    if (i >= count) {
        return;
    }
    gCheckpointRouteCount = gCheckpointRouteCount - 1;
    count = gCheckpointRouteCount;
    e = &gCheckpointRouteTable[i];
    while (i < count) {
        e->entry = (e + 1)->entry;
        e->key = (e + 1)->key;
        e++;
        i++;
    }
}

u32 gCheckpointPartFxListBuffer[0x14];

void Checkpoint_Add(CheckpointRouteEntry* entry) {
    int i = 0;
    CheckpointSlot* p = gCheckpointRouteTable;
    int count;
    while (i < (count = gCheckpointRouteCount) && entry->sortKey > p[i].key) {
        i++;
    }
    {
        CheckpointSlot* end = &gCheckpointRouteTable[count];
        while (count > i) {
            end->entry = (end - 1)->entry;
            end->key = (end - 1)->key;
            end--;
            count--;
        }
    }
    gCheckpointRouteCount = gCheckpointRouteCount + 1;
    gCheckpointRouteTable[i].entry = entry;
    gCheckpointRouteTable[i].key = entry->sortKey;
}

void Checkpoint_reset(void) {
    gCheckpointRouteCount = 0x0;
}

void Checkpoint_release(void) {
}
void Checkpoint_initialise(void) {
    gCheckpointRouteCount = 0;
    gCheckpointRankItemsPending = gCheckpointPartFxListBuffer;
    gCheckpointRankItems = gCheckpointPartFxListBuffer + 10;
}
typedef struct CheckpointDllInterface {
    u32 reserved0;
    u32 reserved1;
    u32 reserved2;
    u32 slotCountAndFlags;
    ObjectDescriptorCallback initialise;
    ObjectDescriptorCallback release;
    ObjectDescriptorCallback slot02;
    ObjectDescriptorCallback reset;
    ObjectDescriptorCallback add;
    ObjectDescriptorCallback remove;
    ObjectDescriptorCallback findRouteForObject;
    ObjectDescriptorCallback getRouteHeading;
    ObjectDescriptorCallback advanceRoute;
    ObjectDescriptorCallback slot09;
    ObjectDescriptorCallback getRandomLinkedVector;
    ObjectDescriptorCallback find;
    ObjectDescriptorCallback rewindRoute;
    ObjectDescriptorCallback queueRouteRankItem;
    ObjectDescriptorCallback getRouteRankItems;
    ObjectDescriptorCallback getRouteRank;
    ObjectDescriptorCallback getRouteRankItem;
    ObjectDescriptorCallback onGameLoop;
} CheckpointDllInterface;

CheckpointDllInterface Checkpoint_funcs = {
    0,
    0,
    0,
    0x00110000,
    (ObjectDescriptorCallback)Checkpoint_initialise,
    (ObjectDescriptorCallback)Checkpoint_release,
    0,
    (ObjectDescriptorCallback)Checkpoint_reset,
    (ObjectDescriptorCallback)Checkpoint_Add,
    (ObjectDescriptorCallback)Checkpoint_Remove,
    (ObjectDescriptorCallback)Checkpoint_findRouteForObject,
    (ObjectDescriptorCallback)Checkpoint_getRouteHeading,
    (ObjectDescriptorCallback)Checkpoint_advanceRoute,
    (ObjectDescriptorCallback)Checkpoint_func09_ret_1,
    (ObjectDescriptorCallback)Checkpoint_getRandomLinkedVector,
    (ObjectDescriptorCallback)Checkpoint_find,
    (ObjectDescriptorCallback)Checkpoint_rewindRoute,
    (ObjectDescriptorCallback)Checkpoint_queueRouteRankItem,
    (ObjectDescriptorCallback)Checkpoint_getRouteRankItems,
    (ObjectDescriptorCallback)Checkpoint_getRouteRank,
    (ObjectDescriptorCallback)Checkpoint_getRouteRankItem,
    (ObjectDescriptorCallback)Checkpoint_onGameLoop,
};
