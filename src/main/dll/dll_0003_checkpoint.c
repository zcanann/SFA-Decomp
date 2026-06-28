/*
 * Checkpoint route DLL (DLL 0x0003).
 *
 * Central TU globals:
 *   gCheckpointRouteTable - route table (sorted CheckpointSlot array)
 *   gCheckpointRouteCount - route count (entries in the table)
 *   lbl_803DD418 - front particle-list pointer (read side this frame)
 *   lbl_803DD41C - back particle-list pointer (write side this frame)
 *   lbl_803DD414 - front particle count (this frame's entries)
 *   lbl_803DD416 - back particle count (next frame's entries, capped at 10)
 *
 * Maintains the global sorted table of CheckpointRouteEntry nodes
 * (gCheckpointRouteTable, count gCheckpointRouteCount) used for path/route following, plus a
 * double-buffered particle-ranking list (lbl_803DD418/lbl_803DD41C, swapped
 * each game loop) holding up to 10 entries (lbl_803DD414/lbl_803DD416).
 *
 * Checkpoint_Add / Checkpoint_remove keep the table key-sorted;
 * Checkpoint_find does a binary search by key. fn_800D55BC builds the per-
 * segment Hermite control points (curve mode 0 = endpoints, 1 = full 4-point
 * spline sampled along the heading-rotated cross section, >=2 = single point);
 * Checkpoint_func08 walks the route advancing by arc length and clamps the
 * Hermite parameter t to [0,1]; Checkpoint_func07 / Checkpoint_func06 project
 * an object onto the route and select the active checkpoint segment.
 */
#include "main/checkpoint_route.h"
extern int randomGetRange(int lo, int hi);
extern s16 lbl_803DD414;
extern s16 lbl_803DD416;
extern f32 lbl_803E04E8;
extern f32 lbl_803E0500;
extern float mathSinf(float x);
extern float mathCosf(float x);
extern f32 sqrtf(f32);
extern f32 gCheckpointPi;
extern f32 gCheckpointAngleToRadians;
extern f32 gCheckpointWidthScale;
extern f32 lbl_803E04E4;

#pragma dont_inline on
CheckpointRouteEntry* Checkpoint_find(s32 key, s32* idx_out)
{
    extern CheckpointSlot gCheckpointRouteTable[]; /* #57 */
    extern s32 gCheckpointRouteCount; /* #57 */
    s32 high;
    s32 low;
    s32 mid;
    *idx_out = -1;
    if (key < 0) return NULL;
    high = gCheckpointRouteCount - 1;
    low = 0;
    while (high >= low)
    {
        mid = (high + low) >> 1;
        if ((u32)key > gCheckpointRouteTable[mid].key)
        {
            low = mid + 1;
        }
        else if ((u32)key < gCheckpointRouteTable[mid].key)
        {
            high = mid - 1;
        }
        else
        {
            *idx_out = mid;
            return gCheckpointRouteTable[mid].entry;
        }
    }
    *idx_out = -1;
    return NULL;
}

#pragma dont_inline off
s32 fn_800D55BC(CheckpointRouteEntry* p, s32 idx, f32* out1, f32* out2, f32* out3, u8 mode, f32 fa, f32 fb)
{
    f32 cosB;
    s32 local_idx;
    s32 j;
    f32 cosA;
    f32 sinA;
    CheckpointRouteEntry* q;
    f32 sinB;
    f32 sclA;
    f32 sclB;
    s32 i;
    s32 ret;
    f32* v3;

    ret = 1;
    if (p == NULL)
    {
        return 0;
    }
    q = Checkpoint_find(p->forwardLinkIds[idx], &local_idx);
    if (q == NULL)
    {
        q = Checkpoint_find(p->forwardLinkIds[1 - idx], &local_idx);
        ret = 2;
    }
    if (q == NULL)
    {
        return 0;
    }

    cosA = -mathSinf(gCheckpointPi * (f32)(p->heading << 8) / gCheckpointAngleToRadians);
    sinA = -mathCosf(gCheckpointPi * (f32)(p->heading << 8) / gCheckpointAngleToRadians);
    cosB = -mathSinf(gCheckpointPi * (f32)(q->heading << 8) / gCheckpointAngleToRadians);
    sinB = -mathCosf(gCheckpointPi * (f32)(q->heading << 8) / gCheckpointAngleToRadians);
    sclA = gCheckpointWidthScale * (f32)(u32)p->width;
    sclB = gCheckpointWidthScale * (f32)(u32)q->width;

    if (mode == 1)
    {
        f32 prodA;
        f32 prodB;
        f32 prodC;
        f32 prodD;
        j = 0;
        i = 0;
        v3 = out3;
        prodA = sclA * sinA;
        prodB = sclB * sinB;
        prodC = sclA * -cosA;
        prodD = sclB * -cosB;
        do
        {
            out1[0] = p->sideOffsets[i] * prodA + p->posX;
            out1[1] = q->sideOffsets[i] * prodB + q->posX;
            out1[2] = 2.0f * ((f32)(u32)p->waveAmplitude *
                mathSinf(3.1415927f * (f32)(p->wavePhase << 8) / 32768.0f));
            out1[3] = 2.0f * ((f32)(u32)q->waveAmplitude *
                mathSinf(3.1415927f * (f32)(q->wavePhase << 8) / 32768.0f));
            out2[0] = sclA * p->heightOffsets[i] + p->posY;
            out2[1] = sclB * q->heightOffsets[i] + q->posY;
            out2[2] = 0.0f;
            out2[3] = 0.0f;
            v3[0] = p->sideOffsets[i] * prodC + p->posZ;
            v3[1] = q->sideOffsets[i] * prodD + q->posZ;
            v3[2] = 2.0f * ((f32)(u32)p->waveAmplitude *
                mathCosf(3.1415927f * (f32)(p->wavePhase << 8) / 32768.0f));
            v3[3] = 2.0f * ((f32)(u32)q->waveAmplitude *
                mathCosf(3.1415927f * (f32)(q->wavePhase << 8) / 32768.0f));
            i += 1;
            out1 += 4;
            out2 += 4;
            v3 += 4;
            j += 4;
        }
        while (j < 0x10);
    }
    else if (mode == 0)
    {
        out1[0] = fa * (sclA * sinA) + p->posX;
        out1[1] = fa * (sclB * sinB) + q->posX;
        out1[2] = lbl_803E04E4 * ((f32)(u32)p->waveAmplitude *
            mathSinf(gCheckpointPi * (f32)(p->wavePhase << 8) / gCheckpointAngleToRadians));
        out1[3] = lbl_803E04E4 * ((f32)(u32)q->waveAmplitude *
            mathSinf(gCheckpointPi * (f32)(q->wavePhase << 8) / gCheckpointAngleToRadians));
        out2[0] = sclA * fb + p->posY;
        out2[1] = sclB * fb + q->posY;
        {
            f32 e8 = lbl_803E04E8;
            out2[2] = e8;
            out2[3] = e8;
        }
        out3[0] = fa * (sclA * -cosA) + p->posZ;
        out3[1] = fa * (sclB * -cosB) + q->posZ;
        out3[2] = lbl_803E04E4 * ((f32)(u32)p->waveAmplitude *
            mathCosf(gCheckpointPi * (f32)(p->wavePhase << 8) / gCheckpointAngleToRadians));
        out3[3] = lbl_803E04E4 * ((f32)(u32)q->waveAmplitude *
            mathCosf(gCheckpointPi * (f32)(q->wavePhase << 8) / gCheckpointAngleToRadians));
    }
    else
    {
        s32 pointIdx = mode - 2;
        out1[0] = p->sideOffsets[pointIdx] * (sclA * sinA) + p->posX;
        out1[1] = q->sideOffsets[pointIdx] * (sclB * sinB) + q->posX;
        out1[2] = lbl_803E04E4 * ((f32)(u32)p->waveAmplitude *
            mathSinf(gCheckpointPi * (f32)(p->wavePhase << 8) / gCheckpointAngleToRadians));
        out1[3] = lbl_803E04E4 * ((f32)(u32)q->waveAmplitude *
            mathSinf(gCheckpointPi * (f32)(q->wavePhase << 8) / gCheckpointAngleToRadians));
        out2[0] = sclA * p->heightOffsets[pointIdx] + p->posY;
        out2[1] = sclB * q->heightOffsets[pointIdx] + q->posY;
        {
            f32 e8 = lbl_803E04E8;
            out2[2] = e8;
            out2[3] = e8;
        }
        out3[0] = p->sideOffsets[pointIdx] * (sclA * -cosA) + p->posZ;
        out3[1] = q->sideOffsets[pointIdx] * (sclB * -cosB) + q->posZ;
        out3[2] = lbl_803E04E4 * ((f32)(u32)p->waveAmplitude *
            mathCosf(gCheckpointPi * (f32)(p->wavePhase << 8) / gCheckpointAngleToRadians));
        out3[3] = lbl_803E04E4 * ((f32)(u32)q->waveAmplitude *
            mathCosf(gCheckpointPi * (f32)(q->wavePhase << 8) / gCheckpointAngleToRadians));
    }
    return ret;
}

u32 Checkpoint_func0E(s32* p)
{
    extern u32 lbl_803DD418; /* #57 */
    *p = lbl_803DD414;
    return lbl_803DD418;
}

/* Rank object r3 against array at lbl_803DD418 by (priority, distSq) descending. */
typedef struct PartFxItem
{
    u8 pad00[0xc];
    f32 distSq;
    u8 pad10[0xc];
    s32 priority;
} PartFxItem;

s32 Checkpoint_func0F(PartFxItem* p)
{
    extern u32 lbl_803DD418; /* #57 */
    PartFxItem* q;
    s32 rank = 1;
    PartFxItem** arr = (PartFxItem**)lbl_803DD418;
    s32 i;
    for (i = 0; i < lbl_803DD414; i++)
    {
        q = arr[i];
        if (q != p)
        {
            if (q->priority > p->priority)
            {
                rank++;
            }
            else if (q->priority == p->priority)
            {
                if (q->distSq > p->distSq)
                {
                    rank++;
                }
            }
        }
    }
    return rank;
}

PartFxItem* Checkpoint_func10(s32 target_rank)
{
    extern u32 lbl_803DD418; /* #57 */
    s32 i = 0;
    PartFxItem** outer = (PartFxItem**)lbl_803DD418;
    PartFxItem** base = outer;
    s32 n = lbl_803DD414;
    for (; i < n; i++)
    {
        PartFxItem* cur = *outer;
        s32 rank = 1;
        PartFxItem** inner = base;
        s32 j;
        for (j = 0; j < n; j++)
        {
            PartFxItem* other = *inner;
            if (other != cur)
            {
                if (other->priority > cur->priority)
                {
                    rank++;
                }
                else if (other->priority == cur->priority)
                {
                    if (other->distSq > cur->distSq)
                    {
                        rank++;
                    }
                }
            }
            inner++;
        }
        if (rank == target_rank)
        {
            return cur;
        }
        outer++;
    }
    return NULL;
}

/* Look up a checkpoint by key and emit a random local offset, then pick the
 * forward or back link to advance along depending on the flag byte. */
void Checkpoint_func0A(s32 key, f32* out_vec, u8* flag_byte)
{
    s32 local_idx;
    CheckpointRouteEntry* n;
    s32 alt_found;
    n = Checkpoint_find(key, &local_idx);
    if (n == 0) return;
    out_vec[0] = (f32)(s32)
    randomGetRange(-0x63, 0x63) / lbl_803E0500;
    out_vec[1] = (f32)(s32)
    randomGetRange(-0x63, 0x63) / lbl_803E0500;
    out_vec[2] = (f32)(s32)
    randomGetRange(0, 0x63) / lbl_803E0500;
    alt_found = 0;
    {
        s32 v = n->forwardLink0;
        if (v != 0)
        {
            CheckpointRouteEntry* m = Checkpoint_find(v, &local_idx);
            if (m->forwardLink0 > -1)
            {
                alt_found = 1;
            }
        }
    }
    if ((s8) * flag_byte == 0)
    {
        if (alt_found != 0)
        {
            *(s32*)(out_vec + 4) = n->forwardLink0;
        }
        else
        {
            s32 v = n->backLink0;
            if (v > -1)
            {
                *(s32*)(out_vec + 4) = v;
                *flag_byte = 1;
            }
        }
    }
    else
    {
        s32 v = n->backLink0;
        if (v != 0)
        {
            *(s32*)(out_vec + 4) = v;
        }
        else if (alt_found != 0)
        {
            *(s32*)(out_vec + 4) = n->forwardLink0;
            *flag_byte = 0;
        }
    }
}

void Checkpoint_func0C(CheckpointRouteState* o)
{
    s32 local_idx;
    CheckpointRouteEntry* ret;
    s32 nxt;
    ret = Checkpoint_find(o->startCheckpointId, &local_idx);
    if (ret == 0)
    {
        o->currentCheckpointId = 0;
        o->routeProgress = lbl_803E04E8;
    }
    else
    {
        while ((nxt = ret->backLink0) > -1)
        {
            ret = Checkpoint_find(nxt, &local_idx);
            o->linkDepth = o->linkDepth + 1;
        }
        o->currentCheckpointId = o->startCheckpointId;
        o->routeProgress = lbl_803E04E8;
    }
}

void Checkpoint_func0D(u32 v)
{
    extern u32 lbl_803DD41C; /* #57 */
    if (lbl_803DD416 >= 10) return;
    ((u32*)lbl_803DD41C)[lbl_803DD416++] = v;
}

int Checkpoint_func09_ret_1(void) { return 0x1; }

extern f32 lbl_803E0504; /* used by Checkpoint_func08/07/06 */
extern f32 lbl_803E0508; /* used by Checkpoint_func08 */
extern f32 Curve_EvalHermite(f32* values, f32 t, f32* outTangent);

/* Advance along the route by arc-length `dist`, sampling the Hermite curve and
 * clamping t to [0,1]; crossing a segment end hands off to the next checkpoint. */
s32 Checkpoint_func08(u8* out, u8* o, f32 dist, s32 p3, u8 flag)
{
    extern u16 getAngle(f32 a, f32 b); /* #57 */
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
    kMin = lbl_803E04E8;
    kMax = lbl_803E0504;
    do
    {
        if (((CheckpointRouteState*)o)->startCheckpointId < 0)
        {
            return 1;
        }
        n = Checkpoint_find(((CheckpointRouteState*)o)->startCheckpointId, &local_idx);
        if (n == NULL)
        {
            return 1;
        }
        if (n->forwardLink0 < 0)
        {
            ((CheckpointRouteState*)o)->startCheckpointId = -1;
            return 1;
        }
        alt = 0;
        if (n->forwardLink1 > -1 && *(u8*)(o + 0x30) != 0)
        {
            alt = 1;
        }
        if (fn_800D55BC(n, alt, v1, v2, v3, mode, lbl_803E04E8, *(f32*)&lbl_803E04E8) == 0)
        {
            return 1;
        }
        len = sqrtf((v3[0] - v3[1]) * (v3[0] - v3[1]) +
            ((v1[0] - v1[1]) * (v1[0] - v1[1]) + (v2[0] - v2[1]) * (v2[0] - v2[1])));
        t = ((CheckpointRouteState*)o)->pathT + dist / len;
        clamp = 0;
        if (t < kMin)
        {
            t = kMin;
            clamp = -1;
        }
        if (t > kMax)
        {
            t = kMax;
            clamp = 1;
        }
        x = Curve_EvalHermite(v1, t, &outX);
        y = Curve_EvalHermite(v2, t, &outY);
        z = Curve_EvalHermite(v3, t, &outZ);
        ang1 = getAngle(outX, outZ) + 0x8000;
        if (flag != 0)
        {
            f32 xd;
            f32 zd;
            ang2 = getAngle(sqrtf(outX * outX + outZ * outZ), outY) - 0x4000;
            xd = x - *(f32*)(out + 0xc);
            zd = z - *(f32*)(out + 0x14);
            seg = sqrtf(xd * xd + zd * zd);
        }
        else
        {
            f32 xd;
            f32 zd;
            xd = x - *(f32*)(out + 0xc);
            zd = z - *(f32*)(out + 0x14);
            seg = sqrtf(xd * xd + zd * zd);
        }
        if (dist < kMin)
        {
            seg = -seg;
        }
        if (clamp == -1 && seg < dist)
        {
            ((CheckpointRouteState*)o)->startCheckpointId = n->backLinkIds[alt];
            ((CheckpointRouteState*)o)->pathT = lbl_803E0508;
            if (alt != 0 && ((CheckpointRouteState*)o)->startCheckpointId < 0)
            {
                ((CheckpointRouteState*)o)->startCheckpointId = n->backLink0;
            }
        }
        else if (clamp == 1 && seg < dist)
        {
            ((CheckpointRouteState*)o)->startCheckpointId = n->forwardLinkIds[alt];
            ((CheckpointRouteState*)o)->pathT = lbl_803E04E8;
            if (alt != 0 && ((CheckpointRouteState*)o)->startCheckpointId < 0)
            {
                ((CheckpointRouteState*)o)->startCheckpointId = n->forwardLink0;
            }
        }
        else
        {
            ((CheckpointRouteState*)o)->pathT = t;
        }
        dist -= seg;
        *(f32*)(out + 0xc) = x;
        if (flag != 0)
        {
            *(f32*)(out + 0x10) = y;
        }
        *(f32*)(out + 0x14) = z;
        i += 1;
    }
    while (i < 3);
    *(s16*)(out + 0) = ang1;
    if (flag != 0)
    {
        *(s16*)(out + 2) = ang2;
    }
    return 0;
}

void Checkpoint_onGameLoop(void)
{
    extern u32 lbl_803DD418; /* #57 */
    extern u32 lbl_803DD41C; /* #57 */
    u32 tmp = lbl_803DD418;
    lbl_803DD418 = lbl_803DD41C;
    lbl_803DD41C = tmp;
    lbl_803DD414 = lbl_803DD416;
    lbl_803DD416 = 0;
}

#pragma dont_inline reset

#include "main/game_object.h"
extern f32 lbl_803E050C; /* used by Checkpoint_func07 */
extern f32 lbl_803E0510; /* used by Checkpoint_func07 */
extern f32 lbl_803E0514; /* used by Checkpoint_func07 */
extern f32 lbl_803E0518; /* used by Checkpoint_func07/06 */

#pragma opt_common_subs off
/* Project the object onto the current checkpoint segment, stepping the route
 * cursor forward or back and returning the segment heading. */
int Checkpoint_func07(GameObject* obj, CheckpointRouteState* state)
{
    extern int getAngle(f32 dx, f32 dz); /* #57 */
    s32 slotC;
    s32 slot8;
    CheckpointRouteEntry* cp;
    CheckpointRouteEntry* cp2;
    short ang;
    f32 cosv, sinv, cos2, sin2;
    f32 dist, dist2, nx, nz, offs, dx;
    f32 offs2, distA, distB, dz, dy, len, q, proj, proj2, t0, sum, frac, zero;
    f32 cpX, cpZ, cp2X, cp2Z;

    if (state->currentCheckpointId < 0)
    {
        state->linkDepth = 0;
        state->routeProgress = lbl_803E04E8;
        if (state->startCheckpointId < 0)
        {
            return 0;
        }
        state->currentCheckpointId = state->startCheckpointId;
    }
    cp = Checkpoint_find(state->currentCheckpointId, &slot8);
    if (cp == NULL)
    {
        state->currentCheckpointId = -1;
        return 0;
    }
    cosv = mathSinf((gCheckpointPi * (f32)(cp->heading << 8)) / gCheckpointAngleToRadians);
    sinv = mathCosf((gCheckpointPi * (f32)(cp->heading << 8)) / gCheckpointAngleToRadians);
    offs = -(cp->posX * cosv + cp->posZ * sinv);
    dist = offs + (cosv * obj->anim.localPosX + sinv * obj->anim.localPosZ);
    if (cp->backLink0 > -1 && dist >= lbl_803E04E8)
    {
        state->currentCheckpointId = cp->backLink0;
        state->routeProgress = lbl_803E050C;
        state->linkDepth = state->linkDepth - 1;
        return cp->heading;
    }
    if (cp->forwardLink0 < 0)
    {
        return cp->heading;
    }
    cp2 = Checkpoint_find(cp->forwardLink0, &slotC);
    ang = getAngle(cp2->posX - cp->posX, cp2->posZ - cp->posZ);
    cos2 = mathSinf((gCheckpointPi * (f32)(cp2->heading << 8)) / gCheckpointAngleToRadians);
    sin2 = mathCosf((gCheckpointPi * (f32)(cp2->heading << 8)) / gCheckpointAngleToRadians);
    offs2 = -(cp2->posX * cos2 + cp2->posZ * sin2);
    dist2 = offs2 + (cos2 * obj->anim.localPosX + sin2 * obj->anim.localPosZ);
    zero = lbl_803E04E8;
    if (dist2 < zero)
    {
        state->currentCheckpointId = cp->forwardLink0;
        state->routeProgress = zero;
        state->linkDepth = state->linkDepth + 1;
        return ang;
    }
    cp2X = cp2->posX;
    cp2Z = cp2->posZ;
    distA = offs + (cosv * cp2X + sinv * cp2Z);
    cpX = cp->posX;
    cpZ = cp->posZ;
    distB = offs2 + (cos2 * cpX + sin2 * cpZ);
    if (((distA < zero && dist < zero) || (distA >= lbl_803E04E8 && dist >= lbl_803E04E8)) &&
        ((distB <= lbl_803E04E8 && dist2 <= lbl_803E04E8) || (distB > lbl_803E04E8 && dist2 > lbl_803E04E8)))
    {
        dx = cpX - cp2X;
        dy = cp->posY - cp2->posY;
        dz = cpZ - cp2Z;
        len = sqrtf(dz * dz + (dx * dx + dy * dy));
        if (len > lbl_803E04E8)
        {
            q = lbl_803E0504 / len;
            nx = dx * q;
            nz = dz * q;
        }
        proj = cosv * nx + sinv * nz;
        if (proj > lbl_803E0510 && proj < lbl_803E0514)
        {
            return ang;
        }
        t0 = -dist / proj;
        proj2 = cos2 * nx + sin2 * nz;
        if (proj2 > lbl_803E0510 && proj2 < lbl_803E0514)
        {
            return ang;
        }
        sum = t0 + dist2 / proj2;
        frac = lbl_803E04E8;
        if (lbl_803E04E8 != sum)
        {
            frac = t0 / sum;
        }
        state->routeProgress = frac;
        if (state->routeProgress < lbl_803E04E8)
        {
            state->routeProgress = lbl_803E04E8;
        }
        if (state->routeProgress >= lbl_803E0518)
        {
            state->routeProgress = lbl_803E0518;
        }
    }
    return ang;
}
#pragma opt_common_subs reset

#pragma scheduling on
#pragma peephole on
void Checkpoint_release(void)
{
}

void Checkpoint_reset(void) { extern u32 gCheckpointRouteCount; /* #57 */ gCheckpointRouteCount = 0x0; }

extern u32 gCheckpointPartFxListBuffer[];

#pragma scheduling off
void Checkpoint_initialise(void)
{
    extern void* lbl_803DD418; /* #57 */
    extern void* lbl_803DD41C; /* #57 */
    extern u32 gCheckpointRouteCount; /* #57 */
    gCheckpointRouteCount = 0;
    lbl_803DD41C = gCheckpointPartFxListBuffer;
    lbl_803DD418 = (void*)((u8*)gCheckpointPartFxListBuffer + 0x28);
}

#pragma opt_common_subs off
#pragma peephole off
void Checkpoint_Add(CheckpointRouteEntry* entry)
{
    extern CheckpointSlot gCheckpointRouteTable[]; /* #57 */
    extern u32 gCheckpointRouteCount; /* #57 */
    int i = 0;
    CheckpointSlot* p = gCheckpointRouteTable;
    int count;
    while (i < (count = gCheckpointRouteCount) && entry->sortKey > p[i].key)
    {
        i++;
    }
    {
        CheckpointSlot* end = &gCheckpointRouteTable[count];
        while (count > i)
        {
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
#pragma opt_common_subs reset

#pragma opt_common_subs off
void Checkpoint_remove(CheckpointRouteEntry* obj)
{
    extern CheckpointSlot gCheckpointRouteTable[]; /* #57 */
    extern u32 gCheckpointRouteCount; /* #57 */
    int count;
    int i = 0;
    CheckpointSlot* p = gCheckpointRouteTable;
    CheckpointSlot* e;

    while (i < (count = gCheckpointRouteCount) && obj->sortKey != p[i].key)
    {
        i++;
    }
    if (i >= count) return;
    count = gCheckpointRouteCount - 1;
    gCheckpointRouteCount = count;
    e = &gCheckpointRouteTable[i];
    while (i < count)
    {
        e->entry = (e + 1)->entry;
        e->key = (e + 1)->key;
        e++;
        i++;
    }
}
#pragma opt_common_subs reset

extern f64 lbl_803E0520;
extern f32 lbl_803E051C;
extern f32 lbl_803E0528;
extern f32 lbl_803E052C;
extern f32 lbl_803E0530;
extern f32 lbl_803E0534;
extern f32 lbl_803E0538;

/* Flood-search the route graph (filtered by group) for the segment the object
 * lies within, recording the matched checkpoint and local coordinates. */
#pragma opt_propagation off
void Checkpoint_func06(GameObject* obj, CheckpointRouteState* state, int filter)
{
    extern CheckpointSlot gCheckpointRouteTable[]; /* #57 */
    extern u32 gCheckpointRouteCount; /* #57 */
    int stack[64];
    char visited[200];
    s32 cur;
    s32 slot;
    int count, k, i, j;
    CheckpointRouteEntry* cp;
    CheckpointRouteEntry* n;
    CheckpointRouteEntry* e;
    f32 cos1, sin1, cos2, sin2;
    f32 dist1, dist2, nx, nz, offs1, dz;
    f32 offs2, distA, distB, dx, dy, len, q, t0, sum, frac, b1, width;
    f32 px, py, pz, outX, outY;
    f32 ddy, ddx, ddz;

    count = 0;
    for (i = 0; i < (int)gCheckpointRouteCount; i++)
    {
        visited[i] = 0;
    }
    cp = Checkpoint_find(state->startCheckpointId, &cur);
    if (cp != NULL)
    {
        stack[count++] = cur;
    }
    else
    {
        for (i = 0; i < (int)gCheckpointRouteCount; i++)
        {
            e = gCheckpointRouteTable[i].entry;
            if (visited[i] == 0 && (filter == -1 || e->group == filter))
            {
                ddx = e->posX - obj->anim.localPosX;
                ddy = e->posY - obj->anim.localPosY;
                ddz = e->posZ - obj->anim.localPosZ;
                if (ddz * ddz + (ddx * ddx + ddy * ddy) < lbl_803E051C)
                {
                    stack[count++] = i;
                    for (j = i; j < (int)gCheckpointRouteCount; j++)
                    {
                        if (filter == gCheckpointRouteTable[j].entry->group)
                        {
                            visited[j] = 1;
                        }
                    }
                }
            }
        }
    }
    for (i = 0; i < (int)gCheckpointRouteCount; i++)
    {
        visited[i] = 0;
    }
    for (;;)
    {
        if (count > 0)
        {
            count--;
            cur = stack[count];
            cp = gCheckpointRouteTable[cur].entry;
        }
        else
        {
            state->startCheckpointId = -1;
            return;
        }
        if (cp == NULL)
        {
            return;
        }
        for (k = 0; k < 2; k++)
        {
            n = Checkpoint_find(cp->forwardLinkIds[k], &slot);
            if (n != NULL)
            {
                cos1 = mathSinf((gCheckpointPi * (f32)(cp->heading << 8)) / gCheckpointAngleToRadians);
                sin1 = mathCosf((gCheckpointPi * (f32)(cp->heading << 8)) / gCheckpointAngleToRadians);
                offs1 = -(cp->posX * cos1 + cp->posZ * sin1);
                cos2 = mathSinf((gCheckpointPi * (f32)(n->heading << 8)) / gCheckpointAngleToRadians);
                sin2 = mathCosf((gCheckpointPi * (f32)(n->heading << 8)) / gCheckpointAngleToRadians);
                offs2 = -(n->posX * cos2 + n->posZ * sin2);
                dist1 = offs1 + (cos1 * obj->anim.localPosX + sin1 * obj->anim.localPosZ);
                dist2 = offs2 + (cos2 * obj->anim.localPosX + sin2 * obj->anim.localPosZ);
                distA = offs1 + (cos1 * n->posX + sin1 * n->posZ);
                distB = offs2 + (cos2 * cp->posX + sin2 * cp->posZ);
                if (((distA <= 0.0f && dist1 <= 0.0f) || (distA > 0.0f && dist1 > 0.0f))
                    &&
                    ((distB <= 0.0f && dist2 <= 0.0f) || (distB > 0.0f && dist2 >
                        0.0f)))
                {
                    dx = cp->posX - n->posX;
                    dy = cp->posY - n->posY;
                    dz = cp->posZ - n->posZ;
                    len = sqrtf(dz * dz + (dx * dx + dy * dy));
                    if (len > lbl_803E0520)
                    {
                        q = lbl_803E0504 / len;
                        nx = dx * q;
                        nz = dz * q;
                    }
                    q = cos1 * nx + sin1 * nz;
                    t0 = -dist1 / q;
                    sum = t0 + dist2 / (cos2 * nx + sin2 * nz);
                    if (sum > lbl_803E0528 || sum < lbl_803E052C)
                    {
                        frac = t0 / sum;
                    }
                    else
                    {
                        frac = lbl_803E04E8;
                    }
                    if (frac < lbl_803E04E8)
                    {
                        frac = lbl_803E04E8;
                    }
                    if (frac >= lbl_803E0518)
                    {
                        frac = lbl_803E0518;
                    }
                    b1 = cp->width;
                    width = frac * ((f32)n->width - b1) + b1;
                    px = -(dx * frac - cp->posX);
                    py = -(dy * frac - cp->posY);
                    pz = -(dz * frac - cp->posZ);
                    outY = (obj->anim.localPosY - py) / width;
                    outX = (-(px * nz - pz * nx) + (obj->anim.localPosX * nz - obj->anim.localPosZ * nx)) / width;
                    if (outX < lbl_803E0530 || outX > lbl_803E0534 || outY < lbl_803E0538 || outY > lbl_803E0534)
                    {
                    }
                    else
                    {
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
        if (visited[cur] == 0)
        {
            {
                /* lp walks cp + k words; backLinkIds at word 6 (0x18),
                 * forwardLinkIds at word 8 (0x20). Single induction pointer
                 * matches the retail strength-reduced addressing. */
                s32* lp;
                k = 1;
                lp = (s32*)cp + 1;
                for (; k >= 0; k--)
                {
                    n = Checkpoint_find(lp[6], &slot);
                    if (n != NULL && visited[slot] == 0 && count < 0x3c)
                    {
                        stack[count++] = slot;
                    }
                    n = Checkpoint_find(lp[8], &slot);
                    if (n != NULL && visited[slot] == 0 && count < 0x3c)
                    {
                        stack[count++] = slot;
                    }
                    lp--;
                }
            }
            visited[cur] = 1;
        }
    }
}
#pragma opt_propagation reset
