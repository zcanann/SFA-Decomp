#include "ghidra_import.h"
#include "main/dll/dll_B6.h"

extern void *Obj_GetPlayerObject(void);
extern int objAnimFn_80296328(void);
extern u8 **ObjList_GetObjects(int *idx, int *count);
extern int fn_80295C24(void *player);
extern void voxmaps_worldToGrid(f32 *world, int *grid);
extern u8 voxmaps_traceLine(int *from, int *to, int *out, u8 *occOut, int e);
extern f32 PSVECMag(void *vec);
extern float sqrtf(float x);

extern int gCamcontrolActiveActionId;
extern u16 lbl_803DB992;
extern f32 lbl_803E1630;
extern f32 lbl_803E1644;
extern f32 lbl_803E1648;
extern f32 lbl_803E1658;

/*
 * --INFO--
 *
 * Function: camcontrol_findBestTarget
 * EN v1.0 Address: 0x801010B4
 * EN v1.0 Size: 1268b
 * EN v1.1 Address: 0x80101350
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void *camcontrol_findBestTarget(int param_1, u8 *focus)
{
    int objIndex;
    int objCount;
    u8 out2[4];
    f32 v1[3];
    f32 v2[3];
    int g1[3];
    int g2[3];
    int out1[3];
    u8 *arr[8];
    f32 dist[8];
    u8 **ptr;
    int bestPri;
    u8 *obj;
    int idx;
    int count;
    u8 *player;
    u8 *f;
    u8 canTarget;
    u8 *data;
    u8 *entry;
    u8 *pp;
    u8 *row;
    u8 *src;
    u8 *best;
    int i;
    int k;
    int t;
    int ok;
    f32 dx, dz, dy, distsq, range;
    f32 *pd;
    u8 **pa;

    f = focus;
    bestPri = -1;
    count = 0;
    player = Obj_GetPlayerObject();
    if (player == NULL || f == NULL || gCamcontrolActiveActionId == 0x44 ||
        objAnimFn_80296328() == 0) {
        return NULL;
    }
    ptr = ObjList_GetObjects(&objIndex, &objCount);
    idx = objIndex;
    ptr += idx;
    for (; idx < objCount; ptr++, idx++) {
        obj = *ptr;
        data = *(u8 **)(obj + 0x78);
        if (data == NULL
           || *(u8 *)(obj + 0x36) != 0xff
           || (*(u8 *)(obj + 0xaf) & 0x28)
           || (!(*(u16 *)(obj + 0xb0) & 0x800) && !(*(u32 *)(*(u8 **)(obj + 0x50) + 0x44) & 1))
           || (*(s16 *)(obj + 6) & 0x4000)
           || (*(u16 *)(obj + 0xb0) & 0x40)
           || (lbl_803DB992 & ((ok = 1) << (data[*(u8 *)(obj + 0xe4) * 5 + 4] & 0xf))) == 0) {
            ok = 0;
        }
        if (ok == 0) {
            continue;
        }
        if ((int)*(u8 *)(*(u8 **)(*(u8 **)(obj + 0x50) + 0x40) + *(u8 *)(obj + 0xe4) * 0x18 + 0x11) < bestPri) {
            continue;
        }
        if ((*(u8 *)(obj + 0xaf) & 0x80) || (data[*(u8 *)(obj + 0xe4) * 5 + 4] & 0x80)) {
            dy = lbl_803E1630;
        } else {
            dy = *(f32 *)(f + 0x1c) - *(f32 *)(*(u8 **)(obj + 0x74) + *(u8 *)(obj + 0xe4) * 0x18 + 0x10);
        }
        if (dy <= lbl_803E1644) {
            continue;
        }
        if (dy >= lbl_803E1648) {
            continue;
        }
        dx = *(f32 *)(f + 0x18) - *(f32 *)(*(u8 **)(obj + 0x74) + *(u8 *)(obj + 0xe4) * 0x18 + 0xc);
        dz = *(f32 *)(f + 0x20) - *(f32 *)(*(u8 **)(obj + 0x74) + *(u8 *)(obj + 0xe4) * 0x18 + 0x14);
        distsq = dz * dz + dx * dx;
        entry = data + *(u8 *)(obj + 0xe4) * 5;
        range = (f32)(int)(entry[2] << 2);
        if (distsq >= range * range) {
            continue;
        }
        canTarget = 1;
        if ((entry[4] & 0xf) == 2 && fn_80295C24(player) != 0) {
            canTarget = 0;
        }
        if (canTarget == 0) {
            continue;
        }
        bestPri = *(u8 *)(*(u8 **)(*(u8 **)(obj + 0x50) + 0x40) + *(u8 *)(obj + 0xe4) * 0x18 + 0x11);
        i = 0;
        pa = arr;
        while (i < count
            && (int)*(u8 *)(*(u8 **)(*(u8 **)(*pa + 0x50) + 0x40) + *(u8 *)(*pa + 0xe4) * 0x18 + 0x11) > bestPri) {
            pa++;
            i++;
        }
        pd = dist + i;
        pa = arr + i;
        while (i < count && *pd < distsq
            && bestPri == (int)*(u8 *)(*(u8 **)(*(u8 **)(*pa + 0x50) + 0x40) + *(u8 *)(*pa + 0xe4) * 0x18 + 0x11)) {
            pd++;
            pa++;
            i++;
        }
        for (k = count; k > i; k--) {
            dist[k] = dist[k - 1];
            arr[k] = arr[k - 1];
        }
        dist[i] = distsq;
        arr[i] = obj;
        count++;
        if (count == 8) {
            break;
        }
    }
    if (count > 0) {
        best = arr[0];
        pp = *(u8 **)(*(u8 **)(best + 0x50) + 0x40);
        t = *(u8 *)(best + 0xe4) * 0x18;
        row = pp + t;
        if (row[0x10] & 0x20) {
            v1[0] = *(f32 *)(f + 0x18);
            v1[1] = lbl_803E1648 + *(f32 *)(f + 0x1c);
            v1[2] = *(f32 *)(f + 0x20);
            src = *(u8 **)(best + 0x74);
            v2[0] = *(f32 *)(src + t);
            v2[1] = *(f32 *)(src + t + 4);
            v2[2] = *(f32 *)(src + t + 8);
            voxmaps_worldToGrid(v1, g1);
            voxmaps_worldToGrid(v2, g2);
            if (voxmaps_traceLine(g1, g2, out1, out2, 0) == 0 && out2[0] != 1) {
                return NULL;
            }
        }
        return arr[0];
    }
    return NULL;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: camcontrol_updateMoveAverage
 * EN v1.0 Address: 0x801015A8
 * EN v1.0 Size: 232b
 * EN v1.1 Address: 0x801018A4
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void camcontrol_updateMoveAverage(int *obj, void *p) {
    f32 mag;
    *(f32 *)((char *)obj + 0xc8) = *(f32 *)((char *)obj + 0xcc);
    *(f32 *)((char *)obj + 0xcc) = *(f32 *)((char *)obj + 0xd0);
    *(f32 *)((char *)obj + 0xd0) = *(f32 *)((char *)obj + 0xd4);
    *(f32 *)((char *)obj + 0xd4) = *(f32 *)((char *)obj + 0xd8);
    mag = PSVECMag((char *)p + 0x24);
    if (mag > lbl_803E1630) {
        mag = sqrtf(mag);
    }
    *(f32 *)((char *)obj + 0xd8) = mag;
    *(f32 *)((char *)obj + 0xc4) = lbl_803E1630;
    *(f32 *)((char *)obj + 0xc4) = *(f32 *)((char *)obj + 0xc4) + *(f32 *)((char *)obj + 0xc8);
    *(f32 *)((char *)obj + 0xc4) = *(f32 *)((char *)obj + 0xc4) + *(f32 *)((char *)obj + 0xcc);
    *(f32 *)((char *)obj + 0xc4) = *(f32 *)((char *)obj + 0xc4) + *(f32 *)((char *)obj + 0xd0);
    *(f32 *)((char *)obj + 0xc4) = *(f32 *)((char *)obj + 0xc4) + *(f32 *)((char *)obj + 0xd4);
    *(f32 *)((char *)obj + 0xc4) = *(f32 *)((char *)obj + 0xc4) + *(f32 *)((char *)obj + 0xd8);
    *(f32 *)((char *)obj + 0xc4) = *(f32 *)((char *)obj + 0xc4) * lbl_803E1658;
    if (*(f32 *)((char *)obj + 0xc4) < lbl_803E1630) {
        *(f32 *)((char *)obj + 0xc4) = -*(f32 *)((char *)obj + 0xc4);
    }
}
#pragma peephole reset
#pragma scheduling reset
