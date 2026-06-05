#include "ghidra_import.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/DB/DBbonedust.h"
#include "main/objanim.h"
#include "main/unknown/autos/placeholder_80295318.h"
#include "main/dll/player_80295318_shared.h"

#define SFXdn_rexhurt13 16
#define SFXdn_rexroarlng11 17
#define SFXdn_hightop_hurt1 27
#define SFXen_lflsh2_b 44
#define SFXen_liftstpc 46
#define SFXen_littletink22 47
#define SFXmn_dimbos36 105
#define SFXmn_dimraw26 109
#define SFXsp_skeep_mumb1 266
#define SFXtr_gal_prophit 302
#define SFXtr_jbike_snowhit 304
#define SFXtr_barrelgrabber_eloop 307
#define SFXtr_jbike_snowspray 309
#define SFXtr_jbike_boost 310
#define SFXmammoth_snowstep 520
#define SFXmammoth_annoyed 521
#define SFXmammoth_attacks 522
#define SFXmammoth_suck 523
#define SFXthorntail_injured2 528
#define SFXthorntail_snort1 529
#define SFXthorntail_snort2 530
#define SFXhightop_call1 533
#define SFXhightop_call2 534
#define SFXmammoth_annoyed2 535
#define SFXmammoth_breath1 536
#define SFXmammoth_breath2 537
#define SFXmammoth_huff1 538
#define SFXmammoth_huff2 539
#define SFXmammoth_dirtstep 540
#define SFXbaddie_eggsnatch_sniff3 707
#define SFXspirit_pool_wobble2 799
#define SFXdrak_roar1 826

void fn_802960E4(void) {}

int fn_80297498(void) { return 0x0; }

int fn_80297824(void) { return 0x0; }

#pragma scheduling off
#pragma peephole off
int fn_80295CE4(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return (*(u8 *)((char *)inner + 0x3f4) >> 6) & 1;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802960E8(void *playerObj, s16 p2)
{
    int inner = *(int *)((char *)playerObj + 0xb8);
    *(s16 *)((char *)inner + 0x81c) = p2;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802960F4(int obj, int *out)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if (out == NULL) {
        return;
    }
    *out = (int)((char *)inner + 0x3c4);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
f32 fn_8029610C(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(f32 *)((char *)inner + 0x280);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80296118(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(int *)((char *)inner + 0x2d0);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
f32 fn_80296214(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(f32 *)((char *)inner + 0x784);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_80296220(int obj, f32 v)
{
    int inner = *(int *)((char *)obj + 0xb8);
    *(f32 *)((char *)inner + 0x784) = v;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_8029622C(int obj)
{
    return (*(u16 *)((char *)obj + 0xb0) & 0x1000) == 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80296448(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return (*(u8 *)((char *)inner + 0x3f0) >> 5) & 1;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80296464(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(int *)((char *)inner + 0x360) & 1;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80295BF0(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(u8 *)((char *)inner + 0x8c8) != 0x44;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80295C0C(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return ((*(u8 *)((char *)inner + 0x3f0) >> 1) & 1) == 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80295C24(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(f32 *)((char *)inner + 0x87c) > lbl_803E7EA4;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80295C40(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(f32 *)((char *)inner + 0x838) > lbl_803E7ED4;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80295CBC(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(s16 *)((char *)inner + 0x274) == 0x13;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802961FC(int a, u8 type)
{
    if (type > 2) {
        lbl_803DE459 = 0;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_8029630C(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(s16 *)((char *)inner + 0x274) != 0x26;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_8029669C(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(s16 *)((char *)inner + 0x274) == 7;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802966B4(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(s16 *)((char *)inner + 0x274) == 6;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_80296BBC(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    *(int *)((char *)inner + 0x360) &= ~2;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_80296C6C(int obj, int flag)
{
    int inner = *(int *)((char *)obj + 0xb8);
    ((ByteFlags *)((char *)inner + 0x3f3))->b02 = flag;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_80297254(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    ((ByteFlags *)((char *)inner + 0x3f2))->b20 = 1;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_8029726C(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    ((ByteFlags *)((char *)inner + 0x3f2))->b40 = 1;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_80297284(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    ((ByteFlags *)((char *)inner + 0x3f2))->b80 = 1;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802966CC(int obj)
{
    return *(int *)((char *)obj + 0xc8);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_80296B70(int v)
{
    lbl_803DE424 = v;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
f32 fn_802966F4(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(f32 *)((char *)inner + 0x778);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802972A8(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(int *)((char *)inner + 0x7f0);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int EmissionController_IsLingering(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(u8 *)((char *)inner + 0x8c5);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
uint playerGetStateFlag310(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(int *)((char *)inner + 0x310);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80296A14(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(s16 *)((char *)*(int *)((char *)inner + 0x35c) + 4);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80296A8C(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(s16 *)((char *)*(int *)((char *)inner + 0x35c) + 6);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80296C4C(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return (*(u8 *)((char *)inner + 0x3f3) >> 1) & 1;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80296C5C(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return (*(u8 *)((char *)inner + 0x3f3) >> 2) & 1;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_8029656C(int obj, f32 *out)
{
    int inner = *(int *)((char *)obj + 0xb8);
    *out = *(f32 *)((char *)inner + 0x77c);
    return *(u8 *)((char *)inner + 0x8c4);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80296AD4(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(s8 *)((char *)*(int *)((char *)inner + 0x35c) + 1);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80296AE8(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(s8 *)((char *)*(int *)((char *)inner + 0x35c));
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int playerGetMoney(void *player)
{
    int inner = *(int *)((char *)player + 0xb8);
    return *(u8 *)((char *)*(int *)((char *)inner + 0x35c) + 8);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int playerIsDisguised(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return (*(u8 *)((char *)inner + 0x3f3) >> 3) & 1;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int objGetAnimStateFlags(int obj, int flag)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(s8 *)((char *)*(int *)((char *)inner + 0x35c) + 2) & flag;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int objGetAnimState80A(void *obj)
{
    void *inner = *(void **)((char *)obj + 0xb8);
    if (inner != NULL) {
        return *(s16 *)((char *)inner + 0x80a);
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void cameraGetPrevPos2(int obj, f32 *x, f32 *y, f32 *z)
{
    int inner = *(int *)((char *)obj + 0xb8);
    *x = *(f32 *)((char *)inner + 0x24);
    *y = *(f32 *)((char *)inner + 0x28);
    *z = *(f32 *)((char *)inner + 0x2c);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802966D4(int obj, int *out)
{
    int inner = *(int *)((char *)obj + 0xb8);
    *out = *(int *)((char *)inner + 0x7f8);
    return *(int *)((char *)inner + 0x7f8) != 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80296C2C(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(s8 *)((char *)*(int *)((char *)inner + 0x35c)) > 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_80298924(int obj)
{
    ObjHits_SyncObjectPositionIfDirty(obj);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802A00C0(int obj)
{
    ObjHits_SyncObjectPositionIfDirty(obj);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802A49A8(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    *(int *)((char *)inner + 0x400) = (int)lbl_80333250;
    *(int *)((char *)inner + 0x3f8) = (int)lbl_80333050;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802B6F48(int obj)
{
    playerInitFuncPtrs(obj);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802969F0(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if (((ByteFlags *)((char *)inner + 0x3f1))->b01) {
        return *(u8 *)((char *)inner + 0x86c);
    }
    return -1;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802961D4(int obj, int v)
{
    int inner = *(int *)((char *)obj + 0xb8);
    *(s16 *)((char *)obj + 0) = v;
    *(s16 *)((char *)inner + 0x478) = v;
    *(s16 *)((char *)inner + 0x484) = v;
    *(int *)((char *)inner + 0x360) |= 0x800000;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_80296B78(int obj, int p2)
{
    fn_802AB38C(obj, *(int *)((char *)obj + 0xb8), p2);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802974A0(int obj, int state, f32 fv)
{
    int inner = *(int *)((char *)obj + 0xb8);
    *(f32 *)((char *)inner + 0x778) = lbl_803E7ED8;
    *(int *)((char *)inner + 0x360) |= 0x2000000;
    *(int *)((char *)state + 0) |= 0x200000;
    if (lbl_803E7EA4 == *(f32 *)((char *)inner + 0x784)) {
        void *sub;
        ((ByteFlags *)((char *)inner + 0x3f0))->b80 = 0;
        ((ByteFlags *)((char *)inner + 0x3f0))->b10 = 0;
        ((ByteFlags *)((char *)inner + 0x3f0))->b08 = 0;
        staffFn_80170380(lbl_803DE450, 2);
        ((ByteFlags *)((char *)inner + 0x3f0))->b02 = 0;
        *(int *)((char *)inner + 0x360) |= 0x800000;
        ObjHits_SyncObjectPositionIfDirty(obj);
        ((ByteFlags *)((char *)inner + 0x3f0))->b40 = 0;
        ((ByteFlags *)((char *)inner + 0x3f0))->b04 = 1;
        ((ByteFlags *)((char *)inner + 0x3f4))->b10 = 0;
        *(u8 *)((char *)inner + 0x800) = 0;
        sub = *(void **)((char *)inner + 0x7f8);
        if (sub != NULL) {
            s16 id = *(s16 *)((char *)sub + 0x46);
            if (id == 0x3cf || id == 0x662) {
                objThrowFn_80182504((int)sub);
            } else {
                objSaveFn_800ea774((int)sub);
            }
            *(s16 *)((char *)*(int *)((char *)inner + 0x7f8) + 0x6) &= ~0x4000;
            *(int *)((char *)*(int *)((char *)inner + 0x7f8) + 0xf8) = 0;
            *(int *)((char *)inner + 0x7f8) = 0;
        }
        *(int *)((char *)state + 0x308) = (int)fn_802A514C;
        return 3;
    }
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        ObjAnim_SetCurrentMove(obj, 0x12, lbl_803E7EA4, 1);
    }
    {
        f32 v = (lbl_803E7EE0 + *(f32 *)((char *)inner + 0x784)) * lbl_803E7E98;
        f32 clamped;
        if (v < lbl_803E7EA4) {
            clamped = lbl_803E7EA4;
        } else if (v > lbl_803E7EE0) {
            clamped = lbl_803E7EE0;
        } else {
            clamped = v;
        }
        ObjAnim_SetMoveProgress(lbl_803E7EE0 - clamped, (ObjAnimComponent *)obj);
    }
    (*(void (*)(int, int, int, f32, f32))(*(int *)(*gPlayerInterface + 0x44)))(
        obj, state, *(int *)((char *)inner + 0x474), fv, lbl_803E7EE0);
    *(f32 *)((char *)state + 0x2b8) = lbl_803E7EF4;
    *(f32 *)((char *)state + 0x2a0) = lbl_803E7EF8;
    *(f32 *)((char *)obj + 0x28) = *(f32 *)((char *)inner + 0x784) * fv;
    if (*(f32 *)((char *)state + 0x298) > lbl_803E7EFC) {
        *(s16 *)((char *)inner + 0x478) =
            (s16)(int)((f32)(s16)*(s16 *)((char *)inner + 0x478) +
                       lbl_803E7F00 * ((f32)*(int *)((char *)inner + 0x480) * fv * lbl_803E7F04));
        *(s16 *)((char *)inner + 0x484) = *(s16 *)((char *)inner + 0x478);
    }
    fn_802ABAE8(obj, state, inner, lbl_803E7EA4);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_8029782C(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    *(int *)((char *)inner + 0x360) |= 0x800000;
    ((ByteFlags *)((char *)inner + 0x3f6))->b20 = 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int objIsCurModelNotZero(void *obj)
{
    if (obj != NULL) {
        return *(s8 *)((char *)obj + 0xad) != 0;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int playerHasSpell(int obj, int spell)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if ((u32)spell > 0xb) {
        return 0;
    }
    return *(u8 *)((char *)inner + 0x8c7) & (1 << spell);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80295C5C(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(s16 *)((char *)inner + 0x274) == 0x36 &&
           ((ByteFlags *)((char *)inner + 0x3f3))->b10;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int objFn_80296700(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if (*(u8 *)((char *)inner + 0x8b3) != 0 && *(u8 *)((char *)inner + 0x8b4) != 0) {
        return 1;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802961A4(int obj, int *out1, f32 *out2)
{
    int inner = *(int *)((char *)obj + 0xb8);
    *out1 = *(s16 *)((char *)obj + 0xa0);
    if (*(s16 *)((char *)inner + 0x274) == 0x26) {
        *out2 = *(f32 *)((char *)inner + 0x7d8);
    } else {
        *out2 = *(f32 *)((char *)inner + 0x7d4);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void playerLock(int obj, int p2)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if (p2 != 0) {
        *(int *)((char *)inner + 0x360) |= 0x200000;
    } else {
        *(int *)((char *)inner + 0x360) &= ~0x200000;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_80296A9C(int obj, int p2)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int deref = *(int *)((char *)inner + 0x35c);
    int v = *(s16 *)((char *)deref + 6) + p2;
    if (v < 0) {
        v = 0;
    } else if (v > 0x64) {
        v = 0x64;
    }
    *(s16 *)((char *)deref + 6) = (s16)v;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_80296518(int obj, int flag, int set)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if (set != 0) {
        *(s8 *)((char *)*(int *)((char *)inner + 0x35c) + 2) |= flag;
    } else {
        *(s8 *)((char *)*(int *)((char *)inner + 0x35c) + 2) &= ~flag;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
u8 fn_80296414(int obj, int p2, u8 *out)
{
    int inner = *(int *)((char *)obj + 0xb8);
    *out = *(u8 *)((char *)inner + 0x682);
    return *(s16 *)((char *)inner + 0x274) == 0x1c &&
           *(u32 *)((char *)inner + 0x67c) == (u32)p2;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80295C88(int obj)
{
    f32 dist = lbl_803E7EDC;
    return ObjGroup_FindNearestObject(0x30, obj, &dist);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_8029697C(int obj, s16 *out1, s16 *out2)
{
    int inner = *(int *)((char *)obj + 0xb8);
    *out1 = lbl_803E7EE4 * *(f32 *)((char *)inner + 0x7b8);
    if (*(void **)((char *)inner + 0x7f0) != NULL) {
        *out2 = lbl_803E7EE8 * *(f32 *)((char *)inner + 0x7bc);
    } else {
        *out2 = lbl_803E7EEC * *(f32 *)((char *)inner + 0x7bc);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void playerAddHealth(int obj, int amount)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int deref = *(int *)((char *)inner + 0x35c);
    int h = *(s8 *)((char *)deref);
    h += amount;
    if (h < 0) {
        h = 0;
    } else if (h > *(s8 *)((char *)deref + 1)) {
        h = *(s8 *)((char *)deref + 1);
    }
    *(s8 *)((char *)deref) = (s8)h;
    if (*(s8 *)((char *)*(int *)((char *)inner + 0x35c)) <= 0) {
        playerDie(obj);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void playerAddRemoveMagic(int obj, int amount)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int deref = *(int *)((char *)inner + 0x35c);
    int m = *(s16 *)((char *)deref + 4);
    m += amount;
    if (m < 0) {
        m = 0;
    } else if (m > *(s16 *)((char *)deref + 6)) {
        m = *(s16 *)((char *)deref + 6);
    }
    *(s16 *)((char *)deref + 4) = (s16)m;
    if (amount > 0) {
        Sfx_PlayFromObject(0, SFXmammoth_dirtstep);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802994A4(int obj)
{
    *(s16 *)((char *)*(int *)((char *)obj + 0xb8) + 0x80a) = -1;
    ObjHits_SyncObjectPositionIfDirty(obj);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int objFn_802962b4(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    ByteFlags *f = (ByteFlags *)((char *)inner + 0x3f0);
    s16 s;
    if (f->b04 || f->b08 || f->b10) {
        return 0;
    }
    s = *(s16 *)((char *)inner + 0x274);
    if (s == 1 || s == 2) {
        return 1;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80296240(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    ByteFlags *f = (ByteFlags *)((char *)inner + 0x3f0);
    s16 s;
    if (f->b04 || f->b08 || f->b20 || f->b10 ||
        ((ByteFlags *)((char *)inner + 0x3f3))->b08) {
        return 0;
    }
    s = *(s16 *)((char *)inner + 0x274);
    if (s == 1 || s == 2) {
        return 1;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_80296474(int obj, int spell, int set)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if ((u32)spell > 0xb) {
        return;
    }
    if (set != 0) {
        *(u8 *)((char *)inner + 0x8c7) |= (1 << spell);
    } else {
        *(u8 *)((char *)inner + 0x8c7) &= ~(1 << spell);
    }
    GameBit_Set(lbl_80334A54[spell], set);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802A4B4C(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    void *p = *(void **)((char *)inner + 0x7f8);
    if (p != NULL) {
        *(int *)((char *)p + 0xf8) = 1;
        *(int *)((char *)inner + 0x360) |= 0x800000;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802985AC(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    ((ByteFlags *)((char *)inner + 0x3f4))->b20 = 0;
    *(f32 *)((char *)inner + 0x414) = lbl_803E7EA4;
    ((ByteFlags *)((char *)inner + 0x3f3))->b10 = 0;
    *(s16 *)((char *)inner + 0x80a) = -1;
    ObjHits_SyncObjectPositionIfDirty(obj);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_8029F9D4(int p1, int state)
{
    if (GameBit_Get(0x2d0)) {
        *(int *)((char *)state + 0x308) = (int)fn_802A514C;
        return -1;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80297748(int p1, int obj)
{
    if (*(s8 *)((char *)obj + 0x27a) != 0) {
        *(u8 *)((char *)obj + 0x357) = 0;
    }
    *(u8 *)((char *)obj + 0x357) += 1;
    if (*(s8 *)((char *)obj + 0x346) != 0 && *(s8 *)((char *)obj + 0x357) > 0x1e) {
        *(int *)((char *)obj + 0x308) = (int)fn_802A514C;
        return 2;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_8029852C(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);
    u8 v;
    ((ByteFlags *)((char *)inner + 0x3f6))->b20 = 1;
    v = *(u8 *)((char *)state + 0x34b);
    if (v == 3) {
        *(int *)((char *)state + 0x308) = (int)fn_8029782C;
        return 0x3c;
    }
    if (v == 4) {
        *(int *)((char *)state + 0x308) = (int)fn_8029782C;
        return 0x3e;
    }
    if (v == 1) {
        *(int *)((char *)state + 0x308) = (int)fn_8029782C;
        return 0x3b;
    }
    *(int *)((char *)state + 0x308) = (int)fn_8029782C;
    return 0x39;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802A2E8C(int obj, int p2)
{
    int inner = *(int *)((char *)obj + 0xb8);
    f32 fz;
    *(int *)((char *)inner + 0x360) &= ~2;
    *(int *)((char *)inner + 0x360) |= 0x2000;
    *(int *)((char *)p2 + 4) |= 0x100000;
    fz = lbl_803E7EA4;
    *(f32 *)((char *)p2 + 0x280) = fz;
    *(f32 *)((char *)p2 + 0x284) = fz;
    *(int *)((char *)p2 + 0) |= 0x200000;
    *(f32 *)((char *)obj + 0x24) = fz;
    *(f32 *)((char *)obj + 0x2c) = fz;
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802A3F24(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);
    f32 fz;
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        *(s16 *)((char *)state + 0x278) = 9;
        *(int *)((char *)inner + 0x898) = 0;
    }
    *(int *)((char *)inner + 0x360) &= ~2;
    *(int *)((char *)inner + 0x360) |= 0x2000;
    *(int *)((char *)state + 4) |= 0x100000;
    fz = lbl_803E7EA4;
    *(f32 *)((char *)state + 0x280) = fz;
    *(f32 *)((char *)state + 0x284) = fz;
    *(int *)((char *)state + 0) |= 0x200000;
    *(f32 *)((char *)obj + 0x24) = fz;
    *(f32 *)((char *)obj + 0x2c) = fz;
    *(int *)((char *)state + 4) |= 0x8000000;
    *(f32 *)((char *)obj + 0x28) = fz;
    if (*(s16 *)((char *)obj + 0xa0) == 0x419) {
        if (*(s8 *)((char *)state + 0x346) != 0) {
            ObjAnim_SetCurrentMove(obj, lbl_80332EF0[6], fz, 0);
            lbl_803DC6A0 = 6;
            *(f32 *)((char *)state + 0x2a0) = lbl_803E8038;
            fn_802AB5A4(obj, inner + 4, 5);
            *(int *)((char *)state + 0x308) = 0;
            return 0xd;
        }
    } else {
        f32 k;
        ObjAnim_SetCurrentMove(obj, 0x419, fz, 1);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7E90;
        *(s16 *)((char *)inner + 0x478) =
            (s16)getAngle(*(f32 *)((char *)inner + 0x5c4), *(f32 *)((char *)inner + 0x5cc));
        *(s16 *)((char *)inner + 0x484) = *(s16 *)((char *)inner + 0x478);
        k = lbl_803E7F10;
        *(f32 *)((char *)obj + 0x18) =
            k * *(f32 *)((char *)inner + 0x5c4) + *(f32 *)((char *)inner + 0x5d4);
        *(f32 *)((char *)obj + 0x1c) =
            *(f32 *)((char *)inner + 0x5ac) - *(f32 *)((char *)inner + 0x874);
        *(f32 *)((char *)obj + 0x20) =
            k * *(f32 *)((char *)inner + 0x5cc) + *(f32 *)((char *)inner + 0x5dc);
        Obj_TransformWorldPointToLocal(
            (f32 *)((char *)obj + 0xc), (f32 *)((char *)obj + 0x10), (f32 *)((char *)obj + 0x14),
            *(int *)((char *)obj + 0x30),
            *(f32 *)((char *)obj + 0x18), *(f32 *)((char *)obj + 0x1c), *(f32 *)((char *)obj + 0x20));
        objHitDetectFn_80062e84(obj, *(int *)((char *)inner + 0x4c4), 1);
        if (*(void **)((char *)inner + 0x4c4) != NULL) {
            Obj_TransformWorldPointToLocal(
                (f32 *)((char *)inner + 0x5d4), (f32 *)((char *)inner + 0x5d8), (f32 *)((char *)inner + 0x5dc),
                *(int *)((char *)inner + 0x4c4),
                *(f32 *)((char *)inner + 0x5d4), *(f32 *)((char *)inner + 0x5d8), *(f32 *)((char *)inner + 0x5dc));
            Obj_TransformWorldPointToLocal(
                (f32 *)((char *)inner + 0x5ec), (f32 *)((char *)inner + 0x5f0), (f32 *)((char *)inner + 0x5f4),
                *(int *)((char *)inner + 0x4c4),
                *(f32 *)((char *)inner + 0x5ec), *(f32 *)((char *)inner + 0x5f0), *(f32 *)((char *)inner + 0x5f4));
            Obj_TransformWorldPointToLocal(
                (f32 *)((char *)inner + 0x5f8), (f32 *)((char *)inner + 0x5fc), (f32 *)((char *)inner + 0x600),
                *(int *)((char *)inner + 0x4c4),
                *(f32 *)((char *)inner + 0x5f8), *(f32 *)((char *)inner + 0x5fc), *(f32 *)((char *)inner + 0x600));
            *(f32 *)((char *)inner + 0x5ac) =
                *(f32 *)((char *)inner + 0x5ac) - *(f32 *)((char *)*(int *)((char *)inner + 0x4c4) + 0x10);
            *(f32 *)((char *)inner + 0x5b0) =
                *(f32 *)((char *)inner + 0x5b0) - *(f32 *)((char *)*(int *)((char *)inner + 0x4c4) + 0x10);
            *(u8 *)((char *)inner + 0x609) = 0;
        }
    }
    fn_802AB5A4(obj, inner + 4, 5);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802A36EC(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);
    f32 fz;
    *(int *)((char *)inner + 0x360) &= ~2;
    *(int *)((char *)inner + 0x360) |= 0x2000;
    *(int *)((char *)state + 4) |= 0x100000;
    fz = lbl_803E7EA4;
    *(f32 *)((char *)state + 0x280) = fz;
    *(f32 *)((char *)state + 0x284) = fz;
    *(int *)((char *)state + 0) |= 0x200000;
    *(f32 *)((char *)obj + 0x24) = fz;
    *(f32 *)((char *)obj + 0x2c) = fz;
    *(int *)((char *)state + 4) |= 0x8000000;
    *(f32 *)((char *)obj + 0x28) = fz;
    *(int *)((char *)state + 0) |= 0x200000;
    switch (lbl_803DC6A0) {
    case 0x12:
    case 0x1a:
        if (*(int *)((char *)state + 0x314) & 1) {
            Sfx_PlayFromObject(
                obj, (u16)(*(s16 *)((char *)inner + 0x81a) != 0 ? 0x1d : 0x398));
        }
        if ((((u32)*(u8 *)((char *)inner + 0x3f0) >> 5) & 1) || lbl_803DC6A0 == 0x1a) {
            if (*(int *)((char *)state + 0x314) & 0x80) {
                Sfx_PlayFromObject(obj, SFXen_littletink22);
            }
        }
    case 0xe:
    case 0x16:
        if (*(s8 *)((char *)state + 0x346) != 0) {
            *(int *)((char *)state + 4) &= ~0x100000;
            fn_802AB5A4(obj, inner, 5);
            *(int *)((char *)inner + 0x360) |= 0x800000;
            *(int *)((char *)state + 0x308) = (int)fn_802A514C;
            return 2;
        }
        break;
    default: {
        f32 lo;
        f32 hi;
        f32 t;
        f32 r;
        if (*(u8 *)((char *)inner + 0x606) == 0x10) {
            lbl_803DC6A0 = 0x1a;
            lo = lbl_803E8040;
            hi = lbl_803E8044;
            *(f32 *)((char *)state + 0x2a0) = lbl_803E7F28;
        } else if (*(f32 *)((char *)inner + 0x5a8) >= lbl_803E8040) {
            lbl_803DC6A0 = 0xe;
            lo = lbl_803E8040;
            hi = lbl_803E7F30;
            *(f32 *)((char *)state + 0x2a0) = lbl_803E7F0C;
        } else if (*(f32 *)((char *)inner + 0x5a8) >= lbl_803E8048) {
            lbl_803DC6A0 = 0x16;
            lo = lbl_803E8048;
            hi = lbl_803E8040;
            *(f32 *)((char *)state + 0x2a0) = lbl_803E804C;
        } else {
            lbl_803DC6A0 = 0x12;
            lo = lbl_803E8018;
            hi = lbl_803E8048;
            *(f32 *)((char *)state + 0x2a0) = lbl_803E804C;
        }
        t = (*(f32 *)((char *)inner + 0x5a8) - lo) / (hi - lo) * lbl_803E7FAC;
        r = lbl_803E7EA4;
        if (t >= lbl_803E7EA4) {
            if (t <= lbl_803E7FAC) {
                r = t;
            } else {
                r = lbl_803E7FAC;
            }
        }
        *(s16 *)((char *)inner + 0x604) = (s16)r;
        ObjAnim_SetCurrentMove(obj, lbl_80332EF0[lbl_803DC6A0], lbl_803E7EA4, 0);
        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent *)obj, 0xa);
        *(s16 *)((char *)inner + 0x484) =
            (s16)getAngle(*(f32 *)((char *)inner + 0x5c4), *(f32 *)((char *)inner + 0x5cc));
        *(s16 *)((char *)inner + 0x478) = *(s16 *)((char *)inner + 0x484);
        Obj_TransformWorldPointToLocal(
            (f32 *)((char *)obj + 0xc), (f32 *)((char *)obj + 0x10), (f32 *)((char *)obj + 0x14),
            *(int *)((char *)obj + 0x30),
            *(f32 *)((char *)obj + 0x18), *(f32 *)((char *)obj + 0x1c), *(f32 *)((char *)obj + 0x20));
        objHitDetectFn_80062e84(obj, *(int *)((char *)inner + 0x4c4), 1);
        *(f32 *)((char *)inner + 0x5b4) = *(f32 *)((char *)obj + 0xc);
        *(f32 *)((char *)inner + 0x5b8) = *(f32 *)((char *)obj + 0x10);
        *(f32 *)((char *)inner + 0x5bc) = *(f32 *)((char *)obj + 0x14);
        if (*(void **)((char *)inner + 0x4c4) != NULL) {
            Obj_TransformWorldPointToLocal(
                (f32 *)((char *)inner + 0x5d4), (f32 *)((char *)inner + 0x5d8), (f32 *)((char *)inner + 0x5dc),
                *(int *)((char *)inner + 0x4c4),
                *(f32 *)((char *)inner + 0x5d4), *(f32 *)((char *)inner + 0x5d8), *(f32 *)((char *)inner + 0x5dc));
            Obj_TransformWorldPointToLocal(
                (f32 *)((char *)inner + 0x5ec), (f32 *)((char *)inner + 0x5f0), (f32 *)((char *)inner + 0x5f4),
                *(int *)((char *)inner + 0x4c4),
                *(f32 *)((char *)inner + 0x5ec), *(f32 *)((char *)inner + 0x5f0), *(f32 *)((char *)inner + 0x5f4));
            Obj_TransformWorldPointToLocal(
                (f32 *)((char *)inner + 0x5f8), (f32 *)((char *)inner + 0x5fc), (f32 *)((char *)inner + 0x600),
                *(int *)((char *)inner + 0x4c4),
                *(f32 *)((char *)inner + 0x5f8), *(f32 *)((char *)inner + 0x5fc), *(f32 *)((char *)inner + 0x600));
            *(f32 *)((char *)inner + 0x5ac) =
                *(f32 *)((char *)inner + 0x5ac) - *(f32 *)((char *)*(int *)((char *)inner + 0x4c4) + 0x10);
            *(f32 *)((char *)inner + 0x5b0) =
                *(f32 *)((char *)inner + 0x5b0) - *(f32 *)((char *)*(int *)((char *)inner + 0x4c4) + 0x10);
            *(u8 *)((char *)inner + 0x609) = 0;
        }
        break;
    }
    }
    *(f32 *)((char *)obj + 0xc) = *(f32 *)((char *)obj + 0x98) *
            (*(f32 *)((char *)inner + 0x5ec) - *(f32 *)((char *)inner + 0x5b4)) +
        *(f32 *)((char *)inner + 0x5b4);
    *(f32 *)((char *)obj + 0x10) = *(f32 *)((char *)obj + 0x98) *
            (*(f32 *)((char *)inner + 0x5f0) - *(f32 *)((char *)inner + 0x5b8)) +
        *(f32 *)((char *)inner + 0x5b8);
    *(f32 *)((char *)obj + 0x14) = *(f32 *)((char *)obj + 0x98) *
            (*(f32 *)((char *)inner + 0x5f4) - *(f32 *)((char *)inner + 0x5bc)) +
        *(f32 *)((char *)inner + 0x5bc);
    Object_ObjAnimSetSecondaryBlendMove(
        (ObjAnimComponent *)obj, lbl_80332EF0[lbl_803DC6A0 + 2], *(s16 *)((char *)inner + 0x604));
    fn_802AB5A4(obj, inner, 5);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802A3B04(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);
    f32 fz;
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        void *sub;
        Sfx_PlayFromObject(obj, (u16)(*(s16 *)((char *)inner + 0x81a) != 0 ? 0x29 : 0x2cb));
        *(s16 *)((char *)state + 0x278) = 0xa;
        *(int *)((char *)inner + 0x898) = 0;
        *(u8 *)((char *)inner + 0x800) = 0;
        sub = *(void **)((char *)inner + 0x7f8);
        if (sub != NULL) {
            s16 id = *(s16 *)((char *)sub + 0x46);
            if (id == 0x3cf || id == 0x662) {
                objThrowFn_80182504((int)sub);
            } else {
                objSaveFn_800ea774((int)sub);
            }
            *(s16 *)((char *)*(int *)((char *)inner + 0x7f8) + 0x6) &= ~0x4000;
            *(int *)((char *)*(int *)((char *)inner + 0x7f8) + 0xf8) = 0;
            *(int *)((char *)inner + 0x7f8) = 0;
        }
    }
    fz = lbl_803E7EA4;
    *(f32 *)((char *)inner + 0x778) = fz;
    *(int *)((char *)inner + 0x360) &= ~2;
    *(int *)((char *)inner + 0x360) |= 0x2000;
    *(int *)((char *)state + 4) |= 0x100000;
    *(f32 *)((char *)state + 0x280) = fz;
    *(f32 *)((char *)state + 0x284) = fz;
    *(int *)((char *)state + 0) |= 0x200000;
    *(f32 *)((char *)obj + 0x24) = fz;
    *(f32 *)((char *)obj + 0x2c) = fz;
    *(int *)((char *)state + 4) |= 0x8000000;
    *(f32 *)((char *)obj + 0x28) = fz;
    if (*(s16 *)((char *)obj + 0xa0) == 0x22 || *(s16 *)((char *)obj + 0xa0) == 0xd) {
        f32 c;
        f32 d = *(f32 *)((char *)obj + 0x98) / lbl_803E7F44;
        c = lbl_803E7EA4;
        if (d >= lbl_803E7EA4) {
            if (d <= lbl_803E7EE0) {
                c = d;
            } else {
                c = lbl_803E7EE0;
            }
        }
        *(f32 *)((char *)obj + 0xc) =
            c * (*(f32 *)((char *)inner + 0x5f8) - *(f32 *)((char *)inner + 0x5b4)) +
            *(f32 *)((char *)inner + 0x5b4);
        *(f32 *)((char *)obj + 0x10) =
            *(f32 *)((char *)inner + 0x5b8) -
            *(f32 *)((char *)obj + 0x98) *
                (*(f32 *)((char *)inner + 0x5b8) -
                 (*(f32 *)((char *)inner + 0x5ac) - *(f32 *)((char *)inner + 0x874)));
        *(f32 *)((char *)obj + 0x14) =
            c * (*(f32 *)((char *)inner + 0x600) - *(f32 *)((char *)inner + 0x5bc)) +
            *(f32 *)((char *)inner + 0x5bc);
        if (*(s8 *)((char *)state + 0x346) != 0) {
            ObjAnim_SetCurrentMove(obj, lbl_80332EF0[6], lbl_803E7EA4, 0);
            *(f32 *)((char *)state + 0x2a0) = lbl_803E8038;
            lbl_803DC6A0 = 6;
            fn_802AB5A4(obj, inner + 4, 5);
            *(int *)((char *)state + 0x308) = 0;
            return 0xd;
        }
    } else {
        int m;
        int d = (u16)getAngle(*(f32 *)((char *)inner + 0x5c4), *(f32 *)((char *)inner + 0x5cc)) -
                *(s16 *)((char *)inner + 0x478);
        if (d > 0x8000) {
            d -= 0xffff;
        }
        if (d < -0x8000) {
            d += 0xffff;
        }
        m = *(u8 *)((char *)inner + 0x607) == 1 ? 0xb : 0xa;
        *(s16 *)((char *)inner + 0x478) = *(s16 *)((char *)inner + 0x478) + d;
        *(s16 *)((char *)inner + 0x484) = *(s16 *)((char *)inner + 0x478);
        Obj_TransformWorldPointToLocal(
            (f32 *)((char *)obj + 0xc), (f32 *)((char *)obj + 0x10), (f32 *)((char *)obj + 0x14),
            *(int *)((char *)obj + 0x30),
            *(f32 *)((char *)obj + 0x18), *(f32 *)((char *)obj + 0x1c), *(f32 *)((char *)obj + 0x20));
        objHitDetectFn_80062e84(obj, *(int *)((char *)inner + 0x4c4), 1);
        *(f32 *)((char *)inner + 0x5b4) = *(f32 *)((char *)obj + 0xc);
        *(f32 *)((char *)inner + 0x5b8) = *(f32 *)((char *)obj + 0x10);
        *(f32 *)((char *)inner + 0x5bc) = *(f32 *)((char *)obj + 0x14);
        ObjAnim_SetCurrentMove(obj, lbl_80332EF0[m], lbl_803E7EA4, 4);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7F34;
        if (*(u8 *)((char *)inner + 0x8c8) != 0x48 && *(u8 *)((char *)inner + 0x8c8) != 0x47) {
            struct {
                s16 a;
                u8 b;
                u8 c;
            } shk;
            shk.a = 0;
            shk.b = 0;
            shk.c = 1;
            (*(void (*)(int, int, int, int, void *, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
                0x43, 1, 0, 4, &shk, 0, 0xff);
        }
        if (*(void **)((char *)inner + 0x4c4) != NULL) {
            Obj_TransformWorldPointToLocal(
                (f32 *)((char *)inner + 0x5d4), (f32 *)((char *)inner + 0x5d8), (f32 *)((char *)inner + 0x5dc),
                *(int *)((char *)inner + 0x4c4),
                *(f32 *)((char *)inner + 0x5d4), *(f32 *)((char *)inner + 0x5d8), *(f32 *)((char *)inner + 0x5dc));
            Obj_TransformWorldPointToLocal(
                (f32 *)((char *)inner + 0x5ec), (f32 *)((char *)inner + 0x5f0), (f32 *)((char *)inner + 0x5f4),
                *(int *)((char *)inner + 0x4c4),
                *(f32 *)((char *)inner + 0x5ec), *(f32 *)((char *)inner + 0x5f0), *(f32 *)((char *)inner + 0x5f4));
            Obj_TransformWorldPointToLocal(
                (f32 *)((char *)inner + 0x5f8), (f32 *)((char *)inner + 0x5fc), (f32 *)((char *)inner + 0x600),
                *(int *)((char *)inner + 0x4c4),
                *(f32 *)((char *)inner + 0x5f8), *(f32 *)((char *)inner + 0x5fc), *(f32 *)((char *)inner + 0x600));
            *(f32 *)((char *)inner + 0x5ac) =
                *(f32 *)((char *)inner + 0x5ac) - *(f32 *)((char *)*(int *)((char *)inner + 0x4c4) + 0x10);
            *(f32 *)((char *)inner + 0x5b0) =
                *(f32 *)((char *)inner + 0x5b0) - *(f32 *)((char *)*(int *)((char *)inner + 0x4c4) + 0x10);
            *(u8 *)((char *)inner + 0x609) = 0;
        }
    }
    *(u8 *)((char *)inner + 0x8c9) |= 4;
    fn_802AB5A4(obj, inner + 4, 5);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802AA4B0(int obj, int p2, f32 unused)
{
    int spawned = 0;
    int inner = *(int *)((char *)obj + 0xb8);
    int slot;
    int setup;
    f32 vec[3];
    struct {
        s16 angles[4];
        f32 mat[4];
    } v;
    f32 mtx[16];

    slot = Camera_GetCurrentViewSlot();
    if (Obj_IsLoadingLocked()) {
        Sfx_PlayFromObject(obj, SFXmammoth_attacks);
        setup = Obj_AllocObjectSetup(0x24, 0x14b);
        *(u8 *)((char *)setup + 0x4) = 2;
        *(u8 *)((char *)setup + 0x5) = 1;
        *(u8 *)((char *)setup + 0x6) = 0xff;
        *(u8 *)((char *)setup + 0x7) = 0xff;
        if (*(void **)((char *)p2 + 0x2d0) != NULL) {
            ObjPath_GetPointWorldPosition(lbl_803DE44C, 0, (f32 *)((char *)setup + 0x8),
                                          (f32 *)((char *)setup + 0xc), (f32 *)((char *)setup + 0x10), 0);
        } else {
            *(f32 *)((char *)setup + 0x8) = *(f32 *)((char *)slot + 0xc);
            *(f32 *)((char *)setup + 0xc) = *(f32 *)((char *)slot + 0x10);
            *(f32 *)((char *)setup + 0x10) = *(f32 *)((char *)slot + 0x14);
        }
        *(s8 *)((char *)setup + 0x19) = (s8)(*(int (*)(void *))(
            *(int *)((char *)*(int *)(*(int *)((char *)lbl_803DE44C + 0x68)) + 0x44)))(lbl_803DE44C);
        if (*(void **)((char *)p2 + 0x2d0) == NULL) {
            *(s16 *)((char *)setup + 0x1a) = 1;
        }
        setup = Obj_SetupObject(setup, 5, -1, -1, 0);
        if (setup == 0) {
            return;
        }
        *(s16 *)((char *)setup + 0x6) = *(s16 *)((char *)setup + 0x6) | 0x2000;
        if (*(void **)((char *)p2 + 0x2d0) != NULL) {
            int sp = *(int *)((char *)p2 + 0x2d0);
            int pt = *(int *)((char *)sp + 0x74) + *(u8 *)((char *)sp + 0xe4) * 0x18;
            f32 dx = *(f32 *)pt - *(f32 *)((char *)lbl_803DE44C + 0xc);
            f32 dy = *(f32 *)((char *)pt + 4) - *(f32 *)((char *)lbl_803DE44C + 0x10);
            f32 dz = *(f32 *)((char *)pt + 8) - *(f32 *)((char *)lbl_803DE44C + 0x14);
            spawned = sp;
            v.mat[1] = lbl_803E7EA4;
            v.mat[2] = lbl_803E7EA4;
            v.mat[3] = lbl_803E7EA4;
            v.mat[0] = lbl_803E7EE0;
            v.angles[0] = *(s16 *)((char *)inner + 0x478);
            v.angles[1] = (s16)getAngle(dy, sqrtf(dx * dx + dz * dz));
            v.angles[2] = 0;
            if (*(void **)((char *)obj + 0x30) != NULL) {
                v.angles[0] = v.angles[0] + *(s16 *)(*(int *)((char *)obj + 0x30));
            }
            setMatrixFromObjectPos(mtx, v.angles);
            Matrix_TransformPoint(mtx, lbl_803E7EA4, lbl_803E7EA4, lbl_803E80DC,
                                  (f32 *)((char *)setup + 0x24), (f32 *)((char *)setup + 0x28),
                                  (f32 *)((char *)setup + 0x2c));
            *(f32 *)((char *)setup + 0x18) = *(f32 *)((char *)setup + 0xc);
            *(f32 *)((char *)setup + 0x1c) = *(f32 *)((char *)setup + 0x10);
            *(f32 *)((char *)setup + 0x20) = *(f32 *)((char *)setup + 0x14);
            *(s16 *)((char *)setup + 0x0) = *(s16 *)((char *)inner + 0x478);
            *(s16 *)((char *)setup + 0x2) = *(s16 *)((char *)slot + 0x2) / 2;
        } else {
            int res = getScreenResolution();
            int half = res >> 17;
            f32 fov;
            f32 cot;
            f32 fx;
            f32 mag;
            f32 k;
            f32 m;
            *(s16 *)((char *)setup + 0x0) = *(s16 *)((char *)slot + 0x0);
            fov = lbl_803E7F94 * (Camera_GetFovY() * lbl_803E80D4) / lbl_803E7F98;
            cot = lbl_803E7F5C * (fn_80293E80(fov) / sin(fov));
            fx = cot * -((*(f32 *)((char *)inner + 0x788) - (f32)(int)((res & 0xffff) >> 1)) /
                         (f32)(int)((res & 0xffff) >> 1) * Camera_GetAspectRatio());
            cot = cot * ((*(f32 *)((char *)inner + 0x78c) - (f32)half) / (f32)half);
            mag = sqrtf(lbl_803E80AC + (fx * fx + cot * cot));
            vec[0] = fx / mag;
            vec[1] = cot / mag;
            vec[2] = lbl_803E7F5C / mag;
            Matrix_TransformVector(fn_8000E814(), vec, vec);
            m = lbl_803E80DC;
            *(f32 *)((char *)setup + 0x24) = m * vec[0];
            *(f32 *)((char *)setup + 0x28) = m * vec[1];
            *(f32 *)((char *)setup + 0x2c) = m * vec[2];
            k = lbl_803E7ED4;
            *(f32 *)((char *)setup + 0x18) = *(f32 *)((char *)setup + 0xc) =
                k * *(f32 *)((char *)setup + 0x24) + *(f32 *)((char *)slot + 0xc);
            *(f32 *)((char *)setup + 0x1c) = *(f32 *)((char *)setup + 0x10) =
                k * *(f32 *)((char *)setup + 0x28) + *(f32 *)((char *)slot + 0x10);
            *(f32 *)((char *)setup + 0x20) = *(f32 *)((char *)setup + 0x14) =
                k * *(f32 *)((char *)setup + 0x2c) + *(f32 *)((char *)slot + 0x14);
            *(s16 *)((char *)setup + 0x2) = *(s16 *)((char *)slot + 0x2) / 2;
            *(s16 *)((char *)setup + 0x0) = -*(s16 *)((char *)slot + 0x0);
        }
        *(int *)((char *)setup + 0xf4) = 0x5f;
        *(int *)((char *)setup + 0xf8) = spawned;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void playerCalcWaterCurrent(f32 *outX, f32 *outZ, int player)
{
    int inner = *(int *)((char *)player + 0xb8);
    f32 sumC = lbl_803E7EA4;
    f32 sumS = lbl_803E7EA4;
    int any = 0;
    int *objs;
    int n;
    int i;

    objs = (int *)ObjGroup_GetObjects(0x14, &n);
    for (i = 0; i < n; i++) {
        int o = objs[i];
        if (*(u8 *)((char *)*(int *)((char *)o + 0x4c) + 0x1a) & 2) {
            f32 dy;
            any = 1;
            dy = *(f32 *)((char *)o + 0x10) - *(f32 *)((char *)player + 0x10);
            if (dy <= lbl_803E8050 && dy >= lbl_803E80F0) {
                f32 dx = *(f32 *)((char *)o + 0xc) - *(f32 *)((char *)player + 0xc);
                f32 dz = *(f32 *)((char *)o + 0x14) - *(f32 *)((char *)player + 0x14);
                f32 dist = sqrtf(dx * dx + dz * dz);
                f32 thresh =
                    lbl_803E7FC4 * (f32)(u32) * (u8 *)((char *)*(int *)((char *)o + 0x4c) + 0x19);
                if (dist < thresh) {
                    f32 ratio = lbl_803E7EA4;
                    if (thresh > lbl_803E7EA4) {
                        ratio = (thresh - dist) / thresh;
                    }
                    ratio = ratio * (lbl_803E7ED8 * *(f32 *)((char *)o + 0x8));
                    sumC = ratio * fn_80293E80(lbl_803E7F94 * (f32)(int)*(s16 *)((char *)o + 0) /
                                               lbl_803E7F98) +
                           sumC;
                    sumS = ratio * sin(lbl_803E7F94 * (f32)(int)*(s16 *)((char *)o + 0) /
                                       lbl_803E7F98) +
                           sumS;
                }
            }
        }
    }
    objs = (int *)ObjGroup_GetObjects(0x50, &n);
    for (i = 0; i < n; i++) {
        int o = objs[i];
        f32 strength =
            (f32)(u32) * (u8 *)((char *)*(int *)((char *)o + 0x4c) + 0x32) / lbl_803E7ED8;
        f32 dy;
        any = 1;
        dy = *(f32 *)((char *)o + 0x10) - *(f32 *)((char *)player + 0x10);
        if (dy <= lbl_803E8050 && dy >= lbl_803E80F0) {
            f32 dx = *(f32 *)((char *)o + 0xc) - *(f32 *)((char *)player + 0xc);
            f32 dz = *(f32 *)((char *)o + 0x14) - *(f32 *)((char *)player + 0x14);
            int a22 = (s16)(getAngle(dx, dz) + 0x84d0);
            f32 dist = sqrtf(dx * dx + dz * dz);
            f32 thresh = (f32)(int)(*(u8 *)((char *)*(int *)((char *)o + 0x4c) + 0x29) << 3);
            if (dist < thresh) {
                f32 ratio = lbl_803E7EA4;
                f32 angle;
                if (thresh > lbl_803E7EA4) {
                    ratio = (thresh - dist) / thresh;
                }
                ratio = ratio * strength;
                angle = lbl_803E7F94 * (f32)(int)a22 / lbl_803E7F98;
                sumC = ratio * fn_80293E80(angle) + sumC;
                sumS = ratio * sin(angle) + sumS;
            }
        }
    }
    if (any) {
        f32 mag;
        sumC = sumC / (f32)(int)any;
        sumS = sumS / (f32)(int)any;
        *(f32 *)((char *)inner + 0x648) =
            *(f32 *)((char *)inner + 0x648) - lbl_803E7F6C * sumC;
        *(f32 *)((char *)inner + 0x64c) =
            *(f32 *)((char *)inner + 0x64c) - lbl_803E7F6C * sumS;
        *(f32 *)((char *)inner + 0x648) = *(f32 *)((char *)inner + 0x648) * lbl_803E7F68;
        *(f32 *)((char *)inner + 0x64c) = *(f32 *)((char *)inner + 0x64c) * lbl_803E7F68;
        mag = sqrtf(*(f32 *)((char *)inner + 0x648) * *(f32 *)((char *)inner + 0x648) +
                    *(f32 *)((char *)inner + 0x64c) * *(f32 *)((char *)inner + 0x64c));
        if (mag > lbl_803E7F1C) {
            f32 s = lbl_803E7F1C / mag;
            *(f32 *)((char *)inner + 0x648) = *(f32 *)((char *)inner + 0x648) * s;
            *(f32 *)((char *)inner + 0x64c) = *(f32 *)((char *)inner + 0x64c) * s;
        }
        *outX = *(f32 *)((char *)inner + 0x648) * timeDelta;
        *outZ = *(f32 *)((char *)inner + 0x64c) * timeDelta;
    } else {
        *outX = lbl_803E7EA4;
        *outZ = lbl_803E7EA4;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_8029A76C(int obj, int state, f32 fv)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int r;
    struct {
        u8 pad[6];
        u16 mode;
        f32 scale;
        f32 x;
        f32 y;
        f32 z;
    } pfx;
    struct {
        u8 pad[6];
        u16 mode;
        f32 scale;
        f32 x;
        f32 y;
        f32 z;
    } pfx2;

    if (*(void **)((char *)state + 0x2d0) == NULL) {
        f32 z = lbl_803E7EA4;
        *(f32 *)((char *)state + 0x294) = z;
        *(f32 *)((char *)state + 0x284) = z;
        *(f32 *)((char *)state + 0x280) = z;
        *(f32 *)((char *)obj + 0x24) = z;
        *(f32 *)((char *)obj + 0x28) = z;
        *(f32 *)((char *)obj + 0x2c) = z;
    }
    r = ((int (*)(int, int, int))fn_802AC7DC)(obj, state, inner);
    if (r != 0) {
        return r;
    }
    setAButtonIcon(6);
    setBButtonIcon(0xa);
    if (lbl_803DE42C != 0) {
        Sfx_KeepAliveLoopedObjectSound(obj, 0x382);
        *(f32 *)((char *)inner + 0x854) = *(f32 *)((char *)inner + 0x854) - timeDelta;
        if (*(f32 *)((char *)inner + 0x854) <= lbl_803E7EA4) {
            int sub = *(int *)((char *)*(int *)((char *)obj + 0xb8) + 0x35c);
            int v = *(s16 *)((char *)sub + 0x4) - 1;
            if (v < 0) {
                v = 0;
            } else if (v > *(s16 *)((char *)sub + 0x6)) {
                v = *(s16 *)((char *)sub + 0x6);
            }
            *(s16 *)((char *)sub + 0x4) = v;
            *(f32 *)((char *)inner + 0x854) = lbl_803E7F58;
        }
        ObjPath_GetPointWorldPosition(lbl_803DE44C, 5, &pfx.x, &pfx.y, &pfx.z, 0);
        pfx.scale = lbl_803E7F9C;
        pfx.mode = 0;
        (**(void (**)(int, int, void *, int, int, int))((char *)(*gPartfxInterface) + 0x8))(
            (int)lbl_803DE44C, 0x7f5, &pfx, 0x200001, -1, 0);
        pfx.mode = 1;
        (**(void (**)(int, int, void *, int, int, int))((char *)(*gPartfxInterface) + 0x8))(
            (int)lbl_803DE44C, 0x7f5, &pfx, 0x200001, -1, 0);
        if (((u16)*(s16 *)((char *)inner + 0x6e0) & lbl_803DE4B4) == 0 ||
            *(s16 *)((char *)*(int *)((char *)*(int *)((char *)obj + 0xb8) + 0x35c) + 0x4) == 0 ||
            getCurSeqNo() != 0) {
            void **p = lbl_80332ED4;
            int i;
            lbl_803DE42C = 0;
            for (i = 0; i < 7; i++) {
                if (*p != NULL) {
                    Obj_FreeObject((int)*p);
                    *p = NULL;
                }
                p++;
            }
            if (lbl_803DE454 != NULL) {
                Resource_Release(lbl_803DE454);
                lbl_803DE454 = NULL;
            }
        }
    }
    if (*(s16 *)((char *)obj + 0xa0) == 0x43f) {
        if (*(void **)((char *)state + 0x2d0) == NULL) {
            int res;
            int half;
            int low;
            f32 a;
            f32 b;
            *(int *)((char *)inner + 0x360) &= ~0x400;
            a = *(f32 *)((char *)inner + 0x7bc);
            b = *(f32 *)((char *)inner + 0x7b8);
            res = getScreenResolution();
            half = res >> 17;
            low = (res & 0xffff) >> 1;
            *(f32 *)((char *)inner + 0x788) =
                lbl_803E7E98 * (b * (f32)(int)low) + (f32)(int)low;
            if (a < lbl_803E7EA4) {
                *(f32 *)((char *)inner + 0x78c) =
                    lbl_803E7E98 * (a * (f32)(int)half) + (f32)(int)half;
            } else {
                *(f32 *)((char *)inner + 0x78c) =
                    lbl_803E7F44 * (a * (f32)(int)half) + (f32)(int)half;
            }
            *(int *)((char *)inner + 0x360) |= 0x400;
            if (*(s8 *)((char *)state + 0x346) != 0) {
                *(int *)((char *)state + 0x308) = (int)fn_8029A4A8;
                return 0x2d;
            }
        }
    } else {
        int i;
        int sub;
        int v;
        ObjPath_GetPointWorldPosition(lbl_803DE44C, 0, &pfx2.x, &pfx2.y, &pfx2.z, 0);
        for (i = 0; i < 0x28; i++) {
            (**(void (**)(int, int, void *, int, int, int))((char *)(*gPartfxInterface) + 0x8))(
                (int)lbl_803DE44C, 0x3ed, &pfx2, 0x200001, -1, 0);
        }
        sub = *(int *)((char *)*(int *)((char *)obj + 0xb8) + 0x35c);
        v = *(s16 *)((char *)sub + 0x4) - 2;
        if (v < 0) {
            v = 0;
        } else if (v > *(s16 *)((char *)sub + 0x6)) {
            v = *(s16 *)((char *)sub + 0x6);
        }
        *(s16 *)((char *)sub + 0x4) = v;
        fn_802AA4B0(obj, state, *(f32 *)((char *)inner + 0x7bc));
        if (*(void **)((char *)state + 0x2d0) == NULL) {
            *(int *)((char *)state + 0x308) = (int)fn_8029A4A8;
            return 0x2d;
        } else {
            lbl_803DE460 = lbl_803E7EA4;
            lbl_803DE464 = lbl_803E7EA4;
        }
    }
    if (*(void **)((char *)state + 0x2d0) == NULL) {
        if (((u16)*(s16 *)((char *)inner + 0x6e2) & 0x200) != 0 ||
            *(u8 *)((char *)inner + 0x8c8) != 0x52) {
            *(int *)((char *)state + 0x308) = (int)fn_8029A420;
            return 0x2c;
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E7ED4;
extern f32 lbl_803E8064;
extern f32 lbl_803E8068;
extern f32 lbl_803E806C;
extern f32 lbl_803E7F14;
extern f32 lbl_803E7F2C;
extern f32 lbl_803E7EA4;
extern f32 lbl_803E7EE0;
extern f32 lbl_803E7F6C;
extern f32 lbl_803E8070;
extern f32 lbl_803E7F98;
extern f32 lbl_803E7EFC;
extern f32 lbl_803E8074;
extern f32 lbl_803E7FA4;
extern f32 lbl_803E7EAC;
extern f32 lbl_803E8030;
extern f32 lbl_803E7F00;
extern f32 lbl_803E7EA8;
extern f32 lbl_803E7F94;
extern f32 lbl_803E7F90;
extern f32 lbl_803E7F20;
extern f32 lbl_803E7E8C;
extern f32 lbl_803E8078;
extern f32 lbl_803E807C;
extern f32 lbl_803E8080;
extern f32 lbl_803E7F74;
extern f32 lbl_803E7E98;
extern f32 lbl_803E7EE8;
extern f32 lbl_803E7ECC;
extern f32 lbl_803E7FAC;
extern f32 lbl_803E7F78;
extern int fn_802AD2F4(int obj, int inner, int state);

#pragma scheduling off
#pragma peephole off
int fn_802A5384(int obj, int state)
{
    int inner;
    int dir;
    f32 t;
    f32 spd;
    f32 ya;

    inner = *(int *)((char *)obj + 0xb8);
    ((ByteFlags *)((char *)inner + 0x3f1))->b02 = 0;
    ((ByteFlags *)((char *)inner + 0x3f1))->b04 = 0;
    ((ByteFlags *)((char *)inner + 0x3f1))->b08 = 0;
    ((ByteFlags *)((char *)inner + 0x3f2))->b10 = 0;
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        {
            register u32 m;
            register u32 v;
            register int base = inner;
            asm {
                lwz v, 0x360(base)
                lis m, 0x200
                or m, v, m
                stw m, 0x360(base)
            }
        }
        ((ByteFlags *)((char *)inner + 0x3f0))->b80 = 0;
        ((ByteFlags *)((char *)inner + 0x3f0))->b40 = 0;
        ((ByteFlags *)((char *)inner + 0x3f3))->b40 = 0;
        *(u8 *)((char *)inner + 0x8cc) = 0;
        *(s16 *)((char *)inner + 0x81e) = 0;
        ((ByteFlags *)((char *)inner + 0x3f2))->b10 = 1;
    }
    {
        int r = ((int (*)(int, int, int))fn_802AC7DC)(obj, state, inner);
        if (r != 0) {
            return r;
        }
    }
    fn_802AD204(obj, inner);
    {
        u32 fl = *(u8 *)((char *)inner + 0x3f0);
        if ((fl >> 5 & 1) != 0) {
            *(u32 *)state |= 0x200000;
            *(u32 *)((char *)inner + 0x360) |= 0x2000;
            {
            register u32 m;
            register u32 v;
            register int base = inner;
            asm {
                lwz v, 0x360(base)
                lis m, 0x200
                or m, v, m
                stw m, 0x360(base)
            }
        }
            *(s16 *)((char *)state + 0x278) = 2;
            *(int *)((char *)inner + 0x898) = (int)fn_802A514C;
            if (((u32)*(u8 *)((char *)inner + 0x3f1) >> 5 & 1) != 0) {
                *(f32 *)((char *)inner + 0x404) = lbl_803E7F2C;
            } else {
                *(f32 *)((char *)inner + 0x404) = lbl_803E8064;
            }
        } else if (((u32)*(u8 *)((char *)inner + 0x3f1) >> 5 & 1) != 0) {
            {
            register u32 m;
            register u32 v;
            register int base = inner;
            asm {
                lwz v, 0x360(base)
                lis m, 0x200
                or m, v, m
                stw m, 0x360(base)
            }
        }
            *(u32 *)state |= 0x800000;
            *(s16 *)((char *)state + 0x278) = 0;
            *(f32 *)((char *)inner + 0x404) = lbl_803E7ED4;
        } else if ((fl >> 3 & 1) != 0 || (fl >> 2 & 1) != 0) {
            *(u32 *)state |= 0x200000;
            {
            register u32 m;
            register u32 v;
            register int base = inner;
            asm {
                lwz v, 0x360(base)
                lis m, 0x200
                or m, v, m
                stw m, 0x360(base)
            }
        }
            *(f32 *)((char *)inner + 0x404) = lbl_803E8068;
        } else {
            {
            register u32 m;
            register u32 v;
            register int base = inner;
            asm {
                lwz v, 0x360(base)
                lis m, 0x200
                or m, v, m
                stw m, 0x360(base)
            }
        }
            *(u32 *)state |= 0x800000;
            *(s16 *)((char *)state + 0x278) = 0;
            *(f32 *)((char *)inner + 0x404) = lbl_803E806C;
        }
    }
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        if (((u32)*(u8 *)((char *)inner + 0x3f1) >> 5 & 1) == 0 &&
            ((u32)*(u8 *)((char *)inner + 0x3f0) >> 2 & 1) == 0) {
            *(s16 *)((char *)inner + 0x484) =
                *(s16 *)((char *)inner + 0x484) + *(int *)((char *)inner + 0x48c) * 0xb6;
        }
        *(int *)((char *)inner + 0x488) = 0;
        *(int *)((char *)inner + 0x48c) = 0;
    }
    {
        f32 v = (*(f32 *)((char *)state + 0x298) - lbl_803E7F14) / lbl_803E7F2C;
        t = lbl_803E7EA4;
        if (v < t) {
        } else {
            t = lbl_803E7EE0;
            if (v > t) {
            } else {
                t = v;
            }
        }
    }
    *(f32 *)((char *)inner + 0x408) =
        (*(f32 *)((char *)inner + 0x404) - lbl_803E7F6C) *
        (t * *(f32 *)((char *)inner + 0x840));
    {
        u32 fl = *(u8 *)((char *)inner + 0x3f0);
        if ((fl >> 6 & 1) != 0) {
            {
            register u32 m;
            register u32 v;
            register int base = inner;
            asm {
                lwz v, 0x360(base)
                lis m, 0x100
                or m, v, m
                stw m, 0x360(base)
            }
        }
            *(f32 *)((char *)state + 0x2a0) = lbl_803E8070;
            {
                int cd = (int)(lbl_803E7F98 * *(f32 *)((char *)obj + 0x98) +
                               (f32)*(int *)((char *)inner + 0x858));
                *(s16 *)((char *)inner + 0x478) = cd;
                *(int *)((char *)inner + 0x494) = (s16)cd;
            }
            if (*(s8 *)((char *)state + 0x346) != 0) {
                ((ByteFlags *)((char *)inner + 0x3f0))->b40 = 0;
                {
                    int a = *(s16 *)((char *)inner + 0x484);
                    *(s16 *)((char *)inner + 0x478) = a;
                    *(int *)((char *)inner + 0x494) = a;
                }
                *(u8 *)((char *)inner + 0x8cc) = 0xc;
                ((ByteFlags *)((char *)inner + 0x3f1))->b04 = 1;
                ((ByteFlags *)((char *)inner + 0x3f1))->b08 = 1;
            }
            *(f32 *)((char *)state + 0x294) =
                *(f32 *)((char *)inner + 0x844) * timeDelta + *(f32 *)((char *)state + 0x294);
            *(f32 *)((char *)inner + 0x408) = lbl_803E7EA4;
            if (*(f32 *)((char *)obj + 0x98) > lbl_803E7EFC &&
                *(f32 *)((char *)obj + 0x98) < lbl_803E8074) {
                *(u16 *)((char *)inner + 0x8d8) |= 8;
            }
        } else if ((fl >> 4 & 1) != 0) {
            fn_802AE650(obj, inner, state);
        } else if ((fl >> 7 & 1) != 0) {
            int r = fn_802AE480(obj, inner, state);
            if (r != 0) {
                *(int *)((char *)state + 0x308) = (int)fn_802A514C;
                return 2;
            }
        } else if ((fl >> 1 & 1) != 0) {
            int leave;
            *(u32 *)((char *)inner + 0x360) |= 0x800;
            {
                f32 z = lbl_803E7EA4;
                *(f32 *)((char *)state + 0x294) = z;
                *(f32 *)((char *)state + 0x294) = z;
                *(f32 *)((char *)state + 0x284) = z;
                *(f32 *)((char *)state + 0x280) = z;
                *(f32 *)((char *)obj + 0x24) = z;
                *(f32 *)((char *)obj + 0x28) = z;
                *(f32 *)((char *)obj + 0x2c) = z;
                {
                    f32 w = lbl_803E7FA4;
                    *(f32 *)((char *)inner + 0x428) = w;
                    *(f32 *)((char *)inner + 0x42c) = z;
                    *(f32 *)((char *)inner + 0x430) = w;
                    *(f32 *)((char *)inner + 0x434) = z;
                    *(f32 *)((char *)inner + 0x408) = z;
                }
            }
            if ((getButtons_80014dd8(0) & 0x20) == 0) {
                goto sit;
            }
            {
                u32 fl2;
                int stay;
                if (((u32)*(u8 *)((char *)inner + 0x3f4) >> 6 & 1) != 0 &&
                    ((fl2 = *(u8 *)((char *)inner + 0x3f0)) >> 5 & 1) == 0 &&
                    (fl2 >> 3 & 1) == 0 && (fl2 >> 2 & 1) == 0 &&
                    *(u8 *)((char *)inner + 0x8c8) != 0x44 &&
                    *(void **)((char *)inner + 0x7f8) == NULL &&
                    *(void **)((char *)inner + 0x2d0) == NULL &&
                    ((u32)*(u8 *)((char *)inner + 0x3f6) >> 6 & 1) == 0 &&
                    *(s16 *)((char *)inner + 0x274) != 0x26 &&
                    (*(u16 *)((char *)obj + 0xb0) & 0x1000) == 0 &&
                    *(f32 *)((char *)inner + 0x880) == lbl_803E7EA4) {
                    stay = 1;
                } else {
                    stay = 0;
                }
                if (!stay) {
                sit:
                    if (lbl_803DE44C != 0 &&
                        ((u32)*(u8 *)((char *)inner + 0x3f4) >> 6 & 1) != 0) {
                        *(u8 *)((char *)inner + 0x8b4) = 1;
                        ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 1;
                    }
                    staffFn_80170380(lbl_803DE450, 2);
                    ((ByteFlags *)((char *)inner + 0x3f0))->b02 = 0;
                    {
                        register u32 m;
                        register u32 v;
                        register int base = inner;
                        asm {
                            lwz v, 0x360(base)
                            lis m, 0x80
                            or m, v, m
                            stw m, 0x360(base)
                        }
                    }
                    ObjHits_SyncObjectPositionIfDirty(obj);
                    leave = 1;
                } else {
                    leave = 0;
                }
            }
            if (leave) {
                *(int *)((char *)state + 0x308) = (int)fn_802A514C;
                return 2;
            }
        } else if ((fl >> 5 & 1) != 0) {
            fn_802ADE80(obj, inner, state);
        } else if ((fl >> 3 & 1) != 0) {
            fn_802ADC08(obj, inner, state);
        } else if ((fl >> 2 & 1) != 0) {
            int r = fn_802AD2F4(obj, inner, state);
            if (r != 0) {
                *(int *)((char *)state + 0x308) = (int)fn_802A514C;
                return 2;
            }
        }
    }
    {
        int calm;
        {
            u32 fl = *(u8 *)((char *)inner + 0x3f0);
            if ((fl >> 5 & 1) == 0 && (fl >> 6 & 1) == 0 && (fl >> 4 & 1) == 0 &&
                (fl >> 2 & 1) == 0 && (fl >> 3 & 1) == 0 && (fl >> 1 & 1) == 0 &&
                *(void **)((char *)inner + 0x7f8) == NULL &&
                *(u8 *)((char *)inner + 0x8c8) != 0x44) {
                calm = 1;
            } else {
                calm = 0;
            }
        }
        if (calm && (*(u16 *)((char *)inner + 0x6e2) & 0x400) != 0) {
            fn_802AED2C(obj, inner, state);
        }
    }
    {
        int ok;
        {
            u32 fl = *(u8 *)((char *)inner + 0x3f0);
            if ((fl >> 5 & 1) == 0 && (fl >> 6 & 1) == 0 && (fl >> 7 & 1) == 0 &&
                (fl >> 4 & 1) == 0 && (fl >> 2 & 1) == 0 && (fl >> 3 & 1) == 0 &&
                ((u32)*(u8 *)((char *)inner + 0x3f1) >> 5 & 1) == 0) {
                ok = 1;
            } else {
                ok = 0;
            }
        }
        if (ok &&
            *(f32 *)((char *)state + 0x294) >
                lbl_803E7EAC + *(f32 *)(*(int *)((char *)inner + 0x400) + 0x14) &&
            (*(f32 *)((char *)inner + 0x470) < lbl_803E8030 ||
             *(int *)((char *)inner + 0x488) >= 0x96)) {
            *(u16 *)((char *)inner + 0x8d8) |= 8;
            ((ByteFlags *)((char *)inner + 0x3f0))->b80 = 1;
            *(u8 *)((char *)inner + 0x8a6) = *(u8 *)((char *)inner + 0x8a7);
            {
            register u32 m;
            register u32 v;
            register int base = inner;
            asm {
                lwz v, 0x360(base)
                lis m, 0x100
                or m, v, m
                stw m, 0x360(base)
            }
        }
            *(f32 *)((char *)inner + 0x844) = *(f32 *)((char *)state + 0x280);
            ObjAnim_SetCurrentMove(obj,
                                   *(s16 *)(*(int *)((char *)inner + 0x3f8) + 0x3c),
                                   lbl_803E7EA4, 0);
        }
    }
    {
        u32 fl = *(u8 *)((char *)inner + 0x3f0);
        if ((fl >> 7 & 1) == 0 && (fl >> 6 & 1) == 0 &&
            ((u32)*(u8 *)((char *)inner + 0x3f1) >> 5 & 1) == 0) {
            if (*(int *)((char *)inner + 0x488) < 0x96) {
                f32 d = interpolate((f32)*(int *)((char *)inner + 0x47c),
                                    lbl_803E7EE0 / *(f32 *)((char *)inner + 0x428),
                                    timeDelta);
                {
                    f32 m = timeDelta *
                            (*(f32 *)((char *)inner + 0x42c) * *(f32 *)((char *)inner + 0x420));
                    if (d > m) {
                        d = m;
                    }
                }
                if (*(int *)((char *)inner + 0x480) < 0) {
                    d = -d;
                }
                *(s16 *)((char *)inner + 0x478) =
                    (s16)(lbl_803E7F00 * d + (f32)*(s16 *)((char *)inner + 0x478));
            }
            if (*(int *)((char *)inner + 0x488) < 0x96) {
                f32 d = interpolate((f32)*(int *)((char *)inner + 0x488),
                                    lbl_803E7EE0 / *(f32 *)((char *)inner + 0x430),
                                    timeDelta);
                {
                    f32 m = *(f32 *)((char *)inner + 0x434) * timeDelta;
                    if (d > m) {
                        d = m;
                    }
                }
                if (*(int *)((char *)inner + 0x48c) < 0) {
                    d = -d;
                }
                *(s16 *)((char *)inner + 0x484) =
                    (s16)(lbl_803E7F00 * d + (f32)*(s16 *)((char *)inner + 0x484));
            } else {
                u32 fl3 = *(u8 *)((char *)inner + 0x3f0);
                if ((fl3 >> 3 & 1) == 0 && (fl3 >> 2 & 1) == 0 && (fl3 >> 4 & 1) == 0 &&
                    *(f32 *)((char *)state + 0x294) <=
                        *(f32 *)(*(int *)((char *)inner + 0x400) + 4) &&
                    *(f32 *)((char *)state + 0x280) <=
                        *(f32 *)(*(int *)((char *)inner + 0x400) + 0xc)) {
                    *(s16 *)((char *)inner + 0x484) =
                        *(s16 *)((char *)inner + 0x484) +
                        *(int *)((char *)inner + 0x48c) * 0xb6;
                }
            }
        }
    }
    {
        u32 fl;
        u32 fl1 = *(u8 *)((char *)inner + 0x3f1);
        if ((fl1 >> 5 & 1) != 0) {
            spd = *(f32 *)((char *)inner + 0x404) *
                  (t * -fn_80293E80((lbl_803E7F94 * (f32)*(int *)((char *)inner + 0x474)) /
                                    lbl_803E7F98));
            ya = *(f32 *)((char *)inner + 0x404) *
                 (t * -sin((lbl_803E7F94 * (f32)*(int *)((char *)inner + 0x474)) /
                           lbl_803E7F98));
            t = interpolate(spd - *(f32 *)((char *)inner + 0x4c8),
                            *(f32 *)((char *)inner + 0x438), timeDelta);
            {
                f32 dy = interpolate(ya - *(f32 *)((char *)inner + 0x4cc),
                                     *(f32 *)((char *)inner + 0x438), timeDelta);
                *(f32 *)((char *)inner + 0x4c8) = *(f32 *)((char *)inner + 0x4c8) + t;
                *(f32 *)((char *)inner + 0x4cc) = *(f32 *)((char *)inner + 0x4cc) + dy;
            }
            *(f32 *)((char *)state + 0x294) =
                sqrtf(*(f32 *)((char *)inner + 0x4c8) * *(f32 *)((char *)inner + 0x4c8) +
                      *(f32 *)((char *)inner + 0x4cc) * *(f32 *)((char *)inner + 0x4cc));
            {
                f32 v = *(f32 *)((char *)state + 0x294);
                f32 m = **(f32 **)((char *)inner + 0x400);
                if (v < m) {
                } else {
                    m = *(f32 *)((char *)inner + 0x404);
                    if (v > m) {
                    } else {
                        m = v;
                    }
                }
                *(f32 *)((char *)state + 0x294) = m;
            }
            t = fn_80293E80((lbl_803E7F94 * (f32)*(s16 *)((char *)inner + 0x478)) /
                            lbl_803E7F98);
            {
                f32 sn = sin((lbl_803E7F94 * (f32)*(s16 *)((char *)inner + 0x478)) /
                             lbl_803E7F98);
                f32 nx = -*(f32 *)((char *)inner + 0x4cc) * sn -
                         *(f32 *)((char *)inner + 0x4c8) * t;
                ya = *(f32 *)((char *)inner + 0x4c8) * sn -
                     *(f32 *)((char *)inner + 0x4cc) * t;
                *(f32 *)((char *)state + 0x280) =
                    *(f32 *)((char *)state + 0x280) +
                    interpolate(nx - *(f32 *)((char *)state + 0x280),
                                *(f32 *)((char *)inner + 0x82c), timeDelta);
                *(f32 *)((char *)state + 0x284) =
                    *(f32 *)((char *)state + 0x284) +
                    interpolate(ya - *(f32 *)((char *)state + 0x284),
                                *(f32 *)((char *)inner + 0x82c), timeDelta);
            }
            spd = *(f32 *)((char *)state + 0x284);
            if (spd < lbl_803E7EA4) {
                spd = -spd;
            }
            t = *(f32 *)((char *)state + 0x280);
            if (t < lbl_803E7EA4) {
                t = -t;
            }
            {
                int r = ObjAnim_SampleRootCurvePhase(*(f32 *)((char *)state + 0x294),
                                                     (ObjAnimComponent *)obj,
                                                     (f32 *)(state + 0x2a0));
                if (r == 0) {
                    *(f32 *)((char *)state + 0x2a0) = lbl_803E7F78;
                }
            }
            if (((u32)*(u8 *)((char *)inner + 0x3f0) >> 5 & 1) != 0) {
                *(f32 *)((char *)state + 0x2a0) =
                    *(f32 *)((char *)state + 0x2a0) * lbl_803E7E98;
            }
            if (t > spd) {
                if (*(f32 *)((char *)state + 0x280) < lbl_803E7EA4) {
                    dir = 1;
                } else {
                    dir = 0;
                }
            } else if (*(f32 *)((char *)state + 0x284) >= lbl_803E7EA4) {
                dir = 3;
            } else {
                dir = 2;
            }
        } else {
            fl = *(u8 *)((char *)inner + 0x3f0);
            if ((fl >> 6 & 1) == 0 && (fl1 >> 2 & 1) == 0 && (fl >> 4 & 1) == 0 &&
                (fl1 >> 1 & 1) == 0 && (fl >> 3 & 1) == 0 && (fl >> 2 & 1) == 0 &&
                (fl >> 1 & 1) == 0) {
                f32 d = interpolate(*(f32 *)((char *)inner + 0x408) -
                                        *(f32 *)((char *)state + 0x294),
                                    *(f32 *)((char *)inner + 0x438), timeDelta);
                f32 m = lbl_803E7EA8 * timeDelta;
                if (d < m) {
                } else {
                    m = lbl_803E7EFC * timeDelta;
                    if (d > m) {
                    } else {
                        m = d;
                    }
                }
                if (*(int *)((char *)inner + 0x488) >= 0x96 && m > lbl_803E7EA4) {
                    m = lbl_803E7ED4 * -m;
                }
                *(f32 *)((char *)state + 0x294) = *(f32 *)((char *)state + 0x294) + m;
                {
                    f32 v = *(f32 *)((char *)state + 0x294);
                    f32 c = **(f32 **)((char *)inner + 0x400);
                    if (v < c) {
                    } else {
                        c = *(f32 *)((char *)inner + 0x404);
                        if (v > c) {
                        } else {
                            c = v;
                        }
                    }
                    *(f32 *)((char *)state + 0x294) = c;
                }
                *(f32 *)((char *)state + 0x284) = lbl_803E7EA4;
            } else if (((u32)*(u8 *)((char *)inner + 0x3f0) >> 3 & 1) != 0 ||
                       ((u32)*(u8 *)((char *)inner + 0x3f0) >> 2 & 1) != 0) {
                t = *(f32 *)((char *)inner + 0x408) *
                    -fn_80293E80((lbl_803E7F94 *
                                  (lbl_803E7F00 * (f32)*(int *)((char *)inner + 0x48c))) /
                                 lbl_803E7F98);
                ya = *(f32 *)((char *)inner + 0x408) *
                     sin((lbl_803E7F94 *
                          (lbl_803E7F00 * (f32)*(int *)((char *)inner + 0x48c))) /
                         lbl_803E7F98);
                if (((u32)*(u8 *)((char *)inner + 0x3f0) >> 2 & 1) != 0) {
                    *(f32 *)((char *)state + 0x294) =
                        *(f32 *)((char *)state + 0x294) *
                        powfBitEstimate(lbl_803E7F90, timeDelta);
                } else {
                    *(f32 *)((char *)state + 0x294) =
                        -(lbl_803E7F20 * timeDelta - *(f32 *)((char *)state + 0x294));
                }
                {
                    f32 v2 = lbl_803E7E8C * ya;
                    f32 m = lbl_803E8078;
                    if (v2 < m) {
                    } else {
                        m = lbl_803E807C;
                        if (v2 > m) {
                        } else {
                            m = v2;
                        }
                    }
                    *(f32 *)((char *)state + 0x294) =
                        m * timeDelta + *(f32 *)((char *)state + 0x294);
                }
                {
                    f32 v = *(f32 *)((char *)state + 0x294);
                    f32 m = lbl_803E8080;
                    if (v < m) {
                    } else {
                        m = lbl_803E7EFC + *(f32 *)((char *)inner + 0x404);
                        if (v > m) {
                        } else {
                            m = v;
                        }
                    }
                    *(f32 *)((char *)state + 0x294) = m;
                }
                t = t * lbl_803E7F74;
                *(f32 *)((char *)state + 0x284) =
                    *(f32 *)((char *)state + 0x284) +
                    interpolate(t - *(f32 *)((char *)state + 0x284), lbl_803E807C,
                                timeDelta);
            } else {
                f32 v = *(f32 *)((char *)state + 0x294);
                f32 lim = *(f32 *)((char *)inner + 0x404);
                f32 m = -lim;
                if (v < m) {
                } else {
                    if (v > lim) {
                        m = lim;
                    } else {
                        m = v;
                    }
                }
                *(f32 *)((char *)state + 0x294) = m;
            }
            {
                if (((u32)*(u8 *)((char *)inner + 0x3f0) >> 4 & 1) == 0 &&
                    ((u32)*(u8 *)((char *)inner + 0x3f1) >> 1 & 1) == 0 &&
                    ((u32)*(u8 *)((char *)inner + 0x3f0) >> 1 & 1) == 0) {
                    *(f32 *)((char *)state + 0x280) =
                        *(f32 *)((char *)state + 0x280) +
                        interpolate(*(f32 *)((char *)state + 0x294) -
                                        *(f32 *)((char *)state + 0x280),
                                    *(f32 *)((char *)inner + 0x82c), timeDelta);
                }
            }
            dir = 0;
        }
    }
    {
        u32 fl = *(u8 *)((char *)inner + 0x3f0);
        if ((fl >> 7 & 1) == 0 && (fl >> 6 & 1) == 0 && (fl >> 4 & 1) == 0 &&
            (fl >> 2 & 1) == 0 && (fl >> 3 & 1) == 0 && (fl >> 1 & 1) == 0) {
            int locked;
            int step;
            locked = 0;
            if (((u32)*(u8 *)((char *)inner + 0x3f1) >> 3 & 1) != 0) {
                locked = 1;
                spd = lbl_803E7EA4;
            } else {
                spd = *(f32 *)((char *)obj + 0x98);
            }
            step = *(s8 *)((char *)inner + 0x8cc) / 4 * 2;
            *(u8 *)((char *)inner + 0x8b0) = (step >> 1) + 1;
            if (*(u8 *)((char *)inner + 0x8b0) > 4) {
                *(u8 *)((char *)inner + 0x8b0) = 4;
            }
            {
                u8 c;
                if (*(u8 *)((char *)inner + 0x8b0) > 3) {
                    c = *(u8 *)((char *)inner + 0x8a4);
                } else {
                    c = *(u8 *)((char *)inner + 0x8a3);
                }
                *(u8 *)((char *)inner + 0x8a6) = c;
            }
            {
                f32 v = *(f32 *)((char *)state + 0x294);
                int tb = *(int *)((char *)inner + 0x400);
                if (v < *(f32 *)(tb + step * 4)) {
                    if (*(s8 *)((char *)inner + 0x8cc) == 4) {
                        if (*(f32 *)((char *)state + 0x280) < *(f32 *)(tb + 0x10) &&
                            *(f32 *)((char *)state + 0x298) < lbl_803E7F14) {
                            *(int *)((char *)state + 0x308) = (int)fn_802A514C;
                            return 2;
                        }
                    } else {
                        *(u8 *)((char *)inner + 0x8cc) -= 4;
                    }
                } else if (v >= *(f32 *)(tb + step * 4 + 4)) {
                    int cc = *(s8 *)((char *)inner + 0x8cc);
                    if (cc < 0x14) {
                        if (cc == 0) {
                            spd = lbl_803E7EA4;
                        }
                        if (v < *(f32 *)((char *)inner + 0x404)) {
                            *(u8 *)((char *)inner + 0x8cc) += 4;
                        }
                    }
                }
            }
            if (locked != 0 ||
                *(void **)((char *)inner + 0x3fc) != *(void **)((char *)inner + 0x3f8) ||
                *(s16 *)((char *)obj + 0xa0) !=
                    *(s16 *)(*(int *)((char *)inner + 0x3f8) +
                             (*(s8 *)((char *)inner + 0x8cc) + dir) * 2)) {
                if (ObjAnim_GetCurrentEventCountdown((ObjAnimComponent *)obj) == 0 ||
                    ((u32)*(u8 *)((char *)inner + 0x3f2) >> 4 & 1) != 0) {
                    ObjAnim_SetCurrentMove(obj,
                                           *(s16 *)(*(int *)((char *)inner + 0x3f8) +
                                                    (*(s8 *)((char *)inner + 0x8cc) + dir) * 2),
                                           spd, 0);
                    if (((u32)*(u8 *)((char *)inner + 0x3f1) >> 5 & 1) != 0 &&
                        *(s8 *)((char *)state + 0x27a) == 0) {
                        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent *)obj, 0xc);
                    }
                }
            }
        }
    }
    {
        f32 v = (f32)*(s16 *)((char *)state + 0x19c) / lbl_803E7EE8;
        t = lbl_803E7ECC;
        if (v < t) {
        } else {
            t = lbl_803E7EE0;
            if (v > t) {
            } else {
                t = v;
            }
        }
    }
    {
        f32 ad = t;
        int pos;
        if (t > lbl_803E7EA4) {
            pos = 1;
        } else {
            pos = 0;
        }
        if (t < lbl_803E7EA4) {
            ad = -t;
        }
        if (((u32)*(u8 *)((char *)inner + 0x3f1) >> 5 & 1) == 0) {
            u32 fl = *(u8 *)((char *)inner + 0x3f0);
            if ((fl >> 7 & 1) == 0 && (fl >> 6 & 1) == 0 && (fl >> 4 & 1) == 0 &&
                (fl >> 2 & 1) == 0 && (fl >> 3 & 1) == 0 && (fl >> 1 & 1) == 0) {
                if ((fl >> 5 & 1) == 0) {
                    Object_ObjAnimSetSecondaryBlendMove(
                        (ObjAnimComponent *)obj,
                        *(s16 *)(*(int *)((char *)inner + 0x3f8) +
                                 (*(s8 *)((char *)inner + 0x8cc) + pos) * 2 + 2),
                        (int)(lbl_803E7FAC * ad));
                }
                {
                    int r = ObjAnim_SampleRootCurvePhase(*(f32 *)((char *)state + 0x294),
                                                         (ObjAnimComponent *)obj,
                                                         (f32 *)(state + 0x2a0));
                    if (r == 0) {
                        *(f32 *)((char *)state + 0x2a0) = lbl_803E7F78;
                    }
                }
            }
        }
    }
    fn_802ABAE8(obj, state, inner, t);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

extern s16 lbl_803DC6A2;
extern f32 lbl_803E8020;

#pragma scheduling off
#pragma peephole off
int fn_802A1CA8(int obj, int state)
{
    int jt;
    int inner;
    f32 t;
    f32 spd;
    f32 ph;
    f32 buf1[3];
    f32 buf2[3];
    f32 tmp[2];
    f32 outY;

    inner = *(int *)((char *)obj + 0xb8);
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        ObjHits_MarkObjectPositionDirty();
        if (lbl_803DE44C != 0 &&
            ((u32)*(u8 *)((char *)inner + 0x3f4) >> 6 & 1) != 0) {
            *(u8 *)((char *)inner + 0x8b4) = 1;
            ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 1;
        }
        if (*(s16 *)((char *)obj + 0xa0) == lbl_80332F2C[8] ||
            *(s16 *)((char *)obj + 0xa0) == lbl_80332F2C[12]) {
            lbl_803DC6A0 = 8;
        } else {
            lbl_803DC6A0 = 9;
        }
    }
    if (*(s8 *)((char *)inner + 0x4e4) > 3) {
        setAButtonIcon(0x1a);
    } else {
        setAButtonIcon(0x1c);
    }
    {
        register u32 m;
        register u32 v;
        register int base = *(int *)((char *)obj + 0xb8);
        asm {
            lwz v, 0x360(base)
            li m, -3
            and m, v, m
            stw m, 0x360(base)
        }
        *(u32 *)((char *)base + 0x360) |= 0x2000;
    }
    *(u32 *)((char *)state + 4) |= 0x100000;
    {
        f32 z = lbl_803E7EA4;
        *(f32 *)((char *)state + 0x280) = z;
        *(f32 *)((char *)state + 0x284) = z;
        *(u32 *)state |= 0x200000;
        *(f32 *)((char *)obj + 0x24) = z;
        *(f32 *)((char *)obj + 0x2c) = z;
        *(u32 *)((char *)state + 4) |= 0x8000000;
        if (*(f32 *)((char *)inner + 0x838) > lbl_803E7FA0) {
            fn_802AB5A4(obj, inner, 5);
            ((void (*)(int, int, int))fn_802AE83C)(obj, inner, state);
            *(int *)((char *)state + 0x308) = (int)fn_802A514C;
            return 2;
        }
        *(f32 *)((char *)obj + 0x28) = z;
        {
            f32 mag = *(f32 *)((char *)state + 0x28c) / lbl_803E7FA8;
            if (mag < z) {
                mag = -mag;
            }
            t = lbl_803E7EFC;
            if (mag < t) {
            } else {
                t = lbl_803E7EE0;
                if (mag > t) {
                } else {
                    t = mag;
                }
            }
        }
    }
    jt = *(int *)(*(int *)((char *)obj + 0x7c) + *(s8 *)((char *)obj + 0xad) * 4);
    spd = lbl_803E7EA4;
    ph = *(f32 *)((char *)state + 0x2a0);
    lbl_803DC6A2 = lbl_803DC6A0;
    if ((*(int *)((char *)state + 0x314) & 1) != 0) {
        switch (*(s8 *)((char *)inner + 0x546)) {
        case 4:
            Sfx_PlayFromObject(obj, 0x33a);
            break;
        default:
            Sfx_PlayFromObject(obj, 0x11);
            break;
        }
    }
    switch ((s16)lbl_803DC6A0) {
    case 8:
    case 9:
    case 12:
    case 13:
        *(f32 *)((char *)obj + 0x10) = *(f32 *)((char *)inner + 0x4f4);
        *(s16 *)((char *)obj + 0xa2) = -1;
        *(u8 *)((char *)inner + 0x4e6) = 0;
        *(f32 *)((char *)inner + 0x4f8) = *(f32 *)((char *)inner + 0x4f4);
        spd = lbl_803E7EA4;
        ph = spd;
        if ((lbl_803DC6A0 & 1) != 0) {
            lbl_803DC6A0 = 1;
        } else {
            lbl_803DC6A0 = 0;
        }
        goto finish;
    case 6:
    case 7:
        if ((*(int *)((char *)state + 0x314) & 0x80) != 0) {
            Sfx_PlayFromObject(obj, 0x10);
            if (*(s16 *)((char *)inner + 0x81a) == 0) {
                Sfx_PlayFromObject(obj, 0x398);
            }
        }
        if (*(s8 *)((char *)state + 0x346) != 0) {
            *(f32 *)((char *)obj + 0x10) = *(f32 *)((char *)inner + 0x4e8);
        } else {
            ObjModel_SampleJointTransform(jt, 0, 0, lbl_803E7EA4,
                                          *(f32 *)((char *)obj + 8), buf1, tmp);
            ObjModel_SampleJointTransform(jt, 0, 0, lbl_803E7EE0,
                                          *(f32 *)((char *)obj + 8), buf2, tmp);
            *(f32 *)((char *)obj + 0x10) =
                *(f32 *)((char *)obj + 0x98) *
                    ((lbl_803DE43C - (buf2[1] - buf1[1])) - (lbl_803DE438 + buf1[1])) +
                lbl_803DE438;
        }
        /* fall through */
    case 10:
    case 11:
        if ((*(int *)((char *)state + 0x314) & 0x200) != 0) {
            doRumble(lbl_803E7F10);
            if (*(f32 *)((char *)inner + 0x838) > lbl_803E7EA4) {
                (**(void (**)(int, f32, f32, f32, f32))((char *)(*gWaterfxInterface) + 0x10))(
                    obj, *(f32 *)((char *)obj + 0xc), *(f32 *)((char *)obj + 0x10),
                    *(f32 *)((char *)obj + 0x14), lbl_803E8018);
            }
        }
        if (*(s8 *)((char *)state + 0x346) != 0) {
            *(f32 *)((char *)obj + 0x18) = *(f32 *)((char *)inner + 0x768);
            *(f32 *)((char *)obj + 0x20) = *(f32 *)((char *)inner + 0x770);
            if (*(void **)((char *)obj + 0x30) != NULL) {
                *(f32 *)((char *)obj + 0x18) =
                    *(f32 *)((char *)obj + 0x18) + playerMapOffsetX;
                *(f32 *)((char *)obj + 0x20) =
                    *(f32 *)((char *)obj + 0x20) + playerMapOffsetZ;
            }
            ((void (*)(f32, f32, f32, f32 *, f32 *, f32 *, int))Obj_TransformWorldPointToLocal)(
                *(f32 *)((char *)obj + 0x18), lbl_803E7EA4, *(f32 *)((char *)obj + 0x20),
                (f32 *)((char *)obj + 0xc), &outY, (f32 *)((char *)obj + 0x14),
                *(int *)((char *)obj + 0x30));
            if (lbl_803DC6A0 == 6 || lbl_803DC6A0 == 7) {
                fn_802AB5A4(obj, inner, 7);
            } else {
                fn_802AB5A4(obj, inner, 5);
            }
            ObjAnim_SetCurrentMove(obj, **(s16 **)((char *)inner + 0x3f8),
                                   lbl_803E7EA4, 1);
            {
                register u32 m;
                register u32 v;
                register int base = inner;
                asm {
                    lwz v, 0x360(base)
                    lis m, 0x80
                    or m, v, m
                    stw m, 0x360(base)
                }
            }
            *(int *)((char *)state + 0x308) = (int)fn_802A514C;
            return 2;
        }
        goto finish;
    case 4:
    case 5:
        if (*(f32 *)((char *)state + 0x28c) > lbl_803E7F10) {
            ((void (*)(int, f32))ObjAnim_SetMoveProgress)(obj, lbl_803E7EA4);
        } else if (*(f32 *)((char *)state + 0x28c) < lbl_803E801C) {
            ((void (*)(int, f32))ObjAnim_SetMoveProgress)(obj, lbl_803E7EA4);
        } else {
            if ((*(int *)((char *)state + 0x31c) & 0x100) != 0 &&
                *(s8 *)((char *)inner + 0x4e4) > 3) {
                *(int *)((char *)state + 0x308) = (int)fn_8029FFD0;
                return -0x10;
            }
            goto finish;
        }
        /* fall through */
    default:
        if ((*(int *)((char *)state + 0x314) & 0x80) != 0) {
            Sfx_PlayFromObject(obj, 0x11);
        }
        if ((*(int *)((char *)state + 0x31c) & 0x100) != 0 &&
            *(s8 *)((char *)inner + 0x4e4) > 3) {
            *(int *)((char *)state + 0x308) = (int)fn_8029FFD0;
            return -0x10;
        }
        if (lbl_803E7EE0 == *(f32 *)((char *)obj + 0x98)) {
            if (*(f32 *)((char *)state + 0x28c) < lbl_803E801C) {
                *(u8 *)((char *)inner + 0x4e6) = 0;
                ph = -(lbl_803E7EF8 * t + lbl_803E7F20);
                if ((s16)lbl_803DC6A0 <= 1) {
                    lbl_803DC6A0 += 2;
                    spd = lbl_803E7F68;
                }
            } else {
                *(u8 *)((char *)inner + 0x4e4) += 1;
                *(u8 *)((char *)inner + 0x4e6) = 1;
                ph = lbl_803E7EA4;
                if ((s16)lbl_803DC6A0 <= 1) {
                    lbl_803DC6A0 ^= 1;
                    spd = ph;
                }
                *(f32 *)((char *)inner + 0x4f8) =
                    *(f32 *)((char *)obj + 0x10) + *(f32 *)((char *)inner + 0x500);
                *(f32 *)((char *)inner + 0x4f4) =
                    (f32)*(s8 *)((char *)inner + 0x4e4) * *(f32 *)((char *)inner + 0x4f0) +
                    *(f32 *)((char *)inner + 0x4ec);
                *(f32 *)((char *)obj + 0x10) = *(f32 *)((char *)inner + 0x4f8);
            }
        }
        {
            f32 z2 = lbl_803E7EA4;
            if (z2 == *(f32 *)((char *)obj + 0x98)) {
                if (*(f32 *)((char *)state + 0x28c) > lbl_803E7F10) {
                    *(u8 *)((char *)inner + 0x4e6) = 1;
                    if ((int)*(s8 *)((char *)inner + 0x4e4) >=
                        *(s8 *)((char *)inner + 0x4e5) - 3) {
                        spd = z2;
                        ph = lbl_803E8020;
                        {
                            s16 ns;
                            if ((lbl_803DC6A0 & 1) != 0) {
                                ns = 7;
                            } else {
                                ns = 6;
                            }
                            lbl_803DC6A0 = ns;
                        }
                        lbl_803DE438 = *(f32 *)((char *)obj + 0x10);
                        lbl_803DE43C = *(f32 *)((char *)inner + 0x4e8) + lbl_803DAF88[0];
                        if (*(u8 *)((char *)inner + 0x8c8) != 0x48 &&
                            *(u8 *)((char *)inner + 0x8c8) != 0x47) {
                            (**(void (**)(int, int, int, int, int, int, int))((char *)(*gCameraInterface) + 0x1c))(
                                0x42, 0, 1, 0, 0, 0x1e, 0xff);
                        }
                        goto finish;
                    }
                    spd = z2;
                    ph = lbl_803E7F84 * t + lbl_803E7F20;
                    if ((s16)lbl_803DC6A0 > 1) {
                        if ((lbl_803DC6A0 & 1) != 0) {
                            lbl_803DC6A0 = 1;
                        } else {
                            lbl_803DC6A0 = 0;
                        }
                    }
                } else if (*(f32 *)((char *)state + 0x28c) < lbl_803E801C) {
                    *(u8 *)((char *)inner + 0x4e4) -= 1;
                    *(u8 *)((char *)inner + 0x4e6) = 0;
                    if (*(s8 *)((char *)inner + 0x4e4) < 1) {
                        if (*(u8 *)((char *)inner + 0x8c8) != 0x48 &&
                            *(u8 *)((char *)inner + 0x8c8) != 0x47 &&
                            *(u8 *)((char *)inner + 0x8c8) != 0x42) {
                            (**(void (**)(int, int, int, int, int, int, int))((char *)(*gCameraInterface) + 0x1c))(
                                0x42, 0, 1, 0, 0, 0x1e, 0xff);
                            *(u8 *)((char *)inner + 0x8c8) = 0x42;
                        }
                        if (((u32)*(u8 *)((char *)inner + 0x547) >> 7 & 1) != 0) {
                            spd = lbl_803E7EA4;
                            ph = lbl_803E7FE8;
                            {
                                s16 ns;
                                if ((lbl_803DC6A0 & 1) != 0) {
                                    ns = 0xb;
                                } else {
                                    ns = 0xa;
                                }
                                lbl_803DC6A0 = ns;
                            }
                            *(f32 *)((char *)obj + 0x10) = *(f32 *)((char *)inner + 0x4ec);
                            goto finish;
                        } else {
                            {
                                f32 z3 = lbl_803E7EA4;
                                *(f32 *)((char *)state + 0x294) = z3;
                                *(f32 *)((char *)state + 0x284) = z3;
                                *(f32 *)((char *)state + 0x280) = z3;
                                *(f32 *)((char *)obj + 0x24) = z3;
                                *(f32 *)((char *)obj + 0x28) = z3;
                                *(f32 *)((char *)obj + 0x2c) = z3;
                            }
                            ((ByteFlags *)((char *)inner + 0x3f0))->b80 = 0;
                            ((ByteFlags *)((char *)inner + 0x3f0))->b10 = 0;
                            ((ByteFlags *)((char *)inner + 0x3f0))->b08 = 0;
                            staffFn_80170380(lbl_803DE450, 2);
                            ((ByteFlags *)((char *)inner + 0x3f0))->b02 = 0;
                            {
                                register u32 m;
                                register u32 v;
                                register int base = inner;
                                asm {
                                    lwz v, 0x360(base)
                                    lis m, 0x80
                                    or m, v, m
                                    stw m, 0x360(base)
                                }
                            }
                            ObjHits_SyncObjectPositionIfDirty(obj);
                            ((ByteFlags *)((char *)inner + 0x3f0))->b40 = 0;
                            ((ByteFlags *)((char *)inner + 0x3f0))->b04 = 1;
                            ((ByteFlags *)((char *)inner + 0x3f4))->b10 = 1;
                            *(u8 *)((char *)inner + 0x800) = 0;
                            if (*(void **)((char *)inner + 0x7f8) != NULL) {
                                if (*(s16 *)(*(int *)((char *)inner + 0x7f8) + 0x46) == 0x3cf ||
                                    *(s16 *)(*(int *)((char *)inner + 0x7f8) + 0x46) == 0x662) {
                                    objThrowFn_80182504(*(int *)((char *)inner + 0x7f8));
                                } else {
                                    objSaveFn_800ea774(*(int *)((char *)inner + 0x7f8));
                                }
                                *(s16 *)(*(int *)((char *)inner + 0x7f8) + 6) =
                                    *(s16 *)(*(int *)((char *)inner + 0x7f8) + 6) & ~0x4000;
                                *(int *)(*(int *)((char *)inner + 0x7f8) + 0xf8) = 0;
                                *(int *)((char *)inner + 0x7f8) = 0;
                            }
                            fn_802AB5A4(obj, inner, 5);
                            *(int *)((char *)state + 0x308) = (int)fn_802A514C;
                            return 3;
                        }
                    } else {
                        spd = lbl_803E7F68;
                        ph = -(lbl_803E7EF8 * t + lbl_803E7F20);
                        {
                            s16 ns;
                            if ((lbl_803DC6A0 & 1) != 0) {
                                ns = 2;
                            } else {
                                ns = 3;
                            }
                            lbl_803DC6A0 = ns;
                        }
                        *(f32 *)((char *)inner + 0x4f4) =
                            (f32)*(s8 *)((char *)inner + 0x4e4) * *(f32 *)((char *)inner + 0x4f0) +
                            *(f32 *)((char *)inner + 0x4ec);
                        {
                            f32 y2 = *(f32 *)((char *)obj + 0x10) -
                                     *(f32 *)((char *)inner + 0x500);
                            *(f32 *)((char *)inner + 0x4f8) = y2;
                            *(f32 *)((char *)obj + 0x10) = y2;
                        }
                        goto vel_join;
                    }
                } else {
                    if (((int (*)(ObjAnimComponent *))ObjAnim_GetCurrentEventCountdown)((ObjAnimComponent *)obj) != 0) {
                        goto vel_join;
                    }
                    spd = lbl_803E7EA4;
                    ph = lbl_803E7EF8;
                    if ((lbl_803DC6A0 & 1) != 0 && lbl_803DC6A0 != 5) {
                        lbl_803DC6A0 = 5;
                    } else if ((lbl_803DC6A0 & 1) == 0 && lbl_803DC6A0 != 4) {
                        lbl_803DC6A0 = 4;
                    }
                    goto finish;
                }
            }
        }
    vel_join:
        if (ph < lbl_803E7EA4) {
            ph = -(lbl_803E7EF8 * t + lbl_803E7F20);
        } else if (ph > lbl_803E7EA4) {
            ph = lbl_803E7F84 * t + lbl_803E7F20;
        }
        if (*(s8 *)((char *)inner + 0x4e6) != 0) {
            *(f32 *)((char *)obj + 0x10) =
                *(f32 *)((char *)obj + 0x98) *
                    (*(f32 *)((char *)inner + 0x4f4) - *(f32 *)((char *)inner + 0x4f8)) +
                *(f32 *)((char *)inner + 0x4f8);
        } else {
            *(f32 *)((char *)obj + 0x10) =
                (lbl_803E7EE0 - *(f32 *)((char *)obj + 0x98)) *
                    (*(f32 *)((char *)inner + 0x4f4) - *(f32 *)((char *)inner + 0x4f8)) +
                *(f32 *)((char *)inner + 0x4f8);
        }
        break;
    }
finish:
    *(f32 *)((char *)state + 0x2a0) = ph;
    if (lbl_803DC6A2 != lbl_803DC6A0) {
        ObjAnim_SetCurrentMove(obj, lbl_80332F2C[lbl_803DC6A0], spd, 1);
        if ((s16)lbl_803DC6A0 <= 1 && *(s8 *)((char *)inner + 0x4e7) == 0) {
            ObjModel_SampleJointTransform(jt, 0, 0, lbl_803E7EA4,
                                          *(f32 *)((char *)obj + 8), buf1, tmp);
            ObjModel_SampleJointTransform(jt, 0, 0, lbl_803E7EE0,
                                          *(f32 *)((char *)obj + 8), buf2, tmp);
            *(f32 *)((char *)inner + 0x500) = buf2[1] - buf1[1];
            *(u8 *)((char *)inner + 0x4e7) = 1;
        }
    }
    {
        f32 x = *(f32 *)((char *)obj + 0xc);
        f32 zz = *(f32 *)((char *)obj + 0x14);
        f32 y;
        switch ((s16)lbl_803DC6A0) {
        case 0:
        case 1:
        case 2:
        case 3:
            y = *(f32 *)((char *)obj + 0x98) *
                    (((f32)(*(s8 *)((char *)inner + 0x4e4) + 1) *
                          *(f32 *)((char *)inner + 0x4f0) +
                      *(f32 *)((char *)inner + 0x4ec)) -
                     *(f32 *)((char *)obj + 0x10)) +
                *(f32 *)((char *)obj + 0x10);
            break;
        case 10:
        case 11:
            x = *(f32 *)((char *)obj + 0x98) * (*(f32 *)((char *)inner + 0x768) - x) + x;
            y = (lbl_803E7EE0 - *(f32 *)((char *)obj + 0x98)) *
                    (*(f32 *)((char *)inner + 0x4f4) - *(f32 *)((char *)obj + 0x10)) +
                *(f32 *)((char *)obj + 0x10);
            zz = *(f32 *)((char *)obj + 0x98) * (*(f32 *)((char *)inner + 0x770) - zz) + zz;
            break;
        case 6:
        case 7:
            x = *(f32 *)((char *)obj + 0x98) * (*(f32 *)((char *)inner + 0x768) - x) + x;
            y = *(f32 *)((char *)obj + 0x98) *
                    (*(f32 *)((char *)inner + 0x4e8) - *(f32 *)((char *)obj + 0x10)) +
                *(f32 *)((char *)obj + 0x10);
            zz = *(f32 *)((char *)obj + 0x98) * (*(f32 *)((char *)inner + 0x770) - zz) + zz;
            break;
        default:
            y = *(f32 *)((char *)obj + 0x10);
            break;
        }
        (**(void (**)(f32, f32, f32))((char *)(*gCameraInterface) + 0x2c))(x, y, zz);
    }
    fn_802AB5A4(obj, inner, 5);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

typedef struct {
    u8 pad0[0xc];
    f32 fz0;
    f32 fz1;
    u8 pad1[8];
    f32 nx;
    f32 ny;
    f32 nz;
    f32 nw;
    u8 pad2[0x10];
    f32 ga;
    f32 gb;
    u8 pad3[4];
    f32 gt;
    u8 pad4[6];
    s8 flags;
    u8 pad5;
} WallHit;

extern f32 lbl_803E7F30;
extern f32 lbl_803E7F50;
extern f32 lbl_803E7FF8;
extern f32 lbl_803E7FFC;
extern f32 lbl_803E7FCC;
extern f32 lbl_803E8000;
extern f32 lbl_803E8004;

#pragma scheduling off
#pragma peephole off
int fn_802A0680(int obj, int state)
{
    int jt;
    int inner;
    int b6;
    int b7;
    int b8;
    int b9;
    int dir;
    int mask;
    s16 i;
    f32 oldSpd;
    f32 dx;
    f32 dy;
    f32 ph;
    WallHit hit;
    f32 out1[3];
    f32 pnt[3];
    f32 dst[3];
    f32 tmp[2];

    inner = *(int *)((char *)obj + 0xb8);
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        lbl_803DC6A0 = 0x10;
        ObjHits_MarkObjectPositionDirty();
    }
    {
        register u32 m;
        register u32 v;
        register int base = *(int *)((char *)obj + 0xb8);
        asm {
            lwz v, 0x360(base)
            li m, -3
            and m, v, m
            stw m, 0x360(base)
        }
        *(u32 *)((char *)base + 0x360) |= 0x2000;
    }
    *(u32 *)((char *)state + 4) |= 0x100000;
    {
        f32 z = lbl_803E7EA4;
        *(f32 *)((char *)state + 0x280) = z;
        *(f32 *)((char *)state + 0x284) = z;
        *(u32 *)state |= 0x200000;
        *(f32 *)((char *)obj + 0x24) = z;
        *(f32 *)((char *)obj + 0x2c) = z;
        *(u32 *)((char *)state + 4) |= 0x8000000;
        *(f32 *)((char *)obj + 0x28) = z;
    }
    jt = *(int *)(*(int *)((char *)obj + 0x7c) + *(s8 *)((char *)obj + 0xad) * 4);
    ph = *(f32 *)((char *)state + 0x2a0);
    lbl_803DC6A2 = lbl_803DC6A0;
    switch ((s16)lbl_803DC6A0) {
    case 0x10:
        if (*(s16 *)((char *)obj + 0xa0) == 0x66) {
            *(s16 *)((char *)inner + 0x5a6) = 0;
            lbl_803DC6A0 = 0x16;
        } else {
            *(s16 *)((char *)inner + 0x5a6) = 1;
            lbl_803DC6A0 = 0x15;
        }
        *(f32 *)((char *)obj + 0x10) = *(f32 *)((char *)inner + 0x76c);
        ph = lbl_803E7FF8;
        /* fall through */
    case 0x15:
    case 0x16:
        {
            f32 z = lbl_803E7EA4;
            *(f32 *)((char *)inner + 0x564) = z;
            *(f32 *)((char *)inner + 0x560) = z;
            *(f32 *)((char *)inner + 0x568) = z;
        }
        fn_802A13F4(obj, state);
        if (*(f32 *)((char *)state + 0x298) <= lbl_803E7EFC) {
            goto store_ph;
        }
        oldSpd = *(f32 *)((char *)obj + 0x98);
        *(f32 *)((char *)obj + 0x98) = lbl_803E7EE0;
        /* fall through */
    default:
        if (lbl_803E7EE0 == *(f32 *)((char *)obj + 0x98)) {
        pnt[0] = -(lbl_803E7F30 * *(f32 *)((char *)inner + 0x56c) -
                   *(f32 *)((char *)inner + 0x768));
        pnt[1] = *(f32 *)((char *)inner + 0x76c);
        pnt[2] = -(lbl_803E7F30 * *(f32 *)((char *)inner + 0x574) -
                   *(f32 *)((char *)inner + 0x770));
        {
            int r = objBboxFn_800640cc(lbl_803E7EA4, (void *)((char *)inner + 0x768), pnt, 3,
                                       &hit, obj, 1, 3, 0xff, 0);
            if (r != 0) {
                *(f32 *)((char *)obj + 0xc) = pnt[0];
                *(f32 *)((char *)obj + 0x14) = pnt[2];
                *(f32 *)((char *)inner + 0x54c) = hit.gt * (hit.gb - hit.ga) + hit.ga;
                *(f32 *)((char *)inner + 0x550) = hit.gt * (hit.fz1 - hit.fz0) + hit.fz0;
                *(f32 *)((char *)inner + 0x56c) = hit.nx;
                *(f32 *)((char *)inner + 0x570) = hit.ny;
                *(f32 *)((char *)inner + 0x574) = hit.nz;
                *(f32 *)((char *)inner + 0x578) = hit.nw;
                *(f32 *)((char *)inner + 0x57c) = -hit.nz;
                *(f32 *)((char *)inner + 0x580) = lbl_803E7EA4;
                *(f32 *)((char *)inner + 0x584) = hit.nx;
                *(f32 *)((char *)inner + 0x588) =
                    -(pnt[2] * *(f32 *)((char *)inner + 0x584) +
                      (pnt[0] * *(f32 *)((char *)inner + 0x57c) +
                       pnt[1] * *(f32 *)((char *)inner + 0x580)));
                *(s16 *)((char *)inner + 0x478) =
                    (s16)getAngle(*(f32 *)((char *)inner + 0x56c),
                                  *(f32 *)((char *)inner + 0x574));
                *(s16 *)((char *)inner + 0x484) = *(s16 *)((char *)inner + 0x478);
                {
                    int hf = hit.flags;
                    if ((hf & 4) != 0) {
                        dir = 0;
                    } else if ((hf & 8) != 0) {
                        dir = 1;
                    } else if ((hf & 2) != 0) {
                        dir = 2;
                    } else {
                        dir = 3;
                    }
                }
            } else {
                dir = 2;
            }
        }
        if (lbl_803DC6A0 != 0x15 && lbl_803DC6A0 != 0x16) {
            *(f32 *)((char *)obj + 0x10) = *(f32 *)((char *)inner + 0x76c);
        }
        if (*(f32 *)((char *)state + 0x298) > lbl_803E7EFC) {
            lbl_803DC6A0 =
                ((getAngle(*(f32 *)((char *)state + 0x290),
                           -*(f32 *)((char *)state + 0x28c)) & 0xffff) + 0x1000 >> 13) & 7;
            lbl_803DC6A2 = -1;
            if ((s16)lbl_803DC6A0 == 4 || (s16)lbl_803DC6A0 == 0) {
                *(s16 *)((char *)inner + 0x5a6) ^= 1;
            }
            b6 = 0;
            b7 = 0;
            b8 = 0;
            b9 = 0;
            switch (lbl_803DC6A0) {
            case 4:
                b6 = 1;
                break;
            case 0:
                b7 = 1;
                break;
            case 6:
                b8 = 1;
                break;
            case 2:
                b9 = 1;
                break;
            case 3:
                b6 = 1;
                b9 = 1;
                break;
            case 5:
                b6 = 1;
                b8 = 1;
                break;
            case 1:
                b7 = 1;
                b9 = 1;
                break;
            case 7:
                b7 = 1;
                b8 = 1;
                break;
            }
            if (*(s16 *)((char *)inner + 0x5a6) != 0) {
                lbl_803DC6A0 += 8;
            }
            if (b6 != 0) {
                f32 fv = *(f32 *)((char *)inner + 0x54c) - *(f32 *)((char *)inner + 0x76c);
                f32 lo = lbl_803DAF88[12];
                f32 hi;
                if (lo < lbl_803E7EA4) {
                    lo = -lo;
                }
                hi = lbl_803DAF88[13];
                if (hi < lbl_803E7EA4) {
                    hi = -hi;
                }
                if (fv < hi && (dir == 0 || dir == 3)) {
                    f32 frac = (fv - lo) / (hi - lo);
                    f32 m = lbl_803E7EA4;
                    if (frac < m) {
                    } else {
                        m = lbl_803E7EE0;
                        if (frac > m) {
                        } else {
                            m = frac;
                        }
                    }
                    *(s16 *)((char *)inner + 0x5a4) = (s16)(lbl_803E7FAC * m);
                    *(f32 *)((char *)inner + 0x560) = m;
                    *(int *)((char *)state + 0x308) = (int)fn_8029FFD0;
                    return 0x15;
                }
            } else if (b7 != 0) {
                f32 fv = *(f32 *)((char *)inner + 0x76c) - *(f32 *)((char *)inner + 0x550);
                f32 lo = lbl_803DAF88[14];
                f32 hi;
                if (lo < lbl_803E7EA4) {
                    lo = -lo;
                }
                hi = lbl_803DAF88[15];
                if (hi < lbl_803E7EA4) {
                    hi = -hi;
                }
                if (fv < hi && (dir == 1 || dir == 3)) {
                    f32 frac = (fv - lo) / (hi - lo);
                    f32 m = lbl_803E7EA4;
                    if (frac < m) {
                    } else {
                        m = lbl_803E7EE0;
                        if (frac > m) {
                        } else {
                            m = frac;
                        }
                    }
                    *(s16 *)((char *)inner + 0x5a4) = (s16)(lbl_803E7FAC * m);
                    *(f32 *)((char *)inner + 0x560) = m;
                    *(int *)((char *)state + 0x308) = (int)fn_8029FFD0;
                    return 0x16;
                }
            }
            ((int (*)(int, int, f32, int))Object_ObjAnimSetMove)(
                obj, lbl_80332F48[lbl_803DC6A0], lbl_803E7EA4, 1);
            ObjModel_SampleJointTransform(jt, 1, 0, lbl_803E7EE0,
                                          *(f32 *)((char *)obj + 8), out1, tmp);
            *(s16 *)((char *)obj + 0xa2) = -1;
            *(f32 *)((char *)inner + 0x564) = *(f32 *)((char *)inner + 0x57c) * -out1[0];
            *(f32 *)((char *)inner + 0x560) = out1[1];
            *(f32 *)((char *)inner + 0x568) = *(f32 *)((char *)inner + 0x584) * -out1[0];
            if (b6 == 0 && b7 == 0) {
                *(f32 *)((char *)inner + 0x560) = lbl_803E7EA4;
            }
            if (b8 == 0 && b9 == 0) {
                f32 z = lbl_803E7EA4;
                *(f32 *)((char *)inner + 0x564) = z;
                *(f32 *)((char *)inner + 0x568) = z;
            }
            mask = 0;
            if (out1[0] < lbl_803E7EA4) {
                dx = lbl_803E7FFC * *(f32 *)((char *)inner + 0x57c);
                dy = lbl_803E7FFC * *(f32 *)((char *)inner + 0x584);
            } else {
                dx = lbl_803E7FFC * -*(f32 *)((char *)inner + 0x57c);
                dy = lbl_803E7FFC * -*(f32 *)((char *)inner + 0x584);
            }
            if (b6 != 0 || b7 != 0) {
                pnt[1] = *(f32 *)((char *)inner + 0x76c) + out1[1];
                if (out1[1] < lbl_803E7EA4) {
                    pnt[1] = pnt[1] - lbl_803E7F50;
                } else {
                    pnt[1] = pnt[1] + lbl_803E7F50;
                }
                ph = lbl_803E7F30;
                for (i = 0; i < 2; i++) {
                    if (i != 0) {
                        pnt[0] = *(f32 *)((char *)inner + 0x768) + dx;
                        pnt[2] = *(f32 *)((char *)inner + 0x770) + dy;
                    } else {
                        pnt[0] = *(f32 *)((char *)inner + 0x768) - dx;
                        pnt[2] = *(f32 *)((char *)inner + 0x770) - dy;
                    }
                    dst[0] = -(ph * *(f32 *)((char *)inner + 0x56c) - pnt[0]);
                    dst[1] = pnt[1];
                    dst[2] = -(ph * *(f32 *)((char *)inner + 0x574) - pnt[2]);
                    if (objBboxFn_800640cc(lbl_803E7EA4, pnt, dst, 3, 0, obj, 1, 3, 0xff,
                                           0) != 0) {
                        mask = mask | 1 << i;
                    }
                }
            } else {
                mask |= 3;
            }
            if (b8 != 0 || b9 != 0) {
                pnt[0] = dx + (*(f32 *)((char *)inner + 0x768) +
                               *(f32 *)((char *)inner + 0x564));
                pnt[2] = dy + (*(f32 *)((char *)inner + 0x770) +
                               *(f32 *)((char *)inner + 0x568));
                dy = lbl_803E7F30;
                for (i = 0; i < 2; i++) {
                    if (i != 0) {
                        pnt[1] = lbl_803E7F50 + *(f32 *)((char *)inner + 0x76c);
                    } else {
                        pnt[1] = *(f32 *)((char *)inner + 0x76c) - lbl_803E7F50;
                    }
                    dst[0] = -(dy * *(f32 *)((char *)inner + 0x56c) - pnt[0]);
                    dst[1] = pnt[1];
                    dst[2] = -(dy * *(f32 *)((char *)inner + 0x574) - pnt[2]);
                    if (objBboxFn_800640cc(lbl_803E7EA4, pnt, dst, 3, 0, obj, 1, 3, 0xff,
                                           0) != 0) {
                        mask = mask | 1 << (i + 2);
                    }
                }
            } else {
                mask |= 0xc;
            }
            ph = lbl_803E7FCC;
            if (mask != 0xf) {
                {
                    f32 z = lbl_803E7EA4;
                    *(f32 *)((char *)inner + 0x564) = z;
                    *(f32 *)((char *)inner + 0x560) = z;
                    *(f32 *)((char *)inner + 0x568) = z;
                }
                {
                    int st2 = (s16)lbl_803DC6A0;
                    if (st2 == 4 || st2 == 0 || ((st2 == 0xc) | (st2 == 8)) != 0) {
                        *(s16 *)((char *)inner + 0x5a6) ^= 1;
                    }
                }
                {
                    s16 ns;
                    if (*(s16 *)((char *)inner + 0x5a6) != 0) {
                        ns = 0x15;
                    } else {
                        ns = 0x16;
                    }
                    lbl_803DC6A0 = ns;
                }
                if (*(s16 *)((char *)obj + 0xa0) == lbl_80332F48[21] ||
                    *(s16 *)((char *)obj + 0xa0) == lbl_80332F48[22]) {
                    lbl_803DC6A2 = lbl_803DC6A0;
                    *(f32 *)((char *)obj + 0x98) = oldSpd;
                }
                ph = lbl_803E7FF8;
            }
        } else {
            *(f32 *)((char *)obj + 0x10) = *(f32 *)((char *)inner + 0x76c);
            {
                s16 ns;
                if (*(s16 *)((char *)inner + 0x5a6) != 0) {
                    ns = 0x15;
                } else {
                    ns = 0x16;
                }
                lbl_803DC6A0 = ns;
            }
            ph = lbl_803E7FF8;
        }
    }
        if (lbl_803DC6A0 != 0x15 && lbl_803DC6A0 != 0x16) {
            if (ph < lbl_803E7EA4) {
                ph = -(lbl_803E8004 * *(f32 *)((char *)state + 0x298) + lbl_803E8000);
            } else if (ph > lbl_803E7EA4) {
                ph = lbl_803E8004 * *(f32 *)((char *)state + 0x298) + lbl_803E8000;
            }
        }
        fn_802A13F4(obj, state);
        break;
    }
store_ph:
    *(f32 *)((char *)state + 0x2a0) = ph;
    if (lbl_803DC6A2 != lbl_803DC6A0) {
        ObjAnim_SetCurrentMove(obj, lbl_80332F48[lbl_803DC6A0], lbl_803E7EA4, 1);
    }
    {
        f32 sp = *(f32 *)((char *)obj + 0x98);
        (**(void (**)(f32, f32, f32))((char *)(*gCameraInterface) + 0x2c))(
            *(f32 *)((char *)inner + 0x564) * sp + *(f32 *)((char *)obj + 0xc),
            *(f32 *)((char *)inner + 0x560) * sp + *(f32 *)((char *)obj + 0x10),
            *(f32 *)((char *)inner + 0x568) * sp + *(f32 *)((char *)obj + 0x14));
    }
    fn_802AB5A4(obj, inner, 5);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int player_SeqFn(int obj, int obj2, int seq, int endFlag)
{
    int ctrl;
    register int va;
    int vb;
    int tbl;
    int mapVal;
    int result;
    register u8 *inner;
    u8 found;
    f32 npos[3];
    f32 pz;
    f32 py;
    f32 px;
    int objCount;
    f32 nearArg;

    tbl = (int)lbl_80332EC0;
    ctrl = *(int *)((char *)obj2 + 0x4c);
    inner = *(u8 **)((char *)obj + 0xb8);
    result = 0;
    va = (int)objModelGetVecFn_800395d8(obj, 0);
    vb = (int)objModelGetVecFn_800395d8(obj, 9);
    *(int *)((char *)seq + 0xe8) = (int)fn_802A93F4;
    if (*(void **)&lbl_803DE450 != NULL) {
        staffFn_80170380(lbl_803DE450, 0);
    }
    fn_802B07D8(obj, (int)inner);
    if (*(void **)&lbl_803DE448 == NULL && Obj_IsLoadingLocked() != 0) {
        ObjLink_AttachChild(obj,
                            lbl_803DE448 = Obj_SetupObject(Obj_AllocObjectSetup(0x18, 0x66a), 4, -1,
                                                           -1, *(int *)((char *)obj + 0x30)),
                            3);
    }
    if (*(void **)&lbl_803DE448 != NULL) {
        *(int *)(lbl_803DE448 + 0x30) = *(int *)((char *)obj + 0x30);
        if (*(s16 *)((char *)inner + 0x81a) == 0) {
            *(s16 *)(lbl_803DE448 + 6) |= 0x4000;
        }
    }
    if (*(void **)&lbl_803DE450 == NULL && Obj_IsLoadingLocked() != 0) {
        lbl_803DE450 = Obj_SetupObject(Obj_AllocObjectSetup(0x24, 0x773), 5, -1, -1,
                                       *(int *)((char *)obj + 0x30));
    }
    if (*(void **)&lbl_803DE450 != NULL) {
        ObjPath_GetPointWorldPosition(obj, 4, lbl_803DE450 + 0xc, lbl_803DE450 + 0x10,
                                      lbl_803DE450 + 0x14, 0);
    }
    if ((((u32)*(u8 *)((char *)inner + 0x3f3) >> 3 & 1) != 0 ||
         *(s16 *)((char *)inner + 0x80a) == 0x40) &&
        ((u32)*(u8 *)((char *)inner + 0x3f4) >> 7 & 1) == 0) {
        fn_80295E90(obj, 0);
        *(s16 *)((char *)inner + 0x80a) = -1;
    }
    ObjHits_DisableObject(obj);
    {
        register u32 m;
        register u32 v;
        asm {
            lwz v, 0x360(inner)
            li m, -3
            and m, v, m
            stw m, 0x360(inner)
        }
    }
    if (*(s8 *)((char *)seq + 0x56) != 0) {
        s8 c;
        {
            register u32 m;
            register u32 v;
            asm {
                lwz v, 0x360(inner)
                li m, -0x401
                and m, v, m
                stw m, 0x360(inner)
            }
        }
        {
            f32 fz = lbl_803E7EA4;
            *(f32 *)((char *)inner + 0x79c) = fz;
            *(f32 *)((char *)inner + 0x7a0) = fz;
        }
        if (((u32)*(u8 *)((char *)inner + 0x3f2) >> 7 & 1) == 0) {
            if (lbl_803DE44C != NULL && ((u32)*(u8 *)((char *)inner + 0x3f4) >> 6 & 1) != 0) {
                *(u8 *)((char *)inner + 0x8b4) = 1;
                ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 1;
            }
            *(u8 *)((char *)inner + 0x800) = 0;
            {
                int p = *(int *)((char *)inner + 0x7f8);
                if ((u32)p != 0) {
                    s16 sp = *(s16 *)(p + 0x46);
                    if (sp == 0x3cf || sp == 0x662) {
                        objThrowFn_80182504(p);
                    } else {
                        objSaveFn_800ea774(p);
                    }
                    *(s16 *)(*(int *)((char *)inner + 0x7f8) + 6) &= ~0x4000;
                    *(int *)(*(int *)((char *)inner + 0x7f8) + 0xf8) = 0;
                    *(int *)((char *)inner + 0x7f8) = 0;
                }
            }
        }
        if (*(s8 *)(ctrl + 0x20) == 0 || (c = *(s8 *)((char *)seq + 0x56)) == 3 || c == 2) {
            *(s16 *)((char *)seq + 0x6e) = *(s16 *)((char *)seq + 0x70);
            if (*(s8 *)((char *)seq + 0x56) != 2) {
                *(f32 *)((char *)seq + 0x4c) = lbl_803E7EE0;
                *(f32 *)((char *)seq + 0x40) =
                    *(f32 *)((char *)obj + 0xc) - *(f32 *)((char *)obj2 + 0xc);
                *(f32 *)((char *)seq + 0x44) =
                    *(f32 *)((char *)obj + 0x10) - *(f32 *)((char *)obj2 + 0x10);
                *(f32 *)((char *)seq + 0x48) =
                    *(f32 *)((char *)obj + 0x14) - *(f32 *)((char *)obj2 + 0x14);
                *(s16 *)((char *)seq + 0x50) =
                    *(s16 *)((char *)inner + 0x478) - (u16)*(s16 *)obj2;
                if (*(s16 *)((char *)seq + 0x50) > 0x8000) {
                    *(s16 *)((char *)seq + 0x50) = *(s16 *)((char *)seq + 0x50) - 0xffff;
                }
                if (*(s16 *)((char *)seq + 0x50) < -0x8000) {
                    *(s16 *)((char *)seq + 0x50) = *(s16 *)((char *)seq + 0x50) + 0xffff;
                }
                *(s16 *)((char *)seq + 0x52) =
                    *(s16 *)((char *)obj + 2) - (u16)*(s16 *)((char *)obj2 + 2);
                if (*(s16 *)((char *)seq + 0x52) > 0x8000) {
                    *(s16 *)((char *)seq + 0x52) = *(s16 *)((char *)seq + 0x52) - 0xffff;
                }
                if (*(s16 *)((char *)seq + 0x52) < -0x8000) {
                    *(s16 *)((char *)seq + 0x52) = *(s16 *)((char *)seq + 0x52) + 0xffff;
                }
                *(s16 *)((char *)seq + 0x54) =
                    (u16)*(s16 *)((char *)obj2 + 4) - (u16)*(s16 *)((char *)obj + 4);
                if (*(s16 *)((char *)seq + 0x54) > 0x8000) {
                    *(s16 *)((char *)seq + 0x54) = *(s16 *)((char *)seq + 0x54) - 0xffff;
                }
                if (*(s16 *)((char *)seq + 0x54) < -0x8000) {
                    *(s16 *)((char *)seq + 0x54) = *(s16 *)((char *)seq + 0x54) + 0xffff;
                }
                *(u8 *)((char *)seq + 0x56) = 2;
            }
            *(f32 *)((char *)seq + 0x4c) =
                -(*(f32 *)((char *)seq + 0x24) * timeDelta - *(f32 *)((char *)seq + 0x4c));
            if (*(f32 *)((char *)seq + 0x4c) <= lbl_803E7EA4) {
                *(u8 *)((char *)seq + 0x56) = 0;
            }
            *(s16 *)((char *)obj + 0xa2) = -1;
            *(s16 *)((char *)inner + 0x4d2) = 0;
            *(s16 *)((char *)inner + 0x4d0) = 0;
            *(s16 *)((char *)inner + 0x4d4) = 0;
            *(s16 *)((char *)inner + 0x4d6) = 0;
        } else if (c == 4) {
            f32 dz;
            f32 dy;
            f32 dx;
            int d;
            *(s16 *)((char *)seq + 0x6e) &= ~0x4c;
            *(s16 *)((char *)seq + 0x70) &= ~0x48;
            obj2 = getFocusedNpc();
            if (objModelGetVecFn_800395d8(obj2, 0) != 0) {
                objPosFn_80039510(obj2, 0, npos);
            } else {
                f32 *pv = *(f32 **)(obj2 + 0x74);
                if (pv == NULL) {
                    npos[0] = *(f32 *)(obj2 + 0x18);
                    npos[1] = *(f32 *)(obj2 + 0x1c);
                    npos[2] = *(f32 *)(obj2 + 0x20);
                } else {
                    npos[0] = pv[0];
                    npos[1] = pv[1];
                    npos[2] = pv[2];
                }
            }
            ObjPath_GetPointWorldPosition(obj, 5, (int)&px, (int)&py, (int)&pz, 0);
            dx = *(f32 *)((char *)obj + 0x18) - npos[0];
            dy = (*(f32 *)((char *)inner + 0x7dc) + *(f32 *)((char *)obj + 0x1c)) - npos[1];
            dz = *(f32 *)((char *)obj + 0x20) - npos[2];
            {
                s16 ang = (s16)getAngle(dx, dz);
                lbl_803DE4B0 = ang;
                d = ang - (u16)*(s16 *)((char *)inner + 0x478);
            }
            if (d > 0x8000) {
                d -= 0xffff;
            }
            if (d < -0x8000) {
                d += 0xffff;
            }
            *(s16 *)((char *)inner + 0x4d8) = -*(s16 *)(va + 2);
            *(s16 *)((char *)inner + 0x4dc) = -*(s16 *)va;
            if (d >= 0) {
                if (d > 0x2aaa) {
                    *(s16 *)((char *)inner + 0x4da) = -0x2aaa;
                    *(s16 *)((char *)inner + 0x4e0) = d - 0x2aaa;
                } else {
                    *(s16 *)((char *)inner + 0x4da) = -d;
                    *(s16 *)((char *)inner + 0x4e0) = 0;
                }
            } else if (d < -0x2aaa) {
                *(s16 *)((char *)inner + 0x4da) = 0x2aaa;
                *(s16 *)((char *)inner + 0x4e0) = d + 0x2aaa;
            } else {
                *(s16 *)((char *)inner + 0x4da) = -d;
                *(s16 *)((char *)inner + 0x4e0) = 0;
            }
            *(s16 *)((char *)inner + 0x4de) = (s16)getAngle(dy, sqrtf(dx * dx + dz * dz));
            {
                int v = *(s16 *)((char *)inner + 0x4de);
                if (v < -0x1000) {
                    v = -0x1000;
                } else if (v > 0x1000) {
                    v = 0x1000;
                }
                *(s16 *)((char *)inner + 0x4de) = v;
            }
            *(s16 *)((char *)seq + 0x54) = 0;
            *(f32 *)((char *)seq + 0x4c) = lbl_803E7EA4;
            *(f32 *)((char *)seq + 0x24) = lbl_803E8154;
            *(u8 *)((char *)seq + 0x56) = 5;
            {
                int mv;
                if (*(u32 *)((char *)inner + 0x7f8) != 0) {
                    mv = 8;
                } else {
                    mv = 0;
                }
                if (*(s16 *)((char *)obj + 0xa0) != mv) {
                    ObjAnim_SetCurrentMove(obj, mv, lbl_803E7EA4, 0);
                    ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent *)obj, 1);
                }
            }
            ((void (*)(int, f32, f32, int))ObjAnim_AdvanceCurrentMove)(obj, lbl_803E7F78, timeDelta, 0);
            result = 1;
        } else if (c == 5) {
            *(s16 *)((char *)seq + 0x6e) &= ~0x4c;
            *(s16 *)((char *)seq + 0x70) &= ~0x48;
            ObjHits_EnableObject(obj);
            if (*(f32 *)((char *)seq + 0x4c) >= lbl_803E7EE0 &&
                (**(int (**)(void))((char *)(*gCameraInterface) + 0x50))() == 0) {
                *(s16 *)((char *)inner + 0x4d2) = 0;
                *(s16 *)((char *)inner + 0x4d0) = 0;
                if ((s8)endFlag == 0) {
                    *(u8 *)((char *)seq + 0x56) = 0;
                } else {
                    *(u8 *)((char *)seq + 0x56) = 6;
                }
                if (*(u32 *)((char *)inner + 0x7f0) != 0) {
                    (**(void (**)(int, int, int))((char *)(*gPlayerInterface) + 0x14))(obj, (int)inner,
                                                                                       0x18);
                    *(void (**)(int))((char *)inner + 0x304) = fn_8029F67C;
                } else {
                    (**(void (**)(int, int, int))((char *)(*gPlayerInterface) + 0x14))(obj, (int)inner,
                                                                                       1);
                    *(void (**)(int, int))((char *)inner + 0x304) = fn_802A514C;
                    *(s16 *)((char *)inner + 0x276) = 1;
                }
            } else {
                f32 prev = *(f32 *)((char *)seq + 0x4c);
                f32 one;
                int dd;
                *(f32 *)((char *)seq + 0x4c) = *(f32 *)((char *)seq + 0x24) * timeDelta + prev;
                if (*(f32 *)((char *)seq + 0x4c) > lbl_803E7EE0) {
                    *(f32 *)((char *)seq + 0x4c) = lbl_803E7EE0;
                }
                prev = *(f32 *)((char *)seq + 0x4c) - prev;
                *(s16 *)((char *)inner + 0x478) +=
                    (s16)(prev * (f32)*(s16 *)((char *)inner + 0x4e0));
                *(s16 *)obj = *(s16 *)((char *)inner + 0x484) = *(s16 *)((char *)inner + 0x478);
                dd = *(s16 *)((char *)inner + 0x4d8) - (u16)*(s16 *)((char *)inner + 0x4da);
                if (dd > 0x8000) {
                    dd = dd - 0xffff;
                }
                if (dd < -0x8000) {
                    dd = dd + 0xffff;
                }
                *(s16 *)(va + 2) = (s16)((f32)dd * *(f32 *)((char *)seq + 0x4c) +
                                         (f32)*(s16 *)((char *)inner + 0x4d8));
                dd = *(s16 *)((char *)inner + 0x4dc) - (u16)*(s16 *)((char *)inner + 0x4de);
                if (dd > 0x8000) {
                    dd = dd - 0xffff;
                }
                if (dd < -0x8000) {
                    dd = dd + 0xffff;
                }
                *(s16 *)va = (s16)((f32)dd * *(f32 *)((char *)seq + 0x4c) +
                                   (f32)*(s16 *)((char *)inner + 0x4dc));
                *(s16 *)(vb + 2) = (s16)((f32)*(s16 *)((char *)inner + 0x4d2) *
                                         ((one = lbl_803E7EE0) - *(f32 *)((char *)seq + 0x4c)));
                *(s16 *)(vb + 4) = (s16)((f32)*(s16 *)((char *)inner + 0x4d0) *
                                         (one - *(f32 *)((char *)seq + 0x4c)));
                *(s16 *)((char *)obj + 4) = *(s16 *)(vb + 4) / 4;
                *(s16 *)((char *)inner + 0x4d4) = *(s16 *)(va + 2);
                *(s16 *)((char *)inner + 0x4d6) = -*(s16 *)va;
            }
            ((void (*)(int, f32, f32, int))ObjAnim_AdvanceCurrentMove)(obj, lbl_803E7F78, timeDelta, 0);
            result = 1;
        } else if (c == 6) {
            *(s16 *)((char *)seq + 0x6e) &= ~0x4c;
            *(s16 *)((char *)seq + 0x70) &= ~0x48;
            ObjHits_EnableObject(obj);
            if ((s8)endFlag == 0) {
                *(u8 *)((char *)seq + 0x56) = 0;
            }
            ((void (*)(int, f32, f32, int))ObjAnim_AdvanceCurrentMove)(obj, lbl_803E7F78, timeDelta, 0);
            result = 0;
        } else {
            f32 dz2;
            f32 dist;
            f32 dx2;
            f32 d2;
            if (c != 1) {
                *(f32 *)((char *)seq + 0x40) = *(f32 *)((char *)obj + 0xc);
                *(f32 *)((char *)seq + 0x44) = *(f32 *)((char *)obj + 0x10);
                *(f32 *)((char *)seq + 0x48) = *(f32 *)((char *)obj + 0x14);
                lbl_803DE468 = lbl_803E80AC;
                lbl_803DE46C = 0;
            }
            result = 1;
            *(s16 *)((char *)seq + 0x6e) = 0;
            *(u8 *)((char *)seq + 0x56) = 1;
            {
                f32 ax = *(f32 *)((char *)seq + 0x40) - *(f32 *)((char *)obj + 0xc);
                f32 az = *(f32 *)((char *)seq + 0x48) - *(f32 *)((char *)obj + 0x14);
                dist = sqrtf(ax * ax + az * az);
            }
            dx2 = *(f32 *)((char *)obj2 + 0xc) - *(f32 *)((char *)seq + 0x40);
            dz2 = *(f32 *)((char *)obj2 + 0x14) - *(f32 *)((char *)seq + 0x48);
            d2 = sqrtf(dx2 * dx2 + dz2 * dz2);
            if (dist <= lbl_803DE468) {
                lbl_803DE46C += 1;
            }
            if (dist >= d2 || lbl_803DE46C > 5) {
                int dd3 = *(s16 *)((char *)inner + 0x478) - (u16)*(s16 *)obj2;
                if (dd3 > 0x8000) {
                    dd3 -= 0xffff;
                }
                if (dd3 < -0x8000) {
                    dd3 += 0xffff;
                }
                if (dd3 > 0x4000) {
                    dd3 = 0x4000;
                }
                if (dd3 < -0x4000) {
                    dd3 = -0x4000;
                }
                *(s16 *)((char *)inner + 0x478) -= (dd3 * framesThisStep) >> 3;
                *(s16 *)((char *)inner + 0x484) = *(s16 *)((char *)inner + 0x478);
                if (lbl_803DE46C > 6) {
                    dd3 = 0;
                }
                if (dd3 < 0x100 && dd3 > -0x100) {
                    *(s16 *)((char *)seq + 0x6e) = *(s16 *)((char *)seq + 0x70);
                    *(u8 *)((char *)seq + 0x56) = 0;
                    *(s16 *)((char *)seq + 0x5a) = *(s16 *)((char *)seq + 0x58) - 1;
                    *(s16 *)((char *)obj + 0xa2) = -1;
                    result = 0;
                } else {
                    f32 fz3 = lbl_803E7EA4;
                    *(f32 *)((char *)inner + 0x290) = fz3;
                    *(f32 *)((char *)inner + 0x28c) = fz3;
                    (**(void (**)(int))((char *)(*gPlayerInterface) + 0x10))(obj2);
                    *(int *)((char *)inner + 0x31c) = 0;
                    *(int *)((char *)inner + 0x318) = 0;
                    *(int *)((char *)obj + 0xf4) = 0;
                    *(s16 *)((char *)inner + 0x330) = 0;
                    *(u8 *)((char *)inner + 0x25f) = 1;
                    *(u32 *)((char *)inner + 4) = *(u32 *)((char *)inner + 4) & ~0x100000;
                    *(u8 *)((char *)inner + 0x8c5) = 0;
                    fn_802B0EA4(obj, (int)inner, (int)inner);
                    (**(void (**)(f32, int, int, f32, void *, void *))((char *)(*gPlayerInterface) +
                                                                       8))(
                        timeDelta, obj, (int)inner, timeDelta, lbl_803DAFC8, &lbl_803DE4B8);
                }
            } else {
                dx2 = dx2 / d2;
                dz2 = dz2 / d2;
                {
                    f32 k = lbl_803E80C4;
                    *(f32 *)((char *)inner + 0x290) = k * -dx2;
                    *(f32 *)((char *)inner + 0x28c) = k * dz2;
                }
                *(f32 *)((char *)obj + 0xc) = dist * dx2 + *(f32 *)((char *)seq + 0x40);
                *(f32 *)((char *)obj + 0x14) = dist * dz2 + *(f32 *)((char *)seq + 0x48);
                (**(void (**)(int))((char *)(*gPlayerInterface) + 0x10))(obj2);
                *(int *)((char *)inner + 0x31c) = 0;
                *(int *)((char *)inner + 0x318) = 0;
                *(int *)((char *)obj + 0xf4) = 0;
                *(s16 *)((char *)inner + 0x330) = 0;
                *(u8 *)((char *)inner + 0x25f) = 1;
                *(u32 *)((char *)inner + 4) = *(u32 *)((char *)inner + 4) & ~0x100000;
                *(u8 *)((char *)inner + 0x8c5) = 0;
                fn_802B0EA4(obj, (int)inner, (int)inner);
                (**(void (**)(f32, int, int, f32, void *, void *))((char *)(*gPlayerInterface) +
                                                                   8))(timeDelta, obj, (int)inner,
                                                                       timeDelta, lbl_803DAFC8,
                                                                       &lbl_803DE4B8);
            }
            lbl_803DE468 = dist;
        }
        if (*(s8 *)((char *)seq + 0x56) == 0) {
            (**(void (**)(int, int, int))((char *)(*gPlayerInterface) + 0x14))(obj, (int)inner, 1);
            *(void (**)(int, int))((char *)inner + 0x304) = fn_802A514C;
            *(s16 *)((char *)inner + 0x276) = 1;
        }
    } else {
        *(s16 *)((char *)seq + 0x6e) |= *(s16 *)((char *)seq + 0x70) & ~0x400;
        *(u8 *)((char *)inner + 0x34c) = 0;
        {
            f32 fz2 = lbl_803E7EA4;
            *(f32 *)((char *)inner + 0x290) = fz2;
            *(f32 *)((char *)inner + 0x28c) = fz2;
        }
        *(s16 *)((char *)inner + 0x330) = 0;
        *(int *)((char *)inner + 0x31c) = 0;
        *(int *)((char *)inner + 0x318) = 0;
        if (*(s16 *)((char *)seq + 0x6e) & 1) {
            *(u32 *)((char *)inner + 4) |= 0x100000;
            *(u8 *)((char *)inner + 0x25f) = 0;
        }
        for (vb = 0; vb < *(u8 *)((char *)seq + 0x8b); vb++) {
            switch (((u8 *)seq)[vb + 0x81]) {
            case 3: {
                f32 best;
                obj2 = (int)ObjGroup_GetObjects(10, &objCount);
                found = 0;
                best = lbl_803E80AC;
                for (endFlag = 0; endFlag < objCount; endFlag++) {
                    va = *(int *)obj2;
                    if ((u32)va != 0 && arrayIndexOf((void *)(tbl + 0x13c), 9, *(s16 *)(va + 0x46)) != -1) {
                        f32 dsq = vec3f_distanceSquared((void *)(va + 0x18), (void *)(obj + 0x18));
                        if (dsq < best || found == 0) {
                            best = dsq;
                            *(int *)((char *)inner + 0x7f0) = va;
                            found = 1;
                        }
                    }
                    obj2 += 4;
                }
                if (found != 0) {
                    *(f32 *)((char *)inner + 0x6a4) = lbl_803E7EE0;
                    *(f32 *)((char *)inner + 0x6a8) = *(f32 *)((char *)inner + 0x768);
                    *(f32 *)((char *)inner + 0x6ac) = *(f32 *)((char *)inner + 0x76c);
                    *(f32 *)((char *)inner + 0x6b0) = *(f32 *)((char *)inner + 0x770);
                    va = *(int *)((char *)inner + 0x7f0);
                    (*(void (*)(int, int))*(int *)((char *)*(int *)(*(int *)(va + 0x68)) + 0x3c))(
                        va, 2);
                    *(s16 *)((char *)obj + 6) |= 8;
                    *(u32 *)(*(int *)((char *)obj + 0x64) + 0x30) |= 0x1000;
                    *(s16 *)(*(int *)((char *)obj + 0x64) + 0x36) = 0;
                    *(s16 *)((char *)seq + 0x6e) &= ~4;
                    switch (*(s16 *)(va + 0x46)) {
                    case 0x72:
                    case 0x38c:
                        Music_Trigger(0x97, 1);
                        GameBit_Set(0xc1f, 0);
                        *(int *)((char *)inner + 0x6e8) = tbl + 0x3f0;
                        *(u8 *)((char *)inner + 0x6ec) = 3;
                        ObjAnim_SetCurrentMove(obj, 0x17, lbl_803E7EA4, 1);
                        break;
                    case 0x8c:
                        *(int *)((char *)inner + 0x6e8) = tbl + 0x408;
                        *(u8 *)((char *)inner + 0x6ec) = 4;
                        ObjAnim_SetCurrentMove(obj, 0x7b, lbl_803E7EA4, 1);
                        if ((u32)getSbGalleon() != 0) {
                            (**(void (**)(int, int))((char *)(*gCameraInterface) + 0x28))(va, 0);
                            (**(void (**)(int, int, int, int))((char *)(*gObjectTriggerInterface) +
                                                               0x50))(0x4a, 1, 0, 0x78);
                        }
                        break;
                    case 0x416:
                        Music_Trigger(0xd5, 1);
                        *(int *)((char *)inner + 0x6e8) = tbl + 0x438;
                        *(u8 *)((char *)inner + 0x6ec) = 8;
                        ObjAnim_SetCurrentMove(obj, *(s16 *)(tbl + 0x438), lbl_803E7EA4, 1);
                        break;
                    case 0x419:
                        Music_Trigger(0xe6, 1);
                        *(int *)((char *)inner + 0x6e8) = tbl + 0x408;
                        *(u8 *)((char *)inner + 0x6ec) = 4;
                        ObjAnim_SetCurrentMove(obj, 0x7b, lbl_803E7EA4, 1);
                        break;
                    case 0x484:
                        Music_Trigger(0xe6, 1);
                        *(int *)((char *)inner + 0x6e8) = tbl + 0x420;
                        *(u8 *)((char *)inner + 0x6ec) = 4;
                        ObjAnim_SetCurrentMove(obj, 0xf8, lbl_803E7EA4, 1);
                        break;
                    default:
                        Music_Trigger(0x1f, 1);
                    case 0x714:
                        *(int *)((char *)inner + 0x6e8) = tbl + 0x420;
                        *(u8 *)((char *)inner + 0x6ec) = 4;
                        ObjAnim_SetCurrentMove(obj, 0xf8, lbl_803E7EA4, 1);
                    }
                    if (arrayIndexOf((void *)(tbl + 0x160), 4, *(s16 *)(va + 0x46)) != -1) {
                        (**(void (**)(int, int, int))((char *)(*gPlayerInterface) + 0x14))(
                            obj, (int)inner, 0x1a);
                        *(void (**)(int))((char *)inner + 0x304) = fn_8029F67C;
                    } else {
                        (**(void (**)(int, int, int))((char *)(*gPlayerInterface) + 0x14))(
                            obj, (int)inner, 0x18);
                        *(void (**)(int))((char *)inner + 0x304) = fn_8029F67C;
                    }
                }
                break;
            }
            case 2:
                if (fn_802957B4(obj) != 0) {
                    *(s16 *)((char *)seq + 0x6e) |= 4;
                }
                break;
            case 4:
                obj2 = *(int *)((char *)inner + 0x7f0);
                (**(void (**)(int, int))((char *)(*gCameraInterface) + 0x28))(obj2, 0);
                (**(void (**)(int, int, int, int))((char *)(*gObjectTriggerInterface) + 0x50))(
                    0x45, 0, 0, 0);
                *(int *)((char *)inner + 0x6e8) = 0;
                if ((u32)obj2 != 0 && *(s16 *)(obj2 + 0x46) == 0x22) {
                    (**(void (**)(int, int, int))((char *)(*gPlayerInterface) + 0x14))(obj, (int)inner,
                                                                                       0x16);
                    *(int *)((char *)inner + 0x304) = 0;
                } else {
                    (**(void (**)(int, int, int))((char *)(*gPlayerInterface) + 0x14))(obj, (int)inner,
                                                                                       0x18);
                    *(void (**)(int))((char *)inner + 0x304) = fn_8029F67C;
                }
                break;
            case 0xb: {
                int gb = *(int *)((char *)inner + 0x7f0);
                if ((u32)gb != 0 && *(s16 *)(gb + 0x46) == 0x416) {
                    (**(void (**)(int, int))((char *)(*gCameraInterface) + 0x28))(gb, 0);
                    (**(void (**)(int, int, int))((char *)(*gCameraInterface) + 0x24))(0, 0x69, 0);
                    (**(void (**)(int, int, int, int))((char *)(*gObjectTriggerInterface) + 0x50))(
                        0x42, 4, 0, 0);
                } else if ((u32)gb != 0 && arrayIndexOf((void *)(tbl + 0x160), 4, *(s16 *)(gb + 0x46)) != -1) {
                    (**(void (**)(int, int, int, int))((char *)(*gObjectTriggerInterface) + 0x50))(
                        0x53, 0, 0, 0);
                } else {
                    (**(void (**)(int, int, int))((char *)(*gCameraInterface) + 0x24))(0, 0x1d, 0);
                    (**(void (**)(int, int, int, int))((char *)(*gObjectTriggerInterface) + 0x50))(
                        0x42, 4, 0, 0);
                }
                break;
            }
            case 6:
                (**(void (**)(int, int, int, int))((char *)(*gObjectTriggerInterface) + 0x50))(
                    0x44, 0, 0, 0);
                (**(void (**)(int, int, int))((char *)(*gPlayerInterface) + 0x14))(obj, (int)inner,
                                                                                   0x17);
                *(int *)((char *)inner + 0x304) = 0;
                break;
            case 7:
                *(s16 *)((char *)seq + 0x6e) &= ~3;
                obj2 = *(int *)((char *)obj + 0xb8);
                (**(void (**)(int, int, int))((char *)(*gPlayerInterface) + 0x14))(obj, obj2,
                                                                                   0x3e);
                *(int *)(obj2 + 0x304) = 0;
                *(u32 *)(obj2 + 0x360) |= 1;
                *(s16 *)((char *)obj + 6) |= 8;
                break;
            case 8: {
                *(s16 *)((char *)seq + 0x6e) = *(s16 *)((char *)seq + 0x70);
                obj2 = *(int *)((char *)obj + 0xb8);
                (**(void (**)(int, int, int))((char *)(*gPlayerInterface) + 0x14))(obj, obj2, 1);
                *(void (**)(int, int))(obj2 + 0x304) = fn_802A514C;
                {
                    register u32 m;
                    register u32 v;
                    register int base = obj2;
                    asm {
                        lwz v, 0x360(base)
                        li m, -2
                        and m, v, m
                        stw m, 0x360(base)
                    }
                }
                *(s16 *)((char *)obj + 6) &= ~8;
                break;
            }
            case 0xa:
                if (lbl_803DE44C != NULL &&
                    ((u32)*(u8 *)((char *)inner + 0x3f4) >> 6 & 1) != 0) {
                    *(u8 *)((char *)inner + 0x8b4) = 2;
                    ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 0;
                }
                break;
            case 0x18:
                if (lbl_803DE44C != NULL &&
                    ((u32)*(u8 *)((char *)inner + 0x3f4) >> 6 & 1) != 0) {
                    *(u8 *)((char *)inner + 0x8b4) = 0;
                    ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 0;
                }
                break;
            case 0xd: {
                f32 spd;
                f32 dy2;
                f32 sp3;
                (**(void (**)(int, int, int))((char *)(*gObjectTriggerInterface) + 0x7c))(
                    *(s16 *)(*(int *)((char *)obj + 0xc4) + 0x46), *(int *)((char *)obj + 0xc4),
                    0);
                {
                    int prt = *(int *)((char *)obj + 0xc4);
                    obj2 = *(int *)(prt + 0xb8);
                    if (*(u32 *)(prt + 0x54) != 0) {
                        spd = (f32)*(s16 *)(*(int *)(prt + 0x54) + 0x5a);
                    } else {
                        spd = *(f32 *)(prt + 0xa8) * *(f32 *)(prt + 8);
                    }
                    dy2 = (*(f32 *)(*(int *)(prt + 0x74) + 4) - *(f32 *)(prt + 0x10)) -
                          lbl_803E8158;
                }
                sp3 = spd *
                      -sin(lbl_803E7F94 * (f32)*(s16 *)(obj2 + 0x478) / lbl_803E7F98);
                (**(void (**)(f32, f32, f32))((char *)(*gObjectTriggerInterface) + 0x80))(
                    spd * -fn_80293E80(lbl_803E7F94 * (f32)*(s16 *)(obj2 + 0x478) /
                                       lbl_803E7F98),
                    dy2, sp3);
                (**(void (**)(int, int, int))((char *)(*gObjectTriggerInterface) + 0x48))(
                    *(int *)((char *)obj + 0xf4), obj, -1);
                break;
            }
            case 0xf:
                objHitDetectFn_80062e84(obj, 0, 1);
                break;
            case 0x10: {
                int t;
                nearArg = lbl_803E815C;
                t = ObjGroup_FindNearestObject(6, obj, &nearArg);
                if ((u32)t != 0) {
                    objHitDetectFn_80062e84(obj, t, 1);
                }
                break;
            }
            case 0x17:
                va = *(int *)((char *)obj + 0xb8);
                if (*(u32 *)(va + 0x7f8) != 0) {
                    *(u8 *)(va + 0x800) = 0;
                    {
                        int p17 = *(int *)(va + 0x7f8);
                        if ((u32)p17 != 0) {
                            s16 sp17 = *(s16 *)(p17 + 0x46);
                            if (sp17 == 0x3cf || sp17 == 0x662) {
                                objThrowFn_80182504(p17);
                            } else {
                                objSaveFn_800ea774(p17);
                            }
                            *(s16 *)(*(int *)(va + 0x7f8) + 6) &= ~0x4000;
                            *(int *)(*(int *)(va + 0x7f8) + 0xf8) = 0;
                            *(int *)(va + 0x7f8) = 0;
                        }
                    }
                    {
                        register u32 m;
                        register u32 v;
                        register int base = va;
                        asm {
                            lwz v, 0x360(base)
                            lis m, 0x80
                            or m, v, m
                            stw m, 0x360(base)
                        }
                    }
                    (**(void (**)(int, int, int))((char *)(*gPlayerInterface) + 0x14))(obj, va,
                                                                                       1);
                    *(void (**)(int, int))(va + 0x304) = fn_802A514C;
                }
                break;
            case 0x14: {
                register u32 m;
                register u32 v;
                asm {
                    lwz v, 0x360(inner)
                    lis m, 0x4
                    or m, v, m
                    stw m, 0x360(inner)
                }
                break;
            }
            case 0x15: {
                register u32 t15;
                register u32 m;
                register u32 v;
                asm {
                    lwz v, 0x360(inner)
                    lis t15, 0xfffc
                    subi m, t15, 0x1
                    and m, v, m
                    stw m, 0x360(inner)
                }
                break;
            }
            case 0x16: {
                register u32 m;
                register u32 v;
                asm {
                    lwz v, 0x360(inner)
                    lis m, 0x2
                    or m, v, m
                    stw m, 0x360(inner)
                }
                break;
            }
            case 0x12: {
                register u32 t12;
                register u32 m;
                register u32 v;
                asm {
                    lwz v, 0x360(inner)
                    lis t12, 0x1
                    addi m, t12, -0x8000
                    or m, v, m
                    stw m, 0x360(inner)
                }
                break;
            }
            case 0x13:
                loadUiDll(1);
                break;
            case 0x19:
                (**(void (**)(void))((char *)(*gMapEventInterface) + 0x28))();
                break;
            case 0x1c:
                fn_80295CF4(obj, 0);
                break;
            case 0x1d:
                (**(void (**)(int, int, int))((char *)(*gPlayerInterface) + 0x14))(obj, (int)inner,
                                                                                   0x1a);
                *(void (**)(int))((char *)inner + 0x304) = fn_8029F67C;
                break;
            case 0x1e:
                (**(void (**)(int, int, int))((char *)(*gPlayerInterface) + 0x14))(obj, (int)inner, 1);
                *(void (**)(int, int))((char *)inner + 0x304) = fn_802A514C;
                break;
            case 0x1f:
                __set_debug_bba(lbl_803DE420);
                fn_80026C30(lbl_803DE420, 1);
                break;
            case 0x20:
                fn_80026C30(lbl_803DE420, 0);
                break;
            case 0x21:
                lbl_803DC66C = 2;
                break;
            case 0x22:
                lbl_803DC66C = 1;
                break;
            case 0x1a:
                if (*(u32 *)((char *)inner + 0x684) != 0) {
                    int p1a = *(int *)(*(int *)((char *)inner + 0x684) + 0x50);
                    int snd = *(s16 *)(p1a + 0x7a);
                    if (snd > -1) {
                        (**(void (**)(int, int, int, int))((char *)(*gGameUIInterface) + 0x38))(
                            snd, 0x154, 300, 0);
                    } else {
                        (**(void (**)(int, int, int, int))((char *)(*gGameUIInterface) + 0x38))(
                            *(s16 *)(p1a + 0x7c), 0x154, 300, 0);
                    }
                }
                break;
            case 1:
                if (*(u32 *)((char *)inner + 0x684) != 0) {
                    ObjMsg_SendToObject(*(int *)((char *)inner + 0x684), 0x7000b, obj, 0);
                    *(int *)((char *)inner + 0x684) = 0;
                }
                break;
            case 0x25:
                *(u16 *)((char *)inner + 0x8d8) ^= 1;
                break;
            case 0x26:
                *(u16 *)((char *)inner + 0x8d8) ^= 2;
                break;
            case 0x27:
                hudFn_8011f38c(1);
                break;
            case 0x28: {
                int h;
                switch (coordsToMapCell(*(f32 *)((char *)obj + 0xc),
                                        *(f32 *)((char *)obj + 0x14))) {
                case 0x13:
                    mapVal = 0x10;
                    break;
                case 0xc:
                    mapVal = 0x14;
                    break;
                case 0xd:
                    mapVal = 0x18;
                    break;
                case 2:
                    mapVal = 0x1c;
                    break;
                }
                h = *(int *)((char *)obj + 0xb8);
                if ((s8)*(s8 *)(*(int *)(h + 0x35c) + 1) <= mapVal - 4) {
                    int vv = mapVal;
                    if (mapVal < 0) {
                        vv = 0;
                    } else if (mapVal > 0x50) {
                        vv = 0x50;
                    }
                    *(s8 *)(*(int *)(h + 0x35c) + 1) = vv;
                    vv = mapVal;
                    h = *(int *)((char *)obj + 0xb8);
                    if (mapVal < 0) {
                        vv = 0;
                    } else {
                        s8 cur2 = *(s8 *)(*(int *)(h + 0x35c) + 1);
                        if (mapVal > cur2) {
                            vv = cur2;
                        }
                    }
                    *(s8 *)(*(int *)(h + 0x35c)) = vv;
                }
                break;
            }
            case 0x29:
                hudFn_8011f38c(0);
                break;
            case 0x2a:
                if ((*(u8 (*)(int))*(int *)((char *)(*gMapEventInterface) + 0x40))(0xb) == 7) {
                    getEnvfxActImmediately(obj, obj, 0x1fb, 0);
                    getEnvfxActImmediately(obj, obj, 0x1ff, 0);
                    getEnvfxActImmediately(obj, obj, 0x249, 0);
                    getEnvfxActImmediately(obj, obj, 0x1fd, 0);
                } else {
                    getEnvfxActImmediately(obj, obj, 0x217, 0);
                    getEnvfxActImmediately(obj, obj, 0x216, 0);
                    getEnvfxActImmediately(obj, obj, 0x22e, 0);
                    getEnvfxActImmediately(obj, obj, 0x218, 0);
                    getEnvfxActImmediately(obj, obj, 0x84, 0);
                    getEnvfxActImmediately(obj, obj, 0x8a, 0);
                }
                ((void (*)(int, f32))skyFn_80088e54)(0, lbl_803E7EA4);
                break;
            case 0x2d:
                Rcp_SetSpiritVisionEnabled(1);
                break;
            case 0x2e:
                Rcp_SetSpiritVisionEnabled(0);
                break;
            case 0x2b: {
                register u32 m;
                register u32 v;
                register int base;
                base = *(int *)((char *)obj + 0x64);
                asm {
                    lwz v, 0x30(base)
                    li m, -5
                    and m, v, m
                    stw m, 0x30(base)
                }
                break;
            }
            case 0x2c:
                *(u32 *)(*(int *)((char *)obj + 0x64) + 0x30) |= 4;
                break;
            case 0x31:
                viewFinderSetZoomTo50();
                break;
            case 0x32:
                viewFinderSetZoom(Camera_GetFovY());
                break;
            }
        }
        if (*(int *)(*(int *)((char *)obj + 0xb8) + 0x360) & 1) {
            *(s16 *)((char *)seq + 0x6e) &= ~3;
        }
    }
    if (lbl_803DE458 != 0) {
        *(u8 *)((char *)seq + 0x90) |= 4;
        lbl_803DE458 = 0;
    }
    {
        int g = *(int *)((char *)inner + 0x7f0);
        if ((u32)g != 0 &&
            (*(int (*)(int))*(int *)((char *)*(int *)(*(int *)(g + 0x68)) + 0x38))(g) == 2) {
            *(s16 *)((char *)seq + 0x6e) &= ~3;
        }
    }
    if (((u32)*(u8 *)((char *)inner + 0x3f2) >> 6 & 1) != 0) {
        characterDoEyeAnims(obj, (int)((char *)inner + 0x364));
    }
    if (lbl_803DC66C == 2) {
        lbl_803DC66C = 1;
    }
    if (*(s16 *)((char *)lbl_803DE44C + 0x44) == 0x2d) {
        ((void (*)(void))objSetAnimField48to0)();
    }
    ((void (*)(int, int, f32))fn_802AEF34)(obj, (int)inner, timeDelta);
    if (lbl_803DE44C != NULL && ((u32)*(u8 *)((char *)inner + 0x3f4) >> 6 & 1) != 0) {
        *(u16 *)((char *)lbl_803DE44C + 0xb0) &= ~7;
        if (*(u8 *)((char *)inner + 0x8b3) == 0) {
            *(u16 *)((char *)lbl_803DE44C + 0xb0) |= 2;
        }
    }
    {
        register u32 m;
        register u32 v;
        asm {
            lwz v, 0x360(inner)
            lis m, 0x80
            or m, v, m
            stw m, 0x360(inner)
        }
    }
    ((void (*)(int, int, int, int, int, f32, f32))objAudioFn_8006ef38)(
        obj, (int)((char *)seq + 0xf0), *(u8 *)((char *)inner + 0x8a6),
        (int)((char *)inner + 0x3c4), (int)((char *)inner + 4),
        *(f32 *)((char *)inner + 0x280), lbl_803E7EE0);
    return result;
}
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E8090;
extern f32 lbl_803E8094;
extern f32 lbl_803E8098;
extern f32 lbl_803E809C;
extern f32 lbl_803E80A0;
extern char sNotOnGroundFailureMessage[];
extern void fn_80137948(const char *fmt, ...);
int fn_802A87CC(int obj, char *cam, f32 *out, f32 *vec, f32 fa, f32 fb);

#pragma scheduling off
#pragma peephole off
s8 fn_802A74A4(int obj, int p2, int p3, void *out, f32 fv, u32 mask)
{
    typedef struct {
        int hitObj;
        f32 minX;
        f32 maxX;
        f32 minY;
        f32 maxY;
        f32 minZ;
        f32 maxZ;
        f32 nx;
        f32 ny;
        f32 nz;
        f32 nw;
        u8 padA[0xc];
        f32 g38;
        f32 g3c;
        f32 g40;
        f32 dist;
        u8 padB[9];
        s8 kind;
        u8 padC[2];
    } SweepHit;
    f32 nearDist;
    int objCount;
    s8 dirs[13] = { 0xb, 4, 6, 0xa, 0xa, 3, 3, 2, 0xe, 0x10, 0x12, 0x13, 5 };
    f32 sc0[3];
    f32 sc1[3];
    f32 end[3];
    f32 start[3];
    f32 vec[3];
    f32 rot[3];
    struct {
        u8 pad[2];
        u16 mode;
        u8 pad2[4];
        f32 scale;
        f32 x;
        f32 y;
        f32 z;
    } pfx;
    u16 dirMasks[13] = { 1, 2, 4, 8, 8, 0x10, 0x10, 0x40, 0x80, 0x100, 1, 0x20, 0xffff };
    SweepHit buf;
    f32 ang;
    f32 hd;
    f32 dp;
    int i;
    s8 ok;
    s8 flagA;
    s8 flagB;
    u8 useAlt;
    u8 hit;
    f32 *dir;

    ang = (lbl_803E7F94 *
           (f32)((u16)getAngle(*(f32 *)(p3 + 0x290), -*(f32 *)(p3 + 0x28c)) -
                 *(s16 *)(p3 + 0x330))) /
          lbl_803E7F98;
    rot[0] = -fn_80293E80(ang);
    rot[1] = lbl_803E7EA4;
    rot[2] = -sin(ang);
    fn_802A81B8(obj, p2, vec);
    sc1[0] = lbl_803E808C * rot[0];
    sc1[1] = lbl_803E808C * rot[1];
    sc1[2] = lbl_803E808C * rot[2];
    sc0[0] = lbl_803E808C * vec[0];
    sc0[1] = lbl_803E808C * vec[1];
    sc0[2] = lbl_803E808C * vec[2];
    {
        register u32 m;
        register u32 v;
        register int base = p2;
        asm {
            lwz v, 0x360(base)
            li m, -0x101
            and m, v, m
            stw m, 0x360(base)
        }
    }
    for (i = 0; i < 13; i++) {
        if ((mask & dirMasks[i]) == 0) {
            continue;
        }
        ok = 0;
        useAlt = 0;
        flagB = 1;
        flagA = 0;
        switch (i) {
        case 1:
        case 7:
        case 12: {
            u8 b;
            s16 v = *(s16 *)(p2 + 0x274);
            if (v == 0xc) {
                continue;
            }
            if ((u16)(v - 9) <= 2) {
                continue;
            }
            b = *(u8 *)(p2 + 0x3f0);
            if ((u32)b >> 3 & 1) {
                continue;
            }
            if ((u32)b >> 2 & 1) {
                continue;
            }
            flagB = 0;
            flagA = 1;
            ok = 1;
            break;
        }
        case 0:
        case 10:
            if (((u32)*(u8 *)(p2 + 0x3f1) & 1) == 0) {
                fn_80137948(sNotOnGroundFailureMessage);
                continue;
            }
            ok = 1;
            break;
        case 3:
        case 5: {
            u8 b = *(u8 *)(p2 + 0x3f0);
            if ((u32)b >> 3 & 1 || (u32)b >> 2 & 1) {
                ok = 1;
            }
            useAlt = 1;
            break;
        }
        case 2: {
            u8 b2;
            if (((u32)*(u8 *)(p2 + 0x3f1) & 1) == 0) {
                u8 b = *(u8 *)(p2 + 0x3f0);
                if (((u32)b >> 3 & 1) == 0 && ((u32)b >> 2 & 1) == 0) {
                    continue;
                }
            }
            b2 = *(u8 *)(p2 + 0x3f0);
            if ((u32)b2 >> 3 & 1 || (u32)b2 >> 2 & 1) {
                ok = 1;
            }
            break;
        }
        case 4:
        case 6: {
            u8 b2;
            if (((u32)*(u8 *)(p2 + 0x3f1) & 1) == 0) {
                u8 b = *(u8 *)(p2 + 0x3f0);
                if (((u32)b >> 3 & 1) == 0 && ((u32)b >> 2 & 1) == 0) {
                    continue;
                }
            }
            b2 = *(u8 *)(p2 + 0x3f0);
            if ((u32)b2 >> 3 & 1 || (u32)b2 >> 2 & 1) {
                ok = 1;
            }
            break;
        }
        case 11:
            flagB = 0;
            ok = 1;
            break;
        }
        if (ok == 0) {
            if (*(f32 *)(p3 + 0x298) < lbl_803E7EFC) {
                continue;
            }
        }
        if (useAlt == 0) {
            if (ok == 0) {
                end[0] = *(f32 *)(obj + 0xc) + sc1[0];
                end[1] = *(f32 *)(obj + 0x10) + sc1[1];
                end[2] = *(f32 *)(obj + 0x14) + sc1[2];
                dir = rot;
            } else {
                end[0] = *(f32 *)(obj + 0xc) + sc0[0];
                end[1] = *(f32 *)(obj + 0x10) + sc0[1];
                end[2] = *(f32 *)(obj + 0x14) + sc0[2];
                dir = vec;
            }
            start[0] = *(f32 *)(obj + 0xc);
            start[1] = *(f32 *)(obj + 0x10);
            start[2] = *(f32 *)(obj + 0x14);
        } else {
            if (ok == 0) {
                start[0] = *(f32 *)(obj + 0xc) + sc1[0];
                start[1] = *(f32 *)(obj + 0x10) + sc1[1];
                start[2] = *(f32 *)(obj + 0x14) + sc1[2];
                dir = rot;
            } else {
                start[0] = *(f32 *)(obj + 0xc) + sc0[0];
                start[1] = *(f32 *)(obj + 0x10) + sc0[1];
                start[2] = *(f32 *)(obj + 0x14) + sc0[2];
                dir = vec;
            }
            end[0] = *(f32 *)(obj + 0xc);
            end[1] = *(f32 *)(obj + 0x10);
            end[2] = *(f32 *)(obj + 0x14);
        }
        hit = objBboxFn_800640cc(lbl_803E7EA4, start, end, 3, &buf, obj, 1, dirs[i], 0xff, 10);
        if (flagA != 0 && hit != 0) {
            *(f32 *)(p2 + 0x778) = buf.dist;
        }
        if (flagB != 0 && hit != 0) {
            dp = buf.nx * dir[0] + buf.ny * dir[1] + buf.nz * dir[2];
            switch (i) {
            case 3:
            case 5:
                if (*(f32 *)(obj + 0x10) < lbl_803E7F10 + buf.minY &&
                    *(f32 *)(obj + 0x10) < lbl_803E7F10 + buf.maxY) {
                    hit = 0;
                }
                break;
            case 2:
            case 4:
            case 6:
                if (((u32)*(u8 *)(p2 + 0x3f1) & 1) != 0) {
                    if (dp > lbl_803E8090 ||
                        (*(f32 *)(obj + 0x10) > buf.g3c - lbl_803E7ED8 &&
                         *(f32 *)(obj + 0x10) > buf.g40 - lbl_803E7ED8)) {
                        hit = 0;
                    }
                } else {
                    if (dp > lbl_803E8094) {
                        hit = 0;
                    }
                }
                break;
            case 0:
            case 10:
                break;
            default:
                if (dp > lbl_803E8090) {
                    hit = 0;
                }
            }
        }
        if (flagB != 0 && hit != 0) {
            if (useAlt == 0) {
                start[0] = *(f32 *)(obj + 0xc);
                start[1] = *(f32 *)(obj + 0x10);
                start[2] = *(f32 *)(obj + 0x14);
                end[0] = -(lbl_803E808C * buf.nx - *(f32 *)(obj + 0xc));
                end[1] = *(f32 *)(obj + 0x10);
                end[2] = -(lbl_803E808C * buf.nz - *(f32 *)(obj + 0x14));
            } else {
                start[0] = lbl_803E808C * buf.nx + *(f32 *)(obj + 0xc);
                start[1] = *(f32 *)(obj + 0x10);
                start[2] = lbl_803E808C * buf.nz + *(f32 *)(obj + 0x14);
                end[0] = *(f32 *)(obj + 0xc);
                end[1] = *(f32 *)(obj + 0x10);
                end[2] = *(f32 *)(obj + 0x14);
            }
            hit = objBboxFn_800640cc(lbl_803E7EA4, start, end, 3, &buf, obj, 1, dirs[i], 0xff,
                                     10);
        }
        if (hit == 0) {
            continue;
        }
        hd = buf.dist;
        if (useAlt != 0) {
            hd = lbl_803E808C - hd;
        }
        switch (i) {
        case 0: {
            int t = buf.hitObj;
            if ((u32)t == 0) {
                continue;
            }
            if ((*(int (*)(int))*(int *)((char *)*(int *)(t + 0x68) + 0x2c))(t) != 0 &&
                *(f32 *)(p3 + 0x298) > lbl_803E7EFC &&
                hd <= lbl_803E7ED4 + lbl_803DC6C0) {
                switch (((int (*)(int, int, void *, int, f32 *, f32))fn_802A8EE4)(
                    obj, p2, &buf, p2 + 0x5a8, end, hd)) {
                case 2:
                    return 4;
                case 3:
                    return 5;
                }
            }
            if (hd >= lbl_803E7FA4) {
                continue;
            }
            if (*(u8 *)(t + 0xaf) & 8) {
                continue;
            }
            *(u32 *)(p2 + 0x360) |= 0x100;
            if ((*(int *)(p3 + 0x31c) & 0x100) == 0) {
                continue;
            }
            *(f32 *)(p2 + 0x654) = buf.nx;
            *(f32 *)(p2 + 0x658) = buf.ny;
            *(f32 *)(p2 + 0x65c) = buf.nz;
            *(f32 *)(p2 + 0x660) = buf.g38;
            *(u8 *)(p2 + 0x681) = 0;
            if ((u32)buf.hitObj != 0) {
                Obj_TransformWorldPointToLocal((f32 *)(p2 + 0x664), (f32 *)(p2 + 0x668),
                                               (f32 *)(p2 + 0x66c), buf.hitObj, end[0], end[1],
                                               end[2]);
                *(int *)(p2 + 0x67c) = buf.hitObj;
            } else {
                *(f32 *)(p2 + 0x664) = end[0];
                *(f32 *)(p2 + 0x668) = end[1];
                *(f32 *)(p2 + 0x66c) = end[2];
                *(int *)(p2 + 0x67c) = 0;
            }
            return 6;
        }
        case 10:
            if (hd >= lbl_803E8098) {
                continue;
            }
            if ((*(int *)(p3 + 0x31c) & 0x100) == 0) {
                continue;
            }
            *(f32 *)(p2 + 0x654) = buf.nx;
            *(f32 *)(p2 + 0x658) = buf.ny;
            *(f32 *)(p2 + 0x65c) = buf.nz;
            *(f32 *)(p2 + 0x660) = buf.g38;
            *(u8 *)(p2 + 0x681) = 0;
            if ((u32)buf.hitObj != 0) {
                Obj_TransformWorldPointToLocal((f32 *)(p2 + 0x664), (f32 *)(p2 + 0x668),
                                               (f32 *)(p2 + 0x66c), buf.hitObj, end[0], end[1],
                                               end[2]);
                *(int *)(p2 + 0x67c) = buf.hitObj;
            } else {
                *(f32 *)(p2 + 0x664) = end[0];
                *(f32 *)(p2 + 0x668) = end[1];
                *(f32 *)(p2 + 0x66c) = end[2];
                *(int *)(p2 + 0x67c) = 0;
            }
            return 0xd;
        case 3:
        case 4:
            if (hd > lbl_803E7F58) {
                continue;
            }
            if (fn_802A8350(obj, p2, (int)&buf, p2 + 0x4e4, i == 3) == 0) {
                continue;
            }
            return 0;
        case 5:
        case 6:
            if (hd > lbl_803E7EE0 + lbl_803DC6C0) {
                continue;
            }
            if (fn_802A8680(obj, p2, (int)&buf, (int)end, p2 + 0x548, i == 5) == 0) {
                continue;
            }
            return 9;
        case 1:
        case 7:
        case 12:
            if (hd >= lbl_803E7F58) {
                continue;
            }
            switch (fn_802A87CC(obj, (char *)&buf, (f32 *)(p2 + 0x5a8), end, hd, fv)) {
            case 4:
                return 8;
            case 5:
                return 7;
            }
            break;
        case 2:
        case 9:
            if (hd > lbl_803E7EE0 + lbl_803DC6C0) {
                continue;
            }
            switch (((int (*)(int, int, void *, int, f32 *, f32))fn_802A8EE4)(obj, p2, &buf,
                                                                              p2 + 0x5a8, end,
                                                                              hd)) {
            case 2:
                return 4;
            case 3:
                return 5;
            case 6:
                return 0xc;
            }
            break;
        case 8: {
            s8 ok2;
            int t8;
            if (hd > lbl_803E7EE0 + lbl_803DC6C0) {
                continue;
            }
            nearDist = lbl_803E808C;
            t8 = ObjGroup_FindNearestObject(0x23, obj, &nearDist);
            ok2 = 1;
            if ((u32)t8 != 0) {
                if ((*(u8 (*)(int))*(int *)((char *)*(int *)(t8 + 0x68) + 0x24))(t8) == 0) {
                    ok2 = 0;
                }
            }
            if (ok2 == 0) {
                continue;
            }
            *(f32 *)(p2 + 0x60c) = buf.nx;
            *(f32 *)(p2 + 0x610) = buf.ny;
            *(f32 *)(p2 + 0x614) = buf.nz;
            *(f32 *)(p2 + 0x618) = buf.nw;
            return 0xb;
        }
        case 11:
            if (hd >= lbl_803E809C) {
                continue;
            }
            if (buf.kind == 0xd) {
                int k;
                if (*(f32 *)(p3 + 0x280) <= lbl_803E80A0) {
                    continue;
                }
                if (*(f32 *)(p2 + 0x878) <= lbl_803E7EA4) {
                    for (k = 0; k < 0x4b; k++) {
                        f32 lo;
                        lo = buf.minX;
                        pfx.x = lo + (buf.maxX - lo) * (f32)randomGetRange(0, 100) /
                                         lbl_803E7F5C;
                        lo = buf.minY;
                        pfx.y = lo + (buf.g3c - lo) * (f32)randomGetRange(0, 100) /
                                         lbl_803E7F5C;
                        lo = buf.minZ;
                        pfx.z = lo + (buf.maxZ - lo) * (f32)randomGetRange(0, 100) /
                                         lbl_803E7F5C;
                        pfx.scale = lbl_803E7EE0;
                        pfx.mode = 0x3c;
                        (**(void (**)(int, int, void *, int, int, int))(
                            (char *)(*gPartfxInterface) + 0x8))(obj, 0x804, &pfx, 0x200001, -1,
                                                                0);
                    }
                    *(f32 *)(p2 + 0x878) = lbl_803E7F30;
                }
            } else {
                ObjPath_GetPointWorldPosition(obj, 0xb, &pfx.x, &pfx.y, &pfx.z, 0);
                ((void (*)(int, int, int, int, int, f32, f32, f32))ObjHits_RecordPositionHit)(
                    obj, 0, 8, 1, -1, pfx.x, pfx.y, pfx.z);
            }
            break;
        }
    }
    if ((*(int *)(p3 + 0x31c) & 0x100) != 0 && (mask & 0x200) != 0) {
        int *objs = (int *)ObjGroup_GetObjects(10, &objCount);
        int k2;
        for (k2 = 0; k2 < objCount; k2++) {
            int cur = *objs;
            if ((*(int (*)(int, int))*(int *)((char *)*(int *)(cur + 0x68) + 0x20))(cur, obj) !=
                0) {
                *(int *)(p2 + 0x7f0) = cur;
                return 0xa;
            }
            objs++;
        }
    }
    return -1;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802ABAE8(int obj, int state, int inner, f32 fv)
{
    int d = *(s16 *)((char *)inner + 0x478) - (u16)*(s16 *)((char *)inner + 0x492);
    int near;
    int g;
    if (d > 0x8000) d -= 0xffff;
    if (d < -0x8000) d += 0xffff;
    if ((((u32)*(u8 *)((char *)inner + 0x3f1) >> 5) & 1) || (((u32)*(u8 *)((char *)inner + 0x3f0) >> 4) & 1)) {
        d = 0;
    }
    {
        f32 f2 = lbl_803E7E98 * (*(f32 *)((char *)state + 0x294) - lbl_803E7E9C) + lbl_803E7EE0;
        if (f2 < lbl_803E7EA4) {
            f2 = lbl_803E7EA4;
        }
        d = (int)((f32)(int)d * (lbl_803E7FC4 * f2));
        if (d < -0xccc) {
            d = -0xccc;
        } else if (d > 0xccc) {
            d = 0xccc;
        }
    }
    {
        int e = d - (u16)*(s16 *)((char *)inner + 0x4d0);
        if (e > 0x8000) e -= 0xffff;
        if (e < -0x8000) e += 0xffff;
        *(s16 *)((char *)inner + 0x4d0) = (int)((f32)(int)*(s16 *)((char *)inner + 0x4d0) +
            interpolate((f32)(int)e, lbl_803E7EB4, timeDelta));
    }
    near = fn_802AB1D0(obj);
    if (near != 0 && (((u32)*(u8 *)((char *)inner + 0x3f0) >> 7) & 1) == 0 &&
        (((u32)*(u8 *)((char *)inner + 0x3f0) >> 6) & 1) == 0 &&
        (((u32)*(u8 *)((char *)inner + 0x3f0) >> 4) & 1) == 0 &&
        (((u32)*(u8 *)((char *)inner + 0x3f0) >> 5) & 1) == 0) {
        int gd = (u16)getAngle(-(*(f32 *)((char *)near + 0xc) - *(f32 *)((char *)obj + 0xc)),
                               -(*(f32 *)((char *)near + 0x14) - *(f32 *)((char *)obj + 0x14))) -
                 (u16)*(s16 *)((char *)inner + 0x478);
        f32 t;
        f32 c;
        f32 f5;
        f32 lo;
        f32 hi;
        f32 fd;
        if (gd > 0x8000) gd -= 0xffff;
        if (gd < -0x8000) gd += 0xffff;
        t = lbl_803E7EE0 - (*(f32 *)((char *)state + 0x294) - lbl_803E7E9C) /
                              (*(f32 *)((char *)inner + 0x404) - lbl_803E7E9C);
        if (t >= lbl_803E7EA4) {
            if (t > lbl_803E7EE0) {
                c = lbl_803E7EE0;
            } else {
                c = t;
            }
        } else {
            c = lbl_803E7EA4;
        }
        f5 = lbl_803E80C4 * c + lbl_803E80F4;
        lo = lbl_803E80F8 * -f5;
        hi = lbl_803E80F8 * f5;
        fd = (f32)(int)gd;
        if (fd >= lo) {
            if (fd <= hi) {
                fd = (f32)(int)gd;
            } else {
                fd = hi;
            }
        } else {
            fd = lo;
        }
        g = (int)fd;
    } else {
        g = 0;
    }
    {
        int r0;
        int h;
        if ((((u32)*(u8 *)((char *)inner + 0x3f1) >> 5) & 1) ||
            (((u32)*(u8 *)((char *)inner + 0x3f0) >> 4) & 1)) {
            r0 = 0;
        } else {
            r0 = *(int *)((char *)inner + 0x480);
        }
        if (r0 < -0x28) {
            r0 = -0x28;
        } else if (r0 > 0x28) {
            r0 = 0x28;
        }
        h = g + r0 * 0xb6;
        if (h < -0x3ffc) {
            h = -0x3ffc;
        } else if (h > 0x3ffc) {
            h = 0x3ffc;
        }
        h = h - (u16)*(s16 *)((char *)inner + 0x4d4);
        if (h > 0x8000) h -= 0xffff;
        if (h < -0x8000) h += 0xffff;
        h = (int)((f32)(int)h * lbl_803E7EB4);
        if (h < -0x16c) {
            h = -0x16c;
        } else if (h > 0x16c) {
            h = 0x16c;
        }
        *(s16 *)((char *)inner + 0x4d4) = (int)((f32)(int)h * timeDelta +
            (f32)(int)*(s16 *)((char *)inner + 0x4d4));
        *(s16 *)((char *)inner + 0x4d2) = *(s16 *)((char *)inner + 0x4d4) / 2;
    }
    {
        int k = (int)(lbl_803E80F8 * (lbl_803E7ED8 * -fv)) - (u16)*(s16 *)((char *)inner + 0x4d6);
        if (k > 0x8000) k -= 0xffff;
        if (k < -0x8000) k += 0xffff;
        *(s16 *)((char *)inner + 0x4d6) = *(s16 *)((char *)inner + 0x4d6) + k;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_80296EB4(int obj, int newParent)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int oldParent = *(int *)((char *)obj + 0x30);
    struct {
        f32 wp0[3];
        f32 wv[3];
        f32 wp2[3];
        f32 wp[3];
    } s;
    int a0;
    int a1;
    int a2;
    int a3;
    int a4;
    int a5;

    if ((void *)oldParent == (void *)newParent) {
        return;
    }
    if ((void *)oldParent != NULL) {
        Obj_TransformLocalPointToWorld(&s.wp[0], &s.wp[1], &s.wp[2], oldParent,
                                       *(f32 *)((char *)obj + 0xc), *(f32 *)((char *)obj + 0x10),
                                       *(f32 *)((char *)obj + 0x14));
        Obj_TransformLocalPointToWorld(&s.wp2[0], &s.wp2[1], &s.wp2[2], oldParent,
                                       *(f32 *)((char *)obj + 0x80), *(f32 *)((char *)obj + 0x84),
                                       *(f32 *)((char *)obj + 0x88));
        Obj_TransformLocalVectorToWorld(&s.wv[0], &s.wv[1], &s.wv[2], oldParent,
                                        *(f32 *)((char *)obj + 0x24), lbl_803E7EA4,
                                        *(f32 *)((char *)obj + 0x2c));
        a0 = Angle_AddWrappedS16(*(s16 *)((char *)obj + 0x0), oldParent);
        a1 = Angle_AddWrappedS16(*(s16 *)((char *)inner + 0x478), oldParent);
        a2 = Angle_AddWrappedS16(*(s16 *)((char *)inner + 0x484), oldParent);
        a3 = Angle_AddWrappedS16(*(s16 *)((char *)inner + 0x492), oldParent);
        a4 = Angle_AddWrappedS16(*(s16 *)((char *)inner + 0x490), oldParent);
        a5 = Angle_AddWrappedS16(*(int *)((char *)inner + 0x494), oldParent);
        Obj_TransformLocalPointToWorld(&s.wp0[0], &s.wp0[1], &s.wp0[2], oldParent,
                                       *(f32 *)((char *)inner + 0x118), *(f32 *)((char *)inner + 0x11c),
                                       *(f32 *)((char *)inner + 0x120));
    } else {
        s.wp[0] = *(f32 *)((char *)obj + 0xc);
        s.wp[1] = *(f32 *)((char *)obj + 0x10);
        s.wp[2] = *(f32 *)((char *)obj + 0x14);
        s.wp2[0] = *(f32 *)((char *)obj + 0x80);
        s.wp2[1] = *(f32 *)((char *)obj + 0x84);
        s.wp2[2] = *(f32 *)((char *)obj + 0x88);
        s.wv[0] = *(f32 *)((char *)obj + 0x24);
        s.wv[2] = *(f32 *)((char *)obj + 0x2c);
        a0 = *(s16 *)((char *)obj + 0x0);
        a1 = *(s16 *)((char *)inner + 0x478);
        a2 = *(s16 *)((char *)inner + 0x484);
        a3 = *(s16 *)((char *)inner + 0x492);
        a4 = *(s16 *)((char *)inner + 0x490);
        a5 = *(int *)((char *)inner + 0x494);
        s.wp0[0] = *(f32 *)((char *)inner + 0x118);
        s.wp0[1] = *(f32 *)((char *)inner + 0x11c);
        s.wp0[2] = *(f32 *)((char *)inner + 0x120);
    }
    if ((void *)newParent != NULL) {
        Obj_TransformWorldPointToLocal((f32 *)((char *)obj + 0xc), (f32 *)((char *)obj + 0x10),
                                       (f32 *)((char *)obj + 0x14), newParent, s.wp[0], s.wp[1], s.wp[2]);
        Obj_TransformWorldPointToLocal((f32 *)((char *)obj + 0x80), (f32 *)((char *)obj + 0x84),
                                       (f32 *)((char *)obj + 0x88), newParent, s.wp2[0], s.wp2[1], s.wp2[2]);
        Obj_TransformWorldVectorToLocal((f32 *)((char *)obj + 0x24), &s.wv[1],
                                        (f32 *)((char *)obj + 0x2c), newParent, s.wv[0], lbl_803E7EA4, s.wv[2]);
        *(s16 *)((char *)obj + 0x0) = Angle_SubWrappedS16(a0, newParent);
        *(s16 *)((char *)inner + 0x478) = Angle_SubWrappedS16(a1, newParent);
        *(s16 *)((char *)inner + 0x484) = Angle_SubWrappedS16(a2, newParent);
        *(s16 *)((char *)inner + 0x492) = Angle_SubWrappedS16(a3, newParent);
        *(s16 *)((char *)inner + 0x490) = Angle_SubWrappedS16(a4, newParent);
        *(int *)((char *)inner + 0x494) = Angle_SubWrappedS16(a5, newParent);
        Obj_TransformWorldPointToLocal((f32 *)((char *)inner + 0x118), (f32 *)((char *)inner + 0x11c),
                                       (f32 *)((char *)inner + 0x120), newParent, s.wp0[0], s.wp0[1], s.wp0[2]);
    } else {
        *(f32 *)((char *)obj + 0xc) = s.wp[0];
        *(f32 *)((char *)obj + 0x10) = s.wp[1];
        *(f32 *)((char *)obj + 0x14) = s.wp[2];
        *(f32 *)((char *)obj + 0x80) = s.wp2[0];
        *(f32 *)((char *)obj + 0x84) = s.wp2[1];
        *(f32 *)((char *)obj + 0x88) = s.wp2[2];
        *(f32 *)((char *)obj + 0x24) = s.wv[0];
        *(f32 *)((char *)obj + 0x2c) = s.wv[2];
        *(s16 *)((char *)obj + 0x0) = a0;
        *(s16 *)((char *)inner + 0x478) = a1;
        *(s16 *)((char *)inner + 0x484) = a2;
        *(s16 *)((char *)inner + 0x492) = a3;
        *(s16 *)((char *)inner + 0x490) = a4;
        *(int *)((char *)inner + 0x494) = a5;
        *(f32 *)((char *)inner + 0x118) = s.wp0[0];
        *(f32 *)((char *)inner + 0x11c) = s.wp0[1];
        *(f32 *)((char *)inner + 0x120) = s.wp0[2];
    }
    *(f32 *)((char *)obj + 0x18) = s.wp[0];
    *(f32 *)((char *)obj + 0x1c) = s.wp[1];
    *(f32 *)((char *)obj + 0x20) = s.wp[2];
    *(f32 *)((char *)obj + 0x8c) = s.wp2[0];
    *(f32 *)((char *)obj + 0x90) = s.wp2[1];
    *(f32 *)((char *)obj + 0x94) = s.wp2[2];
    *(f32 *)((char *)*(int *)((char *)obj + 0x54) + 0x10) = *(f32 *)((char *)obj + 0xc);
    *(f32 *)((char *)*(int *)((char *)obj + 0x54) + 0x14) = *(f32 *)((char *)obj + 0x10);
    *(f32 *)((char *)*(int *)((char *)obj + 0x54) + 0x18) = *(f32 *)((char *)obj + 0x14);
    *(f32 *)((char *)*(int *)((char *)obj + 0x54) + 0x1c) = *(f32 *)((char *)obj + 0x18);
    *(f32 *)((char *)*(int *)((char *)obj + 0x54) + 0x20) = *(f32 *)((char *)obj + 0x1c);
    *(f32 *)((char *)*(int *)((char *)obj + 0x54) + 0x24) = *(f32 *)((char *)obj + 0x20);
    *(int *)((char *)obj + 0x30) = newParent;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802A8680(int p1, int p2, int src, int vec, int out, int flag)
{
    f32 d1;
    f32 d2;
    f32 nx;
    f32 ny;
    *(f32 *)((char *)out + 0x44) = *(f32 *)((char *)vec + 0x0);
    *(f32 *)((char *)out + 0x48) = *(f32 *)((char *)src + 0xc);
    *(f32 *)((char *)out + 0x4c) = *(f32 *)((char *)vec + 0x8);
    *(f32 *)((char *)out + 0x50) = *(f32 *)((char *)p2 + 0x768);
    *(f32 *)((char *)out + 0x54) = lbl_803E7EA4;
    *(f32 *)((char *)out + 0x58) = *(f32 *)((char *)p2 + 0x770);
    if (flag != 0) {
        *(u8 *)((char *)out + 0x1) = 1;
    } else {
        *(u8 *)((char *)out + 0x1) = 0;
    }
    *(f32 *)((char *)out + 0x24) = *(f32 *)((char *)src + 0x1c);
    *(f32 *)((char *)out + 0x28) = *(f32 *)((char *)src + 0x20);
    *(f32 *)((char *)out + 0x2c) = *(f32 *)((char *)src + 0x24);
    *(f32 *)((char *)out + 0x30) = *(f32 *)((char *)src + 0x28);
    *(f32 *)((char *)out + 0x34) = -*(f32 *)((char *)src + 0x24);
    *(f32 *)((char *)out + 0x38) = lbl_803E7EA4;
    *(f32 *)((char *)out + 0x3c) = *(f32 *)((char *)src + 0x1c);
    *(f32 *)((char *)out + 0x40) = *(f32 *)((char *)out + 0x48) * *(f32 *)((char *)out + 0x38) +
                                       *(f32 *)((char *)out + 0x44) * *(f32 *)((char *)out + 0x34) -
                                   *(f32 *)((char *)out + 0x4c) * *(f32 *)((char *)out + 0x3c);
    nx = -*(f32 *)((char *)out + 0x2c);
    ny = *(f32 *)((char *)out + 0x24);
    d1 = (ny * *(f32 *)((char *)src + 0x14) - nx * *(f32 *)((char *)src + 0x4)) +
         (ny * *(f32 *)((char *)out + 0x4c) +
          (nx * *(f32 *)((char *)out + 0x44) + *(f32 *)((char *)out + 0x38) * *(f32 *)((char *)out + 0x48)));
    nx = -nx;
    ny = -ny;
    d2 = (ny * *(f32 *)((char *)src + 0x18) - nx * *(f32 *)((char *)src + 0x8)) +
         (ny * *(f32 *)((char *)out + 0x4c) +
          (nx * *(f32 *)((char *)out + 0x44) + *(f32 *)((char *)out + 0x38) * *(f32 *)((char *)out + 0x48)));
    if (d1 > lbl_803E80BC && d2 > lbl_803E80BC) {
        *(f32 *)((char *)out + 0x8) = *(f32 *)((char *)src + 0xc);
        *(f32 *)((char *)out + 0x4) = *(f32 *)((char *)src + 0x3c);
        *(s8 *)((char *)out + 0x2) = *(s8 *)((char *)src + 0x53);
        return 1;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_8029ABD8(int obj, int state, f32 fv)
{
    int inner = *(int *)((char *)obj + 0xb8);
    struct {
        u8 pad[6];
        u16 mode;
        f32 scale;
        f32 x;
        f32 y;
        f32 z;
    } pfx;

    if (lbl_803DE42C != 0) {
        Sfx_KeepAliveLoopedObjectSound(obj, 0x382);
        *(f32 *)((char *)inner + 0x854) = *(f32 *)((char *)inner + 0x854) - timeDelta;
        if (*(f32 *)((char *)inner + 0x854) <= lbl_803E7EA4) {
            int sub = *(int *)((char *)*(int *)((char *)obj + 0xb8) + 0x35c);
            int v = *(s16 *)((char *)sub + 0x4) - 1;
            if (v < 0) {
                v = 0;
            } else if (v > *(s16 *)((char *)sub + 0x6)) {
                v = *(s16 *)((char *)sub + 0x6);
            }
            *(s16 *)((char *)sub + 0x4) = v;
            *(f32 *)((char *)inner + 0x854) = lbl_803E7F58;
        }
        ObjPath_GetPointWorldPosition(lbl_803DE44C, 5, &pfx.x, &pfx.y, &pfx.z, 0);
        pfx.scale = lbl_803E7F9C;
        pfx.mode = 0;
        (**(void (**)(int, int, void *, int, int, int))((char *)(*gPartfxInterface) + 0x8))(
            (int)lbl_803DE44C, 0x7f5, &pfx, 0x200001, -1, 0);
        pfx.mode = 1;
        (**(void (**)(int, int, void *, int, int, int))((char *)(*gPartfxInterface) + 0x8))(
            (int)lbl_803DE44C, 0x7f5, &pfx, 0x200001, -1, 0);
        if ((*(u16 *)((char *)inner + 0x6e0) & lbl_803DE4B4) == 0 ||
            *(s16 *)((char *)*(int *)((char *)*(int *)((char *)obj + 0xb8) + 0x35c) + 0x4) == 0 ||
            getCurSeqNo() != 0) {
            void **p = lbl_80332ED4;
            int i;
            *(s16 *)((char *)inner + 0x80a) = -1;
            lbl_803DE42C = 0;
            for (i = 0; i < 7; i++) {
                if (*p != NULL) {
                    Obj_FreeObject((int)*p);
                    *p = NULL;
                }
                p++;
            }
            if (lbl_803DE454 != NULL) {
                Resource_Release(lbl_803DE454);
                lbl_803DE454 = NULL;
            }
        }
    } else if (*(s16 *)((char *)inner + 0x80e) != -1 || (*(u16 *)((char *)inner + 0x6e2) & 0x800) != 0) {
        int yitem;
        int b28;
        s16 item;
        if (*(u16 *)((char *)inner + 0x6e2) & 0x800) {
            yitem = getYButtonItem(&item);
            b28 = 0x800;
        } else {
            yitem = 0;
            item = *(s16 *)((char *)inner + 0x80e);
            b28 = 0x100;
        }
        if (*(s16 *)((char *)inner + 0x80e) != -1 ||
            (yitem == 1 && (item == 0x2d || item == 0x5ce))) {
            buttonDisable(0, 0x900);
            *(s16 *)((char *)inner + 0x6e2) = *(u16 *)((char *)inner + 0x6e2) & ~0x900;
            lbl_803DE4B2 = item;
            if (item != *(s16 *)((char *)inner + 0x80a)) {
                fn_802AB38C(obj, inner, item);
            }
            switch (lbl_803DE4B2) {
            case 0x2d: {
                int sub = *(int *)((char *)*(int *)((char *)obj + 0xb8) + 0x35c);
                if (*(s16 *)((char *)sub + 0x4) >= 2) {
                    int r = fn_8029A76C(obj, state, fv);
                    if (r != 0) {
                        return r;
                    }
                } else {
                    Sfx_PlayFromObject(0, SFXsp_skeep_mumb1);
                }
                break;
            }
            case 0x958: {
                int sub = *(int *)((char *)*(int *)((char *)obj + 0xb8) + 0x35c);
                if (*(s16 *)((char *)sub + 0x4) >= 0) {
                    int r = ((int (*)(int, int, f32))fn_8029A5E4)(obj, state, fv);
                    if (r != 0) {
                        return r;
                    }
                } else {
                    Sfx_PlayFromObject(0, SFXsp_skeep_mumb1);
                }
                break;
            }
            case 0x5ce: {
                int sub = *(int *)((char *)*(int *)((char *)obj + 0xb8) + 0x35c);
                if (*(s16 *)((char *)sub + 0x4) >= 1) {
                    int sub2;
                    int v;
                    ((void (*)(int))fn_802A96D8)(obj);
                    lbl_803DE4B4 = b28;
                    lbl_803DE42C = 1;
                    lbl_803DE430 = lbl_803E7EA4;
                    *(f32 *)((char *)inner + 0x854) = lbl_803E7F58;
                    sub2 = *(int *)((char *)*(int *)((char *)obj + 0xb8) + 0x35c);
                    v = *(s16 *)((char *)sub2 + 0x4) - 1;
                    if (v < 0) {
                        v = 0;
                    } else if (v > *(s16 *)((char *)sub2 + 0x6)) {
                        v = *(s16 *)((char *)sub2 + 0x6);
                    }
                    *(s16 *)((char *)sub2 + 0x4) = v;
                }
                break;
            }
            }
        }
    }
    *(s16 *)((char *)inner + 0x80a) = -1;
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_8029AF9C(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int r;
    f32 spin;
    struct {
        u8 pad[6];
        u16 mode;
        f32 scale;
        f32 x;
        f32 y;
        f32 z;
    } pfx;

    r = ((int (*)(int, int, int))fn_802AC7DC)(obj, state, inner);
    if (r != 0) {
        return r;
    }
    {
        f32 z = lbl_803E7EA4;
        *(f32 *)((char *)state + 0x294) = z;
        *(f32 *)((char *)state + 0x284) = z;
        *(f32 *)((char *)state + 0x280) = z;
        *(f32 *)((char *)obj + 0x24) = z;
        *(f32 *)((char *)obj + 0x28) = z;
        *(f32 *)((char *)obj + 0x2c) = z;
    }
    *(int *)((char *)inner + 0x360) |= 0x2000000;
    setAButtonIcon(6);
    setBButtonIcon(0xa);
    switch (*(s16 *)((char *)obj + 0xa0)) {
    case 0x43e: {
        f32 t;
        f32 c;
        f32 a;
        t = *(f32 *)((char *)state + 0x28c) / lbl_803E7FA8;
        c = (t < lbl_803E7ECC) ? lbl_803E7ECC : ((t > lbl_803E7EE0) ? lbl_803E7EE0 : t);
        *(f32 *)((char *)inner + 0x7bc) =
            *(f32 *)((char *)inner + 0x7bc) +
            interpolate(c - *(f32 *)((char *)inner + 0x7bc), lbl_803E7EFC, timeDelta);
        t = *(f32 *)((char *)state + 0x290) / lbl_803E7FA8;
        c = (t < lbl_803E7ECC) ? lbl_803E7ECC : ((t > lbl_803E7EE0) ? lbl_803E7EE0 : t);
        *(f32 *)((char *)inner + 0x7b8) =
            *(f32 *)((char *)inner + 0x7b8) +
            interpolate(c - *(f32 *)((char *)inner + 0x7b8), lbl_803E7EFC, timeDelta);
        if (*(f32 *)((char *)inner + 0x7b8) > lbl_803E7EA4) {
            spin = *(f32 *)((char *)inner + 0x7b8) - lbl_803E7EA0;
            if (spin < lbl_803E7EA4) {
                spin = lbl_803E7EA4;
            }
        } else {
            spin = lbl_803E7EA0 + *(f32 *)((char *)inner + 0x7b8);
            if (spin > lbl_803E7EA4) {
                spin = lbl_803E7EA4;
            }
        }
        a = *(f32 *)((char *)inner + 0x7bc);
        if (a > lbl_803E7EA4) {
            Object_ObjAnimSetSecondaryBlendMove((ObjAnimComponent *)obj, 0x441,
                                                (int)(lbl_803E7FAC * a));
        } else {
            Object_ObjAnimSetSecondaryBlendMove((ObjAnimComponent *)obj, 0x440,
                                                (int)(lbl_803E7FAC * -a));
        }
        *(s16 *)((char *)inner + 0x4d2) = lbl_803E7FB0 * *(f32 *)((char *)inner + 0x7b8);
        objModelGetVecFn_800395d8(obj, 9);
        *(int *)((char *)inner + 0x360) &= ~0x400;
        if (lbl_803DE4B2 == 0x2d) {
            f32 bv;
            f32 av;
            int res;
            int half;
            int low;
            f32 k;
            av = *(f32 *)((char *)inner + 0x7bc);
            bv = *(f32 *)((char *)inner + 0x7b8);
            res = getScreenResolution();
            half = res >> 17;
            low = (res & 0xffff) >> 1;
            k = lbl_803E7E98;
            *(f32 *)((char *)inner + 0x788) =
                k * (bv * (f32)(int)low) + (f32)(int)low;
            if (av < lbl_803E7EA4) {
                *(f32 *)((char *)inner + 0x78c) =
                    k * (av * (f32)(int)half) + (f32)(int)half;
            } else {
                *(f32 *)((char *)inner + 0x78c) =
                    lbl_803E7F44 * (av * (f32)(int)half) + (f32)(int)half;
            }
            *(int *)((char *)inner + 0x360) |= 0x400;
        }
        if (lbl_803DE42C != 0) {
            f32 x;
            int hi;
            Sfx_KeepAliveLoopedObjectSound(obj, 0x382);
            x = *(f32 *)((char *)inner + 0x854) - timeDelta;
            *(f32 *)((char *)inner + 0x854) = x;
            if (x <= lbl_803E7EA4) {
                int sub = *(int *)((char *)*(int *)((char *)obj + 0xb8) + 0x35c);
                int v = *(s16 *)((char *)sub + 0x4) - 1;
                if (v < 0) {
                    v = 0;
                } else if (v > *(s16 *)((char *)sub + 0x6)) {
                    v = *(s16 *)((char *)sub + 0x6);
                }
                *(s16 *)((char *)sub + 0x4) = v;
                *(f32 *)((char *)inner + 0x854) = lbl_803E7F58;
            }
            ObjPath_GetPointWorldPosition(lbl_803DE44C, 5, &pfx.x, &pfx.y, &pfx.z, 0);
            pfx.scale = lbl_803E7F9C;
            hi = 0x200000;
            pfx.mode = 0;
            (**(void (**)(int, int, void *, int, int, int))((char *)(*gPartfxInterface) + 0x8))(
                (int)lbl_803DE44C, 0x7f5, &pfx, hi + 1, -1, 0);
            pfx.mode = 1;
            (**(void (**)(int, int, void *, int, int, int))((char *)(*gPartfxInterface) + 0x8))(
                (int)lbl_803DE44C, 0x7f5, &pfx, hi + 1, -1, 0);
            if ((*(u16 *)((char *)inner + 0x6e0) & lbl_803DE4B4) == 0 ||
                *(s16 *)((char *)*(int *)((char *)*(int *)((char *)obj + 0xb8) + 0x35c) + 0x4) == 0 ||
                getCurSeqNo() != 0) {
                int i;
                void **p;
                lbl_803DE42C = 0;
                i = 0;
                p = lbl_80332ED4;
                for (; i < 7; i++) {
                    if (*p != NULL) {
                        Obj_FreeObject((int)*p);
                        *p = NULL;
                    }
                    p++;
                }
                if (lbl_803DE454 != NULL) {
                    Resource_Release(lbl_803DE454);
                    lbl_803DE454 = NULL;
                }
            }
        } else if ((*(u16 *)((char *)inner + 0x6e2) & 0x900) != 0) {
            int yitem;
            u16 b28;
            s16 item;
            if (*(u16 *)((char *)inner + 0x6e2) & 0x800) {
                yitem = getYButtonItem(&item);
                b28 = 0x800;
            } else {
                yitem = 0;
                item = lbl_803DE4B2;
                b28 = 0x100;
            }
            if ((*(u16 *)((char *)inner + 0x6e2) & 0x100) != 0 ||
                (yitem == 1 && (item == 0x2d || item == 0x5ce))) {
                buttonDisable(0, 0x900);
                *(u16 *)((char *)inner + 0x6e2) = *(u16 *)((char *)inner + 0x6e2) & ~0x900;
                lbl_803DE4B2 = item;
                if (item != *(s16 *)((char *)inner + 0x80a)) {
                    fn_802AB38C(obj, inner, item);
                }
                switch (lbl_803DE4B2) {
                case 0x2d: {
                    int sub = *(int *)((char *)*(int *)((char *)obj + 0xb8) + 0x35c);
                    if (*(s16 *)((char *)sub + 0x4) >= 2) {
                        *(int *)((char *)state + 0x308) = (int)fn_8029A4A8;
                        return 0x2f;
                    }
                    Sfx_PlayFromObject(0, 0x40c);
                    break;
                }
                case 0x958: {
                    int sub = *(int *)((char *)*(int *)((char *)obj + 0xb8) + 0x35c);
                    if (*(s16 *)((char *)sub + 0x4) >= 0) {
                        *(int *)((char *)state + 0x308) = (int)fn_8029A4A8;
                        return 0x30;
                    }
                    Sfx_PlayFromObject(0, 0x40c);
                    break;
                }
                case 0x5ce: {
                    int sub = *(int *)((char *)*(int *)((char *)obj + 0xb8) + 0x35c);
                    if (*(s16 *)((char *)sub + 0x4) >= 1) {
                        int sub2;
                        int v;
                        ((void (*)(int))fn_802A96D8)(obj);
                        lbl_803DE4B4 = b28;
                        lbl_803DE42C = 1;
                        lbl_803DE430 = lbl_803E7EA4;
                        *(f32 *)((char *)inner + 0x854) = lbl_803E7F58;
                        sub2 = *(int *)((char *)*(int *)((char *)obj + 0xb8) + 0x35c);
                        v = *(s16 *)((char *)sub2 + 0x4) - 1;
                        if (v < 0) {
                            v = 0;
                        } else if (v > *(s16 *)((char *)sub2 + 0x6)) {
                            v = *(s16 *)((char *)sub2 + 0x6);
                        }
                        *(s16 *)((char *)sub2 + 0x4) = v;
                        break;
                    }
                    Sfx_PlayFromObject(0, 0x40c);
                    break;
                }
                }
            }
        }
        *(s16 *)((char *)inner + 0x478) =
            lbl_803E7FB4 * spin + (f32)(int)*(s16 *)((char *)inner + 0x478);
        {
            s16 v = *(s16 *)((char *)inner + 0x478);
            *(s16 *)((char *)inner + 0x484) = v;
            *(s16 *)((char *)obj + 0x0) = v;
        }
        break;
    }
    default:
        ObjAnim_SetCurrentMove(obj, 0x43e, lbl_803E7EA4, 0);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7F34;
        lbl_803DE42C = 0;
        lbl_803DE430 = lbl_803E7EA4;
        break;
    }
    if ((*(u16 *)((char *)inner + 0x6e2) & 0x200) != 0 || *(u8 *)((char *)inner + 0x8c8) != 0x52) {
        *(int *)((char *)inner + 0x360) &= ~0x2000000;
        *(int *)((char *)state + 0x308) = (int)fn_8029A420;
        return 0x2c;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
typedef struct {
    s16 f00;
    s16 moveIdx;
    u8 pad04[0x10];
    u8 f14;
    u8 f15[7];
    f32 f1c;
    f32 f20;
    f32 f24;
    f32 f28;
    f32 f2c;
    f32 f30[3];
    f32 f3c[3];
    f32 f48;
    f32 f4c;
    f32 f50;
    f32 f54;
    u8 pad58[4];
    u8 f5c;
    s8 f5d[3];
    u8 f60[8];
    f32 f68;
    u8 f6c;
    u8 pad6d[0x1b];
    u8 f88;
    u8 pad89[3];
    f32 f8c;
    u8 f90;
    u8 pad91[0xf];
    f32 fa0;
    f32 fa4;
    u8 pada8[8];
} PMSlot;

extern f32 lbl_803E7FB8;
int fn_8029BDB4(int obj, int state, f32 fv)
{
    int r;
    u8 changed;
    int path;
    int inner = *(int *)((char *)obj + 0xb8);
    f32 amt;

    r = fn_8029B9FC(obj, state, fv);
    if (r != 0) {
        return r;
    }
    path = (int)lbl_803DE44C;
    *(s8 *)((char *)state + 0x34d) = 1;
    lbl_803DC66C = 5;
    if (*(s8 *)((char *)state + 0x27a) == 0) {
        if (lbl_803DE459 != 0) {
            doRumble(lbl_803E7ED8);
            *(int *)((char *)state + 0x308) = 0;
            return 0x28;
        }
        changed = 0;
        if (*(f32 *)((char *)state + 0x2a0) > lbl_803E7EA4) {
            if ((*(int *)((char *)state + 0x314) & 0x200) != 0) {
                doRumble(lbl_803E7F10);
                Sfx_PlayFromObject(obj, 0x3cd);
                *(u16 *)((char *)inner + 0x8d8) = *(u16 *)((char *)inner + 0x8d8) | 4;
            }
            if ((*(int *)((char *)state + 0x314) & 0x400) != 0) {
                doRumble(lbl_803E7F10);
                Sfx_PlayFromObject(obj, 0x3cd);
                *(u16 *)((char *)inner + 0x8d8) = *(u16 *)((char *)inner + 0x8d8) | 4;
            }
            if ((*(u8 *)((char *)state + 0x356) & 1) == 0 &&
                *(f32 *)((char *)obj + 0x98) >
                    ((f32 *)(*(int *)((char *)inner + 0x3dc) + (u32)*(u8 *)((char *)inner + 0x8a9) * 0xb0))[0x14]) {
                u16 sfx;
                if (*(s16 *)((char *)inner + 0x81a) == 0) {
                    sfx = 0x2de;
                } else {
                    sfx = 0x1c;
                }
                Sfx_PlayFromObject(obj, sfx);
                *(u8 *)((char *)state + 0x356) = *(u8 *)((char *)state + 0x356) | 1;
            }
            if ((*(u8 *)((char *)state + 0x356) & 2) == 0 &&
                *(f32 *)((char *)obj + 0x98) >
                    ((f32 *)(*(int *)((char *)inner + 0x3dc) + (u32)*(u8 *)((char *)inner + 0x8a9) * 0xb0))[0x15]) {
                Sfx_PlayFromObject(obj, 0x1a);
                *(u8 *)((char *)state + 0x356) = *(u8 *)((char *)state + 0x356) | 2;
            }
        }
        {
            int slot = *(int *)((char *)inner + 0x3dc) + (u32)*(u8 *)((char *)inner + 0x8a9) * 0xb0;
            if (*(s8 *)(slot + 0x15) >= 0) {
                if (*(f32 *)((char *)obj + 0x98) > *(f32 *)(slot + 0x28)) {
                    *(u8 *)((char *)state + 0x34a) = *(u8 *)((char *)state + 0x34a) | 2;
                    if (((u8 *)(*(int *)((char *)inner + 0x3dc) + (u32)*(u8 *)((char *)inner + 0x8a9) * 0xb0))[0x6c] != 0) {
                        *(u8 *)((char *)state + 0x34a) = *(u8 *)((char *)state + 0x34a) | 4;
                        *(u8 *)((char *)inner + 0x8c0) = 0;
                    }
                }
                if (*(f32 *)((char *)obj + 0x98) >
                    ((f32 *)(*(int *)((char *)inner + 0x3dc) + (u32)*(u8 *)((char *)inner + 0x8a9) * 0xb0))[0x8]) {
                    *(u8 *)((char *)state + 0x34a) = *(u8 *)((char *)state + 0x34a) | 1;
                }
                if (*(f32 *)((char *)obj + 0x98) >
                    ((f32 *)(*(int *)((char *)inner + 0x3dc) + (u32)*(u8 *)((char *)inner + 0x8a9) * 0xb0))[0x9]) {
                    *(u8 *)((char *)state + 0x34a) = *(u8 *)((char *)state + 0x34a) & ~1;
                }
                if ((*(int *)((char *)state + 0x31c) & 0x100) != 0 &&
                    (*(u8 *)((char *)state + 0x34a) & 1) != 0) {
                    *(u8 *)((char *)state + 0x34a) = *(u8 *)((char *)state + 0x34a) | 4;
                    *(int *)((char *)state + 0x31c) = *(int *)((char *)state + 0x31c) & ~0x100;
                    buttonDisable(0, 0x100);
                    *(u8 *)((char *)inner + 0x8c0) = *(u8 *)((char *)state + 0x34b);
                }
                if ((*(u8 *)((char *)state + 0x34a) & 4) != 0 &&
                    (*(u8 *)((char *)state + 0x34a) & 2) != 0) {
                    f32 v = (f32)(u8)fn_8014C4D8(*(int *)((char *)state + 0x2d0));
                    int slot2 = *(int *)((char *)inner + 0x3dc) +
                                (u32)*(u8 *)((char *)inner + 0x8a9) * 0xb0;
                    if (v >= *(f32 *)(slot2 + 0x8c)) {
                        *(u8 *)((char *)inner + 0x8a9) =
                            *(u8 *)(slot2 + (u32)*(u8 *)((char *)inner + 0x8c0) + 0x15);
                    } else {
                        *(u8 *)((char *)inner + 0x8a9) = *(u8 *)(slot2 + 0x90);
                    }
                    changed = 1;
                }
            }
        }
    } else {
        lbl_803DE459 = 0;
        changed = 1;
        *(int *)((char *)inner + 0x360) &= ~0x40;
        *(u8 *)((char *)*(int *)((char *)obj + 0x54) + 0x70) = 0;
        {
            f32 z = lbl_803E7EA4;
            *(f32 *)((char *)inner + 0x828) = z;
            *(u8 *)((char *)inner + 0x8ab) = 0;
            *(int *)((char *)inner + 0x4c0) = 0;
            *(s8 *)((char *)inner + 0x8cd) = -1;
            *(f32 *)((char *)state + 0x294) = z;
            *(f32 *)((char *)state + 0x284) = z;
            *(f32 *)((char *)state + 0x280) = z;
            *(f32 *)((char *)obj + 0x24) = z;
            *(f32 *)((char *)obj + 0x28) = z;
            *(f32 *)((char *)obj + 0x2c) = z;
        }
    }
    if (*(void **)((char *)state + 0x2d0) != NULL) {
        if (*(u8 *)((char *)inner + 0x8a9) >= 5 && *(u8 *)((char *)inner + 0x8a9) <= 9) {
            amt = (f32)*(int *)((char *)inner + 0x4a4);
        } else {
            amt = (f32)*(int *)((char *)inner + 0x4a4) / lbl_803E7FB8;
        }
        *(s16 *)((char *)inner + 0x478) = (f32)(int)*(s16 *)((char *)inner + 0x478) + amt;
        *(s16 *)((char *)inner + 0x484) = *(s16 *)((char *)inner + 0x478);
    } else if (*(s8 *)((char *)state + 0x27a) != 0 && *(void **)((char *)inner + 0x4b8) != NULL &&
               *(u16 *)((char *)inner + 0x4b4) == 1) {
        if (*(int *)((char *)inner + 0x4a8) < 0x4000) {
            amt = (f32)*(int *)((char *)inner + 0x4a4);
        }
        *(s16 *)((char *)inner + 0x478) = (f32)(int)*(s16 *)((char *)inner + 0x478) + amt;
        *(s16 *)((char *)inner + 0x484) = *(s16 *)((char *)inner + 0x478);
    } else if (*(s8 *)((char *)state + 0x27a) != 0) {
        s16 v = *(int *)((char *)inner + 0x474);
        *(s16 *)((char *)inner + 0x478) = v;
        *(s16 *)((char *)inner + 0x484) = v;
    }
    if (changed != 0) {
        *(int *)((char *)obj + 0x5c) = *(int *)((char *)inner + 0x3dc) +
                                       ((u32)*(u8 *)((char *)inner + 0x8a9) * 0xb0 + 0x60);
        {
            int slot = *(int *)((char *)inner + 0x3dc) + (u32)*(u8 *)((char *)inner + 0x8a9) * 0xb0;
            if (*(s16 *)((char *)obj + 0xa0) != lbl_803336BC[*(s16 *)(slot + 0x2)]) {
                ObjAnim_SetCurrentMove(obj, lbl_803336BC[*(s16 *)(slot + 0x2)],
                                       *(f32 *)(slot + 0x68), 0);
                ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent *)obj, 2);
            }
        }
        *(u8 *)((char *)state + 0x34a) = *(u8 *)((char *)state + 0x34a) & ~0xef;
        *(f32 *)((char *)state + 0x2a0) = ((f32 *)(*(int *)((char *)inner + 0x3dc) + (u32)*(u8 *)((char *)inner + 0x8a9) * 0xb0))[0x7];
        *(f32 *)((char *)inner + 0x824) = *(f32 *)((char *)state + 0x2a0);
        *(u8 *)((char *)inner + 0x8cf) = 0;
        *(f32 *)((char *)state + 0x284) = lbl_803E7EA4;
        *(u8 *)((char *)state + 0x356) = 0;
        if (*(void **)((char *)state + 0x2d0) != NULL) {
            if (*(u8 *)((char *)inner + 0x8a9) >= 5 && *(u8 *)((char *)inner + 0x8a9) <= 9) {
                (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x30)))(obj, state, fv, 1);
            } else {
                (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x30)))(obj, state, fv, 2);
            }
            {
                s16 v = *(s16 *)((char *)obj + 0x0);
                *(s16 *)((char *)inner + 0x484) = v;
                *(s16 *)((char *)inner + 0x478) = v;
            }
        }
        if (*(void **)((char *)obj + 0x54) != NULL) {
            *(u8 *)((char *)*(int *)((char *)obj + 0x54) + 0x70) = 0;
        }
        *(s8 *)((char *)inner + 0x8cd) = -1;
        if (*(s16 *)((char *)path + 0x44) == 0x2d) {
            objSetAnimField48to0((int *)path);
            (*(void (*)(int, int))*(int *)(*(int *)(*(int *)((char *)path + 0x68)) + 0x38))(
                path, ((u8 *)(*(int *)((char *)inner + 0x3dc) + (u32)*(u8 *)((char *)inner + 0x8a9) * 0xb0))[0x5c]);
            {
                int slot = *(int *)((char *)inner + 0x3dc) +
                           (u32)*(u8 *)((char *)inner + 0x8a9) * 0xb0;
                (*(void (*)(int, f32, f32))*(int *)(*(int *)(*(int *)((char *)path + 0x68)) + 0x4c))(
                    path, *(f32 *)(slot + 0x48), *(f32 *)(slot + 0x4c));
            }
        }
        {
            f32 z = lbl_803E7EA4;
            *(f32 *)((char *)inner + 0x7d8) = z;
            *(f32 *)((char *)inner + 0x828) = z;
            *(u8 *)((char *)inner + 0x8ab) = 0;
            *(int *)((char *)inner + 0x4c0) = 0;
        }
    }
    *(u8 *)((char *)*(int *)((char *)obj + 0x54) + 0x6e) = 0xb;
    *(u8 *)((char *)*(int *)((char *)obj + 0x54) + 0x6f) =
        ((u8 *)(*(int *)((char *)inner + 0x3dc) + (u32)*(u8 *)((char *)inner + 0x8a9) * 0xb0))[0x14];
    {
        int slot = *(int *)((char *)inner + 0x3dc) + (u32)*(u8 *)((char *)inner + 0x8a9) * 0xb0;
        f32 t = *(f32 *)(slot + 0xa0);
        if (t >= lbl_803E7EA4) {
            if (t >= *(f32 *)((char *)obj + 0x98) ||
                *(f32 *)((char *)obj + 0x98) >= *(f32 *)(slot + 0xa4)) {
                *(f32 *)((char *)inner + 0x7d8) = lbl_803E7EA4;
            } else {
                if (*(f32 *)((char *)inner + 0x7d8) == lbl_803E7EA4) {
                    Sfx_PlayFromObject(obj, 0x21b);
                }
                *(f32 *)((char *)inner + 0x7d8) =
                    lbl_803E7ED4 * timeDelta + *(f32 *)((char *)inner + 0x7d8);
                if (*(f32 *)((char *)inner + 0x7d8) > lbl_803E7FBC) {
                    *(f32 *)((char *)inner + 0x7d8) = lbl_803E7FBC;
                }
            }
        }
    }
    if ((((u8 *)(*(int *)((char *)inner + 0x3dc) + (u32)*(u8 *)((char *)inner + 0x8a9) * 0xb0))[0x88] &
         2) != 0 &&
        *(int *)((char *)inner + 0x4c0) != 0) {
        if (*(u8 *)((char *)inner + 0x8ab) < *(u8 *)((char *)inner + 0x8ac)) {
            f32 t = *(f32 *)((char *)inner + 0x828) - lbl_803E7EE0;
            *(f32 *)((char *)inner + 0x828) = t;
            if (t <= lbl_803E7EA4) {
                ((void (*)(int, int, int, int, int))ObjHits_RecordObjectHit)(
                    *(int *)((char *)inner + 0x4c0), obj, 0xb, 1, 0);
                *(s8 *)((char *)inner + 0x8ab) = *(s8 *)((char *)inner + 0x8ab) + 1;
                *(f32 *)((char *)inner + 0x828) = (f32)(u8)*(u8 *)((char *)inner + 0x8ad);
            }
        } else {
            *(int *)((char *)inner + 0x4c0) = 0;
        }
    }
    {
        int off;
        int i;
        int n;
        off = 0;
        *(int *)((char *)*(int *)((char *)obj + 0x54) + 0x48) = 0;
        i = 0;
        n = 3;
        do {
            int stride = (u32)*(u8 *)((char *)inner + 0x8a9) * 0xb0;
            int ent = *(int *)((char *)inner + 0x3dc) + stride + off;
            if (*(f32 *)((char *)obj + 0x98) >= *(f32 *)(ent + 0x30) &&
                *(f32 *)((char *)obj + 0x98) <= *(f32 *)(ent + 0x3c)) {
                if (*(s8 *)((char *)*(int *)((char *)obj + 0x54) + 0x70) == 0) {
                    int bits;
                    switch (*(s8 *)((char *)*(int *)((char *)inner + 0x3dc) + stride + i + 0x5d)) {
                    case -1:
                        bits = 0;
                        break;
                    case 0:
                        bits = 0xc;
                        break;
                    case 1:
                        bits = 3;
                        break;
                    case 4:
                        bits = 0xf;
                        break;
                    case 2:
                        bits = 0x100000;
                        break;
                    case 3:
                        bits = 0x10000;
                        break;
                    default:
                        bits = 0;
                        break;
                    }
                    *(int *)((char *)*(int *)((char *)obj + 0x54) + 0x48) = bits;
                }
                if (i != *(s8 *)((char *)inner + 0x8cd)) {
                    *(u8 *)((char *)*(int *)((char *)obj + 0x54) + 0x70) = 0;
                    *(s8 *)((char *)inner + 0x8cd) = (s8)i;
                    *(u8 *)((char *)inner + 0x8ab) = 0;
                    *(f32 *)((char *)inner + 0x828) = lbl_803E7EA4;
                    *(int *)((char *)inner + 0x4c0) = 0;
                }
                break;
            }
            off += 4;
            i++;
            n--;
        } while (n != 0);
    }
    (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x20)))(obj, state, fv, 3);
    if (*(s8 *)((char *)state + 0x346) == 0) {
        if (*(f32 *)((char *)obj + 0x98) >=
            ((f32 *)(*(int *)((char *)inner + 0x3dc) + (u32)*(u8 *)((char *)inner + 0x8a9) * 0xb0))[0xb]) {
            if (*(void **)((char *)state + 0x2d0) == NULL) {
                if ((*(int *)((char *)state + 0x31c) & 0x100) != 0 &&
                    *(f32 *)((char *)state + 0x298) > lbl_803E7EAC) {
                    *(s16 *)((char *)inner + 0x478) =
                        *(s16 *)((char *)inner + 0x478) + (s16)*(int *)((char *)inner + 0x480) * 0xb6;
                    *(s16 *)((char *)inner + 0x484) = *(s16 *)((char *)inner + 0x478);
                    *(int *)((char *)inner + 0x47c) = 0;
                    *(int *)((char *)inner + 0x480) = 0;
                    *(int *)((char *)inner + 0x488) = 0;
                    *(int *)((char *)inner + 0x48c) = 0;
                    *(int *)((char *)state + 0x308) = 0;
                    return 0x32;
                }
            } else if ((*(int *)((char *)state + 0x31c) & 0x100) != 0) {
                *(u8 *)((char *)*(int *)((char *)obj + 0x54) + 0x70) = 0;
                *(s8 *)((char *)inner + 0x8cd) = -1;
                (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x30)))(obj, state, fv, 2);
                {
                    s16 v = *(s16 *)((char *)obj + 0x0);
                    *(s16 *)((char *)inner + 0x484) = v;
                    *(s16 *)((char *)inner + 0x478) = v;
                }
                *(int *)((char *)state + 0x308) = 0;
                return 0x31;
            }
        }
        return 0;
    } else {
        *(u8 *)((char *)*(int *)((char *)obj + 0x54) + 0x70) = 0;
        if (*(void **)((char *)state + 0x2d0) == NULL) {
            *(u8 *)((char *)inner + 0x3f1) = (*(u8 *)((char *)inner + 0x3f1) & 0x7f) | 0x80;
            *(int *)((char *)inner + 0x360) |= 0x800000;
            *(int *)((char *)state + 0x308) = (int)fn_802A514C;
            return 2;
        }
        *(int *)((char *)state + 0x308) = (int)fn_8029C8C8;
        return 0x25;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802977A8(int obj, int state)
{
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        ObjAnim_SetCurrentMove(obj, 0xe, lbl_803E7EA4, 0);
        *(s8 *)((char *)state + 0x346) = 0;
    }
    *(f32 *)((char *)state + 0x2a0) = lbl_803E7F08;
    if (*(s8 *)((char *)state + 0x346) != 0) {
        *(int *)((char *)state + 0x308) = 0;
        return 0x41;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_8029D454(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);
    *(u8 *)((char *)state + 0x34d) = 3;
    if (*(s8 *)((char *)*(int *)((char *)inner + 0x35c)) > 0) {
        ObjAnim_SetCurrentMove(obj, 0xc8, lbl_803E7EA4, 0);
        *(int *)((char *)state + 0x308) = 0;
        return -0x21;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_8029B994(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);
    u32 b;
    if ((*(int *)((char *)state + 0x31c) & 0x100) != 0) {
        b = (*(u8 *)((char *)inner + 0x3f4) >> 6) & 1;
        if (b != 0) {
            if (lbl_803DE44C != NULL && b != 0) {
                *(u8 *)((char *)inner + 0x8b4) = 4;
                ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 1;
            }
            *(int *)((char *)state + 0x308) = 0;
            return 0x32;
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_8029EBCC(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);
    void *sub;
    f32 v7b8, v7bc;
    int res, halfW, halfH;

    *(int *)((char *)inner + 0x360) &= 0xFFFFFFFD;
    ObjHits_EnableObject(obj);
    sub = *(void **)((char *)inner + 0x7f0);
    if (sub == NULL) {
        f32 z = lbl_803E7EA4;
        *(f32 *)((char *)state + 0x294) = z;
        *(f32 *)((char *)state + 0x284) = z;
        *(f32 *)((char *)state + 0x280) = z;
        *(f32 *)((char *)obj + 0x24) = z;
        *(f32 *)((char *)obj + 0x28) = z;
        *(f32 *)((char *)obj + 0x2c) = z;
        ObjHits_EnableObject(obj);
    } else {
        if (*(s16 *)((char *)sub + 0x46) != 0x714) {
            ObjHits_DisableObject(obj);
        }
    }
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        f32 z = lbl_803E7EA4;
        *(f32 *)((char *)inner + 0x7b8) = z;
        *(f32 *)((char *)inner + 0x7bc) = z;
        (*(void (*)(int, int, int, int, int, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
            0x53, 1, sub != NULL ? 0x12 : -2, 0, 0, 0, 0xff);
        ObjAnim_SetCurrentMove(obj, 0x43e, lbl_803E7EA4, 0);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7F34;
        *(f32 *)((char *)inner + 0x418) = lbl_803E7EA4;
        if (lbl_803DE44C != NULL) {
            if ((*(u8 *)((char *)inner + 0x3f4) >> 6 & 1) != 0) {
                *(u8 *)((char *)inner + 0x8b4) = 4;
                *(u8 *)((char *)inner + 0x3f4) |= 8;
            }
        }
    }
    if (*(u8 *)((char *)obj + 0x36) > 1) {
        *(u8 *)((char *)obj + 0x36) = 1;
    }
    *(f32 *)((char *)inner + 0x418) = *(f32 *)((char *)inner + 0x418) - timeDelta;
    if (*(f32 *)((char *)inner + 0x418) < lbl_803E7EA4) {
        *(f32 *)((char *)inner + 0x418) = lbl_803E7EA4;
    }
    if ((*(u16 *)((char *)inner + 0x6e2) & 0x100) != 0) {
        if (*(f32 *)((char *)inner + 0x418) <= lbl_803E7EA4) {
            buttonDisable(0, 0x100);
            ((void (*)(int, int, f32, f32))fn_802AA014)(obj, state, *(f32 *)((char *)inner + 0x7bc), lbl_803E7EA4);
            *(f32 *)((char *)inner + 0x418) = lbl_803E7F10;
        }
    }
    {
        f32 x = *(f32 *)((char *)state + 0x28c) / lbl_803E7FA8;
        f32 c;
        void *hit;
        if (x >= lbl_803E7FF0) {
            if (x <= lbl_803E7FC4) {
                c = x;
            } else {
                c = lbl_803E7FC4;
            }
        } else {
            c = lbl_803E7FF0;
        }
        hit = *(void **)((char *)inner + 0x7f0);
        if (hit != NULL && *(s16 *)((char *)hit + 0x46) == 0x484) {
            c = c + lbl_803DC6E0;
        }
        if (hit == NULL) {
            c = c + lbl_803DC6E4;
        }
        *(f32 *)((char *)inner + 0x7bc) +=
            interpolate(c - *(f32 *)((char *)inner + 0x7bc), lbl_803DC6D4, timeDelta);
    }
    {
        f32 x = *(f32 *)((char *)state + 0x290) / lbl_803E7FA8;
        f32 c;
        if (x >= lbl_803E7ECC) {
            if (x <= lbl_803E7EE0) {
                c = x;
            } else {
                c = lbl_803E7EE0;
            }
        } else {
            c = lbl_803E7ECC;
        }
        *(f32 *)((char *)inner + 0x7b8) +=
            interpolate(c - *(f32 *)((char *)inner + 0x7b8), lbl_803DC6D8, timeDelta);
    }
    {
        f32 d = *(f32 *)((char *)inner + 0x7b8);
        if (d > lbl_803E7EA4) {
            d = d - lbl_803E7EA0;
            if (d < lbl_803E7EA4) {
                d = lbl_803E7EA4;
            }
        } else {
            d = lbl_803E7EA0 + d;
            if (d > lbl_803E7EA4) {
                d = lbl_803E7EA4;
            }
        }
        *(s16 *)((char *)inner + 0x478) =
            (int)(lbl_803E7FB4 * d * lbl_803DC6DC + (f32)*(s16 *)((char *)inner + 0x478));
        *(s16 *)((char *)inner + 0x484) = *(s16 *)((char *)inner + 0x478);
    }
    if (*(f32 *)((char *)inner + 0x7bc) > lbl_803E7EA4) {
        ((void (*)(int, int, f32, int))Object_ObjAnimSetSecondaryBlendMove)(obj, 0x441, lbl_803E7EA4,
            (int)(lbl_803E7FAC * *(f32 *)((char *)inner + 0x7bc)));
    } else {
        ((void (*)(int, int, f32, int))Object_ObjAnimSetSecondaryBlendMove)(obj, 0x440, lbl_803E7FAC,
            (int)(lbl_803E7FAC * -*(f32 *)((char *)inner + 0x7bc)));
    }
    *(s16 *)((char *)inner + 0x4d0) =
        (int)((f32)*(s16 *)((char *)inner + 0x4d0) * powfBitEstimate(lbl_803E7FF4, timeDelta));
    *(s16 *)((char *)inner + 0x4d6) =
        (int)((f32)*(s16 *)((char *)inner + 0x4d6) * powfBitEstimate(lbl_803E7F1C, timeDelta));
    *(s16 *)((char *)inner + 0x4d2) = (int)(lbl_803E7FB0 * *(f32 *)((char *)inner + 0x7b8));
    *(s16 *)((char *)inner + 0x4d4) = (s16)(*(s16 *)((char *)inner + 0x4d2) >> 1);
    *(int *)((char *)inner + 0x360) &= 0xFFFFFBFF;
    v7bc = *(f32 *)((char *)inner + 0x7bc);
    v7b8 = *(f32 *)((char *)inner + 0x7b8);
    res = getScreenResolution();
    halfW = res >> 17;
    halfH = (int)(u16)res >> 1;
    *(f32 *)((char *)inner + 0x788) = lbl_803E7E98 * (v7b8 * (f32)halfH) + (f32)halfH;
    if (v7bc < lbl_803E7EA4) {
        *(f32 *)((char *)inner + 0x78c) = lbl_803E7E98 * (v7bc * (f32)halfW) + (f32)halfW;
    } else {
        *(f32 *)((char *)inner + 0x78c) = lbl_803E7F44 * (v7bc * (f32)halfW) + (f32)halfW;
    }
    *(int *)((char *)inner + 0x360) |= 0x400;
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_8029F108(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int sub = *(int *)((char *)inner + 0x7f0);
    void *vec;
    int kind;
    int joint;
    int n;
    f32 t;
    f32 pos1[3];
    f32 pos2[3];
    s16 ang[3];
    f32 localPt;
    f32 cam[3];

    if (*(s8 *)((char *)state + 0x27a) != 0) {
        *(s16 *)((char *)state + 0x278) = 0x19;
        *(int *)((char *)inner + 0x898) = 0;
    }
    {
        int inner2 = *(int *)((char *)obj + 0xb8);
        *(int *)((char *)inner2 + 0x360) &= ~0x2;
        *(int *)((char *)inner2 + 0x360) |= 0x2000;
    }
    *(int *)((char *)state + 0x4) |= 0x100000;
    {
        f32 z = lbl_803E7EA4;
        *(f32 *)((char *)state + 0x280) = z;
        *(f32 *)((char *)state + 0x284) = z;
        *(int *)((char *)state + 0x0) |= 0x200000;
        *(f32 *)((char *)obj + 0x24) = z;
        *(f32 *)((char *)obj + 0x2c) = z;
    }
    *(u8 *)((char *)state + 0x25f) = 0;
    ObjHits_DisableObject(obj);
    *(f32 *)((char *)obj + 0x28) = lbl_803E7EA4;
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        (*(void (*)(int, void *, void *, void *))(*(int *)(*(int *)*(int *)((char *)sub + 0x68) + 0x28)))(
            sub, (char *)obj + 0xc, (char *)obj + 0x10, (char *)obj + 0x14);
        if (*(s16 *)((char *)sub + 0x46) == 0x38c || *(s16 *)((char *)sub + 0x46) == 0x72) {
            (*(void (*)(int, int, int, int, int, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
                0x42, 0, 1, 0, 0, 0x64, 0xff);
        } else {
            (*(void (*)(int, int, int))(*(int *)(*gCameraInterface + 0x24)))(0, 1, 0);
        }
        kind = (*(int (*)(int))(*(int *)(*(int *)*(int *)((char *)sub + 0x68) + 0x30)))(sub);
        (*(void (*)(int, int))(*(int *)(*(int *)*(int *)((char *)sub + 0x68) + 0x3c)))(sub, 3);
        if (kind >= 2) {
            n = 9;
        } else if (kind >= 1) {
            n = 8;
        } else {
            n = 9;
        }
        *(s16 *)((char *)inner + 0x478) = *(s16 *)((char *)sub + 0x0);
        *(s16 *)((char *)inner + 0x484) = *(s16 *)((char *)inner + 0x478);
        *(s16 *)((char *)obj + 0x2) = 0;
        *(s16 *)((char *)obj + 0x4) = 0;
        ObjAnim_SetCurrentMove(obj, ((s16 *)*(int *)((char *)inner + 0x6e8))[n], lbl_803E7EA4, 1);
        joint = ((int *)*(int *)((char *)obj + 0x7c))[*(s8 *)((char *)obj + 0xad)];
        ObjModel_SampleJointTransform(joint, 0, 0, lbl_803E7EA4, *(f32 *)((char *)obj + 0x8), pos1, ang);
        ObjModel_SampleJointTransform(joint, 0, 0, lbl_803E7EE0, *(f32 *)((char *)obj + 0x8), pos2, ang);
        ang[0] = *(s16 *)((char *)inner + 0x478);
        ang[1] = 0;
        ang[2] = 0;
        mathFn_80021ac8(ang, pos2);
        pos2[0] = pos2[0] + *(f32 *)((char *)obj + 0xc);
        pos2[2] = pos2[2] + *(f32 *)((char *)obj + 0x14);
        *(f32 *)((char *)obj + 0x10) = *(f32 *)((char *)obj + 0x10) - pos1[1];
        t = (*(f32 (*)(int, f32, f32, f32, f32))(*(int *)(*gPathControlInterface + 0x24)))(
            obj, pos2[0], *(f32 *)((char *)obj + 0x10), pos2[2], lbl_803E7FA4);
        *(f32 *)((char *)inner + 0x6b4) = pos2[0];
        *(f32 *)((char *)inner + 0x6b8) = t;
        *(f32 *)((char *)inner + 0x6bc) = pos2[2];
        *(f32 *)((char *)inner + 0x6c4) = *(f32 *)((char *)obj + 0x10) - t;
        *(u8 *)((char *)inner + 0x6cc) = (u8)kind;
        *(s16 *)((char *)obj + 0x6) &= ~0x8;
        *(s16 *)((char *)obj + 0xa2) = -1;
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7FE8;
    }
    t = lbl_803E7EE0 - *(f32 *)((char *)obj + 0x98);
    *(f32 *)((char *)obj + 0x10) =
        *(f32 *)((char *)inner + 0x6c4) * t + *(f32 *)((char *)inner + 0x6b8);
    vec = objModelGetVecFn_800395d8(obj, 5);
    if (vec != NULL) {
        *(s16 *)vec = (int)((f32)*(s16 *)((char *)sub + 0x2) * t);
        *(s16 *)((char *)vec + 0x4) = (int)((f32)*(s16 *)((char *)sub + 0x4) * t);
    }
    (*(void (*)(int, f32 *, f32 *, f32 *))(*(int *)(*(int *)*(int *)((char *)sub + 0x68) + 0x34)))(
        sub, &cam[0], &cam[1], &cam[2]);
    {
        f32 w = *(f32 *)((char *)obj + 0x98);
        f32 cx = w * (*(f32 *)((char *)inner + 0x6b4) - cam[0]) + cam[0];
        f32 cy = w * (*(f32 *)((char *)inner + 0x6b8) - cam[1]) + cam[1];
        f32 cz = w * (*(f32 *)((char *)inner + 0x6bc) - cam[2]) + cam[2];
        (*(void (*)(f32, f32, f32))(*(int *)(*gCameraInterface + 0x2c)))(cx, cy, cz);
    }
    if (*(s8 *)((char *)state + 0x27a) == 0 && *(s8 *)((char *)state + 0x346) != 0) {
        if (vec != NULL) {
            *(s16 *)vec = 0;
            *(s16 *)((char *)vec + 0x4) = 0;
        }
        *(int *)(*(int *)((char *)obj + 0x64) + 0x30) &= ~0x1000;
        *(f32 *)((char *)obj + 0x18) = *(f32 *)((char *)inner + 0x768);
        *(f32 *)((char *)obj + 0x20) = *(f32 *)((char *)inner + 0x770);
        if (*(void **)((char *)obj + 0x30) != NULL) {
            *(f32 *)((char *)obj + 0x18) += playerMapOffsetX;
            *(f32 *)((char *)obj + 0x20) += playerMapOffsetZ;
        }
        Obj_TransformWorldPointToLocal((f32 *)((char *)obj + 0xc), &localPt, (f32 *)((char *)obj + 0x14),
            *(int *)((char *)obj + 0x30), *(f32 *)((char *)obj + 0x18), lbl_803E7EA4,
            *(f32 *)((char *)obj + 0x20));
        if (*(u8 *)((char *)inner + 0x6cc) == 1) {
            *(s16 *)((char *)inner + 0x478) += 0x4000;
            *(s16 *)((char *)inner + 0x484) = *(s16 *)((char *)inner + 0x478);
        } else {
            *(s16 *)((char *)inner + 0x478) -= 0x4000;
            *(s16 *)((char *)inner + 0x484) = *(s16 *)((char *)inner + 0x478);
        }
        ObjAnim_SetCurrentMove(obj, 0, lbl_803E7EA4, 1);
        ((void (*)(int, int, int, int))ObjAnim_WriteStateWord)
            (obj, OBJANIM_STATE_INDEX_CURRENT, OBJANIM_STATE_WORD_EVENT_COUNTDOWN, 0);
        (*(void (*)(int, int))(*(int *)(*(int *)*(int *)((char *)sub + 0x68) + 0x3c)))(sub, 0);
        fn_802AB5A4(obj, inner, 7);
        ObjHits_EnableObject(obj);
        *(int *)((char *)inner + 0x7f0) = 0;
        *(int *)((char *)state + 0x308) = (int)fn_802A514C;
        return 2;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_8029DA60(int obj, int state)
{
    *(u8 *)((char *)state + 0x34d) = 3;
    *(f32 *)((char *)state + 0x2a0) = lbl_803E7FD8;
    *(f32 *)((char *)state + 0x280) = lbl_803E7EA4;
    (*(void (*)(int, int, int))(*(int *)(*gPlayerInterface + 0x20)))(obj, state, 2);
    if (*(s8 *)((char *)state + 0x346) != 0) {
        *(int *)((char *)state + 0x308) = (int)fn_802A514C;
        return 2;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802A7160(int obj, int state)
{
    if (GameBit_Get(0x970)) {
        GameBit_Set(0x970, 0);
        (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(0x10, obj, -1);
    }
    *(int *)((char *)state + 0x308) = (int)fn_802A514C;
    return 2;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_8029BC08(int obj)
{
    *(int *)((char *)*(int *)((char *)obj + 0x54) + 0x48) = 0;
    if (*(s16 *)((char *)lbl_803DE44C + 0x44) == 0x2d) {
        objSetAnimField48to0((int *)lbl_803DE44C);
    }
    lbl_803DC66C = 1;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_8029F67C(int obj)
{
    int m = *(int *)((char *)obj + 0x64);
    s16 *v;
    *(int *)((char *)m + 0x30) &= ~0x1000;
    *(s16 *)((char *)obj + 0x6) &= ~0x8;
    *(s16 *)((char *)obj + 0xa2) = -1;
    v = objModelGetVecFn_800395d8(obj, 9);
    if (v != NULL) {
        v[0] = 0;
        v[1] = 0;
        v[2] = 0;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_80296124(int obj, void *p2, void *p3)
{
    int inner = *(int *)((char *)obj + 0xb8);
    *(int *)((char *)inner + 0x360) &= ~0x4000;
    if (p2 != NULL) {
        *(f32 *)((char *)obj + 0xc) = *(f32 *)((char *)p2 + 0);
        *(f32 *)((char *)obj + 0x10) = *(f32 *)((char *)p2 + 4);
        *(f32 *)((char *)obj + 0x14) = *(f32 *)((char *)p2 + 8);
        *(int *)((char *)inner + 0x360) |= 0x4000;
    }
    if (p3 != NULL) {
        s16 t = *(s16 *)((char *)p3 + 0);
        *(s16 *)((char *)obj + 0) = t;
        *(s16 *)((char *)inner + 0x478) = t;
        *(s16 *)((char *)inner + 0x484) = t;
        *(s16 *)((char *)inner + 0x484) = *(s16 *)((char *)inner + 0x478);
        *(s16 *)((char *)obj + 2) = *(s16 *)((char *)p3 + 2);
        *(s16 *)((char *)obj + 4) = *(s16 *)((char *)p3 + 4);
        *(int *)((char *)inner + 0x360) |= 0x4000;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_8029605C(int obj, f32 *p2, f32 *p3)
{
    void *inner = *(void **)((char *)obj + 0xb8);
    if (inner != NULL && getCurSeqNo() == 0) {
        if ((*(int *)((char *)inner + 0x360) & 0x400) != 0) {
            *p2 = *(f32 *)((char *)inner + 0x788);
            *p3 = *(f32 *)((char *)inner + 0x78c);
            return 1;
        }
        return 0;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_8029A420(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if (*(u8 *)((char *)inner + 0x8c8) != 0x42 && getCurSeqNo() == 0) {
        (*(void (*)(int, int, int, int, int, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
            0x42, 0, 1, 0, 0, 0x3c, 0xfe);
    }
    ((ByteFlags *)((char *)inner + 0x3f6))->b40 = 0;
    *(s16 *)((char *)inner + 0x80a) = -1;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void playerUpdateWhileTimeStopped(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    f32 zero = lbl_803E7EA4;
    f32 v = *(f32 *)((char *)inner + 0x820);
    if (v > zero) {
        v -= lbl_803E7EE0;
        *(f32 *)((char *)inner + 0x820) = v;
        v = *(f32 *)((char *)inner + 0x820);
        if (v <= zero) {
            cutsceneEnterExit(0, 0);
            *(u8 *)((char *)inner + 0x8cf) = 1;
        } else if (lbl_803E7EF0 == v) {
            cutsceneEnterExit(1, 0);
            setTimeStop(0xfd);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_8029DAE0(int obj, int *p2)
{
    int inner = *(int *)((char *)obj + 0xb8);
    u8 c;
    *p2 &= ~0x4000;
    c = *(u8 *)((char *)inner + 0x8c8);
    if (c != 0x48 && c != 0x47 && getCurSeqNo() == 0) {
        (*(void (*)(int, int, int, int, int, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
            0x42, 0, 1, 0, 0, 0x3c, 0xfe);
    }
    ObjHits_SyncObjectPositionIfDirty(obj);
}
#pragma peephole reset
#pragma scheduling reset

typedef struct {
    u8 pad[0x1ba8];
    int moveA[4];
    int moveB[4];
    int moveC[4];
    f32 spdD[4];
    f32 spdE[4];
} HeadMoveTable;

typedef struct {
    int a;
    int b;
} ColPair;

extern int lbl_803DE484;
extern int lbl_803E7E78;
extern int lbl_803E7E7C;
extern f32 lbl_803E7FDC;
extern f32 lbl_803E7FE0;
extern f32 lbl_803E7FE4;

#pragma scheduling off
#pragma peephole off
int fn_8029DB70(int obj, int state, f32 fv)
{
    int prev;
    HeadMoveTable *tbl = (HeadMoveTable *)lbl_80332EC0;
    int inner = *(int *)((char *)obj + 0xb8);
    int sub;
    int nextMove = -1;
    int doXform = 1;
    int camCall = 0;
    f32 t;
    f32 t2;
    f32 xc;
    f32 yc;
    f32 yT;
    f32 xT;
    f32 yOut;
    ColPair col;

    col = *(ColPair *)&lbl_803E7E78;
    setAButtonIcon(0xf);
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        ((ByteFlags *)((char *)inner + 0x3f3))->b01 = ((ByteFlags *)((char *)inner + 0x3f3))->b08;
        *(s16 *)((char *)state + 0x278) = 0x1d;
        *(int *)((char *)inner + 0x898) = (int)fn_8029DAE0;
    }
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        if (lbl_803DE44C != 0 && ((ByteFlags *)((char *)inner + 0x3f4))->b40 != 0) {
            *(u8 *)((char *)inner + 0x8b4) = 1;
            ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 1;
        }
        if (*(u8 *)((char *)inner + 0x8c8) != 0x48 && *(u8 *)((char *)inner + 0x8c8) != 0x47) {
            cameraSetInterpMode(2);
            (*(void (*)(int, int, int, int, void *, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
                0x52, 1, 0, 8, &col, 0x1e, 0xff);
        }
        *(u8 *)((char *)inner + 0x86d) = 0;
        *(u8 *)((char *)inner + 0x86e) = 0;
        *(s16 *)((char *)inner + 0x478) =
            getAngle(*(f32 *)((char *)inner + 0x654), *(f32 *)((char *)inner + 0x65c));
        {
            s16 ang = *(s16 *)((char *)inner + 0x478);
            *(s16 *)((char *)inner + 0x484) = ang;
            *(s16 *)obj = ang;
        }
        ((ByteFlags *)((char *)inner + 0x3f2))->b01 = 1;
        ObjAnim_SetCurrentMove(obj, 0x5f, lbl_803E7EA4, 0);
        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent *)obj, 8);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7EF8;
        {
            f32 z = lbl_803E7EA4;
            *(f32 *)((char *)inner + 0x444) = z;
            *(f32 *)((char *)inner + 0x448) = z;
        }
        ((ByteFlags *)((char *)inner + 0x3f3))->b80 = 0;
        ObjHits_MarkObjectPositionDirty(obj);
    }
    *(f32 *)((char *)inner + 0x7bc) = lbl_803E7F2C;
    {
        f32 z = lbl_803E7EA4;
        *(f32 *)((char *)inner + 0x7b8) = z;
        *(f32 *)((char *)state + 0x280) = z;
        *(f32 *)((char *)state + 0x284) = z;
    }
    sub = *(int *)((char *)inner + 0x67c);
    switch (*(s16 *)((char *)obj + 0xa0)) {
    case 0x5f:
        if ((*(int *)((char *)state + 0x318) & 0x100) == 0) {
            *(u32 *)((char *)inner + 0x360) |= 0x800000;
            *(int *)((char *)state + 0x308) = (int)fn_802A514C;
            return 2;
        }
        break;
    case 0x4d:
    case 0x4e:
    case 0x5a:
    case 0x65:
        if (*(s8 *)((char *)state + 0x346) != 0) {
            *(u32 *)((char *)inner + 0x360) |= 0x800000;
            *(int *)((char *)state + 0x308) = (int)fn_802A514C;
            return 2;
        }
        camCall = 1;
        doXform = 0;
        break;
    }
    prev = *(u8 *)((char *)inner + 0x86d);
    t = (f32)padGetStickX(0) / lbl_803E7FA8;
    xc = (t < lbl_803E7ECC) ? lbl_803E7ECC : ((t > lbl_803E7EE0) ? lbl_803E7EE0 : t);
    t2 = (f32)padGetStickY(0) / lbl_803E7FA8;
    yc = (t2 < lbl_803E7ECC) ? lbl_803E7ECC : ((t2 > lbl_803E7EE0) ? lbl_803E7EE0 : t2);
    if (((ByteFlags *)((char *)inner + 0x3f3))->b80 == 0) {
        if (yc > lbl_803E7F14) {
            xT = -(lbl_803E7F48 * yc - lbl_803E7FDC);
            *(f32 *)((char *)inner + 0x448) = yT = lbl_803E7EA4;
            *(u8 *)((char *)inner + 0x86d) = 1;
        } else if (yc < lbl_803E7FE0) {
            xT = -(lbl_803E7F48 * yc - lbl_803E7F6C);
            *(f32 *)((char *)inner + 0x448) = yT = lbl_803E7EA4;
            *(u8 *)((char *)inner + 0x86d) = 2;
        } else if (xc > lbl_803E7F14) {
            *(f32 *)((char *)inner + 0x444) = xT = lbl_803E7EA4;
            yT = lbl_803E7EAC * xc + lbl_803E7F6C;
            *(u8 *)((char *)inner + 0x86d) = 3;
        } else if (xc < lbl_803E7FE0) {
            *(f32 *)((char *)inner + 0x444) = xT = lbl_803E7EA4;
            yT = lbl_803E7EAC * xc + lbl_803E7FDC;
            *(u8 *)((char *)inner + 0x86d) = 4;
        } else {
            if (*(f32 *)((char *)inner + 0x444) <= lbl_803E7F6C &&
                *(f32 *)((char *)inner + 0x444) >= lbl_803E7FDC &&
                *(f32 *)((char *)inner + 0x448) <= lbl_803E7F6C &&
                *(f32 *)((char *)inner + 0x448) >= lbl_803E7FDC) {
                *(u8 *)((char *)inner + 0x86d) = 0;
                nextMove = 0x5f;
                *(f32 *)((char *)state + 0x2a0) = lbl_803E7EF8;
            }
            xT = lbl_803E7EA4;
            yT = lbl_803E7EA4;
        }
        {
            f32 k = lbl_803E7EFC;
            *(f32 *)((char *)inner + 0x444) =
                k * (xT - *(f32 *)((char *)inner + 0x444)) + *(f32 *)((char *)inner + 0x444);
            *(f32 *)((char *)inner + 0x448) =
                k * (yT - *(f32 *)((char *)inner + 0x448)) + *(f32 *)((char *)inner + 0x448);
        }
    }
    if (((ByteFlags *)((char *)inner + 0x3f3))->b80 == 0 &&
        ((*(int *)((char *)state + 0x318) & 0x100) == 0 || *(s8 *)((char *)inner + 0x681) != 0 ||
         (((ByteFlags *)((char *)inner + 0x3f1))->b01 == 0 &&
          *(f32 *)((char *)state + 0x1b0) >= lbl_803E7F58))) {
        if (*(s8 *)((char *)inner + 0x86d) != 0) {
            ObjAnim_SetCurrentMove(obj, tbl->moveA[*(s8 *)((char *)inner + 0x86d)], lbl_803E7E98, 0);
            *(f32 *)((char *)state + 0x2a0) = lbl_803E7F20;
        } else {
            *(u32 *)((char *)inner + 0x360) |= 0x800000;
            *(int *)((char *)state + 0x308) = (int)fn_802A514C;
            return 2;
        }
        *(u8 *)((char *)inner + 0x86d) = 0;
        ((ByteFlags *)((char *)inner + 0x3f3))->b80 = 1;
    }
    if (((ByteFlags *)((char *)inner + 0x3f3))->b80 == 0) {
        if (*(s8 *)((char *)inner + 0x86d) != 0) {
            lbl_803DE484 = lbl_803DE484 - framesThisStep;
            if (lbl_803DE484 <= 0) {
                lbl_803DE484 = randomGetRange(0xb4, 0xf0);
                Sfx_PlayFromObject(obj, 0x2b);
            }
            *(int *)((char *)inner + 0x360) |= 0x200;
            if (*(s8 *)((char *)inner + 0x86d) != (u8)prev || *(s8 *)((char *)inner + 0x86e) == 0) {
                ((ByteFlags *)((char *)inner + 0x3f2))->b01 = 1;
                *(u8 *)((char *)inner + 0x86e) = 0;
            } else if (*(s8 *)((char *)inner + 0x86d) == *(s8 *)((char *)inner + 0x86e)) {
                if (((ByteFlags *)((char *)inner + 0x3f3))->b08 != 0 &&
                    ((ByteFlags *)((char *)inner + 0x3f3))->b01 == 0) {
                    ((ByteFlags *)((char *)inner + 0x3f2))->b01 = 1;
                    *(u8 *)((char *)inner + 0x86e) = 0;
                } else {
                    ((ByteFlags *)((char *)inner + 0x3f2))->b01 = 0;
                }
            }
            if (((ByteFlags *)((char *)inner + 0x3f2))->b01 != 0) {
                *(f32 *)((char *)state + 0x2a0) =
                    lbl_803E7EF8 * *(f32 *)((char *)state + 0x298) +
                    tbl->spdD[*(s8 *)((char *)inner + 0x86d)];
                nextMove = tbl->moveC[*(s8 *)((char *)inner + 0x86d)];
            } else {
                int *tblB = tbl->moveB;
                if (*(s16 *)((char *)obj + 0xa0) != tblB[*(s8 *)((char *)inner + 0x86d)] ||
                    *(f32 *)((char *)obj + 0x98) >= lbl_803E7FE4) {
                    *(f32 *)((char *)state + 0x2a0) =
                        lbl_803E7F78 * ((f32)randomGetRange(0, 100) / lbl_803E7F5C) +
                        tbl->spdE[*(s8 *)((char *)inner + 0x86d)];
                }
                nextMove = tblB[*(s8 *)((char *)inner + 0x86d)];
            }
        }
        {
            u8 res;
            f32 a;
            f32 b;
            if (*(s8 *)((char *)inner + 0x86d) == 0) {
                a = lbl_803E7EA4;
                b = lbl_803E7EA4;
            } else {
                a = *(f32 *)((char *)inner + 0x444);
                b = *(f32 *)((char *)inner + 0x448);
            }
            res = (*(u8 (*)(int, int, int, f32, f32))(
                *(int *)(*(int *)(*(int *)((char *)sub + 0x68)) + 0x20)))(
                sub, obj, *(s8 *)((char *)inner + 0x86d), a, b);
            if (res == 1) {
                *(u8 *)((char *)inner + 0x86e) = 1;
            } else if (res == 2) {
                *(u8 *)((char *)inner + 0x86e) = 2;
            } else if (res == 3) {
                *(u8 *)((char *)inner + 0x86e) = 4;
            } else if (res == 4) {
                *(u8 *)((char *)inner + 0x86e) = 3;
            } else if (res == 5) {
                *(u8 *)((char *)inner + 0x681) = 1;
            } else {
                *(u8 *)((char *)inner + 0x86e) = 0;
            }
        }
    }
    if (nextMove != -1 && *(s16 *)((char *)obj + 0xa0) != nextMove &&
        ObjAnim_GetCurrentEventCountdown((ObjAnimComponent *)obj) == 0) {
        ObjAnim_SetCurrentMove(obj, nextMove, lbl_803E7EA4, 0);
        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent *)obj, 0xa);
    }
    if (camCall != 0) {
        (*(void (*)(int, int, int, f32))(*(int *)(*gPlayerInterface + 0x20)))(obj, state, 3, fv);
    }
    if (doXform != 0) {
        ((void (*)(f32, f32, f32, void *, f32 *, void *, int))Obj_TransformLocalPointToWorld)(
            *(f32 *)((char *)inner + 0x664), *(f32 *)((char *)inner + 0x668),
            *(f32 *)((char *)inner + 0x66c), (void *)(obj + 0xc), &yOut, (void *)(obj + 0x14), sub);
        *(f32 *)((char *)obj + 0xc) =
            lbl_803E7FB8 * *(f32 *)((char *)inner + 0x654) + *(f32 *)((char *)obj + 0xc);
        *(f32 *)((char *)obj + 0x14) =
            lbl_803E7FB8 * *(f32 *)((char *)inner + 0x65c) + *(f32 *)((char *)obj + 0x14);
    }
    ((ByteFlags *)((char *)inner + 0x3f3))->b01 = ((ByteFlags *)((char *)inner + 0x3f3))->b08;
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

extern s16 lbl_803DC6A2;
extern f32 lbl_803E8030;
extern f32 lbl_803E8034;
extern f32 lbl_803E803C;

#pragma scheduling off
#pragma peephole off
int fn_802A2EE0(int obj, int state, f32 fv)
{
    int inner = *(int *)((char *)obj + 0xb8);
    f32 diff = *(f32 *)((char *)inner + 0x5ac) - *(f32 *)((char *)inner + 0x874);
    f32 blend;
    f32 z;
    f32 t;

    if (*(s8 *)((char *)state + 0x27a) != 0) {
        *(s16 *)((char *)state + 0x278) = 0xc;
        *(int *)((char *)inner + 0x898) = 0;
        *(f32 *)((char *)obj + 0x28) = lbl_803E7EA4;
    }
    z = lbl_803E7EA4;
    *(f32 *)((char *)inner + 0x778) = z;
    {
        int in2 = *(int *)((char *)obj + 0xb8);
        *(int *)((char *)in2 + 0x360) &= ~2;
        *(int *)((char *)in2 + 0x360) |= 0x2000;
    }
    *(u32 *)((char *)state + 4) |= 0x100000;
    *(f32 *)((char *)state + 0x280) = z;
    *(f32 *)((char *)state + 0x284) = z;
    *(u32 *)state |= 0x200000;
    *(f32 *)((char *)obj + 0x24) = z;
    *(f32 *)((char *)obj + 0x2c) = z;
    *(u32 *)((char *)state + 4) |= 0x8000000;
    lbl_803DC6A2 = lbl_803DC6A0;
    switch (lbl_803DC6A0) {
    case 0:
        t = (*(f32 *)((char *)obj + 0x10) - *(f32 *)((char *)inner + 0x5b8)) /
            (diff - *(f32 *)((char *)inner + 0x5b8));
        *(f32 *)((char *)obj + 0xc) =
            t * (*(f32 *)((char *)inner + 0x5f8) - *(f32 *)((char *)inner + 0x5b4)) +
            *(f32 *)((char *)inner + 0x5b4);
        *(f32 *)((char *)obj + 0x14) =
            t * (*(f32 *)((char *)inner + 0x600) - *(f32 *)((char *)inner + 0x5bc)) +
            *(f32 *)((char *)inner + 0x5bc);
        (*(void (*)(int, int, int))(*(int *)(*gPlayerInterface + 0x20)))(obj, state, 0x14);
        *(f32 *)((char *)obj + 0x10) =
            *(f32 *)((char *)state + 0x2b4) * timeDelta + *(f32 *)((char *)obj + 0x10);
        if (*(s8 *)((char *)state + 0x346) != 0) {
            f32 d2;
            f32 v;
            lbl_803DC6A0 = 2;
            blend = lbl_803E7EF8;
            d2 = (lbl_803E7F10 + diff) - *(f32 *)((char *)obj + 0x10);
            v = lbl_803E8030 * -d2;
            if (v >= lbl_803E7EA4) {
                *(f32 *)((char *)obj + 0x28) = sqrtf(v);
            } else {
                *(f32 *)((char *)obj + 0x28) = lbl_803E7EA4;
            }
            Sfx_PlayFromObject(obj,
                               (u16)(*(s16 *)((char *)inner + 0x81a) == 0 ? 0x2d5 : 0x2d4));
        }
        break;
    case 2:
        if (*(f32 *)((char *)obj + 0x10) >= diff) {
            lbl_803DC6A0 = 3;
            blend = lbl_803E800C;
            *(f32 *)((char *)obj + 0x28) = z;
            *(f32 *)((char *)obj + 0xc) = *(f32 *)((char *)inner + 0x5f8);
            *(f32 *)((char *)obj + 0x10) = diff;
            *(f32 *)((char *)obj + 0x14) = *(f32 *)((char *)inner + 0x600);
        } else {
            *(f32 *)((char *)obj + 0x28) =
                lbl_803E7E88 * fv + *(f32 *)((char *)obj + 0x28);
            t = (*(f32 *)((char *)obj + 0x10) - *(f32 *)((char *)inner + 0x5b8)) /
                (diff - *(f32 *)((char *)inner + 0x5b8));
            *(f32 *)((char *)obj + 0xc) =
                t * (*(f32 *)((char *)inner + 0x5f8) - *(f32 *)((char *)inner + 0x5b4)) +
                *(f32 *)((char *)inner + 0x5b4);
            *(f32 *)((char *)obj + 0x14) =
                t * (*(f32 *)((char *)inner + 0x600) - *(f32 *)((char *)inner + 0x5bc)) +
                *(f32 *)((char *)inner + 0x5bc);
        }
        break;
    case 3:
        *(f32 *)((char *)inner + 0x5b4) = *(f32 *)((char *)obj + 0xc);
        *(f32 *)((char *)inner + 0x5b8) = *(f32 *)((char *)obj + 0x10);
        *(f32 *)((char *)inner + 0x5bc) = *(f32 *)((char *)obj + 0x14);
        if (*(f32 *)((char *)obj + 0x98) > lbl_803E7F48) {
            if (*(f32 *)((char *)state + 0x28c) > lbl_803E7F10) {
                lbl_803DC6A0 = 5;
                blend = lbl_803E8024;
                Sfx_PlayFromObject(obj,
                                   (u16)(*(s16 *)((char *)inner + 0x81a) == 0 ? 0x398 : 0x1d));
                if (*(u8 *)((char *)inner + 0x608) == 5) {
                    Sfx_PlayFromObject(obj, 0x2f);
                }
            } else if (*(f32 *)((char *)state + 0x28c) < lbl_803E801C) {
                *(int *)((char *)inner + 0x5c0) = *(s16 *)obj;
                lbl_803DC6A0 = 7;
                blend = lbl_803E8034;
                *(f32 *)((char *)obj + 0x28) = z;
            } else if (*(s8 *)((char *)state + 0x346) != 0) {
                lbl_803DC6A0 = 6;
                blend = lbl_803E8038;
            }
        }
        break;
    case 6:
        *(f32 *)((char *)inner + 0x5b4) = *(f32 *)((char *)obj + 0xc);
        *(f32 *)((char *)inner + 0x5b8) = *(f32 *)((char *)obj + 0x10);
        *(f32 *)((char *)inner + 0x5bc) = *(f32 *)((char *)obj + 0x14);
        if (*(f32 *)((char *)state + 0x28c) > lbl_803E7F10) {
            lbl_803DC6A0 = 5;
            blend = lbl_803E8024;
            Sfx_PlayFromObject(obj,
                               (u16)(*(s16 *)((char *)inner + 0x81a) == 0 ? 0x398 : 0x1d));
            if (*(u8 *)((char *)inner + 0x608) == 5) {
                Sfx_PlayFromObject(obj, 0x2f);
            }
        } else if (*(f32 *)((char *)state + 0x28c) < lbl_803E801C) {
            *(int *)((char *)inner + 0x5c0) = *(s16 *)obj;
            lbl_803DC6A0 = 7;
            blend = lbl_803E8034;
            *(f32 *)((char *)obj + 0x28) = z;
        }
        break;
    case 7: {
        f32 c5cc = *(f32 *)((char *)inner + 0x5cc);
        f32 k = lbl_803E7E98 + lbl_803DC6C0;
        f32 c5dc = *(f32 *)((char *)inner + 0x5dc);
        f32 y2 = c5cc * k + c5dc;
        s16 ang;
        *(f32 *)((char *)obj + 0xc) =
            *(f32 *)((char *)obj + 0x98) *
                ((*(f32 *)((char *)inner + 0x5c4) * k + *(f32 *)((char *)inner + 0x5d4)) -
                 *(f32 *)((char *)inner + 0x5b4)) +
            *(f32 *)((char *)inner + 0x5b4);
        *(f32 *)((char *)obj + 0x14) =
            *(f32 *)((char *)obj + 0x98) * (y2 - *(f32 *)((char *)inner + 0x5bc)) +
            *(f32 *)((char *)inner + 0x5bc);
        *(f32 *)((char *)obj + 0x28) =
            -(lbl_803E7F6C * timeDelta - *(f32 *)((char *)obj + 0x28));
        ang = -(lbl_803E7F98 * *(f32 *)((char *)obj + 0x98) -
                (f32)*(int *)((char *)inner + 0x5c0));
        *(s16 *)((char *)inner + 0x484) = ang;
        *(s16 *)((char *)inner + 0x478) = ang;
        if (*(s8 *)((char *)state + 0x346) != 0) {
            *(f32 *)((char *)state + 0x294) = z;
            *(f32 *)((char *)state + 0x280) = z;
            *(f32 *)((char *)state + 0x284) = z;
            *(f32 *)((char *)obj + 0x24) = z;
            *(f32 *)((char *)obj + 0x2c) = z;
            *(u32 *)((char *)state + 4) &= ~0x100000;
            fn_802AB5A4(obj, inner, 5);
            ((ByteFlags *)((char *)inner + 0x3f0))->b80 = 0;
            ((ByteFlags *)((char *)inner + 0x3f0))->b10 = 0;
            ((ByteFlags *)((char *)inner + 0x3f0))->b08 = 0;
            staffFn_80170380(lbl_803DE450, 2);
            ((ByteFlags *)((char *)inner + 0x3f0))->b02 = 0;
            *(u32 *)((char *)inner + 0x360) |= 0x800000;
            ObjHits_SyncObjectPositionIfDirty(obj);
            ((ByteFlags *)((char *)inner + 0x3f0))->b40 = 0;
            ((ByteFlags *)((char *)inner + 0x3f0))->b04 = 1;
            ((ByteFlags *)((char *)inner + 0x3f4))->b10 = 1;
            *(u8 *)((char *)inner + 0x800) = 0;
            if (*(void **)((char *)inner + 0x7f8) != NULL) {
                s16 typ = *(s16 *)((char *)*(int *)((char *)inner + 0x7f8) + 0x46);
                if (typ == 0x3cf || typ == 0x662) {
                    objThrowFn_80182504(*(int *)((char *)inner + 0x7f8));
                } else {
                    objSaveFn_800ea774(*(int *)((char *)inner + 0x7f8));
                }
                *(s16 *)((char *)*(int *)((char *)inner + 0x7f8) + 0x6) =
                    *(s16 *)((char *)*(int *)((char *)inner + 0x7f8) + 0x6) & ~0x4000;
                *(int *)((char *)*(int *)((char *)inner + 0x7f8) + 0xf8) = 0;
                *(int *)((char *)inner + 0x7f8) = 0;
            }
            *(int *)((char *)state + 0x308) = (int)fn_802A514C;
            return 3;
        }
        break;
    }
    case 5:
        t = *(f32 *)((char *)obj + 0x98) / lbl_803E7F68;
        z = (t < z) ? z : ((t > lbl_803E7EE0) ? lbl_803E7EE0 : t);
        *(f32 *)((char *)obj + 0xc) =
            z * (*(f32 *)((char *)inner + 0x5ec) - *(f32 *)((char *)inner + 0x5b4)) +
            *(f32 *)((char *)inner + 0x5b4);
        *(f32 *)((char *)obj + 0x10) =
            z * (*(f32 *)((char *)inner + 0x5f0) - *(f32 *)((char *)inner + 0x5b8)) +
            *(f32 *)((char *)inner + 0x5b8);
        *(f32 *)((char *)obj + 0x14) =
            z * (*(f32 *)((char *)inner + 0x5f4) - *(f32 *)((char *)inner + 0x5bc)) +
            *(f32 *)((char *)inner + 0x5bc);
        if (*(f32 *)((char *)obj + 0x98) > lbl_803E7F68) {
            *(u32 *)((char *)state + 4) &= ~0x100000;
            fn_802AB5A4(obj, inner, 5);
            *(u32 *)((char *)inner + 0x360) |= 0x800000;
            *(int *)((char *)state + 0x308) = (int)fn_802A514C;
            return 2;
        }
        break;
    default:
        lbl_803DC6A0 = 0;
        lbl_803DC6A2 = 0;
        *(f32 *)((char *)state + 0x2a0) = lbl_803E803C;
        ObjAnim_SetCurrentMove(obj, lbl_80332EF0[lbl_803DC6A0], lbl_803E7EA4, 0);
        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent *)obj, 10);
        {
            s16 ang =
                getAngle(*(f32 *)((char *)inner + 0x5c4), *(f32 *)((char *)inner + 0x5cc));
            *(s16 *)((char *)inner + 0x484) = ang;
            *(s16 *)((char *)inner + 0x478) = ang;
        }
        *(f32 *)((char *)obj + 0x28) = lbl_803E7EA4;
        ((void (*)(f32, f32, f32, void *, void *, void *, int))Obj_TransformWorldPointToLocal)(
            *(f32 *)((char *)obj + 0x18), *(f32 *)((char *)obj + 0x1c),
            *(f32 *)((char *)obj + 0x20), (void *)(obj + 0xc), (void *)(obj + 0x10),
            (void *)(obj + 0x14), *(int *)((char *)obj + 0x30));
        objHitDetectFn_80062e84(obj, *(int *)((char *)inner + 0x4c4), 1);
        *(f32 *)((char *)inner + 0x5b4) = *(f32 *)((char *)obj + 0xc);
        *(f32 *)((char *)inner + 0x5b8) = *(f32 *)((char *)obj + 0x10);
        *(f32 *)((char *)inner + 0x5bc) = *(f32 *)((char *)obj + 0x14);
        {
        char *xf = *(char **)((char *)inner + 0x4c4);
        if (xf != NULL) {
            ((void (*)(f32, f32, f32, void *, void *, void *, char *))Obj_TransformWorldPointToLocal)(
                *(f32 *)((char *)inner + 0x5d4), *(f32 *)((char *)inner + 0x5d8),
                *(f32 *)((char *)inner + 0x5dc), (void *)(inner + 0x5d4),
                (void *)(inner + 0x5d8), (void *)(inner + 0x5dc), xf);
            ((void (*)(f32, f32, f32, void *, void *, void *, int))Obj_TransformWorldPointToLocal)(
                *(f32 *)((char *)inner + 0x5ec), *(f32 *)((char *)inner + 0x5f0),
                *(f32 *)((char *)inner + 0x5f4), (void *)(inner + 0x5ec),
                (void *)(inner + 0x5f0), (void *)(inner + 0x5f4),
                *(int *)((char *)inner + 0x4c4));
            ((void (*)(f32, f32, f32, void *, void *, void *, int))Obj_TransformWorldPointToLocal)(
                *(f32 *)((char *)inner + 0x5f8), *(f32 *)((char *)inner + 0x5fc),
                *(f32 *)((char *)inner + 0x600), (void *)(inner + 0x5f8),
                (void *)(inner + 0x5fc), (void *)(inner + 0x600),
                *(int *)((char *)inner + 0x4c4));
            *(f32 *)((char *)inner + 0x5ac) =
                *(f32 *)((char *)inner + 0x5ac) -
                *(f32 *)((char *)*(int *)((char *)inner + 0x4c4) + 0x10);
            *(f32 *)((char *)inner + 0x5b0) =
                *(f32 *)((char *)inner + 0x5b0) -
                *(f32 *)((char *)*(int *)((char *)inner + 0x4c4) + 0x10);
            *(u8 *)((char *)inner + 0x609) = 0;
        }
        }
        break;
    }
    if (lbl_803DC6A2 != lbl_803DC6A0) {
        ObjAnim_SetCurrentMove(obj, lbl_80332EF0[lbl_803DC6A0], lbl_803E7EA4, 0);
        *(f32 *)((char *)state + 0x2a0) = blend;
    }
    fn_802AB5A4(obj, inner, 5);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

extern void Camera_EnableViewYOffset(void);
extern void CameraShake_SetAllMagnitudes(f32 mag);
extern f32 lbl_803E8104;
extern f32 lbl_803E8108;
extern f32 lbl_803E810C;
extern f32 lbl_803E8110;

#pragma scheduling off
#pragma peephole off
int fn_802AD2F4(int obj, int inner, int state)
{
    f32 hdiff;
    int sfx;
    f32 z;
    f32 y;
    f32 x;

    *(f32 *)((char *)obj + 0x28) =
        -(lbl_803E7EFC * timeDelta - *(f32 *)((char *)obj + 0x28));
    switch (*(s16 *)((char *)obj + 0xa0)) {
    case 0xa:
    case 0x54:
    case 0x90:
        *(u8 *)((char *)inner + 0x8c5) = 2;
        break;
    case 0x13: {
        f32 zz = lbl_803E7EA4;
        *(f32 *)((char *)state + 0x284) = zz;
        *(f32 *)((char *)obj + 0x28) = zz;
    }
        if (*(f32 *)((char *)obj + 0x98) >= lbl_803E7F10 * *(f32 *)((char *)state + 0x2a0)) {
            ((ByteFlags *)((char *)inner + 0x3f2))->b08 = 0;
        } else if (*(u8 *)((char *)inner + 0x3f7) >= 2 &&
                   ((ByteFlags *)((char *)inner + 0x3f2))->b04 == 0) {
            s8 hv;
            Camera_EnableViewYOffset();
            CameraShake_SetAllMagnitudes(lbl_803E7ED8);
            ObjPath_GetPointWorldPosition(obj, 0xb, &x, &y, &z, 0);
            if (*(u8 *)((char *)inner + 0x86c) == 0x1a) {
                hv = 0x14;
            } else {
                hv = 2;
            }
            ObjHits_RecordPositionHit(obj, 0, hv, 1, 0, x, y, z);
            ((ByteFlags *)((char *)inner + 0x3f2))->b04 = 1;
        }
        if (*(s8 *)((char *)state + 0x346) != 0) {
            ((ByteFlags *)((char *)inner + 0x3f0))->b04 = 0;
            ((ByteFlags *)((char *)inner + 0x3f3))->b40 = 1;
            *(u8 *)((char *)inner + 0x40d) = 0;
            return 1;
        }
        if (*(u8 *)((char *)inner + 0x3f7) >= 2) {
            *(u8 *)((char *)inner + 0x8c5) = 4;
        } else {
            *(u8 *)((char *)inner + 0x8c5) = 3;
        }
        break;
    case 0xb: {
        f32 zz = lbl_803E7EA4;
        *(f32 *)((char *)state + 0x284) = zz;
        if (*(s8 *)((char *)state + 0x346) != 0) {
            if (**(s8 **)((char *)inner + 0x35c) > 0) {
                ObjAnim_SetCurrentMove(obj, 0xc, zz, 0);
                *(f32 *)((char *)state + 0x2a0) = lbl_803E8038;
            } else {
                ((ByteFlags *)((char *)inner + 0x3f0))->b04 = 0;
                *(u8 *)((char *)inner + 0x40d) = 0;
                playerDie(obj);
            }
        }
        (*(void (*)(int, int, int, f32))(*(int *)(*gPlayerInterface + 0x20)))(obj, state, 2,
                                                                              timeDelta);
        *(u8 *)((char *)inner + 0x8c5) = 4;
        break;
    }
    case 0xc:
        if ((*(int *)((char *)state + 0x314) & 1) != 0 &&
            *(s16 *)((char *)inner + 0x81a) != 0) {
            Sfx_PlayFromObject(obj, 0x20e);
            Sfx_PlayFromObject(obj, 0x20f);
        }
        if (*(s8 *)((char *)state + 0x346) != 0) {
            ((ByteFlags *)((char *)inner + 0x3f0))->b04 = 0;
            ((ByteFlags *)((char *)inner + 0x3f3))->b40 = 1;
            *(u8 *)((char *)inner + 0x40d) = 0;
            return 1;
        }
        (*(void (*)(int, int, int, f32))(*(int *)(*gPlayerInterface + 0x20)))(obj, state, 2,
                                                                              timeDelta);
        *(u8 *)((char *)inner + 0x8c5) = 4;
        break;
    default:
        ObjAnim_SetCurrentMove(obj, 0x54, lbl_803E7EA4, 0);
        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent *)obj, 0x14);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7F6C;
        *(u8 *)((char *)inner + 0x8c5) = 2;
        *(u8 *)((char *)inner + 0x3f7) = 0;
        ((ByteFlags *)((char *)inner + 0x3f0))->b01 = 0;
        ((ByteFlags *)((char *)inner + 0x3f2))->b08 = 0;
        ((ByteFlags *)((char *)inner + 0x3f2))->b04 = 0;
        ((ByteFlags *)((char *)inner + 0x3f2))->b02 = 0;
        *(f32 *)((char *)inner + 0x848) = *(f32 *)((char *)obj + 0x1c);
        break;
    }
    hdiff = *(f32 *)((char *)inner + 0x848) - *(f32 *)((char *)obj + 0x1c);
    if (((ByteFlags *)((char *)inner + 0x3f1))->b01 != 0 &&
        ((ByteFlags *)((char *)inner + 0x3f0))->b01 == 0) {
        ((ByteFlags *)((char *)inner + 0x3f0))->b01 = 1;
        sfx = audioPickSoundEffect_8006ed24(*(u8 *)((char *)inner + 0x86c),
                                            *(u8 *)((char *)inner + 0x8a5));
        if (hdiff > lbl_803E8104) {
            s8 hv;
            doRumble(lbl_803E7FA4);
            Camera_EnableViewYOffset();
            CameraShake_SetAllMagnitudes(lbl_803E7F58);
            ObjAnim_SetCurrentMove(obj, 0xb, lbl_803E7EA4, 0);
            *(f32 *)((char *)state + 0x2a0) = lbl_803E7F34;
            Sfx_PlayFromObject(obj, 0x20d);
            Sfx_PlayFromObject(obj, 0x28);
            ObjPath_GetPointWorldPosition(obj, 0xb, &x, &y, &z, 0);
            if (*(u8 *)((char *)inner + 0x86c) == 0x1a) {
                hv = 0x14;
            } else {
                hv = 2;
            }
            ObjHits_RecordPositionHit(obj, 0, hv, 2, 0, x, y, z);
            ((ByteFlags *)((char *)inner + 0x3f2))->b08 = 0;
            if (*(f32 *)((char *)inner + 0x838) > lbl_803E7FC4) {
                Sfx_PlayFromObject(obj, 0x428);
            }
        } else if (hdiff > lbl_803E8108) {
            doRumble(lbl_803E7ED8);
            ObjAnim_SetCurrentMove(obj, 0x13, lbl_803E7EA4, 0);
            *(f32 *)((char *)state + 0x2a0) = lbl_803E800C;
            Sfx_PlayFromObject(obj, sfx);
            Sfx_StopFromObject(obj,
                               (u16)(*(s16 *)((char *)inner + 0x81a) == 0 ? 0x2d0 : 0x26));
            ((ByteFlags *)((char *)inner + 0x3f2))->b08 = 1;
            if (*(f32 *)((char *)inner + 0x838) > lbl_803E7FC4) {
                Sfx_PlayFromObject(obj, 0x429);
            }
        } else if (hdiff > lbl_803E810C) {
            doRumble(lbl_803E7ED8);
            ObjAnim_SetCurrentMove(obj, 0x13, lbl_803E7EA4, 0);
            *(f32 *)((char *)state + 0x2a0) = lbl_803E800C;
            Sfx_PlayFromObject(obj, sfx);
            Sfx_PlayFromObject(obj,
                               (u16)(*(s16 *)((char *)inner + 0x81a) == 0 ? 0x399 : 0x27));
            ((ByteFlags *)((char *)inner + 0x3f2))->b08 = 1;
            if (*(f32 *)((char *)inner + 0x838) > lbl_803E7FC4) {
                Sfx_PlayFromObject(obj, 0x42a);
            }
        } else {
            doRumble(lbl_803E7F10);
            Sfx_PlayFromObject(0, sfx);
            ((ByteFlags *)((char *)inner + 0x3f0))->b04 = 0;
            *(u8 *)((char *)inner + 0x40d) = 0;
            ((ByteFlags *)((char *)inner + 0x3f1))->b08 = 1;
            ((ByteFlags *)((char *)inner + 0x3f2))->b10 = 1;
            ((ByteFlags *)((char *)inner + 0x3f2))->b08 = 1;
            if (*(f32 *)((char *)inner + 0x838) > lbl_803E7FC4) {
                Sfx_PlayFromObject(obj, 0x42b);
            }
        }
        if (hdiff > lbl_803E810C) {
            f32 z2 = lbl_803E7EA4;
            *(f32 *)((char *)state + 0x294) = z2;
            *(f32 *)((char *)state + 0x280) = z2;
        }
        *(f32 *)((char *)state + 0x284) = lbl_803E7EA4;
    }
    if (((ByteFlags *)((char *)inner + 0x3f0))->b01 == 0) {
        if (*(f32 *)((char *)state + 0x1b0) < lbl_803E80C4) {
            ((ByteFlags *)((char *)inner + 0x3f2))->b08 = 1;
        }
        if (hdiff > lbl_803E8104 && *(u8 *)((char *)inner + 0x3f7) < 3) {
            ObjAnim_SetCurrentMove(obj, 0xa, lbl_803E7EA4, 0);
            ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent *)obj, 0x19);
            *(f32 *)((char *)state + 0x2a0) = lbl_803E7EF8;
            *(u8 *)((char *)inner + 0x3f7) = 3;
            ((ByteFlags *)((char *)inner + 0x3f2))->b08 = 0;
        } else if (hdiff > lbl_803E8108 && *(u8 *)((char *)inner + 0x3f7) < 2) {
            if (Sfx_IsPlayingFromObject(
                    0, (u16)(*(s16 *)((char *)inner + 0x81a) == 0 ? 0x2d0 : 0x26)) == 0) {
                Sfx_PlayFromObject(obj,
                                   (u16)(*(s16 *)((char *)inner + 0x81a) == 0 ? 0x2d0 : 0x26));
            }
            *(u8 *)((char *)inner + 0x3f7) = 2;
        } else if (hdiff > lbl_803E810C && *(u8 *)((char *)inner + 0x3f7) < 1) {
            ObjAnim_SetCurrentMove(obj, 0x90, lbl_803E7EA4, 0);
            ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent *)obj, 0x19);
            *(f32 *)((char *)state + 0x2a0) = lbl_803E7EFC;
            *(u8 *)((char *)inner + 0x3f7) = 1;
        }
    }
    if (((ByteFlags *)((char *)inner + 0x3f2))->b08 != 0 &&
        (*(u16 *)((char *)inner + 0x6e2) & 0x400) != 0) {
        ((ByteFlags *)((char *)inner + 0x3f2))->b02 = 1;
        *(u16 *)((char *)inner + 0x6e2) = *(u16 *)((char *)inner + 0x6e2) & ~0x400;
    }
    if (((ByteFlags *)((char *)inner + 0x3f0))->b01 != 0 &&
        ((ByteFlags *)((char *)inner + 0x3f2))->b02 != 0 &&
        *(u8 *)((char *)inner + 0x3f7) < 3) {
        fn_802AED2C(obj, inner, state);
        ((ByteFlags *)((char *)inner + 0x3f0))->b04 = 0;
        *(u8 *)((char *)inner + 0x40d) = 0;
    }
    if (*(u8 *)((char *)inner + 0x3f7) == 0 &&
        ((ByteFlags *)((char *)inner + 0x3f4))->b10 == 0) {
        *(f32 *)((char *)inner + 0x428) = lbl_803E7FBC;
        *(f32 *)((char *)inner + 0x42c) = lbl_803E7E98;
        *(f32 *)((char *)inner + 0x430) = lbl_803E7FBC;
        *(f32 *)((char *)inner + 0x434) = lbl_803E7E98;
        *(f32 *)((char *)inner + 0x82c) = lbl_803E7F14;
        *(f32 *)((char *)inner + 0x408) = *(f32 *)((char *)inner + 0x408) * lbl_803E7F14;
    } else {
        *(f32 *)((char *)inner + 0x428) = lbl_803E7FBC;
        *(f32 *)((char *)inner + 0x42c) = lbl_803E7EA4;
        *(f32 *)((char *)inner + 0x430) = lbl_803E7FBC;
        *(f32 *)((char *)inner + 0x434) = lbl_803E7EA4;
        *(f32 *)((char *)inner + 0x82c) = lbl_803E7EA4;
        *(f32 *)((char *)inner + 0x408) = *(f32 *)((char *)inner + 0x408) * lbl_803E7EA4;
    }
    {
        f32 t = *(f32 *)((char *)inner + 0x408);
        *(f32 *)((char *)inner + 0x408) =
            (t < lbl_803E8110)
                ? lbl_803E8110
                : ((t > *(f32 *)((char *)inner + 0x404)) ? *(f32 *)((char *)inner + 0x404) : t);
    }
    if (*(u8 *)((char *)inner + 0x8c8) == 0x4b) {
        (*(void (*)(int, int, int, int, int, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
            0x42, 0, 1, 0, 0, 0, 0xff);
        *(u8 *)((char *)inner + 0x8c8) = 0x42;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

extern int *gScreenTransitionInterface;
extern void Pause_ResetMenuFrameCounter(void);
extern int getSkyColorFn_80088e30(int idx);
extern void objAudioFn_8006edcc();
extern int isInBounds(f32 x, f32 z);
extern int getCurUiDll(void);
extern void fn_802B249C(int obj, int inner, int state);
extern void fn_802AFB0C(int obj, int inner, int state);
extern u8 lbl_803DC6A8[8];
extern u8 lbl_803DC6B0[2];
extern int lbl_802C2C50[];
extern f32 lbl_803E8164;

typedef struct {
    int a[6];
} UiMsgBlock;

typedef struct {
    u8 pad[0x8b9];
    u8 bits[7];
} InnerBits;

#pragma scheduling off
#pragma peephole off
void playerUpdate(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int cam = Camera_GetCurrentViewSlot();
    f32 cd = *(f32 *)((char *)inner + 0x820);
    f32 limit = lbl_803E7EF0;
    if (cd >= limit) {
        f32 zero = lbl_803E7EA4;
        if (cd > zero) {
            *(f32 *)((char *)inner + 0x820) = cd - lbl_803E7EE0;
            if (*(f32 *)((char *)inner + 0x820) <= zero) {
                cutsceneEnterExit(0, 0);
                *(u8 *)((char *)inner + 0x8cf) = 1;
            } else if (limit == *(f32 *)((char *)inner + 0x820)) {
                cutsceneEnterExit(1, 0);
                setTimeStop(0xfd);
            }
        }
    } else if (getCurUiDll() != 4) {
        if ((*(u32 *)((char *)inner + 0x360) & 0x200000) != 0) {
            return;
        }
        if (((ByteFlags *)((char *)inner + 0x3f3))->b08 != 0) {
            setBButtonIcon(10);
        }
        if (*(void **)((char *)obj + 0x30) == NULL && *(void **)((char *)inner + 0x7f0) == NULL &&
            isInBounds(*(f32 *)((char *)obj + 0xc), *(f32 *)((char *)obj + 0x14)) == 0) {
            *(int *)((char *)inner + 0x2d0) = 0;
            *(int *)((char *)inner + 0x7ec) = 0;
            (*(void (*)(int))(*(int *)(*gCameraInterface + 0x48)))(0);
            {
                f32 z = lbl_803E7EA4;
                *(f32 *)((char *)inner + 0x294) = z;
                *(f32 *)((char *)inner + 0x284) = z;
                *(f32 *)((char *)inner + 0x280) = z;
                *(f32 *)((char *)obj + 0x24) = z;
                *(f32 *)((char *)obj + 0x28) = z;
                *(f32 *)((char *)obj + 0x2c) = z;
            }
            fn_802AB5A4(obj, inner, 0xff);
        } else {
            f32 dt;
            f32 ym;
            int i;
            int v;
            u8 hov;
            UiMsgBlock m;
            *(u8 *)((char *)inner + 0x8c8) = (*(int (*)(void))(*(int *)(*gCameraInterface + 0x10)))();
            if (*(u8 *)((char *)inner + 0x8c8) == 0x44 && *(s16 *)((char *)inner + 0x274) != 1) {
                (*(void (*)(int, int, int))(*(int *)(*gPlayerInterface + 0x14)))(obj, inner, 1);
                {
                    f32 z = lbl_803E7EA4;
                    *(f32 *)((char *)inner + 0x294) = z;
                    *(f32 *)((char *)inner + 0x284) = z;
                    *(f32 *)((char *)inner + 0x280) = z;
                    *(f32 *)((char *)obj + 0x24) = z;
                    *(f32 *)((char *)obj + 0x28) = z;
                    *(f32 *)((char *)obj + 0x2c) = z;
                }
                *(int *)((char *)inner + 0x304) = (int)fn_802A514C;
            }
            fn_802B249C(obj, inner, inner);
            fn_802B4A9C(obj, inner, inner);
            fn_802B07D8(obj, inner);
            if ((u32)lbl_803DE448 == 0 && Obj_IsLoadingLocked() != 0) {
                lbl_803DE448 = Obj_SetupObject(Obj_AllocObjectSetup(0x18, 0x66a), 4, -1, -1,
                                               *(int *)((char *)obj + 0x30));
                ObjLink_AttachChild(obj, lbl_803DE448, 3);
            }
            if ((u32)lbl_803DE448 != 0) {
                *(int *)(lbl_803DE448 + 0x30) = *(int *)((char *)obj + 0x30);
                if (*(s16 *)((char *)inner + 0x81a) == 0) {
                    *(s16 *)(lbl_803DE448 + 6) = *(s16 *)(lbl_803DE448 + 6) | 0x4000;
                }
            }
            if ((u32)lbl_803DE450 == 0 && Obj_IsLoadingLocked() != 0) {
                lbl_803DE450 = Obj_SetupObject(Obj_AllocObjectSetup(0x24, 0x773), 5, -1, -1,
                                               *(int *)((char *)obj + 0x30));
            }
            if ((u32)lbl_803DE450 != 0) {
                ObjPath_GetPointWorldPosition(obj, 4, (void *)(lbl_803DE450 + 0xc),
                                              (void *)(lbl_803DE450 + 0x10),
                                              (void *)(lbl_803DE450 + 0x14), 0);
            }
            if (*(s16 **)((char *)obj + 0x30) != NULL) {
                v = (**(s16 **)((char *)obj + 0x30) & 0xffffU) -
                    ((0x8000U - *(s16 *)cam) & 0xffff);
                if (v > 0x8000) {
                    v -= 0xffff;
                }
                if (v < -0x8000) {
                    v += 0xffff;
                }
                *(s16 *)((char *)inner + 0x330) = (s16)(v + 0x8000);
            } else {
                *(s16 *)((char *)inner + 0x330) = *(s16 *)cam;
            }
            *(f32 *)((char *)inner + 0x778) = lbl_803E8164;
            *(u8 *)((char *)inner + 0x8c9) = 0;
            *(int *)((char *)inner + 0x310) = 0;
            for (i = 0; i < *(u8 *)((char *)inner + 0x8b8); i++) {
                int idx = i + 0x8b9;
                *(u32 *)((char *)inner + 0x310) |= 1 << *(u8 *)((char *)inner + idx);
            }
            *(u32 *)((char *)inner + 0x360) &= 0xfffff4ff;
            dt = timeDelta;
            fn_802B19F8(obj, inner, dt);
            fn_802B4C18(obj, inner, dt);
            ((void (*)(int, int, f32))fn_802AEF34)(obj, inner, dt);
            fn_802B1E5C(obj, inner, inner, dt);
            ((void (*)(int, int, int, f32))fn_802B1BF8)(obj, inner, inner, dt);
            {
                f32 t = *(f32 *)((char *)obj + 0x24);
                *(f32 *)((char *)obj + 0x24) =
                    (t < lbl_803E801C) ? lbl_803E801C
                                       : ((t > lbl_803E7F10) ? lbl_803E7F10 : t);
                t = *(f32 *)((char *)obj + 0x28);
                *(f32 *)((char *)obj + 0x28) =
                    (t < lbl_803E811C) ? lbl_803E811C
                                       : ((t > lbl_803E80E4) ? lbl_803E80E4 : t);
                t = *(f32 *)((char *)obj + 0x2c);
                *(f32 *)((char *)obj + 0x2c) =
                    (t < lbl_803E801C) ? lbl_803E801C
                                       : ((t > lbl_803E7F10) ? lbl_803E7F10 : t);
            }
            ym = *(f32 *)((char *)obj + 0x28) * dt;
            if (ym > lbl_803E7ED8) {
                ym = lbl_803E7ED8;
            }
            objMove(obj, *(f32 *)((char *)obj + 0x24) * dt, ym,
                    *(f32 *)((char *)obj + 0x2c) * dt);
            *(s16 *)obj = *(s16 *)((char *)inner + 0x478);
            m = *(UiMsgBlock *)lbl_802C2C50;
            (*(void (*)(void *, int))(*(int *)(*gGameUIInterface + 0x24)))(&m, 6);
            fn_802B0920(obj, inner);
            {
                s16 nv = *(s16 *)((char *)inner + 0x810) - framesThisStep;
                *(s16 *)((char *)inner + 0x810) = nv;
                if (nv < 0) {
                    *(s16 *)((char *)inner + 0x810) =
                        lbl_803DC6A8[*(u8 *)((char *)inner + 0x8b0)];
                    *(u8 *)((char *)inner + 0x8b1) =
                        lbl_803DC6B0[*(u8 *)((char *)inner + 0x8b0)];
                }
            }
            fn_802B066C(obj, inner);
            if (*(u8 *)((char *)inner + 0x8ca) == 1) {
                *(f32 *)((char *)inner + 0x7d0) =
                    *(f32 *)((char *)inner + 0x7cc) * timeDelta + *(f32 *)((char *)inner + 0x7d0);
                if (*(f32 *)((char *)inner + 0x7d0) >= lbl_803E80C4) {
                    *(f32 *)((char *)inner + 0x7d0) = lbl_803E80C4;
                    *(f32 *)((char *)inner + 0x7cc) = lbl_803E7EA4;
                } else if (*(f32 *)((char *)inner + 0x7d0) <= lbl_803E7EA4) {
                    *(f32 *)((char *)inner + 0x7d0) = lbl_803E7EA4;
                    *(f32 *)((char *)inner + 0x7cc) = lbl_803E7F14;
                }
            }
            fn_802AFB0C(obj, inner, inner);
            if (*(void **)((char *)inner + 0x7f8) != NULL &&
                Obj_IsObjectAlive(*(int *)((char *)inner + 0x7f8)) == 0) {
                *(u8 *)((char *)inner + 0x800) = 0;
                if (*(void **)((char *)inner + 0x7f8) != NULL) {
                    s16 typ = *(s16 *)((char *)*(int *)((char *)inner + 0x7f8) + 0x46);
                    if (typ == 0x3cf || typ == 0x662) {
                        objThrowFn_80182504(*(int *)((char *)inner + 0x7f8));
                    } else {
                        objSaveFn_800ea774(*(int *)((char *)inner + 0x7f8));
                    }
                    *(s16 *)((char *)*(int *)((char *)inner + 0x7f8) + 0x6) =
                        *(s16 *)((char *)*(int *)((char *)inner + 0x7f8) + 0x6) & ~0x4000;
                    *(int *)((char *)*(int *)((char *)inner + 0x7f8) + 0xf8) = 0;
                    *(int *)((char *)inner + 0x7f8) = 0;
                }
            }
            if ((*(u8 *)(*(int *)((char *)obj + 0xb8) + 0xc4) & 0x40) != 0) {
                v = (int)-(lbl_803E80E4 * timeDelta -
                           (f32)(u32)*(u8 *)((char *)obj + 0xf1));
            } else {
                v = (int)(lbl_803E80E4 * timeDelta +
                          (f32)(u32)*(u8 *)((char *)obj + 0xf1));
            }
            if (v < (u8)getSkyColorFn_80088e30(2)) {
                v = (u8)getSkyColorFn_80088e30(2);
            } else if (v > 0xff) {
                v = 0xff;
            }
            *(u8 *)((char *)obj + 0xf1) = (u8)v;
            fn_802AF7F8(obj, inner);
            playerProcessQueuedItemCommand(obj, inner);
            if (((ByteFlags *)((char *)inner + 0x3f3))->b20 != 0 &&
                (*(int (*)(void))(*(int *)(*gScreenTransitionInterface + 0x14)))() != 0) {
                (*(void (*)(void))(*(int *)(*gMapEventInterface + 0x28)))();
            }
            if (((ByteFlags *)((char *)inner + 0x3f3))->b20 == 0 &&
                (*(int *)((char *)inner + 0x310) & 1) != 0) {
                if (Sfx_IsPlayingFromObject(
                        obj, (u16)(*(s16 *)((char *)inner + 0x81a) == 0 ? 0x2d0 : 0x26)) == 0) {
                    Sfx_PlayFromObject(
                        0, (u16)(*(s16 *)((char *)inner + 0x81a) == 0 ? 0x2d0 : 0x26));
                }
                ((ByteFlags *)((char *)inner + 0x3f3))->b20 = 1;
                (*(void (*)(int, int))(*(int *)(*gScreenTransitionInterface + 0x8)))(0x1e, 1);
                Pause_ResetMenuFrameCounter();
            }
            if (lbl_803DE44C != 0 && ((ByteFlags *)((char *)inner + 0x3f4))->b40 != 0) {
                *(u16 *)((char *)lbl_803DE44C + 0xb0) =
                    *(u16 *)((char *)lbl_803DE44C + 0xb0) & ~7;
                if (*(u8 *)((char *)inner + 0x8b3) == 0) {
                    *(u16 *)((char *)lbl_803DE44C + 0xb0) =
                        *(u16 *)((char *)lbl_803DE44C + 0xb0) | 2;
                }
            }
            hov = ((ByteFlags *)((char *)inner + 0x3f4))->b40;
            if (hov != 0) {
                if (*(u8 *)((char *)inner + 0x8b3) != 0) {
                    setAButtonIcon(1);
                } else {
                    int ok = (*(void **)((char *)inner + 0x7f8) == NULL && hov != 0 &&
                              ((ByteFlags *)((char *)inner + 0x3f0))->b20 == 0 &&
                              ((ByteFlags *)((char *)inner + 0x3f0))->b10 == 0);
                    if (ok) {
                        setAButtonIcon(0xb);
                    }
                }
                if (*(u8 *)((char *)inner + 0x8b3) != 0) {
                    setBButtonIcon(0xc);
                }
            }
            (*(void (*)(int))(*(int *)(*gCameraInterface + 0x68)))(*(u8 *)((char *)inner + 0x8c9));
            *(u8 *)((char *)inner + 0x800) = 0;
            *(u8 *)((char *)inner + 0x8b8) = 0;
            *(s16 *)obj = *(s16 *)((char *)inner + 0x478);
            objAudioFn_8006edcc(obj, *(int *)((char *)inner + 0x314),
                                *(u8 *)((char *)inner + 0x8a6), (void *)(inner + 0x3c4),
                                (void *)(inner + 4), *(f32 *)((char *)inner + 0x280),
                                lbl_803E7EE0);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern f32 Curve_EvalCatmullRom(int curve, f32 t, int mode);
extern f32 lbl_803E7FA8;
extern f32 lbl_803E7F6C;
extern f64 lbl_803E7EC0;
extern f32 lbl_803E7F00;
extern f32 lbl_803E7F44;
extern f32 lbl_803E80E4;
extern f32 lbl_803E7F10;
extern f32 lbl_803E7FFC;
extern f32 lbl_803E8098;
extern f32 lbl_803E7E98;
extern f32 lbl_803E7EE8;
extern f32 lbl_803E7EAC;
extern f32 lbl_803E7EFC;

#pragma scheduling off
#pragma peephole off
void fn_802B0EA4(int obj, int inner, int state)
{
    int d;
    char *cam;
    f32 dx;
    f32 dz;
    f32 spd;
    f32 t;
    f32 u;
    int idx;
    f32 one;
    f32 v;

    if ((*(u32 *)((char *)inner + 0x360) & 0x800000) != 0) {
        s16 a = *(s16 *)obj;
        *(s16 *)((char *)inner + 0x484) = a;
        *(s16 *)((char *)inner + 0x478) = a;
        *(int *)((char *)inner + 0x494) = a;
        *(f32 *)((char *)state + 0x298) = lbl_803E7EA4;
    }
    *(f32 *)((char *)state + 0x29c) = *(f32 *)((char *)state + 0x298);
    *(s16 *)((char *)inner + 0x490) = *(s16 *)((char *)inner + 0x484);
    *(s16 *)((char *)inner + 0x492) = *(s16 *)((char *)inner + 0x478);
    *(f32 *)((char *)state + 0x298) =
        sqrtf(*(f32 *)((char *)state + 0x290) * *(f32 *)((char *)state + 0x290) +
              *(f32 *)((char *)state + 0x28c) * *(f32 *)((char *)state + 0x28c));
    if (*(f32 *)((char *)state + 0x298) > lbl_803E7FA8) {
        *(f32 *)((char *)state + 0x298) = lbl_803E7FA8;
    }
    *(f32 *)((char *)state + 0x298) = *(f32 *)((char *)state + 0x298) / lbl_803E7FA8;
    *(f32 *)((char *)inner + 0x470) =
        *(f32 *)((char *)state + 0x298) - *(f32 *)((char *)state + 0x29c);
    if (*(f32 *)((char *)state + 0x298) < lbl_803E7F6C) {
        *(f32 *)((char *)state + 0x298) = lbl_803E7EA4;
        *(int *)((char *)inner + 0x474) = *(int *)((char *)inner + 0x494);
    } else {
        *(int *)((char *)inner + 0x474) =
            getAngle(*(f32 *)((char *)state + 0x290), -*(f32 *)((char *)state + 0x28c)) & 0xffff;
        *(int *)((char *)inner + 0x474) =
            *(int *)((char *)inner + 0x474) - *(s16 *)((char *)state + 0x330);
        if ((*(u32 *)((char *)inner + 0x360) & 0x1000000) == 0) {
            *(int *)((char *)inner + 0x494) = *(int *)((char *)inner + 0x474);
        }
    }
    d = *(int *)((char *)inner + 0x474) - (u16)*(s16 *)((char *)inner + 0x484);
    if (d > 0x8000) {
        d = d - 0xffff;
    }
    if (d < -0x8000) {
        d = d + 0xffff;
    }
    *(int *)((char *)inner + 0x48c) = (int)((f32)d / lbl_803E7F00);
    if (*(f32 *)((char *)inner + 0x85c) != lbl_803E7EA4) {
        f32 dead = *(f32 *)((char *)inner + 0x85c) * *(f32 *)((char *)state + 0x280);
        if ((f32)*(int *)((char *)inner + 0x48c) < dead &&
            (f32)*(int *)((char *)inner + 0x48c) > -dead) {
            *(int *)((char *)inner + 0x48c) = 0;
        }
    }
    if (d < 0) {
        *(int *)((char *)inner + 0x488) = -*(int *)((char *)inner + 0x48c);
    } else {
        *(int *)((char *)inner + 0x488) = *(int *)((char *)inner + 0x48c);
    }
    if (*(f32 *)((char *)state + 0x298) < lbl_803E7F6C) {
        *(u8 *)((char *)state + 0x34b) = 0;
    } else {
        d = d + 0xa000;
        if (d < 0) {
            d = d + 0xffff;
        }
        if (d > 0xffff) {
            d = d - 0xffff;
        }
        *(u8 *)((char *)state + 0x34b) = (u8)(4 - d / 0x4000);
    }
    d = *(int *)((char *)inner + 0x474) - (u16)*(s16 *)((char *)inner + 0x478);
    if (d > 0x8000) {
        d = d - 0xffff;
    }
    if (d < -0x8000) {
        d = d + 0xffff;
    }
    *(int *)((char *)inner + 0x480) = (int)((f32)d / lbl_803E7F00);
    if (*(f32 *)((char *)inner + 0x85c) != lbl_803E7EA4) {
        f32 dead = *(f32 *)((char *)inner + 0x85c) * *(f32 *)((char *)state + 0x280);
        if ((f32)*(int *)((char *)inner + 0x480) < dead &&
            (f32)*(int *)((char *)inner + 0x480) > -dead) {
            *(int *)((char *)inner + 0x480) = 0;
        }
    }
    if (d < 0) {
        *(int *)((char *)inner + 0x47c) = -*(int *)((char *)inner + 0x480);
    } else {
        *(int *)((char *)inner + 0x47c) = *(int *)((char *)inner + 0x480);
    }
    d = *(int *)((char *)inner + 0x474) - (u16)*(s16 *)((char *)inner + 0x4d4);
    if (d > 0x8000) {
        d = d - 0xffff;
    }
    if (d < -0x8000) {
        d = d + 0xffff;
    }
    *(int *)((char *)inner + 0x49c) = (int)((f32)d / lbl_803E7F00);
    if (d < 0) {
        *(int *)((char *)inner + 0x498) = -*(int *)((char *)inner + 0x49c);
    } else {
        *(int *)((char *)inner + 0x498) = *(int *)((char *)inner + 0x49c);
    }
    *(int *)((char *)inner + 0x4b8) =
        (**(int (**)(void))((char *)(*gCameraInterface) + 0x40))();
    cam = *(char **)((char *)inner + 0x4b8);
    if (cam != NULL) {
        dx = *(f32 *)(cam + 0xc) - *(f32 *)((char *)obj + 0xc);
        dz = *(f32 *)(cam + 0x14) - *(f32 *)((char *)obj + 0x14);
        *(int *)((char *)inner + 0x4ac) = getAngle(-dx, -dz) & 0xffff;
        *(f32 *)((char *)inner + 0x4b0) = sqrtf(dx * dx + dz * dz);
        *(u16 *)((char *)inner + 0x4b4) =
            *(u8 *)(*(int *)(*(int *)(cam + 0x50) + 0x40) + 0x10) & 0xf;
    }
    d = *(int *)((char *)inner + 0x4ac) - (u16)*(s16 *)((char *)inner + 0x478);
    if (d > 0x8000) {
        d = d - 0xffff;
    }
    if (d < -0x8000) {
        d = d + 0xffff;
    }
    *(int *)((char *)inner + 0x4a4) = (int)(f32)d;
    if (d < 0) {
        *(int *)((char *)inner + 0x4a8) = -*(int *)((char *)inner + 0x4a4);
    } else {
        *(int *)((char *)inner + 0x4a8) = *(int *)((char *)inner + 0x4a4);
    }
    if (((ByteFlags *)((char *)inner + 0x3f1))->b20 != 0) {
        spd = sqrtf(*(f32 *)((char *)state + 0x280) * *(f32 *)((char *)state + 0x280) +
                    *(f32 *)((char *)state + 0x284) * *(f32 *)((char *)state + 0x284));
        t = lbl_803E7EA4;
        if (spd < t) {
        } else {
            t = *(f32 *)((char *)inner + 0x404);
            if (spd > t) {
            } else {
                t = spd;
            }
        }
        if (lbl_803E7EE0 == *(f32 *)((char *)inner + 0x82c)) {
            *(f32 *)((char *)inner + 0x438) = lbl_803E7F44;
        } else {
            u = t * *(f32 *)((char *)inner + 0x7e0);
            idx = (int)u;
            *(f32 *)((char *)inner + 0x438) =
                lbl_803E7EE0 / Curve_EvalCatmullRom(*(int *)((char *)inner + 0x450) + (idx + 1) * 4, u - (f32)idx, 0);
        }
    } else {
        spd = *(f32 *)((char *)state + 0x280);
        t = lbl_803E7EA4;
        if (spd < t) {
        } else {
            t = *(f32 *)((char *)inner + 0x404);
            if (spd > t) {
            } else {
                t = spd;
            }
        }
        u = t * *(f32 *)((char *)inner + 0x7e0);
        idx = (int)u;
        *(f32 *)((char *)inner + 0x438) =
            lbl_803E7EE0 / Curve_EvalCatmullRom(*(int *)((char *)inner + 0x450) + (idx + 1) * 4, u - (f32)idx, 0);
    }
    u = t * *(f32 *)((char *)inner + 0x7e0);
    idx = (int)u;
    *(f32 *)((char *)inner + 0x428) = Curve_EvalCatmullRom(*(int *)((char *)inner + 0x454) + (idx + 1) * 4, u - (f32)idx, 0);
    u = t * *(f32 *)((char *)inner + 0x7e0);
    idx = (int)u;
    *(f32 *)((char *)inner + 0x42c) = Curve_EvalCatmullRom(*(int *)((char *)inner + 0x458) + (idx + 1) * 4, u - (f32)idx, 0);
    u = t * *(f32 *)((char *)inner + 0x7e0);
    idx = (int)u;
    *(f32 *)((char *)inner + 0x430) = Curve_EvalCatmullRom(*(int *)((char *)inner + 0x45c) + (idx + 1) * 4, u - (f32)idx, 0);
    u = t * *(f32 *)((char *)inner + 0x7e0);
    idx = (int)u;
    *(f32 *)((char *)inner + 0x434) = Curve_EvalCatmullRom(*(int *)((char *)inner + 0x460) + (idx + 1) * 4, u - (f32)idx, 0);
    if (((ByteFlags *)((char *)inner + 0x3f0))->b20 != 0) {
        *(f32 *)((char *)inner + 0x428) = *(f32 *)((char *)inner + 0x428) * lbl_803E80E4;
        *(f32 *)((char *)inner + 0x430) = *(f32 *)((char *)inner + 0x430) * lbl_803E80E4;
        *(f32 *)((char *)inner + 0x438) = *(f32 *)((char *)inner + 0x438) * lbl_803E7F44;
    } else {
        if (lbl_803E7EE0 != *(f32 *)((char *)inner + 0x834)) {
            f32 base = *(f32 *)(*(int *)((char *)inner + 0x400) + 0x10);
            f32 frac = (*(f32 *)((char *)state + 0x280) - base) /
                       (*(f32 *)((char *)inner + 0x404) - base);
            f32 c = lbl_803E7EA4;
            if (frac < c) {
            } else {
                if (frac > lbl_803E7EE0) {
                    c = lbl_803E7EE0;
                } else {
                    c = frac;
                }
            }
            *(f32 *)((char *)inner + 0x430) =
                *(f32 *)((char *)inner + 0x430) *
                ((*(f32 *)((char *)inner + 0x834) - lbl_803E7EE0) * c + lbl_803E7EE0);
        }
    }
    if (*(void **)((char *)inner + 0x464) != NULL) {
        int n = *(int *)((char *)inner + 0x47c);
        *(f32 *)((char *)inner + 0x420) = Curve_EvalCatmullRom(
            *(int *)((char *)inner + 0x464) + (n / 5 + 1) * 4, (f32)(n % 5) / lbl_803E7F10, 0);
    } else {
        *(f32 *)((char *)inner + 0x420) = lbl_803E7EE0;
    }
    one = lbl_803E7EE0;
    *(f32 *)((char *)inner + 0x420) = one;
    if (((ByteFlags *)((char *)inner + 0x3f0))->b20 == 0 &&
        *(f32 *)((char *)inner + 0x838) > lbl_803E7EA4) {
        *(f32 *)((char *)inner + 0x840) =
            (*(f32 *)((char *)inner + 0x838) - lbl_803E7FFC) / lbl_803E8098;
        v = *(f32 *)((char *)inner + 0x840);
        t = lbl_803E7EA4;
        if (v < t) {
        } else {
            if (v > one) {
                t = one;
            } else {
                t = v;
            }
        }
        *(f32 *)((char *)inner + 0x840) = t;
        *(f32 *)((char *)inner + 0x840) =
            -(lbl_803E7E98 * *(f32 *)((char *)inner + 0x840) - lbl_803E7EE0);
    } else {
        if (*(s16 *)((char *)state + 0x19c) < 1) {
            *(f32 *)((char *)inner + 0x840) = lbl_803E7EE0;
        } else {
            *(f32 *)((char *)inner + 0x840) =
                (f32)*(s16 *)((char *)state + 0x19c) / lbl_803E7EE8;
            v = *(f32 *)((char *)inner + 0x840);
            t = lbl_803E7EA4;
            if (v < t) {
            } else {
                t = lbl_803E7EE0;
                if (v > t) {
                } else {
                    t = v;
                }
            }
            *(f32 *)((char *)inner + 0x840) = t;
            *(f32 *)((char *)inner + 0x840) =
                -(lbl_803E7EAC * *(f32 *)((char *)inner + 0x840) - lbl_803E7EE0);
        }
    }
    if (*(void **)((char *)inner + 0x7f8) != NULL) {
        *(f32 *)((char *)inner + 0x840) = *(f32 *)((char *)inner + 0x840) - lbl_803E7EFC;
    }
    v = *(f32 *)((char *)inner + 0x840);
    t = lbl_803E7E98;
    if (v < t) {
    } else {
        t = lbl_803E7EE0;
        if (v > t) {
        } else {
            t = v;
        }
    }
    *(f32 *)((char *)inner + 0x840) = t;
    *(u32 *)((char *)inner + 0x360) = *(u32 *)((char *)inner + 0x360) & 0xfe7fffff;
}
#pragma peephole reset
#pragma scheduling reset

typedef struct {
    u8 pad[0x170];
    f32 off;
    u8 pad2[12];
    f32 def;
} IdleEntry;

extern s16 lbl_803DC6CC[4];
extern f32 lbl_803E7FC8;
extern f32 lbl_803E7FBC;
extern f32 lbl_803E7F78;
extern f32 lbl_803E7ED4;
extern f32 lbl_803E8018;
extern f32 lbl_803E8084;
extern f32 lbl_803E8088;
extern f32 lbl_803E7E90;
extern f32 lbl_803E7F94;
extern f32 lbl_803E7F98;
extern f32 lbl_803E7F14;
extern f32 lbl_803E806C;
extern f32 lbl_803E8064;

#pragma scheduling off
#pragma peephole off
int fn_802A6694(int obj, int state, f32 fv)
{
    char *tbl;
    int inner;
    int move;
    f32 t;
    f32 v;
    int calm;

    tbl = (char *)lbl_80332EC0;
    inner = *(int *)((char *)obj + 0xb8);
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        if (*(s16 *)((char *)state + 0x276) != 0x24 &&
            *(s16 *)((char *)state + 0x276) != 0x25) {
            *(f32 *)((char *)state + 0x294) = lbl_803E7EA4;
        } else if (((ByteFlags *)((char *)inner + 0x3f1))->b20 == 0) {
            int a = *(int *)((char *)inner + 0x474);
            *(int *)((char *)inner + 0x494) = a;
            *(s16 *)((char *)inner + 0x484) = a;
            *(int *)((char *)inner + 0x48c) = 0;
            *(int *)((char *)inner + 0x488) = 0;
        } else {
            f32 z = lbl_803E7EA4;
            *(f32 *)((char *)inner + 0x4c8) = z;
            *(f32 *)((char *)inner + 0x4cc) = z;
        }
        *(f32 *)((char *)inner + 0x814) = lbl_803E7EA4;
        *(s16 *)((char *)inner + 0x812) = randomGetRange(800, 0x44c);
    }
    *(f32 *)((char *)state + 0x280) =
        *(f32 *)((char *)state + 0x280) -
        interpolate(*(f32 *)((char *)state + 0x280), *(f32 *)((char *)inner + 0x82c),
                    timeDelta);
    if (*(f32 *)((char *)state + 0x280) <= *(f32 *)(tbl + 0x398)) {
        *(f32 *)((char *)state + 0x280) = lbl_803E7EA4;
    }
    {
        f32 z = lbl_803E7EA4;
        *(f32 *)((char *)state + 0x284) = z;
        *(f32 *)((char *)obj + 0x24) = z;
        *(f32 *)((char *)obj + 0x2c) = z;
    }
    {
        int r = ((int (*)(int, int, int, f32))fn_802AC7DC)(obj, state, inner, fv);
        if (r != 0) {
            return r;
        }
    }
    if (*(f32 *)((char *)state + 0x29c) >= lbl_803E7FC8 ||
        *(f32 *)((char *)state + 0x298) >= lbl_803E7FC8 ||
        *(f32 *)((char *)state + 0x294) >= *(f32 *)(*(int *)((char *)inner + 0x400) + 4)) {
        goto active;
    }
    *(int *)((char *)state + 0x308) = (int)fn_802A514C;
    return 3;
active:
    fn_802AD204(obj, inner);
    if (*(s16 **)((char *)inner + 0x3f8) == (s16 *)(tbl + 0x190)) {
        if (*(f32 *)((char *)inner + 0x814) >= lbl_803E7FBC ||
            **(s8 **)((char *)inner + 0x35c) > 4) {
            goto pick;
        }
        move = 0x5d;
        fv = lbl_803E7F78;
        if (RandomTimer_UpdateRangeTrigger(inner + 0x3ec, lbl_803E7ED4, lbl_803E7F10) != 0) {
            Sfx_PlayFromObject(obj, 0x452);
        }
        goto picked;
    pick:
        {
            move = **(s16 **)((char *)inner + 0x3f8);
            fv = lbl_803E7F78;
            if (*(s16 *)((char *)inner + 0x812) <= 0) {
                if (*(u8 *)((char *)inner + 0x8c8) != 0x44) {
                    u32 i = *(u8 *)((char *)inner + 0x86f);
                    move = lbl_803DC6CC[i];
                    {
                        IdleEntry *e = (IdleEntry *)(tbl + i * 4);
                        if (*(s16 *)((char *)inner + 0x81a) == 0) {
                            fv = e->off;
                        } else {
                            fv = e->def;
                        }
                    }
                    *(u8 *)((char *)inner + 0x86f) += 1;
                    *(u8 *)((char *)inner + 0x86f) =
                        (u8)(*(u8 *)((char *)inner + 0x86f) % 3);
                }
                *(s16 *)((char *)inner + 0x812) = randomGetRange(800, 0x44c);
            }
        }
    picked:
        if (*(s16 *)((char *)obj + 0xa0) == **(s16 **)((char *)inner + 0x3f8)) {
            *(f32 *)((char *)inner + 0x814) =
                *(f32 *)((char *)inner + 0x814) + timeDelta;
            v = *(f32 *)((char *)inner + 0x814);
            t = lbl_803E7EA4;
            if (v < t) {
            } else {
                t = lbl_803E7FBC;
                if (v > t) {
                } else {
                    t = v;
                }
            }
            *(f32 *)((char *)inner + 0x814) = t;
            *(u16 *)((char *)inner + 0x812) =
                (int)((f32)*(s16 *)((char *)inner + 0x812) - timeDelta);
            {
                int cd = *(s16 *)((char *)inner + 0x812);
                if (cd < 0) {
                    cd = 0;
                } else if (cd > 0x44c) {
                    cd = 0x44c;
                }
                *(s16 *)((char *)inner + 0x812) = (s16)cd;
            }
        } else {
            if (*(s16 *)((char *)obj + 0xa0) != 0x5d) {
                *(f32 *)((char *)inner + 0x814) = lbl_803E7EA4;
            }
            *(s16 *)((char *)inner + 0x812) = randomGetRange(800, 0x44c);
        }
    } else {
        move = **(s16 **)((char *)inner + 0x3f8);
        fv = lbl_803E7F78;
    }
    if (((ByteFlags *)((char *)inner + 0x3f0))->b20 != 0) {
        *(u32 *)state |= 0x200000;
        *(u32 *)((char *)inner + 0x360) &= 0xfdffffff;
        *(s16 *)((char *)state + 0x278) = 1;
        *(int *)((char *)inner + 0x898) = (int)fn_802A514C;
        if (((ByteFlags *)((char *)inner + 0x3f1))->b20 != 0) {
            *(f32 *)((char *)inner + 0x404) = lbl_803E7F2C;
        } else {
            *(f32 *)((char *)inner + 0x404) = lbl_803E8064;
        }
    } else {
        if (((ByteFlags *)((char *)inner + 0x3f1))->b20 != 0) {
            *(u32 *)((char *)inner + 0x360) |= 0x2000000;
            *(s16 *)((char *)state + 0x278) = 0;
            *(f32 *)((char *)inner + 0x404) = lbl_803E7ED4;
        } else {
            *(u32 *)((char *)inner + 0x360) |= 0x2000000;
            *(s16 *)((char *)state + 0x278) = 0;
            *(f32 *)((char *)inner + 0x404) = lbl_803E806C;
        }
    }
    {
        f32 frac = (*(f32 *)((char *)state + 0x298) - lbl_803E7F14) / lbl_803E7F2C;
        t = lbl_803E7EA4;
        if (frac < t) {
        } else {
            t = lbl_803E7EE0;
            if (frac > t) {
            } else {
                t = frac;
            }
        }
    }
    *(f32 *)((char *)inner + 0x408) =
        (*(f32 *)((char *)inner + 0x404) - lbl_803E7F6C) *
        (t * *(f32 *)((char *)inner + 0x840));
    if (((ByteFlags *)((char *)inner + 0x3f0))->b20 != 0) {
        fn_802ADE80(obj, inner, state);
    }
    {
        u32 fl = *(u8 *)((char *)inner + 0x3f0);
        if ((fl >> 5 & 1) == 0 && (fl >> 6 & 1) == 0 && (fl >> 4 & 1) == 0 &&
            (fl >> 2 & 1) == 0 && (fl >> 3 & 1) == 0 && (fl >> 1 & 1) == 0 &&
            *(void **)((char *)inner + 0x7f8) == NULL &&
            *(u8 *)((char *)inner + 0x8c8) != 0x44) {
            calm = 1;
        } else {
            calm = 0;
        }
    }
    if (calm && (*(u16 *)((char *)inner + 0x6e2) & 0x400) != 0) {
        fn_802AED2C(obj, inner, state);
        *(int *)((char *)state + 0x308) = (int)fn_802A514C;
        return 3;
    }
    if (((ByteFlags *)((char *)inner + 0x3f1))->b20 == 0) {
        *(f32 *)((char *)state + 0x294) =
            *(f32 *)((char *)state + 0x294) +
            interpolate(*(f32 *)((char *)inner + 0x408) - *(f32 *)((char *)state + 0x294),
                        *(f32 *)((char *)inner + 0x438), timeDelta);
    }
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        *(int *)((char *)inner + 0x47c) = 0;
        *(int *)((char *)inner + 0x480) = 0;
        *(int *)((char *)inner + 0x488) = 0;
        *(int *)((char *)inner + 0x48c) = 0;
        *(u8 *)((char *)inner + 0x8a6) = *(u8 *)((char *)inner + 0x8a3);
        *(u8 *)((char *)inner + 0x8b0) = 0;
        *(f32 *)((char *)state + 0x2b8) = lbl_803E8018;
        *(f32 *)((char *)state + 0x2a0) = lbl_803E8084;
        if (((ByteFlags *)((char *)inner + 0x3f0))->b20 == 0 &&
            ((ByteFlags *)((char *)inner + 0x3f1))->b20 == 0) {
            if (*(s16 *)((char *)state + 0x276) == 2) {
                int mA = *(s16 *)(*(int *)((char *)inner + 0x3f8) + 0x30);
                int mB;
                if (*(s16 *)((char *)obj + 0xa0) != mA &&
                    (mB = *(s16 *)(*(int *)((char *)inner + 0x3f8) + 0x32),
                     *(s16 *)((char *)obj + 0xa0) != mB) &&
                    ((ByteFlags *)((char *)inner + 0x3f3))->b40 == 0) {
                    if (*(f32 *)((char *)obj + 0x98) > lbl_803E7E98) {
                        ObjAnim_SetCurrentMove(obj, mB, lbl_803E7EA4, 0);
                    } else {
                        ObjAnim_SetCurrentMove(obj, mA, lbl_803E7EA4, 0);
                    }
                }
                *(f32 *)((char *)state + 0x2a0) = lbl_803E8088;
            } else if (*(s16 *)((char *)obj + 0xa0) != move) {
                ObjAnim_SetCurrentMove(obj, move, lbl_803E7EA4, 0);
                *(f32 *)((char *)state + 0x2a0) = fv;
            }
        } else if (*(s16 *)((char *)obj + 0xa0) != move) {
            ObjAnim_SetCurrentMove(obj, move, lbl_803E7EA4, 0);
            *(f32 *)((char *)state + 0x2a0) = fv;
        }
    }
    if (*(s16 *)((char *)obj + 0xa0) == *(s16 *)(*(int *)((char *)inner + 0x3f8) + 0x30) ||
        *(s16 *)((char *)obj + 0xa0) == *(s16 *)(*(int *)((char *)inner + 0x3f8) + 0x32)) {
        if (*(s8 *)((char *)state + 0x346) != 0 &&
            ((int (*)(int))ObjAnim_GetCurrentEventCountdown)(obj) == 0) {
            ObjAnim_SetCurrentMove(obj, move, lbl_803E7EA4, 0);
            *(f32 *)((char *)state + 0x2a0) = fv;
        }
    } else if (((ByteFlags *)((char *)inner + 0x3f0))->b20 == 0 &&
               ((ByteFlags *)((char *)inner + 0x3f1))->b20 == 0 &&
               *(int *)((char *)inner + 0x47c) > 5) {
        if (*(s16 *)((char *)obj + 0xa0) !=
                *(s16 *)(*(int *)((char *)inner + 0x3f8) + 0x3e) &&
            ((int (*)(int))ObjAnim_GetCurrentEventCountdown)(obj) == 0) {
            ObjAnim_SetCurrentMove(obj, *(s16 *)(*(int *)((char *)inner + 0x3f8) + 0x3e),
                                   lbl_803E7EA4, 0);
            *(f32 *)((char *)state + 0x2a0) = lbl_803E7E90;
        }
    } else if (*(s16 *)((char *)obj + 0xa0) != move &&
               ((int (*)(int))ObjAnim_GetCurrentEventCountdown)(obj) == 0) {
        s16 cur = *(s16 *)((char *)obj + 0xa0);
        if (cur == lbl_803DC6CC[0] || cur == lbl_803DC6CC[1] ||
            cur == lbl_803DC6CC[2] || cur == lbl_803DC6CC[3]) {
            if (*(s8 *)((char *)state + 0x346) != 0) {
                ObjAnim_SetCurrentMove(obj, move, lbl_803E7EA4, 0);
                *(f32 *)((char *)state + 0x2a0) = fv;
            }
        } else {
            ObjAnim_SetCurrentMove(obj, move, lbl_803E7EA4, 0);
            *(f32 *)((char *)state + 0x2a0) = fv;
            if (move == 0x5d) {
                ((void (*)(int, int))ObjAnim_SetCurrentEventStepFrames)(obj, 0x1e);
            }
        }
    }
    if (((ByteFlags *)((char *)inner + 0x3f1))->b20 == 0) {
        f32 step;
        f32 lim;
        step = interpolate((f32)*(int *)((char *)inner + 0x47c),
                           lbl_803E7EE0 / *(f32 *)((char *)inner + 0x428), timeDelta);
        lim = timeDelta * (*(f32 *)((char *)inner + 0x42c) * *(f32 *)((char *)inner + 0x420));
        if (step < lim) {
        } else {
            step = lim;
        }
        if (*(int *)((char *)inner + 0x480) < 0) {
            step = -step;
        }
        *(u16 *)((char *)inner + 0x478) =
            (int)(lbl_803E7F00 * step + (f32)*(s16 *)((char *)inner + 0x478));
        step = interpolate((f32)*(int *)((char *)inner + 0x488),
                           lbl_803E7EE0 / *(f32 *)((char *)inner + 0x430), timeDelta);
        lim = *(f32 *)((char *)inner + 0x434) * timeDelta;
        if (step < lim) {
        } else {
            step = lim;
        }
        if (*(int *)((char *)inner + 0x48c) < 0) {
            step = -step;
        }
        *(u16 *)((char *)inner + 0x484) =
            (int)(lbl_803E7F00 * step + (f32)*(s16 *)((char *)inner + 0x484));
    } else {
        f32 vx;
        f32 vz;
        f32 c;
        c = fn_80293E80((lbl_803E7F94 * (f32)*(int *)((char *)inner + 0x474)) /
                        lbl_803E7F98);
        vx = *(f32 *)((char *)inner + 0x404) * (t * -c);
        c = sin((lbl_803E7F94 * (f32)*(int *)((char *)inner + 0x474)) / lbl_803E7F98);
        vz = *(f32 *)((char *)inner + 0x404) * (t * -c);
        vx = interpolate(vx - *(f32 *)((char *)inner + 0x4c8),
                         *(f32 *)((char *)inner + 0x438), timeDelta);
        vz = interpolate(vz - *(f32 *)((char *)inner + 0x4cc),
                         *(f32 *)((char *)inner + 0x438), timeDelta);
        *(f32 *)((char *)inner + 0x4c8) = *(f32 *)((char *)inner + 0x4c8) + vx;
        *(f32 *)((char *)inner + 0x4cc) = *(f32 *)((char *)inner + 0x4cc) + vz;
        *(f32 *)((char *)state + 0x294) =
            sqrtf(*(f32 *)((char *)inner + 0x4c8) * *(f32 *)((char *)inner + 0x4c8) +
                  *(f32 *)((char *)inner + 0x4cc) * *(f32 *)((char *)inner + 0x4cc));
        v = *(f32 *)((char *)state + 0x294);
        t = lbl_803E7EA4;
        if (v < t) {
        } else {
            t = *(f32 *)((char *)inner + 0x404);
            if (v > t) {
            } else {
                t = v;
            }
        }
        *(f32 *)((char *)state + 0x294) = t;
    }
    if (((ByteFlags *)((char *)inner + 0x3f0))->b20 == 0) {
        fn_802AC32C(obj, state, inner);
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset



extern void fn_80026C54(int a);

typedef struct {
    u8 pad[0x88];
    u8 flags;
    u8 pad2[0x1f];
    u8 valsA[3];
    u8 valsB[5];
} HitDesc;
extern int getSbGalleon(void);
extern int DBprotection_getCameraState(void);
extern f32 lbl_803E8160;

#pragma scheduling off
#pragma peephole off
void playerDoHitDetection(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    f32 dt = timeDelta;
    f32 spd;
    int sub;
    int desc;
    u32 fl;
    f32 x;
    f32 y;
    f32 z;

    *(u32 *)((char *)inner + 0x360) &= 0xf7ffffff;
    if (((ByteFlags *)((char *)inner + 0x3f2))->b20 != 0 &&
        (*(u16 *)((char *)obj + 0xb0) & 0x1000) != 0) {
        *(u8 *)((char *)inner + 0x25f) = 0;
    }
    (*(void (*)(int, void *, f32))(*(int *)(*gPathControlInterface + 0x10)))(
        obj, (void *)(inner + 4), timeDelta);
    (*(void (*)(int, void *))(*(int *)(*gPathControlInterface + 0x14)))(obj,
                                                                        (void *)(inner + 4));
    (*(void (*)(int, void *, f32))(*(int *)(*gPathControlInterface + 0x18)))(
        obj, (void *)(inner + 4), timeDelta);
    fn_80026C54(lbl_803DE420);
    if (!(*(f32 *)((char *)inner + 0x820) >= lbl_803E7EF0)) {
        (*(void (*)(int, int, void *))(*(int *)(*gPlayerInterface + 0xc)))(obj, inner,
                                                                           lbl_803DAFC8);
        if (*(s8 *)((char *)inner + 0x34d) == 1) {
            if (lbl_803DE44C != 0 && ((ByteFlags *)((char *)inner + 0x3f4))->b40 != 0 &&
                (*(void **)((sub = *(int *)((char *)lbl_803DE44C + 0x54)) + 0x50) != NULL ||
                 (*(s8 *)(sub + 0xad) != 0 && *(s8 *)(sub + 0xac) != 0xe))) {
                *(u8 *)(*(int *)((char *)obj + 0x54) + 0x70) = 1;
                *(f32 *)((char *)inner + 0x7d8) = lbl_803E7EA4;
                *(u8 *)((char *)inner + 0x8ce) = *(u8 *)((char *)inner + 0x8cd);
                {
                    HitDesc *t = (HitDesc *)*(int *)((char *)inner + 0x3dc) +
                                 *(u8 *)((char *)inner + 0x8a9);
                    if ((t->flags & 1) != 0) {
                        *(f32 *)((char *)inner + 0x820) = lbl_803E80A8;
                    }
                }
                {
                HitDesc *d = &((HitDesc *)*(int *)((char *)inner + 0x3dc))[*(u8 *)((char *)inner + 0x8a9)];
                if ((d->flags & 2) != 0) {
                    *(u8 *)((char *)inner + 0x8ad) = d->valsA[*(s8 *)((char *)inner + 0x8cd)];
                    {
                        HitDesc *e = (HitDesc *)*(int *)((char *)inner + 0x3dc) +
                                     *(u8 *)((char *)inner + 0x8a9);
                        *(u8 *)((char *)inner + 0x8ac) =
                            e->valsB[*(s8 *)((char *)inner + 0x8cd)];
                    }
                    *(f32 *)((char *)inner + 0x828) =
                        (f32)(u32)*(u8 *)((char *)inner + 0x8ad);
                    *(u8 *)((char *)inner + 0x8ab) += 1;
                    *(int *)((char *)inner + 0x4c0) = *(int *)(sub + 0x50);
                }
                }
                {
                    char *h2 = *(char **)(sub + 0x50);
                    if (h2 != NULL) {
                        if ((*(u8 *)(*(int *)((char *)h2 + 0x50) + 0x76) & 4) != 0) {
                            doRumble(lbl_803E7ED8);
                        }
                        if ((*(u8 *)(*(int *)((char *)h2 + 0x50) + 0x76) & 8) != 0) {
                            lbl_803DE459 = 1;
                        }
                    } else if (*(s8 *)(sub + 0xad) != 0) {
                        doRumble(lbl_803E7ED8);
                        lbl_803DE459 = 1;
                    }
                }
                {
                    u8 c = *(u8 *)((char *)inner + 0x8a9);
                    if (c == 0xf) {
                        *(u8 *)((char *)inner + 0x8c1) = 1;
                    } else if (c == 0x1b) {
                        *(u8 *)((char *)inner + 0x8c1) = 2;
                    } else if (c == 0x11) {
                        *(u8 *)((char *)inner + 0x8c1) = 0;
                    } else {
                        *(u8 *)((char *)inner + 0x8c1) = 1;
                    }
                }
            }
            if (*(void **)(*(int *)((char *)obj + 0x54) + 0x50) != NULL) {
                *(u8 *)(*(int *)((char *)obj + 0x54) + 0x70) = 1;
                *(f32 *)((char *)inner + 0x7d8) = lbl_803E7EA4;
                *(u8 *)((char *)inner + 0x8ce) = *(u8 *)((char *)inner + 0x8cd);
                {
                    HitDesc *t = (HitDesc *)*(int *)((char *)inner + 0x3dc) +
                                 *(u8 *)((char *)inner + 0x8a9);
                    if ((t->flags & 1) != 0) {
                        *(f32 *)((char *)inner + 0x820) = lbl_803E80A8;
                    }
                }
                {
                HitDesc *d = &((HitDesc *)*(int *)((char *)inner + 0x3dc))[*(u8 *)((char *)inner + 0x8a9)];
                if ((d->flags & 2) != 0) {
                    *(u8 *)((char *)inner + 0x8ad) = d->valsA[*(s8 *)((char *)inner + 0x8cd)];
                    {
                        HitDesc *e = (HitDesc *)*(int *)((char *)inner + 0x3dc) +
                                     *(u8 *)((char *)inner + 0x8a9);
                        *(u8 *)((char *)inner + 0x8ac) =
                            e->valsB[*(s8 *)((char *)inner + 0x8cd)];
                    }
                    *(f32 *)((char *)inner + 0x828) =
                        (f32)(u32)*(u8 *)((char *)inner + 0x8ad);
                    *(u8 *)((char *)inner + 0x8ab) += 1;
                    *(int *)((char *)inner + 0x4c0) =
                        *(int *)(*(int *)((char *)obj + 0x54) + 0x50);
                }
                }
            }
        }
        if ((*(u32 *)((char *)inner + 0x360) & 2) != 0) {
            int h = *(int *)((char *)inner + 0xdc);
            if (h != 0 && ((fl = *(u32 *)(*(int *)(h + 0x50) + 0x44)) & 0x40) != 0 &&
                (fl & 0x8000) == 0) {
                objHitDetectFn_80062e84(obj, h, 1);
            } else if (*(void **)((char *)obj + 0x30) != NULL && h == 0) {
                objHitDetectFn_80062e84(obj, 0, 1);
            }
        }
        *(u32 *)((char *)inner + 0x360) |= 2;
        if (*(int *)((char *)inner + 0x7f0) != 0 &&
            ((*(u16 *)((char *)obj + 0xb0) & 0x1000) != 0 ||
             arrayIndexOf(&lbl_803DC6C4, 2, *(s16 *)((char *)inner + 0x274)) != -1)) {
            (*(void (*)(int, f32 *, f32 *, f32 *))(
                *(int *)(*(int *)(*(int *)(*(int *)((char *)inner + 0x7f0) + 0x68)) + 0x34)))(
                *(int *)((char *)inner + 0x7f0), &x, &y, &z);
            (*(void (*)(f32, f32, f32))(*(int *)(*gCameraInterface + 0x2c)))(x, y, z);
            fn_802A9D0C(obj, inner, *(int *)((char *)inner + 0x7f0), 0, 0, 0, 0, 0);
        }
        if (*(s8 *)((char *)inner + 0x25f) == 1 &&
            (*(int *)((char *)inner + 4) & 0x100000) == 0) {
            if ((*(u32 *)((char *)inner + 0x360) & 0x2000) == 0 &&
                (*(s8 *)((char *)inner + 0x264) & 0x33) != 0) {
                *(f32 *)((char *)obj + 0x28) =
                    (*(f32 *)((char *)obj + 0x1c) - *(f32 *)((char *)obj + 0x90)) / dt;
                if (*(f32 *)((char *)obj + 0x28) < lbl_803E811C) {
                    *(f32 *)((char *)obj + 0x28) = lbl_803E811C;
                }
                if (*(f32 *)((char *)obj + 0x28) > lbl_803E7EA4) {
                    *(f32 *)((char *)obj + 0x28) = lbl_803E7EA4;
                }
            }
            if ((*(int *)inner & 0x800000) != 0 &&
                lbl_803E7EA4 == *(f32 *)((char *)inner + 0x890) &&
                lbl_803E7EA4 == *(f32 *)((char *)inner + 0x894)) {
                spd = sqrtf(*(f32 *)((char *)obj + 0x24) * *(f32 *)((char *)obj + 0x24) +
                            *(f32 *)((char *)obj + 0x2c) * *(f32 *)((char *)obj + 0x2c));
                if (*(void **)((char *)obj + 0x30) != NULL) {
                    *(f32 *)((char *)obj + 0x24) =
                        (*(f32 *)((char *)obj + 0xc) - *(f32 *)((char *)obj + 0x80)) / dt;
                    *(f32 *)((char *)obj + 0x2c) =
                        (*(f32 *)((char *)obj + 0x14) - *(f32 *)((char *)obj + 0x88)) / dt;
                } else {
                    *(f32 *)((char *)obj + 0x24) =
                        (*(f32 *)((char *)obj + 0x18) - *(f32 *)((char *)obj + 0x8c)) / dt;
                    *(f32 *)((char *)obj + 0x2c) =
                        (*(f32 *)((char *)obj + 0x20) - *(f32 *)((char *)obj + 0x94)) / dt;
                }
                if (((*(s8 *)((char *)inner + 0x264) & 2) != 0 &&
                     (*(s8 *)((char *)inner + 0x264) & 0x20) == 0) ||
                    *(u8 *)((char *)inner + 0x262) != 0 ||
                    (*(s16 *)(*(int *)((char *)obj + 0x54) + 0x60) & 8) != 0) {
                    if (*(f32 *)((char *)inner + 0x410) <= lbl_803E7EA4 &&
                        *(f32 *)((char *)inner + 0x280) > lbl_803E8160) {
                        doRumble(lbl_803E7F10);
                        *(f32 *)((char *)inner + 0x410) = lbl_803E7F30;
                        Sfx_PlayFromObject(obj, 0x404);
                    }
                    dt = fn_80293E80((lbl_803E7F94 * (f32)*(s16 *)((char *)inner + 0x484)) /
                                     lbl_803E7F98);
                    {
                        f32 s = sin((lbl_803E7F94 * (f32)*(s16 *)((char *)inner + 0x484)) /
                                    lbl_803E7F98);
                        *(f32 *)((char *)inner + 0x280) =
                            -*(f32 *)((char *)obj + 0x2c) * s -
                            *(f32 *)((char *)obj + 0x24) * dt;
                    }
                    *(f32 *)((char *)inner + 0x280) =
                        *(f32 *)((char *)inner + 0x280) * lbl_803E7FC4;
                    {
                        f32 c = *(f32 *)((char *)inner + 0x280);
                        f32 lo = lbl_803E8110 * *(f32 *)((char *)inner + 0x298);
                        *(f32 *)((char *)inner + 0x280) =
                            (c < lo) ? lo
                                     : ((c > *(f32 *)((char *)inner + 0x404))
                                            ? *(f32 *)((char *)inner + 0x404)
                                            : c);
                    }
                    {
                        f32 c = *(f32 *)((char *)inner + 0x280);
                        *(f32 *)((char *)inner + 0x280) =
                            (c < lbl_803E7EA4) ? lbl_803E7EA4 : ((c > spd) ? spd : c);
                    }
                    if (((ByteFlags *)((char *)inner + 0x3f0))->b40 == 0) {
                        *(f32 *)((char *)inner + 0x294) = *(f32 *)((char *)inner + 0x280);
                    }
                }
                *(u32 *)inner &= ~0x800000;
            }
        }
        if ((*(u16 *)((char *)obj + 0xb0) & 0x1000) == 0) {
            *(s16 *)obj = *(s16 *)((char *)inner + 0x478);
        }
        {
            int g = getSbGalleon();
            if (g != 0 && DBprotection_getCameraState() == 2) {
                *(f32 *)(*(int *)((char *)obj + 0x64) + 0x20) =
                    *(f32 *)((char *)obj + 0xc) - *(f32 *)((char *)g + 0xc);
                *(f32 *)(*(int *)((char *)obj + 0x64) + 0x24) =
                    *(f32 *)((char *)obj + 0x10) - *(f32 *)((char *)g + 0x10);
                *(f32 *)(*(int *)((char *)obj + 0x64) + 0x28) =
                    *(f32 *)((char *)obj + 0x14) - *(f32 *)((char *)g + 0x14);
                mathFn_80021ac8((void *)g, (void *)(*(int *)((char *)obj + 0x64) + 0x20));
                *(f32 *)(*(int *)((char *)obj + 0x64) + 0x20) =
                    *(f32 *)(*(int *)((char *)obj + 0x64) + 0x20) + *(f32 *)((char *)g + 0xc);
                *(f32 *)(*(int *)((char *)obj + 0x64) + 0x24) =
                    *(f32 *)(*(int *)((char *)obj + 0x64) + 0x24) + *(f32 *)((char *)g + 0x10);
                *(f32 *)(*(int *)((char *)obj + 0x64) + 0x28) =
                    *(f32 *)(*(int *)((char *)obj + 0x64) + 0x28) + *(f32 *)((char *)g + 0x14);
                *(u32 *)(*(int *)((char *)obj + 0x64) + 0x30) |= 0x2020;
                *(s16 *)((char *)obj + 4) = *(s16 *)((char *)g + 4);
                *(u32 *)((char *)inner + 0x360) |= 0x8000000;
            }
        }
        *(u32 *)((char *)inner + 0x360) &= 0xffbfffff;
    }
}
#pragma peephole reset
#pragma scheduling reset

typedef struct {
    s16 rx, ry, rz;
    f32 scale;
    f32 x, y, z;
} HitFxDesc;

typedef struct {
    int a, b, c, d;
} ColQuad;

typedef struct {
    u8 knock : 3;
    u8 low : 5;
} KnockBits;

typedef struct {
    f32 x, y, z;
} VecXYZ;

extern int objGetFlagsE5_2(int obj);
extern void *Resource_Acquire(int id, int n);
extern void objLightFn_8009a1dc(int obj, f32 fv, void *buf, int n, int m);
extern void fn_8009A8C8(int obj, f32 fv);
extern int lbl_803DE470;
extern int lbl_803DE474;
extern int lbl_802C2C68[];
extern f32 lbl_803E8134;

#pragma scheduling off
#pragma peephole off
void fn_802AFB0C(int obj, int inner, int state)
{
    int orig;
    int work;
    int newAnim;
    int keepKnock;
    int knockKind;
    int canCounter;
    int anim;
    HitFxDesc desc;
    VecXYZ pos;
    u8 buf[12];
    ColQuad col;
    int surfIdx;
    int damage;
    char *hitObj;

    col = *(ColQuad *)lbl_802C2C68;
    knockKind = 0;
    if (*(f32 *)(*(int *)((char *)obj + 0xb8) + 0x838) > lbl_803E7ED8) {
        *(f32 *)((char *)inner + 0x79c) = lbl_803E7EA4;
    }
    if (lbl_803DE470 > 0) {
        lbl_803DE470 = lbl_803DE470 - framesThisStep;
        if (lbl_803DE470 < 0) {
            lbl_803DE470 = 0;
        }
    }
    work = ObjHits_GetPriorityHitWithPosition(obj, &hitObj, &surfIdx, &damage, &pos.x, &pos.y, &pos.z);
    orig = work;
    if (**(s8 **)((char *)inner + 0x35c) <= 0) {
        **(s8 **)((char *)inner + 0x35c) = 1;
    }
    if ((*(int (*)(int))ObjHits_IsObjectEnabled)(obj) == 0 || objGetFlagsE5_2(obj) != 0 ||
        ((ByteFlags *)((char *)inner + 0x3f3))->b20 != 0 ||
        (*(u16 *)((char *)obj + 0xb0) & 0x1000)) {
        return;
    }
    if (*(void **)((char *)inner + 0x7f0) != NULL && work != 0) {
        work = 0x15;
    }
    keepKnock = 1;
    if (work != 0) {
        if (surfIdx != -1) {
            pos.x = pos.x + playerMapOffsetX;
            pos.z = pos.z + playerMapOffsetZ;
        }
        if (*(s16 *)((char *)state + 0x278) != 0) {
            work = 0x1b;
        }
        if (*(s8 *)((char *)state + 0x34d) == 3 && *(s8 *)((char *)state + 0x34f) <= work) {
            return;
        }
        *(s8 *)((char *)state + 0x34f) = work;
        *(s16 *)((char *)obj + 0xa2) = -1;
        newAnim = -1;
        {
            u32 fl = *(u8 *)((char *)inner + 0x3f0);
            if ((fl >> 4 & 1) != 0 || (fl >> 2 & 1) != 0 || (fl >> 3 & 1) != 0 ||
                (fl >> 5 & 1) != 0 ||
                (anim = *(s16 *)((char *)state + 0x274)) == 0x36) {
                canCounter = 0;
            } else if ((u16)(anim - 1) <= 1 || (u16)(anim - 0x24) <= 1 ||
                       *(void **)((char *)state + 0x2d0) != NULL) {
                canCounter = 1;
            } else {
                canCounter = 0;
            }
        }
        switch (work) {
        case 0xb:
            if (canCounter && *(void **)((char *)state + 0x2d0) != NULL) {
                *(u8 *)((char *)inner + 0x8a2) = 2;
                newAnim = 0x23;
                *(int *)((char *)inner + 0x898) = 0;
            }
            break;
        case 7:
        case 8:
        case 9:
            if (canCounter && *(void **)((char *)state + 0x2d0) != NULL) {
                *(u8 *)((char *)inner + 0x8a2) = 3;
                newAnim = 0x23;
                *(int *)((char *)inner + 0x898) = 0;
            }
            break;
        case 0xc:
            if (canCounter && *(void **)((char *)state + 0x2d0) != NULL) {
                *(u8 *)((char *)inner + 0x8a2) = 1;
                newAnim = 0x23;
                *(int *)((char *)inner + 0x898) = 0;
            }
            break;
        case 0xa:
            if (canCounter && *(void **)((char *)state + 0x2d0) != NULL) {
                *(u8 *)((char *)inner + 0x8a2) = 3;
                newAnim = 0x23;
                *(int *)((char *)inner + 0x898) = 0;
            }
            break;
        case 4:
            if (canCounter) {
                newAnim = 0x1f;
                *(int *)((char *)inner + 0x898) = 0;
            }
            break;
        case 1:
            damage = **(s8 **)((char *)inner + 0x35c);
            break;
        case 0x15:
            switch (*(s16 *)(*(int *)((char *)inner + 0x7f0) + 0x46)) {
            case 0x714:
                Camera_EnableViewYOffset();
                CameraShake_SetAllMagnitudes(lbl_803E7EE0);
                break;
            }
            break;
        case 0x16:
            if (((ByteFlags *)((char *)inner + 0x3f0))->b02 == 0) {
                keepKnock = 0;
            }
            if (canCounter && *(void **)((char *)state + 0x2d0) == NULL) {
                *(u8 *)((char *)inner + 0x8a2) = 5;
            }
            break;
        case 0x19:
            Camera_EnableViewYOffset();
            CameraShake_SetAllMagnitudes(lbl_803E7EE0);
            break;
        case 0x1b:
            newAnim = *(s16 *)((char *)state + 0x278);
            break;
        case 0x14:
        case 0x1a:
        case 0x1f:
            if (*(f32 *)((char *)inner + 0x79c) <= lbl_803E7EA4) {
                knockKind = 1;
            }
            if (((ByteFlags *)((char *)inner + 0x3f0))->b02 == 0) {
                keepKnock = 0;
            }
            if (canCounter && *(void **)((char *)state + 0x2d0) == NULL) {
                *(u8 *)((char *)inner + 0x8a2) = 5;
            }
            break;
        case 0x1e:
            if (((ByteFlags *)((char *)inner + 0x3f3))->b08 != 0) {
                return;
            }
            knockKind = 2;
            if (((ByteFlags *)((char *)inner + 0x3f0))->b02 == 0) {
                keepKnock = 0;
            }
            if (canCounter && *(void **)((char *)state + 0x2d0) == NULL) {
                *(u8 *)((char *)inner + 0x8a2) = 5;
            }
            break;
            return;
        case 2:
        case 5:
        case 0x12:
        case 0x17:
        case 0x18:
            break;
        default:
            if (canCounter && *(void **)((char *)state + 0x2d0) != NULL) {
                *(u8 *)((char *)inner + 0x8a2) = 0;
                newAnim = 0x23;
                *(int *)((char *)inner + 0x898) = 0;
            }
            break;
        }
        if ((*(u32 *)((char *)inner + 0x360) & 0x800) == 0 && knockKind != 0) {
            *(f32 *)((char *)inner + 0x79c) = lbl_803E7EDC;
            *(f32 *)((char *)inner + 0x7a0) = lbl_803E8050;
            *(f32 *)((char *)inner + 0x7a4) = lbl_803E7EE0;
            ((KnockBits *)((char *)inner + 0x7a8))->knock = (u8)knockKind;
        }
        if ((*(u32 *)((char *)inner + 0x360) & 0x800) != 0 && keepKnock != 0) {
            damage = 0;
            ((ByteFlags *)((char *)inner + 0x3f6))->b10 = 1;
            if (hitObj != NULL && *(s16 *)(hitObj + 0x46) != 0x2c5) {
                if (lbl_803DE470 == 0) {
                    Sfx_PlayFromObject(
                        obj, (u16)(*(s16 *)((char *)inner + 0x81a) == 0 ? 0x2ce : 0x48c));
                }
                lbl_803DE470 = 6;
            }
            if (lbl_803DE474 == 0) {
                char *pt = *(char **)(*(int *)(*(int *)((char *)obj + 0x7c) +
                                               *(s8 *)((char *)obj + 0xad) * 4) +
                                      0x50);
                desc.x = playerMapOffsetX + *(f32 *)(pt + surfIdx * 0x10 + 4);
                desc.y = *(f32 *)(pt + surfIdx * 0x10 + 8);
                desc.z = playerMapOffsetZ + *(f32 *)(pt + surfIdx * 0x10 + 0xc);
                (**(void (**)(int, int, void *, int, int, int))((char *)(*gPartfxInterface) + 0x8))(
                    obj, 0x328, &desc, 0x200001, -1, 0);
                desc.x -= *(f32 *)((char *)obj + 0x18);
                desc.y -= *(f32 *)((char *)obj + 0x1c);
                desc.z -= *(f32 *)((char *)obj + 0x20);
                if (lbl_803DE454 == NULL) {
                    lbl_803DE454 = Resource_Acquire(0x5a, 1);
                }
                col.b += randomGetRange(0, 0x9b);
                col.c += randomGetRange(0, 0x9b);
                desc.scale = lbl_803E7EE0;
                desc.rx = 0;
                desc.ry = 0;
                desc.rz = 0;
                (**(void (**)(int, int, void *, int, int, ColQuad *))((char *)*(int **)lbl_803DE454 + 0x4))(
                    obj, 0, &desc, 1, -1, &col);
                if (lbl_803DE454 != NULL) {
                    Resource_Release(lbl_803DE454);
                }
                lbl_803DE454 = NULL;
                lbl_803DE474 = 10;
                return;
            } else {
                lbl_803DE474 = lbl_803DE474 - 1;
                return;
            }
        }
        if (damage != 0) {
            {
                int v;
                int hb = *(int *)((char *)obj + 0xb8);
                s8 *hp = *(s8 **)((char *)hb + 0x35c);
                v = *hp - damage;
                if (v < 0) {
                    v = 0;
                } else if (v > hp[1]) {
                    v = hp[1];
                }
                *hp = v;
                if (**(s8 **)((char *)hb + 0x35c) <= 0) {
                    playerDie(obj);
                }
            }
            lbl_803DE474 = 0;
            if (hitObj != NULL) {
                switch (*(s16 *)(hitObj + 0x46)) {
                case 0x11:
                case 0x33:
                case 0x13a:
                case 0x5b7:
                case 0x5b8:
                case 0x5b9:
                case 0x5e1:
                    Sfx_PlayFromObject((int)hitObj, 0x36e);
                    break;
                case 0x5f9:
                case 0x5fa:
                case 0x5fe:
                    Sfx_PlayFromObject((int)hitObj, 0x239);
                    break;
                case 0x2c5:
                    Sfx_PlayFromObject((int)hitObj, 0xd0);
                    break;
                case 0x709:
                    Sfx_PlayFromObject((int)hitObj, 0x486);
                    break;
                case 0x458:
                case 0x842:
                    Sfx_PlayFromObject((int)hitObj, 0x36f);
                    break;
                }
            }
            switch (orig) {
            case 0x16:
                if (hitObj != NULL && (*(s16 *)(hitObj + 0x46) == 0x613 ||
                                    *(s16 *)(hitObj + 0x46) == 0x70f)) {
                    Sfx_PlayFromObject(obj,
                                       (u16)(*(s16 *)((char *)inner + 0x81a) == 0 ? 0x1f : 0x24));
                } else {
                    Sfx_PlayFromObject(obj, 0x367);
                }
                break;
            case 0x14:
            case 0x1f:
                Sfx_PlayFromObject(obj, (u16)(*(s16 *)((char *)inner + 0x81a) == 0 ? 0x1f : 0x24));
                Sfx_PlayFromObject(obj, 0x393);
                if (Sfx_IsPlayingFromObject(obj, 0x394) == 0) {
                    Sfx_PlayFromObject(obj, 0x394);
                }
                if (**(s8 **)((char *)inner + 0x35c) > 0) {
                    objLightFn_8009a1dc(obj, lbl_803E8024, buf, 6, 0);
                }
                break;
            case 0x1c:
                Sfx_PlayFromObject(obj, 0x318);
                if (**(s8 **)((char *)inner + 0x35c) > 0) {
                    objLightFn_8009a1dc(obj, lbl_803E8024, buf, 8, 0);
                }
                break;
            default:
                Sfx_PlayFromObject(obj, (u16)(*(s16 *)((char *)inner + 0x81a) == 0 ? 0x1f : 0x24));
                if (hitObj != NULL) {
                    switch (*(s16 *)(hitObj + 0x46)) {
                    case 0x33:
                        Sfx_PlayFromObject(obj, 0x36e);
                        if (**(s8 **)((char *)inner + 0x35c) > 0) {
                            objLightFn_8009a1dc(obj, lbl_803E8024, buf, 5, 0);
                        }
                        break;
                    case 0x7c8:
                        if (**(s8 **)((char *)inner + 0x35c) > 0) {
                            objLightFn_8009a1dc(obj, lbl_803E8024, buf, 8, 0);
                        }
                        break;
                    default:
                        if (**(s8 **)((char *)inner + 0x35c) > 0) {
                            objLightFn_8009a1dc(obj, lbl_803E8024, buf, 5, 0);
                        }
                        break;
                    }
                } else {
                    if (**(s8 **)((char *)inner + 0x35c) > 0) {
                        objLightFn_8009a1dc(obj, lbl_803E8024, buf, 5, 0);
                    }
                }
                break;
            }
            if (**(s8 **)((char *)inner + 0x35c) > 0) {
                Obj_SetModelColorFadeRecursive(obj, 0xb4, 200, 0, 0, 1);
            }
            if (*(s16 *)((char *)state + 0x274) == 0x1a) {
                fn_8009A8C8(obj, lbl_803E8134);
            }
            *(f32 *)((char *)inner + 0x814) = lbl_803E7EA4;
            *(s16 *)((char *)inner + 0x812) = randomGetRange(800, 0x44c);
            *(u8 *)((char *)inner + 0x800) = 0;
            if (*(void **)((char *)inner + 0x7f8) != NULL) {
                s16 t = *(s16 *)(*(int *)((char *)inner + 0x7f8) + 0x46);
                if (t == 0x3cf || t == 0x662) {
                    objThrowFn_80182504(*(int *)((char *)inner + 0x7f8));
                } else {
                    objSaveFn_800ea774(*(int *)((char *)inner + 0x7f8));
                }
                *(s16 *)(*(int *)((char *)inner + 0x7f8) + 6) =
                    *(s16 *)(*(int *)((char *)inner + 0x7f8) + 6) & ~0x4000;
                *(int *)(*(int *)((char *)inner + 0x7f8) + 0xf8) = 0;
                *(int *)((char *)inner + 0x7f8) = 0;
            }
            if (newAnim != -1 && *(s16 *)((char *)state + 0x274) != newAnim &&
                **(s8 **)((char *)inner + 0x35c) > 0) {
                (*(void (*)(int, int, int))(*(int *)(*gPlayerInterface + 0x14)))(obj, state, newAnim);
                *(int *)((char *)state + 0x304) = *(int *)((char *)inner + 0x898);
            }
        } else {
            lbl_803DE474 = 0;
        }
    } else {
        lbl_803DE474 = 0;
    }
}
#pragma peephole reset
#pragma scheduling reset


#pragma scheduling off
#pragma peephole off
void fn_802B249C(int obj, int inner, int state)
{
    int p;
    int param = 0;
    int msg;

    while (ObjMsg_Pop(obj, &msg, &p, &param) != 0) {
        switch (msg) {
        case 0x80002:
            *(s16 *)((char *)inner + 0x80c) = (s16)param;
            if (*(void **)((char *)state + 0x2d0) != NULL &&
                (param == 0x2d || param == 0x5ce)) {
                *(s16 *)((char *)inner + 0x80e) = (s16)param;
                *(s16 *)((char *)inner + 0x80c) = -1;
            }
            break;
        case 0x60003: {
            f32 dx = *(f32 *)(p + 0xc) - *(f32 *)((char *)obj + 0xc);
            f32 dz = *(f32 *)(p + 0x14) - *(f32 *)((char *)obj + 0x14);
            f32 d = sqrtf(dx * dx + dz * dz);
            if (d > lbl_803E7EE0) {
                dx = dx / d;
                dz = dz / d;
            }
            *(f32 *)((char *)obj + 0x24) = lbl_803E7F9C * dx;
            *(f32 *)((char *)obj + 0x2c) = lbl_803E7F9C * dz;
            *(f32 *)((char *)obj + 0x28) = lbl_803E7F9C;
            (*(void (*)(int, int, int))(*(int *)(*gPlayerInterface + 0x14)))(obj, state, 0x21);
            *(int *)((char *)state + 0x304) = 0;
            {
                int in2 = *(int *)((char *)obj + 0xb8);
                s8 *pc = *(s8 **)((char *)in2 + 0x35c);
                int v = pc[0] - param;
                if (v < 0) {
                    v = 0;
                } else if (v > pc[1]) {
                    v = pc[1];
                }
                pc[0] = (s8)v;
                if (**(s8 **)((char *)in2 + 0x35c) < 1) {
                    playerDie(obj);
                }
            }
            *(u8 *)((char *)inner + 0x800) = 0;
            if (*(void **)((char *)inner + 0x7f8) != NULL) {
                s16 typ = *(s16 *)((char *)*(int *)((char *)inner + 0x7f8) + 0x46);
                if (typ == 0x3cf || typ == 0x662) {
                    objThrowFn_80182504(*(int *)((char *)inner + 0x7f8));
                } else {
                    objSaveFn_800ea774(*(int *)((char *)inner + 0x7f8));
                }
                *(s16 *)((char *)*(int *)((char *)inner + 0x7f8) + 0x6) =
                    *(s16 *)((char *)*(int *)((char *)inner + 0x7f8) + 0x6) & ~0x4000;
                *(int *)((char *)*(int *)((char *)inner + 0x7f8) + 0xf8) = 0;
                *(int *)((char *)inner + 0x7f8) = 0;
            }
            break;
        }
        case 0x60004: {
            f32 dx = *(f32 *)(p + 0xc) - *(f32 *)((char *)obj + 0xc);
            f32 dz = *(f32 *)(p + 0x14) - *(f32 *)((char *)obj + 0x14);
            f32 d = sqrtf(dx * dx + dz * dz);
            if (d > lbl_803E7EE0) {
                dx = dx / d;
                dz = dz / d;
            }
            *(f32 *)((char *)obj + 0x24) = lbl_803E7F9C * -dx;
            *(f32 *)((char *)obj + 0x2c) = lbl_803E7F9C * -dz;
            *(f32 *)((char *)obj + 0x28) = lbl_803E7F9C;
            (*(void (*)(int, int, int))(*(int *)(*gPlayerInterface + 0x14)))(obj, state, 0x21);
            *(int *)((char *)state + 0x304) = 0;
            {
                int in2 = *(int *)((char *)obj + 0xb8);
                s8 *pc = *(s8 **)((char *)in2 + 0x35c);
                int v = pc[0] - param;
                if (v < 0) {
                    v = 0;
                } else if (v > pc[1]) {
                    v = pc[1];
                }
                pc[0] = (s8)v;
                if (**(s8 **)((char *)in2 + 0x35c) < 1) {
                    playerDie(obj);
                }
            }
            *(u8 *)((char *)inner + 0x800) = 0;
            if (*(void **)((char *)inner + 0x7f8) != NULL) {
                s16 typ = *(s16 *)((char *)*(int *)((char *)inner + 0x7f8) + 0x46);
                if (typ == 0x3cf || typ == 0x662) {
                    objThrowFn_80182504(*(int *)((char *)inner + 0x7f8));
                } else {
                    objSaveFn_800ea774(*(int *)((char *)inner + 0x7f8));
                }
                *(s16 *)((char *)*(int *)((char *)inner + 0x7f8) + 0x6) =
                    *(s16 *)((char *)*(int *)((char *)inner + 0x7f8) + 0x6) & ~0x4000;
                *(int *)((char *)*(int *)((char *)inner + 0x7f8) + 0xf8) = 0;
                *(int *)((char *)inner + 0x7f8) = 0;
            }
            Sfx_PlayFromObject(obj,
                               (u16)(*(s16 *)((char *)inner + 0x81a) == 0 ? 0x1f : 0x24));
            break;
        }
        case 0x60005: {
            f32 dx = *(f32 *)(p + 0xc) - *(f32 *)((char *)obj + 0xc);
            f32 dz = *(f32 *)(p + 0x14) - *(f32 *)((char *)obj + 0x14);
            f32 d = sqrtf(dx * dx + dz * dz);
            if (d > lbl_803E7EE0) {
                dx = dx / d;
                dz = dz / d;
            }
            *(f32 *)((char *)obj + 0x24) = lbl_803E7F9C * -dx;
            *(f32 *)((char *)obj + 0x2c) = lbl_803E7F9C * -dz;
            *(f32 *)((char *)obj + 0x28) = lbl_803E7F9C;
            (*(void (*)(int, int, int))(*(int *)(*gPlayerInterface + 0x14)))(obj, state, 0x21);
            *(int *)((char *)state + 0x304) = 0;
            ObjAnim_SetCurrentMove(obj, 0x450, lbl_803E7EA4, 0);
            {
                int in2 = *(int *)((char *)obj + 0xb8);
                s8 *pc = *(s8 **)((char *)in2 + 0x35c);
                int v = pc[0] - param;
                if (v < 0) {
                    v = 0;
                } else if (v > pc[1]) {
                    v = pc[1];
                }
                pc[0] = (s8)v;
                if (**(s8 **)((char *)in2 + 0x35c) < 1) {
                    playerDie(obj);
                }
            }
            *(u8 *)((char *)inner + 0x800) = 0;
            if (*(void **)((char *)inner + 0x7f8) != NULL) {
                s16 typ = *(s16 *)((char *)*(int *)((char *)inner + 0x7f8) + 0x46);
                if (typ == 0x3cf || typ == 0x662) {
                    objThrowFn_80182504(*(int *)((char *)inner + 0x7f8));
                } else {
                    objSaveFn_800ea774(*(int *)((char *)inner + 0x7f8));
                }
                *(s16 *)((char *)*(int *)((char *)inner + 0x7f8) + 0x6) =
                    *(s16 *)((char *)*(int *)((char *)inner + 0x7f8) + 0x6) & ~0x4000;
                *(int *)((char *)*(int *)((char *)inner + 0x7f8) + 0xf8) = 0;
                *(int *)((char *)inner + 0x7f8) = 0;
            }
            break;
        }
        case 0x7000a: {
            int t;
            s16 bit;
            *(int *)((char *)inner + 0x8dc) = param;
            t = *(int *)(p + 0x64);
            if (t != 0) {
                *(u32 *)(t + 0x30) &= 0xfffffffb;
            }
            bit = **(s16 **)((char *)inner + 0x8dc);
            if (bit > 0) {
                if (GameBit_Get(bit) != 0) {
                    ObjMsg_SendToObject(p, 0x7000b, obj, 0);
                    break;
                } else {
                    f32 r = *(f32 *)(p + 8) / *(f32 *)(*(int *)(p + 0x50) + 4);
                    f32 k = lbl_803E7F68;
                    f32 lim = lbl_803E7F30;
                    while (r * (*(f32 *)((char *)obj + 0xa8) * *(f32 *)((char *)obj + 8)) >
                           lim) {
                        *(f32 *)(p + 8) = *(f32 *)(p + 8) * k;
                        r = *(f32 *)(p + 8) / *(f32 *)(*(int *)(p + 0x50) + 4);
                    }
                    GameBit_Set(**(s16 **)((char *)inner + 0x8dc), 1);
                    (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x7c)))(
                        *(s16 *)(p + 0x46), 0, 0);
                    (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(
                        0, obj, -1);
                }
            } else {
                f32 r = *(f32 *)(p + 8) / *(f32 *)(*(int *)(p + 0x50) + 4);
                f32 k = lbl_803E7F68;
                f32 lim = lbl_803E7F30;
                while (r * (*(f32 *)((char *)obj + 0xa8) * *(f32 *)((char *)obj + 8)) > lim) {
                    *(f32 *)(p + 8) = *(f32 *)(p + 8) * k;
                    r = *(f32 *)(p + 8) / *(f32 *)(*(int *)(p + 0x50) + 4);
                }
                (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x7c)))(
                    *(s16 *)(p + 0x46), 0, 0);
                (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(0, obj,
                                                                                        -1);
            }
            *(int *)((char *)inner + 0x684) = p;
            *(s16 *)((char *)inner + 0x688) = *(s16 *)(*(int *)((char *)inner + 0x8dc) + 2);
            t = *(int *)(*(int *)((char *)inner + 0x684) + 0x64);
            if (t != 0) {
                *(int *)(t + 0x30) = 0x1000;
            }
            if (lbl_803DE44C != 0 && ((ByteFlags *)((char *)inner + 0x3f4))->b40 != 0) {
                *(u8 *)((char *)inner + 0x8b4) = 1;
                ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 1;
            }
            break;
        }
        case 0x100008:
            *(u8 *)((char *)inner + 0x800) = 1;
            if (*(int *)((char *)inner + 0x7f8) == 0) {
                int *mdl;
                *(int *)((char *)inner + 0x7f8) = p;
                mdl = (int *)Obj_GetActiveModel(*(int *)((char *)inner + 0x7f8));
                if (mdl != NULL && *mdl != 0 && (*(u16 *)(*mdl + 2) & 0x8000) == 0) {
                    *(u8 *)(*(int *)((char *)inner + 0x7f8) + 0xf2) =
                        *(u8 *)((char *)obj + 0xf2);
                }
                *(f32 *)((char *)inner + 0x7fc) = (f32)(param >> 0x10) / lbl_803E7ED8;
                (*(void (*)(int, int, int))(*(int *)(*gPlayerInterface + 0x14)))(obj, state, 5);
                *(int *)((char *)state + 0x304) = (int)fn_802A4B4C;
                if (lbl_803DE44C != 0 && ((ByteFlags *)((char *)inner + 0x3f4))->b40 != 0) {
                    *(u8 *)((char *)inner + 0x8b4) = 1;
                    ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 1;
                }
            }
            break;
        case 0x100010:
            *(u8 *)((char *)inner + 0x800) = 1;
            if (*(int *)((char *)inner + 0x7f8) == 0) {
                int *mdl;
                *(int *)((char *)inner + 0x7f8) = p;
                mdl = (int *)Obj_GetActiveModel(*(int *)((char *)inner + 0x7f8));
                if (mdl != NULL && *mdl != 0 && (*(u16 *)(*mdl + 2) & 0x8000) == 0) {
                    *(u8 *)(*(int *)((char *)inner + 0x7f8) + 0xf2) =
                        *(u8 *)((char *)obj + 0xf2);
                }
                *(f32 *)((char *)inner + 0x7fc) = (f32)(param >> 0x10);
                (*(void (*)(int, int, int))(*(int *)(*gPlayerInterface + 0x14)))(obj, state, 5);
                *(int *)((char *)state + 0x304) = (int)fn_802A4B4C;
                if (lbl_803DE44C != 0 && ((ByteFlags *)((char *)inner + 0x3f4))->b40 != 0) {
                    *(u8 *)((char *)inner + 0x8b4) = 1;
                    ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 1;
                }
            }
            break;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_80295B2C(int obj, f32 f1, f32 f2, f32 f3)
{
    int inner = *(int *)((char *)obj + 0xb8);
    *(f32 *)((char *)obj + 0x8c) = f1;
    *(f32 *)((char *)obj + 0x80) = f1;
    *(f32 *)((char *)obj + 0x18) = f1;
    *(f32 *)((char *)obj + 0xc) = f1;
    *(f32 *)((char *)obj + 0x90) = f2;
    *(f32 *)((char *)obj + 0x84) = f2;
    *(f32 *)((char *)obj + 0x1c) = f2;
    *(f32 *)((char *)obj + 0x10) = f2;
    *(f32 *)((char *)obj + 0x94) = f3;
    *(f32 *)((char *)obj + 0x88) = f3;
    *(f32 *)((char *)obj + 0x20) = f3;
    *(f32 *)((char *)obj + 0x14) = f3;
    fn_802AB5A4(obj, inner, 7);
    (*(void (*)(int, int, int))(*(int *)(*gPlayerInterface + 0x14)))(obj, inner, 1);
    *(int *)((char *)inner + 0x304) = (int)fn_802A514C;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802A4F8C(int obj, int state, f32 fv)
{
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        ObjAnim_SetCurrentMove(obj, 0x92, lbl_803E7EA4, 0);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E8060;
    }
    (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x20)))(obj, state, fv, 3);
    if (*(s8 *)((char *)state + 0x346) != 0) {
        *(int *)((char *)state + 0x308) = (int)fn_802A514C;
        return 2;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void playerAddMoney(int obj, int amount)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int cap;
    int total;
    if (GameBit_Get(0x91b)) {
        cap = 0xc8;
    } else if (GameBit_Get(0x91a)) {
        cap = 0x64;
    } else if (GameBit_Get(0x919)) {
        cap = 0x32;
    } else {
        cap = 0xa;
    }
    total = *(u8 *)((char *)*(int *)((char *)inner + 0x35c) + 8);
    total += amount;
    if (amount > *(u8 *)((char *)inner + 0x3e8)) {
        *(u8 *)((char *)inner + 0x3e8) = (u8)amount;
    }
    if (total < 0) {
        total = 0;
    } else if (total > cap) {
        total = cap;
    }
    *(u8 *)((char *)*(int *)((char *)inner + 0x35c) + 8) = (u8)total;
    GameBit_Set(0x1be, total);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_80296C84(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int deref = *(int *)((char *)inner + 0x35c);
    int v = *(s8 *)((char *)deref + 1);
    if (v < 0) {
        v = 0;
    } else if (v > *(s8 *)((char *)deref + 1)) {
        v = *(s8 *)((char *)deref + 1);
    }
    *(s8 *)((char *)*(int *)((char *)inner + 0x35c)) = (s8)v;
    Obj_SetModelColorFadeRecursive(obj, 0x168, 0xc8, 0, 0, 1);
    ((ByteFlags *)((char *)inner + 0x3f3))->b04 = 1;
    *(f32 *)((char *)inner + 0x79c) = lbl_803E7EA4;
    *(u8 *)((char *)inner + 0x8a2) = 0xff;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_8029672C(int obj, int mode)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if (mode == 0) {
        if (lbl_803DE44C == NULL) return;
        if (((ByteFlags *)((char *)inner + 0x3f4))->b40 == 0) return;
        *(u8 *)((char *)inner + 0x8b4) = 0;
        ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 0;
    } else if (mode == 1) {
        if (lbl_803DE44C == NULL) return;
        if (((ByteFlags *)((char *)inner + 0x3f4))->b40 == 0) return;
        *(u8 *)((char *)inner + 0x8b4) = 1;
        ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 1;
    } else {
        if (lbl_803DE44C == NULL) return;
        if (((ByteFlags *)((char *)inner + 0x3f4))->b40 == 0) return;
        *(u8 *)((char *)inner + 0x8b4) = 1;
        ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 0;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802967E0(int obj, int mode)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if (mode == 0) {
        if (lbl_803DE44C == NULL) return;
        if (((ByteFlags *)((char *)inner + 0x3f4))->b40 == 0) return;
        *(u8 *)((char *)inner + 0x8b4) = 2;
        ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 0;
    } else if (mode == 1) {
        if (lbl_803DE44C == NULL) return;
        if (((ByteFlags *)((char *)inner + 0x3f4))->b40 == 0) return;
        *(u8 *)((char *)inner + 0x8b4) = 4;
        ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 1;
    } else {
        if (lbl_803DE44C == NULL) return;
        if (((ByteFlags *)((char *)inner + 0x3f4))->b40 == 0) return;
        *(u8 *)((char *)inner + 0x8b4) = 4;
        ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 0;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_8029B6BC(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int r = ((int (*)(int, int, int))fn_802AC7DC)(obj, state, inner);
    if (r != 0) {
        return r;
    }
    if (*(s16 *)((char *)obj + 0xa0) != 0x449) {
        u8 c;
        ObjAnim_SetCurrentMove(obj, 0x449, lbl_803E7EA4, 0);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7F4C;
        Sfx_PlayFromObject(obj, 0x40b);
        c = *(u8 *)((char *)inner + 0x8c8);
        if (c != 0x42 && c != 0x4c) {
            (*(void (*)(int, int, int, int, int, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
                0x42, 0, 1, 0, 0, 0x3c, 0xfe);
        }
    }
    if (*(s8 *)((char *)state + 0x346) != 0) {
        *(int *)((char *)state + 0x308) = (int)fn_802A514C;
        return -1;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int Lightfoot_UpdateProximityInteractionState(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if (*(void **)((char *)state + 0x2d0) != NULL) {
        if (*(u16 *)((char *)*(int *)((char *)inner + 0x40c) + 0x22) <
            *(u16 *)((char *)inner + 0x3fe)) {
            if (*(s8 *)((char *)state + 0x27b) != 0 || *(s8 *)((char *)state + 0x346) != 0 ||
                *(s16 *)((char *)state + 0x274) == 0) {
                (*(void (*)(int, int, int))(*(int *)(*gPlayerInterface + 0x14)))(obj, state, 4);
            }
        } else if (*(s8 *)((char *)state + 0x27b) != 0 || *(s8 *)((char *)state + 0x346) != 0) {
            (*(void (*)(int, int, int))(*(int *)(*gPlayerInterface + 0x14)))(obj, state, 0);
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802A1114(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int flag549;
    f32 fz;
    s16 *tbl;
    int flags;
    int model;
    u8 ic;
    f32 buf1[3];
    f32 buf2[2];
    f32 pos[2];
    *(int *)((char *)inner + 0x360) &= ~2;
    *(int *)((char *)inner + 0x360) |= 0x2000;
    *(int *)((char *)state + 0x4) |= 0x100000;
    fz = lbl_803E7EA4;
    *(f32 *)((char *)state + 0x280) = fz;
    *(f32 *)((char *)state + 0x284) = fz;
    *(int *)((char *)state + 0x0) |= 0x200000;
    *(f32 *)((char *)obj + 0x24) = fz;
    *(f32 *)((char *)obj + 0x2c) = fz;
    *(int *)((char *)state + 0x4) |= 0x8000000;
    *(f32 *)((char *)obj + 0x28) = fz;
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        *(s16 *)((char *)state + 0x278) = 0x12;
        *(int *)((char *)inner + 0x898) = (int)fn_8029FFD0;
        if (lbl_803DE44C != NULL) {
            if (((ByteFlags *)((char *)inner + 0x3f4))->b40) {
                *(u8 *)((char *)inner + 0x8b4) = 1;
                ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 1;
            }
        }
        ObjHits_MarkObjectPositionDirty(obj);
    }
    flag549 = *(s8 *)((char *)inner + 0x549);
    if (flag549 != 0) {
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7EF8;
    } else {
        *(f32 *)((char *)state + 0x2a0) = lbl_803E8008;
    }
    fn_802A13F4(obj, state);
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        *(f32 *)((char *)state + 0x280) = lbl_803E7EA4;
        *(f32 *)((char *)state + 0x284) = lbl_803E7EA4;
        *(s16 *)((char *)inner + 0x478) =
            (s16)getAngle(*(f32 *)((char *)inner + 0x56c), *(f32 *)((char *)inner + 0x574));
        *(s16 *)((char *)inner + 0x484) = *(s16 *)((char *)inner + 0x478);
        *(f32 *)((char *)obj + 0xc) = *(f32 *)((char *)inner + 0x58c);
        *(f32 *)((char *)obj + 0x14) = *(f32 *)((char *)inner + 0x594);
        if (flag549 != 0) {
            tbl = &lbl_803DC69C;
        } else {
            tbl = &lbl_803DC698;
        }
        flags = 0x25;
        if (flag549 != 0) {
            flags |= 0x40;
        }
        *(s16 *)((char *)inner + 0x5a4) =
            fn_802A71E0(obj, tbl[0], tbl[1], (int *)((char *)inner + 0x598),
                        (int *)((char *)inner + 0x56c), lbl_803E7EA4, lbl_803E7EA4, 2, (u8)flags);
        model = *(int *)((char *)*(int *)((char *)obj + 0x7c) +
                         ((s32)(*(s8 *)((char *)obj + 0xad)) << 2));
        ObjModel_SampleJointTransform(model, 0, 0, lbl_803E7EE0,
                                      *(f32 *)((char *)obj + 0x8), buf1, buf2);
        *(f32 *)((char *)inner + 0x564) = lbl_803E7EA4;
        *(f32 *)((char *)inner + 0x560) = buf1[1];
        *(f32 *)((char *)inner + 0x568) = lbl_803E7EA4;
        pos[0] = *(f32 *)((char *)inner + 0x54c);
        pos[1] = *(f32 *)((char *)inner + 0x550);
        ic = *(u8 *)((char *)inner + 0x8c8);
        if (ic != 0x48 && ic != 0x47) {
            (*(void (*)(int, int, int, int, f32 *, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
                0x4b, 1, 1, 8, pos, 0, 0);
        }
    } else {
        if (*(f32 *)((char *)obj + 0x98) >= lbl_803E7EE0) {
            *(int *)((char *)state + 0x308) = (int)fn_8029FFD0;
            return 0x14;
        }
    }
    ObjAnim_WriteStateWord((ObjAnimComponent *)obj, OBJANIM_STATE_INDEX_CURRENT,
                           OBJANIM_STATE_WORD_EVENT_STATE, *(s16 *)((char *)inner + 0x5a4));
    (*(void (*)(f32, f32, f32))(*(int *)(*gCameraInterface + 0x2c)))(
        *(f32 *)((char *)obj + 0xc),
        *(f32 *)((char *)inner + 0x560) * *(f32 *)((char *)obj + 0x98) + *(f32 *)((char *)obj + 0x10),
        *(f32 *)((char *)obj + 0x14));
    fn_802AB5A4(obj, inner, 5);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
s16 fn_802A71E0(int obj, int a, int b, int *p6, int *p7, f32 e, f32 f, int n, int flags)
{
    int model;
    int uf;
    u8 mf;
    int sel;
    int blend;
    f32 v1, v2, t;
    f32 buf1[3];
    f32 buf2[2];
    model = *(int *)((char *)*(int *)((char *)obj + 0x7c) +
                     ((s32)(*(s8 *)((char *)obj + 0xad)) << 2));
    uf = (u8)flags;
    mf = 0;
    if (uf & 0x2) {
        mf |= 0x2;
    }
    if (uf & 0x40) {
        mf |= 0x4;
    }
    if (uf & 0x10) {
        mf |= 0x8;
    }
    if (uf & 0x20) {
        mf |= 0x1;
    }
    sel = uf & 0x4;
    if (sel != 0) {
        ObjAnim_SetCurrentMove(obj, a, lbl_803E7EA4, mf);
        ObjAnim_AdvanceCurrentMove(f, lbl_803E7EA4, obj, NULL);
        ObjModel_SampleJointTransform(model, 0, 0, e, *(f32 *)((char *)obj + 0x8), buf1, buf2);
    } else {
        Object_ObjAnimSetMove(lbl_803E7EA4, obj, a, mf);
        Object_ObjAnimAdvanceMove(f, lbl_803E7EA4, obj, NULL);
        ObjModel_SampleJointTransform(model, 1, 0, e, *(f32 *)((char *)obj + 0x8), buf1, buf2);
    }
    v1 = *(f32 *)((char *)buf1 + ((u8)n << 2));
    if (v1 < lbl_803E7EA4) {
        v1 = -v1;
    }
    if (sel != 0) {
        Object_ObjAnimSetSecondaryBlendMove((ObjAnimComponent *)obj, b, 0);
        ObjModel_SampleJointTransform(model, 0, 2, e, *(f32 *)((char *)obj + 0x8), buf1, buf2);
    } else {
        Object_ObjAnimSetPrimaryBlendMove((ObjAnimComponent *)obj, b, 0);
        ObjModel_SampleJointTransform(model, 1, 2, e, *(f32 *)((char *)obj + 0x8), buf1, buf2);
    }
    v2 = *(f32 *)((char *)buf1 + ((u8)n << 2));
    if (v2 < lbl_803E7EA4) {
        v2 = -v2;
    }
    t = *(f32 *)((char *)p7 + 0xc) +
        (*(f32 *)((char *)p6 + 0x0) * *(f32 *)((char *)p7 + 0x0) +
         *(f32 *)((char *)p6 + 0x8) * *(f32 *)((char *)p7 + 0x8));
    if (t < lbl_803E7EA4) {
        t = -t;
    }
    t = (t - v1) / (v2 - v1);
    if (uf & 0x1) {
        if (t < lbl_803E7EA4) {
            t = lbl_803E7EA4;
        }
    } else {
        if (t < lbl_803E7EA4) {
            t = -t;
        }
    }
    if (t > lbl_803E7EE0) {
        t = lbl_803E7EE0;
    }
    blend = (int)(lbl_803E7FAC * t);
    if (sel != 0) {
        Object_ObjAnimSetSecondaryBlendMove((ObjAnimComponent *)obj, b, (s16)blend);
    } else {
        Object_ObjAnimSetPrimaryBlendMove((ObjAnimComponent *)obj, b, (s16)blend);
    }
    return blend;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_8029F6E4(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);
    void *sub;
    f32 out;
    f32 a;
    int b;
    f32 c;
    int d;
    f32 ret;
    int blend;
    (*(void (*)(int))(*(int *)(*gCameraInterface + 0x68)))(2);
    *(u8 *)((char *)state + 0x25f) = 0;
    *(int *)((char *)state + 0x4) |= 0x100000;
    *(int *)((char *)inner + 0x360) &= ~2;
    ObjHits_DisableObject(obj);
    sub = *(void **)((char *)inner + 0x7f0);
    if (sub == NULL) {
        *(s16 *)((char *)obj + 0xa2) = -1;
        return 0;
    }
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        if (*(void **)((char *)inner + 0x6e8) == NULL) {
            *(int *)((char *)inner + 0x6e8) = (int)lbl_803332B0;
        }
        ObjAnim_SetCurrentMove(obj, *(s16 *)(*(int *)((char *)inner + 0x6e8) + 0x2),
                               lbl_803E7EA4, 0);
        ObjAnim_AdvanceCurrentMove(lbl_803E7EA4, lbl_803E7EA4, obj, NULL);
    }
    if ((*(u8 *)((char *)inner + 0x6ec) & 0x4) != 0) {
        ObjAnim_SetMoveProgress(*(f32 *)((char *)sub + 0x98), (ObjAnimComponent *)obj);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7EA4;
    } else {
        ret = (*(f32 (*)(int, f32 *))(*(int *)((char *)*(int *)*(int *)((char *)sub + 0x68) + 0x44)))(
            (int)sub, &out);
        if (out <= lbl_803E7EE0) {
            *(f32 *)((char *)state + 0x2a0) = out;
        } else {
            *(f32 *)((char *)state + 0x2a0) = lbl_803E7F6C * ret + lbl_803E7EF8;
        }
    }
    if ((*(u8 *)((char *)inner + 0x6ec) & 0x1) != 0) {
        (*(void (*)(int, f32 *, int *))(*(int *)((char *)*(int *)*(int *)((char *)sub + 0x68) + 0x40)))(
            (int)sub, &a, &b);
        blend = (int)(lbl_803E7FAC * a);
        if (blend < 0) {
            blend = -blend;
        }
        if (b != 0) {
            Object_ObjAnimSetSecondaryBlendMove((ObjAnimComponent *)obj,
                                                *(s16 *)(*(int *)((char *)inner + 0x6e8) + 0xa), blend);
        } else {
            Object_ObjAnimSetSecondaryBlendMove((ObjAnimComponent *)obj,
                                                *(s16 *)(*(int *)((char *)inner + 0x6e8) + 0x8), blend);
        }
    } else if ((*(u8 *)((char *)inner + 0x6ec) & 0x8) != 0) {
        (*(void (*)(int, f32 *, int *))(*(int *)((char *)*(int *)*(int *)((char *)sub + 0x68) + 0x40)))(
            (int)sub, &c, &d);
        *(int *)((char *)inner + 0x360) |= 0x2000000;
        *(s16 *)((char *)inner + 0x4d6) = (s16)d;
        *(s16 *)((char *)inner + 0x4d4) = (s16)c;
        *(s16 *)((char *)inner + 0x4d2) = *(s16 *)((char *)inner + 0x4d4) / 2;
        *(s16 *)((char *)inner + 0x4d0) = *(s16 *)((char *)inner + 0x4d4) / 2;
    }
    if ((*(u8 *)((char *)inner + 0x6ec) & 0x1) != 0) {
        ObjAnim_WriteStateWord((ObjAnimComponent *)obj, OBJANIM_STATE_INDEX_CURRENT,
                               OBJANIM_STATE_WORD_PREV_EVENT_STATE, 0);
        ObjAnim_WriteStateWord((ObjAnimComponent *)obj, OBJANIM_STATE_INDEX_ACTIVE,
                               OBJANIM_STATE_WORD_PREV_EVENT_STATE, 0);
    }
    if ((*(int (*)(int, int))(*(int *)((char *)*(int *)*(int *)((char *)sub + 0x68) + 0x2c)))(
            (int)sub, obj) != 0) {
        *(int *)((char *)state + 0x308) = 0;
        return 0x1a;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802A93F4(int obj, int p2, int p3)
{
    int inner = *(int *)((char *)obj + 0xb8);
    f32 dist;
    void *found;
    s16 *vec;
    int *tex;
    dist = lbl_803E80CC;
    *(f32 *)((char *)obj + 0x8) = lbl_803E7EE0;
    viewFinderSetZoom(Camera_GetFovY());
    *(u16 *)((char *)obj + 0xb0) &= ~0x1000;
    *(u8 *)((char *)obj + 0x36) = 0xff;
    ((ByteFlags *)((char *)inner + 0x3f2))->b80 = 0;
    if (((ByteFlags *)((char *)inner + 0x3f2))->b40) {
        *(f32 *)((char *)inner + 0x87c) = lbl_803E7FBC;
    }
    ((ByteFlags *)((char *)inner + 0x3f2))->b40 = 0;
    ((ByteFlags *)((char *)inner + 0x3f2))->b20 = 0;
    ((ByteFlags *)((char *)inner + 0x3f4))->b80 = 0;
    ObjHits_EnableObject(obj);
    *(f32 *)((char *)obj + 0x28) = lbl_803E7EA4;
    if ((*(s16 *)((char *)p3 + 0x6e) & 1) != 0) {
        fn_802AB5A4(obj, inner, 7);
    }
    fn_80026C30(lbl_803DE420, 1);
    *(u8 *)((char *)inner + 0x8c4) = 2;
    if (lbl_803DE444 != NULL) {
        found = (void *)ObjGroup_FindNearestObject(0x20, obj, &dist);
        if (found != NULL) {
            (*(void (*)(void *))(*(int *)((char *)*(int *)*(int *)((char *)found + 0x68) + 0x24)))(found);
        }
        ObjLink_DetachChild(obj, (int)lbl_803DE444);
        Obj_FreeObject((int)lbl_803DE444);
        lbl_803DE444 = NULL;
    }
    *(int *)((char *)inner + 0x360) |= 0x800000;
    *(int *)((char *)inner + 0x684) = 0;
    ((ByteFlags *)((char *)inner + 0x3f0))->b10 = 0;
    ((ByteFlags *)((char *)inner + 0x3f0))->b08 = 0;
    ((ByteFlags *)((char *)inner + 0x3f0))->b04 = 0;
    *(u8 *)((char *)inner + 0x40d) = 0;
    ((ByteFlags *)((char *)inner + 0x3f0))->b80 = 0;
    ((ByteFlags *)((char *)inner + 0x3f0))->b40 = 0;
    ((ByteFlags *)((char *)inner + 0x3f0))->b20 = 0;
    *(s16 *)((char *)inner + 0x80a) = -1;
    ((ByteFlags *)((char *)inner + 0x3f6))->b40 = 0;
    staffFn_80170380(lbl_803DE450, 2);
    ((ByteFlags *)((char *)inner + 0x3f0))->b02 = 0;
    *(int *)((char *)inner + 0x360) |= 0x800000;
    ObjHits_SyncObjectPositionIfDirty(obj);
    *(f32 *)((char *)inner + 0x838) = lbl_803E7EA4;
    *(f32 *)((char *)inner + 0x83c) = lbl_803E80D0;
    *(f32 *)((char *)inner + 0x880) = lbl_803E7FA4;
    *(u8 *)((char *)inner + 0x25f) = 1;
    *(int *)((char *)inner + 0x4) &= ~0x100000;
    *(int *)((char *)inner + 0x4) |= 0x8000000;
    if (*(s8 *)(*(int *)((char *)*(int *)((char *)obj + 0xb8) + 0x35c)) <= 0) {
        (*(void (*)(int, int, int))(*(int *)(*gPlayerInterface + 0x14)))(obj, inner, 3);
        *(int *)((char *)inner + 0x304) = 0;
    }
    vec = (s16 *)objModelGetVecFn_800395d8(obj, 1);
    if (vec != NULL) {
        vec[0] = 0;
        vec[1] = 0;
        vec[2] = 0;
    }
    ObjModel_ClearBlendChannels(Obj_GetActiveModel(obj));
    tex = objFindTexture(obj, 1, 0);
    *(s16 *)((char *)tex + 0x8) = 0;
    *(s16 *)((char *)tex + 0xa) = 0;
    tex = objFindTexture(obj, 0, 0);
    *(s16 *)((char *)tex + 0x8) = 0;
    *(s16 *)((char *)tex + 0xa) = 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802A9D0C(int p1, int p2, int p3, int p4, int p5, int p6, int p7, int p8)
{
    void *vec;
    s16 v;
    f32 a, b, c;
    int d, e, flag;
    s16 angle;
    int clamped;
    int inner;
    if (p8 != 0) {
        vec = (void *)objModelGetVecFn_800395d8(p1, 0);
        if (vec != NULL) {
            v = *(s16 *)((char *)vec + 0x2);
            if (v > 0) {
                *(s16 *)((char *)vec + 0x2) = v - (int)(lbl_803E8050 * timeDelta);
                if (*(s16 *)((char *)vec + 0x2) < 0) {
                    *(s16 *)((char *)vec + 0x2) = 0;
                }
            } else {
                *(s16 *)((char *)vec + 0x2) = v + (int)(lbl_803E8050 * timeDelta);
                if (*(s16 *)((char *)vec + 0x2) > 0) {
                    *(s16 *)((char *)vec + 0x2) = 0;
                }
            }
        }
        (*(void (*)(int, int, int, int, int, int))(*(int *)((char *)*(int *)*(int *)((char *)p3 + 0x68) + 0x10)))(
            p3, p4, p5, p6, p7, -1);
        *(f32 *)((char *)p1 + 0x8c) = *(f32 *)((char *)p1 + 0x18);
        *(f32 *)((char *)p1 + 0x90) = *(f32 *)((char *)p1 + 0x1c);
        *(f32 *)((char *)p1 + 0x94) = *(f32 *)((char *)p1 + 0x20);
        *(f32 *)((char *)p1 + 0x80) = *(f32 *)((char *)p1 + 0xc);
        *(f32 *)((char *)p1 + 0x84) = *(f32 *)((char *)p1 + 0x10);
        *(f32 *)((char *)p1 + 0x88) = *(f32 *)((char *)p1 + 0x14);
    }
    (*(void (*)(int, f32 *, f32 *, f32 *))(*(int *)((char *)*(int *)*(int *)((char *)p3 + 0x68) + 0x28)))(
        p3, &a, &b, &c);
    *(f32 *)((char *)p1 + 0xc) = a;
    *(f32 *)((char *)p1 + 0x10) = b;
    *(f32 *)((char *)p1 + 0x14) = c;
    inner = *(int *)((char *)p1 + 0xb8);
    if (*(s16 *)((char *)inner + 0x274) == 0x18 || (*(u16 *)((char *)p1 + 0xb0) & 0x1000) != 0) {
        *(s16 *)((char *)p1 + 0x2) = *(s16 *)((char *)p3 + 0x2);
        *(s16 *)((char *)p1 + 0x4) = *(s16 *)((char *)p3 + 0x4);
        *(s16 *)((char *)p2 + 0x478) = *(s16 *)((char *)p3 + 0x0);
    } else {
        flag = 1;
        (*(void (*)(int, int, int *))(*(int *)((char *)*(int *)*(int *)((char *)p3 + 0x68) + 0x54)))(
            p3, 2, &d);
        angle = (s16)(*(s16 *)((char *)p2 + 0x478) - (u16)d);
        if (angle > 0x8000) {
            angle = angle - 0xFFFF;
        }
        if (angle < -0x8000) {
            angle = angle + 0xFFFF;
        }
        (*(void (*)(int, int, int *))(*(int *)((char *)*(int *)*(int *)((char *)p3 + 0x68) + 0x54)))(
            p3, 3, &e);
        if (angle < (s16)-e) {
            clamped = (s16)-e;
        } else if (angle > (s16)e) {
            clamped = (s16)e;
        } else {
            clamped = angle;
        }
        *(s16 *)((char *)p2 + 0x478) = (s16)d + clamped;
        (*(void (*)(int, int, int *))(*(int *)((char *)*(int *)*(int *)((char *)p3 + 0x68) + 0x54)))(
            p3, 4, &flag);
        if (flag != 0) {
            *(s16 *)((char *)p1 + 0x2) = *(s16 *)((char *)p3 + 0x2);
            *(s16 *)((char *)p1 + 0x4) = *(s16 *)((char *)p3 + 0x4);
        }
    }
    *(s16 *)((char *)p2 + 0x484) = *(s16 *)((char *)p2 + 0x478);
    *(s16 *)((char *)p1 + 0x0) = *(s16 *)((char *)p2 + 0x478);
    *(f32 *)((char *)p1 + 0x18) = *(f32 *)((char *)p1 + 0xc);
    *(f32 *)((char *)p1 + 0x1c) = *(f32 *)((char *)p1 + 0x10);
    *(f32 *)((char *)p1 + 0x20) = *(f32 *)((char *)p1 + 0x14);
    *(f32 *)((char *)p1 + 0x24) = *(f32 *)((char *)p3 + 0x24);
    *(f32 *)((char *)p1 + 0x28) = *(f32 *)((char *)p3 + 0x28);
    *(f32 *)((char *)p1 + 0x2c) = *(f32 *)((char *)p3 + 0x2c);
    fn_802AB5A4(p1, p2, 7);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80299E44(int obj, int state, f32 fv)
{
    int inner = *(int *)((char *)obj + 0xb8);
    struct {
        u8 pad[6];
        u16 mode;
        f32 scale;
        f32 x;
        f32 y;
        f32 z;
    } pfx;

    if (lbl_803DE42C != 0) {
        Sfx_KeepAliveLoopedObjectSound(obj, 0x382);
        *(f32 *)((char *)inner + 0x854) = *(f32 *)((char *)inner + 0x854) - timeDelta;
        if (*(f32 *)((char *)inner + 0x854) <= lbl_803E7EA4) {
            int sub = *(int *)((char *)*(int *)((char *)obj + 0xb8) + 0x35c);
            int v = *(s16 *)((char *)sub + 0x4) - 1;
            if (v < 0) {
                v = 0;
            } else if (v > *(s16 *)((char *)sub + 0x6)) {
                v = *(s16 *)((char *)sub + 0x6);
            }
            *(s16 *)((char *)sub + 0x4) = v;
            *(f32 *)((char *)inner + 0x854) = lbl_803E7F58;
        }
        ObjPath_GetPointWorldPosition(lbl_803DE44C, 5, &pfx.x, &pfx.y, &pfx.z, 0);
        pfx.scale = lbl_803E7F9C;
        pfx.mode = 0;
        (**(void (**)(int, int, void *, int, int, int))((char *)(*gPartfxInterface) + 0x8))(
            (int)lbl_803DE44C, 0x7f5, &pfx, 0x200001, -1, 0);
        pfx.mode = 1;
        (**(void (**)(int, int, void *, int, int, int))((char *)(*gPartfxInterface) + 0x8))(
            (int)lbl_803DE44C, 0x7f5, &pfx, 0x200001, -1, 0);
        if ((*(u16 *)((char *)inner + 0x6e0) & lbl_803DE4B4) == 0 ||
            *(s16 *)((char *)*(int *)((char *)*(int *)((char *)obj + 0xb8) + 0x35c) + 0x4) == 0 ||
            getCurSeqNo() != 0) {
            int i;
            void **p = lbl_80332ED4;
            lbl_803DE42C = 0;
            for (i = 0; i < 7; i++) {
                if (*p != NULL) {
                    Obj_FreeObject((int)*p);
                    *p = NULL;
                }
                p++;
            }
            if (lbl_803DE454 != NULL) {
                Resource_Release(lbl_803DE454);
                lbl_803DE454 = NULL;
            }
        }
    }
    if (*(s16 *)((char *)inner + 0x80e) != -1 || (*(int *)((char *)state + 0x31c) & 0x800) != 0) {
        int r = fn_8029ABD8(obj, state, fv);
        if (r != 0) {
            return r;
        }
        *(s16 *)((char *)inner + 0x80e) = -1;
    }
    if ((*(int *)((char *)state + 0x31c) & 0x400) != 0) {
        switch (*(u8 *)((char *)state + 0x34b)) {
        case 1:
            *(u8 *)((char *)inner + 0x8a9) = 8;
            ObjAnim_SetCurrentMove(
                obj,
                lbl_803336BC[((MoveSlot *)(*(int *)((char *)inner + 0x3dc)))[*(u8 *)((char *)inner + 0x8a9)].moveIdx],
                lbl_803E7EA4, 0);
            *(int *)((char *)state + 0x308) = (int)fn_8029BC08;
            return 0x27;
        case 3:
            *(u8 *)((char *)inner + 0x8a9) = 9;
            ObjAnim_SetCurrentMove(
                obj,
                lbl_803336BC[((MoveSlot *)(*(int *)((char *)inner + 0x3dc)))[*(u8 *)((char *)inner + 0x8a9)].moveIdx],
                lbl_803E7EA4, 0);
            *(int *)((char *)state + 0x308) = (int)fn_8029BC08;
            return 0x27;
        case 4:
            *(u8 *)((char *)inner + 0x8a9) = 7;
            ObjAnim_SetCurrentMove(
                obj,
                lbl_803336BC[((MoveSlot *)(*(int *)((char *)inner + 0x3dc)))[*(u8 *)((char *)inner + 0x8a9)].moveIdx],
                lbl_803E7EA4, 0);
            *(int *)((char *)state + 0x308) = (int)fn_8029BC08;
            return 0x27;
        case 2:
            *(u8 *)((char *)inner + 0x8a9) = 6;
            ObjAnim_SetCurrentMove(
                obj,
                lbl_803336BC[((MoveSlot *)(*(int *)((char *)inner + 0x3dc)))[*(u8 *)((char *)inner + 0x8a9)].moveIdx],
                lbl_803E7EA4, 0);
            *(int *)((char *)state + 0x308) = (int)fn_8029BC08;
            return 0x27;
        default:
            *(u8 *)((char *)inner + 0x8a9) = 5;
            ObjAnim_SetCurrentMove(
                obj,
                lbl_803336BC[((MoveSlot *)(*(int *)((char *)inner + 0x3dc)))[*(u8 *)((char *)inner + 0x8a9)].moveIdx],
                lbl_803E7EA4, 0);
            *(int *)((char *)state + 0x308) = (int)fn_8029BC08;
            return 0x27;
        }
    }
    if ((*(int *)((char *)state + 0x31c) & 0x100) != 0) {
        if (*(u8 *)((char *)state + 0x34b) == 2 && *(f32 *)((char *)state + 0x298) > lbl_803E7EAC) {
            *(u8 *)((char *)inner + 0x8a9) = 1;
            ObjAnim_SetCurrentMove(
                obj,
                lbl_803336BC[((MoveSlot *)(*(int *)((char *)inner + 0x3dc)))[*(u8 *)((char *)inner + 0x8a9)].moveIdx],
                lbl_803E7EA4, 0);
            *(int *)((char *)state + 0x308) = (int)fn_8029BC08;
            return 0x27;
        }
        if (*(u8 *)((char *)state + 0x34b) == 3 && *(f32 *)((char *)state + 0x298) > lbl_803E7EAC) {
            *(u8 *)((char *)inner + 0x8a9) = 4;
            ObjAnim_SetCurrentMove(
                obj,
                lbl_803336BC[((MoveSlot *)(*(int *)((char *)inner + 0x3dc)))[*(u8 *)((char *)inner + 0x8a9)].moveIdx],
                lbl_803E7EA4, 0);
            *(int *)((char *)state + 0x308) = (int)fn_8029BC08;
            return 0x27;
        }
        if (*(u8 *)((char *)state + 0x34b) == 1 && *(f32 *)((char *)state + 0x298) > lbl_803E7EAC) {
            *(u8 *)((char *)inner + 0x8a9) = 3;
            ObjAnim_SetCurrentMove(
                obj,
                lbl_803336BC[((MoveSlot *)(*(int *)((char *)inner + 0x3dc)))[*(u8 *)((char *)inner + 0x8a9)].moveIdx],
                lbl_803E7EA4, 0);
            *(int *)((char *)state + 0x308) = (int)fn_8029BC08;
            return 0x27;
        }
        if (*(u8 *)((char *)state + 0x34b) == 4 && *(f32 *)((char *)state + 0x298) > lbl_803E7EAC) {
            *(u8 *)((char *)inner + 0x8a9) = 2;
            ObjAnim_SetCurrentMove(
                obj,
                lbl_803336BC[((MoveSlot *)(*(int *)((char *)inner + 0x3dc)))[*(u8 *)((char *)inner + 0x8a9)].moveIdx],
                lbl_803E7EA4, 0);
            *(int *)((char *)state + 0x308) = (int)fn_8029BC08;
            return 0x27;
        }
        *(u8 *)((char *)inner + 0x8a9) = 0;
        ObjAnim_SetCurrentMove(
            obj,
            lbl_803336BC[((MoveSlot *)(*(int *)((char *)inner + 0x3dc)))[*(u8 *)((char *)inner + 0x8a9)].moveIdx],
            lbl_803E7EA4, 0);
        *(int *)((char *)state + 0x308) = (int)fn_8029BC08;
        return 0x27;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80299BB0(int obj, int p2)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int state30 = 0x1a;
    int state29 = 0x1a;
    void *near;
    f32 dist;
    f32 dir[3];
    f32 cosv;
    f32 sinv;
    f32 fz;
    dist = lbl_803E7F5C;
    near = (void *)ObjGroup_FindNearestObject(0x3e, obj, &dist);
    ((ByteFlags *)((char *)inner + 0x3f4))->b20 = 1;
    fz = lbl_803E7EA4;
    *(f32 *)((char *)inner + 0x414) = fz;
    if (near != 0) {
        dir[0] = *(f32 *)((char *)near + 0xc) - *(f32 *)((char *)obj + 0xc);
        dir[1] = *(f32 *)((char *)near + 0x10) - *(f32 *)((char *)obj + 0x10);
        dir[2] = *(f32 *)((char *)near + 0x14) - *(f32 *)((char *)obj + 0x14);
        dir[1] = fz;
        Vec3_Normalize(dir);
        cosv = fn_80293E80(lbl_803E7F94 * (f32)*(s16 *)((char *)inner + 0x478) / lbl_803E7F98);
        sinv = sin(lbl_803E7F94 * (f32)*(s16 *)((char *)inner + 0x478) / lbl_803E7F98);
        switch (*(u8 *)(*(int *)((char *)near + 0x50) + 0x75)) {
        case 3:
            if (dir[2] * cosv - dir[0] * sinv > lbl_803E7EA4) {
                state29 = 0x1a;
            }
            state30 = state29;
            break;
        case 2:
            state29 = 0x1a;
            break;
        case 1:
            state30 ^= state29;
            state29 ^= state30;
            state30 ^= state29;
            break;
        default:
            *(u8 *)((char *)inner + 0x8aa) = (u8)(*(u8 *)((char *)inner + 0x8aa) ^ 1);
            if (*(u8 *)((char *)inner + 0x8aa) != 0) {
                state29 = 0x1a;
            }
            break;
        }
    } else {
        *(u8 *)((char *)inner + 0x8aa) = (u8)(*(u8 *)((char *)inner + 0x8aa) ^ 1);
        if (*(u8 *)((char *)inner + 0x8aa) != 0) {
            state29 = 0x1a;
        }
    }
    if (*(u8 *)((char *)p2 + 0x34b) == 2 && *(f32 *)((char *)p2 + 0x298) > lbl_803E7EAC) {
        ObjAnim_SetCurrentMove(
            obj, lbl_803336BC[((MoveSlot *)(*(int *)((char *)inner + 0x3dc)))[(u8)state30].moveIdx],
            lbl_803E7EA4, 0);
        *(u8 *)((char *)inner + 0x8a9) = state30;
        *(int *)((char *)p2 + 0x308) = (int)fn_8029BC08;
        return 0x27;
    }
    ObjAnim_SetCurrentMove(
        obj, lbl_803336BC[((MoveSlot *)(*(int *)((char *)inner + 0x3dc)))[(u8)state29].moveIdx],
        lbl_803E7EA4, 0);
    *(u8 *)((char *)inner + 0x8a9) = state29;
    *(int *)((char *)p2 + 0x308) = (int)fn_8029BC08;
    return 0x27;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
int fn_802A9B1C(int obj, int p2, int p3)
{
    int inner = *(int *)((char *)obj + 0xb8);
    u8 c = *(u8 *)((char *)inner + 0x8c8);
    int deref;
    int v;
    if (c == 0x48 || c == 0x47 || c == 0x44 ||
        *(void **)((char *)inner + 0x7f8) != NULL ||
        ((ByteFlags *)((char *)inner + 0x3f0))->b20 ||
        ((ByteFlags *)((char *)inner + 0x3f0))->b04 ||
        ((ByteFlags *)((char *)inner + 0x3f0))->b08 ||
        ((ByteFlags *)((char *)inner + 0x3f4))->b40 == 0) {
        return 0;
    }
    deref = *(int *)((char *)inner + 0x35c);
    if (p3 == 0x2d) {
        if (*(s16 *)((char *)deref + 4) < 2) return 0;
    } else {
        if (*(s16 *)((char *)deref + 4) < 1) return 0;
    }
    v = *(s16 *)((char *)p2 + 0x274);
    if (v == 1 || v == 2 || v == 0x2a || v == 0x2c || (u16)(v - 0x2e) <= 1 || v == 0x2d) {
        return 1;
    }
    return 0;
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_8029FFD0(int obj, int p2)
{
    int inner = *(int *)((char *)obj + 0xb8);
    s16 v = *(s16 *)((char *)p2 + 0x274);
    if (v != 0x15 && v != 0x14 && v != 0x12 && v != 0x13 && v != 0xe && v != 0xf && v != 0x10) {
        u8 c = *(u8 *)((char *)inner + 0x8c8);
        if (c != 0x48 && c != 0x47 && c != 0x42 && getCurSeqNo() == 0) {
            (*(void (*)(int, int, int, int, int, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
                0x42, 0, 1, 0, 0, 0, 0xff);
            *(u8 *)((char *)inner + 0x8c8) = 0x42;
        }
        *(int *)((char *)inner + 0x360) |= 0x800000;
        ObjHits_SyncObjectPositionIfDirty(obj);
    }
    *(s16 *)((char *)obj + 0xa2) = -1;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802A00E0(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);
    f32 fz;
    f32 obj98;
    f32 t1, t2, t3;
    f32 outY;
    fn_802A13F4(obj, state);
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        u8 ic;
        int model;
        f32 buf2[2];
        f32 buf1[3];
        ObjHits_MarkObjectPositionDirty(obj);
        ic = *(u8 *)((char *)inner + 0x8c8);
        if (ic != 0x48 && ic != 0x47) {
            (*(void (*)(int, int, int, int, int, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
                0x42, 0, 1, 0, 0, 0x3c, 0xff);
        }
        ObjAnim_SetCurrentMove(obj, lbl_80332F48[0x13], lbl_803E7EA4, 1);
        Object_ObjAnimSetSecondaryBlendMove((ObjAnimComponent *)obj, lbl_80332F48[0x14], 0);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7F34;
        model = *(int *)((char *)*(int *)((char *)obj + 0x7c) +
                         ((s32)(*(s8 *)((char *)obj + 0xad)) << 2));
        ObjModel_SampleJointTransform(model, 0, 0, lbl_803E7EE0,
                                      *(f32 *)((char *)obj + 0x8), buf1, buf2);
        *(f32 *)((char *)inner + 0x564) = *(f32 *)((char *)inner + 0x56c) * buf1[2];
        *(f32 *)((char *)inner + 0x568) = *(f32 *)((char *)inner + 0x574) * buf1[2];
        *(f32 *)((char *)obj + 0x10) = *(f32 *)((char *)inner + 0x550);
        *(s16 *)((char *)state + 0x278) = 0x15;
        *(int *)((char *)inner + 0x898) = (int)fn_8029FFD0;
    }
    *(int *)((char *)*(int *)((char *)obj + 0xb8) + 0x360) &= ~2;
    *(int *)((char *)*(int *)((char *)obj + 0xb8) + 0x360) |= 0x2000;
    *(int *)((char *)state + 4) |= 0x100000;
    fz = lbl_803E7EA4;
    *(f32 *)((char *)state + 0x280) = fz;
    *(f32 *)((char *)state + 0x284) = fz;
    *(int *)((char *)state + 0) |= 0x200000;
    *(f32 *)((char *)obj + 0x24) = fz;
    *(f32 *)((char *)obj + 0x2c) = fz;
    *(int *)((char *)state + 4) |= 0x8000000;
    *(f32 *)((char *)obj + 0x28) = fz;
    ObjAnim_WriteStateWord((ObjAnimComponent *)obj, OBJANIM_STATE_INDEX_CURRENT,
                           OBJANIM_STATE_WORD_EVENT_STATE, *(s16 *)((char *)inner + 0x5a4));
    if ((*(int *)((char *)state + 0x314) & 0x400) != 0) {
        doRumble(lbl_803E7F10);
    }
    obj98 = *(f32 *)((char *)obj + 0x98);
    if (obj98 > lbl_803E7F68) {
        *(f32 *)((char *)obj + 0x18) = *(f32 *)((char *)inner + 0x768);
        *(f32 *)((char *)obj + 0x20) = *(f32 *)((char *)inner + 0x770);
        if (*(int *)((char *)obj + 0x30) != 0) {
            *(f32 *)((char *)obj + 0x18) = *(f32 *)((char *)obj + 0x18) + playerMapOffsetX;
            *(f32 *)((char *)obj + 0x20) = *(f32 *)((char *)obj + 0x20) + playerMapOffsetZ;
        }
        Obj_TransformWorldPointToLocal(
            (f32 *)((char *)obj + 0xc), &outY, (f32 *)((char *)obj + 0x14),
            *(int *)((char *)obj + 0x30),
            *(f32 *)((char *)obj + 0x18), lbl_803E7EA4, *(f32 *)((char *)obj + 0x20));
        fn_802AB5A4(obj, inner, 5);
        ObjAnim_SetCurrentMove(obj,
                               *(s16 *)*(int *)((char *)inner + 0x3f8),
                               lbl_803E7EA4, 1);
        *(int *)((char *)inner + 0x360) |= 0x800000;
        *(int *)((char *)state + 0x308) = (int)fn_802A514C;
        return -1;
    }
    t1 = *(f32 *)((char *)inner + 0x564) * obj98 + *(f32 *)((char *)obj + 0xc);
    t2 = *(f32 *)((char *)obj + 0x10) -
         *(f32 *)((char *)inner + 0x560) * (lbl_803E7EE0 - obj98);
    t3 = *(f32 *)((char *)inner + 0x568) * obj98 + *(f32 *)((char *)obj + 0x14);
    (*(void (*)(f32, f32, f32))(*(int *)(*gCameraInterface + 0x2c)))(t1, t2, t3);
    fn_802AB5A4(obj, inner, 5);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802A03BC(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);
    f32 fz;
    f32 obj98;
    f32 t1, t2, t3;
    f32 outY;
    fn_802A13F4(obj, state);
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        u8 ic;
        int model;
        f32 buf2[2];
        f32 buf1[3];
        ObjHits_MarkObjectPositionDirty(obj);
        ic = *(u8 *)((char *)inner + 0x8c8);
        if (ic != 0x48 && ic != 0x47) {
            (*(void (*)(int, int, int, int, int, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
                0x42, 0, 1, 0, 0, 0x3c, 0xff);
        }
        ObjAnim_SetCurrentMove(obj, lbl_80332F48[0x11], lbl_803E7EA4, 1);
        Object_ObjAnimSetSecondaryBlendMove((ObjAnimComponent *)obj, lbl_80332F48[0x12], 0);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7F84;
        model = *(int *)((char *)*(int *)((char *)obj + 0x7c) +
                         ((s32)(*(s8 *)((char *)obj + 0xad)) << 2));
        ObjModel_SampleJointTransform(model, 0, 0, lbl_803E7EE0,
                                      *(f32 *)((char *)obj + 0x8), buf1, buf2);
        *(f32 *)((char *)inner + 0x564) = *(f32 *)((char *)inner + 0x56c) * buf1[2];
        *(f32 *)((char *)inner + 0x568) = *(f32 *)((char *)inner + 0x574) * buf1[2];
        *(f32 *)((char *)obj + 0x10) = *(f32 *)((char *)inner + 0x54c);
        *(s16 *)((char *)state + 0x278) = 0x14;
        *(int *)((char *)inner + 0x898) = (int)fn_8029FFD0;
    }
    *(int *)((char *)*(int *)((char *)obj + 0xb8) + 0x360) &= ~2;
    *(int *)((char *)*(int *)((char *)obj + 0xb8) + 0x360) |= 0x2000;
    *(int *)((char *)state + 4) |= 0x100000;
    fz = lbl_803E7EA4;
    *(f32 *)((char *)state + 0x280) = fz;
    *(f32 *)((char *)state + 0x284) = fz;
    *(int *)((char *)state + 0) |= 0x200000;
    *(f32 *)((char *)obj + 0x24) = fz;
    *(f32 *)((char *)obj + 0x2c) = fz;
    *(int *)((char *)state + 4) |= 0x8000000;
    *(f32 *)((char *)obj + 0x28) = fz;
    ObjAnim_WriteStateWord((ObjAnimComponent *)obj, OBJANIM_STATE_INDEX_CURRENT,
                           OBJANIM_STATE_WORD_EVENT_STATE, *(s16 *)((char *)inner + 0x5a4));
    obj98 = *(f32 *)((char *)obj + 0x98);
    if (obj98 > lbl_803E7F68) {
        *(f32 *)((char *)obj + 0x18) = *(f32 *)((char *)inner + 0x768);
        *(f32 *)((char *)obj + 0x20) = *(f32 *)((char *)inner + 0x770);
        if (*(int *)((char *)obj + 0x30) != 0) {
            *(f32 *)((char *)obj + 0x18) = *(f32 *)((char *)obj + 0x18) + playerMapOffsetX;
            *(f32 *)((char *)obj + 0x20) = *(f32 *)((char *)obj + 0x20) + playerMapOffsetZ;
        }
        Obj_TransformWorldPointToLocal(
            (f32 *)((char *)obj + 0xc), &outY, (f32 *)((char *)obj + 0x14),
            *(int *)((char *)obj + 0x30),
            *(f32 *)((char *)obj + 0x18), lbl_803E7EA4, *(f32 *)((char *)obj + 0x20));
        fn_802AB5A4(obj, inner, 5);
        ObjAnim_SetCurrentMove(obj,
                               *(s16 *)*(int *)((char *)inner + 0x3f8),
                               lbl_803E7EA4, 1);
        *(int *)((char *)inner + 0x360) |= 0x800000;
        *(int *)((char *)state + 0x308) = (int)fn_802A514C;
        return -1;
    }
    t1 = *(f32 *)((char *)inner + 0x564) * obj98 + *(f32 *)((char *)obj + 0xc);
    t2 = *(f32 *)((char *)obj + 0x10) -
         *(f32 *)((char *)inner + 0x560) * (lbl_803E7EE0 - obj98);
    t3 = *(f32 *)((char *)inner + 0x568) * obj98 + *(f32 *)((char *)obj + 0x14);
    (*(void (*)(f32, f32, f32))(*(int *)(*gCameraInterface + 0x2c)))(t1, t2, t3);
    fn_802AB5A4(obj, inner, 5);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int objAnimFn_80296328(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int v;
    if ((*(u16 *)((char *)obj + 0xb0) & 0x1000) != 0 &&
        ((ByteFlags *)((char *)inner + 0x3f2))->b80 == 0) {
        return 0;
    }
    if (((ByteFlags *)((char *)inner + 0x3f0))->b04 ||
        ((ByteFlags *)((char *)inner + 0x3f0))->b08 ||
        ((ByteFlags *)((char *)inner + 0x3f0))->b20 ||
        *(void **)((char *)inner + 0x7f8) != NULL ||
        ((ByteFlags *)((char *)inner + 0x3f0))->b02) {
        return 0;
    }
    v = *(s16 *)((char *)inner + 0x274);
    if (v == 1 || v == 2 || v == 0x26) {
        return 1;
    }
    if (v == 0x18) {
        if (GameBit_Get(0x3e3)) {
            return 1;
        }
        if (*(s16 *)((char *)*(int *)((char *)inner + 0x7f0) + 0x46) == 0x416) {
            return 1;
        }
    }
    if (*(void **)((char *)inner + 0x2d0) != NULL) {
        return 1;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802AD204(int p1, int obj)
{
    char *t = (char *)lbl_80332EC0;
    *(int *)((char *)obj + 0x3fc) = *(int *)((char *)obj + 0x3f8);
    if (((ByteFlags *)((char *)obj + 0x3f0))->b20) {
        if (((ByteFlags *)((char *)obj + 0x3f1))->b20) {
            *(int *)((char *)obj + 0x3f8) = (int)(t + 0x310);
            *(int *)((char *)obj + 0x400) = (int)(t + 0xd8);
        } else {
            *(int *)((char *)obj + 0x3f8) = (int)(t + 0x210);
            *(int *)((char *)obj + 0x400) = (int)(t + 0xd8);
        }
    } else if (*(void **)((char *)obj + 0x7f8) != NULL) {
        *(int *)((char *)obj + 0x3f8) = (int)(t + 0x250);
        *(int *)((char *)obj + 0x400) = (int)(t + 0x390);
    } else if (((ByteFlags *)((char *)obj + 0x3f1))->b20) {
        if (*(u8 *)((char *)obj + 0x8b3) != 0) {
            *(int *)((char *)obj + 0x3f8) = (int)(t + 0x290);
            *(int *)((char *)obj + 0x400) = (int)(t + 0x390);
        } else {
            *(int *)((char *)obj + 0x3f8) = (int)(t + 0x2d0);
            *(int *)((char *)obj + 0x400) = (int)(t + 0x390);
        }
    } else if (*(u8 *)((char *)obj + 0x8b3) != 0) {
        *(int *)((char *)obj + 0x3f8) = (int)(t + 0x1d0);
        *(int *)((char *)obj + 0x400) = (int)(t + 0x390);
    } else {
        *(int *)((char *)obj + 0x3f8) = (int)(t + 0x190);
        *(int *)((char *)obj + 0x400) = (int)(t + 0x390);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void fn_802AB5A4(int obj, int p2, int flags)
{
    u8 f = (u8)flags;
    char *q = (char *)p2 + 4;
    if (f & 1) {
        curves_updateLocalPointTransforms(obj, (u32 *)q);
    }
    if (f & 2) {
        curves_preparePointCollisionFrame(obj, (u32 *)q);
        *(f32 *)(q + 0x20) = *(f32 *)((char *)obj + 0x18);
        *(f32 *)(q + 0x24) = lbl_803E80EC + *(f32 *)((char *)obj + 0x1c);
        *(f32 *)(q + 0x28) = *(f32 *)((char *)obj + 0x20);
    }
    if (f & 4) {
        *(f32 *)((char *)*(int *)((char *)obj + 0x54) + 0x10) = *(f32 *)((char *)obj + 0xc);
        *(f32 *)((char *)*(int *)((char *)obj + 0x54) + 0x14) = *(f32 *)((char *)obj + 0x10);
        *(f32 *)((char *)*(int *)((char *)obj + 0x54) + 0x18) = *(f32 *)((char *)obj + 0x14);
        *(f32 *)((char *)*(int *)((char *)obj + 0x54) + 0x1c) = *(f32 *)((char *)obj + 0x18);
        *(f32 *)((char *)*(int *)((char *)obj + 0x54) + 0x20) = *(f32 *)((char *)obj + 0x1c);
        *(f32 *)((char *)*(int *)((char *)obj + 0x54) + 0x24) = *(f32 *)((char *)obj + 0x20);
    }
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802A5048(int obj, int state, f32 fv)
{
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        ObjAnim_SetCurrentMove(obj, 0x8e, lbl_803E7EA4, 0);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E8060;
    }
    (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x20)))(obj, state, fv, 3);
    if (*(s8 *)((char *)state + 0x346) != 0) {
        int i;
        void **p;
        lbl_803DE42C = 0;
        p = lbl_80332ED4;
        for (i = 0; i < 7; i++) {
            if (*p != NULL) {
                Obj_FreeObject((int)*p);
                *p = NULL;
            }
            p++;
        }
        if (lbl_803DE454 != NULL) {
            Resource_Release(lbl_803DE454);
            lbl_803DE454 = NULL;
        }
        showDeathMenu();
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_8029D7F0(int obj, int state, f32 fv)
{
    *(u8 *)((char *)state + 0x34d) = 3;
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        ObjAnim_SetCurrentMove(obj, 0x44c, lbl_803E7EA4, 0);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7FD4;
    }
    switch (*(s16 *)((char *)obj + 0xa0)) {
    case 0x44c:
        if (*(s8 *)((char *)state + 0x346) != 0) {
            ObjAnim_SetCurrentMove(obj, 0x44d, lbl_803E7EA4, 0);
            *(f32 *)((char *)state + 0x2a0) = lbl_803E7FCC;
        }
        break;
    case 0x44d:
        if (*(s8 *)((char *)state + 0x346) != 0) {
            *(int *)((char *)state + 0x308) = (int)fn_802A514C;
            return 2;
        }
        break;
    }
    (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x20)))(obj, state, fv, 1);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
int fn_802A9A0C(int obj, int p2)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int threshold;
    if (GameBit_Get(0xc55)) {
        threshold = 0x14;
    } else {
        threshold = 0xa;
    }
    if (GameBit_Get(0x107) &&
        *(s16 *)((char *)*(int *)((char *)*(int *)((char *)obj + 0xb8) + 0x35c) + 4) >= threshold &&
        *(u8 *)((char *)inner + 0x8c8) != 0x44 &&
        *(void **)((char *)inner + 0x7f8) == NULL &&
        !((ByteFlags *)((char *)inner + 0x3f0))->b20 &&
        !((ByteFlags *)((char *)inner + 0x3f0))->b04 &&
        !((ByteFlags *)((char *)inner + 0x3f0))->b08 &&
        ((ByteFlags *)((char *)inner + 0x3f4))->b40) {
        s16 v = *(s16 *)((char *)p2 + 0x274);
        if (v == 1 || v == 2 || v == 0x25 || v == 0x24) {
            return 1;
        }
    }
    return 0;
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
int fn_802A9C0C(int obj, int p2, int p3)
{
    int inner = *(int *)((char *)obj + 0xb8);
    u8 c = *(u8 *)((char *)inner + 0x8c8);
    int deref;
    int v;
    if (c == 0x48 || c == 0x47 || c == 0x44 ||
        *(void **)((char *)inner + 0x7f8) != NULL ||
        ((ByteFlags *)((char *)inner + 0x3f0))->b20 ||
        ((ByteFlags *)((char *)inner + 0x3f0))->b04 ||
        ((ByteFlags *)((char *)inner + 0x3f0))->b08 ||
        ((ByteFlags *)((char *)inner + 0x3f4))->b40 == 0) {
        return 0;
    }
    deref = *(int *)((char *)inner + 0x35c);
    if (p3 == 0x2d) {
        if (*(s16 *)((char *)deref + 4) < 2) return 0;
    } else {
        if (*(s16 *)((char *)deref + 4) < 1) return 0;
    }
    v = *(s16 *)((char *)p2 + 0x274);
    if (v == 1 || v == 2 || (u16)(v - 0x24) <= 1 || (u16)(v - 0x2a) <= 2 ||
        (u16)(v - 0x2e) <= 1 || v == 0x2d) {
        return 1;
    }
    return 0;
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_8029C8C8(int obj, int p2)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if (*(f32 *)((char *)p2 + 0x298) < lbl_803E7F6C) {
        s16 h = *(s16 *)((char *)obj + 0);
        *(s16 *)((char *)inner + 0x484) = h;
        *(s16 *)((char *)inner + 0x478) = h;
        *(int *)((char *)inner + 0x494) = h;
        *(f32 *)((char *)p2 + 0x298) = lbl_803E7EA4;
    } else {
        int t = *(int *)((char *)inner + 0x474);
        *(int *)((char *)inner + 0x494) = t;
        *(s16 *)((char *)inner + 0x484) = (s16)t;
        *(int *)((char *)inner + 0x48c) = 0;
        *(int *)((char *)inner + 0x488) = 0;
    }
    lbl_803DC66C = 1;
    if (*(s16 *)((char *)p2 + 0x274) != 0x24 && *(s16 *)((char *)p2 + 0x274) != 0x25 &&
        lbl_803DE42C != 0) {
        int i;
        void **p;
        *(s16 *)((char *)inner + 0x80a) = -1;
        lbl_803DE42C = 0;
        p = lbl_80332ED4;
        for (i = 0; i < 7; i++) {
            if (*p != NULL) {
                Obj_FreeObject((int)*p);
                *p = NULL;
            }
            p++;
        }
        if (lbl_803DE454 != NULL) {
            Resource_Release(lbl_803DE454);
            lbl_803DE454 = NULL;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802B1B28(int obj, f32 fv)
{
    f32 x, y, z;
    f32 v;

    v = *(f32 *)((char *)obj + 0x24);
    if (v < lbl_803E801C) {
        v = lbl_803E801C;
    } else if (v > lbl_803E7F10) {
        v = lbl_803E7F10;
    }
    *(f32 *)((char *)obj + 0x24) = v;

    v = *(f32 *)((char *)obj + 0x28);
    if (v < lbl_803E811C) {
        v = lbl_803E811C;
    } else if (v > lbl_803E80E4) {
        v = lbl_803E80E4;
    }
    *(f32 *)((char *)obj + 0x28) = v;

    v = *(f32 *)((char *)obj + 0x2c);
    if (v < lbl_803E801C) {
        v = lbl_803E801C;
    } else if (v > lbl_803E7F10) {
        v = lbl_803E7F10;
    }
    *(f32 *)((char *)obj + 0x2c) = v;

    y = *(f32 *)((char *)obj + 0x28) * fv;
    if (y > lbl_803E7ED8) {
        y = lbl_803E7ED8;
    }
    x = *(f32 *)((char *)obj + 0x24) * fv;
    z = *(f32 *)((char *)obj + 0x2c) * fv;
    objMove(obj, x, y, z);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Lightfoot_UpdateAttachedChild(int obj, int inner)
{
    int animState = *(int *)((char *)inner + 0x40c);
    int child;
    int setup;

    if (*(s16 *)((char *)animState + 0x26) == *(s16 *)((char *)animState + 0x28)) return;
    if (*(u8 *)((char *)obj + 0x36) == 0) return;

    child = *(int *)((char *)obj + 0xc8);
    if (child != 0) {
        ObjLink_DetachChild(obj, child);
        Obj_FreeObject(child);
    }
    if (Obj_IsLoadingLocked()) {
        if (*(s16 *)((char *)animState + 0x28) > 0) {
            setup = Obj_AllocObjectSetup(0x20);
            setup = Obj_SetupObject(setup, 4, *(s8 *)((char *)obj + 0xac), -1,
                                    *(int *)((char *)obj + 0x30));
            ObjLink_AttachChild(obj, setup, 0);
            *(s16 *)((char *)animState + 0x26) = *(s16 *)((char *)animState + 0x28);
        }
    } else {
        *(s16 *)((char *)animState + 0x26) = 0;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int Lightfoot_UpdateWanderSteering(int obj, int state, f32 fv)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int sub = *(int *)((char *)inner + 0x40c);
    if (*(f32 *)((char *)sub + 0x14) <= lbl_803E8180) {
        Sfx_PlayFromObject(obj, 0x4be);
        *(f32 *)((char *)sub + 0x14) = (f32)randomGetRange(0x78, 0xb4);
    }
    *(f32 *)((char *)state + 0x2a0) =
        lbl_803E8184 * (lbl_803E8188 -
                        (f32)(u16)*(u16 *)((char *)sub + 0x22) /
                            (f32)(u16)*(u16 *)((char *)inner + 0x3fe));
    if (*(f32 *)((char *)state + 0x2a0) < lbl_803E818C) {
        *(f32 *)((char *)state + 0x2a0) = lbl_803E818C;
    }
    if (*(s8 *)((char *)state + 0x27a) != 0 || *(s8 *)((char *)state + 0x346) != 0) {
        u8 r;
        if (*(u8 *)((char *)sub + 0x2c) != 0) {
            *(u8 *)((char *)sub + 0x2c) = *(u8 *)((char *)sub + 0x2c) - 1;
        } else {
            r = (*(u8 (*)(int, int, f32))(*(int *)(*gBaddieControlInterface + 0x18)))(
                obj, state, lbl_803E8190);
            if ((r & 1) == 0) {
                if (r & 4) {
                    *(s16 *)((char *)obj + 0) = *(s16 *)((char *)obj + 0) + 0x7ff8;
                    *(u8 *)((char *)sub + 0x2c) = 3;
                } else if (r & 2) {
                    *(s16 *)((char *)obj + 0) = *(s16 *)((char *)obj + 0) - 0x3ffc;
                    *(u8 *)((char *)sub + 0x2c) = 3;
                } else if (r & 8) {
                    *(s16 *)((char *)obj + 0) = *(s16 *)((char *)obj + 0) + 0x3ffc;
                    *(u8 *)((char *)sub + 0x2c) = 3;
                }
            }
        }
        ObjAnim_SetCurrentMove(obj, 0x14, lbl_803E8180, 0);
    }
    if (*(u8 *)((char *)sub + 0x2c) == 0) {
        *(s16 *)((char *)obj + 0) = *(s16 *)((char *)obj + 0) +
            (int)((f32)(s32)((u16)*(u16 *)((char *)sub + 0x20) - 0x7fff) *
                  timeDelta * lbl_803E8194);
    }
    (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x20)))(obj, state, fv, 1);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Lightfoot_RecordCompletedChallengeTargetHit(int obj, int inner, int animState)
{
    int idx;

    if (*(u8 *)((char *)animState + 0x2e) == 0) return;
    if ((*(u16 *)((char *)inner + 0x400) & 2) == 0) return;

    idx = *(int *)((char *)obj + 0x4c);
    if (*(u32 *)((char *)idx + 0x14) == 0x46A51 && GameBit_Get(0xc49) == 0) {
        GameBit_Set(0xc49, 1);
    } else if (*(u32 *)((char *)idx + 0x14) == 0x46A55 && GameBit_Get(0xc4a) == 0) {
        GameBit_Set(0xc4a, 1);
    } else if (*(u32 *)((char *)idx + 0x14) == 0x49928 && GameBit_Get(0xc4b) == 0) {
        GameBit_Set(0xc4b, 1);
    }
    *(u8 *)((char *)animState + 0x2e) = 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802A96D8(void)
{
    void **p;
    s8 i;
    int idx3;
    int obj;

    if (!Obj_IsLoadingLocked()) return;
    p = lbl_80332ED4;
    idx3 = 0;
    for (i = 0; i < 7; i++) {
        if (*p == NULL) {
            obj = Obj_AllocObjectSetup(0x24, 0x4ec);
            ObjPath_GetPointWorldPosition(lbl_803DE44C, 0, (char *)obj + 8,
                                          (char *)obj + 0xc, (char *)obj + 0x10, 0);
            *(u8 *)((char *)obj + 4) = 2;
            *(u8 *)((char *)obj + 5) = 1;
            *(u8 *)((char *)obj + 6) = 0xff;
            *(u8 *)((char *)obj + 7) = 0xff;
            *(s16 *)((char *)obj + 0x1a) = (s16)idx3;
            *(s16 *)((char *)obj + 0x1c) = 0;
            *p = (void *)Obj_SetupObject(obj, 5, -1, -1, 0);
        }
        p++;
        idx3 += 3;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802B4DE0(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int off;
    int i;

    if ((u32)lbl_803DE448 != 0) {
        Obj_FreeObject(lbl_803DE448);
        ObjLink_DetachChild(obj, lbl_803DE448);
        lbl_803DE448 = 0;
    }
    if ((int)lbl_803DE44C != 0) {
        Obj_FreeObject((int)lbl_803DE44C);
        ObjLink_DetachChild(obj, lbl_803DE44C);
        lbl_803DE44C = NULL;
    }
    if (lbl_803DE450 != 0) {
        lbl_803DE450 = 0;
    }
    off = 0;
    for (i = 0; i < *(u8 *)((char *)inner + 0x8a8); i++) {
        int e = *(int *)(*(int *)((char *)inner + 0x3dc) + off + 0x64);
        if (e != 0) mm_free((void *)e);
        off += 0xb0;
    }
    ObjGroup_RemoveObject(obj, 0);
    ObjGroup_RemoveObject(obj, 0x25);
    fn_80026C88(lbl_803DE420);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802A13F4(int obj, int p2)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int cell;
    int t;
    int sfx;

    if (*(int *)((char *)p2 + 0x314) & 1) {
        cell = coordsToMapCell(*(f32 *)((char *)obj + 0xc), *(f32 *)((char *)obj + 0x14));
        if (cell == 0x12) {
            Sfx_PlayFromObject(obj, SFXthorntail_snort1);
        } else {
            Sfx_PlayFromObject(obj, SFXdn_rexhurt13);
        }
    }
    if (lbl_803DE47C > 0) {
        t = lbl_803DE47C - framesThisStep;
        lbl_803DE47C = t;
        if (t < 0) lbl_803DE47C = 0;
    }
    if (*(int *)((char *)p2 + 0x314) & 0x80) {
        if (lbl_803DE47C == 0) {
            if (randomGetRange(1, 0x64) < 0x46) {
                if (*(s16 *)((char *)inner + 0x81a) == 0) {
                    sfx = 0x398;
                } else {
                    sfx = 0x25;
                }
                Sfx_PlayFromObject(obj, (u16)sfx);
                lbl_803DE47C = 0x3c;
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
int fn_802A98FC(int obj, int p2)
{
    int inner = *(int *)((char *)obj + 0xb8);
    s16 sel = *(s16 *)((char *)p2 + 0x274);

    if (sel == 1 || sel == 2) {
        void *slot = *(void **)((char *)inner + 0x4b8);
        u8 af;
        u8 c;
        if (slot == NULL || *(s16 *)((char *)slot + 0x46) != 0x414 ||
            ((af = *(u8 *)((char *)slot + 0xaf)) & 4) == 0 || (af & 0x18) != 0) {
            return 0;
        }
        c = *(u8 *)((char *)inner + 0x8c8);
        if (*(void **)((char *)p2 + 0x2d0) != NULL ||
            c == 0x48 || c == 0x47 || c == 0x44 ||
            *(void **)((char *)inner + 0x7f8) != NULL ||
            ((ByteFlags *)((char *)inner + 0x3f0))->b20 ||
            ((ByteFlags *)((char *)inner + 0x3f0))->b04 ||
            ((ByteFlags *)((char *)inner + 0x3f0))->b08 ||
            ((ByteFlags *)((char *)inner + 0x3f4))->b40 == 0 ||
            *(s16 *)((char *)*(int *)((char *)inner + 0x35c) + 4) < 0x14 ||
            !GameBit_Get(0x5bd)) {
            return 0;
        }
        return 1;
    }
    return 0;
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Lightfoot_ResetScriptedPosition(int obj)
{
    switch (*(int *)((char *)*(int *)((char *)obj + 0x4c) + 0x14)) {
    case 0x34316:
        *(f32 *)((char *)obj + 0x18) = lbl_803E81DC;
        *(f32 *)((char *)obj + 0x1c) = lbl_803E81E0;
        *(f32 *)((char *)obj + 0x20) = lbl_803E81E4;
        *(s16 *)((char *)obj + 0) = 0x2565;
        break;
    case 0x33E3C:
        *(f32 *)((char *)obj + 0x18) = lbl_803E81E8;
        *(f32 *)((char *)obj + 0x1c) = lbl_803E81EC;
        *(f32 *)((char *)obj + 0x20) = lbl_803E81F0;
        *(s16 *)((char *)obj + 0) = 0x1c42;
        break;
    case 0x33E34:
        *(f32 *)((char *)obj + 0x18) = lbl_803E81F4;
        *(f32 *)((char *)obj + 0x1c) = lbl_803E81EC;
        *(f32 *)((char *)obj + 0x20) = lbl_803E81F8;
        *(s16 *)((char *)obj + 0) = 0x1d00;
        break;
    case 0x45C47:
        *(f32 *)((char *)obj + 0x18) = lbl_803E81FC;
        *(f32 *)((char *)obj + 0x1c) = lbl_803E81E0;
        *(f32 *)((char *)obj + 0x20) = lbl_803E8200;
        *(s16 *)((char *)obj + 0) = 0x32c1;
        break;
    case 0x460B6:
        *(f32 *)((char *)obj + 0x18) = lbl_803E8204;
        *(f32 *)((char *)obj + 0x1c) = lbl_803E81E0;
        *(f32 *)((char *)obj + 0x20) = lbl_803E8208;
        *(s16 *)((char *)obj + 0) = 0x119f;
        break;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
int fn_802A97D0(int obj, int p2)
{
    int inner = *(int *)((char *)obj + 0xb8);
    void *slot;
    u8 af;
    u8 c;
    s16 sel = *(s16 *)((char *)p2 + 0x274);

    if ((sel != 1 && sel != 2 && sel != 0x26) ||
        !GameBit_Get(0x957) ||
        (slot = *(void **)((char *)inner + 0x4b8)) == NULL ||
        *(s16 *)((char *)slot + 0x46) != 0x64f ||
        ((af = *(u8 *)((char *)slot + 0xaf)) & 4) == 0 ||
        (af & 0x18) != 0 ||
        *(void **)((char *)p2 + 0x2d0) != NULL ||
        (c = *(u8 *)((char *)inner + 0x8c8)) == 0x48 || c == 0x47 || c == 0x44 ||
        *(void **)((char *)inner + 0x7f8) != NULL ||
        ((ByteFlags *)((char *)inner + 0x3f0))->b20 ||
        ((ByteFlags *)((char *)inner + 0x3f0))->b04 ||
        ((ByteFlags *)((char *)inner + 0x3f0))->b08 ||
        ((ByteFlags *)((char *)inner + 0x3f4))->b40 == 0 ||
        *(s16 *)((char *)*(int *)((char *)*(int *)((char *)obj + 0xb8) + 0x35c) + 4) < 0xa) {
        return 0;
    }
    return 1;
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void fn_802B18BC(int obj, int state, f32 fv)
{
    f32 v;

    if ((*(u16 *)((char *)state + 0x6e0) & 0x100) && fn_802A9A0C(obj, state)) {
        ((ByteFlags *)((char *)state + 0x3f4))->b20 = 1;
        *(f32 *)((char *)state + 0x414) += fv;
        v = *(f32 *)((char *)state + 0x414);
        if (v < lbl_803E7EA4) {
            v = lbl_803E7EA4;
        } else if (v > lbl_803E813C) {
            v = lbl_803E813C;
        }
        *(f32 *)((char *)state + 0x414) = v;
    } else {
        ((ByteFlags *)((char *)state + 0x3f4))->b20 = 0;
        *(f32 *)((char *)state + 0x414) = lbl_803E7EA4;
    }

    *(f32 *)((char *)state + 0x410) -= fv;
    if (*(f32 *)((char *)state + 0x410) < lbl_803E7EA4) {
        *(f32 *)((char *)state + 0x410) = lbl_803E7EA4;
    }
    *(f32 *)((char *)state + 0x878) -= fv;
    if (*(f32 *)((char *)state + 0x878) < lbl_803E7EA4) {
        *(f32 *)((char *)state + 0x878) = lbl_803E7EA4;
    }
    *(f32 *)((char *)state + 0x87c) -= fv;
    if (*(f32 *)((char *)state + 0x87c) < lbl_803E7EA4) {
        *(f32 *)((char *)state + 0x87c) = lbl_803E7EA4;
    }
    *(f32 *)((char *)state + 0x880) -= fv;
    if (*(f32 *)((char *)state + 0x880) < lbl_803E7EA4) {
        *(f32 *)((char *)state + 0x880) = lbl_803E7EA4;
    }
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802B19F8(int obj, int state, f32 fv)
{
    u8 c;

    *(int *)((char *)state + 0x6d0) = 0;
    *(int *)((char *)state + 0x6d4) = 0;
    *(u16 *)((char *)state + 0x6e0) = 0;
    *(u16 *)((char *)state + 0x6e2) = 0;
    *(u16 *)((char *)state + 0x6e4) = 0;
    if ((*(int *)((char *)state + 0x360) & 0x200000) == 0 &&
        *(s16 *)((char *)state + 0x81a) != -1 &&
        (c = *(u8 *)((char *)state + 0x8c8)) != 0x44 && c != 0x4e) {
        *(int *)((char *)state + 0x6d0) = padGetStickX(0);
        *(int *)((char *)state + 0x6d4) = padGetStickY(0);
        *(u16 *)((char *)state + 0x6e0) = getButtonsHeld(0);
        *(u16 *)((char *)state + 0x6e2) = getButtonsJustPressed(0);
        *(u16 *)((char *)state + 0x6e4) = getButtonsJustPressedIfNotBusy(0);
    }
    *(f32 *)((char *)state + 0x6dc) = (f32)*(int *)((char *)state + 0x6d0);
    *(f32 *)((char *)state + 0x6d8) = (f32)*(int *)((char *)state + 0x6d4);
    fn_802B18BC(obj, state, fv);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802B1BF8(EmitObj *a, int b, int state)
{
    struct {
        s16 angles[4];
        f32 mat[4];
    } v;
    f32 mtx[16];
    f32 oy;
    f32 f31v;
    f32 f30v;
    s8 flags = *(s8 *)((char *)state + 0x34c);

    if ((flags & 2) == 0 && (flags & 1) == 0) {
        f31v = *(f32 *)((char *)state + 0x280);
        f30v = *(f32 *)((char *)state + 0x284);
        if (((ByteFlags *)((char *)b + 0x3f0))->b20) {
            f31v = f31v + *(f32 *)((char *)b + 0x43c);
            f30v = f30v + *(f32 *)((char *)b + 0x440);
        }
        v.angles[0] = *(s16 *)((char *)b + 0x484);
        v.angles[1] = 0;
        v.angles[2] = 0;
        v.mat[0] = lbl_803E7EE0;
        v.mat[1] = lbl_803E7EA4;
        v.mat[2] = lbl_803E7EA4;
        v.mat[3] = lbl_803E7EA4;
        setMatrixFromObjectPos(mtx, v.angles);
        Matrix_TransformPoint(mtx, f30v, lbl_803E7EA4, -f31v, &a->x, &oy, &a->z);
        a->x = a->x + *(f32 *)((char *)b + 0x890);
        a->z = a->z + *(f32 *)((char *)b + 0x894);
    } else {
        int cosI =
            (int)fn_80293E80(lbl_803E7F94 * (f32)*(s16 *)((char *)b + 0x484) / lbl_803E7F98);
        int sinI =
            (int)sin(lbl_803E7F94 * (f32)*(s16 *)((char *)b + 0x484) / lbl_803E7F98);
        *(f32 *)((char *)state + 0x284) = a->x * (f32)sinI - a->z * (f32)cosI;
        *(f32 *)((char *)state + 0x280) = -a->z * (f32)sinI - a->x * (f32)cosI;
    }

    if ((*(int *)((char *)state) & 0x200000) == 0) {
        a->y = a->y * powfBitEstimate(lbl_803E8140, timeDelta);
        a->y = a->y - *(f32 *)((char *)state + 0x2a4) * timeDelta;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802B1E5C(int obj, int state, int cfg, f32 dt)
{
    u32 b;
    void *found;
    int iv;
    s16 sv;
    f32 fv2;
    f32 clamp;
    f32 velMag;
    f32 damp;
    f32 r;
    f32 local_78;
    f32 local_74;
    int **nearList;
    f32 local_6c[4];
    f32 local_5c;
    f32 local_58;
    f32 local_54;

    fv2 = lbl_803E7EE0;
    found = 0;
    *(f32 *)((char *)state + 0x82c) = lbl_803E7EE0;
    *(f32 *)((char *)state + 0x834) = fv2;
    *(f32 *)((char *)state + 0x830) = lbl_803E8144;
    *(u8 *)((char *)state + 0x86c) = 0;
    b = *(u8 *)((char *)state + 0x3f0) >> 5 & 1;
    if (b == 0 || (b != 0 && lbl_803E80D0 != *(f32 *)((char *)cfg + 0x1c0))) {
        *(f32 *)((char *)state + 0x83c) = *(f32 *)((char *)cfg + 0x1c0);
    }
    if (lbl_803E80D0 != *(f32 *)((char *)state + 0x83c)) {
        *(f32 *)((char *)state + 0x838) =
            *(f32 *)((char *)state + 0x83c) - *(f32 *)((char *)obj + 0x1c);
    } else {
        *(f32 *)((char *)state + 0x838) = lbl_803E7EA4;
    }
    ((ByteFlags *)((char *)state + 0x3f1))->b01 = 0;
    clamp = lbl_803E7EA4;
    local_74 = lbl_803E7EA4;
    local_78 = lbl_803E7EA4;
    if ((*(s8 *)((char *)cfg + 0x264) & 0x10) != 0) {
        ((ByteFlags *)((char *)state + 0x3f1))->b01 = 1;
        *(u8 *)((char *)state + 0x86c) = *(u8 *)((char *)cfg + 0xbc);
        fv2 = lbl_803E7EE0;
        switch (*(u8 *)((char *)state + 0x86c)) {
        case 13:
            *(f32 *)((char *)state + 0x82c) = lbl_803E8148;
            *(f32 *)((char *)state + 0x834) = lbl_803E814C;
            *(f32 *)((char *)state + 0x830) = lbl_803E8118;
            break;
        case 3:
            *(f32 *)((char *)state + 0x82c) = lbl_803E7EE0;
            *(f32 *)((char *)state + 0x834) = fv2;
            *(f32 *)((char *)state + 0x830) = lbl_803E7F6C;
            break;
        case 6:
            iv = (int)((f32)*(s16 *)((char *)state + 0x808) - dt);
            sv = (s16)iv;
            *(s16 *)((char *)state + 0x808) = sv;
            if (sv <= 0) {
                *(s16 *)((char *)state + 0x808) = 0x3c;
                ObjHits_RecordObjectHit(obj, 0, 0x14, 2, 0);
            }
            break;
        case 29:
            local_6c[0] = lbl_803E8150;
            found = (void *)ObjGroup_FindNearestObject(0x16, obj, local_6c);
            if (found != 0) {
                (*(void (*)(f32, int, int, f32 *, f32 *))(*(int *)(*(int *)(*(int *)((char *)found + 0x68)) + 0x20)))(
                    lbl_803E7EE0, (int)found, obj, &local_74, &local_78);
            }
            break;
        case 26:
            iv = (int)((f32)*(s16 *)((char *)state + 0x808) - dt);
            sv = (s16)iv;
            *(s16 *)((char *)state + 0x808) = sv;
            if (sv <= 0) {
                *(s16 *)((char *)state + 0x808) = 0x3c;
                ObjPath_GetPointWorldPosition(obj, 0xb, &local_5c, &local_58, &local_54, 0);
                ObjHits_RecordPositionHit(local_5c, local_58, local_54, obj, 0, 0x14, 2, 0xffffffff);
            }
            break;
        case 8:
            ObjHits_RecordObjectHit(obj, 0, 1, 0, 0);
            break;
        case 28:
            if (GameBit_Get(0x21) == 0) {
                *(s16 *)((char *)state + 0x8a0) =
                    (s16)(int)((f32)*(u16 *)((char *)state + 0x8a0) + dt);
                if (0x78 < *(u16 *)((char *)state + 0x8a0)) {
                    *(u16 *)((char *)state + 0x8a0) = *(u16 *)((char *)state + 0x8a0) - 0x78;
                    ObjPath_GetPointWorldPosition(obj, 0xb, &local_5c, &local_58, &local_54, 0);
                    ObjHits_RecordPositionHit(local_5c, local_58, local_54, obj, 0, 0x16, 2,
                                              0xffffffff);
                }
            }
            break;
        case 32:
            if (*(f32 *)((char *)cfg + 0x280) <= lbl_803E7E98) {
                *(f32 *)((char *)state + 0x7c8) =
                    -(lbl_803E7E90 * dt - *(f32 *)((char *)state + 0x7c8));
                if (lbl_803DE440 <= clamp) {
                    Sfx_PlayFromObject(obj, SFXmammoth_snowstep);
                    lbl_803DE440 = (f32)(int)randomGetRange(0x27, 0x3c);
                } else {
                    lbl_803DE440 = lbl_803DE440 - dt;
                }
            } else {
                r = lbl_803E7F6C + *(f32 *)((char *)state + 0x7c8);
                if (r < clamp) {
                    clamp = r;
                }
                *(f32 *)((char *)state + 0x7c8) = clamp;
            }
            iv = hitDetectFn_80065e50(obj, &nearList, 0, 0x20, *(f32 *)((char *)obj + 0xc),
                                      *(f32 *)((char *)obj + 0x10), *(f32 *)((char *)obj + 0x14));
            velMag = -*(f32 *)((char *)state + 0x7c8);
            if (1 < iv &&
                (velMag = velMag + (**nearList - *nearList[iv - 1]), lbl_803E7FA0 < velMag)) {
                int inner = *(int *)((char *)obj + 0xb8);
                s8 *p = *(s8 **)((char *)inner + 0x35c);
                int n = *p - 1;
                if (n < 0) {
                    n = 0;
                } else if (p[1] < n) {
                    n = p[1];
                }
                *p = (s8)n;
                if (**(s8 **)((char *)inner + 0x35c) < 1) {
                    playerDie(obj);
                }
            }
            break;
        case 31:
            GameBit_Set(0x643, 1);
            break;
        default:
            *(s16 *)((char *)state + 0x808) = 0;
            if (*(f32 *)((char *)state + 0x7c8) < lbl_803E7EA4) {
                fv2 = lbl_803E7EFC * *(f32 *)((char *)cfg + 0x280) +
                      *(f32 *)((char *)state + 0x7c8);
                r = lbl_803E7EA4;
                if (fv2 < lbl_803E7EA4) {
                    r = fv2;
                }
                *(f32 *)((char *)state + 0x7c8) = r;
                velMag = -*(f32 *)((char *)state + 0x7c8);
            }
            break;
        }
        if (velMag != lbl_803E7EA4) {
            damp = lbl_803E7F14;
            r = -(lbl_803E7F6C * velMag - lbl_803E7EE0);
            if (damp < r) {
                damp = r;
            }
            *(f32 *)((char *)obj + 0x24) =
                *(f32 *)((char *)obj + 0x24) * powfBitEstimate(damp, dt);
            *(f32 *)((char *)obj + 0x2c) =
                *(f32 *)((char *)obj + 0x2c) * powfBitEstimate(damp, dt);
        }
    }
    r = interpolate(local_74 - *(f32 *)((char *)state + 0x890), lbl_803E7FCC, timeDelta);
    *(f32 *)((char *)state + 0x890) = *(f32 *)((char *)state + 0x890) + r;
    r = interpolate(local_78 - *(f32 *)((char *)state + 0x894), lbl_803E7FCC, timeDelta);
    *(f32 *)((char *)state + 0x894) = *(f32 *)((char *)state + 0x894) + r;
    if (found == 0) {
        *(f32 *)((char *)state + 0x890) =
            *(f32 *)((char *)state + 0x890) * powfBitEstimate(lbl_803E7FF4, timeDelta);
        *(f32 *)((char *)state + 0x894) =
            *(f32 *)((char *)state + 0x894) * powfBitEstimate(lbl_803E7FF4, timeDelta);
    }
    if (*(f32 *)((char *)state + 0x890) > lbl_803E7FEC &&
        *(f32 *)((char *)state + 0x890) < lbl_803E7EF8) {
        *(f32 *)((char *)state + 0x890) = lbl_803E7EA4;
    }
    if (*(f32 *)((char *)state + 0x894) > lbl_803E7FEC &&
        *(f32 *)((char *)state + 0x894) < lbl_803E7EF8) {
        *(f32 *)((char *)state + 0x894) = lbl_803E7EA4;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_8029A4A8(int obj, int p2)
{
    int inner = *(int *)((char *)obj + 0xb8);
    s16 sel = *(s16 *)((char *)p2 + 0x274);
    void **p;
    int i;

    if (sel == 0x2a || sel == 0x2e || sel == 0x2f || sel == 0x2c) return;

    *(int *)((char *)inner + 0x360) |= 0x800000;
    *(s16 *)((char *)inner + 0x80a) = -1;
    *(int *)((char *)inner + 0x360) &= ~0x2000400;

    if (*(s16 *)((char *)p2 + 0x274) != 0x2b) {
        if (*(u8 *)((char *)inner + 0x8c8) != 0x42 && getCurSeqNo() == 0) {
            (*(void (*)(int, int, int, int, int, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
                0x42, 0, 1, 0, 0, 0x3c, 0xfe);
        }
        ((ByteFlags *)((char *)inner + 0x3f6))->b40 = 0;
    }

    lbl_803DE42C = 0;
    p = lbl_80332ED4;
    for (i = 0; i < 7; i++) {
        if (*p != NULL) {
            Obj_FreeObject((int)*p);
            *p = NULL;
        }
        p++;
    }
    if (lbl_803DE454 != NULL) {
        Resource_Release(lbl_803DE454);
        lbl_803DE454 = NULL;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802B07D8(int obj, int state)
{
    int setup;
    int b;

    if ((int)lbl_803DE44C == 0 && Obj_IsLoadingLocked()) {
        setup = Obj_AllocObjectSetup(0x18, 0x69);
        setup = Obj_SetupObject(setup, 4, -1, -1, *(int *)((char *)obj + 0x30));
        lbl_803DE44C = (void *)setup;
        ObjLink_AttachChild(obj, setup, 2);
    }
    if ((int)lbl_803DE44C != 0) {
        *(int *)((char *)lbl_803DE44C + 0x30) = *(int *)((char *)obj + 0x30);
    }

    *(f32 *)((char *)state + 0x7d4) -= lbl_803E7E98 * timeDelta;
    if (*(f32 *)((char *)state + 0x7d4) < lbl_803E7EA4) {
        *(f32 *)((char *)state + 0x7d4) = lbl_803E7EA4;
    }
    *(f32 *)((char *)state + 0x7d8) -= lbl_803E7E98 * timeDelta;
    if (*(f32 *)((char *)state + 0x7d8) < lbl_803E7EA4) {
        *(f32 *)((char *)state + 0x7d8) = lbl_803E7EA4;
    }

    fn_8011F34C((u8)(int)*(f32 *)((char *)state + 0x7d4));

    if (obj != 0) {
        b = (*(s8 *)((char *)obj + 0xad) != 0);
    } else {
        b = 0;
    }
    if (b == 0 && GameBit_Get(0x75)) {
        fn_80295CF4(obj, 0);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_8029D900(int obj, int state, f32 fv)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int hit;

    *(u8 *)((char *)state + 0x34d) = 3;
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        if (ObjHits_GetPriorityHit(obj, &hit, 0, 0)) {
            *(s16 *)((char *)inner + 0x478) =
                (s16)getAngle(-*(f32 *)((char *)hit + 0x24), -*(f32 *)((char *)hit + 0x2c));
            *(s16 *)((char *)inner + 0x484) = *(s16 *)((char *)inner + 0x478);
        }
        ObjAnim_SetCurrentMove(obj, 0x407, lbl_803E7EA4, 0);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7F34;
    }
    switch (*(s16 *)((char *)obj + 0xa0)) {
    case 0x407:
        if (*(s8 *)((char *)state + 0x346) != 0) {
            ObjAnim_SetCurrentMove(obj, 0x408, lbl_803E7EA4, 0);
            *(f32 *)((char *)state + 0x2a0) = lbl_803E7FCC;
        }
        break;
    case 0x408:
        if (*(s8 *)((char *)state + 0x346) != 0) {
            *(int *)((char *)state + 0x308) = (int)fn_802A514C;
            return 2;
        }
        break;
    }
    (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x20)))(obj, state, fv, 1);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802957B4(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int sub;

    if (obj == 0) {
        return 0;
    }
    (*(void (*)(int, int, int))(*(int *)(*gCameraInterface + 0x24)))(0, 1, 0);
    (*(void (*)(int, int, int, int))(*(int *)(*gObjectTriggerInterface + 0x50)))(0x42, 4, 0, 0);

    sub = *(int *)((char *)inner + 0x7f0);
    if (sub == 0) {
        return 0;
    }
    (*(void (*)(int, int))(*(int *)(*(int *)((char *)sub + 0x68) + 0x3c)))(sub, 0);
    (*(void (*)(int, int))(*(int *)(*gCameraInterface + 0x28)))(obj, 0);
    *(s16 *)((char *)obj + 6) = *(s16 *)((char *)obj + 6) & ~8;
    *(int *)((char *)*(int *)((char *)obj + 0x64) + 0x30) &= ~0x1000;
    *(int *)((char *)inner + 0x7f0) = 0;
    *(s16 *)((char *)obj + 0xa2) = -1;
    (*(void (*)(int, int, int))(*(int *)(*gPlayerInterface + 0x14)))(obj, inner, 1);
    *(int *)((char *)inner + 0x304) = (int)fn_802A514C;
    Music_Trigger(0x1f, 0);
    Music_Trigger(0x97, 0);
    Music_Trigger(0xe6, 0);
    Music_Trigger(0xd5, 0);
    return 1;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_8029BC4C(int obj, int state, f32 fv)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int idx;

    if (*(s8 *)((char *)state + 0x27a) != 0) {
        if (lbl_803DE459 == 0) {
            lbl_803DE459 = 1;
        } else if (lbl_803DE459 > 2) {
            lbl_803DE459 = 2;
        }
        idx = lbl_803DE459;
        *(f32 *)((char *)state + 0x2a0) = lbl_803DC690[idx - 1];
        ObjAnim_SetCurrentMove(obj, lbl_803DC688[idx - 1], lbl_803E7EA4, 0);
        lbl_803DE459 = 0;
    }
    if (*(s8 *)((char *)state + 0x346) != 0) {
        *(u8 *)((char *)*(int *)((char *)obj + 0x54) + 0x70) = 0;
        if (*(void **)((char *)state + 0x2d0) != NULL) {
            *(int *)((char *)state + 0x308) = (int)fn_8029C8C8;
            return 0x25;
        }
        ((ByteFlags *)((char *)inner + 0x3f1))->b80 = 1;
        *(int *)((char *)inner + 0x360) |= 0x800000;
        *(int *)((char *)state + 0x308) = (int)fn_802A514C;
        return 2;
    }
    (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x20)))(obj, state, fv, 1);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void Lightfoot_ProcessHitResponseFlags(int obj, int inner)
{
    if (*(int *)((char *)inner + 0x314) & 4) {
        *(int *)((char *)inner + 0x314) &= ~4;
        Sfx_PlayFromObject(obj, SFXtr_gal_prophit);
    }
    if (*(int *)((char *)inner + 0x314) & 2) {
        *(int *)((char *)inner + 0x314) &= ~2;
        Sfx_PlayFromObject(obj, SFXtr_gal_prophit);
    }
    if (*(int *)((char *)inner + 0x314) & 1) {
        *(int *)((char *)inner + 0x314) &= ~1;
        if (randomGetRange(0, 2) == 0) {
            Sfx_PlayFromObject(obj, 0x43c);
        }
    }
    if (*(int *)((char *)inner + 0x314) & 0x80) {
        *(int *)((char *)inner + 0x314) &= ~0x80;
        Sfx_PlayFromObject(obj, SFXtr_jbike_snowhit);
    }
    if (*(int *)((char *)inner + 0x314) & 0x200) {
        *(int *)((char *)inner + 0x314) &= ~0x200;
        Sfx_PlayFromObject(obj, SFXtr_barrelgrabber_eloop);
    }
    if (*(int *)((char *)inner + 0x314) & 0x40) {
        *(int *)((char *)inner + 0x314) &= ~0x40;
        Sfx_PlayFromObject(obj, SFXtr_jbike_snowspray);
    }
    if (*(int *)((char *)inner + 0x314) & 0x800) {
        *(int *)((char *)inner + 0x314) &= ~0x800;
        ObjHits_RecordObjectHit(Obj_GetPlayerObject(), obj, 0x19, 2, 1);
        Sfx_PlayFromObject(obj, SFXtr_jbike_boost);
        CameraShake_Start(lbl_803E81CC, lbl_803E81D0, lbl_803E81D4);
        doRumble(lbl_803E81D8);
    }
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_8029E3F4(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);
    f32 k;
    f32 a, b;
    u8 s1, s2;

    if (*(s8 *)((char *)state + 0x27a) != 0) {
        *(s16 *)((char *)state + 0x278) = 0x1c;
        *(int *)((char *)inner + 0x898) = 0;
    }
    k = lbl_803E7EA4;
    *(f32 *)((char *)state + 0x294) = k;
    *(f32 *)((char *)state + 0x284) = k;
    *(f32 *)((char *)state + 0x280) = k;
    *(f32 *)((char *)obj + 0x24) = k;
    *(f32 *)((char *)obj + 0x28) = k;
    *(f32 *)((char *)obj + 0x2c) = k;
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        s1 = 0;
        a = *(f32 *)((char *)inner + 0x654);
        if (a < lbl_803E7EA4) {
            s1 = 1;
            a = -a;
        }
        s2 = 0;
        b = *(f32 *)((char *)inner + 0x65c);
        if (b < lbl_803E7EA4) {
            s2 = 1;
            b = -b;
        }
        if (a > b) {
            if (s1) {
                *(u8 *)((char *)inner + 0x682) = 0;
            } else {
                *(u8 *)((char *)inner + 0x682) = 1;
            }
        } else {
            if (s2) {
                *(u8 *)((char *)inner + 0x682) = 2;
            } else {
                *(u8 *)((char *)inner + 0x682) = 3;
            }
        }
        ObjAnim_SetCurrentMove(obj, 0x57, lbl_803E7EA4, 0);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7FE8;
        Sfx_PlayFromObject(obj, (u16)(*(s16 *)((char *)inner + 0x81a) == 0 ? 0x2d3 : 0x2b));
    }
    if (*(s8 *)((char *)state + 0x346) != 0) {
        *(int *)((char *)state + 0x308) = (int)fn_802A514C;
        return -1;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802A49C8(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int sub;
    f32 k;

    if (*(s8 *)((char *)state + 0x27a) != 0) {
        if (*(void **)((char *)inner + 0x7f8) != NULL) {
            ObjHits_MarkObjectPositionDirty(*(int *)((char *)inner + 0x7f8));
        }
        ObjAnim_SetCurrentMove(obj, 0x443, lbl_803E7EAC, 0);
        *(s16 *)((char *)state + 0x278) = 1;
        *(int *)((char *)inner + 0x898) = (int)fn_802A514C;
    }
    k = lbl_803E7EA4;
    *(f32 *)((char *)state + 0x294) = k;
    *(f32 *)((char *)state + 0x284) = k;
    *(f32 *)((char *)state + 0x280) = k;
    *(f32 *)((char *)obj + 0x24) = k;
    *(f32 *)((char *)obj + 0x28) = k;
    *(f32 *)((char *)obj + 0x2c) = k;
    *(f32 *)((char *)state + 0x2a0) = lbl_803E8058;

    if (*(int *)((char *)state + 0x314) & 1) {
        Sfx_PlayFromObject(obj, (u16)(*(s16 *)((char *)inner + 0x81a) == 0 ? 0x327 : 0x379));
    }

    sub = *(int *)((char *)inner + 0x7f8);
    if (sub == 0 && *(s8 *)((char *)state + 0x346) != 0) {
        *(int *)((char *)state + 0x308) = (int)fn_802A514C;
        return 2;
    }
    if (sub != 0 && *(f32 *)((char *)obj + 0x98) > lbl_803E7E9C) {
        *(u8 *)((char *)inner + 0x800) = 0;
        if (*(void **)((char *)inner + 0x7f8) != NULL) {
            int s2 = *(int *)((char *)inner + 0x7f8);
            s16 id = *(s16 *)((char *)s2 + 0x46);
            if (id == 0x3cf || id == 0x662) {
                objThrowFn_80182504(s2);
            } else {
                objSaveFn_800ea774(s2);
            }
            *(s16 *)((char *)*(int *)((char *)inner + 0x7f8) + 6) &= ~0x4000;
            *(int *)((char *)*(int *)((char *)inner + 0x7f8) + 0xf8) = 0;
            *(int *)((char *)inner + 0x7f8) = 0;
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80298CCC(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);
    f32 k;

    if (*(s8 *)((char *)state + 0x27a) != 0) {
        ObjHits_MarkObjectPositionDirty(obj);
    }
    k = lbl_803E7EA4;
    *(f32 *)((char *)state + 0x294) = k;
    *(f32 *)((char *)state + 0x284) = k;
    *(f32 *)((char *)state + 0x280) = k;
    *(f32 *)((char *)obj + 0x24) = k;
    *(f32 *)((char *)obj + 0x28) = k;
    *(f32 *)((char *)obj + 0x2c) = k;

    if (*(s16 *)((char *)obj + 0xa0) == 0xdd) {
        if (*(f32 *)((char *)obj + 0x98) > lbl_803E7F44) {
            cfPrisonGuard_setLiftHeight(lbl_803DE434, 0);
        }
        if (*(f32 *)((char *)obj + 0x98) > lbl_803E7F48 &&
            (*(u8 *)((char *)state + 0x356) & 1) == 0) {
            Sfx_PlayFromObject(obj, SFXbaddie_eggsnatch_sniff3);
            *(u8 *)((char *)state + 0x356) |= 1;
        }
        if (*(s8 *)((char *)state + 0x346) != 0) {
            *(int *)((char *)inner + 0x360) |= 0x800000;
            *(int *)((char *)state + 0x308) = (int)fn_802A514C;
            return 2;
        }
    } else {
        ObjAnim_SetCurrentMove(obj, 0xdd, k, 0);
        staffactivated_calcInteractionTargetXZ(lbl_803DE434, (char *)obj + 0xc, (char *)obj + 0x14);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7EF8;
        *(u8 *)((char *)state + 0x356) = 0;
        *(s16 *)((char *)inner + 0x478) = *(s16 *)((char *)lbl_803DE434);
        *(s16 *)((char *)inner + 0x484) = *(s16 *)((char *)inner + 0x478);
        if ((int)lbl_803DE44C != 0 && ((ByteFlags *)((char *)inner + 0x3f4))->b40) {
            *(u8 *)((char *)inner + 0x8b4) = 4;
            ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 1;
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_80295CF4(int obj, int a)
{
    int inner = *(int *)((char *)obj + 0xb8);

    if ((int)lbl_803DE44C == 0 || ((ByteFlags *)((char *)inner + 0x3f4))->b40 == a) {
        return;
    }
    if (a == 0) {
        *(s16 *)((char *)lbl_803DE44C + 6) |= 0x4000;
        if ((int)lbl_803DE44C != 0 && ((ByteFlags *)((char *)inner + 0x3f4))->b40) {
            *(u8 *)((char *)inner + 0x8b4) = 1;
            ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 1;
        }
        GameBit_Set(0x96b, 1);
        GameBit_Set(0x961, 1);
        GameBit_Set(0x969, 1);
        GameBit_Set(0x964, 1);
        GameBit_Set(0x965, 1);
        GameBit_Set(0x986, 1);
        GameBit_Set(0x960, 1);
    } else {
        if (((ByteFlags *)((char *)inner + 0x3f4))->b40) {
            *(u8 *)((char *)inner + 0x8b4) = 4;
            ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 1;
        }
        *(s16 *)((char *)lbl_803DE44C + 6) &= ~0x4000;
        GameBit_Set(0x96b, 0);
        GameBit_Set(0x961, 0);
        GameBit_Set(0x969, 0);
        GameBit_Set(0x964, 0);
        GameBit_Set(0x965, 0);
        GameBit_Set(0x986, 0);
        GameBit_Set(0x960, 0);
    }
    ((ByteFlags *)((char *)inner + 0x3f4))->b40 = a;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802AE83C(int obj, int inner)
{
    int sub;

    ((ByteFlags *)((char *)inner + 0x3f1))->b40 = 0;
    ((ByteFlags *)((char *)inner + 0x3f0))->b40 = 0;
    ((ByteFlags *)((char *)inner + 0x3f0))->b80 = 0;
    ((ByteFlags *)((char *)inner + 0x3f0))->b08 = 0;
    ((ByteFlags *)((char *)inner + 0x3f0))->b04 = 0;
    *(u8 *)((char *)inner + 0x40d) = 0;
    ((ByteFlags *)((char *)inner + 0x3f0))->b20 = 1;
    ((ByteFlags *)((char *)inner + 0x3f0))->b10 = 0;
    *(f32 *)((char *)inner + 0x440) = lbl_803E7EA4;
    *(f32 *)((char *)inner + 0x43c) = lbl_803E7EA4;
    Sfx_StopFromObject(obj, (u16)(*(s16 *)((char *)inner + 0x81a) == 0 ? 0x2d0 : 0x26));

    if ((int)lbl_803DE44C != 0 && ((ByteFlags *)((char *)inner + 0x3f4))->b40) {
        *(u8 *)((char *)inner + 0x8b4) = 1;
        ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 1;
    }
    *(u8 *)((char *)inner + 0x800) = 0;
    sub = *(int *)((char *)inner + 0x7f8);
    if (sub != 0) {
        s16 id = *(s16 *)((char *)sub + 0x46);
        if (id == 0x3cf || id == 0x662) {
            objThrowFn_80182504(sub);
        } else {
            objSaveFn_800ea774(sub);
        }
        *(s16 *)((char *)*(int *)((char *)inner + 0x7f8) + 6) &= ~0x4000;
        *(int *)((char *)*(int *)((char *)inner + 0x7f8) + 0xf8) = 0;
        *(int *)((char *)inner + 0x7f8) = 0;
    }
    if (*(f32 *)((char *)obj + 0x28) < lbl_803E812C) {
        Sfx_PlayFromObject(obj, SFXthorntail_snort2);
        (*(void (*)(int, f32, f32, f32, f32))(*(int *)(*gWaterfxInterface + 0x10)))(
            obj, *(f32 *)((char *)obj + 0xc), *(f32 *)((char *)obj + 0x10),
            *(f32 *)((char *)obj + 0x14), lbl_803E7ED8);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80298380(int obj, int state, f32 fv)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int r;

    if (*(s8 *)((char *)state + 0x27a) != 0) {
        ObjAnim_SetCurrentMove(obj, 0xfb, lbl_803E7EA4, 0);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7F28;
        *(f32 *)((char *)state + 0x294) = lbl_803E7EA4;
        *(f32 *)((char *)state + 0x284) = lbl_803E7EA4;
        *(f32 *)((char *)state + 0x280) = lbl_803E7EA4;
        *(f32 *)((char *)obj + 0x24) = lbl_803E7EA4;
        *(f32 *)((char *)obj + 0x28) = lbl_803E7EA4;
        *(f32 *)((char *)obj + 0x2c) = lbl_803E7EA4;
    }

    r = fn_8029B9FC(obj, state, fv);
    if (r != 0) {
        return r;
    }

    (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x30)))(obj, state, fv, 1);
    *(s16 *)((char *)inner + 0x484) = *(s16 *)((char *)obj);
    *(s16 *)((char *)inner + 0x478) = *(s16 *)((char *)obj);
    (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x20)))(obj, state, fv, 2);

    if (*(s8 *)((char *)state + 0x346) != 0) {
        *(int *)((char *)state + 0x308) = (int)fn_8029C8C8;
        return 0x25;
    }
    if (*(f32 *)((char *)obj + 0x98) > lbl_803E7F2C) {
        if (*(u8 *)((char *)state + 0x349) == 1) {
            r = fn_80299E44(obj, state, fv);
            if (r != 0) {
                return r;
            }
        } else {
            if ((int)lbl_803DE44C != 0 && ((ByteFlags *)((char *)inner + 0x3f4))->b40) {
                *(u8 *)((char *)inner + 0x8b4) = 0;
                ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 1;
            }
            *(int *)((char *)state + 0x308) = (int)fn_802A514C;
            return -1;
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802A4B78(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int sub;

    if (*(s8 *)((char *)state + 0x27a) != 0) {
        ObjAnim_SetCurrentMove(obj, 0x447, lbl_803E7EA4, 0);
        *(s16 *)((char *)state + 0x278) = 1;
        *(int *)((char *)inner + 0x898) = (int)fn_802A514C;
    }
    if ((*(int *)((char *)state + 0x314) & 1) &&
        (sub = *(int *)((char *)inner + 0x7f8)) != 0) {
        switch (*(s16 *)((char *)sub + 0x46)) {
        case 0x6d:
        case 0x754:
            Sfx_PlayFromObject(obj, SFXspirit_pool_wobble2);
            break;
        case 0x1f4:
        case 0x1f5:
        case 0x1f6:
        case 0x1f7:
        case 0x1f8:
        case 0x1f9:
        case 0x519:
            Sfx_PlayFromObject(obj, 0x39b);
            break;
        default:
            Sfx_PlayFromObject(obj, SFXmn_dimraw26);
            break;
        }
    }
    *(f32 *)((char *)state + 0x280) = lbl_803E7EA4;
    *(f32 *)((char *)state + 0x2a0) = lbl_803E7F40;

    sub = *(int *)((char *)inner + 0x7f8);
    if (sub == 0 && *(s8 *)((char *)state + 0x346) != 0) {
        *(int *)((char *)inner + 0x360) |= 0x800000;
        *(int *)((char *)state + 0x308) = (int)fn_802A514C;
        return 2;
    }
    if (sub != 0 && *(f32 *)((char *)obj + 0x98) > lbl_803E7F48) {
        *(u8 *)((char *)inner + 0x800) = 0;
        if (*(void **)((char *)inner + 0x7f8) != NULL) {
            int s2 = *(int *)((char *)inner + 0x7f8);
            s16 id = *(s16 *)((char *)s2 + 0x46);
            if (id == 0x3cf || id == 0x662) {
                objThrowFn_80182504(s2);
            } else {
                objSaveFn_800ea774(s2);
            }
            *(s16 *)((char *)*(int *)((char *)inner + 0x7f8) + 6) &= ~0x4000;
            *(int *)((char *)*(int *)((char *)inner + 0x7f8) + 0xf8) = 0;
            *(int *)((char *)inner + 0x7f8) = 0;
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int playerSetHeldObject(int obj, int held)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int sub;

    if (held != 0) {
        *(int *)((char *)inner + 0x7f8) = held;
        (*(void (*)(int, int, int))(*(int *)(*gPlayerInterface + 0x14)))(obj, inner, 5);
        *(int *)((char *)inner + 0x304) = (int)fn_802A4B4C;
    } else if (*(int *)((char *)inner + 0x7f8) != 0) {
        *(u8 *)((char *)inner + 0x800) = 0;
        sub = *(int *)((char *)inner + 0x7f8);
        if (sub != 0) {
            s16 id = *(s16 *)((char *)sub + 0x46);
            if (id == 0x3cf || id == 0x662) {
                objThrowFn_80182504(sub);
            } else {
                objSaveFn_800ea774(sub);
            }
            *(s16 *)((char *)*(int *)((char *)inner + 0x7f8) + 6) &= ~0x4000;
            *(int *)((char *)*(int *)((char *)inner + 0x7f8) + 0xf8) = 0;
            *(int *)((char *)inner + 0x7f8) = 0;
        }
        *(int *)((char *)inner + 0x360) |= 0x800000;
        (*(void (*)(int, int, int))(*(int *)(*gPlayerInterface + 0x14)))(obj, inner, 1);
        *(int *)((char *)inner + 0x304) = (int)fn_802A514C;
    }
    return *(int *)((char *)inner + 0x7f8) != 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80298184(int obj, int state, f32 fv)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int r;
    f32 k;
    s16 hdr;

    *(int *)((char *)inner + 0x360) |= 0x800;
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7EF8;
        k = lbl_803E7EA4;
        *(f32 *)((char *)state + 0x294) = k;
        *(f32 *)((char *)state + 0x284) = k;
        *(f32 *)((char *)state + 0x280) = k;
        *(f32 *)((char *)obj + 0x24) = k;
        *(f32 *)((char *)obj + 0x28) = k;
        *(f32 *)((char *)obj + 0x2c) = k;
    }
    r = fn_8029B9FC(obj, state, fv);
    if (r != 0) {
        return r;
    }
    (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x30)))(obj, state, fv, 1);
    hdr = *(s16 *)obj;
    *(s16 *)((char *)inner + 0x484) = hdr;
    *(s16 *)((char *)inner + 0x478) = hdr;
    if ((getButtons_80014dd8(0) & 0x20) == 0) {
        *(int *)((char *)state + 0x308) = (int)fn_8029C8C8;
        return 0x25;
    }
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        ((ByteFlags *)((char *)inner + 0x3f6))->b10 = 0;
    }
    if (((ByteFlags *)((char *)inner + 0x3f6))->b10) {
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7E8C;
        if (*(s16 *)((char *)obj + 0xa0) != 0x455) {
            doRumble(lbl_803E7ED8);
            ObjAnim_SetCurrentMove(obj, 0x455, lbl_803E7EA4, 0);
            *(f32 *)((char *)state + 0x280) = -*(f32 *)((char *)inner + 0x88c);
        }
        if (*(s8 *)((char *)state + 0x346) != 0) {
            ((ByteFlags *)((char *)inner + 0x3f6))->b10 = 0;
        }
    } else {
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7EF8;
        if (*(s16 *)((char *)obj + 0xa0) != 0x458 &&
            ObjAnim_GetCurrentEventCountdown((ObjAnimComponent *)obj) == 0) {
            ObjAnim_SetCurrentMove(obj, 0x458, *(f32 *)((char *)obj + 0x98), 0);
            ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent *)obj, 8);
        }
    }
    *(f32 *)((char *)state + 0x280) =
        *(f32 *)((char *)state + 0x280) *
        powfBitEstimate(*(f32 *)((char *)inner + 0x888), timeDelta);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80297AD0(int obj, int state, f32 fv)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int r;
    f32 k;
    s16 hdr;

    if (*(s8 *)((char *)state + 0x27a) != 0) {
        ObjAnim_SetCurrentMove(obj, lbl_803336BC[*(s16 *)((char *)lbl_80333714 + 0x422)],
                               lbl_803E7EA4, 0);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7F20;
        k = lbl_803E7EA4;
        *(f32 *)((char *)state + 0x294) = k;
        *(f32 *)((char *)state + 0x284) = k;
        *(f32 *)((char *)state + 0x280) = k;
        *(f32 *)((char *)obj + 0x24) = k;
        *(f32 *)((char *)obj + 0x28) = k;
        *(f32 *)((char *)obj + 0x2c) = k;
    }
    r = fn_8029B9FC(obj, state, fv);
    if (r != 0) {
        return r;
    }
    (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x30)))(obj, state, fv, 0x10);
    hdr = *(s16 *)obj;
    *(s16 *)((char *)inner + 0x484) = hdr;
    *(s16 *)((char *)inner + 0x478) = hdr;
    (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x20)))(obj, state, fv, 1);
    if ((*(u8 *)((char *)state + 0x356) & 1) == 0 &&
        *(f32 *)((char *)obj + 0x98) > lbl_803E7F14) {
        Sfx_PlayFromObject(obj, SFXdn_hightop_hurt1);
        *(u8 *)((char *)state + 0x356) |= 1;
    }
    if ((*(u8 *)((char *)state + 0x356) & 2) == 0 &&
        *(f32 *)((char *)obj + 0x98) > lbl_803E7F18) {
        Sfx_PlayFromObject(obj, SFXen_liftstpc);
        *(u8 *)((char *)state + 0x356) |= 2;
    }
    if (*(s8 *)((char *)state + 0x346) != 0) {
        *(int *)((char *)state + 0x308) = (int)fn_8029C8C8;
        return 0x25;
    }
    if (*(f32 *)((char *)obj + 0x98) > lbl_803E7F1C) {
        if (*(u8 *)((char *)state + 0x349) != 1) {
            if (lbl_803DE44C != 0 && ((ByteFlags *)((char *)inner + 0x3f4))->b40) {
                *(u8 *)((char *)inner + 0x8b4) = 0;
                ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 0;
            }
            *(int *)((char *)state + 0x308) = (int)fn_802A514C;
            return -1;
        }
        r = fn_80299E44(obj, state, fv);
        if (r != 0) {
            return r;
        }
        return 0;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80297D0C(int obj, int state, f32 fv)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int r;
    f32 k;
    s16 hdr;

    if (*(s8 *)((char *)state + 0x27a) != 0) {
        ObjAnim_SetCurrentMove(obj, lbl_803336BC[*(s16 *)((char *)lbl_80333714 + 0x632)],
                               lbl_803E7EA4, 0);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7F24;
        *(u8 *)((char *)state + 0x356) = 0;
        k = lbl_803E7EA4;
        *(f32 *)((char *)state + 0x294) = k;
        *(f32 *)((char *)state + 0x284) = k;
        *(f32 *)((char *)state + 0x280) = k;
        *(f32 *)((char *)obj + 0x24) = k;
        *(f32 *)((char *)obj + 0x28) = k;
        *(f32 *)((char *)obj + 0x2c) = k;
    }
    r = fn_8029B9FC(obj, state, fv);
    if (r != 0) {
        return r;
    }
    (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x30)))(obj, state, fv, 1);
    hdr = *(s16 *)obj;
    *(s16 *)((char *)inner + 0x484) = hdr;
    *(s16 *)((char *)inner + 0x478) = hdr;
    (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x20)))(obj, state, fv, 2);
    if (*(int *)((char *)state + 0x314) & 0x200) {
        doRumble(lbl_803E7F10);
        Sfx_PlayFromObject(obj, 0x3cd);
        *(u16 *)((char *)inner + 0x8d8) |= 4;
    }
    if ((*(u8 *)((char *)state + 0x356) & 1) == 0 &&
        *(f32 *)((char *)obj + 0x98) > lbl_803E7F14) {
        Sfx_PlayFromObject(obj, SFXen_liftstpc);
        *(u8 *)((char *)state + 0x356) |= 1;
    }
    if (*(s8 *)((char *)state + 0x346) != 0) {
        *(int *)((char *)state + 0x308) = (int)fn_8029C8C8;
        return 0x25;
    }
    if (*(f32 *)((char *)obj + 0x98) > lbl_803E7F1C) {
        if (*(u8 *)((char *)state + 0x349) != 1) {
            if (lbl_803DE44C != 0 && ((ByteFlags *)((char *)inner + 0x3f4))->b40) {
                *(u8 *)((char *)inner + 0x8b4) = 0;
                ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 0;
            }
            *(int *)((char *)state + 0x308) = (int)fn_802A514C;
            return -1;
        }
        r = fn_80299E44(obj, state, fv);
        if (r != 0) {
            return r;
        }
        return 0;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80297F48(int obj, int state, f32 fv)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int r;
    f32 k;
    s16 hdr;

    if (*(s8 *)((char *)state + 0x27a) != 0) {
        ObjAnim_SetCurrentMove(obj, lbl_803336BC[*(s16 *)((char *)lbl_80333714 + 0x582)],
                               lbl_803E7EA4, 0);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7F24;
        *(u8 *)((char *)state + 0x356) = 0;
        k = lbl_803E7EA4;
        *(f32 *)((char *)state + 0x294) = k;
        *(f32 *)((char *)state + 0x284) = k;
        *(f32 *)((char *)state + 0x280) = k;
        *(f32 *)((char *)obj + 0x24) = k;
        *(f32 *)((char *)obj + 0x28) = k;
        *(f32 *)((char *)obj + 0x2c) = k;
    }
    r = fn_8029B9FC(obj, state, fv);
    if (r != 0) {
        return r;
    }
    (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x30)))(obj, state, fv, 1);
    hdr = *(s16 *)obj;
    *(s16 *)((char *)inner + 0x484) = hdr;
    *(s16 *)((char *)inner + 0x478) = hdr;
    (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x20)))(obj, state, fv, 2);
    if (*(int *)((char *)state + 0x314) & 0x200) {
        doRumble(lbl_803E7F10);
        Sfx_PlayFromObject(obj, 0x3cd);
        *(u16 *)((char *)inner + 0x8d8) |= 4;
    }
    if ((*(u8 *)((char *)state + 0x356) & 1) == 0 &&
        *(f32 *)((char *)obj + 0x98) > lbl_803E7F14) {
        Sfx_PlayFromObject(obj, SFXen_liftstpc);
        *(u8 *)((char *)state + 0x356) |= 1;
    }
    if (*(s8 *)((char *)state + 0x346) != 0) {
        *(int *)((char *)state + 0x308) = (int)fn_8029C8C8;
        return 0x25;
    }
    if (*(f32 *)((char *)obj + 0x98) > lbl_803E7F1C) {
        if (*(u8 *)((char *)state + 0x349) != 1) {
            if (lbl_803DE44C != 0 && ((ByteFlags *)((char *)inner + 0x3f4))->b40) {
                *(u8 *)((char *)inner + 0x8b4) = 0;
                ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 0;
            }
            *(int *)((char *)state + 0x308) = (int)fn_802A514C;
            return -1;
        }
        r = fn_80299E44(obj, state, fv);
        if (r != 0) {
            return r;
        }
        return 0;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_8029D250(int obj, int state, f32 fv)
{
    MoveTable *mt = (MoveTable *)lbl_80332EC0;
    int inner = *(int *)((char *)obj + 0xb8);
    u32 flags;
    int idx;

    *(u8 *)((char *)state + 0x34d) = 3;
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        if (*(void **)((char *)state + 0x2d0) != NULL &&
            (*(u32 *)((char *)inner + 0x884) & 1)) {
            doRumble(lbl_803E7ED8);
            flags = *(u32 *)((char *)inner + 0x884);
            if (flags & 2) {
                idx = 3;
            } else if (flags & 4) {
                idx = 1;
            } else if (flags & 8) {
                idx = 2;
            } else {
                idx = 3;
            }
            ObjAnim_SetCurrentMove(obj, mt->moves[idx], mt->blend[idx], 0);
            *(f32 *)((char *)state + 0x2a0) = mt->angles[idx];
            *(f32 *)((char *)state + 0x280) = -*(f32 *)((char *)inner + 0x88c);
        } else {
            ObjAnim_SetCurrentMove(obj, mt->moves[*(u8 *)((char *)inner + 0x8a2)],
                                   lbl_803E7EA4, 0);
            *(f32 *)((char *)state + 0x2a0) = mt->angles[*(u8 *)((char *)inner + 0x8a2)];
        }
    }
    if (*(void **)((char *)state + 0x2d0) != NULL) {
        *(s16 *)((char *)inner + 0x478) = *(s16 *)((char *)inner + 0x478) +
            (int)((f32)*(int *)((char *)inner + 0x4a4) / lbl_803E7FC0);
        *(s16 *)((char *)inner + 0x484) = *(s16 *)((char *)inner + 0x478);
    }
    *(f32 *)((char *)state + 0x280) =
        *(f32 *)((char *)state + 0x280) *
        powfBitEstimate(*(f32 *)((char *)inner + 0x888), fv);
    (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x20)))(obj, state, fv, 2);
    if (*(s8 *)((char *)state + 0x346) != 0) {
        *(int *)((char *)state + 0x308) = (int)fn_802A514C;
        return 2;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80297854(int obj, int state, f32 fv)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int r;
    f32 k;
    s16 hdr;

    if (*(s8 *)((char *)state + 0x27a) != 0) {
        ObjAnim_SetCurrentMove(obj, lbl_803336BC[*(s16 *)((char *)lbl_80333714 + 0x4d2)],
                               lbl_803E7EA4, 0);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7F0C;
        k = lbl_803E7EA4;
        *(f32 *)((char *)state + 0x294) = k;
        *(f32 *)((char *)state + 0x284) = k;
        *(f32 *)((char *)state + 0x280) = k;
        *(f32 *)((char *)obj + 0x24) = k;
        *(f32 *)((char *)obj + 0x28) = k;
        *(f32 *)((char *)obj + 0x2c) = k;
    }
    r = fn_8029B9FC(obj, state, fv);
    if (r != 0) {
        return r;
    }
    (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x30)))(obj, state, fv, 0x10);
    hdr = *(s16 *)obj;
    *(s16 *)((char *)inner + 0x484) = hdr;
    *(s16 *)((char *)inner + 0x478) = hdr;
    (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x20)))(obj, state, fv, 1);
    if (*(int *)((char *)state + 0x314) & 0x200) {
        doRumble(lbl_803E7F10);
        Sfx_PlayFromObject(obj, 0x3cd);
        *(u16 *)((char *)inner + 0x8d8) |= 4;
    }
    if ((*(u8 *)((char *)state + 0x356) & 1) == 0 &&
        *(f32 *)((char *)obj + 0x98) > lbl_803E7F14) {
        Sfx_PlayFromObject(obj, SFXdn_hightop_hurt1);
        *(u8 *)((char *)state + 0x356) |= 1;
    }
    if ((*(u8 *)((char *)state + 0x356) & 2) == 0 &&
        *(f32 *)((char *)obj + 0x98) > lbl_803E7F18) {
        Sfx_PlayFromObject(obj, audioPickSoundEffect_8006ed24(*(u8 *)((char *)inner + 0x86c),
                                                              *(u8 *)((char *)inner + 0x8a5)));
        *(u8 *)((char *)state + 0x356) |= 2;
    }
    if (*(s8 *)((char *)state + 0x346) != 0) {
        *(int *)((char *)state + 0x308) = (int)fn_8029C8C8;
        return 0x25;
    }
    if (*(f32 *)((char *)obj + 0x98) > lbl_803E7F1C) {
        if (*(u8 *)((char *)state + 0x349) != 1) {
            if (lbl_803DE44C != 0 && ((ByteFlags *)((char *)inner + 0x3f4))->b40) {
                *(u8 *)((char *)inner + 0x8b4) = 0;
                ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 0;
            }
            *(int *)((char *)state + 0x308) = (int)fn_802A514C;
            return -1;
        }
        r = fn_80299E44(obj, state, fv);
        if (r != 0) {
            return r;
        }
        return 0;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void Lightfoot_UpdatePlayerInteraction(int obj, int inner, int state)
{
    int p = *(int *)((char *)inner + 0x40c);
    int sub = *(int *)((char *)obj + 0x4c);
    int mode;
    int v;

    (*(void (*)(int, int, int, void *, void *, void *))(*(int *)(*gBaddieControlInterface + 0x14)))(
        obj, Obj_GetPlayerObject(), 0x10,
        (char *)p + 0x1e, (char *)p + 0x20, (char *)p + 0x22);
    *(f32 *)((char *)state + 0x2c0) = (f32)(u32)*(u16 *)((char *)p + 0x22);
    mode = *(int *)((char *)obj + 0xf8);
    if (mode == 2) {
        (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(0, obj, -1);
        *(int *)((char *)obj + 0xf8) = 1;
    } else if (mode == 3) {
        (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(1, obj, -1);
        *(int *)((char *)obj + 0xf8) = 1;
    } else {
        characterDoEyeAnims(obj, inner + 0x3ac);
        *(int *)((char *)state + 0x2d0) = Obj_GetPlayerObject();
        v = *(int *)((char *)sub + 0x14);
        if (v >= 0x49942 || v < 0x4993f) {
            (*(void (*)(int, int, f32, int))(*(int *)(*gBaddieControlInterface + 0x2c)))(
                obj, state, lbl_803E820C, 1);
        }
        *(int *)((char *)inner + 0x3e0) = *(int *)((char *)obj + 0xc0);
        *(int *)((char *)obj + 0xc0) = 0;
        (*(void (*)(int, int, f32, f32, void *, void *))(*(int *)(*gPlayerInterface + 0x8)))(
            obj, state, timeDelta, timeDelta, lbl_803DB0DC, lbl_803DB0D0);
        *(int *)((char *)obj + 0xc0) = *(int *)((char *)inner + 0x3e0);
        Lightfoot_ProcessHitResponseFlags(obj, inner);
    }
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802B4C18(int obj, int state, f32 fv)
{
    u8 buf[0x40];

    *(f32 *)((char *)state + 0x2a4) = lbl_803E7EB4;
    *(f32 *)((char *)state + 0x290) = *(f32 *)((char *)state + 0x6dc);
    *(f32 *)((char *)state + 0x28c) = *(f32 *)((char *)state + 0x6d8);
    *(int *)((char *)state + 0x31c) = *(u16 *)((char *)state + 0x6e2);
    *(int *)((char *)state + 0x318) = *(u16 *)((char *)state + 0x6e0);
    *(u8 *)((char *)*(int *)((char *)obj + 0x54) + 0x6e) = 0;
    *(u8 *)((char *)*(int *)((char *)obj + 0x54) + 0x6f) = 0;
    *(u8 *)((char *)*(int *)((char *)obj + 0x54) + 0x6c) = 0;
    *(u8 *)((char *)*(int *)((char *)obj + 0x54) + 0x6d) = 0;
    *(u8 *)((char *)state + 0x25f) = 1;
    *(u32 *)((char *)state + 0x4) &= ~0x8100000;
    playerShadowFn_80062a30(obj);
    *(u8 *)((char *)state + 0x8c5) = 0;
    *(int *)((char *)state + 0x360) &= ~0x2000;
    *(int *)state |= 0x1000000;
    fn_802B0EA4(obj, state, state);
    if (fn_802A74A4(obj, state, state, buf, fv, 0x60) == 8) {
        *(int *)((char *)state + 0x2d0) = 0;
        *(u8 *)((char *)state + 0x349) = 0;
        (*(void (*)(int))(*(int *)(*gCameraInterface + 0x48)))(0);
        if (lbl_803DE44C != 0 && ((ByteFlags *)((char *)state + 0x3f4))->b40) {
            *(u8 *)((char *)state + 0x8b4) = 1;
            ((ByteFlags *)((char *)state + 0x3f4))->b08 = 1;
        }
        (*(void (*)(int, int, int))(*(int *)(*gPlayerInterface + 0x14)))(obj, state, 0xa);
        *(int *)((char *)state + 0x304) = 0;
    }
    (*(void (*)(int, int, f32, f32, int *, int *))(*(int *)(*gPlayerInterface + 0x8)))(
        obj, state, fv, fv, lbl_803DAFC8, &lbl_803DE4B8);
    *(int *)state &= ~0x1000000;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802AC32C(int p1, int p2, int p3)
{
    void *near;
    int angle1;
    int angle2;

    near = (void *)fn_802AB1D0(p1);
    if (near != NULL && ((ByteFlags *)((char *)p3 + 0x3f0))->b80 == 0 &&
        ((ByteFlags *)((char *)p3 + 0x3f0))->b40 == 0) {
        s16 cd = *(s16 *)((char *)p3 + 0x4a0) - 1;
        f32 ratio;
        f32 clamped;
        f32 f5;
        f32 fdelta;
        f32 result;
        int delta;

        *(s16 *)((char *)p3 + 0x4a0) = cd;
        if (cd <= 0) {
            *(s16 *)((char *)p3 + 0x4a0) = (s16)randomGetRange(0x78, 0xf0);
            *(s16 *)((char *)p3 + 0x4a2) = (s16)randomGetRange(0, 0x28);
        }
        delta = (u16)getAngle(-(*(f32 *)((char *)near + 0xc) - *(f32 *)((char *)p1 + 0xc)),
                              -(*(f32 *)((char *)near + 0x14) - *(f32 *)((char *)p1 + 0x14))) -
                (u16)*(s16 *)((char *)p3 + 0x478);
        if (delta > 0x8000) {
            delta -= 0xFFFF;
        }
        if (delta < -0x8000) {
            delta += 0xFFFF;
        }
        ratio = lbl_803E7EE0 - (*(f32 *)((char *)p2 + 0x294) - lbl_803E7E9C) /
                                   (*(f32 *)((char *)p3 + 0x404) - lbl_803E7E9C);
        if (ratio < lbl_803E7EA4) {
            clamped = lbl_803E7EA4;
        } else if (ratio > lbl_803E7EE0) {
            clamped = lbl_803E7EE0;
        } else {
            clamped = ratio;
        }
        f5 = lbl_803E80C4 * clamped + lbl_803E80F4;
        fdelta = (f32)delta;
        if (fdelta < lbl_803E80F8 * -f5) {
            result = lbl_803E80F8 * -f5;
        } else if (fdelta > lbl_803E80F8 * f5) {
            result = lbl_803E80F8 * f5;
        } else {
            result = fdelta;
        }
        angle1 = (int)result;
    } else {
        angle1 = 0;
        *(s16 *)((char *)p3 + 0x4a0) = 0;
    }

    {
        int v480;
        if (((ByteFlags *)((char *)p3 + 0x3f1))->b20) {
            v480 = 0;
        } else {
            v480 = *(int *)((char *)p3 + 0x480);
        }
        if (v480 < -0x28) {
            v480 = -0x28;
        } else if (v480 > 0x28) {
            v480 = 0x28;
        }
        angle1 += v480 * 0xb6;
    }
    angle1 -= (u16)*(s16 *)((char *)p3 + 0x4d4);
    if (angle1 > 0x8000) {
        angle1 -= 0xFFFF;
    }
    if (angle1 < -0x8000) {
        angle1 += 0xFFFF;
    }
    angle1 = (int)((f32)angle1 * lbl_803E7EB4);
    if (angle1 < -0x16c) {
        angle1 = -0x16c;
    } else if (angle1 > 0x16c) {
        angle1 = 0x16c;
    }
    *(s16 *)((char *)p3 + 0x4d4) =
        (int)((f32)angle1 * timeDelta + (f32)*(s16 *)((char *)p3 + 0x4d4));
    *(s16 *)((char *)p3 + 0x4d2) = (s16)(*(s16 *)((char *)p3 + 0x4d4) / 2);

    angle2 = *(s16 *)((char *)p3 + 0x478) - (u16)*(s16 *)((char *)p3 + 0x492);
    if (angle2 > 0x8000) {
        angle2 -= 0xFFFF;
    }
    if (angle2 < -0x8000) {
        angle2 += 0xFFFF;
    }
    if (((ByteFlags *)((char *)p3 + 0x3f1))->b20) {
        angle2 = 0;
    }
    {
        f32 f2 = lbl_803E7E98 * (*(f32 *)((char *)p2 + 0x294) - lbl_803E7E9C) + lbl_803E7EE0;
        if (f2 < lbl_803E7EA4) {
            f2 = lbl_803E7EA4;
        }
        angle2 = (int)((f32)angle2 * (lbl_803E7FC4 * f2));
    }
    if (angle2 < -0xccc) {
        angle2 = -0xccc;
    } else if (angle2 > 0xccc) {
        angle2 = 0xccc;
    }
    angle2 -= (u16)*(s16 *)((char *)p3 + 0x4d0);
    if (angle2 > 0x8000) {
        angle2 -= 0xFFFF;
    }
    if (angle2 < -0x8000) {
        angle2 += 0xFFFF;
    }
    *(s16 *)((char *)p3 + 0x4d0) =
        (int)((f32)*(s16 *)((char *)p3 + 0x4d0) +
              interpolate((f32)angle2, lbl_803E7EB4, timeDelta));
    *(s16 *)((char *)p3 + 0x4d6) =
        (int)((f32)*(s16 *)((char *)p3 + 0x4d6) *
              powfBitEstimate(lbl_803E7F1C, timeDelta));
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int Lightfoot_SeqFn(int p1, int p2, int p3)
{
    int obj = p1;
    int inner = *(int *)((char *)obj + 0xb8);
    int iv6 = *(int *)((char *)obj + 0x4c);
    int t;
    int mode;
    u8 i;
    u8 j;
    f32 f31v;
    f32 z;
    f32 local_58;
    f32 local_54;
    f32 local_50;
    f32 arr[6];

    t = *(int *)((char *)inner + 0x40c);
    z = lbl_803E8180;
    if (*(f32 *)((char *)t + 0x10) != z &&
        (*(f32 *)((char *)t + 0x10) = *(f32 *)((char *)t + 0x10) - timeDelta,
         *(f32 *)((char *)t + 0x10) <= z)) {
        Obj_FreeObject(obj);
    }
    for (i = 0; i < *(u8 *)((char *)p3 + 0x8b); i++) {
        if (*(u8 *)((char *)p3 + i + 0x81) == 1) {
            *(u8 *)((char *)inner + 0x404) = *(u8 *)((char *)inner + 0x404) | 1;
            GameBit_Set(*(s16 *)((char *)iv6 + 0x1c), 1);
            arr[3] = lbl_803E8180;
            arr[4] = lbl_803E81C4;
            arr[5] = lbl_803E8180;
            f31v = lbl_803E8210;
            for (j = 0x19; j != 0; j--) {
                fn_80098B18(f31v * *(f32 *)((char *)obj + 8), obj, 3, 0, 0, arr);
            }
        }
    }
    if (*(s16 *)((char *)iv6 + 0x1a) == 0x64c) {
        Lightfoot_UpdatePlayerInteraction(obj, inner, inner);
        if ((*(u8 *)((char *)inner + 0x404) & 1) != 0 &&
            (*(u16 *)((char *)obj + 0xb0) & 0x800) != 0) {
            t = *(int *)((char *)inner + 0x40c);
            *(f32 *)((char *)t + 0xc) = *(f32 *)((char *)t + 0xc) - timeDelta;
            if (lbl_803E8180 < *(f32 *)((char *)t + 0xc)) {
                mode = 0;
            } else {
                mode = 3;
                *(f32 *)((char *)t + 0xc) = *(f32 *)((char *)t + 0xc) + lbl_803E81C0;
            }
            local_58 = lbl_803E8180;
            local_54 = lbl_803E81C4;
            local_50 = lbl_803E8180;
            Sfx_KeepAliveLoopedObjectSound(obj, 0x455);
            fn_80098B18(lbl_803E81C8 * *(f32 *)((char *)obj + 8), obj, 3, mode, 0, &local_58);
        }
    }
    *(u16 *)((char *)inner + 0x400) = *(u16 *)((char *)inner + 0x400) | 2;
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void objLoadPlayerFromSave(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int pc;
    int me;
    int off;
    int i;
    s16 *gb;
    f32 fz;

    lbl_803DE459 = 0;
    ObjGroup_AddObject(obj, 0);
    ObjGroup_AddObject(obj, 0x25);
    objSetSlot(obj, 0x3c);
    ObjMsg_AllocQueue(obj, 0x14);
    *(int *)((char *)obj + 0xbc) = (int)player_SeqFn;
    *(int *)((char *)obj + 0x4c) = 0;
    *(int *)((char *)inner + 0x7f8) = 0;
    *(int *)((char *)inner + 0x35c) =
        (*(int (*)(int))(*(int *)(*gMapEventInterface + 0x8c)))(*gMapEventInterface);
    *(u16 *)((char *)inner + 0x81a) =
        (u8)(*(int (*)(int))(*(int *)(*gMapEventInterface + 0x74)))(*gMapEventInterface);
    Obj_SetActiveModelIndex(obj, *(s16 *)((char *)inner + 0x81a));
    me = (*(int (*)(int))(*(int *)(*gMapEventInterface + 0x90)))(*gMapEventInterface);
    *(s16 *)((char *)obj + 0) = (s16)(*(s8 *)((char *)me + 0xc) << 8);
    *(s16 *)((char *)inner + 0x478) = *(s16 *)((char *)obj + 0);
    *(s16 *)((char *)inner + 0x484) = *(s16 *)((char *)obj + 0);
    *(int *)((char *)inner + 0x494) = *(s16 *)((char *)obj + 0);
    fz = lbl_803E7EE0;
    *(f32 *)((char *)inner + 0x77c) = fz;
    *(s16 *)((char *)inner + 0x80c) = -1;
    *(s16 *)((char *)inner + 0x80a) = -1;
    *(f32 *)((char *)inner + 0x82c) = fz;
    *(f32 *)((char *)inner + 0x834) = fz;
    *(f32 *)((char *)inner + 0x830) = lbl_803E8144;
    ((ByteFlags *)((char *)inner + 0x3f1))->b01 = 1;
    *(f32 *)((char *)inner + 0x880) = lbl_803E7FA4;
    *(u8 *)((char *)inner + 0x8a3) = 3;
    *(u8 *)((char *)inner + 0x8a4) = 4;
    *(u8 *)((char *)inner + 0x8a5) = 5;
    *(u8 *)((char *)inner + 0x8a7) = 6;
    *(u8 *)((char *)inner + 0x8a6) = *(u8 *)((char *)inner + 0x8a3);
    *(u8 *)((char *)inner + 0x8bf) = 0;
    (*(void (*)(int, int, int, int))(*(int *)(*gPlayerInterface + 0x4)))(obj, inner, 0x42, 1);
    *(int *)((char *)inner + 0x27c) = inner + 0x6f0;
    pc = inner + 0x4;
    (*(void (*)(int, int, int, int))(*(int *)(*gPathControlInterface + 0x4)))(pc, 1, 0x400a7, 1);
    (*(void (*)(int, int, int, int, int))(*(int *)(*gPathControlInterface + 0x8)))(
        pc, 1, (int)((char *)lbl_80332EC0 + 0x130), (int)&lbl_803DC6C0, 1);
    (*(void (*)(int, int, int, int, int))(*(int *)(*gPathControlInterface + 0xc)))(
        pc, 2, (int)((char *)lbl_80332EC0 + 0x118), (int)lbl_803DC6B8, (int)&lbl_803DC6A4);
    *(u8 *)((char *)pc + 0x258) = 0x64;
    fn_802AB5A4(obj, inner, 0xff);
    *(s16 *)((char *)*(int *)((char *)obj + 0x54) + 0xb2) = 0x29;
    *(u8 *)((char *)obj + 0x36) = 0xff;
    if (*(int *)((char *)obj + 0x64) != 0) {
        *(int *)(*(int *)((char *)obj + 0x64) + 0x30) |= 0x4008;
    }
    (*(void (*)(int))(*(int *)(*gGameUIInterface + 0x14)))(*gGameUIInterface);
    lbl_803DE444 = NULL;
    ((ByteFlags *)((char *)inner + 0x3f4))->b40 = 1;
    *(int *)((char *)inner + 0x3f8) = (int)((char *)lbl_80332EC0 + 0x190);
    *(int *)((char *)inner + 0x3dc) = (int)((char *)lbl_80332EC0 + 0x854);
    *(u8 *)((char *)inner + 0x8a8) = 0x1c;
    *(int *)((char *)inner + 0x450) = (int)((char *)lbl_80332EC0 + 0x450);
    *(u8 *)((char *)inner + 0x8d0) = 0x29;
    *(int *)((char *)inner + 0x454) = (int)((char *)lbl_80332EC0 + 0x4f4);
    *(u8 *)((char *)inner + 0x8d1) = 0x29;
    *(int *)((char *)inner + 0x458) = (int)((char *)lbl_80332EC0 + 0x598);
    *(u8 *)((char *)inner + 0x8d2) = 0x2e;
    *(int *)((char *)inner + 0x45c) = (int)((char *)lbl_80332EC0 + 0x650);
    *(u8 *)((char *)inner + 0x8d3) = 0x29;
    *(int *)((char *)inner + 0x460) = (int)((char *)lbl_80332EC0 + 0x6f4);
    *(u8 *)((char *)inner + 0x8d4) = 0x2e;
    *(f32 *)((char *)inner + 0x7e0) = lbl_803E7ED8;
    off = 0;
    for (i = 0; i < *(u8 *)((char *)inner + 0x8a8); i++) {
        int da;
        *(int *)(*(int *)((char *)inner + 0x3dc) + off + 0x64) = (int)mmAlloc(0x800, 0x1a, 0);
        da = *(int *)((char *)inner + 0x3dc) + off;
        objGetWeaponDa(obj, *(s16 *)((char *)obj + 0x46), da + 0x60,
                       *(s16 *)((char *)lbl_80332EC0 + 0x7fc +
                                *(s16 *)((char *)da + 0x2) * 2),
                       0);
        off += 0xb0;
    }
    fn_802AABE4(obj);
    lbl_803DE4B2 = 0x2d;
    lbl_803DE448 = 0;
    gb = (s16 *)((char *)lbl_80332EC0 + 0x1b94);
    for (i = 0; i < 0xb; i++) {
        if (GameBit_Get(*gb) != 0) {
            *(u8 *)((char *)inner + 0x8c7) =
                (u8)(*(u8 *)((char *)inner + 0x8c7) | (1 << i));
        }
        gb++;
    }
    if (*(s16 *)((char *)inner + 0x81a) == 0) {
        *(f32 *)((char *)inner + 0x7dc) = lbl_803E8168;
        *(f32 *)((char *)inner + 0x874) = lbl_803E816C;
    } else {
        *(f32 *)((char *)inner + 0x7dc) = lbl_803E8170;
        *(f32 *)((char *)inner + 0x874) = lbl_803E8174;
    }
    lbl_803DE420 = allocModelStruct2((int)&lbl_803DC668, 1);
    *(int *)((char *)obj + 0x108) = (int)fn_8029560C;
    if (lbl_803DE424 != 0) {
        int v = lbl_803DE424;
        int hi;
        if (v < 0) {
            v = 0;
        } else if (v > 0x50) {
            v = 0x50;
        }
        *(s8 *)(*(int *)((char *)inner + 0x35c) + 1) = (s8)v;
        v = lbl_803DE424;
        if (v < 0) {
            v = 0;
        } else {
            hi = *(s8 *)(*(int *)((char *)inner + 0x35c) + 1);
            if (v > hi) {
                v = hi;
            }
        }
        *(s8 *)(*(int *)((char *)inner + 0x35c) + 0) = (s8)v;
        lbl_803DE424 = 0;
    }
    lbl_803DE428 = 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802AB1D0(int obj)
{
    int objs;
    int i;
    int count;
    int best;
    int cur;
    f32 dist;
    f32 bestDist;
    f32 scale;
    s16 yaw;
    void *held;

    if (*(u16 *)((char *)obj + 0xb0) & 0x1000) {
        return 0;
    }
    held = *(void **)((char *)*(int *)((char *)obj + 0xb8) + 0x2d0);
    if (held != NULL) {
        return (int)held;
    }
    best = 0;
    objs = (int)ObjGroup_GetObjects(8, &count);
    bestDist = lbl_803E7EA4;
    for (i = 0; i < count; i++) {
        cur = ((int *)objs)[i];
        if ((*(s16 *)((char *)cur + 0x44) == 0x1c || *(s16 *)((char *)cur + 0x44) == 0x2a) &&
            *(u8 *)((char *)cur + 0x36) == 0xff) {
            f32 dx = *(f32 *)((char *)cur + 0x18) - *(f32 *)((char *)obj + 0x18);
            f32 dy = *(f32 *)((char *)cur + 0x1c) - *(f32 *)((char *)obj + 0x1c);
            f32 dz = *(f32 *)((char *)cur + 0x20) - *(f32 *)((char *)obj + 0x20);
            dist = dx * dx + dy * dy + dz * dz;
            if (dist < lbl_803E80E8) {
                if (dist <= lbl_803E7EA4) {
                    scale = (f32)*(s8 *)((char *)*(int *)((char *)cur + 0x50) + 0x56);
                    if (scale <= lbl_803E7EA4) {
                        scale = lbl_803E7EE0;
                    }
                    dist = sqrtf(dist) / scale;
                }
                yaw = Obj_GetYawDeltaToObject(obj, cur, 0);
                if (yaw < 0x5555 && yaw > -0x5555) {
                    if (dist < bestDist || lbl_803E7EA4 == bestDist) {
                        bestDist = dist;
                        best = cur;
                    }
                }
            }
        }
    }
    return best;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802AE480(int obj, int inner, int state)
{
    f32 h;
    f32 lim;

    *(int *)((char *)inner + 0x360) |= 0x1000000;
    *(f32 *)((char *)state + 0x2a0) = lbl_803E7F20;
    h = *(f32 *)((char *)obj + 0x98);
    if (h > lbl_803E7EFC && h < lbl_803E7F44 &&
        *(f32 *)((char *)state + 0x294) >
            *(f32 *)((char *)*(int *)((char *)inner + 0x400) + 0x1c) - lbl_803E7E9C &&
        *(f32 *)((char *)state + 0x298) > lbl_803E7F2C &&
        *(int *)((char *)inner + 0x488) >= 0x96) {
        ((ByteFlags *)((char *)inner + 0x3f0))->b40 = 1;
        ((ByteFlags *)((char *)inner + 0x3f0))->b80 = 0;
        *(u8 *)((char *)inner + 0x8a6) = *(u8 *)((char *)inner + 0x8a7);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E8070;
        ObjAnim_SetCurrentMove(obj, *(s16 *)((char *)*(int *)((char *)inner + 0x3f8) + 0x3a),
                               lbl_803E7EA4, 0);
        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent *)obj, 0x10);
        *(int *)((char *)inner + 0x858) = *(s16 *)((char *)inner + 0x484);
        *(f32 *)((char *)inner + 0x844) =
            (lbl_803E7F14 + (*(f32 *)((char *)*(int *)((char *)inner + 0x400) + 0x14) +
                             *(f32 *)((char *)state + 0x294))) / lbl_803E7F30;
        *(s16 *)((char *)inner + 0x478) = *(s16 *)((char *)inner + 0x484);
        *(s16 *)((char *)inner + 0x484) = *(s16 *)((char *)inner + 0x484) + 0x8000;
        *(f32 *)((char *)state + 0x294) = -*(f32 *)((char *)state + 0x294);
        *(f32 *)((char *)state + 0x280) = -*(f32 *)((char *)state + 0x280);
    }
    if (((ByteFlags *)((char *)inner + 0x3f0))->b80) {
        if (*(f32 *)((char *)state + 0x294) <=
                (lim = *(f32 *)((char *)*(int *)((char *)inner + 0x400) + 0x10)) &&
            *(f32 *)((char *)state + 0x280) <= lim) {
            *(int *)((char *)inner + 0x494) = *(s16 *)((char *)inner + 0x484);
            ((ByteFlags *)((char *)inner + 0x3f0))->b40 = 0;
            ((ByteFlags *)((char *)inner + 0x3f0))->b80 = 0;
            return 1;
        }
        *(f32 *)((char *)inner + 0x408) = lbl_803E7EA4;
        *(f32 *)((char *)inner + 0x438) = *(f32 *)((char *)inner + 0x830);
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void fn_80295E90(int obj, int mode)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int oldModel;
    int newModel;
    void *tricky;

    objModelGetVecFn_800395d8(obj, 0);
    objModelGetVecFn_800395d8(obj, 9);
    if (mode != 0) {
        fn_80295CF4(obj, 0);
        ((ByteFlags *)((char *)inner + 0x3f3))->b08 = 1;
        tricky = getTrickyObject();
        if (tricky != NULL) {
            trickyImpress(tricky);
        }
        GameBit_Set(0xc30, 1);
        Sfx_PlayFromObject(obj, SFXmn_dimbos36);
        (*(void (*)(int, int, int, int, int))(*(int *)(*lbl_803DCAB4 + 0xc)))(obj, 0x801, 0, 0x50, 0);
        oldModel = Obj_GetActiveModel(obj);
        Obj_SetActiveModelIndex(obj, 2);
        newModel = Obj_GetActiveModel(obj);
        memcpy((void *)*(int *)((char *)newModel + 0x2c), (void *)*(int *)((char *)oldModel + 0x2c), 0x68);
        memcpy((void *)*(int *)((char *)newModel + 0x30), (void *)*(int *)((char *)oldModel + 0x30), 0x68);
        if (mode == 2) {
            ((ByteFlags *)((char *)inner + 0x3f4))->b80 = 1;
        }
    } else {
        fn_80295CF4(obj, 1);
        ((ByteFlags *)((char *)inner + 0x3f3))->b08 = 0;
        ((ByteFlags *)((char *)inner + 0x3f4))->b80 = 0;
        (*(void (*)(int, int, int, int, int))(*(int *)(*lbl_803DCAB4 + 0xc)))(obj, 0x801, 0, 0x50, 0);
        oldModel = Obj_GetActiveModel(obj);
        Obj_SetActiveModelIndex(obj, 1);
        newModel = Obj_GetActiveModel(obj);
        memcpy((void *)*(int *)((char *)newModel + 0x2c), (void *)*(int *)((char *)oldModel + 0x2c), 0x68);
        memcpy((void *)*(int *)((char *)newModel + 0x30), (void *)*(int *)((char *)oldModel + 0x30), 0x68);
        GameBit_Set(0xc30, 0);
        Sfx_PlayFromObject(obj, SFXmn_dimbos36);
    }
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802AF7F8(int obj, int state)
{
    int inner;
    u8 result;
    int r35c;
    void **p;
    int i;
    int v;
    if (fn_802A9C0C(obj, state, 0x2d) != 0) {
        GameBit_Set(0x965, 0);
        GameBit_Set(0x986, 0);
    } else {
        GameBit_Set(0x965, 1);
        GameBit_Set(0x986, 1);
    }
    if (fn_802A9C0C(obj, state, 0x5ce) != 0) {
        GameBit_Set(0x961, 0);
    } else {
        GameBit_Set(0x961, 1);
    }
    inner = *(int *)((char *)obj + 0xb8);
    if (*(void **)((char *)state + 0x2d0) != NULL ||
        *(s16 *)(*(int *)((char *)inner + 0x35c) + 4) < 0xa ||
        ((ByteFlags *)((char *)inner + 0x3f3))->b08 != 0) {
        result = 0;
    } else if (*(s16 *)((char *)state + 0x274) == 1 || *(s16 *)((char *)state + 0x274) == 2) {
        result = 1;
    } else {
        result = 0;
    }
    if (result != 0) {
        GameBit_Set(0x969, 0);
    } else {
        GameBit_Set(0x969, 1);
    }
    if (fn_802A98FC(obj, state) != 0) {
        GameBit_Set(0x960, 0);
    } else {
        GameBit_Set(0x960, 1);
    }
    if (fn_802A97D0(obj, state) != 0) {
        GameBit_Set(0x964, 0);
    } else {
        GameBit_Set(0x964, 1);
    }
    if (fn_802A9A0C(obj, state) != 0) {
        GameBit_Set(0x96b, 0);
    } else {
        GameBit_Set(0x96b, 1);
    }
    switch (*(s16 *)((char *)state + 0x80a)) {
    case 0x2d:
        break;
    case 0x40:
        if ((getButtonsJustPressed(0) & 0x200) != 0 &&
            ((ByteFlags *)((char *)state + 0x3f3))->b08 != 0 &&
            *(u8 *)((char *)state + 0x8c8) != 0x44) {
            fn_80295E90(obj, 0);
            *(s16 *)((char *)state + 0x80a) = -1;
            *(s16 *)((char *)state + 0x80c) = -1;
            buttonDisable(0, 0x200);
        }
        *(f32 *)((char *)state + 0x854) = *(f32 *)((char *)state + 0x854) - timeDelta;
        if (*(f32 *)((char *)state + 0x854) <= lbl_803E7EA4) {
            r35c = *(int *)((char *)*(int *)((char *)obj + 0xb8) + 0x35c);
            v = *(s16 *)((char *)r35c + 4);
            if (v < 0) {
                v = 0;
            } else if (v > *(s16 *)((char *)r35c + 6)) {
                v = *(s16 *)((char *)r35c + 6);
            }
            *(s16 *)((char *)r35c + 4) = v;
            *(f32 *)((char *)state + 0x854) = lbl_803E7EDC;
        }
        break;
    case 0x5ce:
        if (lbl_803DE42C != 0 && getCurSeqNo() != 0) {
            *(s16 *)((char *)state + 0x80a) = -1;
            lbl_803DE42C = 0;
            p = lbl_80332ED4;
            for (i = 0; i < 7; i++) {
                if (*p != NULL) {
                    Obj_FreeObject((int)*p);
                    *p = NULL;
                }
                p++;
            }
            if (lbl_803DE454 != NULL) {
                Resource_Release(lbl_803DE454);
                lbl_803DE454 = NULL;
            }
        }
        break;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802A14F8(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);
    f32 k;
    f32 pos[2];

    *(int *)((char *)inner + 0x360) &= ~2;
    *(int *)((char *)inner + 0x360) |= 0x2000;
    *(int *)((char *)state + 0x4) |= 0x100000;
    k = lbl_803E7EA4;
    *(f32 *)((char *)state + 0x280) = k;
    *(f32 *)((char *)state + 0x284) = k;
    *(int *)state |= 0x200000;
    *(f32 *)((char *)obj + 0x24) = k;
    *(f32 *)((char *)obj + 0x2c) = k;
    *(int *)((char *)state + 0x4) |= 0x8000000;
    *(f32 *)((char *)obj + 0x28) = k;
    if (*(s8 *)((char *)state + 0x27a) != 0 && lbl_803DE44C != 0 &&
        ((ByteFlags *)((char *)inner + 0x3f4))->b40) {
        *(u8 *)((char *)inner + 0x8b4) = 1;
        ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 1;
    }
    if (*(s16 *)((char *)obj + 0xa0) == 0x41a) {
        if (*(s8 *)((char *)state + 0x346) != 0) {
            fn_802AB5A4(obj, inner + 4, 5);
            *(int *)((char *)state + 0x308) = (int)fn_8029FFD0;
            return -0x13;
        }
    } else {
        pos[0] = *(f32 *)((char *)inner + 0x54c);
        pos[1] = *(f32 *)((char *)inner + 0x550);
        if (*(u8 *)((char *)inner + 0x8c8) != 0x48 && *(u8 *)((char *)inner + 0x8c8) != 0x47) {
            (*(void (*)(int, int, int, int, void *, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
                0x4b, 1, 1, 8, pos, 0, 0xff);
        }
        ObjAnim_SetCurrentMove(obj, 0x41a, lbl_803E7EA4, 1);
        *(s16 *)((char *)inner + 0x478) =
            getAngle(*(f32 *)((char *)inner + 0x56c), *(f32 *)((char *)inner + 0x574));
        *(s16 *)((char *)inner + 0x484) = *(s16 *)((char *)inner + 0x478);
        *(f32 *)((char *)obj + 0xc) = *(f32 *)((char *)inner + 0x58c);
        *(f32 *)((char *)obj + 0x10) = *(f32 *)((char *)inner + 0x76c);
        *(f32 *)((char *)obj + 0x14) = *(f32 *)((char *)inner + 0x594);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E800C;
    }
    fn_802AB5A4(obj, inner + 4, 5);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802972B4(int obj, int *flags, f32 *p5, f32 *p6, f32 *p7, s16 *p8)
{
    int inner = *(int *)((char *)obj + 0xb8);
    s8 idx;
    u8 mode;
    f32 zero;

    *flags = 0;
    zero = lbl_803E7EA4;
    *p5 = zero;
    *p6 = zero;
    *p7 = zero;
    if (*(s16 *)((char *)inner + 0x274) == 0x26) {
        *flags |= 1;
        idx = *(s8 *)((char *)inner + 0x8ce);
        if (idx != -1) {
            *flags |= ((EmitElem *)(*(int *)((char *)inner + 0x3dc) +
                                    *(u8 *)((char *)inner + 0x8a9) * 0xb0))->a8[idx];
            *p6 = ((EmitElem *)(*(int *)((char *)inner + 0x3dc) +
                                *(u8 *)((char *)inner + 0x8a9) * 0xb0))
                      ->a70[*(s8 *)((char *)inner + 0x8ce)];
            *p7 = ((EmitElem *)(*(int *)((char *)inner + 0x3dc) +
                                *(u8 *)((char *)inner + 0x8a9) * 0xb0))
                      ->a7c[*(s8 *)((char *)inner + 0x8ce)];
            *p5 = ((EmitElem *)(*(int *)((char *)inner + 0x3dc) +
                                *(u8 *)((char *)inner + 0x8a9) * 0xb0))
                      ->a94[*(s8 *)((char *)inner + 0x8ce)];
        }
        if (*(u8 *)(*(int *)((char *)inner + 0x3dc) +
                    *(u8 *)((char *)inner + 0x8a9) * 0xb0 + 0x88) & 2) {
            if (*(u8 *)((char *)inner + 0x8ab) < *(u8 *)((char *)inner + 0x8ac)) {
                *p6 = lbl_803E7EA4;
                *p7 = lbl_803E7EA4;
            }
        }
        if ((*(u8 *)(*(int *)((char *)inner + 0x3dc) +
                     *(u8 *)((char *)inner + 0x8a9) * 0xb0 + 0x88) & 1) &&
            *(f32 *)((char *)inner + 0x820) >= lbl_803E7EF0) {
            *flags |= 0x80;
        }
    }
    mode = *(u8 *)((char *)inner + 0x8c1);
    if (mode == 0) {
        *flags |= 0x100;
    } else if (mode == 1) {
        *flags |= 0x200;
    } else if (mode == 2) {
        *flags |= 0x400;
    }
    if (*(s16 *)((char *)inner + 0x274) == 0x2e || *(s16 *)((char *)inner + 0x274) == 0x2f) {
        *flags &= 0x7d;
        *flags |= 2;
    }
    *p8 = 0x78;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802B066C(int obj, int state)
{
    f32 v;
    f32 px;
    f32 py;
    f32 pz;

    if (*(u8 *)((char *)state + 0x86c) == 0x1a) {
        return;
    }
    if (((ByteFlags *)((char *)state + 0x3f0))->b08 == 0) {
        v = sqrtf(*(f32 *)((char *)obj + 0x2c) * *(f32 *)((char *)obj + 0x2c) +
                  *(f32 *)((char *)obj + 0x24) * *(f32 *)((char *)obj + 0x24) +
                  *(f32 *)((char *)obj + 0x28) * *(f32 *)((char *)obj + 0x28));
        *(f32 *)((char *)state + 0x7a4) = v;
        v = *(f32 *)((char *)state + 0x7a4);
        if (v < lbl_803E7EE0) {
            v = lbl_803E7EE0;
        } else if (v > lbl_803E8138) {
            v = lbl_803E8138;
        }
        *(f32 *)((char *)state + 0x7a4) = v;
    }
    *(f32 *)((char *)state + 0x79c) =
        *(f32 *)((char *)state + 0x79c) - timeDelta * *(f32 *)((char *)state + 0x7a4);
    if (*(f32 *)((char *)state + 0x79c) <= lbl_803E7EA4) {
        if (Sfx_IsPlayingFromObject(obj, 0x394)) {
            Sfx_StopFromObject(obj, 0x394);
            Sfx_PlayFromObject(obj, 0x395);
        }
        *(f32 *)((char *)state + 0x79c) = lbl_803E7EA4;
        return;
    }
    *(f32 *)((char *)state + 0x7a0) = *(f32 *)((char *)state + 0x7a0) - timeDelta;
    if (*(f32 *)((char *)state + 0x7a0) <= lbl_803E7EA4) {
        ObjPath_GetPointWorldPosition(obj, 0xb, &px, &py, &pz, 0);
        ObjHits_RecordPositionHit(px, py, pz, obj, 0, 0x1f, 1, -1);
        *(f32 *)((char *)state + 0x7a0) = lbl_803E8050;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void playerDie(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int setup;
    int variant;
    int i;
    void **p;
    cutsceneFadeInOut(1);
    setTimeStop(0xff);
    setPendingMapLoad(1);
    if ((u32)obj != 0) {
        variant = *(s8 *)((char *)obj + 0xad) != 0;
    } else {
        variant = 0;
    }
    if (variant != 0) {
        setup = Obj_AllocObjectSetup(0x20, 0x882);
    } else {
        setup = Obj_AllocObjectSetup(0x20, 0x887);
    }
    *(f32 *)((char *)setup + 0x8) = *(f32 *)((char *)obj + 0xc);
    *(f32 *)((char *)setup + 0xc) = *(f32 *)((char *)obj + 0x10);
    *(f32 *)((char *)setup + 0x10) = *(f32 *)((char *)obj + 0x14);
    *(int *)((char *)inner + 0x46c) = Obj_SetupObject(setup, 5, -1, -1, 0);
    ((ByteFlags *)((char *)inner + 0x3f3))->b04 = 0;
    ((ByteFlags *)((char *)inner + 0x3f3))->b02 = 1;
    lbl_803DE42C = 0;
    p = lbl_80332ED4;
    for (i = 0; i < 7; i++) {
        if (*p != NULL) {
            Obj_FreeObject((int)*p);
            *p = NULL;
        }
        p++;
    }
    if (lbl_803DE454 != NULL) {
        Resource_Release(lbl_803DE454);
        lbl_803DE454 = NULL;
    }
    *(int *)((char *)inner + 0x360) &= ~0x400;
    AudioStream_StopCurrent();
    AudioStream_Play(0x51e0, AudioStream_StartPrepared);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802AABE4(int obj)
{
    s16 *movp;
    f32 *outp;
    int model;
    short i;
    int inner = *(int *)((char *)obj + 0xb8);
    f32 out2[2];
    f32 out1[5];

    model = ((int *)*(int *)((char *)obj + 0x7c))[*(s8 *)((char *)obj + 0xad)];

    ObjAnim_SetCurrentMove(obj, *(s16 *)*(int *)((char *)inner + 0x3f8), lbl_803E7EA4, 0);
    ObjModel_SampleJointTransform(model, 0, 0, lbl_803E7EA4, *(f32 *)((char *)obj + 8), out1, out2);
    lbl_803DAF88[0] = out1[1];

    ObjAnim_SetCurrentMove(obj, lbl_80332F2C[0], lbl_803E7EA4, 0);
    ObjModel_SampleJointTransform(model, 0, 0, lbl_803E7EA4, *(f32 *)((char *)obj + 8), out1, out2);
    lbl_803DAF88[1] = out1[1];

    i = 12;
    movp = (s16 *)((char *)lbl_80332F48 + 0x22);
    outp = &lbl_803DAF88[i];
    for (; i <= 15; i++) {
        ObjAnim_SetCurrentMove(obj, *movp, lbl_803E7EA4, 0);
        ObjModel_SampleJointTransform(model, 0, 0, lbl_803E7EA4, *(f32 *)((char *)obj + 8), out1, out2);
        *outp = out1[1];
        movp++;
        outp++;
    }
    ObjAnim_WriteStateWord((ObjAnimComponent *)obj, OBJANIM_STATE_INDEX_CURRENT,
                           OBJANIM_STATE_WORD_EVENT_COUNTDOWN, 0);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802B4A9C(int obj, int sA, int sB)
{
    int *target = (int *)(*(int (*)(int))(*(int *)(*gCameraInterface + 0x3c)))(*gCameraInterface);
    u32 v = (*(u8 *)((char *)sA + 0x3f4) >> 6) & 1;

    if (v != 0) {
        if ((*(u32 *)((char *)sA + 0x360) & 0x10) != 0) {
            if (lbl_803DE44C != NULL && v != 0) {
                *(u8 *)((char *)sA + 0x8b4) = 2;
                ((ByteFlags *)((char *)sA + 0x3f4))->b08 = 0;
            }
            *(u8 *)((char *)sB + 0x349) = 1;
            if (target != NULL) {
                *(int **)((char *)sB + 0x2d0) = target;
            } else {
                f32 dist = lbl_803E8150;
                *(int *)((char *)sB + 0x2d0) = ObjGroup_FindNearestObject(3, obj, &dist);
            }
        } else {
            if (target != NULL) {
                if (*(int **)((char *)sB + 0x2d0) != target) {
                    *(u8 *)((char *)sB + 0x349) = 0;
                    if ((*(u8 *)((char *)*(int *)((char *)target + 0x78) + 4) & 0xf) == 1) {
                        if (lbl_803DE44C != NULL) {
                            u32 targetFlag = (*(u8 *)((char *)sA + 0x3f4) >> 6) & 1;
                            if (targetFlag != 0) {
                                *(u8 *)((char *)sA + 0x8b4) = 2;
                                ((ByteFlags *)((char *)sA + 0x3f4))->b08 = 0;
                            }
                        }
                        *(u8 *)((char *)sB + 0x349) = 1;
                    }
                }
                *(int **)((char *)sB + 0x2d0) = target;
            } else {
                *(int *)((char *)sB + 0x2d0) = 0;
                *(u8 *)((char *)sB + 0x349) = 0;
            }
        }
        if (*(int **)((char *)sB + 0x2d0) != NULL) {
            fn_8014C540(*(int *)((char *)sB + 0x2d0), (char *)sA + 0x884, (char *)sA + 0x888,
                        (char *)sA + 0x88c);
        } else {
            *(s16 *)((char *)sA + 0x80e) = -1;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_8029A5E4(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int r = ((int (*)(int, int, int))fn_802AC7DC)(obj, state, inner);
    if (r != 0) {
        return r;
    }
    setAButtonIcon(6);
    setBButtonIcon(0xa);
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        int p = *(int *)((char *)*(int *)((char *)obj + 0xb8) + 0x35c);
        int val = *(s16 *)((char *)p + 4);
        if (val < 0) {
            val = 0;
        } else {
            int hi = *(s16 *)((char *)p + 6);
            if (val > hi) {
                val = hi;
            }
        }
        *(s16 *)((char *)p + 4) = (s16)val;
        lbl_803DE45C = lbl_803E7F30;
    }
    if (lbl_803E7F30 == lbl_803DE45C || lbl_803E7FA0 == lbl_803DE45C ||
        lbl_803E7FA4 == lbl_803DE45C) {
        fn_802AA2B0(obj, state, *(f32 *)((char *)inner + 0x7bc),
                    (f32)randomGetRange(-0xc8, 0xc8) / lbl_803E7F5C);
    }
    lbl_803DE45C = lbl_803DE45C - lbl_803E7EE0;
    if (lbl_803DE45C < lbl_803E7EA4) {
        *(int *)((char *)state + 0x308) = (int)fn_8029A4A8;
        return 0x2d;
    }
    if (*(int **)((char *)state + 0x2d0) == NULL) {
        if ((*(u16 *)((char *)inner + 0x6e2) & 0x200) != 0 ||
            *(u8 *)((char *)inner + 0x8c8) != 0x52) {
            *(int *)((char *)state + 0x308) = (int)fn_8029A420;
            return 0x2c;
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_80296D20(int obj, void *arg)
{
    int state = *(int *)((char *)obj + 0xb8);
    int inner = *(int *)((char *)obj + 0xb8);
    short type;

    if (*(void **)((char *)obj + 0x30) == arg) {
        objHitDetectFn_80062e84(obj, 0, 1);
        type = *(s16 *)((char *)state + 0x274);
        if (type == 0xa || type == 0xc) {
            *(int *)((char *)state + 4) &= ~0x100000;
            fn_802AB5A4(obj, inner, 5);
            ((ByteFlags *)((char *)inner + 0x3f0))->b80 = 0;
            ((ByteFlags *)((char *)inner + 0x3f0))->b10 = 0;
            ((ByteFlags *)((char *)inner + 0x3f0))->b08 = 0;
            staffFn_80170380(lbl_803DE450, 2);
            ((ByteFlags *)((char *)inner + 0x3f0))->b02 = 0;
            *(int *)((char *)inner + 0x360) |= 0x800000;
            ObjHits_SyncObjectPositionIfDirty(obj);
            ((ByteFlags *)((char *)inner + 0x3f0))->b40 = 0;
            ((ByteFlags *)((char *)inner + 0x3f0))->b04 = 1;
            ((ByteFlags *)((char *)inner + 0x3f4))->b10 = 1;
            *(u8 *)((char *)inner + 0x800) = 0;
            if (*(void **)((char *)inner + 0x7f8) != NULL) {
                short id = *(s16 *)((char *)*(int *)((char *)inner + 0x7f8) + 0x46);
                if (id == 0x3cf || id == 0x662) {
                    objThrowFn_80182504(*(int *)((char *)inner + 0x7f8));
                } else {
                    objSaveFn_800ea774(*(int *)((char *)inner + 0x7f8));
                }
                *(s16 *)((char *)*(int *)((char *)inner + 0x7f8) + 6) &= ~0x4000;
                *(int *)((char *)*(int *)((char *)inner + 0x7f8) + 0xf8) = 0;
                *(int *)((char *)inner + 0x7f8) = 0;
            }
            (*(void (*)(int, int, int))(*(int *)(*gPlayerInterface + 0x14)))(obj, state, 2);
            *(int *)((char *)state + 0x304) = (int)fn_802A514C;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802A81B8(int obj, int state, f32 *out)
{
    f32 mag;
    u32 flag = (*(u8 *)((char *)state + 0x3f1) >> 5) & 1;

    if (flag != 0 || *(int **)((char *)state + 0x2d0) != NULL) {
        out[0] = *(f32 *)((char *)obj + 0x24);
        out[1] = lbl_803E7EA4;
        out[2] = *(f32 *)((char *)obj + 0x2c);
        mag = PSVECMag(out);
        if (mag > lbl_803E7EA4) {
            PSVECScale(out, out, lbl_803E7EE0 / mag);
        } else {
            out[0] = -fn_80293E80(lbl_803E7F94 * (f32)*(s16 *)((char *)state + 0x478) /
                                  lbl_803E7F98);
            out[1] = lbl_803E7EA4;
            out[2] = -sin(lbl_803E7F94 * (f32)*(s16 *)((char *)state + 0x478) / lbl_803E7F98);
        }
    } else {
        out[0] = -fn_80293E80(lbl_803E7F94 * (f32)*(s16 *)((char *)state + 0x478) / lbl_803E7F98);
        out[1] = lbl_803E7EA4;
        out[2] = -sin(lbl_803E7F94 * (f32)*(s16 *)((char *)state + 0x478) / lbl_803E7F98);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_8029B7B0(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int r = ((int (*)(int, int, int))fn_802AC7DC)(obj, state, inner);
    u32 b;
    if (r != 0) {
        return r;
    }
    {
        f32 z = lbl_803E7EA4;
        *(f32 *)((char *)state + 0x294) = z;
        *(f32 *)((char *)state + 0x284) = z;
        *(f32 *)((char *)state + 0x280) = z;
        *(f32 *)((char *)obj + 0x24) = z;
        *(f32 *)((char *)obj + 0x28) = z;
        *(f32 *)((char *)obj + 0x2c) = z;
    }
    setAButtonIcon(6);
    setBButtonIcon(0xa);
    switch (*(s16 *)((char *)obj + 0xa0)) {
    case 0x43d:
        if (*(s8 *)((char *)state + 0x346) != 0) {
            *(int *)((char *)state + 0x308) = (int)fn_8029A4A8;
            return 0x2d;
        }
        break;
    case 0x448:
        if (*(f32 *)((char *)obj + 0x98) > lbl_803E7E9C) {
            if (*(u8 *)((char *)inner + 0x8b3) == 0) {
                Sfx_PlayFromObject(obj, SFXen_lflsh2_b);
                if (lbl_803DE44C != NULL) {
                    b = (*(u8 *)((char *)inner + 0x3f4) >> 6) & 1;
                    if (b != 0) {
                        *(u8 *)((char *)inner + 0x8b4) = 2;
                        ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 0;
                    }
                }
            }
        }
        if (*(s8 *)((char *)state + 0x346) != 0) {
            *(int *)((char *)state + 0x308) = (int)fn_8029A4A8;
            return 0x2d;
        }
        break;
    default:
    {
        f32 z;
        ObjAnim_SetCurrentMove(obj, 0x43d, lbl_803E7EA4, 0);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7F4C;
        if (lbl_803DE44C != NULL) {
            b = (*(u8 *)((char *)inner + 0x3f4) >> 6) & 1;
            if (b != 0) {
                *(u8 *)((char *)inner + 0x8b4) = 4;
                ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 1;
            }
        }
        z = lbl_803E7EA4;
        lbl_803DE460 = z;
        lbl_803DE464 = z;
        *(f32 *)((char *)inner + 0x7bc) = z;
        *(f32 *)((char *)inner + 0x7b8) = z;
        break;
    }
    }
    if ((*(u16 *)((char *)inner + 0x6e2) & 0x200) != 0 || *(u8 *)((char *)inner + 0x8c8) != 0x52) {
        buttonDisable(0, 0x200);
        *(int *)((char *)state + 0x308) = (int)fn_8029A420;
        return 0x2c;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802B4ED8(int obj, int p2, int mode)
{
    int inner = *(int *)((char *)obj + 0xb8);
    f32 sx, sy, sz;
    u32 v;
    u32 m;

    if ((s8)p2 != -1) {
        if ((*(u32 *)((char *)inner + 0x360) & 0x4001) != 0) {
            return;
        }
    }
    v = (*(u8 *)((char *)inner + 0x3f3) >> 3) & 1;
    if (v != 0) {
        return;
    }
    if ((u32)*(u8 *)((char *)obj + 0x36) < 2) {
        return;
    }
    if (*(void **)((char *)inner + 0x7f0) != NULL) {
        if ((*(u16 *)((char *)obj + 0xb0) & 0x1000) != 0 ||
            arrayIndexOf(&lbl_803DC6C4, 2, *(s16 *)((char *)inner + 0x274)) != -1) {
            int p = *(int *)((char *)inner + 0x7f0);
            (*(void (*)(int, f32))(*(int *)((char *)*(int *)*(int *)((char *)p + 0x68) + 0x50)))(
                p, *(f32 *)((char *)*(int *)((char *)obj + 0x50) + 4));
        }
    }
    if ((*(u32 *)((char *)inner + 0x360) & 0x8000000) != 0) {
        sx = *(f32 *)((char *)obj + 0xc);
        sy = *(f32 *)((char *)obj + 0x10);
        sz = *(f32 *)((char *)obj + 0x14);
        *(f32 *)((char *)obj + 0xc) = *(f32 *)((char *)*(int *)((char *)obj + 0x64) + 0x20);
        *(f32 *)((char *)obj + 0x10) = *(f32 *)((char *)*(int *)((char *)obj + 0x64) + 0x24);
        *(f32 *)((char *)obj + 0x14) = *(f32 *)((char *)*(int *)((char *)obj + 0x64) + 0x28);
        *(f32 *)((char *)*(int *)((char *)obj + 0x64) + 0x20) = sx;
        *(f32 *)((char *)*(int *)((char *)obj + 0x64) + 0x24) = sy;
        *(f32 *)((char *)*(int *)((char *)obj + 0x64) + 0x28) = sz;
    }
    *(f32 *)((char *)obj + 0x10) =
        *(f32 *)((char *)obj + 0x10) + *(f32 *)((char *)inner + 0x7c8);
    m = (u32)(mode & 0xff);
    if (m == 1) {
        objRenderFuzz(obj);
    } else if (m == 2) {
        objRenderFn_800413d4(obj);
    } else if (m == 4) {
        fuzzRenderFn_800412dc(obj);
    }
    objSetMtxFn_800412d4(0);
    *(f32 *)((char *)obj + 0x10) =
        *(f32 *)((char *)obj + 0x10) - *(f32 *)((char *)inner + 0x7c8);
    if ((*(u32 *)((char *)inner + 0x360) & 0x8000000) != 0) {
        *(f32 *)((char *)*(int *)((char *)obj + 0x64) + 0x20) = *(f32 *)((char *)obj + 0xc);
        *(f32 *)((char *)*(int *)((char *)obj + 0x64) + 0x24) = *(f32 *)((char *)obj + 0x10);
        *(f32 *)((char *)*(int *)((char *)obj + 0x64) + 0x28) = *(f32 *)((char *)obj + 0x14);
        *(f32 *)((char *)obj + 0xc) = sx;
        *(f32 *)((char *)obj + 0x10) = sy;
        *(f32 *)((char *)obj + 0x14) = sz;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void fn_802AA8D0(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    struct {
        u8 pad[0xc];
        f32 x;
        f32 y;
        f32 z;
    } buf;
    f32 base = lbl_803E80C4;
    f32 dy;
    int i;

    dy = base - *(f32 *)((char *)inner + 0x7d0);
    buf.y = dy;
    if (lbl_803DE478 < lbl_803E80D8) {
        *(u8 *)((char *)inner + 0x8ca) = 0;
        return;
    }
    if (dy <= lbl_803E7EA4) {
        lbl_803DE478 = lbl_803DE478 - lbl_803E7F14 * timeDelta;
        return;
    }
    lbl_803DE478 = base;
    buf.y = dy + *(f32 *)((char *)obj + 0x10);
    for (i = 0; i < 10; i++) {
        buf.x = *(f32 *)((char *)obj + 0xc) + (f32)randomGetRange(-0x64, 0x64) / lbl_803E7ED8;
        buf.z = *(f32 *)((char *)obj + 0x14) + (f32)randomGetRange(-0x64, 0x64) / lbl_803E7ED8;
        (**(void (**)(int, int, void *, int, int, int))((char *)(*gPartfxInterface) + 0x8))(
            obj, randomGetRange(0, 2) + 0x3f4, &buf, 1, -1, 0);
        (**(void (**)(int, int, void *, int, int, int))((char *)(*gPartfxInterface) + 0x8))(
            obj, randomGetRange(0, 2) + 0x3f7, &buf, 1, -1, 0);
    }
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_8029C9C8(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);
    f32 ratio, c, s, vx, vy, t0, curveOut;
    int r;

    if (*(s8 *)((char *)state + 0x27a) != 0) {
        lbl_803DC66C = 5;
    }
    r = fn_8029B9FC(obj, state, lbl_803E7EA4);
    if (r != 0) {
        return r;
    }
    {
        f32 x = (*(f32 *)((char *)state + 0x298) - lbl_803E7F14) / lbl_803E7F2C;
        if (x >= lbl_803E7EA4) {
            if (x <= lbl_803E7EE0) {
                ratio = x;
            } else {
                ratio = lbl_803E7EE0;
            }
        } else {
            ratio = lbl_803E7EA4;
        }
    }
    {
        f32 ang = lbl_803E7F94 * (f32)(int)*(int *)((char *)inner + 0x474) / lbl_803E7F98;
        vx = *(f32 *)((char *)inner + 0x404) * (ratio * -fn_80293E80(ang));
    }
    {
        f32 ang = lbl_803E7F94 * (f32)(int)*(int *)((char *)inner + 0x474) / lbl_803E7F98;
        vy = *(f32 *)((char *)inner + 0x404) * (ratio * -sin(ang));
    }
    {
        f32 a = interpolate(vx - *(f32 *)((char *)inner + 0x4c8), lbl_803E7F44, timeDelta);
        f32 b = interpolate(vy - *(f32 *)((char *)inner + 0x4cc), lbl_803E7F44, timeDelta);
        *(f32 *)((char *)inner + 0x4c8) += a;
        *(f32 *)((char *)inner + 0x4cc) += b;
    }
    *(f32 *)((char *)state + 0x294) =
        sqrtf(*(f32 *)((char *)inner + 0x4c8) * *(f32 *)((char *)inner + 0x4c8) +
              *(f32 *)((char *)inner + 0x4cc) * *(f32 *)((char *)inner + 0x4cc));
    {
        f32 v = *(f32 *)((char *)state + 0x294);
        f32 lo = *(f32 *)*(int *)((char *)inner + 0x400);
        if (v >= lo) {
            if (v <= *(f32 *)((char *)inner + 0x404)) {
                *(f32 *)((char *)state + 0x294) = v;
            } else {
                *(f32 *)((char *)state + 0x294) = *(f32 *)((char *)inner + 0x404);
            }
        } else {
            *(f32 *)((char *)state + 0x294) = lo;
        }
    }
    {
        f32 ang = lbl_803E7F94 * (f32)*(s16 *)((char *)inner + 0x478) / lbl_803E7F98;
        c = fn_80293E80(ang);
    }
    {
        f32 ang = lbl_803E7F94 * (f32)*(s16 *)((char *)inner + 0x478) / lbl_803E7F98;
        s = sin(ang);
    }
    {
        f32 c8 = *(f32 *)((char *)inner + 0x4c8);
        f32 cc = *(f32 *)((char *)inner + 0x4cc);
        *(f32 *)((char *)state + 0x280) +=
            interpolate(-cc * s - c8 * c - *(f32 *)((char *)state + 0x280),
                        *(f32 *)((char *)inner + 0x82c), timeDelta);
        *(f32 *)((char *)state + 0x284) +=
            interpolate(c8 * s - cc * c - *(f32 *)((char *)state + 0x284),
                        *(f32 *)((char *)inner + 0x82c), timeDelta);
    }
    t0 = *(f32 *)((char *)obj + 0x98);
    {
        u8 phase = *(u8 *)((char *)inner + 0x8cc);
        int idx = (u8)((s8)phase >> 1);
        if (*(f32 *)((char *)state + 0x294) < lbl_80332FC0[idx]) {
            if ((s8)phase == 4) {
                if (*(f32 *)((char *)state + 0x298) < lbl_803E7F14) {
                    *(int *)((char *)state + 0x308) = (int)fn_8029C8C8;
                    return 0x25;
                }
            } else {
                *(u8 *)((char *)inner + 0x8cc) = phase - 4;
            }
        } else {
            if (*(f32 *)((char *)state + 0x294) >= lbl_80332FC0[idx + 1] &&
                (s8)phase < 8) {
                if ((s8)phase == 0) {
                    t0 = lbl_803E7EA4;
                }
                if (*(f32 *)((char *)state + 0x294) < *(f32 *)((char *)inner + 0x404)) {
                    *(u8 *)((char *)inner + 0x8cc) += 4;
                }
            }
        }
    }
    {
        f32 az = *(f32 *)((char *)state + 0x284);
        f32 ax = *(f32 *)((char *)state + 0x280);
        if (az < lbl_803E7EA4) {
            az = -az;
        }
        if (ax < lbl_803E7EA4) {
            ax = -ax;
        }
        if (((int (*)(f32, int, f32 *))ObjAnim_SampleRootCurvePhase)(*(f32 *)((char *)state + 0x294), obj, &curveOut) != 0) {
            *(f32 *)((char *)state + 0x2a0) = curveOut;
        }
        if (ax > az) {
            if (*(f32 *)((char *)state + 0x280) < lbl_803E7EA4) {
                *(f32 *)((char *)state + 0x2a0) = -*(f32 *)((char *)state + 0x2a0);
            }
            if (*(s16 *)((char *)obj + 0xa0) != lbl_80333210[*(s8 *)((char *)inner + 0x8cc)]) {
                if (((int (*)(int))ObjAnim_GetCurrentEventCountdown)(obj) == 0) {
                    ObjAnim_SetCurrentMove(obj, lbl_80333210[*(s8 *)((char *)inner + 0x8cc)], t0, 0);
                    if (*(s8 *)((char *)state + 0x27a) == 0) {
                        ((void (*)(int, int))ObjAnim_SetCurrentEventStepFrames)(obj, 0xc);
                    }
                }
            }
        } else {
            if (*(f32 *)((char *)state + 0x284) >= lbl_803E7EA4) {
                *(f32 *)((char *)state + 0x2a0) = -*(f32 *)((char *)state + 0x2a0);
            }
            if (*(s16 *)((char *)obj + 0xa0) != (lbl_80333210 + 2)[*(s8 *)((char *)inner + 0x8cc)]) {
                if (((int (*)(int))ObjAnim_GetCurrentEventCountdown)(obj) == 0) {
                    ObjAnim_SetCurrentMove(obj, (lbl_80333210 + 2)[*(s8 *)((char *)inner + 0x8cc)], t0, 0);
                    if (*(s8 *)((char *)state + 0x27a) == 0) {
                        ((void (*)(int, int))ObjAnim_SetCurrentEventStepFrames)(obj, 0xc);
                    }
                }
            }
        }
    }
    *(s16 *)((char *)inner + 0x478) =
        (s16)(*(s16 *)((char *)inner + 0x478) +
              (int)((f32)(int)*(int *)((char *)inner + 0x4a4) / lbl_803E7FC0));
    *(s16 *)((char *)inner + 0x484) = *(s16 *)((char *)inner + 0x478);
    *(int *)((char *)inner + 0x360) |= 0x2000000;
    fn_802ABFBC(obj, state, inner);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
extern int gameBitDecrement(int);
extern u8 objGetByteParam1C(int obj);
extern f32 lbl_803E8054;
int fn_802A418C(int obj, int state, f32 fv)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int i;
    s8 c;
    int *list;
    u8 buf[64];
    f32 dist;
    int cnt41;
    int cnt20;
    int cnt30;

    dist = lbl_803E8050;
    if (*(u8 *)((char *)inner + 0x8c8) == 0x44) {
        goto ui_block;
    }
    if (*(void **)((char *)inner + 0x7f8) != NULL) {
        c = ((s8 (*)(int, int, int, void *, int))fn_802A74A4)(obj, inner, state, buf, 0x22);
    } else {
        c = ((s8 (*)(int, int, int, void *, int))fn_802A74A4)(obj, inner, state, buf, -0x141);
    }
    if (c == -1) {
        *(s8 *)((char *)inner + 0x8c2) = -1;
        *(u8 *)((char *)inner + 0x8c3) = 0;
    } else if (c == *(s8 *)((char *)inner + 0x8c2)) {
        int n = *(s8 *)((char *)inner + 0x8c3) + 1;
        *(u8 *)((char *)inner + 0x8c3) = n;
        if ((u8)n > 200) {
            *(u8 *)((char *)inner + 0x8c3) = 200;
        }
    } else {
        *(s8 *)((char *)inner + 0x8c2) = c;
        *(u8 *)((char *)inner + 0x8c3) = 0;
    }
    switch (*(s8 *)((char *)inner + 0x8c2)) {
    case 0:
        if (((ByteFlags *)((char *)inner + 0x3f1))->b01) {
            *(int *)((char *)state + 0x308) = (int)fn_8029FFD0;
            return 0xf;
        }
        goto deflt;
    case 9:
        if (((ByteFlags *)((char *)inner + 0x3f1))->b01) {
            *(int *)((char *)state + 0x308) = (int)fn_8029FFD0;
            return 0x13;
        }
        goto deflt;
    case 4:
        lbl_803DC6A0 = -1;
        *(int *)((char *)state + 0x308) = 0;
        return 0xd;
    case 5:
        if (*(void **)((char *)inner + 0x7f8) == NULL) {
            lbl_803DC6A0 = -1;
            *(int *)((char *)state + 0x308) = 0;
            return 0xc;
        }
        goto deflt;
    case 6:
        *(int *)((char *)state + 0x308) = (int)fn_8029DAE0;
        return -0x1d;
    case 0xd:
        *(int *)((char *)state + 0x308) = 0;
        return 0x1d;
    case 7:
        fn_802AE9C8(obj, inner, state);
        return 0;
    case 8:
        *(int *)((char *)state + 0x308) = 0;
        return 0xb;
    case 0xb:
        *(int *)((char *)state + 0x308) = (int)fn_802A00C0;
        return 0x1c;
    case 10:
        *(int *)((char *)state + 0x308) = 0;
        return 0x17;
    default:
    deflt:
        if (*(void **)((char *)inner + 0x7f8) == NULL &&
            ((ByteFlags *)((char *)inner + 0x3f4))->b40) {
            list = (int *)ObjGroup_GetObjects(0x41, &cnt41);
            for (i = 0; i < cnt41; i++) {
                int o = *list;
                lbl_803DE434 = o;
                if ((*(u8 *)((char *)o + 0xaf) & 4) != 0 &&
                    (*(u8 *)((char *)o + 0xaf) & 0x10) == 0) {
                    switch ((u8)objGetByteParam1C(o)) {
                    case 2:
                        setAButtonIcon(2);
                        if ((*(int *)((char *)state + 0x31c) & 0x100) != 0) {
                            buttonDisable(0, 0x100);
                            *(int *)((char *)state + 0x308) = (int)fn_80298924;
                            return 0x34;
                        }
                        break;
                    case 4:
                    case 5:
                        setAButtonIcon(0xe);
                        if ((*(int *)((char *)state + 0x31c) & 0x100) != 0) {
                            buttonDisable(0, 0x100);
                            *(int *)((char *)state + 0x308) = (int)fn_80298924;
                            return 0x36;
                        }
                        break;
                    case 3:
                        setAButtonIcon(2);
                        if ((*(int *)((char *)state + 0x31c) & 0x100) != 0) {
                            buttonDisable(0, 0x100);
                            *(int *)((char *)state + 0x308) = (int)fn_80298924;
                            return 0x35;
                        }
                        break;
                    case 0:
                        break;
                    }
                }
                list++;
            }
        }
    ui_block:
        ((void (*)(int, int *))ObjGroup_GetObjects)(0x20, &cnt20);
        GameBit_Set(0xeb5, !cnt20);
        if ((*(int (*)(void))(*(int *)(*gGameUIInterface + 0x1c)))() != 0) {
            if ((*(int (*)(int))(*(int *)(*gGameUIInterface + 0x20)))(0x1ee) != 0) {
                char *found;
                s16 *def = NULL;
                buttonDisable(0, 0x100);
                found = ((char *(*)(int, int, f32 *))ObjGroup_FindNearestObject)(0xf, obj, &dist);
                if (found != NULL) {
                    def = *(s16 **)((char *)found + 0x4c);
                }
                if (def != NULL && *def == 0x860 && (*(u8 *)((char *)found + 0xaf) & 4) != 0) {
                    GameBit_Set(0x3f1, 1);
                    GameBit_Set(0x3d8, 1);
                    GameBit_Set(0x651, 1);
                }
                return 0;
            }
            if ((*(int (*)(int))(*(int *)(*gGameUIInterface + 0x20)))(0x953) != 0 &&
                lbl_803DE444 == NULL) {
                int player;
                void *att;
                buttonDisable(0, 0x100);
                if (lbl_803DE44C != NULL && ((ByteFlags *)((char *)inner + 0x3f4))->b40) {
                    *(u8 *)((char *)inner + 0x8b4) = 1;
                    ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 1;
                }
                player = Obj_GetPlayerObject();
                if (Obj_IsLoadingLocked() == 0) {
                    att = NULL;
                } else {
                    char *setup = (char *)Obj_AllocObjectSetup(0x24, 0x62d);
                    *(s16 *)setup = 0x62d;
                    *(u8 *)(setup + 0x4) = 2;
                    *(u8 *)(setup + 0x6) = 0xff;
                    *(u8 *)(setup + 0x5) = 1;
                    *(u8 *)(setup + 0x7) = 0xff;
                    *(int *)(setup + 0x8) = *(int *)((char *)player + 0xc);
                    *(int *)(setup + 0xc) = *(int *)((char *)player + 0x10);
                    *(int *)(setup + 0x10) = *(int *)((char *)player + 0x14);
                    att = (void *)Obj_SetupObject((int)setup, 4, *(s8 *)((char *)player + 0xac),
                                                  -1, *(int *)((char *)player + 0x30));
                    lbl_803DE444 = att;
                }
                ((void (*)(int, void *, int))ObjLink_AttachChild)(obj, att, 1);
                (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(0xd, obj, -1);
            }
        }
        if (*(u8 *)((char *)inner + 0x8c8) != 0x44 &&
            (*(int (*)(void))(*(int *)(*gGameUIInterface + 0x1c)))() != 0 &&
            (*(int (*)(int))(*(int *)(*gGameUIInterface + 0x20)))(0x13e) != 0 &&
            (((void (*)(int, int *))ObjGroup_GetObjects)(0x30, &cnt30), cnt30 == 0)) {
            gameBitDecrement(0x13d);
            if (Obj_IsLoadingLocked() != 0) {
                char *setup = (char *)Obj_AllocObjectSetup(0x24, 0x43b);
                *(s16 *)setup = 0x43b;
                *(u8 *)(setup + 0x2) = 9;
                *(u8 *)(setup + 0x4) = 2;
                *(u8 *)(setup + 0x6) = 0xff;
                *(u8 *)(setup + 0x5) = 1;
                *(u8 *)(setup + 0x7) = 0xff;
                *(int *)(setup + 0x8) = *(int *)((char *)obj + 0xc);
                *(f32 *)(setup + 0xc) = lbl_803E7F58 + *(f32 *)((char *)obj + 0x10);
                *(int *)(setup + 0x10) = *(int *)((char *)obj + 0x14);
                *(u8 *)(setup + 0x19) = 1;
                Obj_SetupObject((int)setup, 5, -1, -1, *(int *)((char *)obj + 0x30));
            }
            (*(void (*)(void))(*(int *)(*gGameUIInterface + 0x10)))();
            return 0;
        }
        {
            if (*(s8 *)((char *)inner + 0x8b3) == 0) {
                if ((*(int *)((char *)state + 0x31c) & 0x100) != 0) {
                    int ok2;
                    if (*(void **)((char *)inner + 0x7f8) != NULL ||
                        !((ByteFlags *)((char *)inner + 0x3f4))->b40 ||
                        ((ByteFlags *)((char *)inner + 0x3f0))->b20 ||
                        ((ByteFlags *)((char *)inner + 0x3f0))->b10) {
                        ok2 = 0;
                    } else {
                        ok2 = 1;
                    }
                    if (ok2 != 0) {
                        if (*(s8 *)((char *)inner + 0x8b4) == 2 ||
                            (*(void **)((char *)inner + 0x4b8) != NULL &&
                             *(f32 *)((char *)inner + 0x4b0) < lbl_803E8054 &&
                             *(int *)((char *)inner + 0x4a8) < 0x4000 &&
                             *(s16 *)((char *)inner + 0x4b4) == 1)) {
                            if (lbl_803DE44C != NULL && ((ByteFlags *)((char *)inner + 0x3f4))->b40) {
                                *(u8 *)((char *)inner + 0x8b4) = 4;
                                ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 1;
                            }
                            *(int *)((char *)state + 0x308) = 0;
                            return 0x32;
                        }
                        if (lbl_803DE44C != NULL && ((ByteFlags *)((char *)inner + 0x3f4))->b40) {
                            *(u8 *)((char *)inner + 0x8b4) = 2;
                            ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 0;
                        }
                    }
                }
            } else {
                int r2;
                if ((*(int *)((char *)state + 0x31c) & 0x200) != 0 && lbl_803DE44C != NULL &&
                    ((ByteFlags *)((char *)inner + 0x3f4))->b40) {
                    *(u8 *)((char *)inner + 0x8b4) = 0;
                    ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 0;
                }
                {
                    int in2 = *(int *)((char *)obj + 0xb8);
                    u8 b;
                    if ((*(int *)((char *)state + 0x31c) & 0x100) == 0 ||
                        (b = ((ByteFlags *)((char *)in2 + 0x3f4))->b40, b == 0)) {
                        r2 = 0;
                    } else {
                        if (lbl_803DE44C != NULL && b != 0) {
                            *(u8 *)((char *)in2 + 0x8b4) = 4;
                            ((ByteFlags *)((char *)in2 + 0x3f4))->b08 = 1;
                        }
                        *(int *)((char *)state + 0x308) = 0;
                        r2 = 0x32;
                    }
                    if (r2 != 0) {
                        return r2;
                    }
                }
            }
            return 0;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
extern int *gPlayerShadowInterface;
extern u8 lbl_8033322C[];
extern int lbl_803E7E68;
extern int lbl_803E7E6C;
void playerRender(int obj, int a, int b, int c, int d, s8 flag)
{
    int inner = *(int *)((char *)obj + 0xb8);
    f32 sx;
    f32 sy;
    f32 sz;
    f32 px;
    f32 py;
    f32 pz;
    f32 qx;
    f32 qy;
    f32 qz;
    int tbl[2];
    struct {
        u8 pad[6];
        u16 mode;
        f32 scale;
        f32 x;
        f32 y;
        f32 z;
    } pfx;
    f32 vel[3];

    if (flag == -1 || (*(u32 *)((char *)inner + 0x360) & 0x4001) == 0) {
        if (*(void **)((char *)inner + 0x7f0) != NULL &&
            ((*(u16 *)((char *)obj + 0xb0) & 0x1000) != 0 ||
             arrayIndexOf(&lbl_803DC6C4, 2, *(s16 *)((char *)inner + 0x274)) != -1)) {
            fn_802A9D0C(obj, inner, *(int *)((char *)inner + 0x7f0), a, b, c, d, 1);
        }
        if (*(u8 *)((char *)inner + 0x8ca) == 1) {
            fn_802AAD44(obj);
        }
        (*(void (*)(int))(*(int *)(*gPlayerShadowInterface + 0x8)))(obj);
        if (*(void **)((char *)inner + 0x7f0) != NULL &&
            ((*(u16 *)((char *)obj + 0xb0) & 0x1000) != 0 ||
             arrayIndexOf(&lbl_803DC6C4, 2, *(s16 *)((char *)inner + 0x274)) != -1)) {
            {
                int held = *(int *)((char *)inner + 0x7f0);
                (*(void (*)(f32))*(int *)(*(int *)(*(int *)((char *)held + 0x68)) + 0x50))(
                    *(f32 *)((char *)*(int *)((char *)obj + 0x50) + 0x4));
            }
        }
        if ((*(u32 *)((char *)inner + 0x360) & 0x8000000) != 0) {
            sx = *(f32 *)((char *)obj + 0xc);
            sy = *(f32 *)((char *)obj + 0x10);
            sz = *(f32 *)((char *)obj + 0x14);
            *(f32 *)((char *)obj + 0xc) = *(f32 *)((char *)*(int *)((char *)obj + 0x64) + 0x20);
            *(f32 *)((char *)obj + 0x10) = *(f32 *)((char *)*(int *)((char *)obj + 0x64) + 0x24);
            *(f32 *)((char *)obj + 0x14) = *(f32 *)((char *)*(int *)((char *)obj + 0x64) + 0x28);
        }
        *(f32 *)((char *)obj + 0x10) = *(f32 *)((char *)obj + 0x10) + *(f32 *)((char *)inner + 0x7c8);
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, a, b, c, d, lbl_803E7EE0);
        *(f32 *)((char *)obj + 0x10) = *(f32 *)((char *)obj + 0x10) - *(f32 *)((char *)inner + 0x7c8);
        if ((*(u32 *)((char *)inner + 0x360) & 0x8000000) != 0) {
            *(f32 *)((char *)obj + 0xc) = sx;
            *(f32 *)((char *)obj + 0x10) = sy;
            *(f32 *)((char *)obj + 0x14) = sz;
        }
        if (flag != 0) {
            fn_802AAF80(obj, inner, a, b, c);
        }
        ((void (*)(int, int, int, int))ObjPath_GetPointWorldPositionArray)(obj, 6, 2,
                                                                           inner + 0x3c4);
        ObjPath_GetPointWorldPosition(obj, 0xb, (f32 *)((char *)inner + 0x768),
                                      (f32 *)((char *)inner + 0x76c),
                                      (f32 *)((char *)inner + 0x770), 0);
        if (((int (*)(int, int))playerHasKrazoaSpirit)(1, 0) == 0) {
            if (lbl_803DE428 != 0) {
                *(int *)((char *)lbl_803DE428 + 0x3c) &= ~0x100000;
                lbl_803DE428 = 0;
            }
        } else if (lbl_803DE428 == 0) {
            int *mdl = (int *)Obj_GetActiveModel(obj);
            int m = *mdl;
            int i;
            for (i = 0; i < (int)(u32)*(u8 *)((char *)m + 0xf8); i++) {
                int op = ObjModel_GetRenderOp(m, i);
                if (*(s8 *)((char *)op + 0x41) == 2) {
                    Shader_getLayer(op, 1);
                    lbl_803DE428 = op;
                    *(int *)((char *)op + 0x3c) |= 0x100000;
                    break;
                }
            }
        }
        {
            int in2 = *(int *)((char *)obj + 0xb8);
            if (*(void **)((char *)in2 + 0x7f8) != NULL &&
                *(int *)((char *)*(int *)((char *)in2 + 0x7f8) + 0xf8) == 1) {
                ObjPath_GetPointWorldPosition(obj, 8, &px, &py, &pz, 0);
                ObjPath_GetPointWorldPosition(obj, 9, &qx, &qy, &qz, 0);
                px = lbl_803E7E98 * (px + qx);
                py = lbl_803E7E98 * (py + qy);
                pz = lbl_803E7E98 * (pz + qz);
                if (*(s16 *)((char *)*(int *)((char *)in2 + 0x7f8) + 0x46) == 0x112) {
                    py = py + lbl_803E7ED4;
                }
                *(f32 *)((char *)*(int *)((char *)in2 + 0x7f8) + 0x18) = px;
                *(f32 *)((char *)*(int *)((char *)in2 + 0x7f8) + 0xc) = px;
                *(f32 *)((char *)*(int *)((char *)in2 + 0x7f8) + 0x1c) = py;
                *(f32 *)((char *)*(int *)((char *)in2 + 0x7f8) + 0x10) = py;
                *(f32 *)((char *)*(int *)((char *)in2 + 0x7f8) + 0x20) = pz;
                *(f32 *)((char *)*(int *)((char *)in2 + 0x7f8) + 0x14) = pz;
                if (*(s16 **)((char *)obj + 0x30) == NULL) {
                    *(s16 *)*(int *)((char *)in2 + 0x7f8) = *(s16 *)((char *)in2 + 0x478);
                } else {
                    *(s16 *)*(int *)((char *)in2 + 0x7f8) =
                        **(s16 **)((char *)obj + 0x30) + *(s16 *)((char *)obj + 0x0);
                }
                (*(void (*)(int, int, int, int, int, int))*(int *)(
                    *(int *)(*(int *)((char *)*(int *)((char *)in2 + 0x7f8) + 0x68)) + 0x10))(
                    *(int *)((char *)in2 + 0x7f8), 0, 0, 0, 0, -1);
            }
        }
        if (lbl_803E7EA4 < *(f32 *)((char *)inner + 0x79c) ||
            (*(u16 *)((char *)inner + 0x8d8) & 2) != 0) {
            tbl[0] = lbl_803E7E68;
            tbl[1] = lbl_803E7E6C;
            objParticleFn_80099d84(obj, lbl_803E7E9C,
                                   tbl[*(u8 *)((char *)inner + 0x7a8) >> 5] & 0xff,
                                   lbl_803E7EE0, 0);
        }
        if ((*(u16 *)((char *)inner + 0x8d8) & 1) != 0) {
            objParticleFn_80099d84(obj, lbl_803E7E9C, 8, lbl_803E7EE0, 0);
        }
        if (*(f32 *)((char *)inner + 0x838) <= lbl_803E7EA4) {
            if (lbl_8033322C[*(u8 *)((char *)inner + 0x86c)] == 6 ||
                lbl_8033322C[*(u8 *)((char *)inner + 0x86c)] == 3) {
                if ((*(u16 *)((char *)inner + 0x8d8) & 8) != 0) {
                    int n;
                    vel[0] = lbl_803E7F6C * *(f32 *)((char *)obj + 0x24);
                    vel[1] = lbl_803E7F6C * *(f32 *)((char *)obj + 0x28);
                    vel[2] = lbl_803E7F6C * *(f32 *)((char *)obj + 0x2c);
                    pfx.x = lbl_803E8018 * *(f32 *)((char *)obj + 0x24) + *(f32 *)((char *)inner + 0x3c4);
                    pfx.y = lbl_803E8018 * *(f32 *)((char *)obj + 0x28) + *(f32 *)((char *)inner + 0x3c8);
                    pfx.z = lbl_803E8018 * *(f32 *)((char *)obj + 0x2c) + *(f32 *)((char *)inner + 0x3cc);
                    pfx.scale = lbl_803E7F18;
                    pfx.mode = lbl_8033322C[*(u8 *)((char *)inner + 0x86c)];
                    for (n = 5; n != 0; n--) {
                        (*(void (*)(int, int, void *, int, int, f32 *))(*(int *)(*gPartfxInterface + 0x8)))(
                            obj, 0x7e6, &pfx, 0x200001, -1, vel);
                    }
                    pfx.x = lbl_803E8018 * *(f32 *)((char *)obj + 0x24) + *(f32 *)((char *)inner + 0x3d0);
                    pfx.y = lbl_803E8018 * *(f32 *)((char *)obj + 0x28) + *(f32 *)((char *)inner + 0x3d4);
                    pfx.z = lbl_803E8018 * *(f32 *)((char *)obj + 0x2c) + *(f32 *)((char *)inner + 0x3d8);
                    pfx.scale = lbl_803E7F18;
                    pfx.mode = lbl_8033322C[*(u8 *)((char *)inner + 0x86c)];
                    for (n = 5; n != 0; n--) {
                        (*(void (*)(int, int, void *, int, int, f32 *))(*(int *)(*gPartfxInterface + 0x8)))(
                            obj, 0x7e6, &pfx, 0x200001, -1, vel);
                    }
                    *(u16 *)((char *)inner + 0x8d8) = *(u16 *)((char *)inner + 0x8d8) & ~0x8;
                }
                if ((*(u16 *)((char *)inner + 0x8d8) & 4) != 0) {
                    u8 n2;
                    vel[0] = lbl_803E7F44 * *(f32 *)((char *)obj + 0x24);
                    vel[1] = lbl_803E7F44 * *(f32 *)((char *)obj + 0x28);
                    vel[2] = lbl_803E7F44 * *(f32 *)((char *)obj + 0x2c);
                    pfx.x = *(f32 *)((char *)obj + 0x18);
                    pfx.y = lbl_803E7F10 + *(f32 *)((char *)obj + 0x1c);
                    pfx.z = *(f32 *)((char *)obj + 0x20);
                    pfx.scale = lbl_803E7EE0;
                    pfx.mode = lbl_8033322C[*(u8 *)((char *)inner + 0x86c)];
                    for (n2 = 0; n2 < 10; n2++) {
                        (*(void (*)(int, int, void *, int, int, f32 *))(*(int *)(*gPartfxInterface + 0x8)))(
                            obj, 0x7e6, &pfx, 0x200001, -1, vel);
                    }
                    *(u16 *)((char *)inner + 0x8d8) = *(u16 *)((char *)inner + 0x8d8) & ~0x4;
                }
            }
        } else if ((*(u16 *)((char *)inner + 0x8d8) & 4) != 0) {
            *(int *)((char *)inner + 0x360) |= 0x20000;
            *(u16 *)((char *)inner + 0x8d8) = *(u16 *)((char *)inner + 0x8d8) & ~0x4;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
extern u64 lbl_803DE4A0;
extern u64 lbl_803DE4A8;
typedef struct { int a; int b; } IntPair2;
extern int lbl_803E7E70;
extern f32 lbl_803E7FA0;
extern f32 lbl_803E80FC;
extern f32 lbl_803E7F30;
extern f32 lbl_803E8100;
extern f32 lbl_803E7FC0;
extern f32 lbl_803E7EF8;
int fn_802AC7DC(int obj, int state, int inner, f32 fv)
{
    int r;
    int ok;
    IntPair2 camp;
    struct {
        s16 a;
        s16 b;
        s16 c;
        f32 d;
        f32 e;
        f32 f;
        f32 g;
    } pos;
    u8 buf[52];
    f32 mtx[16];
    f32 dummy;

    camp = *(IntPair2 *)&lbl_803E7E70;
    if (*(u8 *)((char *)inner + 0x8c8) != 0x48 && *(u8 *)((char *)inner + 0x8c8) != 0x47 &&
        !((ByteFlags *)((char *)inner + 0x3f0))->b04 && !((ByteFlags *)((char *)inner + 0x3f0))->b08 &&
        *(void **)((char *)inner + 0x7f8) == NULL && !((ByteFlags *)((char *)inner + 0x3f0))->b02 &&
        *(void **)((char *)inner + 0x2d0) == NULL && !((ByteFlags *)((char *)inner + 0x3f6))->b40 &&
        *(s16 *)((char *)inner + 0x274) != 0x26) {
        ok = 1;
    } else {
        ok = 0;
    }
    if (ok != 0 && (*(u16 *)((char *)inner + 0x6e0) & 0x40) != 0 && getCurSeqNo() == 0) {
        if (!((ByteFlags *)((char *)inner + 0x3f1))->b20 &&
            !((ByteFlags *)((char *)inner + 0x3f0))->b10) {
            f32 b;
            f32 a;
            a = *(f32 *)((char *)state + 0x284);
            b = *(f32 *)((char *)state + 0x280);
            pos.a = *(s16 *)((char *)inner + 0x484);
            pos.b = 0;
            pos.c = 0;
            pos.d = lbl_803E7EE0;
            pos.e = lbl_803E7EA4;
            pos.f = lbl_803E7EA4;
            pos.g = lbl_803E7EA4;
            setMatrixFromObjectPos(mtx, &pos.a);
            Matrix_TransformPoint(mtx, a, lbl_803E7EA4, -b, (f32 *)((char *)inner + 0x4c8), &dummy,
                                  (f32 *)((char *)inner + 0x4cc));
            ((ByteFlags *)((char *)inner + 0x3f0))->b80 = 0;
            ((ByteFlags *)((char *)inner + 0x3f0))->b40 = 0;
            ((ByteFlags *)((char *)inner + 0x3f0))->b10 = 0;
            ((ByteFlags *)((char *)inner + 0x3f1))->b08 = 1;
            {
                s16 v = *(s16 *)((char *)inner + 0x478);
                *(s16 *)((char *)inner + 0x484) = v;
                *(s16 *)((char *)obj + 0x0) = v;
            }
            ((ByteFlags *)((char *)inner + 0x3f1))->b20 = 1;
            {
                f32 z = lbl_803E7EA4;
                *(f32 *)((char *)inner + 0x7bc) = z;
                *(f32 *)((char *)inner + 0x7b8) = z;
            }
        }
        if (!((ByteFlags *)((char *)inner + 0x3f1))->b10) {
            cameraSetInterpMode(2);
            (*(void (*)(int, int, int, int, void *, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
                0x52, 1, 0, 8, &camp, 0x1e, 0xff);
            if (lbl_803DE4A8 - lbl_803DE4A0 > 2) {
                Sfx_PlayFromObject(obj, 0x3e4);
            }
            lbl_803DE4A0 = lbl_803DE4A8;
            ((ByteFlags *)((char *)inner + 0x3f1))->b10 = 1;
        }
    } else {
        if (((ByteFlags *)((char *)inner + 0x3f1))->b20) {
            s16 v = *(s16 *)((char *)obj + 0x0);
            *(s16 *)((char *)inner + 0x484) = v;
            *(s16 *)((char *)inner + 0x478) = v;
            *(int *)((char *)inner + 0x494) = v;
            *(f32 *)((char *)inner + 0x284) = lbl_803E7EA4;
        }
        ((ByteFlags *)((char *)inner + 0x3f1))->b20 = 0;
        if (((ByteFlags *)((char *)inner + 0x3f1))->b10 && *(u8 *)((char *)inner + 0x8c8) != 0x48 &&
            *(u8 *)((char *)inner + 0x8c8) != 0x47 && getCurSeqNo() == 0) {
            (*(void (*)(int, int, int, int, int, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
                0x42, 0, 1, 0, 0, 0x1e, 0xff);
            ((ByteFlags *)((char *)inner + 0x3f1))->b10 = 0;
        }
    }
    lbl_803DE4A8 = lbl_803DE4A8 + 1;
    if (!((ByteFlags *)((char *)inner + 0x3f0))->b20 &&
        *(f32 *)((char *)inner + 0x838) > lbl_803E7FA0 &&
        *(f32 *)((char *)state + 0x1b0) < lbl_803E80FC) {
        ((void (*)(int, int, int))fn_802AE83C)(obj, inner, state);
        return 0;
    }
    {
        if (!((ByteFlags *)((char *)inner + 0x3f0))->b20 &&
            !((ByteFlags *)((char *)inner + 0x3f0))->b08 &&
            !((ByteFlags *)((char *)inner + 0x3f0))->b04) {
            if (((ByteFlags *)((char *)inner + 0x3f1))->b01 ||
                *(f32 *)((char *)state + 0x1b0) < lbl_803E7F58) {
                *(u8 *)((char *)inner + 0x40d) = 0;
            } else {
                *(u8 *)((char *)inner + 0x40d) = *(u8 *)((char *)inner + 0x40d) + 1;
            }
            if (*(u8 *)((char *)inner + 0x40d) > 10) {
                *(u8 *)((char *)inner + 0x40d) = 10;
            }
            if (*(u8 *)((char *)inner + 0x40d) > 2) {
                ((ByteFlags *)((char *)inner + 0x3f0))->b80 = 0;
                ((ByteFlags *)((char *)inner + 0x3f0))->b10 = 0;
                ((ByteFlags *)((char *)inner + 0x3f0))->b08 = 0;
                staffFn_80170380(lbl_803DE450, 2);
                ((ByteFlags *)((char *)inner + 0x3f0))->b02 = 0;
                *(int *)((char *)inner + 0x360) |= 0x800000;
                ((void (*)(int))ObjHits_SyncObjectPositionIfDirty)(obj);
                ((ByteFlags *)((char *)inner + 0x3f0))->b40 = 0;
                ((ByteFlags *)((char *)inner + 0x3f0))->b04 = 1;
                ((ByteFlags *)((char *)inner + 0x3f4))->b10 = 0;
                *(u8 *)((char *)inner + 0x800) = 0;
                if (*(void **)((char *)inner + 0x7f8) != NULL) {
                    s16 t = *(s16 *)((char *)*(int *)((char *)inner + 0x7f8) + 0x46);
                    if (t == 0x3cf || t == 0x662) {
                        objThrowFn_80182504(*(int *)((char *)inner + 0x7f8));
                    } else {
                        objSaveFn_800ea774(*(int *)((char *)inner + 0x7f8));
                    }
                    *(s16 *)((char *)*(int *)((char *)inner + 0x7f8) + 0x6) =
                        *(s16 *)((char *)*(int *)((char *)inner + 0x7f8) + 0x6) & ~0x4000;
                    *(int *)((char *)*(int *)((char *)inner + 0x7f8) + 0xf8) = 0;
                    *(int *)((char *)inner + 0x7f8) = 0;
                }
                *(int *)((char *)state + 0x308) = (int)fn_802A514C;
                return 3;
            }
        }
        if (!((ByteFlags *)((char *)inner + 0x3f0))->b20 &&
            lbl_803E7EA4 != *(f32 *)((char *)inner + 0x784)) {
            *(int *)((char *)state + 0x308) = 0;
            return 0x42;
        }
        if (!((ByteFlags *)((char *)inner + 0x3f0))->b20 &&
            !((ByteFlags *)((char *)inner + 0x3f0))->b08 &&
            !((ByteFlags *)((char *)inner + 0x3f0))->b04 &&
            *(void **)((char *)inner + 0x2d0) == NULL &&
            !((ByteFlags *)((char *)inner + 0x3f6))->b40 &&
            *(s16 *)((char *)inner + 0x274) != 0x26) {
            ok = 1;
        } else {
            ok = 0;
        }
        if (ok != 0 && *(void **)((char *)inner + 0x7f8) != NULL &&
            *(s8 *)((char *)inner + 0x800) == 0) {
            if ((*(int *)((char *)state + 0x310) & 0x4000) == 0) {
                *(int *)((char *)state + 0x308) = (int)fn_802A49A8;
                return 8;
            }
            *(int *)((char *)state + 0x308) = (int)fn_802A49A8;
            return 7;
        }
        if (!((ByteFlags *)((char *)inner + 0x3f0))->b20 &&
            !((ByteFlags *)((char *)inner + 0x3f0))->b08 &&
            !((ByteFlags *)((char *)inner + 0x3f0))->b04 &&
            !((ByteFlags *)((char *)inner + 0x3f0))->b02 &&
            *(void **)((char *)inner + 0x2d0) == NULL &&
            !((ByteFlags *)((char *)inner + 0x3f6))->b40 &&
            *(s16 *)((char *)inner + 0x274) != 0x26) {
            ok = 1;
        } else {
            ok = 0;
        }
        if (ok != 0) {
            r = ((int (*)(int, int, f32))fn_802A418C)(obj, state, fv);
            if (r != 0) {
                return r;
            }
        }
        if (*(void **)((char *)state + 0x2d0) != NULL) {
            s16 t = *(s16 *)((char *)state + 0x274);
            if (t != 0x24 && t != 0x25 && t != 0x26 &&
                !((ByteFlags *)((char *)inner + 0x3f6))->b20 &&
                *(s8 *)((char *)state + 0x349) == 1) {
                *(int *)((char *)state + 0x308) = (int)fn_8029C8C8;
                return 0x25;
            }
        }
        {
            u32 btn = getButtons_80014dd8(0);
            if ((btn & 0x20) != 0) {
                if (!((ByteFlags *)((char *)inner + 0x3f4))->b40 ||
                    ((ByteFlags *)((char *)inner + 0x3f0))->b20 ||
                    ((ByteFlags *)((char *)inner + 0x3f0))->b08 ||
                    ((ByteFlags *)((char *)inner + 0x3f0))->b04 ||
                    *(u8 *)((char *)inner + 0x8c8) == 0x44 ||
                    *(void **)((char *)inner + 0x7f8) != NULL ||
                    *(void **)((char *)inner + 0x2d0) != NULL ||
                    ((ByteFlags *)((char *)inner + 0x3f6))->b40 ||
                    *(s16 *)((char *)inner + 0x274) == 0x26 ||
                    (*(u16 *)((char *)obj + 0xb0) & 0x1000) != 0 ||
                    *(f32 *)((char *)inner + 0x880) != lbl_803E7EA4) {
                    ok = 0;
                } else {
                    ok = 1;
                }
                if (ok != 0 && !((ByteFlags *)((char *)inner + 0x3f0))->b02) {
                    staffFn_80170380(lbl_803DE450, 1);
                    ObjAnim_SetCurrentMove(obj, 0x4f, *(f32 *)((char *)obj + 0x98), 0);
                    ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent *)obj, 8);
                    if (lbl_803DE44C != NULL && ((ByteFlags *)((char *)inner + 0x3f4))->b40) {
                        *(u8 *)((char *)inner + 0x8b4) = 4;
                        ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 1;
                    }
                    *(f32 *)((char *)state + 0x2a0) = lbl_803E7EF8;
                    ((ByteFlags *)((char *)inner + 0x3f0))->b10 = 0;
                    ((ByteFlags *)((char *)inner + 0x3f0))->b40 = 0;
                    ((ByteFlags *)((char *)inner + 0x3f0))->b80 = 0;
                    ((ByteFlags *)((char *)inner + 0x3f0))->b08 = 0;
                    ((ByteFlags *)((char *)inner + 0x3f0))->b04 = 0;
                    *(u8 *)((char *)inner + 0x40d) = 0;
                    ((ByteFlags *)((char *)inner + 0x3f0))->b02 = 1;
                    *(u8 *)((char *)inner + 0x800) = 0;
                    if (*(void **)((char *)inner + 0x7f8) != NULL) {
                        s16 t = *(s16 *)((char *)*(int *)((char *)inner + 0x7f8) + 0x46);
                        if (t == 0x3cf || t == 0x662) {
                            objThrowFn_80182504(*(int *)((char *)inner + 0x7f8));
                        } else {
                            objSaveFn_800ea774(*(int *)((char *)inner + 0x7f8));
                        }
                        *(s16 *)((char *)*(int *)((char *)inner + 0x7f8) + 0x6) =
                            *(s16 *)((char *)*(int *)((char *)inner + 0x7f8) + 0x6) & ~0x4000;
                        *(int *)((char *)*(int *)((char *)inner + 0x7f8) + 0xf8) = 0;
                        *(int *)((char *)inner + 0x7f8) = 0;
                    }
                    ((void (*)(int))ObjHits_MarkObjectPositionDirty)(obj);
                    *(int *)((char *)state + 0x308) = (int)fn_802A514C;
                    return 3;
                }
            }
        }
        if (((ByteFlags *)((char *)inner + 0x3f0))->b08 ||
            ((ByteFlags *)((char *)inner + 0x3f0))->b04) {
            r = fn_802A74A4(obj, inner, state, buf, fv, 0x14);
            if (r == 0xc) {
                *(int *)((char *)state + 0x308) = 0;
                return 10;
            }
            if (r == 9) {
                if (lbl_803E7F30 + *(f32 *)((char *)inner + 0x550) <=
                        lbl_803E8100 + *(f32 *)((char *)obj + 0x8) &&
                    lbl_803E8100 + *(f32 *)((char *)obj + 0x8) <=
                        *(f32 *)((char *)inner + 0x54c) - lbl_803E7F10) {
                    doRumble(lbl_803E7ED8);
                    *(int *)((char *)state + 0x308) = (int)fn_8029FFD0;
                    return 0x12;
                }
            }
        }
        if (((ByteFlags *)((char *)inner + 0x3f0))->b20) {
            r = fn_802A74A4(obj, inner, state, buf, lbl_803E7EE0, 0x100);
            if (r == 5) {
                lbl_803DC6A0 = -1;
                *(int *)((char *)state + 0x308) = 0;
                return 0xc;
            }
            if (*(f32 *)((char *)inner + 0x838) < lbl_803E7FC0 &&
                ((ByteFlags *)((char *)inner + 0x3f1))->b01) {
                ((ByteFlags *)((char *)inner + 0x3f0))->b20 = 0;
            }
        }
        return 0;
    }
}

extern f32 lbl_803E80C0;
extern f32 lbl_803E80A0;
extern f32 lbl_803DC6B8[2];
int fn_802A87CC(int obj, char *cam, f32 *out, f32 *vec, f32 fa, f32 fb)
{
    s8 mode;
    int inner;
    void *parent;
    int wallHit;
    int tris;
    int verts;
    void **list;
    f32 y1;
    f32 y2;
    f32 z1;
    f32 z2;
    f32 x1;
    f32 x2;
    f32 dists[4];
    f32 z9c;
    f32 planes[7];
    f32 p7c;

    mode = 0;
    inner = *(int *)((char *)obj + 0xb8);
    if (fa <= *(f32 *)((char *)inner + 0x280) * fb || fa <= lbl_803E80C0) {
        s8 st = *(s8 *)((char *)cam + 0x50);
        if (st == 2 || st == 0x11) {
            mode = 4;
        } else if (!(*(f32 *)((char *)inner + 0x280) >= lbl_803E80A0)) {
            mode = 5;
        } else if (st != 4) {
            mode = 4;
        }
    }
    out[7] = *(f32 *)((char *)cam + 0x1c);
    out[8] = *(f32 *)((char *)cam + 0x20);
    out[9] = *(f32 *)((char *)cam + 0x24);
    out[7] = -out[7];
    out[8] = -out[8];
    out[9] = -out[9];
    out[10] = -*(f32 *)((char *)cam + 0x28);
    out[0xb] = vec[0];
    out[0xc] = vec[1];
    out[0xd] = vec[2];
    parent = *(void **)cam;
    if (mode == 4) {
        char *cp;
        f32 *pl;
        f32 *dp;
        int i;
        f32 *b6b8;
        f32 *px2;
        f32 *py2;
        f32 *pz2;
        f32 thresh;
        wallHit = 0;
        if (parent != NULL) {
            tris = *(int *)((char *)*(int *)((char *)parent + 0x50) + 0x34);
            verts = *(int *)((char *)*(int *)((char *)parent + 0x50) + 0x3c);
        } else {
            tris = lbl_803DCF34;
            verts = lbl_803DCF38;
        }
        planes[0] = out[9];
        planes[1] = lbl_803E7EA4;
        planes[2] = -out[7];
        planes[3] = -(planes[0] * *(f32 *)((char *)cam + 0x4) +
                      planes[2] * *(f32 *)((char *)cam + 0x14));
        planes[4] = -planes[0];
        planes[5] = lbl_803E7EA4;
        planes[6] = -planes[2];
        p7c = -(planes[4] * *(f32 *)((char *)cam + 0x8) +
                planes[6] * *(f32 *)((char *)cam + 0x18));
        i = 0;
        pl = planes;
        dp = dists;
        cp = cam;
        b6b8 = lbl_803DC6B8;
        px2 = &x2;
        py2 = &y2;
        pz2 = &z2;
        thresh = lbl_803E7E98;
        do {
            f32 dot = ((f32 (*)(f32 *, f32 *))PSVECDotProduct)(pl, vec);
            *dp = pl[3] + dot;
            if (*dp < thresh + b6b8[1]) {
                int tri;
                if (*(s16 *)(cp + 0x4c) > -1) {
                    tri = tris + *(s16 *)(cp + 0x4c) * 0x10;
                } else {
                    tri = 0;
                }
                if (tri == 0 || ((*(s8 *)(tri + 3) & 0x3f) != 5 && (*(s8 *)(tri + 3) & 0x3f) != 2)) {
                    wallHit = 1;
                } else {
                    x1 = *(f32 *)(verts + *(s16 *)(tri + 4) * 0xc);
                    y1 = lbl_803E7EA4;
                    z1 = *(f32 *)(verts + *(s16 *)(tri + 4) * 0xc + 8);
                    x2 = *(f32 *)(verts + *(s16 *)(tri + 6) * 0xc);
                    y2 = lbl_803E7EA4;
                    z2 = *(f32 *)(verts + *(s16 *)(tri + 6) * 0xc + 8);
                    if (parent != NULL) {
                        ((void (*)(f32 *, f32 *, f32 *, void *))Obj_TransformLocalPointToWorld)(
                            &x1, &y1, &z1, parent);
                        ((void (*)(f32, f32, f32, f32 *, f32 *, f32 *, void *))
                             Obj_TransformLocalPointToWorld)(x2, y2, z2, px2, py2, pz2, parent);
                    }
                    {
                        f32 dz = z2 - z1;
                        f32 dx = x1 - x2;
                        f32 inv = lbl_803E7EE0 / sqrtf(dz * dz + dx * dx);
                        dz = dz * inv;
                        dx = dx * inv;
                        if (dz * out[7] + dx * out[9] < lbl_803E7E98) {
                            wallHit = 1;
                        }
                    }
                }
            }
            pl += 4;
            dp++;
            cp += 2;
            i++;
        } while (i < 2);
        if (dists[0] < dists[1]) {
            *(u8 *)((char *)out + 0x5f) = 0;
        } else {
            *(u8 *)((char *)out + 0x5f) = 1;
        }
        if (wallHit != 0) {
            f32 e = lbl_803E7E98;
            out[0xb] = out[0xb] + ((e + b6b8[1]) - dists[*(u8 *)((char *)out + 0x5f)]) *
                                      planes[(u32)*(u8 *)((char *)out + 0x5f) * 4];
            out[0xd] = out[0xd] + ((e + b6b8[1]) - dists[*(u8 *)((char *)out + 0x5f)]) *
                                      planes[(u32)*(u8 *)((char *)out + 0x5f) * 4 + 2];
        }
        {
            f32 e2 = lbl_803E7E98;
            out[0x11] = -(out[7] * (e2 + lbl_803DC6C0) - out[0xb]);
            out[0x13] = -(out[9] * (e2 + lbl_803DC6C0) - out[0xd]);
        }
        {
            f32 f = lbl_803E7F10;
            out[0x14] = f * out[7] + out[0xb];
            out[0x16] = f * out[9] + out[0xd];
        }
        out[1] = *(f32 *)((char *)cam + 0xc) +
                 *(f32 *)((char *)cam + 0x48) *
                     (*(f32 *)((char *)cam + 0x10) - *(f32 *)((char *)cam + 0xc));
        dists[2] = out[0x14];
        dists[3] = out[1];
        z9c = out[0x16];
        ((void (*)(f32 *, f32 *, f32 *, int))Obj_TransformLocalPointToWorld)(
            &dists[2], &dists[3], &z9c, *(int *)((char *)obj + 0x30));
        {
            int cnt = hitDetectFn_80065e50(obj, (int ***)&list, 0, 0x201, dists[2], dists[3], z9c);
            if (cnt != 0) {
                f32 best = lbl_803E80AC;
                f32 best2 = best;
                int bi = -1;
                int i2 = 0;
                void **pp = list;
                if (cnt > 0) {
                    do {
                        f32 dy = dists[3] - *(f32 *)*pp;
                        if (lbl_803E7EA4 <= dy && (best < lbl_803E7EA4 || dy < best)) {
                            best = dy;
                            bi = i2;
                        }
                        if (lbl_803E80B0 < ((f32 *)*pp)[2] && lbl_803E7EA4 <= dy &&
                            (best2 < lbl_803E7EA4 || dy < best2)) {
                            best2 = dy;
                        }
                        pp++;
                        i2++;
                        cnt--;
                    } while (cnt != 0);
                }
                if (best < lbl_803E80C4 && bi != -1 && ((f32 *)list[bi])[2] <= lbl_803E80B0 &&
                    lbl_803E7EB0 < ((f32 *)list[bi])[2]) {
                    return 0;
                }
                if (best2 < lbl_803E80C4) {
                    return 0;
                }
            }
        }
        dists[2] = out[0x11];
        dists[3] = out[1];
        z9c = out[0x13];
        ((void (*)(f32 *, f32 *, f32 *, int))Obj_TransformLocalPointToWorld)(
            &dists[2], &dists[3], &z9c, *(int *)((char *)obj + 0x30));
        if (hitDetectFn_800658a4(obj, out + 0x12, 0x205, dists[2], dists[3], z9c) == 0) {
            out[0x12] = out[1] - out[0x12];
        } else {
            out[0x12] = out[1];
        }
        out[2] = *(f32 *)((char *)cam + 0xc);
        out[0] = out[1] - out[2];
        *(u8 *)((char *)out + 0x5e) = *(u8 *)((char *)cam + 0x50);
        *(u8 *)((char *)out + 0x60) = *(u8 *)((char *)cam + 0x53);
        if (*(int *)((char *)obj + 0x30) != 0) {
            ((void (*)(f32, f32, f32, f32 *, f32 *, f32 *))Obj_TransformLocalPointToWorld)(
                out[0xb], out[0xc], out[0xd], out + 0xb, out + 0xc, out + 0xd);
            ((void (*)(f32, f32, f32, f32 *, f32 *, f32 *, int))Obj_TransformLocalPointToWorld)(
                out[0x11], out[0x12], out[0x13], out + 0x11, out + 0x12, out + 0x13,
                *(int *)((char *)obj + 0x30));
            ((void (*)(f32, f32, f32, f32 *, f32 *, f32 *, int))Obj_TransformLocalPointToWorld)(
                out[0x14], out[0x15], out[0x16], out + 0x14, out + 0x15, out + 0x16,
                *(int *)((char *)obj + 0x30));
            *(f32 *)((char *)inner + 0x5ac) =
                *(f32 *)((char *)inner + 0x5ac) + *(f32 *)(*(int *)((char *)obj + 0x30) + 0x10);
            *(f32 *)((char *)inner + 0x5b0) =
                *(f32 *)((char *)inner + 0x5b0) + *(f32 *)(*(int *)((char *)obj + 0x30) + 0x10);
        }
        *(u8 *)((char *)out + 0x61) = 1;
        if (parent != NULL && (*(u32 *)((char *)*(int *)((char *)parent + 0x50) + 0x44) & 0x8000) == 0) {
            *(void **)((char *)inner + 0x4c4) = parent;
        } else {
            *(int *)((char *)inner + 0x4c4) = 0;
        }
    } else {
        *(int *)((char *)inner + 0x4c4) = 0;
    }
    return mode;
}

int fn_802A8EE4(int a, int b, int c, int d, int e)
{
    EmitPlane planes[2];
    f32 ax, ay, az, bx, by, bz;
    void *hit;
    int tbl1, tbl2;
    int i;

    *(int *)((char *)b + 0x4c4) = 0;
    *(f32 *)((char *)d + 0x1c) = *(f32 *)((char *)c + 0x1c);
    *(f32 *)((char *)d + 0x20) = *(f32 *)((char *)c + 0x20);
    *(f32 *)((char *)d + 0x24) = *(f32 *)((char *)c + 0x24);
    *(f32 *)((char *)d + 0x28) = *(f32 *)((char *)c + 0x28);
    *(u8 *)((char *)d + 0x60) = *(u8 *)((char *)c + 0x53);
    hit = *(void **)((char *)c + 0x0);
    if (hit != NULL) {
        int m = *(int *)((char *)hit + 0x50);
        tbl1 = *(int *)((char *)m + 0x34);
        tbl2 = *(int *)((char *)m + 0x3c);
    } else {
        tbl1 = lbl_803DCF34;
        tbl2 = lbl_803DCF38;
    }
    planes[0].nx = -*(f32 *)((char *)d + 0x24);
    planes[0].ny = lbl_803E7EA4;
    planes[0].nz = *(f32 *)((char *)d + 0x1c);
    planes[0].d = -(-*(f32 *)((char *)d + 0x24) * *(f32 *)((char *)c + 0x4)) +
                  *(f32 *)((char *)d + 0x1c) * *(f32 *)((char *)c + 0x14);
    planes[1].nx = *(f32 *)((char *)d + 0x24);
    planes[1].ny = lbl_803E7EA4;
    planes[1].nz = -*(f32 *)((char *)d + 0x1c);
    planes[1].d = -(*(f32 *)((char *)d + 0x24) * *(f32 *)((char *)c + 0x8)) +
                  -*(f32 *)((char *)d + 0x1c) * *(f32 *)((char *)c + 0x18);
    for (i = 0; i < 2; i++) {
        f32 dot = ((f32 (*)(void *, void *))PSVECDotProduct)(&planes[i], (void *)e) + planes[i].d;
        int face;
        int v0, v1;
        if (dot < lbl_803E7E98 + lbl_803DC6B8[1]) {
            s16 fi = *(s16 *)((char *)c + i * 2 + 0x4c);
            if (fi > -1) {
                face = tbl1 + (fi << 4);
            } else {
                face = 0;
            }
            if (face == 0) {
                return 0;
            }
            if (((s8)*(s8 *)((char *)face + 0x3) & 0x3f) != 6 &&
                ((s8)*(s8 *)((char *)face + 0x3) & 0x3f) != 0x10) {
                return 0;
            }
            v0 = *(s16 *)((char *)face + 0x4) * 0xc;
            ax = *(f32 *)((char *)tbl2 + v0);
            ay = lbl_803E7EA4;
            az = *(f32 *)((char *)tbl2 + v0 + 8);
            v1 = *(s16 *)((char *)face + 0x6) * 0xc;
            bx = *(f32 *)((char *)tbl2 + v1);
            by = lbl_803E7EA4;
            bz = *(f32 *)((char *)tbl2 + v1 + 8);
            if (hit != NULL) {
                ((void (*)(f32 *, f32 *, f32 *, int))Obj_TransformLocalPointToWorld)(&ax, &ay, &az, (int)hit);
                ((void (*)(f32 *, f32 *, f32 *, int))Obj_TransformLocalPointToWorld)(&bx, &by, &bz, (int)hit);
            }
            {
                f32 dz = bz - az;
                f32 dx = ax - bx;
                f32 len = sqrtf(dx * dx + dz * dz);
                f32 scale = lbl_803E7EE0 / len;
                dx = dx * scale;
                dz = dz * scale;
                if (dx * *(f32 *)((char *)d + 0x1c) + dz * *(f32 *)((char *)d + 0x24) < lbl_803E7E98) {
                    return 0;
                }
            }
        }
    }
    *(f32 *)((char *)d + 0x2c) = *(f32 *)((char *)e + 0x0);
    *(f32 *)((char *)d + 0x30) = *(f32 *)((char *)e + 0x4);
    *(f32 *)((char *)d + 0x34) = *(f32 *)((char *)e + 0x8);
    *(f32 *)((char *)d + 0x44) =
        -(*(f32 *)((char *)d + 0x1c) * (lbl_803E7E98 + lbl_803DC6C0)) + *(f32 *)((char *)d + 0x2c);
    *(f32 *)((char *)d + 0x4c) =
        -(*(f32 *)((char *)d + 0x24) * (lbl_803E7E98 + lbl_803DC6C0)) + *(f32 *)((char *)d + 0x34);
    *(f32 *)((char *)d + 0x50) =
        lbl_803E7F10 * *(f32 *)((char *)d + 0x1c) + *(f32 *)((char *)d + 0x2c);
    *(f32 *)((char *)d + 0x58) =
        lbl_803E7F10 * *(f32 *)((char *)d + 0x24) + *(f32 *)((char *)d + 0x34);
    *(f32 *)((char *)d + 0x38) = *(f32 *)((char *)b + 0x768);
    *(f32 *)((char *)d + 0x3c) = lbl_803E7EA4;
    *(f32 *)((char *)d + 0x40) = *(f32 *)((char *)b + 0x770);
    *(f32 *)((char *)d + 0x4) =
        *(f32 *)((char *)c + 0x48) * (*(f32 *)((char *)c + 0x40) - *(f32 *)((char *)c + 0x3c)) +
        *(f32 *)((char *)c + 0x3c);
    *(u8 *)((char *)d + 0x5e) = *(u8 *)((char *)c + 0x50);
    *(u8 *)((char *)d + 0x61) = 1;
    if (hitDetectFn_800658a4(a, (char *)d + 0x48, 0x205, *(f32 *)((char *)d + 0x44),
                             *(f32 *)((char *)d + 0x4), *(f32 *)((char *)d + 0x4c)) != 0) {
        return 0;
    }
    *(f32 *)((char *)d + 0x48) = *(f32 *)((char *)d + 0x4) - *(f32 *)((char *)d + 0x48);
    if ((s8)*(s8 *)((char *)c + 0x50) == 0x10) {
        *(f32 *)((char *)d + 0x8) = *(f32 *)((char *)a + 0x10);
        *(f32 *)((char *)d + 0x0) = *(f32 *)((char *)d + 0x4) - *(f32 *)((char *)d + 0x8);
        if (*(f32 *)((char *)d + 0x0) >= lbl_803E8044) {
            return 0;
        }
        if (hit != NULL && (*(int *)((char *)*(int *)((char *)hit + 0x50) + 0x44) & 0x8000) == 0) {
            *(int *)((char *)b + 0x4c4) = (int)hit;
        }
        return 3;
    }
    *(f32 *)((char *)d + 0x8) = *(f32 *)((char *)a + 0x84);
    *(f32 *)((char *)d + 0x0) = *(f32 *)((char *)d + 0x4) - *(f32 *)((char *)d + 0x8);
    if ((*(u8 *)((char *)b + 0x3f1) & 1) != 0) {
        if (hit != NULL && (*(int *)((char *)*(int *)((char *)hit + 0x50) + 0x44) & 0x8000) == 0) {
            *(int *)((char *)b + 0x4c4) = (int)hit;
        }
        if (*(f32 *)((char *)d + 0x0) <= lbl_803E80C8) {
            if (*(f32 *)((char *)d + 0x0) > lbl_803E80C4) {
                return 2;
            }
        }
        if (*(f32 *)((char *)d + 0x0) <= lbl_803E80C4) {
            if (*(f32 *)((char *)d + 0x0) >= lbl_803E8018) {
                return 3;
            }
        }
        return 0;
    } else {
        f32 q = *(f32 *)((char *)d + 0x4) -
                (*(f32 *)((char *)c + 0x48) * (*(f32 *)((char *)c + 0x10) - *(f32 *)((char *)c + 0xc)) +
                 *(f32 *)((char *)c + 0xc));
        if (*(f32 *)((char *)d + 0x0) < lbl_803E7ED8) {
            return 0;
        }
        if (*(f32 *)((char *)d + 0x0) > lbl_803E7FBC) {
            return 0;
        }
        if (q < lbl_803E80C4) {
            return 0;
        }
        if (hit != NULL && (*(int *)((char *)*(int *)((char *)hit + 0x50) + 0x44) & 0x8000) == 0) {
            *(int *)((char *)b + 0x4c4) = (int)hit;
        }
        return 6;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802A2918(int obj, int state, f32 fv)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int flag;

    *(int *)((char *)inner + 0x360) &= ~0x2;
    *(int *)((char *)inner + 0x360) |= 0x2000;
    *(int *)((char *)state + 0x4) |= 0x100000;
    {
        f32 z = lbl_803E7EA4;
        *(f32 *)((char *)state + 0x280) = z;
        *(f32 *)((char *)state + 0x284) = z;
        *(int *)((char *)state + 0x0) |= 0x200000;
        *(f32 *)((char *)obj + 0x24) = z;
        *(f32 *)((char *)obj + 0x2c) = z;
        *(int *)((char *)state + 0x4) |= 0x8000000;
        *(f32 *)((char *)obj + 0x28) = z;
    }
    flag = *(s8 *)((char *)inner + 0x4e4) != 1;
    if (flag) {
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7EF8;
    } else {
        *(f32 *)((char *)state + 0x2a0) = lbl_803E8024;
    }
    if ((*(int *)((char *)state + 0x314) & 0x80) != 0) {
        Sfx_PlayFromObject(obj, *(s16 *)((char *)inner + 0x81a) == 0 ? 0x398 : 0x1d);
    }
    if ((*(int *)((char *)state + 0x314) & 1) != 0) {
        if (*(s8 *)((char *)inner + 0x546) == 4) {
            Sfx_PlayFromObject(obj, SFXdrak_roar1);
        } else {
            Sfx_PlayFromObject(obj, SFXdn_rexroarlng11);
        }
    }
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        s16 *tbl;
        s16 *t;
        int sel;
        f32 vx, vy, vz;
        f32 sp1c;
        ObjHits_MarkObjectPositionDirty(obj);
        if (lbl_803DE44C != NULL && (*(u8 *)((char *)inner + 0x3f4) >> 6 & 1) != 0) {
            *(u8 *)((char *)inner + 0x8b4) = 1;
            *(u8 *)((char *)inner + 0x3f4) |= 8;
        }
        *(f32 *)((char *)state + 0x280) = lbl_803E7EA4;
        *(f32 *)((char *)state + 0x284) = lbl_803E7EA4;
        *(s16 *)((char *)state + 0x278) = 0xe;
        *(int *)((char *)inner + 0x898) = (int)fn_8029FFD0;
        sp1c = lbl_803E7EA4;
        if (flag) {
            vx = -*(f32 *)((char *)inner + 0x50c);
            vy = -*(f32 *)((char *)inner + 0x514);
            vz = -*(f32 *)((char *)inner + 0x518);
        } else {
            vx = *(f32 *)((char *)inner + 0x50c);
            vy = *(f32 *)((char *)inner + 0x514);
            vz = *(f32 *)((char *)inner + 0x518);
        }
        {
            int delta = (u16)getAngle(vx, vy) - *(s16 *)((char *)inner + 0x478);
            if (delta > 0x8000) {
                delta -= 0xffff;
            }
            if (delta < -0x8000) {
                delta += 0xffff;
            }
            *(s16 *)((char *)inner + 0x478) = (s16)(*(s16 *)((char *)inner + 0x478) + delta);
            *(s16 *)((char *)inner + 0x484) = *(s16 *)((char *)inner + 0x478);
        }
        *(f32 *)((char *)inner + 0x504) = *(f32 *)((char *)obj + 0xc);
        *(f32 *)((char *)inner + 0x508) = *(f32 *)((char *)obj + 0x14);
        *(f32 *)((char *)obj + 0xc) = *(f32 *)((char *)inner + 0x52c);
        *(f32 *)((char *)obj + 0x14) = *(f32 *)((char *)inner + 0x534);
        sel = *(f32 *)((char *)inner + 0x4fc) >= lbl_803E7EA4 ? 0 : 4;
        tbl = flag ? lbl_80332F88 : lbl_80332F78;
        t = tbl + sel;
        *(s16 *)((char *)inner + 0x544) =
            fn_802A71E0(obj, t[0], t[2], (int *)((char *)inner + 0x538), (int *)&vx,
                        lbl_803E7EA4, *(f32 *)((char *)state + 0x2a0), 2, 9);
        fn_802A71E0(obj, t[0], t[1], (int *)((char *)inner + 0x538),
                    (int *)((char *)inner + 0x51c), lbl_803E7EA4,
                    *(f32 *)((char *)state + 0x2a0), 0, flag ? 0x34 | 0x40 : 0x34);
        fn_802A71E0(obj, t[2], t[3], (int *)((char *)inner + 0x538),
                    (int *)((char *)inner + 0x51c), lbl_803E7EA4,
                    *(f32 *)((char *)state + 0x2a0), 0, 0x1a);
        *(f32 *)((char *)inner + 0x4f4) =
            *(f32 *)((char *)inner + 0x4f0) * (f32)(int)*(s8 *)((char *)inner + 0x4e4) +
            *(f32 *)((char *)inner + 0x4ec);
        *(f32 *)((char *)inner + 0x4f8) = *(f32 *)((char *)obj + 0x10);
        {
            int joint = ((int *)*(int *)((char *)obj + 0x7c))[*(s8 *)((char *)obj + 0xad)];
            f32 a8, ac, jp[3];
            ObjModel_SampleJointTransform(joint, 0, 0, lbl_803E7EE0, *(f32 *)((char *)obj + 0x8),
                                          jp, &a8);
            lbl_803DE438 = *(f32 *)((char *)obj + 0x10) + jp[0];
            lbl_803DE43C = *(f32 *)((char *)inner + 0x4f4) + lbl_803DAF88[1];
            a8 = *(f32 *)((char *)inner + 0x4e8);
            ac = *(f32 *)((char *)inner + 0x4ec);
            if (*(u8 *)((char *)inner + 0x8c8) != 0x48 && *(u8 *)((char *)inner + 0x8c8) != 0x47) {
                (*(void (*)(int, int, int, int, void *, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
                    0x4b, 1, 1, 8, &a8, 0, 0);
            }
        }
    } else {
        if (*(f32 *)((char *)obj + 0x98) > lbl_803E7FF4) {
            ((int (*)(f32, f32, int, int))Object_ObjAnimAdvanceMove)(
                *(f32 *)((char *)state + 0x2a0), fv, obj, 0);
            *(int *)((char *)state + 0x308) = (int)fn_8029FFD0;
            return 0x10;
        }
    }
    if (*(f32 *)((char *)obj + 0x98) >= lbl_803E7F18) {
        f32 g = lbl_803E8028 * (lbl_803E802C * *(f32 *)((char *)obj + 0x98) - lbl_803E7F18);
        f32 c;
        if (g >= lbl_803E7EA4) {
            if (g <= lbl_803E7EE0) {
                c = g;
            } else {
                c = lbl_803E7EE0;
            }
        } else {
            c = lbl_803E7EA4;
        }
        *(f32 *)((char *)obj + 0x10) = c * (lbl_803DE43C - lbl_803DE438) + *(f32 *)((char *)inner + 0x4f8);
    }
    ((void (*)(int, int, int, int))ObjAnim_WriteStateWord)
        (obj, OBJANIM_STATE_INDEX_CURRENT, OBJANIM_STATE_WORD_PREV_EVENT_STATE, 0);
    ((void (*)(int, int, int, int))ObjAnim_WriteStateWord)
        (obj, OBJANIM_STATE_INDEX_ACTIVE, OBJANIM_STATE_WORD_PREV_EVENT_STATE, 0);
    ((void (*)(int, int, int, int))ObjAnim_WriteStateWord)
        (obj, OBJANIM_STATE_INDEX_ACTIVE, OBJANIM_STATE_WORD_EVENT_COUNTDOWN,
         *(s16 *)((char *)inner + 0x544));
    ((int (*)(f32, f32, int, int))Object_ObjAnimAdvanceMove)(
        *(f32 *)((char *)state + 0x2a0), fv, obj, 0);
    (*(void (*)(f32, f32, f32))(*(int *)(*gCameraInterface + 0x2c)))(
        *(f32 *)((char *)obj + 0xc),
        *(f32 *)((char *)obj + 0x98) *
                (*(f32 *)((char *)inner + 0x4f4) - *(f32 *)((char *)obj + 0x10)) +
            *(f32 *)((char *)obj + 0x10),
        *(f32 *)((char *)obj + 0x14));
    fn_802AB5A4(obj, inner, 5);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_8029FA24(int obj, int state, f32 fv)
{
    char *base = (char *)lbl_80332EC0;
    int inner = *(int *)((char *)obj + 0xb8);
    int sub = *(int *)((char *)inner + 0x7f0);
    f32 wpos[3];

    *(int *)((char *)inner + 0x360) &= ~0x2;
    *(int *)((char *)inner + 0x360) |= 0x2000;
    *(int *)((char *)state + 0x4) |= 0x100000;
    {
        f32 z = lbl_803E7EA4;
        *(f32 *)((char *)state + 0x280) = z;
        *(f32 *)((char *)state + 0x284) = z;
        *(int *)((char *)state + 0x0) |= 0x200000;
        *(f32 *)((char *)obj + 0x24) = z;
        *(f32 *)((char *)obj + 0x2c) = z;
    }
    *(s8 *)((char *)state + 0x25f) = 0;
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        *(s16 *)((char *)state + 0x278) = 0x16;
        *(int *)((char *)inner + 0x898) = 0;
    }
    ObjHits_DisableObject(obj);
    *(f32 *)((char *)obj + 0x28) = lbl_803E7EA4;
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        int sel;
        int joint;
        f32 scratch;
        f32 j1[3];
        f32 j0[3];

        if (lbl_803DE44C != NULL && (*(u8 *)((char *)inner + 0x3f4) >> 6 & 1) != 0) {
            *(u8 *)((char *)inner + 0x8b4) = 1;
            *(u8 *)((char *)inner + 0x3f4) |= 8;
        }
        switch (*(s16 *)((char *)sub + 0x46)) {
        case 0x72:
            *(int *)((char *)inner + 0x6e8) = (int)(base + 0x3f0);
            *(u8 *)((char *)inner + 0x6ec) = 3;
            if (coordsToMapCell(*(f32 *)((char *)obj + 0xc), *(f32 *)((char *)obj + 0x14)) == 0x13) {
                GameBit_Set(0xf0a, 1);
            }
            (*(void (*)(int, int, int, int, int, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
                0x45, 1, 0, 0, 0, 0, 0xff);
            break;
        case 0x38c:
            *(int *)((char *)inner + 0x6e8) = (int)(base + 0x3f0);
            *(u8 *)((char *)inner + 0x6ec) = 3;
            (*(void (*)(int, int))(*(int *)(*gCameraInterface + 0x28)))(sub, 0);
            (*(void (*)(int, int, int, int, int, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
                0x45, 1, 0, 0, 0, 0, 0xff);
            break;
        case 0x419:
            *(int *)((char *)inner + 0x6e8) = (int)(base + 0x420);
            (*(void (*)(int, int, int, int, int, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
                0x53, 1, 0, 0, 0, 0x2d, 0xff);
            break;
        case 0x416:
            *(int *)((char *)inner + 0x6e8) = (int)(base + 0x438);
            *(u8 *)((char *)inner + 0x6ec) = 8;
            (*(void (*)(int, int))(*(int *)(*gCameraInterface + 0x28)))(sub, 0);
            (*(void (*)(int, int, int))(*(int *)(*gCameraInterface + 0x24)))(0, 0x69, 0);
            break;
        case 0x8c:
            *(int *)((char *)inner + 0x6e8) = (int)(base + 0x408);
            *(u8 *)((char *)inner + 0x6ec) = 4;
            break;
        default:
            *(int *)((char *)inner + 0x6e8) = (int)(base + 0x420);
            *(u8 *)((char *)inner + 0x6ec) = 4;
            (*(void (*)(int, int, int))(*(int *)(*gCameraInterface + 0x24)))(0, 0x1d, 0);
            break;
        }
        {
            int t = (*(int (*)(int))(*(int *)(*(int *)((char *)sub + 0x68) + 0x24)))(sub);
            (*(void (*)(int, int))(*(int *)(*(int *)((char *)sub + 0x68) + 0x3c)))(sub, 1);
            switch (t) {
            case 1:
                sel = 6;
                break;
            case 2:
                sel = 7;
                break;
            default:
                sel = 7;
                break;
            }
        }
        *(s16 *)((char *)inner + 0x478) = *(s16 *)((char *)sub + 0x0);
        *(s16 *)((char *)inner + 0x484) = *(s16 *)((char *)inner + 0x478);
        ObjAnim_SetCurrentMove(obj, ((s16 *)*(int *)((char *)inner + 0x6e8))[sel],
                               lbl_803E7EA4, 4);
        joint = ((int *)*(int *)((char *)obj + 0x7c))[*(s8 *)((char *)obj + 0xad)];
        ObjModel_SampleJointTransform(joint, 0, 0, lbl_803E7EA4, *(f32 *)((char *)obj + 0x8),
                                      j0, &scratch);
        ObjModel_SampleJointTransform(joint, 0, 0, lbl_803E7EE0, *(f32 *)((char *)obj + 0x8),
                                      j1, &scratch);
        (*(void (*)(int, void *, void *, void *))(*(int *)(*(int *)((char *)sub + 0x68) + 0x28)))(
            sub, &wpos[0], &wpos[1], &wpos[2]);
        wpos[0] = wpos[0] - *(f32 *)((char *)obj + 0xc);
        wpos[1] = wpos[1] - *(f32 *)((char *)obj + 0x10);
        wpos[2] = wpos[2] - *(f32 *)((char *)obj + 0x14);
        *(f32 *)((char *)inner + 0x6b4) = *(f32 *)((char *)obj + 0xc);
        *(f32 *)((char *)inner + 0x6b8) = *(f32 *)((char *)obj + 0x10);
        *(f32 *)((char *)inner + 0x6bc) = *(f32 *)((char *)obj + 0x14);
        *(f32 *)((char *)inner + 0x6c0) = wpos[0];
        *(f32 *)((char *)inner + 0x6c4) = wpos[1] - j1[1];
        *(f32 *)((char *)inner + 0x6c8) = wpos[2];
        *(s16 *)((char *)obj + 0x6) |= 8;
        *(int *)(*(int *)((char *)obj + 0x64) + 0x30) |= 0x1000;
        *(s16 *)(*(int *)((char *)obj + 0x64) + 0x36) = 0;
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7FD8;
    }
    {
        *(f32 *)((char *)obj + 0xc) =
            *(f32 *)((char *)obj + 0x98) * *(f32 *)((char *)inner + 0x6c0) +
            *(f32 *)((char *)inner + 0x6b4);
        *(f32 *)((char *)obj + 0x10) =
            *(f32 *)((char *)obj + 0x98) * *(f32 *)((char *)inner + 0x6c4) +
            *(f32 *)((char *)inner + 0x6b8);
        *(f32 *)((char *)obj + 0x14) =
            *(f32 *)((char *)obj + 0x98) * *(f32 *)((char *)inner + 0x6c8) +
            *(f32 *)((char *)inner + 0x6bc);
        (*(void (*)(int, void *, void *, void *))(*(int *)(*(int *)((char *)sub + 0x68) + 0x34)))(
            sub, &wpos[0], &wpos[1], &wpos[2]);
        (*(void (*)(f32, f32, f32))(*(int *)(*gCameraInterface + 0x2c)))(
            *(f32 *)((char *)obj + 0x98) * (wpos[0] - *(f32 *)((char *)inner + 0x6b4)) +
                *(f32 *)((char *)inner + 0x6b4),
            *(f32 *)((char *)obj + 0x98) * (wpos[1] - *(f32 *)((char *)inner + 0x6b8)) +
                *(f32 *)((char *)inner + 0x6b8),
            *(f32 *)((char *)obj + 0x98) * (wpos[2] - *(f32 *)((char *)inner + 0x6bc)) +
                *(f32 *)((char *)inner + 0x6bc));
    }
    if (*(s8 *)((char *)state + 0x27a) == 0 && *(s8 *)((char *)state + 0x346) != 0) {
        ObjAnim_SetCurrentMove(obj, *(s16 *)*(int *)((char *)inner + 0x6e8), lbl_803E7EA4, 1);
        (*(void (*)(int, int))(*(int *)(*(int *)((char *)sub + 0x68) + 0x3c)))(sub, 2);
        if (arrayIndexOf((s16 *)(base + 0x160), 4, *(s16 *)((char *)sub + 0x46)) != -1) {
            *(int *)((char *)state + 0x308) = (int)fn_8029F67C;
            return 0x1b;
        }
        *(int *)((char *)state + 0x308) = (int)fn_8029F67C;
        return 0x19;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802ABFBC(int obj, int state, int inner)
{
    void *sub;
    f32 dx, dy, dz;
    f32 x1, y1, z1;
    f32 pos2[3];

    *(s16 *)((char *)inner + 0x4d0) =
        (int)((f32)*(s16 *)((char *)inner + 0x4d0) * powfBitEstimate(lbl_803E7FF4, timeDelta));
    sub = *(void **)((char *)inner + 0x4b8);
    if (sub != NULL && *(u8 *)(*(int *)((char *)sub + 0x50) + 0x58) != 0) {
        int d;
        int adj;

        ObjPath_GetPointWorldPosition(obj, 5, &x1, &y1, &z1, 0);
        if (objModelGetVecFn_800395d8((int)sub, 0) != 0) {
            objPosFn_80039510((int)sub, 0, pos2);
        } else {
            pos2[0] = *(f32 *)((char *)sub + 0xc);
            pos2[1] = *(f32 *)((char *)sub + 0x10);
            pos2[2] = *(f32 *)((char *)sub + 0x14);
        }
        dx = pos2[0] - x1;
        dy = pos2[1] - y1;
        dz = pos2[2] - z1;

        d = (u16)getAngle(-dy, sqrtf(dx * dx + dz * dz)) - (u16)*(s16 *)((char *)inner + 0x4d6);
        if (d > 0x8000) d -= 0xffff;
        if (d < -0x8000) d += 0xffff;
        adj = (int)((f32)d * lbl_803E7EB4);
        *(s16 *)((char *)inner + 0x4d6) =
            (int)((f32)adj * timeDelta + (f32)*(s16 *)((char *)inner + 0x4d6));

        d = (u16)getAngle(-dx, -dz) - (u16)*(s16 *)((char *)inner + 0x478);
        if (d > 0x8000) d -= 0xffff;
        if (d < -0x8000) d += 0xffff;
        if (d < -0x1c70) d = -0x1c70;
        else if (d > 0x1c70) d = 0x1c70;
        d -= (u16)*(s16 *)((char *)inner + 0x4d4);
        if (d > 0x8000) d -= 0xffff;
        if (d < -0x8000) d += 0xffff;
        adj = (int)((f32)d * lbl_803E7EB4);
        *(s16 *)((char *)inner + 0x4d4) =
            (int)((f32)adj * timeDelta + (f32)*(s16 *)((char *)inner + 0x4d4));
        *(s16 *)((char *)inner + 0x4d2) = *(s16 *)((char *)inner + 0x4d4) / 2;
    } else {
        *(s16 *)((char *)inner + 0x4d6) =
            (int)((f32)*(s16 *)((char *)inner + 0x4d6) * powfBitEstimate(lbl_803E7F1C, timeDelta));
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_8029CF30(int obj, int state, f32 fv)
{
    int inner = *(int *)((char *)obj + 0xb8);
    f32 t, ang, vx, vy, dx, dy;
    f32 zero = lbl_803E7EA4;
    int r;

    *(f32 *)((char *)state + 0x280) = zero;
    *(f32 *)((char *)state + 0x284) = zero;
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        *(f32 *)((char *)inner + 0x404) = lbl_803E7FC4;
        *(u8 *)((char *)inner + 0x8cc) = 0;
        *(f32 *)((char *)inner + 0x4c8) = zero;
        *(f32 *)((char *)inner + 0x4cc) = zero;
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7F84;
        *(f32 *)((char *)state + 0x294) = zero;
        lbl_803DC66C = 5;
    }

    r = fn_8029B9FC(obj, state, fv);
    if (r != 0) {
        return r;
    }

    t = (*(f32 *)((char *)state + 0x298) - lbl_803E7F14) / lbl_803E7F2C;
    ang = lbl_803E7EA4;
    if (t >= ang) {
        ang = lbl_803E7EE0;
        if (t <= ang) ang = t;
    }
    vx = *(f32 *)((char *)inner + 0x404) *
         (ang * -fn_80293E80(lbl_803E7F94 * (f32)*(int *)((char *)inner + 0x474) / lbl_803E7F98));
    vy = *(f32 *)((char *)inner + 0x404) *
         (ang * -sin(lbl_803E7F94 * (f32)*(int *)((char *)inner + 0x474) / lbl_803E7F98));
    dx = interpolate(vx - *(f32 *)((char *)inner + 0x4c8), lbl_803E7F44, timeDelta);
    dy = interpolate(vy - *(f32 *)((char *)inner + 0x4cc), lbl_803E7F44, timeDelta);
    *(f32 *)((char *)inner + 0x4c8) += dx;
    *(f32 *)((char *)inner + 0x4cc) += dy;
    *(f32 *)((char *)state + 0x294) =
        sqrtf(*(f32 *)((char *)inner + 0x4c8) * *(f32 *)((char *)inner + 0x4c8) +
              *(f32 *)((char *)inner + 0x4cc) * *(f32 *)((char *)inner + 0x4cc));
    {
        f32 d = *(f32 *)((char *)state + 0x294);
        f32 c = lbl_803E7EA4;
        if (d >= c) {
            c = *(f32 *)((char *)inner + 0x404);
            if (d <= c) c = d;
        }
        *(f32 *)((char *)state + 0x294) = c;
    }

    if (*(f32 *)((char *)state + 0x29c) >= lbl_803E7FC8 &&
        *(f32 *)((char *)state + 0x298) >= lbl_803E7FC8 &&
        *(f32 *)((char *)state + 0x294) >= lbl_80332FC0[1]) {
        *(int *)((char *)state + 0x308) = (int)fn_8029C8C8;
        return 0x26;
    }

    if (*(s16 *)((char *)obj + 0xa0) != 0x8c) {
        ObjAnim_SetCurrentMove(obj, 0x8c, lbl_803E7EA4, 0);
        if (*(s16 *)((char *)state + 0x276) == 0x39) {
            ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent *)obj, 8);
        }
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7F84;
    }

    *(s16 *)((char *)inner + 0x478) += (int)((f32)*(int *)((char *)inner + 0x4a4) / lbl_803E7FC0);
    *(s16 *)((char *)inner + 0x484) = *(s16 *)((char *)inner + 0x478);
    *(u32 *)((char *)inner + 0x360) |= 0x2000000;
    fn_802ABFBC(obj, state, inner);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_80295334(int a, int b, f32 *vec, int c, int mode, f32 angle)
{
    f32 mtx1[12];
    f32 mtx2[12];

    switch (lbl_803DC66C) {
    case 0:
        lbl_803DC670 = lbl_803E7E80;
        lbl_803DC674 = lbl_803E7E84;
        lbl_803DC678 = lbl_803E7E88;
        break;
    case 1:
        lbl_803DC670 = lbl_803E7E80;
        lbl_803DC674 = lbl_803E7E84;
        lbl_803DC678 = lbl_803E7E88;
        PSMTXRotRad(mtx1, 0x79, lbl_803E7E8C * fn_802943F4(lbl_803E7E90 * angle - lbl_803E7E94 * (f32)mode));
        PSMTXMultVecSR(mtx1, vec, vec);
        break;
    case 4:
        lbl_803DC670 = lbl_803E7E98;
        lbl_803DC674 = lbl_803E7E84;
        lbl_803DC678 = lbl_803E7E88;
        PSMTXRotRad(mtx1, 0x79, lbl_803E7E8C * fn_802943F4(lbl_803E7E90 * angle - lbl_803E7E94 * (f32)mode));
        PSMTXMultVecSR(mtx1, vec, vec);
        break;
    case 5:
        lbl_803DC670 = lbl_803E7E9C;
        lbl_803DC674 = lbl_803E7E84;
        lbl_803DC678 = lbl_803E7E88;
        PSMTXRotRad(mtx1, 0x79, lbl_803E7E8C * fn_802943F4(lbl_803E7E90 * angle - lbl_803E7E94 * (f32)mode));
        PSMTXMultVecSR(mtx1, vec, vec);
        break;
    case 2:
        lbl_803DC670 = lbl_803E7EA0;
        lbl_803DC674 = lbl_803E7EA4;
        lbl_803DC678 = lbl_803E7EA8;
        PSMTXRotRad(mtx1, 0x79, lbl_803E7EAC * fn_802943F4(lbl_803E7E98 * angle));
        PSMTXRotRad(mtx2, 0x78, lbl_803E7EB0);
        PSMTXConcat(mtx2, mtx1, mtx1);
        PSMTXMultVecSR(mtx1, vec, vec);
        break;
    case 3:
        lbl_803DC670 = lbl_803E7E80;
        lbl_803DC674 = lbl_803E7E84;
        lbl_803DC678 = lbl_803E7E88;
        PSMTXRotRad(mtx1, 0x79, lbl_803E7EB4 * fn_802943F4(lbl_803E7EB4 * angle - lbl_803E7EB8 * (f32)mode));
        if (mode == 1) {
            PSMTXRotRad(mtx2, 0x78, lbl_803E7EBC);
            PSMTXConcat(mtx2, mtx1, mtx1);
        }
        PSMTXMultVecSR(mtx1, vec, vec);
        break;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802AA014(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int slot = Camera_GetCurrentViewSlot();

    if (Obj_IsLoadingLocked()) {
        int setup = Obj_AllocObjectSetup(0x24, 0x14b);
        void *o;
        f32 v[3];

        *(u8 *)((char *)setup + 4) = 2;
        *(u8 *)((char *)setup + 5) = 1;
        *(u8 *)((char *)setup + 6) = 0xff;
        *(u8 *)((char *)setup + 7) = 0xff;
        *(f32 *)((char *)setup + 8) = *(f32 *)((char *)slot + 0xc);
        *(f32 *)((char *)setup + 0xc) = *(f32 *)((char *)slot + 0x10);
        *(f32 *)((char *)setup + 0x10) = *(f32 *)((char *)slot + 0x14);
        Sfx_PlayFromObject(obj, SFXmammoth_suck);
        o = (void *)Obj_SetupObject(setup, 5, -1, -1, 0);
        if (o != NULL) {
            f32 fov, cot, aspect, ycomp, xcomp, len;
            int res, h2, hw;

            *(s16 *)((char *)o + 6) |= 0x2000;
            res = getScreenResolution();
            hw = res >> 17;
            *(s16 *)((char *)o + 0) = *(s16 *)((char *)slot + 0);
            fov = (lbl_803E7F94 * (Camera_GetFovY() * lbl_803E80D4)) / lbl_803E7F98;
            cot = lbl_803E7F5C * (fn_80293E80(fov) / sin(fov));
            aspect = Camera_GetAspectRatio();
            h2 = (u16)res >> 1;
            ycomp = cot * -(((*(f32 *)((char *)inner + 0x788) - (f32)h2) / (f32)h2) * aspect);
            xcomp = cot * ((*(f32 *)((char *)inner + 0x78c) - (f32)hw) / (f32)hw);
            len = sqrtf(lbl_803E80AC + (ycomp * ycomp + xcomp * xcomp));
            v[0] = ycomp / len;
            v[1] = xcomp / len;
            v[2] = lbl_803E7F5C / len;
            Matrix_TransformVector(fn_8000E814(), v, v);
            *(f32 *)((char *)o + 0x24) = v[0] * lbl_803E80D8;
            *(f32 *)((char *)o + 0x28) = v[1] * lbl_803E80D8;
            *(f32 *)((char *)o + 0x2c) = v[2] * lbl_803E80D8;
            *(f32 *)((char *)o + 0xc) = *(f32 *)((char *)o + 0x18) =
                lbl_803E7ED4 * *(f32 *)((char *)o + 0x24) + *(f32 *)((char *)slot + 0xc);
            *(f32 *)((char *)o + 0x10) = *(f32 *)((char *)o + 0x1c) =
                lbl_803E7ED4 * *(f32 *)((char *)o + 0x28) + *(f32 *)((char *)slot + 0x10);
            *(f32 *)((char *)o + 0x14) = *(f32 *)((char *)o + 0x20) =
                lbl_803E7ED4 * *(f32 *)((char *)o + 0x2c) + *(f32 *)((char *)slot + 0x14);
            *(s16 *)((char *)o + 2) = *(s16 *)((char *)slot + 2) / 2;
            *(s16 *)((char *)o + 0) = -*(s16 *)((char *)slot + 0);
            *(int *)((char *)o + 0xf4) = 0x64;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void playerUpdatePathEffectCountdown(int obj, int inner)
{
    f32 outvec[3];
    struct {
        u8 pad[0xc];
        f32 x;
        f32 y;
        f32 z;
    } buf;
    f32 mtx[12];
    u8 cnt = *(u8 *)((char *)inner + 0x8b1);

    if (cnt != 0) {
        if (cnt & 1) {
            int t;
            memcpy(mtx, (void *)ObjPath_GetPointModelMtx(obj, 5), 0x30);
            mtx[3] = lbl_803E7EA4;
            mtx[7] = lbl_803E7EA4;
            mtx[11] = lbl_803E7EA4;
            buf.x = lbl_803E7EA4;
            buf.y = lbl_803E7EA4;
            t = *(u8 *)((char *)inner + 0x8b1);
            buf.z = lbl_803E7EC8 * (f32)(int)randomGetRange(t + 4, t + 8);
            PSMTXMultVec(mtx, &buf.x, outvec);
            buf.x = lbl_803E7EA4;
            buf.y = lbl_803E7ECC;
            buf.z = lbl_803E7ED0;
            ObjPath_GetPointWorldPosition(obj, 0xa, &buf.x, &buf.y, &buf.z, 1);
            (**(void (**)(int, int, void *, int, int, int))((char *)(*gPartfxInterface) + 0x8))(
                obj, 0x7e5, &buf, 0x200001, -1, (int)outvec);
        }
        *(u8 *)((char *)inner + 0x8b1) -= 1;
    }
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802AAF80(int obj, int inner, int a, int b, int c)
{
    int v;
    if (lbl_803DE44C != NULL && ((*(u8 *)((char *)inner + 0x3f4) >> 6) & 1) != 0) {
        (*(void (*)(int, int, int, int, void *))(*(int *)(*gModgfxInterface + 0x1c)))(
            a, b, c, 1, lbl_803DE44C);
    }
    if (*(s16 *)((char *)inner + 0x81c) != 0) {
        (*(void (*)(int, int, int, int, int))(*(int *)(*lbl_803DCAB4 + 0xc)))(
            obj, *(s16 *)((char *)inner + 0x81c), 0, 0x64, 0);
    }
    *(s16 *)((char *)inner + 0x81c) = 0;
    if (*(u8 *)((char *)inner + 0x8ca) == 1) {
        fn_802AA8D0(obj);
    }
    if ((*(int (**)(int))((char *)(*gSHthorntailAnimationInterface) + 0x34))(2) != 0) {
        playerUpdatePathEffectCountdown(obj, inner);
    }
    v = *(int *)((char *)inner + 0x360);
    if ((v & 0x60000) != 0) {
        *(f32 *)((char *)lbl_803DAEF0 + 0xc) = *(f32 *)((char *)obj + 0xc);
        *(f32 *)((char *)lbl_803DAEF0 + 0x10) = *(f32 *)((char *)obj + 0x10);
        *(f32 *)((char *)lbl_803DAEF0 + 0x14) = *(f32 *)((char *)obj + 0x14);
        if ((v & 0x40000) != 0) {
            (**(void (**)(int, int, void *, int, int, int))((char *)(*gPartfxInterface) + 0x8))(
                obj, 0x427, lbl_803DAEF0, 0x200001, -1, 0);
            (**(void (**)(int, int, void *, int, int, int))((char *)(*gPartfxInterface) + 0x8))(
                obj, 0x427, lbl_803DAEF0, 0x200001, -1, 0);
            (**(void (**)(int, int, void *, int, int, int))((char *)(*gPartfxInterface) + 0x8))(
                obj, 0x427, lbl_803DAEF0, 0x200001, -1, 0);
        }
        if ((*(int *)((char *)inner + 0x360) & 0x20000) != 0) {
            (*(void (*)(int, f32, f32, f32, f32))(*(int *)(*gWaterfxInterface + 0x10)))(
                obj, *(f32 *)((char *)obj + 0xc),
                (*(f32 *)((char *)obj + 0x10) + *(f32 *)((char *)inner + 0x838)) - lbl_803E7F10,
                *(f32 *)((char *)obj + 0x14), lbl_803E7FFC);
            (*(void (*)(int, int, f32, f32, f32, f32))(*(int *)(*gWaterfxInterface + 0x14)))(
                0, 2, *(f32 *)((char *)obj + 0xc),
                *(f32 *)((char *)obj + 0x10) + *(f32 *)((char *)inner + 0x838),
                *(f32 *)((char *)obj + 0x14), lbl_803E80E4);
            *(int *)((char *)inner + 0x360) &= ~0x20000;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802AE650(int obj, int state, int p3)
{
    f32 v;
    u32 b;

    (*(void (*)(int, int, int, f32))(*(int *)(*gPlayerInterface + 0x20)))(obj, p3, 1, timeDelta);
    if (*(f32 *)((char *)obj + 0x98) >=
        lbl_803E7EE0 - lbl_803E7F50 * *(f32 *)((char *)p3 + 0x2a0)) {
        *(f32 *)((char *)p3 + 0x280) =
            *(f32 *)((char *)state + 0x844) *
                ((lbl_803E7F14 + *(f32 *)((char *)*(int *)((char *)state + 0x400) + 0x14)) -
                 *(f32 *)((char *)p3 + 0x280)) +
            *(f32 *)((char *)p3 + 0x280);
        *(f32 *)((char *)p3 + 0x294) = *(f32 *)((char *)p3 + 0x280);
        *(f32 *)((char *)state + 0x844) =
            lbl_803E7EFC * timeDelta + *(f32 *)((char *)state + 0x844);
        v = *(f32 *)((char *)state + 0x844);
        if (v < lbl_803E7EA4) {
            v = lbl_803E7EA4;
        } else if (v > lbl_803E7EE0) {
            v = lbl_803E7EE0;
        }
        *(f32 *)((char *)state + 0x844) = v;
    }
    if ((*(int *)((char *)p3 + 0x314) & 0x200) != 0) {
        doRumble(lbl_803E7F10);
        Sfx_PlayFromObject(obj, 0x3cd);
        *(u16 *)((char *)state + 0x8d8) |= 4;
    }
    *(f32 *)((char *)state + 0x428) = lbl_803E7FA4;
    *(f32 *)((char *)state + 0x430) = lbl_803E7FA4;
    b = (*(u8 *)((char *)state + 0x3f1) >> 4) & 1;
    if (b != 0) {
        *(f32 *)((char *)state + 0x42c) = lbl_803E7EA4;
        *(f32 *)((char *)state + 0x434) = lbl_803E7EA4;
    } else {
        *(f32 *)((char *)state + 0x42c) = lbl_803E7ED4;
        *(f32 *)((char *)state + 0x434) = lbl_803E7ED4;
    }
    *(f32 *)((char *)state + 0x7a4) = lbl_803E80E4;
    if (*(f32 *)((char *)obj + 0x98) >= lbl_803E7EE0) {
        short tmp;
        ((ByteFlags *)((char *)state + 0x3f0))->b10 = 0;
        lbl_803DC66C = 1;
        ((ByteFlags *)((char *)state + 0x3f1))->b02 = 1;
        ((ByteFlags *)((char *)state + 0x3f1))->b08 = 1;
        *(u8 *)((char *)state + 0x8cc) = 0xc;
        tmp = *(s16 *)((char *)state + 0x484);
        *(s16 *)((char *)state + 0x478) = tmp;
        *(int *)((char *)state + 0x494) = tmp;
        ObjAnim_SetCurrentMove(obj, ((s16 *)lbl_80333050)[(s8)*(u8 *)((char *)state + 0x8cc)],
                               lbl_803E7EA4, 0);
        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent *)obj, 1);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802AA2B0(int obj, int state, f32 unused, f32 yoff)
{
    int slot = Camera_GetCurrentViewSlot();
    int setup;
    f32 x1, y1, z1, x0, y0, z0;
    f32 dx, dy, dz, len;

    if (Obj_IsLoadingLocked() != 0) {
        Sfx_PlayFromObject(0, SFXmammoth_suck);
        setup = Obj_AllocObjectSetup(0x24, 0x655);
        *(u8 *)((char *)setup + 4) = 2;
        *(u8 *)((char *)setup + 5) = 1;
        *(u8 *)((char *)setup + 6) = 0xff;
        *(u8 *)((char *)setup + 7) = 0xff;
        ObjPath_GetPointWorldPosition((int)lbl_803DE44C, 0, &x0, &y0, &z0, 0);
        *(f32 *)((char *)setup + 8) = x0 + yoff;
        *(f32 *)((char *)setup + 0xc) = y0 + yoff;
        *(f32 *)((char *)setup + 0x10) = z0 + yoff;
        setup = Obj_SetupObject(setup, 5, -1, -1, 0);
        if (setup != 0) {
            ObjPath_GetPointWorldPosition((int)lbl_803DE44C, 0, &x0, &y0, &z0, 0);
            ObjPath_GetPointWorldPosition((int)lbl_803DE44C, 1, &x1, &y1, &z1, 0);
            dx = x0 - x1;
            dy = y0 - y1;
            dz = z0 - z1;
            len = sqrtf(dx * dx + dy * dy + dz * dz);
            dx = dx / len;
            dy = dy / len;
            dz = dz / len;
            *(s16 *)((char *)setup + 0) = (s16)getAngle(dx, dz);
            *(s16 *)((char *)setup + 2) = (s16)(-getAngle(dy, sqrtf(dx * dx + dz * dz)));
            *(f32 *)((char *)setup + 8) = *(f32 *)((char *)setup + 8) * lbl_803E7EF0;
            arwprojectile_placeForward(setup, lbl_803E7ED8);
            arwprojectile_setLifetime(setup, 0x32);
            if (slot == 1) {
                arwprojectile_createLinkedEffect(setup, 1);
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802AED2C(int obj, int state, int p3)
{
    u16 sound;
    u32 b;

    if (*(u8 *)((char *)state + 0x8b3) != 0) {
        ObjAnim_SetCurrentMove(obj, 0x47f, lbl_803E7EA4, 0);
    } else {
        ObjAnim_SetCurrentMove(obj, 0x47b, lbl_803E7EA4, 0);
    }
    *(f32 *)((char *)p3 + 0x2a0) = lbl_803E7F20;
    *(s16 *)((char *)state + 0x478) = *(s16 *)((char *)state + 0x484);
    *(f32 *)((char *)state + 0x844) = lbl_803E7EA4;
    ((ByteFlags *)((char *)state + 0x3f0))->b10 = 1;
    ((ByteFlags *)((char *)state + 0x3f0))->b80 = 0;
    staffFn_80170380(lbl_803DE450, 2);
    ((ByteFlags *)((char *)state + 0x3f0))->b02 = 0;
    *(int *)((char *)state + 0x360) |= 0x800000;
    ObjHits_SyncObjectPositionIfDirty(obj);
    ((ByteFlags *)((char *)state + 0x3f0))->b08 = 0;
    ((ByteFlags *)((char *)state + 0x3f0))->b04 = 0;
    *(u8 *)((char *)state + 0x40d) = 0;
    ((ByteFlags *)((char *)state + 0x3f0))->b40 = 0;
    *(int *)((char *)state + 0x488) = 0;
    *(int *)((char *)state + 0x47c) = 0;
    *(int *)((char *)state + 0x48c) = 0;
    *(int *)((char *)state + 0x480) = 0;
    lbl_803DC66C = 4;
    *(u8 *)((char *)state + 0x800) = 0;
    if (*(void **)((char *)state + 0x7f8) != NULL) {
        short id = *(s16 *)((char *)*(int *)((char *)state + 0x7f8) + 0x46);
        if (id == 0x3cf || id == 0x662) {
            objThrowFn_80182504(*(int *)((char *)state + 0x7f8));
        } else {
            objSaveFn_800ea774(*(int *)((char *)state + 0x7f8));
        }
        *(s16 *)((char *)*(int *)((char *)state + 0x7f8) + 6) &= ~0x4000;
        *(int *)((char *)*(int *)((char *)state + 0x7f8) + 0xf8) = 0;
        *(int *)((char *)state + 0x7f8) = 0;
    }
    b = (*(u8 *)((char *)state + 0x3f1) >> 5) & 1;
    if (b != 0) {
        short t = *(s16 *)((char *)obj + 0);
        *(s16 *)((char *)state + 0x484) = t;
        *(s16 *)((char *)state + 0x478) = t;
        *(int *)((char *)state + 0x494) = t;
        *(f32 *)((char *)state + 0x284) = lbl_803E7EA4;
    }
    ((ByteFlags *)((char *)state + 0x3f1))->b20 = 0;
    if (*(f32 *)((char *)state + 0x838) > lbl_803E7EE0) {
        if (*(s16 *)((char *)state + 0x81a) == 0) {
            sound = 0x427;
        } else {
            sound = 0x427;
        }
        Sfx_PlayFromObject(obj, sound);
    } else {
        if (*(s16 *)((char *)state + 0x81a) == 0) {
            sound = 0x3ce;
        } else {
            sound = 0x2e;
        }
        Sfx_PlayFromObject(obj, sound);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int Lightfoot_UpdateRandomTurn(int obj, int state, f32 fv)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        Sfx_PlayFromObject(obj, *(u16 *)((char *)*(int *)((char *)inner + 0x40c) + 0x2a));
        if (randomGetRange(0, 1) != 0) {
            *(s16 *)((char *)obj + 0) += 0x8AA9;
        } else {
            *(s16 *)((char *)obj + 0) -= 0x8AA9;
        }
        ObjAnim_SetCurrentMove(obj, 0x23, lbl_803E8180, 0);
    }
    *(f32 *)((char *)state + 0x2a0) = lbl_803E81A8;
    (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x20)))(obj, state, fv, 1);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int Lightfoot_UpdateTargetAnimationCycle(int obj, int state, f32 fv)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int a4 = *(int *)((char *)inner + 0x40c);
    void *p = *(void **)((char *)state + 0x2d0);
    if (p != NULL) {
        fn_8003B0D0(obj, (int)p, inner + 0x3ac, 0x19);
    }
    if (*(s8 *)((char *)state + 0x346) != 0 || *(s8 *)((char *)state + 0x27a) != 0) {
        int q = *(int *)((char *)obj + 0x4c);
        *(f32 *)((char *)obj + 0xc) = *(f32 *)((char *)q + 0x8);
        *(f32 *)((char *)obj + 0x14) = *(f32 *)((char *)q + 0x10);
        *(u16 *)((char *)a4 + 0x24) += 1;
        if (lbl_80334F9C[*(u16 *)((char *)a4 + 0x24)] == -1) {
            *(u16 *)((char *)a4 + 0x24) = 0;
        }
        ObjAnim_SetCurrentMove(obj, lbl_80334F9C[*(u16 *)((char *)a4 + 0x24)], lbl_803E8180, 0);
    }
    *(f32 *)((char *)state + 0x2a0) = lbl_80334FAC[*(u16 *)((char *)a4 + 0x24)];
    (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x20)))(obj, state, fv, 1);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int Lightfoot_UpdateButtonTimingChallenge(int obj, int state, f32 fv)
{
    EmitCtrlTbl *t = (EmitCtrlTbl *)lbl_80334EE8;
    int inner = *(int *)((char *)obj + 0xb8);
    int data = *(int *)((char *)inner + 0x40c);
    void *p = *(void **)((char *)state + 0x2d0);
    if (p != NULL) {
        fn_8003B0D0(obj, (int)p, inner + 0x3ac, 0x19);
    }
    if (*(int *)((char *)obj + 0xf8) == 0) {
        *(u16 *)((char *)data + 0x1a) = *(u16 *)((char *)data + 0x1c);
        *(u16 *)((char *)data + 0x1c) = *(u16 *)((char *)data + 0x18);
        *(s16 *)((char *)data + 0x18) += (int)(lbl_803E81AC * timeDelta);
    }
    if (*(u16 *)((char *)data + 0x24) < 4) {
        int v = (s16)(int)(lbl_803E81B0 *
                           fn_80293E80(lbl_803E81B4 * (f32)*(u16 *)((char *)data + 0x18) /
                                       lbl_803E81B8));
        int w = (u16)(int)(lbl_803E81B0 * t->scales[*(u8 *)((char *)data + 0x2d)]);
        if (*(int *)((char *)obj + 0xf8) == 0) {
            if ((s16)*(u16 *)((char *)data + 0x1c) * (s16)*(u16 *)((char *)data + 0x18) < 0) {
                Sfx_PlayFromObject(0, 0x44c);
            }
        }
        setAButtonIcon(6);
        fearTestMeterSetRange(0x60, (u8)w, v);
        if ((((u32 (*)(int))getButtonsJustPressed)(0) & 0x100) && *(int *)((char *)obj + 0xf8) == 0) {
            int a = v < 0 ? -v : v;
            if (a <= w) {
                Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
                *(int *)((char *)obj + 0xf8) = 2;
            } else {
                Sfx_PlayFromObject(0, 0x487);
                *(int *)((char *)obj + 0xf8) = 3;
            }
            fn_8011F6D4(0);
        }
    } else {
        fn_8011F6D4(0);
    }
    if (*(s8 *)((char *)state + 0x346) != 0 || *(s8 *)((char *)state + 0x27a) != 0) {
        int q;
        if (*(s8 *)((char *)state + 0x27a) != 0) {
            int i;
            *(u8 *)((char *)data + 0x2d) = 0;
            for (i = 0; i < 8; i++) {
                if (GameBit_Get(t->bits[i]) != 0) {
                    *(u8 *)((char *)data + 0x2d) += 1;
                }
            }
            *(u16 *)((char *)data + 0x18) = (u16)randomGetRange(0, 0xffff);
            *(u16 *)((char *)data + 0x1c) = *(u16 *)((char *)data + 0x18);
            *(u16 *)((char *)data + 0x1a) = *(u16 *)((char *)data + 0x1c);
            fearTestMeterSetRange(0x60,
                        (u8)(int)(lbl_803E81BC * t->scales[*(u8 *)((char *)data + 0x2d)]),
                        (int)(lbl_803E81B0 *
                              fn_80293E80(lbl_803E81B4 * (f32)*(u16 *)((char *)data + 0x18) /
                                          lbl_803E81B8)));
            fn_8011F6D4(1);
            setAButtonIcon(6);
        }
        q = *(int *)((char *)obj + 0x4c);
        if (*(s8 *)((char *)state + 0x27a) != 0) {
            *(u16 *)((char *)data + 0x24) = 0;
            *(f32 *)((char *)obj + 0xc) = *(f32 *)((char *)q + 0x8);
            *(f32 *)((char *)obj + 0x14) = *(f32 *)((char *)q + 0x10);
        } else {
            *(u16 *)((char *)data + 0x24) += 1;
        }
        if (t->anims[*(u16 *)((char *)data + 0x24)] == -1) {
            *(u16 *)((char *)data + 0x24) = 0;
            *(f32 *)((char *)obj + 0xc) = *(f32 *)((char *)q + 0x8);
            *(f32 *)((char *)obj + 0x14) = *(f32 *)((char *)q + 0x10);
            GameBit_Set(*(s16 *)((char *)q + 0x1a), 1);
            GameBit_Set(*(s16 *)((char *)q + 0x30), 0);
            return 3;
        }
        ObjAnim_SetCurrentMove(obj, t->anims[*(u16 *)((char *)data + 0x24)], lbl_803E8180, 0);
    }
    *(f32 *)((char *)state + 0x2a0) = t->blends[*(u16 *)((char *)data + 0x24)];
    (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x20)))(obj, state, fv, 1);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int Lightfoot_UpdateCompletionInteraction(int obj, int state)
{
    int data = *(int *)((char *)obj + 0x4c);
    int inner = *(int *)((char *)obj + 0xb8);
    int a4 = *(int *)((char *)inner + 0x40c);
    if (*(s8 *)((char *)state + 0x27b) != 0 || *(s8 *)((char *)state + 0x346) != 0) {
        if (GameBit_Get(*(s16 *)((char *)data + 0x1c)) != 0) {
            *(u8 *)((char *)inner + 0x404) |= 1;
        }
        if ((*(u8 *)((char *)inner + 0x404) & 1) != 0) {
            if (*(s16 *)((char *)state + 0x274) != 3) {
                *(u8 *)((char *)a4 + 0x2c) = 4;
                (*(void (*)(int, int, int))(*(int *)(*gPlayerInterface + 0x14)))(obj, state, 3);
            }
            if (*(u8 *)((char *)a4 + 0x2c) != 0) {
                *(u8 *)((char *)a4 + 0x2c) -= 1;
                if (*(u8 *)((char *)a4 + 0x2c) == 0) {
                    GameBit_Set(*(s16 *)((char *)data + 0x1a), 1);
                    GameBit_Set(*(s16 *)((char *)data + 0x30), 0);
                    *(u8 *)((char *)obj + 0x36) = 0;
                    *(s16 *)((char *)obj + 0x6) |= 0x4000;
                    *(f32 *)((char *)a4 + 0x8) = lbl_803E8178;
                    *(f32 *)((char *)a4 + 0x10) = lbl_803E817C;
                }
            }
        } else {
            if (*(s16 *)((char *)state + 0x274) != 1) {
                if (GameBit_Get(*(s16 *)((char *)data + 0x30)) != 0) {
                    (*(void (*)(int, int, int))(*(int *)(*gPlayerInterface + 0x14)))(obj, state, 1);
                }
            }
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int Lightfoot_UpdateAnimationCycle(int obj, int state, f32 fv)
{
    int inner = *(int *)((char *)obj + 0xb8);
    void *p = *(void **)((char *)state + 0x2d0);
    int a4;
    s16 *moves;
    f32 *blends;
    if (p != NULL) {
        fn_8003B0D0(obj, (int)p, inner + 0x3ac, 0x19);
    }
    a4 = *(int *)((char *)inner + 0x40c);
    moves = *(s16 **)((char *)a4 + 0);
    blends = *(f32 **)((char *)a4 + 4);
    if (*(s8 *)((char *)state + 0x27a) != 0 || *(s8 *)((char *)state + 0x346) != 0) {
        *(u8 *)((char *)a4 + 0x2c) = 0;
        *(u16 *)((char *)a4 + 0x24) += 1;
        if (moves[*(u16 *)((char *)a4 + 0x24)] == -1) {
            *(u16 *)((char *)a4 + 0x24) = 0;
        }
        if (*(s8 *)((char *)state + 0x27a) != 0) {
            *(f32 *)((char *)obj + 0x98) = (f32)randomGetRange(0, 0x63) / lbl_803E817C;
            ObjAnim_SetCurrentMove(obj, moves[*(u16 *)((char *)a4 + 0x24)], *(f32 *)((char *)obj + 0x98), 0);
        } else {
            ObjAnim_SetCurrentMove(obj, moves[*(u16 *)((char *)a4 + 0x24)], lbl_803E8180, 0);
        }
    }
    *(f32 *)((char *)state + 0x2a0) = blends[*(u16 *)((char *)a4 + 0x24)];
    (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x20)))(obj, state, fv, 0);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802AB38C(int a, int b, int c)
{
    switch (c) {
    case 0x2d:
        lbl_803DE4B2 = 0x2d;
        break;
    case 0x958:
        lbl_803DE4B2 = 0x958;
        break;
    case 0x5ce:
        lbl_803DE4B2 = 0x5ce;
        break;
    case 0x957:
        lbl_803DE434 = *(int *)((char *)b + 0x4b8);
        (*(void (*)(int, int, int))(*(int *)(*gPlayerInterface + 0x14)))(a, b, 0x32);
        *(int *)((char *)b + 0x304) = (int)fn_802994A4;
        break;
    case 0x107:
    case 0xc55:
        (*(void (*)(int, int, int))(*(int *)(*gPlayerInterface + 0x14)))(a, b, 0x36);
        *(int *)((char *)b + 0x304) = (int)fn_802985AC;
        break;
    case 0x40:
        *(f32 *)((char *)b + 0x854) = lbl_803E7EDC;
        {
            int sub = *(int *)((char *)*(int *)((char *)a + 0xb8) + 0x35c);
            int v = *(s16 *)((char *)sub + 0x4) - 0xa;
            if (v < 0) {
                v = 0;
            } else if (v > *(s16 *)((char *)sub + 0x6)) {
                v = *(s16 *)((char *)sub + 0x6);
            }
            *(s16 *)((char *)sub + 0x4) = v;
        }
        fn_80295E90(a, 1);
        Sfx_PlayFromObject(a, SFXmammoth_annoyed);
        break;
    case 0x5bd:
        c = -1;
        {
            int sub = *(int *)((char *)*(int *)((char *)a + 0xb8) + 0x35c);
            int v = *(s16 *)((char *)sub + 0x4) - 0x14;
            if (v < 0) {
                v = 0;
            } else if (v > *(s16 *)((char *)sub + 0x6)) {
                v = *(s16 *)((char *)sub + 0x6);
            }
            *(s16 *)((char *)sub + 0x4) = v;
        }
        {
            void *cam = (*(void *(*)(void))(*(int *)(*gCameraInterface + 0x40)))();
            if (cam != NULL) {
                s16 id = *(s16 *)((char *)cam + 0x46);
                if (id == 0x414 || id == 0x4a9) {
                    c = 0x5bd;
                    getAngle(*(f32 *)((char *)*(int *)((char *)cam + 0x74)) - *(f32 *)((char *)a + 0xc),
                             *(f32 *)((char *)*(int *)((char *)cam + 0x74) + 0x8) - *(f32 *)((char *)a + 0x14));
                }
            }
        }
        break;
    }
    *(s16 *)((char *)b + 0x80a) = c;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802A514C(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);
    ((ByteFlags *)((char *)inner + 0x3f1))->b80 = 0;
    {
        s16 mode = *(s16 *)((char *)state + 0x274);
        if (mode != 2 && mode != 1 && mode != 5 && mode != 7 && mode != 6) {
            void *sub;
            *(u8 *)((char *)inner + 0x800) = 0;
            sub = *(void **)((char *)inner + 0x7f8);
            if (sub != NULL) {
                s16 id = *(s16 *)((char *)sub + 0x46);
                if (id == 0x3cf || id == 0x662) {
                    objThrowFn_80182504((int)sub);
                } else {
                    objSaveFn_800ea774((int)sub);
                }
                *(s16 *)((char *)*(int *)((char *)inner + 0x7f8) + 0x6) &= ~0x4000;
                *(int *)((char *)*(int *)((char *)inner + 0x7f8) + 0xf8) = 0;
                *(int *)((char *)inner + 0x7f8) = 0;
            }
        }
    }
    {
        s16 mode = *(s16 *)((char *)state + 0x274);
        if (mode != 2 && mode != 1) {
            ((ByteFlags *)((char *)inner + 0x3f0))->b10 = 0;
            ((ByteFlags *)((char *)inner + 0x3f0))->b80 = 0;
            ((ByteFlags *)((char *)inner + 0x3f0))->b40 = 0;
            ((ByteFlags *)((char *)inner + 0x3f0))->b08 = 0;
            ((ByteFlags *)((char *)inner + 0x3f0))->b04 = 0;
            *(u8 *)((char *)inner + 0x40d) = 0;
            ((ByteFlags *)((char *)inner + 0x3f0))->b20 = 0;
            if (((ByteFlags *)((char *)inner + 0x3f1))->b20) {
                s16 t = *(s16 *)((char *)obj + 0);
                *(s16 *)((char *)inner + 0x484) = t;
                *(s16 *)((char *)inner + 0x478) = t;
                *(int *)((char *)inner + 0x494) = t;
                *(f32 *)((char *)inner + 0x284) = lbl_803E7EA4;
            }
            ((ByteFlags *)((char *)inner + 0x3f1))->b20 = 0;
            if (((ByteFlags *)((char *)inner + 0x3f1))->b10) {
                u8 anim = *(u8 *)((char *)inner + 0x8c8);
                if (anim != 0x48 && anim != 0x47 && getCurSeqNo() == 0) {
                    (*(void (*)(int, int, int, int, int, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
                        0x42, 0, 1, 0, 0, 0x1e, 0xff);
                    ((ByteFlags *)((char *)inner + 0x3f1))->b10 = 0;
                }
            }
            *(int *)((char *)inner + 0x360) &= ~0x2000000;
        }
    }
    if (*(s16 *)((char *)state + 0x274) != 2) {
        staffFn_80170380(lbl_803DE450, 2);
        ((ByteFlags *)((char *)inner + 0x3f0))->b02 = 0;
        *(int *)((char *)inner + 0x360) |= 0x800000;
        ObjHits_SyncObjectPositionIfDirty(obj);
    }
    lbl_803DC66C = 1;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802A4D34(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);
    *(f32 *)((char *)state + 0x284) = lbl_803E7EA4;
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        if (lbl_803DE44C != NULL) {
            if (((ByteFlags *)((char *)inner + 0x3f4))->b40) {
                *(u8 *)((char *)inner + 0x8b4) = 1;
                ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 1;
            }
        }
        *(s16 *)((char *)state + 0x278) = 1;
        *(int *)((char *)inner + 0x898) = (int)fn_802A514C;
    }
    if (*(s16 *)((char *)obj + 0xa0) == 5) {
        void *sub;
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7F40;
        *(f32 *)((char *)state + 0x280) = lbl_803E7EA4;
        sub = *(void **)((char *)inner + 0x7f8);
        if (sub != NULL) {
            f32 amt;
            if (*(f32 *)((char *)obj + 0x98) > lbl_803E7E98) {
                *(int *)((char *)sub + 0xf8) = 1;
            }
            amt = interpolate((f32)*(int *)((char *)inner + 0x4a4), lbl_803E805C, timeDelta);
            *(s16 *)((char *)inner + 0x478) = (int)((f32)*(s16 *)((char *)inner + 0x478) + amt);
            *(s16 *)((char *)inner + 0x484) = *(s16 *)((char *)inner + 0x478);
        }
        if (*(f32 *)((char *)obj + 0x98) > lbl_803E7F2C) {
            *(int *)((char *)inner + 0x3f8) = (int)lbl_80333110;
            ObjAnim_SetCurrentMove(obj, *(s16 *)*(int *)((char *)inner + 0x3f8), lbl_803E7EA4, 0);
            *(int *)((char *)inner + 0x360) |= 0x800000;
            *(int *)((char *)state + 0x308) = (int)fn_802A514C;
            return 2;
        }
    } else {
        void *sub = *(void **)((char *)inner + 0x7f8);
        if (sub != NULL && *(s16 *)((char *)sub + 0x46) == 0x112) {
            *(int *)((char *)inner + 0x3f8) = (int)lbl_80333110;
            *(int *)((char *)*(int *)((char *)inner + 0x7f8) + 0xf8) = 1;
            ObjAnim_SetCurrentMove(obj, *(s16 *)*(int *)((char *)inner + 0x3f8), lbl_803E7EA4, 0);
            *(int *)((char *)inner + 0x360) |= 0x800000;
            *(int *)((char *)state + 0x308) = (int)fn_802A514C;
            return 2;
        } else {
            ObjAnim_SetCurrentMove(obj, 5, lbl_803E7EA4, 0);
        }
    }
    if (*(int *)((char *)state + 0x314) & 1) {
        u16 snd;
        if (*(s16 *)((char *)inner + 0x81a) != 0) {
            snd = 0x3c1;
        } else {
            snd = 0x320;
        }
        Sfx_PlayFromObject(obj, snd);
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802ADC08(int obj, int inner, int p3)
{
    *(f32 *)((char *)obj + 0x28) = *(f32 *)((char *)obj + 0x28) - lbl_803DC67C * timeDelta;
    if (*(u8 *)((char *)inner + 0x40c) > 5 && ((ByteFlags *)((char *)inner + 0x3f1))->b01) {
        u16 snd;
        doRumble(lbl_803E7F10);
        Sfx_PlayFromObject(obj, (u16)audioPickSoundEffect_8006ed24(*(u8 *)((char *)inner + 0x86c),
                                                                   *(u8 *)((char *)inner + 0x8a5)));
        if (*(s16 *)((char *)inner + 0x81a) != 0) {
            snd = 0x25;
        } else {
            snd = 0x2cf;
        }
        Sfx_PlayFromObject(obj, snd);
        ((ByteFlags *)((char *)inner + 0x3f0))->b08 = 0;
        ((ByteFlags *)((char *)inner + 0x3f1))->b08 = 1;
        ((ByteFlags *)((char *)inner + 0x3f2))->b10 = 1;
    }
    if (*(f32 *)((char *)obj + 0x1c) <= *(f32 *)((char *)inner + 0x850)
        || ((*(s8 *)((char *)p3 + 0x264) & 2) && (*(s8 *)((char *)p3 + 0x264) & 0x20) == 0)
        || *(u8 *)((char *)p3 + 0x262) != 0) {
        void *sub;
        ((ByteFlags *)((char *)inner + 0x3f0))->b80 = 0;
        ((ByteFlags *)((char *)inner + 0x3f0))->b10 = 0;
        ((ByteFlags *)((char *)inner + 0x3f0))->b08 = 0;
        staffFn_80170380(lbl_803DE450, 2);
        ((ByteFlags *)((char *)inner + 0x3f0))->b02 = 0;
        *(int *)((char *)inner + 0x360) |= 0x800000;
        ObjHits_SyncObjectPositionIfDirty(obj);
        ((ByteFlags *)((char *)inner + 0x3f0))->b40 = 0;
        ((ByteFlags *)((char *)inner + 0x3f0))->b04 = 1;
        ((ByteFlags *)((char *)inner + 0x3f4))->b10 = 0;
        *(u8 *)((char *)inner + 0x800) = 0;
        sub = *(void **)((char *)inner + 0x7f8);
        if (sub != NULL) {
            s16 id = *(s16 *)((char *)sub + 0x46);
            if (id == 0x3cf || id == 0x662) {
                objThrowFn_80182504((int)sub);
            } else {
                objSaveFn_800ea774((int)sub);
            }
            *(s16 *)((char *)*(int *)((char *)inner + 0x7f8) + 0x6) &= ~0x4000;
            *(int *)((char *)*(int *)((char *)inner + 0x7f8) + 0xf8) = 0;
            *(int *)((char *)inner + 0x7f8) = 0;
        }
    }
    *(u8 *)((char *)inner + 0x40c) += 1;
    {
        int v = *(u8 *)((char *)inner + 0x40c);
        if (v > 0xa) v = 0xa;
        *(u8 *)((char *)inner + 0x40c) = v;
    }
    *(u8 *)((char *)inner + 0x8c5) = 1;
    {
        f32 f4 = lbl_803E7FF4;
        f32 c4 = lbl_803E80C4;
        *(f32 *)((char *)inner + 0x428) = c4;
        *(f32 *)((char *)inner + 0x42c) = f4;
        *(f32 *)((char *)inner + 0x430) = c4;
        *(f32 *)((char *)inner + 0x434) = f4;
    }
    *(f32 *)((char *)inner + 0x82c) = lbl_803DC684;
    {
        f32 v = *(f32 *)((char *)inner + 0x408);
        f32 r;
        if (v < lbl_803E7EA4) {
            r = lbl_803E7EA4;
        } else if (v > *(f32 *)((char *)inner + 0x404)) {
            r = *(f32 *)((char *)inner + 0x404);
        } else {
            r = v;
        }
        *(f32 *)((char *)inner + 0x408) = r;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_8029B9FC(int obj, int state, f32 fv)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int v;

    if (*(u8 *)((char *)state + 0x349) != 1 && *(s16 *)((char *)state + 0x274) != 0x26) {
        if (lbl_803DE44C != NULL && ((ByteFlags *)((char *)inner + 0x3f4))->b40) {
            *(u8 *)((char *)inner + 0x8b4) = 0;
            ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 0;
        }
        *(int *)((char *)state + 0x308) = (int)fn_802A514C;
        return 2;
    }
    v = ((int (*)(int, int, int, f32))fn_802AC7DC)(obj, state, inner, fv);
    if (v != 0) {
        if (lbl_803DE44C != NULL && ((ByteFlags *)((char *)inner + 0x3f4))->b40) {
            *(u8 *)((char *)inner + 0x8b4) = 1;
            ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 1;
        }
        *(int *)((char *)state + 0x2d0) = 0;
        *(u8 *)((char *)state + 0x349) = 0;
        (*(void (*)(int))(*(int *)(*gCameraInterface + 0x48)))(0);
        return v;
    }
    if (*(s16 *)((char *)state + 0x274) == 0x26 || ((ByteFlags *)((char *)inner + 0x3f6))->b20) {
        return 0;
    }
    if (*(s16 *)((char *)state + 0x274) != 0x39) {
        if ((getButtons_80014dd8(0) & 0x20) != 0) {
            ((ByteFlags *)((char *)inner + 0x3f6))->b20 = 1;
            *(int *)((char *)state + 0x308) = (int)fn_8029782C;
            return 0x3a;
        }
    }
    if (*(s16 *)((char *)state + 0x274) == 0x39) {
        return 0;
    }
    if ((*(int *)((char *)state + 0x31c) & 0x100) && lbl_803DE44C != NULL
        && ((ByteFlags *)((char *)inner + 0x3f4))->b40) {
        *(u8 *)((char *)inner + 0x8b4) = 4;
        ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 1;
    }
    v = fn_80299E44(obj, state, fv);
    if (v != 0) return v;
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802B0920(int obj, int state)
{
    s16 *vec9 = objModelGetVecFn_800395d8(obj, 9);
    s16 *vec0 = objModelGetVecFn_800395d8(obj, 0);
    int doBlink = 0;
    int inner = *(int *)((char *)obj + 0xb8);
    f32 f31v;
    f32 f30v;

    if ((s8)*(s8 *)(*(int *)((char *)state + 0x35c)) > 0) {
        characterDoEyeAnims(obj, state + 0x364);
    } else {
        int *t5 = objFindTexture(obj, 5, 0);
        int *t4 = objFindTexture(obj, 4, 0);
        if (t5 != NULL) {
            *t5 = 0x200;
        }
        if (t4 != NULL) {
            *t4 = 0x200;
        }
    }
    if ((*(int *)((char *)state + 0x360) & 0x2000000) == 0) {
        *(s16 *)((char *)state + 0x4d0) =
            (f32)*(s16 *)((char *)state + 0x4d0) * powfBitEstimate(lbl_803E7FF4, timeDelta);
        *(s16 *)((char *)state + 0x4d6) =
            (f32)*(s16 *)((char *)state + 0x4d6) * powfBitEstimate(lbl_803E7F1C, timeDelta);
        *(s16 *)((char *)state + 0x4d4) =
            (f32)*(s16 *)((char *)state + 0x4d4) * powfBitEstimate(lbl_803E7F1C, timeDelta);
        *(s16 *)((char *)state + 0x4d2) =
            (f32)*(s16 *)((char *)state + 0x4d2) * powfBitEstimate(lbl_803E7F1C, timeDelta);
    }
    if (((ByteFlags *)((char *)state + 0x3f0))->b20) {
        f31v = *(f32 *)((char *)inner + 0x294) /
               *(f32 *)((char *)(*(int *)((char *)state + 0x400)) + 0x18);
        if (f31v < lbl_803E7EA4) {
            f31v = lbl_803E7EA4;
        } else if (f31v > lbl_803E7EE0) {
            f31v = lbl_803E7EE0;
        }
        f30v = lbl_803E7EE0 - f31v;
    }
    if (vec9 != NULL) {
        if (((ByteFlags *)((char *)state + 0x3f0))->b20) {
            vec9[2] = lbl_803E7E98 *
                      ((f32)*(s16 *)((char *)state + 0x4d0) * f30v +
                       (f32)*(s16 *)((char *)state + 0x4d2) * f31v);
            vec9[1] = lbl_803E7E98 *
                      ((f32)*(s16 *)((char *)state + 0x4d2) * f30v +
                       (f32)*(s16 *)((char *)state + 0x4d0) * f31v);
        } else {
            vec9[2] = *(s16 *)((char *)state + 0x4d0);
            vec9[1] = *(s16 *)((char *)state + 0x4d2);
        }
    }
    if (vec0 != NULL) {
        vec0[0] = -*(s16 *)((char *)state + 0x4d6);
        if (((ByteFlags *)((char *)state + 0x3f0))->b20) {
            int h4 = *(s16 *)((char *)state + 0x4d4) / 2;
            int h0 = -(*(s16 *)((char *)state + 0x4d0) / 2);
            vec0[1] = lbl_803E7E98 * ((f32)h4 * f30v + (f32)h0 * f31v);
            vec0[2] = lbl_803E7E98 * ((f32)h0 * f30v + (f32)h4 * f31v);
        } else {
            vec0[1] = *(s16 *)((char *)state + 0x4d4) / 2;
            vec0[2] = -(*(s16 *)((char *)state + 0x4d0) / 2);
        }
    }
    if (((ByteFlags *)((char *)state + 0x3f0))->b20) {
        *(s16 *)((char *)obj + 0x4) =
            (f32)*(s16 *)((char *)obj + 0x4) * powfBitEstimate(lbl_803E7FF4, timeDelta);
    } else {
        *(s16 *)((char *)obj + 0x4) = *(s16 *)((char *)state + 0x4d0) / 4;
    }
    {
        int e;
        if (*(s16 *)((char *)state + 0x274) == 1) {
            e = 1;
        } else {
            e = 0;
        }
        ((void (*)(int, int, u16))playerEyeAnimFn_80038988)(obj, state + 0x364, e);
    }
    if ((*(u16 *)((char *)obj + 0xb0) & 0x1000) == 0) {
        if (((ByteFlags *)((char *)state + 0x3f1))->b20) {
            lbl_803DC66C = 5;
        } else {
            if (fn_80295A04(obj, 2) == 0 &&
                (s8)*(s8 *)(*(int *)((char *)state + 0x35c)) > 4 &&
                lbl_803DC66C == 1 && randomGetRange(0, 0x12c) == 1) {
                lbl_803DC66C = 2;
                doBlink = 1;
            }
            if (doBlink == 0 && lbl_803DC66C == 2 && randomGetRange(0, 5) == 1) {
                lbl_803DC66C = 1;
            }
        }
        {
            s16 *vec1 = objModelGetVecFn_800395d8(obj, 1);
            if (vec1 != NULL) {
                vec1[0] = 0x1c2;
                vec1[1] = 0;
                vec1[2] = 0;
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802ADE80(int obj, int inner, int state)
{
    f32 waterZ;
    f32 waterX;
    f32 tx;
    f32 ty;
    f32 tz;
    struct {
        u8 pad[6];
        u16 mode;
        f32 scale;
        f32 x;
        f32 y;
        f32 z;
    } pfx;
    struct {
        s16 angles[4];
        f32 mat[4];
    } v;
    f32 mtx[16];
    f32 angle;
    int playEffect;
    int loopCount;
    int i;

    angle = *(f32 *)((char *)inner + 0x83c) +
            fn_80293E80(lbl_803E7F94 * (f32)(u32)*(u16 *)((char *)inner + 0x89c) / lbl_803E7F98);
    *(s16 *)((char *)inner + 0x89c) =
        lbl_803E8114 * timeDelta + (f32)(u32)*(u16 *)((char *)inner + 0x89c);
    {
        f32 d = angle - *(f32 *)((char *)obj + 0x10);
        if (d > lbl_803E7FA0) {
            d = lbl_803E7FA0;
        }
        *(f32 *)((char *)obj + 0x28) =
            d / lbl_803E7FA0 * lbl_803E8118 * timeDelta + *(f32 *)((char *)obj + 0x28);
    }
    *(f32 *)((char *)obj + 0x28) =
        *(f32 *)((char *)obj + 0x28) - lbl_803E7EFC * timeDelta;
    *(f32 *)((char *)obj + 0x28) =
        *(f32 *)((char *)obj + 0x28) * powfBitEstimate(lbl_803E7FD0, timeDelta);
    {
        f32 v = *(f32 *)((char *)obj + 0x28);
        if (v < lbl_803E811C) {
            v = lbl_803E811C;
        } else if (v > lbl_803E8120) {
            v = lbl_803E8120;
        }
        *(f32 *)((char *)obj + 0x28) = v;
    }
    ((void (*)(f32 *, f32 *, f32, int))playerCalcWaterCurrent)(&waterX, &waterZ, lbl_803E7EE0, obj);
    {
        f32 cosv = fn_80293E80(lbl_803E7F94 * (f32)*(s16 *)((char *)inner + 0x478) / lbl_803E7F98);
        f32 sinv = sin(lbl_803E7F94 * (f32)*(s16 *)((char *)inner + 0x478) / lbl_803E7F98);
        f32 a = -waterZ * sinv - waterX * cosv;
        *(f32 *)((char *)inner + 0x440) =
            timeDelta * (lbl_803E7EFC * ((waterX * sinv - waterZ * cosv) - *(f32 *)((char *)inner + 0x440))) +
            *(f32 *)((char *)inner + 0x440);
        *(f32 *)((char *)inner + 0x43c) =
            timeDelta * (lbl_803E7EFC * (a - *(f32 *)((char *)inner + 0x43c))) +
            *(f32 *)((char *)inner + 0x43c);
    }
    playEffect = 0;
    if (*(s16 *)((char *)state + 0x274) == 1) {
        if ((*(int *)((char *)state + 0x314) & 0x200) != 0) {
            Sfx_PlayAtPositionFromObject(obj, 0xe, *(f32 *)((char *)obj + 0xc),
                                         *(f32 *)((char *)inner + 0x83c), *(f32 *)((char *)obj + 0x14));
        }
        if (*(f32 *)((char *)inner + 0x838) < lbl_803E7FA0 &&
            (*(int *)((char *)state + 0x314) & 0x200) != 0) {
            tx = (f32)randomGetRange(-0x14, 0x14) / lbl_803E7ED8;
            tz = (f32)randomGetRange(-0x14, 0x14) / lbl_803E7ED8;
            playEffect = 1;
        }
    } else {
        if ((*(int *)((char *)state + 0x314) & 1) != 0) {
            Sfx_PlayAtPositionFromObject(obj, 0xf, *(f32 *)((char *)obj + 0xc),
                                         *(f32 *)((char *)inner + 0x83c), *(f32 *)((char *)obj + 0x14));
        }
        if (*(f32 *)((char *)inner + 0x838) < lbl_803E7FA0 &&
            (*(int *)((char *)state + 0x314) & 0x200) != 0) {
            s8 c;
            tx = (f32)randomGetRange(-0x14, 0x14) / lbl_803E7ED8;
            c = *(s8 *)((char *)inner + 0x8cc);
            if (c > 0xc) {
                tz = lbl_803E8124;
            } else if (c > 8) {
                tz = lbl_803E8124;
            } else {
                tz = lbl_803E8124;
            }
            playEffect = 1;
        }
    }
    if (playEffect != 0) {
        v.mat[1] = *(f32 *)((char *)obj + 0xc);
        v.mat[2] = lbl_803E7EA4;
        v.mat[3] = *(f32 *)((char *)obj + 0x14);
        v.angles[0] = *(s16 *)((char *)inner + 0x478);
        v.angles[1] = 0;
        v.angles[2] = 0;
        v.mat[0] = lbl_803E7EE0;
        setMatrixFromObjectPos(mtx, v.angles);
        Matrix_TransformPoint(mtx, tx, lbl_803E7EA4, tz, &tx, &ty, &tz);
        (*(void (*)(int, int, f32, f32, f32, f32))(*(int *)(*gWaterfxInterface + 0x14)))(
            0, 5, tx, *(f32 *)((char *)inner + 0x83c), tz, lbl_803E7EA4);
        if (*(f32 *)((char *)inner + 0x838) > lbl_803E8128 &&
            *(f32 *)((char *)state + 0x294) > lbl_803E7E9C) {
            s16 ang = (s16)(*(s16 *)((char *)inner + 0x478) -
                            getAngle(*(f32 *)((char *)state + 0x284), *(f32 *)((char *)state + 0x280)));
            (*(void (*)(int, f32, f32, f32, f32))(*(int *)(*gWaterfxInterface + 0x18)))(
                ang, tx, *(f32 *)((char *)inner + 0x83c), tz, lbl_803E7EA4);
        }
    }
    ObjPath_GetPointWorldPosition(obj, 0x13, &v.mat[1], &v.mat[2], &v.mat[3], 0);
    loopCount = (*(f32 *)((char *)inner + 0x83c) - v.mat[2] > lbl_803E7F10);
    for (i = 0; i < loopCount; i++) {
        pfx.x = v.mat[1] + (f32)randomGetRange(-0x64, 0x64) / lbl_803E7FA4;
        pfx.y = v.mat[2] + (f32)randomGetRange(-0x64, 0x64) / lbl_803E808C;
        pfx.z = v.mat[3] + (f32)randomGetRange(-0x64, 0x64) / lbl_803E7FA4;
        pfx.scale = *(f32 *)((char *)inner + 0x83c) - pfx.y;
        if (pfx.scale > lbl_803E7EA4) {
            (**(void (**)(int, int, void *, int, int, int))((char *)(*gPartfxInterface) + 0x8))(
                obj, 0x202, &pfx, 0x200001, -1, 0);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802A16CC(int obj, int state, f32 fv)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        ObjHits_MarkObjectPositionDirty();
        lbl_803DE498 = lbl_803E7EA4;
        ObjAnim_SetCurrentMove(obj, 0x35, lbl_803E7EA4, 1);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7F20;
        *(f32 *)((char *)inner + 0x500) = *(f32 *)((char *)obj + 0x10);
        *(f32 *)((char *)obj + 0x10) = *(f32 *)((char *)inner + 0x76c);
        fn_802AB5A4(obj, inner, 5);
    }
    if (*(f32 *)((char *)inner + 0x838) > lbl_803E7FA0) {
        fn_802AB5A4(obj, inner, 5);
        ((void (*)(int, int, int))fn_802AE83C)(obj, inner, state);
        *(int *)((char *)state + 0x308) = (int)fn_802A514C;
        return 2;
    }
    *(int *)((char *)state + 0x4) |= 0x100000;
    *(int *)((char *)state + 0x4) |= 0x8000000;
    *(int *)((char *)state + 0) |= 0x200000;
    switch (*(s16 *)((char *)obj + 0xa0)) {
    case 0x35:
        if (*(s8 *)((char *)state + 0x346) != 0) {
            ObjAnim_SetCurrentMove(obj, 0x36, lbl_803E7EA4, 0);
            *(f32 *)((char *)state + 0x2a0) = lbl_803E7F20;
        }
    case 0x36:
        {
            f32 f30 = lbl_803E7ED8 * -lbl_803DE498;
            f32 f3;
            if ((*(int *)((char *)state + 0x314) & 1) != 0) {
                Sfx_PlayFromObject(obj, SFXthorntail_injured2);
            }
            f3 = *(f32 *)((char *)obj + 0x10) - (lbl_803E8010 + *(f32 *)((char *)inner + 0x4ec));
            if (f3 < lbl_803E7EA4) {
                f3 = lbl_803E7EA4;
            }
            if (f3 < f30) {
                f32 ed4 = lbl_803E7ED4;
                *(f32 *)((char *)obj + 0x28) =
                    -sqrtf(ed4 * (lbl_803DE498 * lbl_803DE498 / (ed4 * f30)) * f3);
                if (*(f32 *)((char *)obj + 0x28) >= lbl_803E7FEC) {
                    u8 anim = *(u8 *)((char *)inner + 0x8c8);
                    f32 v4ec;
                    if (anim != 0x48 && anim != 0x47 && anim != 0x42) {
                        (*(void (*)(int, int, int, int, int, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
                            0x42, 0, 1, 0, 0, 0, 0xff);
                        *(u8 *)((char *)inner + 0x8c8) = 0x42;
                    }
                    *(f32 *)((char *)inner + 0x500) = *(f32 *)((char *)obj + 0x10);
                    v4ec = *(f32 *)((char *)inner + 0x4ec);
                    *(f32 *)((char *)obj + 0x1c) = v4ec;
                    *(f32 *)((char *)obj + 0x10) = v4ec;
                    if (((ByteFlags *)((char *)inner + 0x547))->b80) {
                        ObjAnim_SetCurrentMove(obj, 0x37, lbl_803E7EA4, 1);
                        *(f32 *)((char *)state + 0x2a0) = lbl_803E7FCC;
                        *(f32 *)((char *)obj + 0x28) = lbl_803E7EA4;
                    } else {
                        f32 zero = lbl_803E7EA4;
                        void *sub;
                        *(f32 *)((char *)state + 0x294) = zero;
                        *(f32 *)((char *)state + 0x284) = zero;
                        *(f32 *)((char *)state + 0x280) = zero;
                        *(f32 *)((char *)obj + 0x24) = zero;
                        *(f32 *)((char *)obj + 0x28) = zero;
                        *(f32 *)((char *)obj + 0x2c) = zero;
                        fn_802AB5A4(obj, inner, 5);
                        ((ByteFlags *)((char *)inner + 0x3f0))->b80 = 0;
                        ((ByteFlags *)((char *)inner + 0x3f0))->b10 = 0;
                        ((ByteFlags *)((char *)inner + 0x3f0))->b08 = 0;
                        staffFn_80170380(lbl_803DE450, 2);
                        ((ByteFlags *)((char *)inner + 0x3f0))->b02 = 0;
                        *(int *)((char *)inner + 0x360) |= 0x800000;
                        ObjHits_SyncObjectPositionIfDirty(obj);
                        ((ByteFlags *)((char *)inner + 0x3f0))->b40 = 0;
                        ((ByteFlags *)((char *)inner + 0x3f0))->b04 = 1;
                        ((ByteFlags *)((char *)inner + 0x3f4))->b10 = 1;
                        *(u8 *)((char *)inner + 0x800) = 0;
                        sub = *(void **)((char *)inner + 0x7f8);
                        if (sub != NULL) {
                            s16 id = *(s16 *)((char *)sub + 0x46);
                            if (id == 0x3cf || id == 0x662) {
                                objThrowFn_80182504((int)sub);
                            } else {
                                objSaveFn_800ea774((int)sub);
                            }
                            *(s16 *)((char *)*(int *)((char *)inner + 0x7f8) + 0x6) &= ~0x4000;
                            *(int *)((char *)*(int *)((char *)inner + 0x7f8) + 0xf8) = 0;
                            *(int *)((char *)inner + 0x7f8) = 0;
                        }
                        *(int *)((char *)state + 0x308) = (int)fn_802A514C;
                        return 3;
                    }
                }
            } else {
                if (*(f32 *)((char *)obj + 0x28) > lbl_803E8014) {
                    *(f32 *)((char *)obj + 0x28) =
                        *(f32 *)((char *)obj + 0x28) - lbl_803E7F6C * fv;
                }
                if (*(f32 *)((char *)obj + 0x28) < lbl_803E8014) {
                    *(f32 *)((char *)obj + 0x28) = lbl_803E8014;
                }
                if (*(f32 *)((char *)obj + 0x28) < lbl_803DE498) {
                    lbl_803DE498 = *(f32 *)((char *)obj + 0x28);
                }
            }
        }
        break;
    case 0x37:
        if ((*(int *)((char *)state + 0x314) & 1) != 0) {
            int snd = audioPickSoundEffect_8006ed24(*(u8 *)((char *)inner + 0x86c),
                                                    *(u8 *)((char *)inner + 0x8a5));
            Sfx_PlayFromObject(obj, snd);
            doRumble(lbl_803E7F10);
            if (*(f32 *)((char *)inner + 0x838) > lbl_803E7EA4) {
                (*(void (*)(int, f32, f32, f32, f32))(*(int *)(*gWaterfxInterface + 0x10)))(
                    obj, *(f32 *)((char *)obj + 0xc), *(f32 *)((char *)obj + 0x10),
                    *(f32 *)((char *)obj + 0x14), lbl_803E8018);
            }
        }
        if (*(s8 *)((char *)state + 0x346) != 0) {
            f32 local;
            *(f32 *)((char *)obj + 0x18) = *(f32 *)((char *)inner + 0x768);
            *(f32 *)((char *)obj + 0x20) = *(f32 *)((char *)inner + 0x770);
            if (*(void **)((char *)obj + 0x30) != NULL) {
                *(f32 *)((char *)obj + 0x18) += playerMapOffsetX;
                *(f32 *)((char *)obj + 0x20) += playerMapOffsetZ;
            }
            Obj_TransformWorldPointToLocal((f32 *)((char *)obj + 0xc), &local,
                (f32 *)((char *)obj + 0x14), *(int *)((char *)obj + 0x30),
                *(f32 *)((char *)obj + 0x18), lbl_803E7EA4, *(f32 *)((char *)obj + 0x20));
            fn_802AB5A4(obj, inner, 5);
            ObjAnim_SetCurrentMove(obj, *(s16 *)(*(int *)((char *)inner + 0x3f8)), lbl_803E7EA4, 1);
            *(int *)((char *)inner + 0x360) |= 0x800000;
            *(int *)((char *)state + 0x308) = (int)fn_802A514C;
            return 2;
        }
        break;
    }
    {
        f32 cx = *(f32 *)((char *)obj + 0xc);
        f32 cy;
        f32 cz = *(f32 *)((char *)obj + 0x14);
        switch (*(s16 *)((char *)obj + 0xa0)) {
        case 0x35:
            cy = *(f32 *)((char *)obj + 0x98) *
                     (*(f32 *)((char *)obj + 0x10) - *(f32 *)((char *)inner + 0x500)) +
                 *(f32 *)((char *)inner + 0x500);
            break;
        case 0x37:
            {
                f32 w = *(f32 *)((char *)obj + 0x98);
                cx = w * (*(f32 *)((char *)inner + 0x768) - cx) + cx;
                cy = (lbl_803E7EE0 - w) *
                         (*(f32 *)((char *)inner + 0x500) - *(f32 *)((char *)obj + 0x10)) +
                     *(f32 *)((char *)obj + 0x10);
                cz = w * (*(f32 *)((char *)inner + 0x770) - cz) + cz;
            }
            break;
        default:
            cy = *(f32 *)((char *)obj + 0x10);
            break;
        }
        (*(void (*)(f32, f32, f32))(*(int *)(*gCameraInterface + 0x2c)))(cx, cy, cz);
    }
    fn_802AB5A4(obj, inner, 5);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80298E54(int obj, int state, f32 fv)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        ObjHits_MarkObjectPositionDirty();
    }
    setBButtonIcon(0xa);
    {
        f32 zero = lbl_803E7EA4;
        *(f32 *)((char *)state + 0x294) = zero;
        *(f32 *)((char *)state + 0x284) = zero;
        *(f32 *)((char *)state + 0x280) = zero;
        *(f32 *)((char *)obj + 0x24) = zero;
        *(f32 *)((char *)obj + 0x28) = zero;
        *(f32 *)((char *)obj + 0x2c) = zero;
    }
    switch (*(s16 *)((char *)obj + 0xa0)) {
    case 0xab:
        setAButtonIcon(2);
        if (lbl_803DE48C == 0) {
            if (*(f32 *)((char *)obj + 0x98) > lbl_803E7E9C) {
                Sfx_PlayFromObject(obj, SFXmammoth_breath1);
                lbl_803DE48C = 1;
            }
        }
        if (*(s8 *)((char *)state + 0x346) != 0) {
            ObjAnim_SetCurrentMove(obj, 0xb1, lbl_803E7EA4, 0);
            *(f32 *)((char *)state + 0x2a0) = lbl_803E7EF8;
        }
        break;
    case 0xb1: {
        int flags;
        setAButtonIcon(2);
        cfPrisonGuard_setLiftHeight(lbl_803DE434, 0);
        flags = *(u16 *)((char *)inner + 0x6e2);
        if ((flags & 0x100) != 0) {
            buttonDisable(0, 0x100);
            lbl_803DE488 = lbl_803E7ED8;
            ObjAnim_SetCurrentMove(obj, 0xac, lbl_803E7EA4, 0);
            *(f32 *)((char *)state + 0x2a0) = lbl_803E7EA4;
        } else if ((flags & 0x200) != 0) {
            buttonDisable(0, 0x200);
            Sfx_PlayFromObject(obj, SFXmammoth_breath1);
            ObjAnim_SetCurrentMove(obj, 0xd1, lbl_803E7EA4, 0);
            *(f32 *)((char *)state + 0x2a0) = lbl_803E7F4C;
        }
        break;
    }
    case 0xd1:
        if (*(s8 *)((char *)state + 0x346) != 0) {
            *(int *)((char *)inner + 0x360) |= 0x800000;
            *(int *)((char *)state + 0x308) = (int)fn_802A514C;
            return 2;
        }
        break;
    case 0xac: {
        int count;
        f32 prog;
        setAButtonIcon(2);
        lbl_803DE488 = lbl_803DE488 - lbl_803E7EE0;
        if ((*(u16 *)((char *)inner + 0x6e4) & 0x100) != 0 || getCurSeqNo() != 0) {
            buttonDisable(0, 0x100);
            lbl_803DE460 = lbl_803DE460 - fv;
            if (lbl_803DE460 < lbl_803E7EA4) {
                Sfx_PlayFromObject(obj, (u16)(*(s16 *)((char *)inner + 0x81a) == 0 ? 0x2d3 : 0x2b));
                lbl_803DE460 = (f32)(int)randomGetRange(0xa, 0x12);
            }
            switch (cfPrisonGuard_getPullRateMode(lbl_803DE434)) {
            case 2:
                lbl_803DE488 = lbl_803DE488 + lbl_803E7F50;
                break;
            default:
                lbl_803DE488 = lbl_803DE488 + lbl_803E7F54;
                break;
            case 0:
                lbl_803DE488 = lbl_803DE488 + lbl_803E7F58;
                break;
            }
        }
        if (lbl_803DE488 > lbl_803E7F5C) {
            lbl_803DE488 = lbl_803E7F5C;
        } else if (lbl_803DE488 < lbl_803E7F60) {
            lbl_803DE488 = lbl_803E7F60;
        }
        count = (int)((f32)(int)cfPrisonGuard_getLiftHeight(lbl_803DE434) + lbl_803DE488);
        if (count <= 0) {
            lbl_803DE488 = lbl_803E7EA4;
            count = 0;
            ObjAnim_SetCurrentMove(obj, 0xb1, lbl_803E7EA4, 0);
            *(f32 *)((char *)state + 0x2a0) = lbl_803E7EF8;
        } else if (count > 0x800) {
            count = 0x800;
        }
        prog = (f32)count / lbl_803E7F64;
        if (prog >= lbl_803E7F68) {
            fn_80189C68(lbl_803DE434);
            Sfx_PlayFromObject(obj, (u16)(*(s16 *)((char *)inner + 0x81a) == 0 ? 0x2d3 : 0x2b));
            ObjAnim_SetCurrentMove(obj, 0xd0, lbl_803E7EA4, 0);
            *(f32 *)((char *)state + 0x2a0) = lbl_803E7F6C;
        } else {
            ObjAnim_SetMoveProgress(prog + (f32)(int)randomGetRange(-0x64, 0x64) / lbl_803E7F70,
                                    (ObjAnimComponent *)obj);
        }
        cfPrisonGuard_setLiftHeight(lbl_803DE434, count);
        break;
    }
    case 0xd0:
        cfPrisonGuard_setLiftHeight(lbl_803DE434, 0x800);
        if (*(s8 *)((char *)state + 0x346) != 0) {
            Sfx_PlayFromObject(obj, SFXsp_lf_mutter4);
            ObjAnim_SetCurrentMove(obj, 0xb2, lbl_803E7EA4, 0);
            *(f32 *)((char *)state + 0x2a0) = lbl_803E7EF8;
        }
        break;
    case 0xb2:
        cfPrisonGuard_setLiftHeight(lbl_803DE434, 0x800);
        if ((*(u16 *)((char *)inner + 0x6e2) & 0x200) != 0) {
            buttonDisable(0, 0x200);
            Sfx_PlayFromObject(obj, SFXmammoth_breath1);
            ObjAnim_SetCurrentMove(obj, 0xad, lbl_803E7EA4, 0);
            *(f32 *)((char *)state + 0x2a0) = lbl_803E7F4C;
        }
        break;
    case 0xad:
        if (*(s8 *)((char *)state + 0x346) != 0) {
            *(int *)((char *)inner + 0x360) |= 0x800000;
            *(int *)((char *)state + 0x308) = (int)fn_802A514C;
            return 2;
        }
        break;
    default:
        ObjAnim_SetCurrentMove(obj, 0xab, lbl_803E7EA4, 0);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7F40;
        staffactivated_calcInteractionTargetXZ(lbl_803DE434, (f32 *)((char *)obj + 0xc), (f32 *)((char *)obj + 0x14));
        *(s16 *)((char *)inner + 0x478) = *(s16 *)lbl_803DE434 + 0x8000;
        *(s16 *)((char *)inner + 0x484) = *(s16 *)((char *)inner + 0x478);
        if (lbl_803DE44C != NULL && ((ByteFlags *)((char *)inner + 0x3f4))->b40) {
            *(u8 *)((char *)inner + 0x8b4) = 4;
            ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 1;
        }
        lbl_803DE488 = lbl_803E7EA4;
        lbl_803DE48C = 0;
        lbl_803DE460 = lbl_803E7EA4;
        if (*(u8 *)((char *)inner + 0x8c8) != 0x48 && *(u8 *)((char *)inner + 0x8c8) != 0x47) {
            struct {
                s16 a;
                u8 b;
                u8 c;
            } shk;
            shk.a = 0;
            shk.b = 0;
            shk.c = 1;
            (*(void (*)(int, int, int, int, void *, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
                0x43, 1, 0, 4, &shk, 0, 0xff);
        }
        break;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802994D0(int obj, int state, f32 fv)
{
    int inner = *(int *)((char *)obj + 0xb8);
    u32 mask;
    s16 item;
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        ObjHits_MarkObjectPositionDirty();
    }
    if ((s16)getYButtonItem(&item) == 1 && item == 0x957) {
        mask = 0x900;
    } else {
        mask = 0x100;
    }
    *(int *)((char *)state + 0) |= 0x200000;
    switch (*(s16 *)((char *)obj + 0xa0)) {
    case 0x4:
        if (lbl_803DE48D == 0) {
            if (*(f32 *)((char *)obj + 0x98) > lbl_803E7F74) {
                Sfx_PlayFromObject(obj, SFXhightop_call1);
                lbl_803DE48D = 1;
            }
        }
        if (*(s8 *)((char *)state + 0x346) != 0) {
            if ((*(u16 *)((char *)inner + 0x6e0) & mask) != 0) {
                Sfx_PlayFromObject(obj, SFXhightop_call2);
                ObjAnim_SetCurrentMove(obj, 0x87, lbl_803E7EA4, 0);
                *(f32 *)((char *)state + 0x2a0) = lbl_803E7EF8;
            } else {
                ObjAnim_SetCurrentMove(obj, 0x43, lbl_803E7EA4, 0);
                *(f32 *)((char *)state + 0x2a0) = lbl_803E7F78;
            }
        }
        break;
    case 0x87:
        if ((*(u16 *)((char *)inner + 0x6e0) & mask) != 0 &&
            *(f32 *)((char *)inner + 0x7d4) <=
                (f32)*(s16 *)((char *)*(int *)((char *)*(int *)((char *)obj + 0xb8) + 0x35c) + 0x4)) {
            *(f32 *)((char *)state + 0x2a0) = lbl_803E7F20 * fv + *(f32 *)((char *)state + 0x2a0);
            if (*(f32 *)((char *)state + 0x2a0) > lbl_803E7F6C) {
                *(f32 *)((char *)state + 0x2a0) = lbl_803E7F6C;
            }
            *(f32 *)((char *)inner + 0x7d4) = lbl_803E7F7C * fv + *(f32 *)((char *)inner + 0x7d4);
            *(f32 *)((char *)inner + 0x7d4) = lbl_803E7E98 * fv + *(f32 *)((char *)inner + 0x7d4);
            if (*(f32 *)((char *)inner + 0x7d4) >= lbl_803E7ED8) {
                int sub = *(int *)((char *)*(int *)((char *)obj + 0xb8) + 0x35c);
                int v = *(s16 *)((char *)sub + 0x4) - 0xa;
                *(f32 *)((char *)inner + 0x7d4) = lbl_803E7EA4;
                if (v < 0) {
                    v = 0;
                } else if (v > *(s16 *)((char *)sub + 0x6)) {
                    v = *(s16 *)((char *)sub + 0x6);
                }
                *(s16 *)((char *)sub + 0x4) = v;
                Sfx_PlayFromObject(obj, SFXmammoth_annoyed2);
                ObjAnim_SetCurrentMove(obj, 0x88, lbl_803E7EA4, 0);
                *(f32 *)((char *)state + 0x2a0) = lbl_803E7F6C;
            }
        } else {
            ObjAnim_SetCurrentMove(obj, 0x43, lbl_803E7EA4, 0);
            *(f32 *)((char *)state + 0x2a0) = lbl_803E7F78;
        }
        break;
    case 0x43:
        if ((*(u16 *)((char *)inner + 0x6e0) & mask) != 0) {
            Sfx_PlayFromObject(obj, SFXhightop_call2);
            ObjAnim_SetCurrentMove(obj, 0x87, lbl_803E7EA4, 0);
            *(f32 *)((char *)state + 0x2a0) = lbl_803E7EF8;
        } else if ((*(u16 *)((char *)inner + 0x6e2) & 0x200) != 0) {
            buttonDisable(0, 0x200);
            ObjAnim_SetCurrentMove(obj, 0x44, lbl_803E7EA4, 0);
            *(f32 *)((char *)state + 0x2a0) = lbl_803E7F80;
        }
        break;
    case 0x44:
        if (*(s8 *)((char *)state + 0x346) != 0) {
            *(int *)((char *)inner + 0x360) |= 0x800000;
            *(f32 *)((char *)obj + 0x28) = lbl_803E7EA4;
            *(s16 *)((char *)inner + 0x80a) = -1;
            *(int *)((char *)state + 0x308) = (int)fn_802A514C;
            return 2;
        }
        break;
    case 0x88:
        *(f32 *)((char *)obj + 0x28) = lbl_803E7F6C * fv + *(f32 *)((char *)obj + 0x28);
        if (*(s8 *)((char *)state + 0x346) != 0) {
            void *t = getTrickyObject();
            if (t != NULL) {
                trickyImpress(t);
            }
            ObjAnim_SetCurrentMove(obj, 0x7f, lbl_803E7EA4, 0);
            *(f32 *)((char *)state + 0x2a0) = lbl_803E7EB4;
        }
        break;
    case 0x7f:
        *(f32 *)((char *)obj + 0x28) = lbl_803E7EFC * fv + *(f32 *)((char *)obj + 0x28);
        if (*(f32 *)((char *)obj + 0x28) > lbl_803E7F10) {
            *(f32 *)((char *)obj + 0x28) = lbl_803E7F10;
        }
        if (*(f32 *)((char *)obj + 0x10) > lbl_803DE490) {
            ObjAnim_SetCurrentMove(obj, 0x80, lbl_803E7EA4, 0);
            *(f32 *)((char *)state + 0x2a0) = lbl_803E7F84;
        }
        break;
    case 0x80: {
        f32 p;
        *(f32 *)((char *)obj + 0x28) = *(f32 *)((char *)obj + 0x28) - lbl_803E7F88 * fv;
        p = powfBitEstimate(lbl_803E7F90, fv);
        *(f32 *)((char *)obj + 0x28) = *(f32 *)((char *)obj + 0x28) * p;
        (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x20)))(obj, state, fv, 1);
        if (*(s8 *)((char *)state + 0x346) != 0) {
            *(int *)((char *)inner + 0x360) |= 0x800000;
            *(f32 *)((char *)obj + 0x28) = lbl_803E7EA4;
            *(s16 *)((char *)inner + 0x80a) = -1;
            *(int *)((char *)state + 0x308) = (int)fn_802A514C;
            return 2;
        }
        break;
    }
    default: {
        f32 fromVec[3];
        f32 toVec[3];
        u8 hitBuf[0x40];
        f32 zero = lbl_803E7EA4;
        *(f32 *)((char *)state + 0x294) = zero;
        *(f32 *)((char *)state + 0x284) = zero;
        *(f32 *)((char *)state + 0x280) = zero;
        *(f32 *)((char *)obj + 0x24) = zero;
        *(f32 *)((char *)obj + 0x28) = zero;
        *(f32 *)((char *)obj + 0x2c) = zero;
        ObjAnim_SetCurrentMove(obj, 0x4, zero, 0);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7F84;
        lbl_803DE494 = *(f32 *)((char *)obj + 0x10);
        *(s16 *)((char *)inner + 0x478) = *(s16 *)lbl_803DE434;
        *(s16 *)((char *)inner + 0x484) = *(s16 *)((char *)inner + 0x478);
        staffactivated_calcInteractionTargetXZ(lbl_803DE434, (f32 *)((char *)obj + 0xc), (f32 *)((char *)obj + 0x14));
        fn_802AB5A4(obj, inner, 7);
        *(int *)((char *)state + 0x4) |= 0x8000000;
        fromVec[0] = *(f32 *)((char *)obj + 0xc);
        fromVec[1] = lbl_803E7ED8 + *(f32 *)((char *)obj + 0x10);
        fromVec[2] = *(f32 *)((char *)obj + 0x14);
        toVec[0] = fromVec[0] -
                   lbl_803E7F5C * fn_80293E80(lbl_803E7F94 * (f32)(int)*(s16 *)((char *)inner + 0x478) /
                                              lbl_803E7F98);
        toVec[1] = fromVec[1];
        toVec[2] = fromVec[2] -
                   lbl_803E7F5C * sin(lbl_803E7F94 * (f32)(int)*(s16 *)((char *)inner + 0x478) /
                                      lbl_803E7F98);
        if (objBboxFn_800640cc(lbl_803E7EA4, fromVec, toVec, 3, hitBuf, obj, 1, 1, 0xff, 0) != 0) {
            lbl_803DE490 = *(f32 *)(hitBuf + 0x3c) - lbl_803E7F30;
        } else {
            lbl_803DE490 = lbl_803E7F5C + *(f32 *)((char *)obj + 0x10);
        }
        lbl_803DE48D = 0;
        if (lbl_803DE44C != NULL && ((ByteFlags *)((char *)inner + 0x3f4))->b40) {
            *(u8 *)((char *)inner + 0x8b4) = 4;
            ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 1;
        }
        *(f32 *)((char *)inner + 0x7d4) = lbl_803E7EA4;
        if (*(u8 *)((char *)inner + 0x8c8) != 0x48 && *(u8 *)((char *)inner + 0x8c8) != 0x47) {
            struct {
                s16 a;
                u8 b;
                u8 c;
            } shk;
            shk.a = 0;
            shk.b = 0;
            shk.c = 1;
            (*(void (*)(int, int, int, int, void *, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
                0x43, 1, 0, 4, &shk, 0, 0xff);
        }
        break;
    }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_8029E568(int obj, int state, f32 fv)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int camArg = 0;
    f32 vec[3];
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        *(s16 *)((char *)state + 0x278) = 0x1b;
        *(int *)((char *)inner + 0x898) = (int)fn_802A00C0;
        ObjHits_MarkObjectPositionDirty();
    }
    {
        int in2 = *(int *)((char *)obj + 0xb8);
        *(int *)((char *)in2 + 0x360) &= ~2;
        *(int *)((char *)in2 + 0x360) |= 0x2000;
    }
    *(int *)((char *)state + 0x4) |= 0x100000;
    {
        f32 zero = lbl_803E7EA4;
        *(f32 *)((char *)state + 0x280) = zero;
        *(f32 *)((char *)state + 0x284) = zero;
        *(int *)((char *)state + 0) |= 0x200000;
        *(f32 *)((char *)obj + 0x24) = zero;
        *(f32 *)((char *)obj + 0x2c) = zero;
        *(u8 *)((char *)state + 0x25f) = 0;
        *(f32 *)((char *)obj + 0x28) = zero;
    }
    switch (*(s16 *)((char *)obj + 0xa0)) {
    case 0x76:
    case 0x40d: {
        int active;
        f32 amt = *(f32 *)((char *)state + 0x28c) / lbl_803E7FA8;
        f32 clamped;
        f32 sp;
        f32 spd;
        if (amt < lbl_803E7EA4) {
            amt = -amt;
        }
        if (amt >= lbl_803E7EFC) {
            if (amt <= lbl_803E7EE0) {
                clamped = amt;
            } else {
                clamped = lbl_803E7EE0;
            }
        } else {
            clamped = lbl_803E7EFC;
        }
        sp = *(f32 *)((char *)state + 0x28c);
        if (sp > lbl_803E7EE0) {
            spd = lbl_803E7F44 * clamped;
            active = 1;
        } else if (sp < lbl_803E7ECC) {
            spd = lbl_803E7F44 * -clamped;
            active = 1;
        } else {
            spd = lbl_803E7EA4;
            active = 0;
        }
        if (active != 0) {
            lbl_803DE480 = lbl_803DE480 - framesThisStep;
            if (lbl_803DE480 <= 0) {
                lbl_803DE480 = randomGetRange(0x1e, 0x2d);
                Sfx_PlayFromObject(0, 0x378);
            }
        }
        *(f32 *)((char *)state + 0x294) =
            *(f32 *)((char *)state + 0x294) +
            interpolate(spd - *(f32 *)((char *)state + 0x294), lbl_803E7EFC, timeDelta);
        *(f32 *)((char *)inner + 0x640) =
            *(f32 *)((char *)state + 0x294) * timeDelta + *(f32 *)((char *)inner + 0x640);
        {
            f32 ph = *(f32 *)((char *)state + 0x294);
            if (ph < lbl_803E7EF8 && ph > lbl_803E7FEC) {
                *(f32 *)((char *)state + 0x294) = lbl_803E7EA4;
                if (*(s16 *)((char *)obj + 0xa0) != 0x76) {
                    ObjAnim_SetCurrentMove(obj, 0x76, lbl_803E7EA4, 0);
                }
                *(f32 *)((char *)state + 0x2a0) = lbl_803E7F78;
            } else {
                if (*(s16 *)((char *)obj + 0xa0) != 0x40d) {
                    ObjAnim_SetCurrentMove(obj, 0x40d, lbl_803E7EA4, 0);
                }
                ObjAnim_SampleRootCurvePhase(*(f32 *)((char *)state + 0x294), (ObjAnimComponent *)obj,
                                             (f32 *)((char *)state + 0x2a0));
            }
        }
        if (*(f32 *)((char *)inner + 0x640) > *(f32 *)((char *)inner + 0x644) ||
            *(f32 *)((char *)inner + 0x640) < lbl_803E7EA4) {
            u8 anim;
            ObjAnim_SetCurrentMove(obj, 0x40f, lbl_803E7EA4, 0);
            anim = *(u8 *)((char *)inner + 0x8c8);
            if (anim != 0x48 && anim != 0x47) {
                camArg = *(f32 *)((char *)inner + 0x640) < lbl_803E7EA4 ? 0 : 1;
                (*(void (*)(int *))(*(int *)(*gCameraInterface + 0x60)))(&camArg);
            }
        } else {
            *(s16 *)((char *)inner + 0x478) =
                (s16)getAngle(-*(f32 *)((char *)inner + 0x634), -*(f32 *)((char *)inner + 0x63c));
            *(s16 *)((char *)inner + 0x484) = *(s16 *)((char *)inner + 0x478);
            *(s16 *)((char *)obj + 0x2) = 0;
        }
        break;
    }
    case 0x40f:
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7F34;
        (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x20)))(obj, state, fv, 1);
        if (*(s8 *)((char *)state + 0x346) != 0) {
            u8 anim = *(u8 *)((char *)inner + 0x8c8);
            if (anim != 0x48 && anim != 0x47) {
                (*(void (*)(int, int, int, int, int, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
                    0x42, 1, 1, 0, 0, 0, 0xff);
            }
            *(int *)((char *)inner + 0x360) |= 0x800000;
            *(int *)((char *)state + 0x308) = (int)fn_802A514C;
            return 2;
        }
        break;
    case 0x40e:
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7F34;
        (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x20)))(obj, state, fv, 1);
        *(s16 *)((char *)inner + 0x478) =
            (s16)getAngle(*(f32 *)((char *)inner + 0x60c), *(f32 *)((char *)inner + 0x614));
        *(s16 *)((char *)inner + 0x484) = *(s16 *)((char *)inner + 0x478);
        sqrtf(*(f32 *)((char *)inner + 0x60c) * *(f32 *)((char *)inner + 0x60c) +
              *(f32 *)((char *)inner + 0x614) * *(f32 *)((char *)inner + 0x614));
        *(s16 *)((char *)obj + 0x2) = 0;
        if (*(s8 *)((char *)state + 0x346) != 0) {
            ObjAnim_SetCurrentMove(obj, 0x40d, lbl_803E7EA4, 0);
        }
        break;
    default: {
        int curveId = 0x1f;
        if ((*(int (*)(int *, int, int, f32, f32, f32))(*(int *)(*gRomCurveInterface + 0x14)))(
                &curveId, 1, 0, *(f32 *)((char *)obj + 0xc), *(f32 *)((char *)obj + 0x10),
                *(f32 *)((char *)obj + 0x14)) != -1) {
            int pt = (*(int (*)(void))(*(int *)(*gRomCurveInterface + 0x1c)))();
            int pt2;
            *(f32 *)((char *)inner + 0x61c) = *(f32 *)((char *)pt + 0x8);
            *(f32 *)((char *)inner + 0x620) = *(f32 *)((char *)pt + 0xc);
            *(f32 *)((char *)inner + 0x624) = *(f32 *)((char *)pt + 0x10);
            *(f32 *)((char *)obj + 0xc) = *(f32 *)((char *)pt + 0x8);
            *(f32 *)((char *)obj + 0x10) = *(f32 *)((char *)pt + 0xc);
            *(f32 *)((char *)obj + 0x14) = *(f32 *)((char *)pt + 0x10);
            *(s16 *)((char *)inner + 0x478) =
                (s16)getAngle(*(f32 *)((char *)inner + 0x60c), *(f32 *)((char *)inner + 0x614));
            *(s16 *)((char *)inner + 0x484) = *(s16 *)((char *)inner + 0x478);
            sqrtf(*(f32 *)((char *)inner + 0x60c) * *(f32 *)((char *)inner + 0x60c) +
                  *(f32 *)((char *)inner + 0x614) * *(f32 *)((char *)inner + 0x614));
            *(s16 *)((char *)obj + 0x2) = 0;
            if ((*(int (*)(int, int))(*(int *)(*gRomCurveInterface + 0x54)))(pt, -1) == -1) {
                (*(int (*)(int, int))(*(int *)(*gRomCurveInterface + 0x60)))(pt, -1);
            }
            pt2 = (*(int (*)(void))(*(int *)(*gRomCurveInterface + 0x1c)))();
            *(f32 *)((char *)inner + 0x628) = *(f32 *)((char *)pt2 + 0x8);
            *(f32 *)((char *)inner + 0x62c) = *(f32 *)((char *)pt2 + 0xc);
            *(f32 *)((char *)inner + 0x630) = *(f32 *)((char *)pt2 + 0x10);
            *(f32 *)((char *)inner + 0x640) = lbl_803E7EA4;
            PSVECSubtract((f32 *)((char *)inner + 0x628), (f32 *)((char *)inner + 0x61c), vec);
            *(f32 *)((char *)inner + 0x644) = PSVECMag(vec);
            PSVECNormalize(vec, (f32 *)((char *)inner + 0x634));
        }
        ObjAnim_SetCurrentMove(obj, 0x40e, lbl_803E7EA4, 0);
        {
            u8 anim = *(u8 *)((char *)inner + 0x8c8);
            if (anim != 0x48 && anim != 0x47) {
                (*(void (*)(int, int, int, int, int, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
                    0x50, 1, 0, 0, 0, 0x28, 0xff);
            }
        }
        *(f32 *)((char *)state + 0x294) = lbl_803E7EA4;
        break;
    }
    }
    PSVECScale((f32 *)((char *)inner + 0x634), vec, *(f32 *)((char *)inner + 0x640));
    PSVECAdd((f32 *)((char *)inner + 0x61c), vec, (f32 *)((char *)obj + 0xc));
    fn_802AB5A4(obj, inner, 7);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void playerInitFuncPtrs(int obj)
{
    int *p = lbl_803DAFC8;
    p[0] = (int)fn_802A7160;
    p[1] = (int)fn_802A6694;
    p[2] = (int)fn_802A5384;
    p[3] = (int)fn_802A5048;
    p[4] = (int)fn_802A4F8C;
    p[5] = (int)fn_802A4D34;
    p[6] = (int)fn_802A4B78;
    p[7] = (int)fn_802A49C8;
    p[8] = (int)fn_802A418C;
    p[9] = (int)fn_802A3F24;
    p[10] = (int)fn_802A3B04;
    p[11] = (int)fn_802A36EC;
    p[12] = (int)fn_802A2EE0;
    p[13] = (int)fn_802A2E8C;
    p[14] = (int)fn_802A2918;
    p[15] = (int)fn_802A1CA8;
    p[16] = (int)fn_802A16CC;
    p[17] = (int)fn_802A14F8;
    p[18] = (int)fn_802A1114;
    p[19] = (int)fn_802A0680;
    p[20] = (int)fn_802A03BC;
    p[21] = (int)fn_802A00E0;
    p[22] = (int)fn_8029FA24;
    p[23] = (int)fn_8029F9D4;
    p[24] = (int)fn_8029F6E4;
    p[25] = (int)fn_8029F108;
    p[26] = (int)fn_8029EBCC;
    p[27] = (int)fn_8029E568;
    p[28] = (int)fn_8029E3F4;
    p[29] = (int)fn_8029DB70;
    p[30] = (int)fn_8029DA60;
    p[31] = (int)fn_8029D900;
    p[32] = (int)fn_8029D7F0;
    p[33] = (int)fn_8029D4C0;
    p[34] = (int)fn_8029D454;
    p[35] = (int)fn_8029D250;
    p[36] = (int)fn_8029CF30;
    p[37] = (int)fn_8029C9C8;
    p[38] = (int)fn_8029BDB4;
    p[39] = (int)fn_8029BC4C;
    p[40] = (int)fn_8029B9FC;
    p[41] = (int)fn_8029B994;
    p[42] = (int)fn_8029B7B0;
    p[43] = (int)fn_8029B6BC;
    p[44] = (int)fn_8029AF9C;
    p[45] = (int)fn_8029ABD8;
    p[46] = (int)fn_8029A76C;
    p[47] = (int)fn_8029A5E4;
    p[48] = (int)fn_80299E44;
    p[49] = (int)fn_80299BB0;
    p[50] = (int)fn_802994D0;
    p[51] = (int)fn_80298E54;
    p[52] = (int)fn_80298CCC;
    p[53] = (int)fn_80298944;
    p[54] = (int)fn_802985FC;
    p[55] = (int)fn_8029852C;
    p[56] = (int)fn_80298380;
    p[57] = (int)fn_80298184;
    p[58] = (int)fn_80297F48;
    p[59] = (int)fn_80297D0C;
    p[60] = (int)fn_80297AD0;
    p[61] = (int)fn_80297854;
    p[62] = (int)fn_80297824;
    p[63] = (int)fn_802977A8;
    p[64] = (int)fn_80297748;
    p[65] = (int)fn_802974A0;
    lbl_803DE4B8 = (int)fn_80297498;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80298944(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);
    f32 f;

    if (*(s8 *)((char *)state + 0x27a) != 0) {
        ObjHits_MarkObjectPositionDirty(obj);
    }
    f = lbl_803E7EA4;
    *(f32 *)((char *)state + 0x294) = f;
    *(f32 *)((char *)state + 0x284) = f;
    *(f32 *)((char *)state + 0x280) = f;
    *(f32 *)((char *)obj + 0x24) = f;
    *(f32 *)((char *)obj + 0x28) = f;
    *(f32 *)((char *)obj + 0x2c) = f;
    setAButtonIcon(0xe);
    setBButtonIcon(0xa);
    switch (*(s16 *)((char *)obj + 0xa0)) {
    case 0xe0:
        if (*(f32 *)((char *)obj + 0x98) > lbl_803E7E98 &&
            (*(u8 *)((char *)state + 0x356) & 1) == 0) {
            *(u8 *)((char *)state + 0x356) |= 1;
            Sfx_PlayFromObject(obj, 0x376);
        }
        if (*(s8 *)((char *)state + 0x346) != 0) {
            ObjAnim_SetCurrentMove(obj, 0xdf, lbl_803E7EA4, 0);
            *(f32 *)((char *)state + 0x2a0) = lbl_803E7F40;
            *(u8 *)((char *)state + 0x356) = 0;
        }
        break;
    case 0xde:
        if (*(f32 *)((char *)obj + 0x98) > lbl_803E7E9C &&
            (*(u8 *)((char *)state + 0x356) & 1) == 0) {
            *(u8 *)((char *)state + 0x356) |= 1;
            doRumble(lbl_803E7F10);
            Sfx_PlayFromObject(obj, 0x377);
            cfPrisonGuard_setGameBitMirror(lbl_803DE434, 0);
        }
        if (*(s8 *)((char *)state + 0x346) != 0) {
            ObjAnim_SetCurrentMove(obj, 0xe4, lbl_803E7EA4, 0);
            *(f32 *)((char *)state + 0x2a0) = lbl_803E7F40;
            Sfx_PlayFromObject(obj, 0x3c3);
        }
        break;
    case 0xe1:
        if (*(f32 *)((char *)obj + 0x98) > lbl_803E7E98 &&
            (*(u8 *)((char *)state + 0x356) & 1) == 0) {
            *(u8 *)((char *)state + 0x356) |= 1;
            Sfx_PlayFromObject(obj, 0x376);
        }
        if (*(s8 *)((char *)state + 0x346) != 0) {
            ObjAnim_SetCurrentMove(obj, 0xde, lbl_803E7EA4, 0);
            *(f32 *)((char *)state + 0x2a0) = lbl_803E7F40;
            *(u8 *)((char *)state + 0x356) = 0;
        }
        break;
    case 0xdf:
        if (*(f32 *)((char *)obj + 0x98) > lbl_803E7E9C &&
            (*(u8 *)((char *)state + 0x356) & 1) == 0) {
            *(u8 *)((char *)state + 0x356) |= 1;
            doRumble(lbl_803E7F10);
            Sfx_PlayFromObject(obj, 0x377);
            cfPrisonGuard_setGameBitMirror(lbl_803DE434, 1);
        }
        if (*(s8 *)((char *)state + 0x346) != 0) {
            ObjAnim_SetCurrentMove(obj, 0xe5, lbl_803E7EA4, 0);
            *(f32 *)((char *)state + 0x2a0) = lbl_803E7F40;
            Sfx_PlayFromObject(obj, 0x3c3);
        }
        break;
    case 0xe4:
    case 0xe5:
        if (*(s8 *)((char *)state + 0x346) != 0) {
            *(int *)((char *)inner + 0x360) |= 0x800000;
            *(int *)((char *)state + 0x308) = (int)fn_802A514C;
            return 2;
        }
        break;
    default:
        if (cfPrisonGuard_isGameBitMirrorSet(lbl_803DE434) != 0) {
            ObjAnim_SetCurrentMove(obj, 0xe1, lbl_803E7EA4, 0);
        } else {
            ObjAnim_SetCurrentMove(obj, 0xe0, lbl_803E7EA4, 0);
        }
        staffactivated_calcInteractionTargetXZ(lbl_803DE434, (char *)obj + 0xc, (char *)obj + 0x14);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7F40;
        *(u8 *)((char *)state + 0x356) = 0;
        *(s16 *)((char *)inner + 0x478) = *(s16 *)lbl_803DE434;
        *(s16 *)((char *)inner + 0x484) = *(s16 *)((char *)inner + 0x478);
        if (lbl_803DE44C != NULL && ((ByteFlags *)((char *)inner + 0x3f4))->b40) {
            *(u8 *)((char *)inner + 0x8b4) = 4;
            ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 1;
        }
        break;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802985FC(int obj, int state, f32 fv)
{
    int inner = *(int *)((char *)obj + 0xb8);
    f32 f;

    *(int *)state |= 0x200000;
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        ((ByteFlags *)((char *)inner + 0x3f3))->b10 = 0;
        if (*(s16 *)((char *)inner + 0x80a) == 0xc55) {
            *(u8 *)((char *)inner + 0x41c) = 0x14;
        } else {
            *(u8 *)((char *)inner + 0x41c) = 0xa;
        }
        ObjHits_MarkObjectPositionDirty(obj);
    }
    if (((ByteFlags *)((char *)inner + 0x3f0))->b20 == 0 &&
        lbl_803E7EA4 != *(f32 *)((char *)inner + 0x784)) {
        *(int *)((char *)state + 0x308) = 0;
        return 0x42;
    }
    switch (*(s16 *)((char *)obj + 0xa0)) {
    case 0x84:
        if (*(s8 *)((char *)state + 0x346) != 0) {
            ObjAnim_SetCurrentMove(obj, 0x85, lbl_803E7EA4, 0);
            *(f32 *)((char *)state + 0x2a0) = lbl_803E7EFC;
        }
        break;
    case 0x85:
        *(f32 *)((char *)inner + 0x7d4) =
            *(f32 *)((char *)inner + 0x7d4) + lbl_803E7ED4 * fv / lbl_803E7EF0;
        *(f32 *)((char *)inner + 0x7d4) =
            lbl_803E7E98 * fv + *(f32 *)((char *)inner + 0x7d4);
        if (*(f32 *)((char *)inner + 0x7d4) >=
            (f32)(u32) * (u8 *)((char *)inner + 0x41c)) {
            int amt;
            int r35c;
            int v;
            Sfx_PlayFromObject(obj, SFXmammoth_breath2);
            amt = -*(u8 *)((char *)inner + 0x41c);
            r35c = *(int *)((char *)(*(int *)((char *)obj + 0xb8)) + 0x35c);
            v = *(s16 *)((char *)r35c + 4) + amt;
            if (v < 0) {
                v = 0;
            } else if (v > *(s16 *)((char *)r35c + 6)) {
                v = *(s16 *)((char *)r35c + 6);
            }
            *(s16 *)((char *)r35c + 4) = v;
            if (amt > 0) {
                Sfx_PlayFromObject(0, SFXmammoth_dirtstep);
            }
            ObjAnim_SetCurrentMove(obj, 0x86, lbl_803E7EA4, 0);
            *(f32 *)((char *)state + 0x2a0) = lbl_803E7EF8;
        }
        break;
    case 0x86:
        if (((ByteFlags *)((char *)inner + 0x3f3))->b10 == 0 &&
            *(f32 *)((char *)obj + 0x98) > lbl_803E7EFC) {
            void *tricky = getTrickyObject();
            if (tricky != NULL) {
                trickyImpress(tricky);
            }
            Sfx_PlayFromObject(obj, SFXmammoth_huff1);
            superQuakeFn_8016d9fc((char *)obj + 0xc);
            ((ByteFlags *)((char *)inner + 0x3f3))->b10 = 1;
            doRumble(lbl_803E7F30);
        }
        if (*(s8 *)((char *)state + 0x346) != 0) {
            *(int *)((char *)inner + 0x360) |= 0x800000;
            *(int *)((char *)state + 0x308) = (int)fn_802A514C;
            return 2;
        }
        break;
    default:
        Sfx_PlayFromObject(obj, SFXmammoth_huff2);
        f = lbl_803E7EA4;
        *(f32 *)((char *)state + 0x294) = f;
        *(f32 *)((char *)state + 0x284) = f;
        *(f32 *)((char *)state + 0x280) = f;
        *(f32 *)((char *)obj + 0x24) = f;
        *(f32 *)((char *)obj + 0x28) = f;
        *(f32 *)((char *)obj + 0x2c) = f;
        ObjAnim_SetCurrentMove(obj, 0x84, f, 0);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7F34;
        *(f32 *)((char *)inner + 0x7d4) = lbl_803E7EA4;
        ((ByteFlags *)((char *)inner + 0x3f3))->b10 = 0;
        if (lbl_803DE44C != NULL && ((ByteFlags *)((char *)inner + 0x3f4))->b40) {
            *(u8 *)((char *)inner + 0x8b4) = 4;
            ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 1;
        }
        break;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802AE9C8(int obj, int inner, int state)
{
    if (*(f32 *)((char *)obj + 0x98) > lbl_803E7E98) {
        ObjAnim_SetCurrentMove(obj, 0x91, lbl_803E7EA4, 0);
    } else {
        ObjAnim_SetCurrentMove(obj, 0x12, lbl_803E7EA4, 0);
    }
    ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent *)obj, 0xf);

    *(f32 *)((char *)inner + 0x404) = lbl_803E8068;
    *(f32 *)((char *)inner + 0x408) =
        lbl_803E7EA0 * (lbl_803E806C * *(f32 *)((char *)state + 0x298)) +
        lbl_803E7EB4 * *(f32 *)((char *)state + 0x294);
    {
        f32 v = *(f32 *)((char *)inner + 0x408);
        f32 clamped;
        if (v < lbl_803E7F18) {
            clamped = lbl_803E7F18;
        } else if (v > *(f32 *)((char *)inner + 0x404)) {
            clamped = *(f32 *)((char *)inner + 0x404);
        } else {
            clamped = v;
        }
        *(f32 *)((char *)inner + 0x408) = clamped;
    }
    *(f32 *)((char *)state + 0x280) = *(f32 *)((char *)inner + 0x408);
    *(f32 *)((char *)state + 0x294) = *(f32 *)((char *)inner + 0x408);

    *(f32 *)((char *)obj + 0x28) = *(f32 *)((char *)state + 0x280) / lbl_803E8068;
    {
        f32 v = *(f32 *)((char *)obj + 0x28);
        f32 clamped;
        if (v < lbl_803E7EA4) {
            clamped = lbl_803E7EA4;
        } else if (v > lbl_803E7EE0) {
            clamped = lbl_803E7EE0;
        } else {
            clamped = v;
        }
        *(f32 *)((char *)obj + 0x28) = clamped;
    }
    *(f32 *)((char *)obj + 0x28) = *(f32 *)((char *)obj + 0x28) * lbl_803DC680;
    {
        f32 v = *(f32 *)((char *)obj + 0x28);
        f32 clamped;
        if (v < lbl_803E7E98) {
            clamped = lbl_803E7E98;
        } else if (v > lbl_803DC680) {
            clamped = lbl_803DC680;
        } else {
            clamped = v;
        }
        *(f32 *)((char *)obj + 0x28) = clamped;
    }
    *(f32 *)((char *)state + 0x2a0) =
        lbl_803E7EE0 / (lbl_803E7ED4 * lbl_803DC680 / lbl_803DC67C);
    *(f32 *)((char *)inner + 0x84c) = *(f32 *)((char *)obj + 0x1c);
    *(f32 *)((char *)inner + 0x850) = *(f32 *)((char *)obj + 0x1c) - lbl_803E7ED8;

    ((ByteFlags *)((char *)inner + 0x3f0))->b08 = 1;
    ((ByteFlags *)((char *)inner + 0x3f0))->b04 = 0;
    *(u8 *)((char *)inner + 0x40d) = 0;
    ((ByteFlags *)((char *)inner + 0x3f0))->b10 = 0;
    ((ByteFlags *)((char *)inner + 0x3f0))->b80 = 0;
    staffFn_80170380(lbl_803DE450, 2);
    ((ByteFlags *)((char *)inner + 0x3f0))->b02 = 0;
    *(int *)((char *)inner + 0x360) |= 0x800000;
    ObjHits_SyncObjectPositionIfDirty(obj);
    if (((ByteFlags *)((char *)inner + 0x3f0))->b40) {
        *(s16 *)((char *)inner + 0x484) += -0x8000;
    }
    ((ByteFlags *)((char *)inner + 0x3f0))->b40 = 0;
    ((ByteFlags *)((char *)inner + 0x3f1))->b01 = 0;
    *(u8 *)((char *)inner + 0x40c) = 0;
    if (((ByteFlags *)((char *)inner + 0x3f1))->b20) {
        int t = *(s16 *)obj;
        *(s16 *)((char *)inner + 0x484) = t;
        *(s16 *)((char *)inner + 0x478) = t;
        *(int *)((char *)inner + 0x494) = t;
        *(f32 *)((char *)inner + 0x284) = lbl_803E7EA4;
    }
    ((ByteFlags *)((char *)inner + 0x3f1))->b20 = 0;
    if (((ByteFlags *)((char *)inner + 0x3f1))->b10 &&
        *(u8 *)((char *)inner + 0x8c8) != 0x48 &&
        *(u8 *)((char *)inner + 0x8c8) != 0x47 && getCurSeqNo() == 0) {
        (*(void (*)(int, int, int, int, int, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
            0x42, 0, 1, 0, 0, 0x1e, 0xff);
        ((ByteFlags *)((char *)inner + 0x3f1))->b10 = 0;
    }
    {
        u16 sfxId;
        if (*(s16 *)((char *)inner + 0x81a) == 0) {
            sfxId = 0x2d7;
        } else {
            sfxId = 0x2d6;
        }
        Sfx_PlayFromObject(obj, sfxId);
    }
    *(u8 *)((char *)inner + 0x800) = 0;
    {
        void *sub = *(void **)((char *)inner + 0x7f8);
        if (sub != NULL) {
            s16 id = *(s16 *)((char *)sub + 0x46);
            if (id == 0x3cf || id == 0x662) {
                objThrowFn_80182504((int)sub);
            } else {
                objSaveFn_800ea774((int)sub);
            }
            *(s16 *)((char *)*(int *)((char *)inner + 0x7f8) + 0x6) &= ~0x4000;
            *(int *)((char *)*(int *)((char *)inner + 0x7f8) + 0xf8) = 0;
            *(int *)((char *)inner + 0x7f8) = 0;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_8029D4C0(int obj, int state, f32 fv)
{
    int inner = *(int *)((char *)obj + 0xb8);
    u16 sfxId;
    int d;

    switch (*(s16 *)((char *)obj + 0xa0)) {
    case 0x450:
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7FCC;
        if (*(f32 *)((char *)obj + 0x28) < lbl_803E7EE0 &&
            ((ByteFlags *)((char *)inner + 0x3f1))->b01) {
            if (*(s16 *)((char *)inner + 0x81a) == 0) {
                sfxId = 0x2d2;
            } else {
                sfxId = 0x214;
            }
            Sfx_PlayFromObject(obj, sfxId);
            ObjAnim_SetCurrentMove(obj, 0xc6, lbl_803E7EA4, 0);
        }
        if (*(f32 *)((char *)obj + 0x24) * *(f32 *)((char *)obj + 0x24) +
                *(f32 *)((char *)obj + 0x2c) * *(f32 *)((char *)obj + 0x2c) >
            lbl_803E7EE0) {
            d = (u16)getAngle(*(f32 *)((char *)obj + 0x24), *(f32 *)((char *)obj + 0x2c)) -
                (u16) * (s16 *)((char *)inner + 0x478);
            if (d > 0x8000) {
                d -= 0xffff;
            }
            if (d < -0x8000) {
                d += 0xffff;
            }
            *(s16 *)((char *)inner + 0x478) =
                *(s16 *)((char *)inner + 0x478) + (d * (int)fv >> 3);
            *(s16 *)((char *)inner + 0x484) = *(s16 *)((char *)inner + 0x478);
        }
        break;
    case 0xc4:
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7F6C;
        if (*(f32 *)((char *)obj + 0x28) < lbl_803E7EE0 &&
            ((ByteFlags *)((char *)inner + 0x3f1))->b01) {
            if (*(s16 *)((char *)inner + 0x81a) == 0) {
                sfxId = 0x2d2;
            } else {
                sfxId = 0x214;
            }
            Sfx_PlayFromObject(obj, sfxId);
            ObjAnim_SetCurrentMove(obj, 0xc6, lbl_803E7EA4, 0);
        }
        if (*(f32 *)((char *)obj + 0x24) * *(f32 *)((char *)obj + 0x24) +
                *(f32 *)((char *)obj + 0x2c) * *(f32 *)((char *)obj + 0x2c) >
            lbl_803E7EE0) {
            d = (u16)getAngle(*(f32 *)((char *)obj + 0x24), *(f32 *)((char *)obj + 0x2c)) -
                (u16) * (s16 *)((char *)inner + 0x478);
            if (d > 0x8000) {
                d -= 0xffff;
            }
            if (d < -0x8000) {
                d += 0xffff;
            }
            *(s16 *)((char *)inner + 0x478) =
                *(s16 *)((char *)inner + 0x478) + (d * (int)fv >> 3);
            *(s16 *)((char *)inner + 0x484) = *(s16 *)((char *)inner + 0x478);
        }
        break;
    case 0xc6:
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7F6C;
        if (*(s8 *)((char *)state + 0x346) != 0) {
            ObjAnim_SetCurrentMove(obj, 0xc8, lbl_803E7EA4, 0);
        }
        *(f32 *)((char *)obj + 0x24) = lbl_803E7EA4;
        *(f32 *)((char *)obj + 0x2c) = lbl_803E7EA4;
        break;
    case 0xc8:
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7EF8;
        if (*(s8 *)((char *)state + 0x346) != 0) {
            *(int *)((char *)inner + 0x360) |= 0x800000;
            *(int *)((char *)state + 0x308) = (int)fn_802A514C;
            return -1;
        }
        break;
    default:
        ObjAnim_SetCurrentMove(obj, 0xc4, lbl_803E7EA4, 0);
        break;
    }
    *(s8 *)((char *)state + 0x34c) |= 2;
    *(f32 *)((char *)obj + 0x24) =
        *(f32 *)((char *)obj + 0x24) * powfBitEstimate(lbl_803E7FD0, fv);
    *(f32 *)((char *)obj + 0x2c) =
        *(f32 *)((char *)obj + 0x2c) * powfBitEstimate(lbl_803E7FD0, fv);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int Lightfoot_UpdateChallengeGateInteraction(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int r4c;
    int sub;
    int v;

    if (*(void **)((char *)state + 0x2d0) != NULL) {
        sub = *(int *)((char *)inner + 0x40c);
        v = (s16) * (u16 *)((char *)sub + 0x20);
        if (v < 0) {
            v = -v;
        }
        if ((u16)v < 0x1770) {
            r4c = *(int *)((char *)obj + 0x4c);
            *(u8 *)((char *)obj + 0xaf) &= ~8;
            switch (*(int *)((char *)r4c + 0x14)) {
            case 0x46a51:
                if (GameBit_Get(0xc52)) {
                    *(u8 *)((char *)obj + 0xaf) |= 8;
                }
                break;
            case 0x46a55:
                if (GameBit_Get(0xc53)) {
                    *(u8 *)((char *)obj + 0xaf) |= 8;
                }
                break;
            case 0x49928:
                if (GameBit_Get(0xc54)) {
                    *(u8 *)((char *)obj + 0xaf) |= 8;
                }
                break;
            }
            if ((*(u8 *)((char *)obj + 0xaf) & 1) != 0) {
                buttonDisable(0, 0x100);
                switch (*(int *)((char *)r4c + 0x14)) {
                case 0x46a51:
                    if (GameBit_Get(0xc38) != 0 && GameBit_Get(0xc39) != 0 &&
                        GameBit_Get(0xc3a) != 0) {
                        if (GameBit_Get(0xc52) == 0) {
                            GameBit_Set(0xc52, 1);
                            (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(3, obj, -1);
                            *(u8 *)((char *)sub + 0x2e) = 1;
                            *(u8 *)((char *)obj + 0xaf) |= 8;
                        }
                    } else {
                        (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(2, obj, -1);
                    }
                    break;
                case 0x46a55:
                    if (GameBit_Get(0xc3b) != 0 && GameBit_Get(0xc3c) != 0 &&
                        GameBit_Get(0xc3d) != 0) {
                        if (GameBit_Get(0xc53) == 0) {
                            GameBit_Set(0xc53, 1);
                            (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(5, obj, -1);
                            *(u8 *)((char *)sub + 0x2e) = 1;
                            *(u8 *)((char *)obj + 0xaf) |= 8;
                        }
                    } else {
                        (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(4, obj, -1);
                    }
                    break;
                case 0x49928:
                    if (GameBit_Get(0xc3e) != 0 && GameBit_Get(0xc3f) != 0 &&
                        GameBit_Get(0xc40) != 0) {
                        if (GameBit_Get(0xc54) == 0) {
                            GameBit_Set(0xc54, 1);
                            (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(7, obj, -1);
                            *(u8 *)((char *)sub + 0x2e) = 1;
                            *(u8 *)((char *)obj + 0xaf) |= 8;
                        }
                    } else {
                        (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(6, obj, -1);
                    }
                    break;
                }
            }
        } else {
            *(u8 *)((char *)obj + 0xaf) |= 8;
        }
        if (*(s8 *)((char *)state + 0x27b) != 0 || *(s8 *)((char *)state + 0x346) != 0) {
            (*(void (*)(int, int, int))(*(int *)(*gPlayerInterface + 0x14)))(obj, state, 0);
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void playerProcessQueuedItemCommand(int obj, int state)
{
    u8 noMatch;
    s16 cmd;
    s16 item;

    if (*(u16 *)((char *)state + 0x6e2) & 0x800) {
        int yButtonItemResult;
        if (*(u16 *)((char *)state + 0x6e2) & 0x800) {
            yButtonItemResult = getYButtonItem(&item);
        }
        if (yButtonItemResult == 1) {
            buttonDisable(0, 0x800);
            *(u16 *)((char *)state + 0x6e2) &= ~0x800;
            *(s16 *)((char *)state + 0x80c) = item;
        }
    }

    cmd = *(s16 *)((char *)state + 0x80c);
    if (cmd != -1 && cmd != *(s16 *)((char *)state + 0x80a) && getCurSeqNo() == 0) {
        s16 sel = *(s16 *)((char *)state + 0x80c);
        noMatch = 0;
        switch (sel) {
        case 0x2d:
        case 0x958:
        case 0x5ce:
            if (fn_802A9B1C(obj, state, sel) != 0) {
                ByteFlags *f1 = (ByteFlags *)((char *)state + 0x3f1);
                u8 c8;
                if (*(void **)((char *)state + 0x2d0) != NULL) {
                    break;
                }
                c8 = *(u8 *)((char *)state + 0x8c8);
                if (c8 == 0x49) {
                    break;
                }
                if (c8 == 0x52 && !f1->b20 && !f1->b10 &&
                    *(s16 *)((char *)state + 0x274) != 0x1d) {
                    break;
                }
                if (f1->b20) {
                    s16 v = *(s16 *)((char *)obj + 0);
                    *(s16 *)((char *)state + 0x484) = v;
                    *(s16 *)((char *)state + 0x478) = v;
                    *(int *)((char *)state + 0x494) = v;
                    *(f32 *)((char *)state + 0x284) = lbl_803E7EA4;
                }
                f1->b20 = 0;
                if (f1->b10) {
                    u8 c = *(u8 *)((char *)state + 0x8c8);
                    if (c != 0x48 && c != 0x47 && getCurSeqNo() == 0) {
                        (*(void (*)(int, int, int, int, int, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
                            0x42, 0, 1, 0, 0, 0x1e, 0xff);
                        f1->b10 = 0;
                    }
                }
                cameraSetInterpMode(2);
                (*(void (*)(int, int, int, int, int, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
                    0x52, 1, 0, 0, 0, 0x2d, 0xff);
                ((ByteFlags *)((char *)state + 0x3f6))->b40 = 1;
                (*(void (*)(int, int, int))(*(int *)(*gPlayerInterface + 0x14)))(obj, state, 0x2a);
                *(int *)((char *)state + 0x304) = (int)fn_8029A4A8;
                fn_802AB38C(obj, state, *(s16 *)((char *)state + 0x80c));
            } else {
                noMatch = 1;
            }
            break;
        case 0x957:
            if (fn_802A97D0(obj, state) != 0) {
                fn_802AB38C(obj, state, *(s16 *)((char *)state + 0x80c));
            } else {
                noMatch = 1;
            }
            break;
        case 0x107:
        case 0xc55:
            if (fn_802A9A0C(obj, state) != 0) {
                fn_802AB38C(obj, state, *(s16 *)((char *)state + 0x80c));
            } else {
                noMatch = 1;
            }
            break;
        case 0x40: {
            int inner = *(int *)((char *)obj + 0xb8);
            int ok;
            if (*(void **)((char *)state + 0x2d0) != NULL ||
                *(s16 *)((char *)*(int *)((char *)inner + 0x35c) + 4) < 0xa ||
                ((ByteFlags *)((char *)inner + 0x3f3))->b08) {
                ok = 0;
            } else if (*(s16 *)((char *)state + 0x274) == 1 ||
                       *(s16 *)((char *)state + 0x274) == 2) {
                ok = 1;
            } else {
                ok = 0;
            }
            if (ok && !((ByteFlags *)((char *)state + 0x3f3))->b08) {
                fn_802AB38C(obj, state, sel);
            } else {
                noMatch = 1;
            }
            break;
        }
        case 0x5bd:
            if (fn_802A98FC(obj, state) != 0) {
                fn_802AB38C(obj, state, *(s16 *)((char *)state + 0x80c));
            } else {
                noMatch = 1;
            }
            break;
        default:
            fn_802AB38C(obj, state, sel);
            break;
        }
        if (noMatch) {
            Sfx_PlayFromObject(0, SFXsp_skeep_mumb1);
        }
    }

    *(s16 *)((char *)state + 0x80c) = -1;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802AAD44(int obj)
{
    int state = *(int *)((char *)obj + 0xb8);
    u8 *vp = lbl_803DAF08;
    f32 *src = lbl_802C2BF0;
    int i;
    f32 height;
    f32 v;
    struct {
        s16 rx, ry, rz, pad;
        f32 scale;
        f32 px, py, pz;
    } xf;
    f32 mtx[12];

    height = *(f32 *)((char *)state + 0x7d0);
    setTextColor((undefined4 *)0, 0xff, 0xff, 0xff, 0x80);
    textureSetupFn_800799c0();
    textRenderSetupFn_800795e8();
    textRenderSetupFn_80079804();
    fn_80078740();
    GXSetColorUpdate(0);

    v = lbl_803E7FA4 * (lbl_803E80C4 - height);
    for (i = 0; i < 8; i++) {
        if (i < 4) {
            *(s16 *)(vp + 2) = 0x320;
        } else {
            *(s16 *)(vp + 2) = (s16)(s32)v;
        }
        if (i < 4) {
            *(s16 *)(vp + 0) = (s16)(s32)(lbl_803E7FA4 * src[0]);
            *(s16 *)(vp + 4) = (s16)(s32)(lbl_803E7FA4 * src[2]);
        } else {
            *(s16 *)(vp + 0) = (s16)(s32)(lbl_803E7FA4 * src[0]);
            *(s16 *)(vp + 4) = (s16)(s32)(lbl_803E7FA4 * src[2]);
        }
        vp[0xc] = 0xff;
        vp[0xd] = 0;
        vp[0xe] = 0;
        vp[0xf] = 0x40;
        vp += 0x10;
        src += 3;
    }

    xf.px = *(f32 *)((char *)obj + 0xc) - playerMapOffsetX;
    xf.py = *(f32 *)((char *)obj + 0x10);
    xf.pz = *(f32 *)((char *)obj + 0x14) - playerMapOffsetZ;
    xf.rx = *(s16 *)((char *)state + 0x478);
    xf.ry = 0;
    xf.rz = 0;
    xf.scale = lbl_803E7F6C;
    setMatrixFromObjectTransposed(&xf, mtx);
    PSMTXConcat(Camera_GetViewMatrix(), mtx, mtx);
    GXLoadPosMtxImm(mtx, 0);
    drawFn_8005cf8c(lbl_803DAF08, lbl_802C2B30, 0xc);

    if (*(f32 *)((char *)state + 0x7d0) >= lbl_803E80E0) {
        int t = *(u8 *)((char *)obj + 0x36) - (framesThisStep << 2);
        if (t < 0) {
            t = 0;
        }
        *(u8 *)((char *)obj + 0x36) = t;
    }
    GXSetColorUpdate(1);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_8029560C(int obj, int *state)
{
    int v = *state;
    if ((void *)lbl_803DE420 != NULL) {
        tailFn_80026c38(lbl_803DE420, lbl_803DC670, lbl_803DC674, lbl_803DC678);
        playerTailFn_80026b3c(state, v, lbl_803DE420, fn_80295334);
    }
}
#pragma peephole reset
#pragma scheduling reset

void fn_80295918(int obj, int sel, f32 fval)
{
    int state = *(int *)((char *)obj + 0xb8);
    int iv = (int)fval;
    switch (sel) {
    case 1: {
        u8 n = *(u8 *)((char *)state + 0x8b8);
        if (n < 4) {
            *(u8 *)((char *)state + 0x8b8) = n + 1;
            *(u8 *)((char *)state + n + 0x8b9) = (u8)iv;
        }
        break;
    }
    case 6:
        (*(void (*)(int, int, int))(*(int *)(*gPlayerInterface + 0x14)))(obj, state, 0x3f);
        break;
    case 5:
        (*(void (*)(int, int, int))(*(int *)(*gPlayerInterface + 0x14)))(obj, state, 1);
        *(int *)((char *)state + 0x304) = (int)fn_802A514C;
        break;
    case 10:
        *(u32 *)((char *)state + 0x360) |= 0x80000;
        break;
    case 11:
        *(u32 *)((char *)state + 0x360) &= ~0x80000;
        break;
    }
}

#pragma scheduling off
#pragma peephole off
int fn_80295A04(int obj, int sel)
{
    int state = *(int *)((char *)obj + 0xb8);
    switch (sel) {
    case 1:
        if ((*(int *)((char *)state + 0x310) & 0x1000) != 0 ||
            (*(u16 *)((char *)obj + 0xb0) & 0x1000) != 0)
            return 0;
        return 1;
    case 2:
        switch (*(s16 *)((char *)state + 0x274)) {
        case 1:
            return 0;
        case 2: {
            s16 *list;
            s16 key;
            int i;
            i = 0;
            list = *(s16 **)((char *)state + 0x3f8);
            key = *(s16 *)((char *)obj + 0xa0);
            while (key != *list && i < 0x14) {
                list += 4;
                i += 4;
            }
            return i / 4;
        }
        default:
            return 5;
        }
    case 9:
        return *(s8 *)((char *)state + 0x34d) == 3;
    case 10:
        return *(u32 *)((char *)state + 0x360) & 0x200;
    case 11:
        return *(u32 *)((char *)state + 0x360) & 0x100;
    case 13:
        return *(u8 *)((char *)state + 0x349) == 1;
    case 14:
        return *(s16 *)((char *)state + 0x80a);
    case 18: {
        void *p = *(void **)((char *)state + 0x7f0);
        if (p != 0) return *(s16 *)((char *)p + 0x46);
        return 0;
    }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802A8350(int obj, int p4, int src, int dst, int flag)
{
    int **hits;
    f32 pos[3];
    f32 y;
    f32 minDist;
    int best;
    int i;
    int count;
    int *chosen;

    *(u8 *)((char *)dst + 3) = 0;
    ((ByteFlags *)((char *)dst + 0x63))->b80 = 1;
    if ((*(s8 *)((char *)src + 0x52) & 0x08) == 0) {
        ((ByteFlags *)((char *)dst + 0x63))->b80 = 0;
    }

    *(f32 *)((char *)dst + 0x48) =
        *(f32 *)((char *)src + 0x4) +
        lbl_803E7E98 * (*(f32 *)((char *)src + 0x8) - *(f32 *)((char *)src + 0x4));
    *(f32 *)((char *)dst + 0x4c) = *(f32 *)((char *)src + 0xc);
    *(f32 *)((char *)dst + 0x50) =
        *(f32 *)((char *)src + 0x14) +
        lbl_803E7E98 * (*(f32 *)((char *)src + 0x18) - *(f32 *)((char *)src + 0x14));

    if (flag != 0) {
        *(f32 *)((char *)dst + 0x28) = -*(f32 *)((char *)src + 0x1c);
        *(f32 *)((char *)dst + 0x2c) = -*(f32 *)((char *)src + 0x20);
        *(f32 *)((char *)dst + 0x30) = -*(f32 *)((char *)src + 0x24);
        *(f32 *)((char *)dst + 0x34) = -*(f32 *)((char *)src + 0x28);
    } else {
        *(f32 *)((char *)dst + 0x28) = *(f32 *)((char *)src + 0x1c);
        *(f32 *)((char *)dst + 0x2c) = *(f32 *)((char *)src + 0x20);
        *(f32 *)((char *)dst + 0x30) = *(f32 *)((char *)src + 0x24);
        *(f32 *)((char *)dst + 0x34) = *(f32 *)((char *)src + 0x28);
    }

    *(f32 *)((char *)dst + 0x38) = -*(f32 *)((char *)src + 0x24);
    *(f32 *)((char *)dst + 0x3c) = lbl_803E7EA4;
    *(f32 *)((char *)dst + 0x40) = *(f32 *)((char *)src + 0x1c);
    *(f32 *)((char *)dst + 0x44) =
        -(*(f32 *)((char *)dst + 0x4c) * *(f32 *)((char *)dst + 0x3c) +
          *(f32 *)((char *)dst + 0x48) * *(f32 *)((char *)dst + 0x38) +
          *(f32 *)((char *)dst + 0x50) * *(f32 *)((char *)dst + 0x40));

    *(f32 *)((char *)dst + 0x54) = *(f32 *)((char *)p4 + 0x768);
    *(f32 *)((char *)dst + 0x58) = lbl_803E7EA4;
    *(f32 *)((char *)dst + 0x5c) = *(f32 *)((char *)p4 + 0x770);
    *(f32 *)((char *)dst + 0x18) =
        *(f32 *)((char *)dst + 0x58) * *(f32 *)((char *)dst + 0x3c) +
        *(f32 *)((char *)dst + 0x54) * *(f32 *)((char *)dst + 0x38) +
        *(f32 *)((char *)dst + 0x5c) * *(f32 *)((char *)dst + 0x40) +
        *(f32 *)((char *)dst + 0x44);

    *(s8 *)((char *)dst + 0x62) = *(s8 *)((char *)src + 0x53);

    if (*(f32 *)((char *)dst + 0x18) <= lbl_803E80A4) {
        return 0;
    }
    if (*(f32 *)((char *)dst + 0x18) >= lbl_803E80A8) {
        return 0;
    }

    *(f32 *)((char *)dst + 0x8) = *(f32 *)((char *)src + 0xc);
    PSVECScale((f32 *)((char *)src + 0x1c), pos, -lbl_803DC6B8[1]);
    PSVECAdd((f32 *)((char *)dst + 0x48), pos, pos);
    y = *(f32 *)((char *)src + 0x3c);
    pos[1] = y;
    count = hitDetectFn_80065e50(obj, &hits, 0, 0x204, pos[0], y, pos[2]);

    minDist = lbl_803E80AC;
    best = -1;
    for (i = 0; i < count; i++) {
        int *entry = hits[i];
        if (*(f32 *)((char *)entry + 0x8) > lbl_803E80B0) {
            f32 d = pos[1] - *(f32 *)((char *)entry + 0x0);
            if (d < lbl_803E7EA4) {
                d = -d;
            }
            if (d < minDist) {
                minDist = d;
                best = i;
            }
        }
    }

    chosen = hits[best];
    *(f32 *)((char *)dst + 0x4) = *(f32 *)((char *)chosen + 0x0);
    *(s8 *)((char *)dst + 0x1) =
        (s8)(s32)((lbl_803E80B4 + (*(f32 *)((char *)src + 0x3c) - *(f32 *)((char *)dst + 0x8))) /
                  lbl_803E80B8);
    *(f32 *)((char *)dst + 0xc) =
        (*(f32 *)((char *)src + 0x3c) - *(f32 *)((char *)dst + 0x8)) /
        (f32)*(s8 *)((char *)dst + 0x1);

    if (*(f32 *)((char *)obj + 0x10) > *(f32 *)((char *)dst + 0x4) - lbl_803E7ED8) {
        *(s8 *)((char *)dst + 0x0) = *(u8 *)((char *)dst + 0x1) - 3;
    } else {
        *(s8 *)((char *)dst + 0x0) = 1;
    }
    return 1;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802AEF34(int obj, int state)
{
    int prevChanged;
    int changed;
    int model;
    f32 f31;
    void *p;

    model = *(int *)((char *)Obj_GetActiveModel(obj) + 0x30);
    prevChanged = 0;

    if (*(s16 *)((char *)state + 0x806) != 3) {
        u8 b = *(u8 *)((char *)state + 0x8b4);
        if (b == 1) {
            staffDoGrowShrinkAnim(lbl_803DE44C, 0, ((ByteFlags *)((char *)state + 0x3f4))->b08, 0);
            *(u8 *)((char *)state + 0x8b3) = 0;
            if (*(s16 *)((char *)state + 0x806) != 0 && *(s16 *)((char *)state + 0x806) != 0xf) {
                *(s16 *)((char *)state + 0x806) = 3;
            }
        } else if (b == 4) {
            staffDoGrowShrinkAnim(lbl_803DE44C, 1, ((ByteFlags *)((char *)state + 0x3f4))->b08, 0);
            *(u8 *)((char *)state + 0x8b3) = 1;
            if (*(s16 *)((char *)state + 0x806) != 0 && *(s16 *)((char *)state + 0x806) != 0xf) {
                *(s16 *)((char *)state + 0x806) = 3;
            }
        }
    }

    f31 = -lbl_803E7F20;
    do {
        changed = 0;
        switch (*(s16 *)((char *)state + 0x806)) {
        case 2:
            if (prevChanged != 0) {
                Object_ObjAnimSetMove(*(f32 *)((char *)obj + 0x98), obj,
                                      *(s16 *)((char *)obj + 0xa0), 0);
                p = *(void **)((char *)state + 0x4b8);
                if (p != NULL &&
                    (*(s16 *)((char *)p + 0x44) == 0x1c || *(s16 *)((char *)p + 0x44) == 0x2a)) {
                    Object_ObjAnimSetMove(lbl_803E7EA4, obj, 0x82, 0);
                } else {
                    Object_ObjAnimSetMove(lbl_803E7EA4, obj, 0x8d, 0);
                }
                ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent *)obj, 0xc);
            }
            if (*(f32 *)((char *)obj + 0x9c) >= lbl_803E8130) {
                *(u8 *)((char *)state + 0x8b3) = 1;
            }
            if (*(f32 *)((char *)obj + 0x9c) >= lbl_803E7F1C) {
                staffDoGrowShrinkAnim(lbl_803DE44C, 1, 0, 0);
                *(s16 *)((char *)state + 0x806) = 3;
                changed = 1;
            } else {
                Object_ObjAnimAdvanceMove(lbl_803E7F20, lbl_803E7EE0, obj, NULL);
            }
            break;
        case 1:
            if (prevChanged != 0) {
                Object_ObjAnimSetMove(*(f32 *)((char *)obj + 0x98), obj,
                                      *(s16 *)((char *)obj + 0xa0), 0);
                p = *(void **)((char *)state + 0x4b8);
                if (p != NULL &&
                    (*(s16 *)((char *)p + 0x44) == 0x1c || *(s16 *)((char *)p + 0x44) == 0x2a)) {
                    Object_ObjAnimSetMove(lbl_803E7F68, obj, 0x82, 0);
                } else {
                    Object_ObjAnimSetMove(lbl_803E7F68, obj, 0x8d, 0);
                }
                ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent *)obj, 0xc);
            }
            if (*(f32 *)((char *)obj + 0x9c) <= lbl_803E8130) {
                *(u8 *)((char *)state + 0x8b3) = 0;
            }
            if (*(f32 *)((char *)obj + 0x9c) <= lbl_803E7EB4) {
                *(s16 *)((char *)state + 0x806) = 3;
                changed = 1;
            } else {
                Object_ObjAnimAdvanceMove(f31, lbl_803E7EE0, obj, NULL);
            }
            break;
        case 0xf:
            if (prevChanged != 0) {
                Object_ObjAnimSetMove(*(f32 *)((char *)obj + 0x98), obj,
                                      *(s16 *)((char *)obj + 0xa0), 0);
                Object_ObjAnimSetMove(lbl_803E7EA4, obj,
                                      lbl_8033366C[*(u8 *)((char *)state + 0x8a2)], 0);
                ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent *)obj, 0xc);
            }
            if (*(f32 *)((char *)obj + 0x9c) >= lbl_803E7EE0) {
                *(s16 *)((char *)state + 0x806) = 3;
                *(u8 *)((char *)state + 0x8a2) = 0xff;
                changed = 1;
            } else {
                int ok;
                ByteFlags *bf = (ByteFlags *)((char *)state + 0x3f0);
                if (bf->b10 || bf->b04 || bf->b08 || bf->b20 ||
                    *(s16 *)((char *)state + 0x274) == 0x36) {
                    ok = 0;
                } else {
                    s16 t = *(s16 *)((char *)state + 0x274);
                    ok = (u16)(t - 1) <= 1 || (u16)(t - 0x24) <= 1 ||
                         *(void **)((char *)state + 0x2d0) != NULL;
                }
                if (ok) {
                    Object_ObjAnimAdvanceMove(lbl_8033369C[*(u8 *)((char *)state + 0x8a2)],
                                              timeDelta, obj, NULL);
                } else {
                    *(s16 *)((char *)state + 0x806) = 3;
                    *(u8 *)((char *)state + 0x8a2) = 0xff;
                    changed = 1;
                }
            }
            break;
        case 3:
            if (*(s16 *)((char *)obj + 0xa2) != *(s16 *)((char *)obj + 0xa0)) {
                Object_ObjAnimSetMove(*(f32 *)((char *)obj + 0x98), obj,
                                      *(s16 *)((char *)obj + 0xa0), 0);
            }
            if (*(u16 *)((char *)model + 0x58) == 0) {
                *(s16 *)((char *)obj + 0xa2) = -1;
                *(s16 *)((char *)state + 0x806) = 0;
            } else {
                Object_ObjAnimAdvanceMove(lbl_803E7EA4, timeDelta, obj, NULL);
                Object_ObjAnimSetMoveProgress(*(f32 *)((char *)obj + 0x98), (ObjAnimComponent *)obj);
            }
            break;
        default:
            if (*(u8 *)((char *)state + 0x8b3) != 0) {
                if (*(u8 *)((char *)state + 0x8b4) == 0) {
                    staffDoGrowShrinkAnim(lbl_803DE44C, 0, 0, 0);
                    *(s16 *)((char *)state + 0x806) = 1;
                    changed = 1;
                }
            } else if (*(u8 *)((char *)state + 0x8b4) == 2) {
                *(s16 *)((char *)state + 0x806) = 2;
                changed = 1;
            }
            if (*(u8 *)((char *)state + 0x8a2) == 5 || *(u8 *)((char *)state + 0x8a2) == 7) {
                *(s16 *)((char *)state + 0x806) = 0xf;
                changed = 1;
            }
            break;
        }
        prevChanged = changed;
    } while (changed != 0);
}
#pragma peephole reset
#pragma scheduling reset

