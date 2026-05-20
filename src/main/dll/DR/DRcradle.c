#include "ghidra_import.h"
#include "main/dll/DR/DRcradle.h"

extern undefined4 FUN_80006824();
extern undefined4 FUN_8001774c();
extern undefined4 FUN_80017754();
extern undefined4 FUN_80017778();
extern undefined4 FUN_80247e94();
extern undefined4 FUN_80293130();

extern undefined4* DAT_803dd6d0;
extern f64 DOUBLE_803e6798;
extern f32 lbl_803DC074;
extern f32 lbl_803DC078;
extern f32 lbl_803E6780;
extern f32 lbl_803E6784;
extern f32 lbl_803E6790;
extern f32 lbl_803E67B8;
extern f32 lbl_803E67E0;
extern f32 lbl_803E6824;
extern f32 lbl_803E683C;
extern f32 lbl_803E6840;
extern f32 lbl_803E687C;
extern f32 lbl_803E688C;
extern f32 lbl_803E6894;
extern f32 lbl_803E6898;
extern f32 lbl_803E68C0;
extern f32 lbl_803E68C4;
extern f32 lbl_803E68C8;
extern f32 lbl_803E68CC;
extern f32 lbl_803E68D0;

/*
 * --INFO--
 *
 * Function: FUN_801ec7a0
 * EN v1.0 Address: 0x801EC7A0
 * EN v1.0 Size: 1424b
 * EN v1.1 Address: 0x801EC7E4
 * EN v1.1 Size: 1524b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ec7a0(uint param_1,int param_2)
{
  int iVar1;
  byte bVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  double dVar7;
  undefined4 local_78;
  undefined4 local_74;
  float local_70;
  float local_6c;
  float local_68;
  float local_64;
  float local_60 [2];
  undefined4 local_58;
  uint uStack_54;
  longlong local_50;
  longlong local_48;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  longlong local_30;
  undefined4 local_28;
  uint uStack_24;
  undefined8 local_20;
  undefined8 local_18;
  
  bVar2 = *(byte *)(param_2 + 0x428);
  if ((*(uint *)(param_2 + 0x458) & 0x100) == 0) {
    *(byte *)(param_2 + 0x428) = bVar2 & 0xbf;
  }
  else {
    *(byte *)(param_2 + 0x428) = bVar2 & 0xbf | 0x40;
  }
  if ((*(uint *)(param_2 + 0x458) & 0x200) == 0) {
    *(byte *)(param_2 + 0x428) = *(byte *)(param_2 + 0x428) & 0xef;
  }
  else {
    *(byte *)(param_2 + 0x428) = *(byte *)(param_2 + 0x428) & 0xef | 0x10;
  }
  if (((bVar2 >> 4 & 1) == 0) && ((*(byte *)(param_2 + 0x428) >> 4 & 1) != 0)) {
    FUN_80006824(param_1,0x45f);
  }
  fVar3 = lbl_803E6780;
  if ((*(byte *)(param_2 + 0x428) >> 6 & 1) != 0) {
    fVar3 = *(float *)(param_2 + 0x538);
  }
  fVar3 = lbl_803E68C0 * (fVar3 - *(float *)(param_2 + 0x430));
  fVar6 = lbl_803E68C4;
  if ((lbl_803E68C4 <= fVar3) && (fVar6 = fVar3, lbl_803E6824 < fVar3)) {
    fVar6 = lbl_803E6824;
  }
  *(float *)(param_2 + 0x430) = fVar6 * lbl_803DC074 + *(float *)(param_2 + 0x430);
  fVar6 = lbl_803E6780;
  fVar3 = lbl_803E6780;
  if ((*(byte *)(param_2 + 0x428) >> 4 & 1) != 0) {
    fVar4 = *(float *)(param_2 + 0x53c);
    fVar5 = *(float *)(param_2 + 0x49c);
    if (fVar5 < lbl_803E6780) {
      if ((lbl_803E6780 <= fVar4) && (fVar3 = fVar4, -fVar5 * lbl_803DC078 < fVar4)) {
        fVar3 = -fVar5 * lbl_803DC078;
      }
    }
    else {
      fVar4 = -fVar4;
      fVar3 = -fVar5 * lbl_803DC078;
      if ((fVar3 <= fVar4) && (fVar3 = fVar4, lbl_803E6780 < fVar4)) {
        fVar3 = lbl_803E6780;
      }
    }
  }
  *(float *)(param_2 + 0x4a0) = lbl_803E6780;
  *(float *)(param_2 + 0x4a4) = fVar6;
  *(float *)(param_2 + 0x4a8) = lbl_803DC074 * (*(float *)(param_2 + 0x430) + fVar3);
  FUN_80017778((double)*(float *)(param_2 + 0x4a0),(double)*(float *)(param_2 + 0x4a4),
               (double)*(float *)(param_2 + 0x4a8),(float *)(param_2 + 0x6c),&local_68,&local_64,
               local_60);
  FUN_80017778((double)local_68,(double)local_64,(double)local_60[0],(float *)(param_2 + 300),
               &local_68,&local_64,local_60);
  FUN_80247e94(&local_68,(float *)(param_2 + 0x494),(float *)(param_2 + 0x494));
  *(float *)(param_2 + 0x414) =
       lbl_803DC074 * -*(float *)(param_2 + 0x45c) * *(float *)(param_2 + 0x52c) +
       *(float *)(param_2 + 0x414);
  dVar7 = (double)FUN_80293130((double)*(float *)(param_2 + 0x530),(double)lbl_803DC074);
  *(float *)(param_2 + 0x414) = (float)((double)*(float *)(param_2 + 0x414) * dVar7);
  fVar3 = *(float *)(param_2 + 0x414);
  fVar6 = *(float *)(param_2 + 0x534);
  fVar4 = -fVar6;
  if ((fVar4 <= fVar3) && (fVar4 = fVar3, fVar6 < fVar3)) {
    fVar4 = fVar6;
  }
  *(float *)(param_2 + 0x414) = fVar4;
  uStack_54 = (int)*(short *)(param_2 + 0x40e) ^ 0x80000000;
  local_58 = 0x43300000;
  iVar1 = (int)(*(float *)(param_2 + 0x414) * lbl_803DC074 +
               (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e6798));
  local_50 = (longlong)iVar1;
  *(short *)(param_2 + 0x40e) = (short)iVar1;
  iVar1 = (int)(*(float *)(param_2 + 0x414) * *(float *)(param_2 + 0x550));
  local_48 = (longlong)iVar1;
  uStack_3c = iVar1 - (*(uint *)(param_2 + 0x410) & 0xffff);
  if (0x8000 < (int)uStack_3c) {
    uStack_3c = uStack_3c - 0xffff;
  }
  if ((int)uStack_3c < -0x8000) {
    uStack_3c = uStack_3c + 0xffff;
  }
  uStack_3c = uStack_3c ^ 0x80000000;
  local_40 = 0x43300000;
  uStack_34 = *(uint *)(param_2 + 0x410) ^ 0x80000000;
  local_38 = 0x43300000;
  iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e6798) *
                *(float *)(param_2 + 0x554) +
               (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e6798));
  local_30 = (longlong)iVar1;
  *(int *)(param_2 + 0x410) = iVar1;
  uStack_24 = (int)*(short *)(param_2 + 0x40e) - (uint)*(ushort *)(param_2 + 0x40c);
  if (0x8000 < (int)uStack_24) {
    uStack_24 = uStack_24 - 0xffff;
  }
  if ((int)uStack_24 < -0x8000) {
    uStack_24 = uStack_24 + 0xffff;
  }
  uStack_24 = uStack_24 ^ 0x80000000;
  local_28 = 0x43300000;
  local_20 = (double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x40c) ^ 0x80000000);
  *(short *)(param_2 + 0x40c) =
       (short)(int)((float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e6798) *
                    *(float *)(param_2 + 0x558) + (float)(local_20 - DOUBLE_803e6798));
  if (*(char *)(param_2 + 0x428) < '\0') {
    *(float *)(param_2 + 0x584) =
         -*(float *)(param_2 + 0x570) * lbl_803DC074 + *(float *)(param_2 + 0x584);
    fVar3 = *(float *)(param_2 + 0x584);
    fVar6 = lbl_803E68C8;
    if ((lbl_803E68C8 <= fVar3) && (fVar6 = fVar3, lbl_803E67E0 < fVar3)) {
      fVar6 = lbl_803E67E0;
    }
    *(float *)(param_2 + 0x584) = fVar6;
    local_18 = (double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 2) ^ 0x80000000);
    *(short *)(param_1 + 2) =
         (short)(int)(*(float *)(param_2 + 0x584) * lbl_803DC074 +
                     (float)(local_18 - DOUBLE_803e6798));
  }
  if ((*(byte *)(param_2 + 0x428) >> 1 & 1) == 0) {
    local_78 = *(undefined4 *)(param_2 + 0x414);
    local_74 = *(undefined4 *)(param_2 + 0x49c);
    local_18 = (double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 4) ^ 0x80000000);
    local_70 = (float)(local_18 - DOUBLE_803e6798);
    local_20 = (double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 2) ^ 0x80000000);
    local_6c = (float)(local_20 - DOUBLE_803e6798);
    (**(code **)(*DAT_803dd6d0 + 0x60))(&local_78,0x10);
  }
  fVar3 = *(float *)(param_2 + 0x494);
  fVar6 = *(float *)(param_2 + 0x47c);
  fVar4 = -fVar6;
  if ((fVar4 <= fVar3) && (fVar4 = fVar3, fVar6 < fVar3)) {
    fVar4 = fVar6;
  }
  *(float *)(param_2 + 0x494) = fVar4;
  if ((*(float *)(param_2 + 0x494) < lbl_803E6824) &&
     (lbl_803E683C < *(float *)(param_2 + 0x494))) {
    *(float *)(param_2 + 0x494) = lbl_803E6780;
  }
  fVar3 = *(float *)(param_2 + 0x498);
  fVar6 = -*(float *)(param_2 + 0x480);
  if ((fVar6 <= fVar3) && (fVar6 = fVar3, lbl_803E6784 < fVar3)) {
    fVar6 = lbl_803E6784;
  }
  *(float *)(param_2 + 0x498) = fVar6;
  if ((*(float *)(param_2 + 0x498) < lbl_803E6824) &&
     (lbl_803E683C < *(float *)(param_2 + 0x498))) {
    *(float *)(param_2 + 0x498) = lbl_803E6780;
  }
  fVar3 = *(float *)(param_2 + 0x49c);
  fVar6 = *(float *)(param_2 + 0x484);
  fVar4 = -fVar6;
  if ((fVar4 <= fVar3) && (fVar4 = fVar3, fVar6 < fVar3)) {
    fVar4 = fVar6;
  }
  *(float *)(param_2 + 0x49c) = fVar4;
  if ((*(float *)(param_2 + 0x49c) < lbl_803E6824) &&
     (lbl_803E683C < *(float *)(param_2 + 0x49c))) {
    *(float *)(param_2 + 0x49c) = lbl_803E6780;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ecd30
 * EN v1.0 Address: 0x801ECD30
 * EN v1.0 Size: 188b
 * EN v1.1 Address: 0x801ECDD8
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ecd30(undefined4 param_1,int param_2)
{
  ushort local_28 [4];
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  
  local_1c = lbl_803E6780;
  local_18 = lbl_803E6780;
  local_14 = lbl_803E6780;
  local_20 = lbl_803E6784;
  local_28[0] = *(ushort *)(param_2 + 0x40e);
  local_28[1] = 0;
  local_28[2] = 0;
  FUN_80017754((float *)(param_2 + 0x6c),local_28);
  local_28[0] = -*(short *)(param_2 + 0x40e);
  local_28[1] = 0;
  local_28[2] = 0;
  FUN_8001774c((float *)(param_2 + 0xac),(int)local_28);
  local_28[0] = *(ushort *)(param_2 + 0x40c);
  local_28[1] = 0;
  local_28[2] = 0;
  FUN_80017754((float *)(param_2 + 0xec),local_28);
  local_28[0] = -*(short *)(param_2 + 0x40c);
  local_28[1] = 0;
  local_28[2] = 0;
  FUN_8001774c((float *)(param_2 + 300),(int)local_28);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ecdec
 * EN v1.0 Address: 0x801ECDEC
 * EN v1.0 Size: 196b
 * EN v1.1 Address: 0x801ECEA8
 * EN v1.1 Size: 184b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ecdec(undefined4 param_1,int param_2)
{
  float fVar1;
  
  *(float *)(param_2 + 0x52c) = lbl_803E68CC;
  *(float *)(param_2 + 0x530) = lbl_803E68D0;
  *(float *)(param_2 + 0x534) = lbl_803E688C;
  fVar1 = lbl_803E6780;
  *(float *)(param_2 + 0x414) = lbl_803E6780;
  *(float *)(param_2 + 0x584) = fVar1;
  *(float *)(param_2 + 0x548) = lbl_803E6894;
  *(float *)(param_2 + 0x54c) = lbl_803E687C;
  *(float *)(param_2 + 0x540) = lbl_803E67B8;
  *(float *)(param_2 + 0x544) = lbl_803E6790;
  *(float *)(param_2 + 0x558) = lbl_803E6840;
  *(float *)(param_2 + 0x56c) = lbl_803E6898;
  *(byte *)(param_2 + 0x428) = *(byte *)(param_2 + 0x428) & 0x7f;
  *(float *)(param_2 + 0x430) = fVar1;
  *(undefined4 *)(param_2 + 0x464) = *(undefined4 *)(param_2 + 0x470);
  *(undefined4 *)(param_2 + 0x47c) = *(undefined4 *)(param_2 + 0x470);
  *(undefined4 *)(param_2 + 0x468) = *(undefined4 *)(param_2 + 0x474);
  *(undefined4 *)(param_2 + 0x480) = *(undefined4 *)(param_2 + 0x474);
  *(undefined4 *)(param_2 + 0x46c) = *(undefined4 *)(param_2 + 0x478);
  *(undefined4 *)(param_2 + 0x484) = *(undefined4 *)(param_2 + 0x478);
  *(byte *)(param_2 + 0x428) = *(byte *)(param_2 + 0x428) & 0xbf;
  *(byte *)(param_2 + 0x428) = *(byte *)(param_2 + 0x428) & 0xef;
  *(undefined4 *)(param_2 + 0x42c) = 0;
  *(float *)(param_2 + 0x3e4) = fVar1;
  *(float *)(param_2 + 0x3e0) = lbl_803E6784;
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void SnowBike_func17(void) {}
void SnowBike_func16(void) {}

/* 8b "li r3, N; blr" returners. */
int SnowBike_func0E(void) { return 0x2; }
int SnowBike_render2(void) { return 0x0; }
int SnowBike_getExtraSize(void) { return 0x59c; }
int SnowBike_func08(void) { return 0x3; }

/* Pattern wrappers. */
u8 SnowBike_func0B(int *obj) { return *(u8*)((char*)((int**)obj)[0xb8/4] + 0x420); }

/*
 * --INFO--
 *
 * Function: SnowBike_mount
 * EN v1.0 Address: 0x801ECD98
 * EN v1.0 Size: 56b
 */
void SnowBike_mount(int obj, f32 *x, f32 *y, f32 *z)
{
    int t = *(int *)(obj + 0xb8);
    *(f32 *)(t + 0x400) = *(f32 *)(obj + 0xc);
    *(f32 *)(t + 0x404) = *(f32 *)(obj + 0x10);
    *(f32 *)(t + 0x408) = *(f32 *)(obj + 0x14);
    *x = *(f32 *)(t + 0x400);
    *y = *(f32 *)(t + 0x404);
    *z = *(f32 *)(t + 0x408);
}

/*
 * --INFO--
 *
 * Function: SnowBike_modelMtxFn
 * EN v1.0 Address: 0x801ECDE0
 * EN v1.0 Size: 32b
 */
void SnowBike_modelMtxFn(int obj, f32 *x, f32 *y, f32 *z)
{
    int t = *(int *)(obj + 0xb8);
    *x = *(f32 *)(t + 0x3e8);
    *y = *(f32 *)(t + 0x3ec);
    *z = *(f32 *)(t + 0x3f0);
}

extern void ObjGroup_RemoveObject(int obj, int group);
extern void mm_free(void *p);
extern void *lbl_803DCA6C;
extern void *lbl_803DCA68;
extern int lbl_803DC0BC;
extern f32 sqrtf(f32 x);
extern f32 lbl_803E5AE8;
extern f32 lbl_803E5AEC;
extern f32 lbl_803E5AF8;
extern f32 lbl_803E5B20;
extern f32 lbl_803E5B74;
extern f32 lbl_803E5B8C;
extern f32 lbl_803E5BB0;
extern f32 lbl_803E5BB8;
extern f32 lbl_803E5BA8;
extern f32 lbl_803E5BE4;
extern f32 lbl_803E5BF4;
extern f32 lbl_803E5BFC;
extern f32 lbl_803E5C00;
extern f32 lbl_803E5C10;
extern f32 lbl_803E5C14;
extern f32 lbl_803E5C34;
extern f32 lbl_803E5C38;
extern f32 lbl_803E5C3C;
extern f32 lbl_803E5C40;
extern f32 lbl_803E5C44;
extern f32 lbl_803E5C48;
extern f32 lbl_803E5B70;
extern f32 lbl_803E5B90;
extern f32 lbl_803E5B94;
extern f32 lbl_803E5B98;
extern int GameBit_Set(int bit, int val);
extern void *mapRomListFindItem(int a, int b, int c, int d, int e);
extern int lbl_80328590[];
extern void *gPathControlInterface;

/*
 * --INFO--
 *
 * Function: SnowBike_func15
 * EN v1.0 Address: 0x801ECA64
 * EN v1.0 Size: 352b
 */
#pragma peephole off
#pragma scheduling off
void SnowBike_func15(int obj)
{
    int t = *(int *)(obj + 0xb8);
    int *table;
    void *found;
    f32 zero;

    table = (int *)((int)lbl_80328590 + (int)(*(u8 *)(t + 0x434)) * 12);
    found = mapRomListFindItem(table[*(u8 *)(t + 0x435)], 0, 0, 0, 0);
    if (found != NULL) {
        if (*(u8 *)(t + 0x434) != 0) {
            *(f32 *)(obj + 0xc) = *(f32 *)((char *)found + 0x8);
            *(f32 *)(obj + 0x10) = *(f32 *)((char *)found + 0xc);
            *(f32 *)(obj + 0x14) = *(f32 *)((char *)found + 0x10);
            *(s16 *)(obj + 0x0) = (s16)((*(u8 *)((char *)found + 0x29)) << 8);
        }
        (*(void (**)(int, int, int))((char *)*(int *)lbl_803DCA6C + 0x10))(obj, t + 0x28, 0);
        *(f32 *)(t + 0xc) = *(f32 *)(obj + 0xc);
        *(f32 *)(t + 0x10) = *(f32 *)(obj + 0x10);
        *(f32 *)(t + 0x14) = *(f32 *)(obj + 0x14);
        *(s16 *)(t + 0x0) = *(s16 *)(obj + 0x0);
        zero = lbl_803E5AE8;
        *(f32 *)(t + 0x494) = zero;
        *(f32 *)(t + 0x498) = zero;
        *(f32 *)(t + 0x49c) = zero;
        (*(void (**)(int, int))((char *)*(int *)gPathControlInterface + 0x20))(obj, t + 0x178);
        *(f32 *)(*(int *)(obj + 0x54) + 0x10) = *(f32 *)(obj + 0xc);
        *(f32 *)(*(int *)(obj + 0x54) + 0x14) = *(f32 *)(obj + 0x10);
        *(f32 *)(*(int *)(obj + 0x54) + 0x18) = *(f32 *)(obj + 0x14);
        *(f32 *)(*(int *)(obj + 0x54) + 0x1c) = *(f32 *)(obj + 0x18);
        *(f32 *)(*(int *)(obj + 0x54) + 0x20) = *(f32 *)(obj + 0x1c);
        *(f32 *)(*(int *)(obj + 0x54) + 0x24) = *(f32 *)(obj + 0x20);
        *(s8 *)(t + 0x3d3) = 1;
    }
}
#pragma scheduling reset
#pragma peephole reset

extern void setMatrixFromObjectPos(void *mtx, s16 *vec);
extern void mtxRotateByVec3s(void *mtx, s16 *vec);

/*
 * --INFO--
 *
 * Function: fn_801EC7A0
 * EN v1.0 Address: 0x801EC7A0
 * EN v1.0 Size: 208b
 */
#pragma peephole off
#pragma scheduling off
void fn_801EC7A0(int p1, int p2)
{
    struct {
        s16 angles[4];
        f32 mat[4];
    } v;

    v.mat[1] = lbl_803E5AE8;
    v.mat[2] = lbl_803E5AE8;
    v.mat[3] = lbl_803E5AE8;
    v.mat[0] = lbl_803E5AEC;

    v.angles[0] = *(s16 *)(p2 + 0x40e);
    v.angles[1] = 0;
    v.angles[2] = 0;
    setMatrixFromObjectPos((void *)(p2 + 0x6c), v.angles);

    v.angles[0] = -*(s16 *)(p2 + 0x40e);
    v.angles[1] = 0;
    v.angles[2] = 0;
    mtxRotateByVec3s((void *)(p2 + 0xac), v.angles);

    v.angles[0] = *(s16 *)(p2 + 0x40c);
    v.angles[1] = 0;
    v.angles[2] = 0;
    setMatrixFromObjectPos((void *)(p2 + 0xec), v.angles);

    v.angles[0] = -*(s16 *)(p2 + 0x40c);
    v.angles[1] = 0;
    v.angles[2] = 0;
    mtxRotateByVec3s((void *)(p2 + 0x12c), v.angles);
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: fn_801EC870
 * EN v1.0 Address: 0x801EC870
 * EN v1.0 Size: 184b
 */
#pragma dont_inline on
void fn_801EC870(int p1, int p2)
{
    f32 fz, fa, fb, fc;
    *(f32 *)(p2 + 0x52c) = lbl_803E5C34;
    *(f32 *)(p2 + 0x530) = lbl_803E5C38;
    *(f32 *)(p2 + 0x534) = lbl_803E5BF4;
    fz = lbl_803E5AE8;
    *(f32 *)(p2 + 0x414) = fz;
    *(f32 *)(p2 + 0x584) = fz;
    *(f32 *)(p2 + 0x548) = lbl_803E5BFC;
    *(f32 *)(p2 + 0x54c) = lbl_803E5BE4;
    *(f32 *)(p2 + 0x540) = lbl_803E5B20;
    *(f32 *)(p2 + 0x544) = lbl_803E5AF8;
    *(f32 *)(p2 + 0x558) = lbl_803E5BA8;
    *(f32 *)(p2 + 0x56c) = lbl_803E5C00;
    *(u8 *)(p2 + 0x428) &= ~0x80;
    *(f32 *)(p2 + 0x430) = fz;
    fa = *(f32 *)(p2 + 0x470);
    *(f32 *)(p2 + 0x464) = fa;
    *(f32 *)(p2 + 0x47c) = fa;
    fb = *(f32 *)(p2 + 0x474);
    *(f32 *)(p2 + 0x468) = fb;
    *(f32 *)(p2 + 0x480) = fb;
    fc = *(f32 *)(p2 + 0x478);
    *(f32 *)(p2 + 0x46c) = fc;
    *(f32 *)(p2 + 0x484) = fc;
    *(u8 *)(p2 + 0x428) &= ~0x40;
    *(u8 *)(p2 + 0x428) &= ~0x10;
    *(int *)(p2 + 0x42c) = 0;
    *(f32 *)(p2 + 0x3e4) = fz;
    *(f32 *)(p2 + 0x3e0) = lbl_803E5AEC;
}
#pragma dont_inline reset

/*
 * --INFO--
 *
 * Function: fn_801EC928
 * EN v1.0 Address: 0x801EC928
 * EN v1.0 Size: 148b
 */
void fn_801EC928(int p1, int p2)
{
    f32 fa, fz;
    *(f32 *)(p2 + 0x4b0) = lbl_803E5C3C;
    *(f32 *)(p2 + 0x530) = lbl_803E5C38;
    *(f32 *)(p2 + 0x534) = lbl_803E5BF4;
    *(f32 *)(p2 + 0x538) = lbl_803E5B74;
    *(f32 *)(p2 + 0x53c) = lbl_803E5C14;
    *(f32 *)(p2 + 0x548) = lbl_803E5BFC;
    *(f32 *)(p2 + 0x54c) = lbl_803E5BE4;
    *(f32 *)(p2 + 0x540) = lbl_803E5B20;
    *(f32 *)(p2 + 0x544) = lbl_803E5AF8;
    fa = lbl_803E5C40;
    *(f32 *)(p2 + 0x57c) = fa;
    *(f32 *)(p2 + 0x580) = fa;
    *(f32 *)(p2 + 0x554) = lbl_803E5C44;
    *(f32 *)(p2 + 0x550) = lbl_803E5C10;
    *(f32 *)(p2 + 0x570) = lbl_803E5BB8;
    fz = lbl_803E5BA8;
    *(f32 *)(p2 + 0x558) = fz;
    *(f32 *)(p2 + 0x578) = lbl_803E5B8C;
    *(f32 *)(p2 + 0x574) = lbl_803E5BB0;
    *(f32 *)(p2 + 0x56c) = lbl_803E5C00;
    *(f32 *)(p2 + 0x4ac) = fz;
}

/*
 * --INFO--
 *
 * Function: SnowBike_setType
 * EN v1.0 Address: 0x801ECC94
 * EN v1.0 Size: 244b
 */
#pragma peephole off
#pragma scheduling off
void SnowBike_setType(int obj, int type)
{
    int t = *(int *)(obj + 0xb8);
    u32 bit;
    *(s8 *)(t + 0x421) = (s8)type;
    if (type == 2) {
        GameBit_Set(*(s16 *)(t + 0x448), 1);
        fn_801EC870(obj, t);
        bit = (*(u8 *)(t + 0x428) >> 5) & 1;
        if (bit != 0) {
            *(f32 *)(t + 0x4b8) = lbl_803E5B90;
            *(f32 *)(t + 0x4c0) = lbl_803E5AEC;
            *(f32 *)(t + 0x4bc) = lbl_803E5B94;
            if (*(s8 *)(t + 0x421) == 2) {
                (*(void (**)(int, int))((char *)*(int *)lbl_803DCA68 + 0x58))((int)*(f32 *)(t + 0x4b8), 0x5cd);
                (*(void (**)(f32))((char *)*(int *)lbl_803DCA68 + 0x68))(lbl_803E5B98);
            }
        }
        if (*(s16 *)(obj + 0x46) == 0x72) {
            *(s8 *)(*(int *)(obj + 0x54) + 0x6a) = 0x14;
            *(s8 *)(*(int *)(obj + 0x54) + 0x6b) = 0x14;
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: SnowBike_func12
 * EN v1.0 Address: 0x801ECC38
 * EN v1.0 Size: 92b
 */
#pragma peephole off
#pragma scheduling off
void SnowBike_func12(int obj, f32 *outFloat, s32 *outBool)
{
    int t = *(int *)(obj + 0xb8);
    f32 v, r;
    *outFloat = *(f32 *)(t + 0x414) / lbl_803E5C48;
    v = *outFloat;
    r = lbl_803E5B70;
    if (v >= r) {
        r = lbl_803E5AEC;
        if (v <= r) {
            r = v;
        }
    }
    *outFloat = r;
    *outBool = *(f32 *)(t + 0x414) < lbl_803E5AE8;
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: SnowBike_func13
 * EN v1.0 Address: 0x801ECBD4
 * EN v1.0 Size: 100b
 */
#pragma peephole off
#pragma scheduling off
f32 SnowBike_func13(int obj, f32 *out)
{
    int t = *(int *)(obj + 0xb8);
    f32 a, b, c, sum, r;
    *out = lbl_803E5BB8;
    a = *(f32 *)(t + 0x49c) * *(f32 *)(t + 0x49c);
    b = *(f32 *)(t + 0x494) * *(f32 *)(t + 0x494);
    c = *(f32 *)(t + 0x498) * *(f32 *)(t + 0x498);
    sum = b + c;
    sum = a + sum;
    r = sqrtf(sum) * lbl_803E5BA8;
    if (r > lbl_803E5AEC) {
        r = lbl_803E5AEC;
    }
    return r;
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: SnowBike_setScale
 * EN v1.0 Address: 0x801ECE0C
 * EN v1.0 Size: 36b
 */
#pragma peephole off
#pragma scheduling off
u32 SnowBike_setScale(int obj)
{
    int t = *(int *)(obj + 0xb8);
    u32 bit = (*(u8 *)(t + 0x428) >> 1) & 1;
    if (bit != 0) {
        return 0;
    }
    return *(u8 *)(t + 0x420);
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: fn_801EC9BC
 * EN v1.0 Address: 0x801EC9BC
 * EN v1.0 Size: 56b
 */
#pragma peephole off
#pragma scheduling off
void fn_801EC9BC(int obj)
{
    (*(void (**)(int))((char *)*(int *)lbl_803DCA6C + 0x34))(*(int *)(obj + 0xb8) + 0x28);
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: fn_801EC9F4
 * EN v1.0 Address: 0x801EC9F4
 * EN v1.0 Size: 104b
 */
#pragma peephole off
#pragma scheduling off
u32 fn_801EC9F4(int obj)
{
    int result = (*(int (**)(int))((char *)*(int *)lbl_803DCA6C + 0x34))(*(int *)(obj + 0xb8) + 0x28);
    if (result == 3) {
        if (lbl_803DC0BC == -1) {
            return 1;
        }
    }
    return (u32)__cntlzw(lbl_803DC0BC - 1 - result) >> 5;
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: SnowBike_free
 * EN v1.0 Address: 0x801ECE40
 * EN v1.0 Size: 132b
 */
#pragma peephole off
#pragma scheduling off
void SnowBike_free(int obj)
{
    char *p;
    int i;
    u32 bit;
    int t;

    t = *(int *)(obj + 0xb8);
    ObjGroup_RemoveObject(obj, 0xa);
    i = 0;
    p = (char *)t;
    for (; i < 9; i++) {
        mm_free(*(void **)(p + 0x4c8));
        p += 8;
    }
    bit = (*(u8 *)(t + 0x428) >> 5) & 1;
    if (bit != 0) {
        (*(void (**)(void))((char *)*(int *)lbl_803DCA68 + 0x60))();
    }
}
#pragma scheduling reset
#pragma peephole reset

/* 16b chained patterns. */
s32 SnowBike_func14(int *obj) { return *(s8*)((char*)((int**)obj)[0xb8/4] + 0x422); }
s32 SnowBike_getType(int *obj) { return *(s8*)((char*)((int**)obj)[0xb8/4] + 0x421); }
