#include "ghidra_import.h"
#include "main/dll/projLib.h"

extern f32 Vec_distance(f32 *a, f32 *b);
extern u32 randomGetRange(int min, int max);
extern undefined4 Obj_GetPlayerObject();
extern int ObjGroup_FindNearestObject();
extern int Obj_GetYawDeltaToObject();
extern undefined4 fn_80038F1C(int a, int b);
extern void* seqFn_800394a0();
extern undefined4 objMathFn_8003a380(ushort *obj,uint target,float *pos,int pathState,
                                     short *turnState,float targetYaw,int mode,short yawLimit);
extern int fn_8003A8B4();
extern undefined4 fn_8003A9C0();
extern undefined4 fn_8003AC14();
extern undefined4 objFn_8003acfc();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028688c();
extern f32 sqrtf(f32 value);

extern u8 framesThisStep;
extern f32 lbl_803E1C8C;
extern f32 lbl_803E1C90;
extern f64 lbl_803E1C98;
extern f32 lbl_803E1CA4;
extern f32 lbl_803E1CD0;
extern f32 lbl_803E1CD4;
extern f32 lbl_803E1CD8;
extern f32 lbl_803E1CDC;

/*
 * --INFO--
 *
 * Function: dll_2E_func03
 * EN v1.0 Address: 0x80115094
 * EN v1.0 Size: 1468b
 * EN v1.1 Address: 0x80115318
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
typedef struct ProjNearSearch {
  f32 range;
  f32 dx;
  f32 dy;
  f32 dz;
} ProjNearSearch;

#pragma scheduling off
#pragma peephole off
void dll_2E_func03(ushort *puVar5,int iVar10,undefined4 unused)
{
  register int sVar11;
  register int puVar6;
  register uint iVar9;
  int bit1;
  int iVar4;
  uint uVar3;
  float dist;
  float fVar1;
  float fVar2;
  float fVar3;
  float targetYaw;
  ProjNearSearch sv;

  (void)unused;
  sv.range = lbl_803E1C8C;
  targetYaw = lbl_803E1CD0;
  sVar11 = 0;
  puVar6 = (int)seqFn_800394a0();
  Obj_GetPlayerObject();
  if (*(u8 *)(iVar10 + 0x601) == 0) {
    bit1 = *(u8 *)(iVar10 + 0x611) & 1;
    if (bit1 != 0 && *(u8 *)(iVar10 + 0x600) != 8) {
      *(u8 *)(iVar10 + 0x600) = 8;
      if ((*(byte *)(iVar10 + 0x611) & 8) == 0) {
        objFn_8003acfc((int)puVar5,puVar6,(uint)*(byte *)(iVar10 + 0x610),iVar10 + 0x1c);
        *(undefined4 *)(iVar10 + 0x5f8) = 0x50;
        fn_8003A9C0(iVar10 + 0x1c,(uint)*(byte *)(iVar10 + 0x610),0,0);
      }
      else {
        fn_8003AC14((int)puVar5,seqFn_800394a0(),(uint)*(byte *)(iVar10 + 0x610));
      }
    }
    else if (bit1 == 0 && *(u8 *)(iVar10 + 0x600) == 8) {
      *(u8 *)(iVar10 + 0x600) = 0;
      if ((*(byte *)(iVar10 + 0x611) & 8) == 0) {
        objFn_8003acfc((int)puVar5,puVar6,(uint)*(byte *)(iVar10 + 0x610),iVar10 + 0x1c);
        *(undefined4 *)(iVar10 + 0x5f8) = 0x50;
      }
    }
    if (*(u8 *)(iVar10 + 0x600) > 1) {
      if (*(int *)(iVar10 + 0x5f8) != 0 && (*(byte *)(iVar10 + 0x611) & 8) == 0) {
        *(uint *)(iVar10 + 0x5f8) =
            !fn_8003A8B4(puVar5,puVar6,(uint)*(byte *)(iVar10 + 0x610),iVar10 + 0x1c);
      }
      else {
        fn_8003AC14((int)puVar5,seqFn_800394a0(),(uint)*(byte *)(iVar10 + 0x610));
      }
    }
    else {
      uVar3 = *(uint *)(iVar10 + 0x608);
      if (uVar3 != 0) {
      }
      else {
        uVar3 = ObjGroup_FindNearestObject(8,puVar5,&sv);
      }
      iVar9 = uVar3;
      if (iVar9 != 0) {
        if ((*(byte *)(iVar10 + 0x611) & 0x20) != 0) {
          sv.dx = *(float *)(iVar10 + 0x10) - *(float *)(iVar9 + 0xc);
          sv.dy = *(float *)(iVar10 + 0x14) - *(float *)(iVar9 + 0x10);
          sv.dz = *(float *)(iVar10 + 0x18) - *(float *)(iVar9 + 0x14);
          fVar1 = sv.dx * sv.dx;
          fVar2 = sv.dz * sv.dz;
          dist = sqrtf(fVar1 + fVar2);
          if (dist <= lbl_803E1CD4) {
            fVar1 = (dist - lbl_803E1CD8) / lbl_803E1CD0;
            fVar3 = lbl_803E1CA4;
            fVar2 = lbl_803E1C90;
            if (fVar1 < fVar2) {
            }
            else if (fVar1 > fVar3) {
              fVar2 = fVar3;
            }
            else {
              fVar2 = fVar1;
            }
            fVar2 = lbl_803E1CA4 - fVar2;
            fVar1 = lbl_803E1CA4 - fVar2;
            *(float *)(iVar10 + 0x10) =
                 *(float *)(iVar10 + 0x10) * fVar1 + *(float *)(puVar5 + 6) * fVar2;
            *(float *)(iVar10 + 0x18) =
                 *(float *)(iVar10 + 0x18) * fVar1 + *(float *)(puVar5 + 10) * fVar2;
          }
        }
        if ((*(int *)(iVar10 + 0x618) != -1) && (iVar9 == *(uint *)(iVar10 + 0x604))) {
          iVar4 = -(uint)framesThisStep + *(int *)(iVar10 + 0x620);
          *(int *)(iVar10 + 0x620) = iVar4;
          if ((iVar4 <= 0) && (0 < (int)(*(int *)(iVar10 + 0x620) + (uint)framesThisStep))) {
            objFn_8003acfc((int)puVar5,puVar6,(uint)*(byte *)(iVar10 + 0x610),iVar10 + 0x1c);
            *(undefined4 *)(iVar10 + 0x5f8) = 0x50;
            fn_8003A9C0(iVar10 + 0x1c,(uint)*(byte *)(iVar10 + 0x610),0,0);
            *(undefined *)(iVar10 + 0x600) = 0;
            goto LAB_801158cc;
          }
          if (*(int *)(iVar10 + 0x5f8) != 0) {
            *(uint *)(iVar10 + 0x5f8) =
                !fn_8003A8B4(puVar5,puVar6,(uint)*(byte *)(iVar10 + 0x610),iVar10 + 0x1c);
          }
          if (*(int *)(iVar10 + 0x620) < -*(int *)(iVar10 + 0x61c)) {
            *(uint *)(iVar10 + 0x620) =
                randomGetRange(*(int *)(iVar10 + 0x61c),*(int *)(iVar10 + 0x618));
          }
          if (*(int *)(iVar10 + 0x620) < 0) goto LAB_801158cc;
        }
        else {
          *(int *)(iVar10 + 0x620) = *(int *)(iVar10 + 0x618);
        }
        if ((iVar9 != *(uint *)(iVar10 + 0x604)) && (iVar9 != 0)) {
          uVar3 = *(uint *)(iVar9 + 0x54);
          if (uVar3 != 0) {
            if ((*(byte *)(uVar3 + 0x62) & 2) != 0) {
              targetYaw = lbl_803E1CDC * (float)(int)*(short *)(uVar3 + 0x5e);
            }
            else if ((*(byte *)(uVar3 + 0x62) & 1) != 0) {
              targetYaw = (float)(int)*(short *)(uVar3 + 0x5a);
            }
            else {
              targetYaw = lbl_803E1CD0;
            }
          }
          else {
            targetYaw = lbl_803E1CD0;
          }
        }
        if (iVar9 != 0) {
          sVar11 = Obj_GetYawDeltaToObject(puVar5,iVar9,(float *)0x0);
        }
        if ((*(byte *)(iVar10 + 0x611) & 0x10) != 0) {
          fn_80038F1C(0,1);
          sVar11 = sVar11 + -0x8000;
        }
        iVar4 = (short)sVar11;
        iVar4 = (iVar4 >= 0) ? iVar4 : -iVar4;
        if (((0x5555 < iVar4) || (iVar9 == 0)) ||
           (Vec_distance((float *)(puVar5 + 0xc),(float *)(iVar9 + 0x18)) > *(float *)(iVar10 + 0x614))) {
          if ((*(u8 *)(iVar10 + 0x600) != 0) ||
             ((iVar9 == 0 && (*(uint *)(iVar10 + 0x604) != 0)))) {
            objFn_8003acfc((int)puVar5,puVar6,(uint)*(byte *)(iVar10 + 0x610),iVar10 + 0x1c);
            *(undefined4 *)(iVar10 + 0x5f8) = 10;
            fn_8003A9C0(iVar10 + 0x1c,(uint)*(byte *)(iVar10 + 0x610),0,0);
            *(undefined *)(iVar10 + 0x600) = 0;
          }
        }
        else {
          if ((iVar9 != *(uint *)(iVar10 + 0x604)) || (*(u8 *)(iVar10 + 0x600) == 0)) {
            objFn_8003acfc((int)puVar5,puVar6,(uint)*(byte *)(iVar10 + 0x610),iVar10 + 0x1c);
            *(undefined4 *)(iVar10 + 0x5f8) = 1;
          }
          if ((*(byte *)(iVar10 + 0x611) & 8) != 0) {
            *(undefined4 *)(iVar10 + 0x5f8) = 0;
          }
          objMathFn_8003a380(puVar5,iVar9,(float *)(iVar10 + 0x10),
                             (*(int *)(iVar10 + 0x5f8) != 0) ? iVar10 + 0x1c : 0,
                             (short *)(iVar10 + 0x5bc),targetYaw,8,
                             *(short *)(iVar10 + 0x60c));
          *(undefined *)(iVar10 + 0x600) = 1;
        }
        *(uint *)(iVar10 + 0x604) = iVar9;
        if (*(int *)(iVar10 + 0x5f8) == 0) {
          *(undefined4 *)(iVar10 + 0x608) = 0;
        }
        if (((*(byte *)(iVar10 + 0x611) & 8) == 0) && (*(int *)(iVar10 + 0x5f8) != 0)) {
          *(uint *)(iVar10 + 0x5f8) =
              !fn_8003A8B4(puVar5,puVar6,(uint)*(byte *)(iVar10 + 0x610),iVar10 + 0x1c);
        }
      }
    }
  }
LAB_801158cc:
  return;
}
#pragma peephole reset
#pragma scheduling reset

void FUN_801150a4(int param_1,undefined4 param_2)
{
  *(undefined4 *)(param_1 + 0x608) = param_2;
  return;
}

void FUN_801150ac(void)
{
  undefined8 ctx;

  ctx = FUN_80286840();
  dll_2E_func03((ushort *)((ulonglong)ctx >> 0x20),(int)ctx,0);
  FUN_8028688c();
  return;
}
