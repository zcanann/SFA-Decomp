#include "ghidra_import.h"
#include "main/dll/projLib.h"

extern undefined4 Vec_distance();
extern u32 randomGetRange(int min, int max);
extern undefined4 Obj_GetPlayerObject();
extern int ObjGroup_FindNearestObject();
extern int Obj_GetYawDeltaToObject();
extern undefined4 FUN_80038bb0();
extern void* seqFn_800394a0();
extern undefined4 objMathFn_8003a380(ushort *obj,int target,float *pos,int pathState,
                                     short *turnState,float targetYaw,int mode,short yawLimit);
extern undefined4 fn_8003A8B4();
extern undefined4 fn_8003A9C0();
extern undefined4 fn_8003AC14();
extern undefined4 objFn_8003acfc();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028688c();
extern double sqrtf();
extern uint countLeadingZeros();

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
#pragma scheduling off
#pragma peephole off
void dll_2E_func03(ushort *puVar5,int iVar10,undefined4 unused)
{
  float fVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  uint *puVar6;
  uint *puVar7;
  undefined4 uVar8;
  int iVar9;
  short sVar11;
  double dVar12;
  float targetYaw;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  
  (void)unused;
  local_48 = lbl_803E1C8C;
  targetYaw = lbl_803E1CD0;
  sVar11 = 0;
  puVar6 = seqFn_800394a0();
  Obj_GetPlayerObject();
  if (*(char *)(iVar10 + 0x601) == '\0') {
    if (((*(byte *)(iVar10 + 0x611) & 1) == 0) || (*(char *)(iVar10 + 0x600) == '\b')) {
      if (((*(byte *)(iVar10 + 0x611) & 1) == 0) &&
         ((*(char *)(iVar10 + 0x600) == '\b' &&
          (*(undefined *)(iVar10 + 0x600) = 0, (*(byte *)(iVar10 + 0x611) & 8) == 0)))) {
        objFn_8003acfc((int)puVar5,puVar6,(uint)*(byte *)(iVar10 + 0x610),iVar10 + 0x1c);
        *(undefined4 *)(iVar10 + 0x5f8) = 0x50;
      }
    }
    else {
      *(undefined *)(iVar10 + 0x600) = 8;
      if ((*(byte *)(iVar10 + 0x611) & 8) == 0) {
        objFn_8003acfc((int)puVar5,puVar6,(uint)*(byte *)(iVar10 + 0x610),iVar10 + 0x1c);
        *(undefined4 *)(iVar10 + 0x5f8) = 0x50;
        fn_8003A9C0(iVar10 + 0x1c,(uint)*(byte *)(iVar10 + 0x610),0,0);
      }
      else {
        puVar7 = seqFn_800394a0();
        fn_8003AC14((int)puVar5,puVar7,(uint)*(byte *)(iVar10 + 0x610));
      }
    }
    if (*(byte *)(iVar10 + 0x600) < 2) {
      iVar9 = *(int *)(iVar10 + 0x608);
      if (iVar9 == 0) {
        iVar9 = ObjGroup_FindNearestObject(8,puVar5,&local_48);
      }
      if (iVar9 != 0) {
        if ((*(byte *)(iVar10 + 0x611) & 0x20) != 0) {
          local_44 = *(float *)(iVar10 + 0x10) - *(float *)(iVar9 + 0xc);
          local_40 = *(float *)(iVar10 + 0x14) - *(float *)(iVar9 + 0x10);
          local_3c = *(float *)(iVar10 + 0x18) - *(float *)(iVar9 + 0x14);
          dVar12 = sqrtf((double)(local_44 * local_44 + local_3c * local_3c));
          if (dVar12 <= (double)lbl_803E1CD4) {
            fVar1 = (float)(dVar12 - (double)lbl_803E1CD8) / lbl_803E1CD0;
            fVar2 = lbl_803E1C90;
            if ((lbl_803E1C90 <= fVar1) && (fVar2 = fVar1, lbl_803E1CA4 < fVar1)) {
              fVar2 = lbl_803E1CA4;
            }
            fVar2 = lbl_803E1CA4 - fVar2;
            fVar1 = lbl_803E1CA4 - fVar2;
            *(float *)(iVar10 + 0x10) =
                 *(float *)(iVar10 + 0x10) * fVar1 + *(float *)(puVar5 + 6) * fVar2;
            *(float *)(iVar10 + 0x18) =
                 *(float *)(iVar10 + 0x18) * fVar1 + *(float *)(puVar5 + 10) * fVar2;
          }
        }
        if ((*(int *)(iVar10 + 0x618) == -1) || (iVar9 != *(int *)(iVar10 + 0x604))) {
          *(int *)(iVar10 + 0x620) = *(int *)(iVar10 + 0x618);
        }
        else {
          iVar4 = *(int *)(iVar10 + 0x620) - (uint)framesThisStep;
          *(int *)(iVar10 + 0x620) = iVar4;
          if ((iVar4 < 1) && (0 < (int)(*(int *)(iVar10 + 0x620) + (uint)framesThisStep))) {
            objFn_8003acfc((int)puVar5,puVar6,(uint)*(byte *)(iVar10 + 0x610),iVar10 + 0x1c);
            *(undefined4 *)(iVar10 + 0x5f8) = 0x50;
            fn_8003A9C0(iVar10 + 0x1c,(uint)*(byte *)(iVar10 + 0x610),0,0);
            *(undefined *)(iVar10 + 0x600) = 0;
            goto LAB_801158cc;
          }
          if (*(int *)(iVar10 + 0x5f8) != 0) {
            uVar8 = fn_8003A8B4(puVar5,puVar6,(uint)*(byte *)(iVar10 + 0x610),iVar10 + 0x1c);
            uVar3 = countLeadingZeros(uVar8);
            *(uint *)(iVar10 + 0x5f8) = uVar3 >> 5;
          }
          if (*(int *)(iVar10 + 0x620) < (int)-*(uint *)(iVar10 + 0x61c)) {
            uVar3 = randomGetRange(*(uint *)(iVar10 + 0x61c),*(uint *)(iVar10 + 0x618));
            *(uint *)(iVar10 + 0x620) = uVar3;
          }
          if (*(int *)(iVar10 + 0x620) < 0) goto LAB_801158cc;
        }
        if (((iVar9 != *(int *)(iVar10 + 0x604)) && (iVar9 != 0)) &&
           (iVar4 = *(int *)(iVar9 + 0x54), iVar4 != 0)) {
          if ((*(byte *)(iVar4 + 0x62) & 2) == 0) {
            if ((*(byte *)(iVar4 + 0x62) & 1) != 0) {
              targetYaw = (float)((double)CONCAT44(0x43300000,
                  (int)*(short *)(iVar4 + 0x5a) ^ 0x80000000) - lbl_803E1C98);
            }
          }
          else {
            targetYaw = lbl_803E1CDC *
                (float)((double)CONCAT44(0x43300000,
                    (int)*(short *)(iVar4 + 0x5e) ^ 0x80000000) - lbl_803E1C98);
          }
        }
        if (iVar9 != 0) {
          iVar4 = Obj_GetYawDeltaToObject(puVar5,iVar9,(float *)0x0);
          sVar11 = (short)iVar4;
        }
        if ((*(byte *)(iVar10 + 0x611) & 0x10) != 0) {
          FUN_80038bb0('\0',1);
          sVar11 = sVar11 + -0x8000;
        }
        iVar4 = (int)sVar11;
        if (iVar4 < 0) {
          iVar4 = -iVar4;
        }
        if (((0x5555 < iVar4) || (iVar9 == 0)) ||
           (dVar12 = (double)Vec_distance((float *)(puVar5 + 0xc),(float *)(iVar9 + 0x18)),
           (double)*(float *)(iVar10 + 0x614) < dVar12)) {
          if ((*(char *)(iVar10 + 0x600) != '\0') ||
             ((iVar9 == 0 && (*(int *)(iVar10 + 0x604) != 0)))) {
            objFn_8003acfc((int)puVar5,puVar6,(uint)*(byte *)(iVar10 + 0x610),iVar10 + 0x1c);
            *(undefined4 *)(iVar10 + 0x5f8) = 10;
            fn_8003A9C0(iVar10 + 0x1c,(uint)*(byte *)(iVar10 + 0x610),0,0);
            *(undefined *)(iVar10 + 0x600) = 0;
          }
        }
        else {
          if ((iVar9 != *(int *)(iVar10 + 0x604)) || (*(char *)(iVar10 + 0x600) == '\0')) {
            objFn_8003acfc((int)puVar5,puVar6,(uint)*(byte *)(iVar10 + 0x610),iVar10 + 0x1c);
            *(undefined4 *)(iVar10 + 0x5f8) = 1;
          }
          if ((*(byte *)(iVar10 + 0x611) & 8) != 0) {
            *(undefined4 *)(iVar10 + 0x5f8) = 0;
          }
          if (*(int *)(iVar10 + 0x5f8) == 0) {
            iVar4 = 0;
          }
          else {
            iVar4 = iVar10 + 0x1c;
          }
          objMathFn_8003a380(puVar5,iVar9,(float *)(iVar10 + 0x10),iVar4,
                             (short *)(iVar10 + 0x5bc),targetYaw,8,
                             *(short *)(iVar10 + 0x60c));
          *(undefined *)(iVar10 + 0x600) = 1;
        }
        *(int *)(iVar10 + 0x604) = iVar9;
        if (*(int *)(iVar10 + 0x5f8) == 0) {
          *(undefined4 *)(iVar10 + 0x608) = 0;
        }
        if (((*(byte *)(iVar10 + 0x611) & 8) == 0) && (*(int *)(iVar10 + 0x5f8) != 0)) {
          uVar8 = fn_8003A8B4(puVar5,puVar6,(uint)*(byte *)(iVar10 + 0x610),iVar10 + 0x1c);
          uVar3 = countLeadingZeros(uVar8);
          *(uint *)(iVar10 + 0x5f8) = uVar3 >> 5;
        }
      }
    }
    else if ((*(int *)(iVar10 + 0x5f8) == 0) || ((*(byte *)(iVar10 + 0x611) & 8) != 0)) {
      puVar6 = seqFn_800394a0();
      fn_8003AC14((int)puVar5,puVar6,(uint)*(byte *)(iVar10 + 0x610));
    }
    else {
      uVar8 = fn_8003A8B4(puVar5,puVar6,(uint)*(byte *)(iVar10 + 0x610),iVar10 + 0x1c);
      uVar3 = countLeadingZeros(uVar8);
      *(uint *)(iVar10 + 0x5f8) = uVar3 >> 5;
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
