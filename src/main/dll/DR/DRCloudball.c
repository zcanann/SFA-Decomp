#include "ghidra_import.h"
#include "main/dll/DR/DRCloudball.h"

extern double FUN_80010f00();
extern undefined4 FUN_80014b68();
extern int FUN_80021884();
extern int FUN_8002bac4();
extern undefined4 FUN_8002fb40();
extern undefined4 FUN_80036f50();
extern undefined4 FUN_800379bc();
extern undefined4 FUN_80041110();
extern undefined4 FUN_8011f670();
extern undefined4 FUN_8011f6c4();
extern undefined4 FUN_8012f288();
extern undefined4 FUN_801f538c();
extern undefined4 FUN_801f5504();
extern undefined4 FUN_80286840();
extern undefined4 FUN_8028688c();
extern int FUN_80296ffc();

extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd708;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e66c8;
extern f32 FLOAT_803e66f8;
extern f32 FLOAT_803e66fc;
extern f32 FLOAT_803e6700;

/*
 * --INFO--
 *
 * Function: FUN_801e8fa0
 * EN v1.0 Address: 0x801E8FA0
 * EN v1.0 Size: 1044b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e8fa0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  undefined2 *puVar1;
  int iVar2;
  undefined4 uVar3;
  undefined2 uVar5;
  int iVar4;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar6;
  int iVar7;
  undefined8 extraout_f1;
  undefined8 uVar8;
  double dVar9;
  float local_28 [10];
  
  puVar1 = (undefined2 *)FUN_80286840();
  iVar7 = *(int *)(puVar1 + 0x26);
  uVar8 = extraout_f1;
  iVar2 = FUN_8002bac4();
  iVar6 = *(int *)(puVar1 + 0x5c);
  local_28[0] = FLOAT_803e66fc;
  if ((*(byte *)(iVar6 + 0x97) >> 6 & 1) == 0) {
    if ((char)*(byte *)(iVar6 + 0x97) < '\0') {
      *(undefined2 *)(iVar6 + 0x88) = 0xffff;
      iVar2 = FUN_8002bac4();
      FUN_800379bc(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar2,0x7000a,
                   (uint)puVar1,iVar6 + 0x88,in_r7,in_r8,in_r9,in_r10);
      *(byte *)(iVar6 + 0x97) = *(byte *)(iVar6 + 0x97) & 0x7f;
      *(byte *)(iVar6 + 0x97) = *(byte *)(iVar6 + 0x97) & 0xbf | 0x40;
    }
    else {
      if (*(int *)(iVar6 + 0x90) == 0) {
        uVar3 = FUN_80036f50(9,puVar1,local_28);
        *(undefined4 *)(iVar6 + 0x90) = uVar3;
        iVar2 = *(int *)(iVar6 + 0x90);
        if (iVar2 != 0) {
          iVar2 = (**(code **)(**(int **)(iVar2 + 0x68) + 0x28))(iVar2,*(undefined *)(iVar7 + 0x19))
          ;
          if ((iVar2 == 0) ||
             (iVar2 = (**(code **)(**(int **)(*(int *)(iVar6 + 0x90) + 0x68) + 0x2c))
                                (*(int *)(iVar6 + 0x90),*(undefined *)(iVar7 + 0x19)), iVar2 != 0))
          {
            *(byte *)(iVar6 + 0x97) = *(byte *)(iVar6 + 0x97) & 0xbf | 0x40;
            puVar1[3] = puVar1[3] | 0x4000;
            puVar1[0x58] = puVar1[0x58] | 0x8000;
            *(byte *)((int)puVar1 + 0xaf) = *(byte *)((int)puVar1 + 0xaf) | 8;
          }
          uVar5 = (**(code **)(**(int **)(*(int *)(iVar6 + 0x90) + 0x68) + 0x3c))
                            (*(int *)(iVar6 + 0x90),*(undefined *)(iVar7 + 0x19));
          *(undefined2 *)(iVar6 + 0x94) = uVar5;
        }
      }
      else {
        if ((*(byte *)((int)puVar1 + 0xaf) & 4) != 0) {
          FUN_8011f6c4(0x12);
          FUN_8012f288(*(undefined2 *)(iVar6 + 0x94));
        }
        if ((*(byte *)((int)puVar1 + 0xaf) & 1) != 0) {
          iVar2 = FUN_80296ffc(iVar2);
          iVar4 = (**(code **)(**(int **)(*(int *)(iVar6 + 0x90) + 0x68) + 0x38))
                            (*(int *)(iVar6 + 0x90),*(undefined *)(iVar7 + 0x19));
          (**(code **)(**(int **)(*(int *)(iVar6 + 0x90) + 0x68) + 0x40))
                    (*(int *)(iVar6 + 0x90),*(undefined *)(iVar7 + 0x19));
          if (puVar1[0x23] == 0x467) {
            *(float *)(puVar1 + 8) = FLOAT_803e6700 + *(float *)(*(int *)(puVar1 + 0x26) + 0xc);
          }
          if (iVar2 < iVar4) {
            (**(code **)(*DAT_803dd6d4 + 0x48))(1,puVar1,0xffffffff);
          }
          else {
            FUN_8011f670(3);
            (**(code **)(*DAT_803dd6d4 + 0x48))(0,puVar1,0xffffffff);
          }
          FUN_80014b68(0,0x100);
        }
        if (puVar1[0x23] == 0x467) {
          if (FLOAT_803e66c8 < *(float *)(iVar6 + 0x40)) {
            *(float *)(iVar6 + 0x40) = *(float *)(iVar6 + 0x40) - FLOAT_803e66c8;
            if (*(byte *)(iVar6 + 0x68) < 4) {
              FUN_801f538c(puVar1,iVar6);
            }
            else {
              *(byte *)(iVar6 + 0x68) = *(byte *)(iVar6 + 0x68) + 1;
            }
            FUN_801f5504(puVar1,iVar6);
          }
          dVar9 = FUN_80010f00((double)*(float *)(iVar6 + 0x40),(float *)(iVar6 + 4),(float *)0x0);
          *(float *)(puVar1 + 6) = (float)dVar9;
          dVar9 = FUN_80010f00((double)*(float *)(iVar6 + 0x40),(float *)(iVar6 + 0x14),(float *)0x0
                              );
          *(float *)(puVar1 + 8) = (float)dVar9;
          dVar9 = FUN_80010f00((double)*(float *)(iVar6 + 0x40),(float *)(iVar6 + 0x24),(float *)0x0
                              );
          *(float *)(puVar1 + 10) = (float)dVar9;
          *(float *)(iVar6 + 0x40) =
               *(float *)(iVar6 + 0x44) * FLOAT_803dc074 + *(float *)(iVar6 + 0x40);
          iVar2 = FUN_80021884();
          *puVar1 = (short)iVar2;
          (**(code **)(*DAT_803dd708 + 8))(puVar1,0x19f,0,1,0xffffffff,0);
          (**(code **)(*DAT_803dd708 + 8))(puVar1,0x1a0,0,1,0xffffffff,0);
        }
      }
      if ((puVar1[0x23] != 0x464) && (puVar1[0x23] != 0x467)) {
        FUN_8002fb40((double)FLOAT_803e66f8,(double)FLOAT_803dc074);
      }
      if ((*(byte *)((int)puVar1 + 0xaf) & 8) == 0) {
        FUN_80041110();
      }
    }
  }
  else {
    puVar1[3] = puVar1[3] | 0x4000;
    puVar1[0x58] = puVar1[0x58] | 0x8000;
    *(byte *)((int)puVar1 + 0xaf) = *(byte *)((int)puVar1 + 0xaf) | 8;
  }
  FUN_8028688c();
  return;
}
