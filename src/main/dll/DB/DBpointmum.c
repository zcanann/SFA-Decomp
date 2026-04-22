#include "ghidra_import.h"
#include "main/dll/DB/DBpointmum.h"

extern undefined4 FUN_800201ac();
extern void* FUN_80037048();
extern int FUN_800375e4();
extern undefined4 FUN_800379bc();

extern undefined4* DAT_803dd708;
extern f32 FLOAT_803e6348;
extern f32 FLOAT_803e634c;

/*
 * --INFO--
 *
 * Function: FUN_801dfa9c
 * EN v1.0 Address: 0x801DFA9C
 * EN v1.0 Size: 928b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801dfa9c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9
            ,undefined4 param_10,int param_11,undefined4 param_12,undefined4 param_13,
            undefined4 param_14,int param_15,undefined4 param_16)
{
  byte bVar1;
  undefined4 *puVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  double dVar6;
  double dVar7;
  int local_58;
  uint uStack_54;
  uint local_50;
  uint uStack_4c;
  undefined2 local_48;
  undefined2 local_46;
  undefined2 local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  
  iVar5 = 0;
  dVar6 = (double)FLOAT_803e6348;
  dVar7 = (double)FLOAT_803e634c;
  for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar4 = iVar4 + 1) {
    local_3c = (float)dVar6;
    local_38 = (float)dVar6;
    local_34 = (float)dVar6;
    local_40 = (float)dVar7;
    local_46 = 0;
    local_48 = 0;
    local_44 = 0;
    bVar1 = *(byte *)(param_11 + iVar4 + 0x81);
    if (bVar1 == 4) {
      local_44 = 2;
      param_13 = 0xffffffff;
      param_14 = 0;
      param_15 = *DAT_803dd708;
      param_1 = (**(code **)(param_15 + 8))(param_9,0x85,&local_48,1);
    }
    else if (bVar1 < 4) {
      if (bVar1 == 2) {
        local_44 = 0;
        param_13 = 0xffffffff;
        param_14 = 0;
        param_15 = *DAT_803dd708;
        param_1 = (**(code **)(param_15 + 8))(param_9,0x85,&local_48,1);
      }
      else if (bVar1 < 2) {
        if (bVar1 != 0) {
          param_1 = FUN_800201ac(0x75,1);
        }
      }
      else {
        local_44 = 1;
        param_13 = 0xffffffff;
        param_14 = 0;
        param_15 = *DAT_803dd708;
        param_1 = (**(code **)(param_15 + 8))(param_9,0x85,&local_48,1);
      }
    }
    else if (bVar1 == 6) {
      local_44 = 4;
      param_13 = 0xffffffff;
      param_14 = 0;
      param_15 = *DAT_803dd708;
      param_1 = (**(code **)(param_15 + 8))(param_9,0x85,&local_48,1);
    }
    else if (bVar1 < 6) {
      local_44 = 3;
      param_13 = 0xffffffff;
      param_14 = 0;
      param_15 = *DAT_803dd708;
      param_1 = (**(code **)(param_15 + 8))(param_9,0x85,&local_48,1);
    }
  }
  while (iVar4 = FUN_800375e4(param_9,&local_50,&uStack_4c,&uStack_54), iVar4 != 0) {
    if ((*(byte *)(param_11 + 0x90) & 0x80) == 0) {
      if (local_50 == 0xf000c) {
        puVar2 = FUN_80037048(3,&local_58);
        iVar4 = 0;
        while (iVar4 < local_58) {
          iVar3 = iVar4;
          if (*(short *)(puVar2[iVar4] + 0x46) == 0xf7) {
            iVar3 = local_58;
            iVar5 = puVar2[iVar4];
          }
          iVar4 = iVar3 + 1;
        }
        if (iVar5 != 0) {
          FUN_800379bc(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar5,
                       0x130002,param_9,0,param_13,param_14,param_15,param_16);
        }
      }
      else if ((int)local_50 < 0xf000c) {
        if (0xf000a < (int)local_50) {
          puVar2 = FUN_80037048(3,&local_58);
          iVar4 = 0;
          while (iVar4 < local_58) {
            iVar3 = iVar4;
            if (*(short *)(puVar2[iVar4] + 0x46) == 0xf7) {
              iVar3 = local_58;
              iVar5 = puVar2[iVar4];
            }
            iVar4 = iVar3 + 1;
          }
          if (iVar5 != 0) {
            FUN_800379bc(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar5,
                         0x130001,param_9,0,param_13,param_14,param_15,param_16);
          }
        }
      }
      else if ((int)local_50 < 0xf000e) {
        puVar2 = FUN_80037048(3,&local_58);
        iVar4 = 0;
        while (iVar4 < local_58) {
          iVar3 = iVar4;
          if (*(short *)(puVar2[iVar4] + 0x46) == 0xf7) {
            iVar3 = local_58;
            iVar5 = puVar2[iVar4];
          }
          iVar4 = iVar3 + 1;
        }
        if (iVar5 != 0) {
          FUN_800379bc(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar5,
                       0x130003,param_9,0,param_13,param_14,param_15,param_16);
        }
      }
    }
  }
  *(undefined *)(param_11 + 0x56) = 0;
  return 0;
}
