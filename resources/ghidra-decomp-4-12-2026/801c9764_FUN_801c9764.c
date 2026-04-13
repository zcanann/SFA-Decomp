// Function: FUN_801c9764
// Entry: 801c9764
// Size: 916 bytes

/* WARNING: Removing unreachable block (ram,0x801c987c) */

void FUN_801c9764(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9)

{
  byte bVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  char cVar5;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar6;
  undefined8 uVar7;
  
  iVar6 = *(int *)(param_9 + 0x5c);
  iVar3 = FUN_8002bac4();
  if (iVar3 != 0) {
    if ((*(int *)(param_9 + 0x7a) != 0) &&
       (*(int *)(param_9 + 0x7a) = *(int *)(param_9 + 0x7a) + -1, *(int *)(param_9 + 0x7a) == 0)) {
      uVar7 = FUN_80088f20(7,'\x01');
      uVar7 = FUN_80008cbc(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                           iVar3,0xd4,0,in_r7,in_r8,in_r9,in_r10);
      uVar7 = FUN_80008cbc(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                           iVar3,0xd5,0,in_r7,in_r8,in_r9,in_r10);
      FUN_80008cbc(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar3,0x222
                   ,0,in_r7,in_r8,in_r9,in_r10);
    }
    FUN_801c911c(param_9);
    FUN_801d84c4(iVar6 + 4,2,-1,-1,0xdd3,(int *)0xe);
    FUN_801d8650(iVar6 + 4,1,-1,-1,0xcbb,(int *)0x8);
    FUN_801d84c4(iVar6 + 4,4,-1,-1,0xcbb,(int *)0xc4);
    bVar1 = *(byte *)(iVar6 + 0x14);
    if (bVar1 != 3) {
      if (bVar1 < 3) {
        if (bVar1 == 1) {
          param_9[3] = param_9[3] | 0x4000;
          if (*(char *)(iVar6 + 0x15) < '\0') {
            *(undefined *)(iVar6 + 0x14) = 2;
            FUN_800201ac(0x16a,1);
          }
        }
        else if (bVar1 == 0) {
          param_9[3] = param_9[3] & 0xbfff;
          fVar2 = *(float *)(iVar6 + 8) - FLOAT_803dc074;
          *(float *)(iVar6 + 8) = fVar2;
          if (fVar2 <= FLOAT_803e5d74) {
            FUN_8000bb38((uint)param_9,0x343);
            uVar4 = FUN_80022264(500,1000);
            *(float *)(iVar6 + 8) =
                 (float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803e5d68);
          }
          if ((*(byte *)((int)param_9 + 0xaf) & 1) != 0) {
            cVar5 = (**(code **)(*DAT_803dd72c + 0x4c))((int)*(char *)(param_9 + 0x56),1);
            if (cVar5 != '\0') {
              (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0x56),1,0);
            }
            *(undefined *)(iVar6 + 0x14) = 1;
            FUN_800201ac(0xdd3,1);
            *param_9 = 0x7fff;
            (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_9,0xffffffff);
            FUN_8000a538((int *)0xd8,1);
          }
        }
        else {
          uVar4 = FUN_80020078(0x16b);
          if (uVar4 == 0) {
            uVar4 = FUN_80020078(0x16c);
            if (uVar4 != 0) {
              *(undefined *)(iVar6 + 0x14) = 5;
              FUN_800201ac(0xc72,1);
              *(undefined2 *)(iVar6 + 0xc) = 10;
            }
          }
          else {
            *(undefined *)(iVar6 + 0x14) = 4;
            *(undefined2 *)(iVar6 + 0xc) = 0;
          }
        }
      }
      else if (bVar1 == 5) {
        *(undefined *)(iVar6 + 0x14) = 0;
        *(byte *)(iVar6 + 0x15) = *(byte *)(iVar6 + 0x15) & 0x7f;
        *(undefined2 *)(iVar6 + 0xc) = 0;
        FUN_800201ac(0xdd3,0);
        FUN_800201ac(0x15f,0);
        FUN_800201ac(0x16a,0);
        FUN_800201ac(0x16b,0);
        FUN_800201ac(0x16c,0);
        FUN_800201ac(0xc72,0);
        FUN_800201ac(0xc73,0);
      }
      else if (bVar1 < 5) {
        *(undefined *)(iVar6 + 0x14) = 5;
        FUN_80009a94(3);
        (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_9,0xffffffff);
        FUN_800201ac(0xdd3,0);
      }
    }
  }
  return;
}

