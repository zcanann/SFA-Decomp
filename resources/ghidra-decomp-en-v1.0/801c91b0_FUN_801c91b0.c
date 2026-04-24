// Function: FUN_801c91b0
// Entry: 801c91b0
// Size: 916 bytes

/* WARNING: Removing unreachable block (ram,0x801c92c8) */

void FUN_801c91b0(undefined2 *param_1)

{
  byte bVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  char cVar5;
  int iVar6;
  
  iVar6 = *(int *)(param_1 + 0x5c);
  iVar3 = FUN_8002b9ec();
  if (iVar3 != 0) {
    if ((*(int *)(param_1 + 0x7a) != 0) &&
       (*(int *)(param_1 + 0x7a) = *(int *)(param_1 + 0x7a) + -1, *(int *)(param_1 + 0x7a) == 0)) {
      FUN_80088c94(7,1);
      FUN_80008cbc(param_1,iVar3,0xd4,0);
      FUN_80008cbc(param_1,iVar3,0xd5,0);
      FUN_80008cbc(param_1,iVar3,0x222,0);
    }
    FUN_801c8b68(param_1);
    FUN_801d7ed4(iVar6 + 4,2,0xffffffff,0xffffffff,0xdd3,0xe);
    FUN_801d8060(iVar6 + 4,1,0xffffffff,0xffffffff,0xcbb,8);
    FUN_801d7ed4(iVar6 + 4,4,0xffffffff,0xffffffff,0xcbb,0xc4);
    bVar1 = *(byte *)(iVar6 + 0x14);
    if (bVar1 != 3) {
      if (bVar1 < 3) {
        if (bVar1 == 1) {
          param_1[3] = param_1[3] | 0x4000;
          if (*(char *)(iVar6 + 0x15) < '\0') {
            *(undefined *)(iVar6 + 0x14) = 2;
            FUN_800200e8(0x16a,1);
          }
        }
        else if (bVar1 == 0) {
          param_1[3] = param_1[3] & 0xbfff;
          fVar2 = *(float *)(iVar6 + 8) - FLOAT_803db414;
          *(float *)(iVar6 + 8) = fVar2;
          if (fVar2 <= FLOAT_803e50dc) {
            FUN_8000bb18(param_1,0x343);
            uVar4 = FUN_800221a0(500,1000);
            *(float *)(iVar6 + 8) =
                 (float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803e50d0);
          }
          if ((*(byte *)((int)param_1 + 0xaf) & 1) != 0) {
            cVar5 = (**(code **)(*DAT_803dcaac + 0x4c))((int)*(char *)(param_1 + 0x56),1);
            if (cVar5 != '\0') {
              (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0x56),1,0);
            }
            *(undefined *)(iVar6 + 0x14) = 1;
            FUN_800200e8(0xdd3,1);
            *param_1 = 0x7fff;
            (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
            FUN_8000a518(0xd8,1);
          }
        }
        else {
          iVar3 = FUN_8001ffb4(0x16b);
          if (iVar3 == 0) {
            iVar3 = FUN_8001ffb4(0x16c);
            if (iVar3 != 0) {
              *(undefined *)(iVar6 + 0x14) = 5;
              FUN_800200e8(0xc72,1);
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
        FUN_800200e8(0xdd3,0);
        FUN_800200e8(0x15f,0);
        FUN_800200e8(0x16a,0);
        FUN_800200e8(0x16b,0);
        FUN_800200e8(0x16c,0);
        FUN_800200e8(0xc72,0);
        FUN_800200e8(0xc73,0);
      }
      else if (bVar1 < 5) {
        *(undefined *)(iVar6 + 0x14) = 5;
        FUN_80009a94(3);
        (**(code **)(*DAT_803dca54 + 0x48))(1,param_1,0xffffffff);
        FUN_800200e8(0xdd3,0);
      }
    }
  }
  return;
}

