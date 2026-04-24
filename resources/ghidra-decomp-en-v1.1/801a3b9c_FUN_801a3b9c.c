// Function: FUN_801a3b9c
// Entry: 801a3b9c
// Size: 336 bytes

void FUN_801a3b9c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)

{
  uint uVar1;
  int iVar2;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined8 uVar7;
  
  iVar3 = *(int *)(param_9 + 0xb8);
  iVar5 = *(int *)(param_9 + 0x4c);
  if (*(char *)(iVar3 + 0x6e4) != '\x02') {
    if (*(char *)(iVar3 + 0x6e4) == '\0') {
      uVar1 = FUN_80020078((int)*(short *)(iVar5 + 0x40));
      if (uVar1 != 0) {
        FUN_801a3434(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar5,0
                     ,iVar3,in_r7,in_r8,in_r9,in_r10);
        if (*(int *)(iVar3 + 0x6d0) != 0) {
          FUN_8000bb38(param_9,(ushort)*(int *)(iVar3 + 0x6d0));
        }
        *(undefined *)(iVar3 + 0x6e4) = 1;
        *(undefined *)(param_9 + 0x36) = 0;
      }
    }
    else {
      iVar4 = 0;
      iVar6 = iVar3;
      do {
        if (*(int *)(iVar6 + 0x690) != 0) {
          iVar2 = (**(code **)(**(int **)(*(int *)(iVar6 + 0x690) + 0x68) + 0x20))();
          if (iVar2 != 1) {
            if (iVar2 < 1) {
              if (-1 < iVar2) {
                FUN_800201ac((int)*(short *)(iVar5 + 0x3e),1);
                if ((*(uint *)(iVar3 + 0x6cc) & 1 << iVar4) == 0) {
                  *(uint *)(iVar3 + 0x6cc) = *(uint *)(iVar3 + 0x6cc) | 1 << iVar4;
                }
              }
            }
            else if (iVar2 < 3) {
              uVar7 = FUN_800201ac((int)*(short *)(iVar5 + 0x3e),1);
              FUN_8002cc9c(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           *(int *)(iVar6 + 0x690));
              *(undefined4 *)(iVar6 + 0x690) = 0;
            }
          }
        }
        iVar6 = iVar6 + 4;
        iVar4 = iVar4 + 1;
      } while (iVar4 < 0xf);
    }
  }
  return;
}

