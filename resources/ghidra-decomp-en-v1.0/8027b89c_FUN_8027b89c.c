// Function: FUN_8027b89c
// Entry: 8027b89c
// Size: 320 bytes

undefined4
FUN_8027b89c(uint param_1,short param_2,undefined4 param_3,undefined4 param_4,char param_5,
            undefined4 param_6)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  int *piVar4;
  short *psVar5;
  int iVar6;
  int iVar7;
  
  piVar4 = &DAT_803cbbe0;
  iVar3 = 0;
  iVar1 = (int)DAT_803de308;
  if (0 < iVar1) {
    do {
      if ((param_1 & 0xffff) == (uint)*(ushort *)(*piVar4 + 4)) {
        iVar1 = (&DAT_803cbbe0)[iVar3 * 3];
        if (*(short *)(iVar1 + 6) != 0) {
          return 0xffffffff;
        }
        iVar3 = (&DAT_803cbbe8)[iVar3 * 3];
        iVar7 = iVar3 + *(int *)(iVar1 + 0x1c);
        iVar6 = iVar3 + *(int *)(iVar1 + 0x20);
        psVar5 = (short *)(iVar3 + *(int *)(iVar1 + 0x24));
        while( true ) {
          if (*psVar5 == -1) {
            return 0xffffffff;
          }
          if (*psVar5 == param_2) break;
          psVar5 = psVar5 + 0x2a;
        }
        if (param_5 != '\0') {
          uVar2 = FUN_8026c488(iVar7,iVar6,psVar5,param_3,param_4,param_6,param_1);
          return uVar2;
        }
        FUN_80284af4();
        uVar2 = FUN_8026c488(iVar7,iVar6,psVar5,param_3,param_4,param_6,param_1);
        FUN_80284abc();
        return uVar2;
      }
      piVar4 = piVar4 + 3;
      iVar3 = iVar3 + 1;
      iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
  }
  return 0xffffffff;
}

