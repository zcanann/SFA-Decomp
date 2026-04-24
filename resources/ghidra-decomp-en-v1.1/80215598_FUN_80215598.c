// Function: FUN_80215598
// Entry: 80215598
// Size: 716 bytes

void FUN_80215598(void)

{
  int iVar1;
  int iVar2;
  float *pfVar3;
  int iVar4;
  uint uVar5;
  char in_r8;
  int iVar6;
  int iVar7;
  float afStack_68 [12];
  undefined4 local_38;
  uint uStack_34;
  undefined8 local_30;
  undefined4 local_28;
  uint uStack_24;
  
  iVar2 = FUN_80286838();
  DAT_803de9d8 = *(int *)(iVar2 + 0xb8);
  if ((in_r8 != '\0') && (*(int *)(iVar2 + 0xf4) == 0)) {
    if (*(int *)(DAT_803de9d4 + 0x178) != 0) {
      FUN_80060630(*(int *)(DAT_803de9d4 + 0x178));
    }
    iVar6 = 0;
    iVar7 = 0;
    do {
      pfVar3 = *(float **)(DAT_803de9d4 + iVar7 + 0x17c);
      if (pfVar3 != (float *)0x0) {
        FUN_8008fb90(pfVar3);
        iVar4 = *(int *)(DAT_803de9d4 + iVar7 + 0x17c);
        uStack_34 = (uint)*(ushort *)(iVar4 + 0x20);
        local_38 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e7478) +
                     FLOAT_803dc074);
        local_30 = (double)(longlong)iVar1;
        *(short *)(iVar4 + 0x20) = (short)iVar1;
        uVar5 = *(uint *)(DAT_803de9d4 + iVar7 + 0x17c);
        if (*(ushort *)(uVar5 + 0x22) <= *(ushort *)(uVar5 + 0x20)) {
          FUN_800238c4(uVar5);
          *(undefined4 *)(DAT_803de9d4 + iVar7 + 0x17c) = 0;
        }
      }
      iVar7 = iVar7 + 4;
      iVar6 = iVar6 + 1;
    } while (iVar6 < 5);
    if (*(float *)(DAT_803de9d8 + 1000) != FLOAT_803e7450) {
      iVar6 = (int)*(float *)(DAT_803de9d8 + 1000);
      local_30 = (double)(longlong)iVar6;
      FUN_8003b6d8(200,0,0,(char)iVar6);
    }
    FUN_8003b9ec(iVar2);
    FUN_80038524(iVar2,1,(float *)(DAT_803de9d4 + 0x130),(undefined4 *)(DAT_803de9d4 + 0x134),
                 (float *)(DAT_803de9d4 + 0x138),0);
    FUN_80038524(iVar2,2,(float *)(DAT_803de9d4 + 0x148),(undefined4 *)(DAT_803de9d4 + 0x14c),
                 (float *)(DAT_803de9d4 + 0x150),0);
    FUN_80038524(iVar2,3,(float *)(DAT_803de9d4 + 0x160),(undefined4 *)(DAT_803de9d4 + 0x164),
                 (float *)(DAT_803de9d4 + 0x168),0);
    FUN_80038524(iVar2,0,(float *)(DAT_803de9d4 + 0x118),(undefined4 *)(DAT_803de9d4 + 0x11c),
                 (float *)(DAT_803de9d4 + 0x120),0);
    uVar5 = FUN_80038498(iVar2,4);
    FUN_80003494((uint)afStack_68,uVar5,0x30);
    uVar5 = FUN_80022264(0xffffffce,0x32);
    local_30 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
    *(float *)(DAT_803de9d4 + 0x16c) = FLOAT_803e744c * (float)(local_30 - DOUBLE_803e7498);
    uStack_34 = FUN_80022264(0x3c,0x78);
    uStack_34 = uStack_34 ^ 0x80000000;
    local_38 = 0x43300000;
    *(float *)(DAT_803de9d4 + 0x170) =
         FLOAT_803e744c * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e7498);
    uStack_24 = FUN_80022264(100,0x96);
    uStack_24 = uStack_24 ^ 0x80000000;
    local_28 = 0x43300000;
    *(float *)(DAT_803de9d4 + 0x174) =
         FLOAT_803e74e0 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e7498);
    FUN_80247cd8(afStack_68,(float *)(DAT_803de9d4 + 0x16c),(float *)(DAT_803de9d4 + 0x16c));
    *(uint *)(DAT_803de9d4 + 0x104) = *(uint *)(DAT_803de9d4 + 0x104) | 0x100000;
  }
  FUN_80286884();
  return;
}

