// Function: FUN_802020b0
// Entry: 802020b0
// Size: 480 bytes

void FUN_802020b0(void)

{
  float fVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  undefined8 uVar8;
  undefined auStack40 [40];
  
  uVar8 = FUN_802860dc();
  iVar2 = (int)((ulonglong)uVar8 >> 0x20);
  iVar4 = (int)uVar8;
  iVar7 = *(int *)(iVar2 + 0xb8);
  iVar6 = *(int *)(iVar2 + 0x4c);
  iVar5 = *(int *)(iVar7 + 0x40c);
  *(undefined *)(iVar4 + 0x34d) = 0x11;
  fVar1 = FLOAT_803e62a8;
  if (*(char *)(iVar4 + 0x27a) != '\0') {
    *(float *)(iVar4 + 0x284) = FLOAT_803e62a8;
    *(float *)(iVar4 + 0x280) = fVar1;
    *(undefined4 *)(iVar4 + 0x2d0) = 0;
    *(undefined *)(iVar4 + 0x25f) = 1;
    *(undefined *)(iVar4 + 0x349) = 0;
    *(byte *)(iVar2 + 0xaf) = *(byte *)(iVar2 + 0xaf) | 8;
    FUN_80035f00();
    FUN_80036fa4(iVar2,3);
    if (*(int *)(iVar5 + 0x18) != 0) {
      FUN_800378c4(*(int *)(iVar5 + 0x18),0x11,iVar2,0x10);
      *(undefined2 *)(iVar5 + 0x1c) = 0xffff;
      *(undefined4 *)(iVar5 + 0x18) = 0;
    }
  }
  if (*(char *)(iVar4 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e62a8,iVar2,1,0);
    *(undefined *)(iVar4 + 0x346) = 0;
  }
  *(float *)(iVar4 + 0x2a0) = FLOAT_803e6334;
  if (FLOAT_803e6338 < *(float *)(iVar2 + 0x98)) {
    FUN_8001ff3c((int)*(short *)(iVar6 + 0x18));
    if (*(int *)(iVar6 + 0x14) == -1) {
      FUN_8002cbc4(iVar2);
      goto LAB_8020227c;
    }
    while (iVar3 = FUN_800138b4(*(undefined4 *)(iVar5 + 0x24)), iVar3 == 0) {
      FUN_800138e0(*(undefined4 *)(iVar5 + 0x24),auStack40);
    }
    if (*(short *)(iVar6 + 0x2c) == 0) {
      (**(code **)(*DAT_803dcaac + 100))((double)FLOAT_803e633c,*(undefined4 *)(iVar6 + 0x14));
    }
    *(byte *)(iVar7 + 0x404) = *(byte *)(iVar7 + 0x404) | *(byte *)(iVar6 + 0x2b);
  }
  (**(code **)(*DAT_803dca8c + 0x34))(iVar2,iVar4,0,2,&DAT_80329634);
  (**(code **)(*DAT_803dca8c + 0x34))(iVar2,iVar4,7,0,&DAT_80329640);
LAB_8020227c:
  FUN_80286128(0);
  return;
}

