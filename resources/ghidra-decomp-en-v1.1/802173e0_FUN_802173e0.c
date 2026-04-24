// Function: FUN_802173e0
// Entry: 802173e0
// Size: 304 bytes

/* WARNING: Removing unreachable block (ram,0x802174f0) */
/* WARNING: Removing unreachable block (ram,0x802173f0) */

void FUN_802173e0(void)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  double in_f31;
  double dVar5;
  double in_ps31_1;
  undefined auStack_58 [12];
  float local_4c;
  undefined4 local_48;
  float local_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar1 = FUN_80286840();
  iVar4 = *(int *)(uVar1 + 0x4c);
  uVar2 = FUN_80020078((int)*(short *)(iVar4 + 0x24));
  if ((uVar2 != 0) && (iVar3 = FUN_8002bac4(), iVar3 != 0)) {
    *(undefined4 *)(uVar1 + 0xc) = *(undefined4 *)(iVar3 + 0xc);
    *(undefined4 *)(uVar1 + 0x14) = *(undefined4 *)(iVar3 + 0x14);
    iVar3 = 0;
    dVar5 = DOUBLE_803e7568;
    do {
      uStack_3c = FUN_80022264(0xffffff38,200);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_4c = *(float *)(uVar1 + 0xc) + (float)((double)CONCAT44(0x43300000,uStack_3c) - dVar5);
      local_48 = *(undefined4 *)(uVar1 + 0x10);
      uStack_34 = FUN_80022264(0xffffff38,200);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_44 = *(float *)(uVar1 + 0x14) + (float)((double)CONCAT44(0x43300000,uStack_34) - dVar5);
      (**(code **)(*DAT_803dd708 + 8))
                (uVar1,*(undefined2 *)(iVar4 + 0x20),auStack_58,0x200001,0xffffffff,0);
      iVar3 = iVar3 + 1;
    } while (iVar3 < 10);
    FUN_8000bb38(uVar1,0x2b8);
    FUN_800201ac((int)*(short *)(iVar4 + 0x24),0);
  }
  FUN_8028688c();
  return;
}

