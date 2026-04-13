// Function: FUN_802192a0
// Entry: 802192a0
// Size: 616 bytes

void FUN_802192a0(int param_1)

{
  bool bVar1;
  short sVar2;
  short *psVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  uint uVar7;
  short *psVar8;
  
  psVar8 = &DAT_8032b388;
  iVar6 = *(int *)(param_1 + 0xb8);
  if ((*(char *)(iVar6 + 1) == '\0') && (psVar3 = (short *)FUN_8002bac4(), psVar3 != (short *)0x0))
  {
    iVar4 = FUN_80057360();
    (**(code **)(*DAT_803dd72c + 0x1c))(psVar3 + 6,(int)*psVar3,0,iVar4);
    *(undefined *)(iVar6 + 1) = 1;
  }
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
  uVar7 = 0;
  psVar3 = psVar8;
  do {
    uVar5 = FUN_80020078((int)*psVar3);
    if (uVar5 != 0) {
      sVar2 = (&DAT_8032b388)[uVar7];
      goto LAB_80219360;
    }
    psVar3 = psVar3 + 1;
    uVar7 = uVar7 + 1;
  } while (uVar7 < 9);
  sVar2 = 0;
LAB_80219360:
  if (sVar2 == 0) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
  }
  if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
    uVar7 = 0;
    do {
      iVar6 = (**(code **)(*DAT_803dd6e8 + 0x20))((int)*psVar8);
      if (iVar6 != 0) {
        if (DAT_803dd5e8 == '\0') {
          iVar6 = *(int *)(param_1 + 0xb8);
          *(undefined4 *)(iVar6 + 4) = (&DAT_8032b3c0)[uVar7];
          if (uVar7 == 3) {
            *(undefined4 *)(iVar6 + 4) = 0x524;
LAB_80219460:
            FUN_800201ac((int)(short)(&DAT_8032b39c)[uVar7],1);
            FUN_800e815c(uVar7 & 0xff);
          }
          else if (((int)uVar7 < 3) && (-1 < (int)uVar7)) goto LAB_80219460;
          FUN_800201ac((int)(short)(&DAT_8032b3b0)[uVar7],1);
        }
        else {
          iVar6 = *(int *)(param_1 + 0xb8);
          if (((int)uVar7 < 3) && (-1 < (int)uVar7)) {
            FUN_800201ac((int)(short)(&DAT_8032b39c)[uVar7],1);
            FUN_800e815c(uVar7 & 0xff);
          }
          *(undefined4 *)(iVar6 + 4) = (&DAT_8032b3c0)[uVar7];
          FUN_800201ac((int)(short)(&DAT_8032b3b0)[uVar7],1);
        }
        bVar1 = true;
        goto LAB_802194ac;
      }
      psVar8 = psVar8 + 1;
      uVar7 = uVar7 + 1;
    } while (uVar7 < 9);
    bVar1 = false;
LAB_802194ac:
    if (bVar1) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
      FUN_80014b68(0,0x100);
    }
  }
  FUN_80041110();
  return;
}

